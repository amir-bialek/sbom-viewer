import json
import unittest

import _paths  # noqa: F401 — adds backend/ to sys.path

from app.sbom_parser import (  # noqa: E402
    get_components,
    get_grouped_components,
    get_summary,
    get_vulnerability_counts,
    get_vulnerability_detail,
    has_annex_b,
    parse_annex_b,
    parse_dependencies,
    parse_vulnerabilities,
    pick_severity,
)


def _load(path):
    with open(path) as f:
        return json.load(f)


class TestVulnerabilities(unittest.TestCase):
    def test_raw_syft_has_no_vulnerabilities(self):
        data = _load(_paths.SAMPLE_RAW)
        self.assertEqual(parse_vulnerabilities(data), [])
        self.assertEqual(
            get_vulnerability_counts(data),
            {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0},
        )

    def test_trivy_returns_four_normalized_rows(self):
        data = _load(_paths.SAMPLE_TRIVY)
        rows = parse_vulnerabilities(data)
        self.assertEqual(len(rows), 4)
        for r in rows:
            self.assertIn("id", r)
            self.assertIn("severity", r)
            self.assertIn("score", r)
            self.assertIn("source", r)
            self.assertIn("affected_components", r)
            self.assertIsInstance(r["affected_components"], list)
            for ac in r["affected_components"]:
                self.assertIn("name", ac)
                self.assertIn("version", ac)
                self.assertIn("purl", ac)
                self.assertIn("bom_ref", ac)

    def test_merged_returns_four_normalized_rows(self):
        data = _load(_paths.SAMPLE_MERGED)
        rows = parse_vulnerabilities(data)
        self.assertEqual(len(rows), 4)

    def test_one_row_per_cve_dedup_shape(self):
        # Decision D2: one row per CVE. In this sample each CVE has 1 component
        # but row count must equal CVE count and use affected_components list.
        data = _load(_paths.SAMPLE_MERGED)
        rows = parse_vulnerabilities(data)
        cve_ids = {r["id"] for r in rows}
        self.assertEqual(len(cve_ids), len(rows))
        for r in rows:
            self.assertGreaterEqual(len(r["affected_components"]), 1)

    def test_affected_component_resolves_against_components_index(self):
        data = _load(_paths.SAMPLE_MERGED)
        rows = {r["id"]: r for r in parse_vulnerabilities(data)}
        # CVE-2024-2236 hits libgcrypt20
        ac = rows["CVE-2024-2236"]["affected_components"][0]
        self.assertEqual(ac["name"], "libgcrypt20")
        self.assertEqual(ac["version"], "1.10.3-2build1")
        self.assertTrue(ac["purl"].startswith("pkg:deb/ubuntu/libgcrypt20@"))
        self.assertIn("package-id=", ac["bom_ref"])

    def test_severity_counts_on_merged(self):
        # All four sample CVEs have ubuntu severity in {low, medium}
        data = _load(_paths.SAMPLE_MERGED)
        counts = get_vulnerability_counts(data)
        # CVE-2024-2236 ubuntu=low; the other three ubuntu=medium
        self.assertEqual(counts["low"], 1)
        self.assertEqual(counts["medium"], 3)
        self.assertEqual(counts["critical"], 0)
        self.assertEqual(counts["high"], 0)
        self.assertEqual(counts["unknown"], 0)

    def test_detail_returns_ratings_array_verbatim(self):
        data = _load(_paths.SAMPLE_MERGED)
        detail = get_vulnerability_detail(data, "CVE-2024-2236")
        self.assertIsNotNone(detail)
        self.assertEqual(detail["id"], "CVE-2024-2236")
        # Raw ratings preserved for the UI to render per-source breakdown
        self.assertEqual(len(detail["ratings"]), 6)
        sources = {(r.get("source") or {}).get("name") for r in detail["ratings"]}
        self.assertIn("ubuntu", sources)
        self.assertIn("redhat", sources)

    def test_detail_returns_none_for_unknown_cve(self):
        data = _load(_paths.SAMPLE_MERGED)
        self.assertIsNone(get_vulnerability_detail(data, "CVE-9999-0001"))


class TestPickSeverity(unittest.TestCase):
    def setUp(self):
        # Same shape as sample CVE-2024-2236
        self.cve_2024_2236_ratings = [
            {"source": {"name": "alma"}, "severity": "medium"},
            {"source": {"name": "amazon"}, "severity": "medium"},
            {"source": {"name": "oracle-oval"}, "severity": "medium"},
            {"source": {"name": "redhat"}, "score": 5.9, "severity": "medium", "method": "CVSSv31"},
            {"source": {"name": "rocky"}, "severity": "medium"},
            {"source": {"name": "ubuntu"}, "severity": "low"},
        ]
        # CVE-2026-41989 — multiple CVSSv31 entries, no ubuntu CVSS
        self.cve_2026_41989_ratings = [
            {"source": {"name": "amazon"}, "severity": "medium"},
            {"source": {"name": "azure"}, "severity": "low"},
            {"source": {"name": "julia"}, "score": 6.7, "severity": "medium", "method": "CVSSv31"},
            {"source": {"name": "redhat"}, "score": 7.5, "severity": "medium", "method": "CVSSv31"},
            {"source": {"name": "ubuntu"}, "severity": "medium"},
        ]

    def test_rule_1_prefers_matching_source(self):
        sev, score = pick_severity(self.cve_2024_2236_ratings, "ubuntu")
        self.assertEqual(sev, "low")
        # CVSS = highest CVSSv3.1 score regardless of source = 5.9 (redhat)
        self.assertEqual(score, 5.9)

    def test_rule_2_falls_back_to_highest_cvss(self):
        # No source match — sample doesn't have "nvd"
        sev, score = pick_severity(self.cve_2024_2236_ratings, "nvd")
        # Highest CVSSv31 = redhat 5.9 → severity "medium"
        self.assertEqual(sev, "medium")
        self.assertEqual(score, 5.9)

    def test_rule_3_first_nonempty_severity(self):
        ratings = [
            {"source": {"name": "x"}, "severity": ""},
            {"source": {"name": "y"}, "severity": "high"},
            {"source": {"name": "z"}, "severity": "low"},
        ]
        sev, score = pick_severity(ratings, "missing")
        self.assertEqual(sev, "high")
        self.assertIsNone(score)

    def test_empty_ratings(self):
        sev, score = pick_severity([], "ubuntu")
        self.assertEqual(sev, "")
        self.assertIsNone(score)

    def test_highest_cvss_breaks_tie_to_redhat(self):
        sev, score = pick_severity(self.cve_2026_41989_ratings, "ubuntu")
        self.assertEqual(sev, "medium")  # ubuntu's severity wins
        self.assertEqual(score, 7.5)     # highest CVSSv3.1 across all sources


class TestAnnexB(unittest.TestCase):
    def test_raw_syft_has_no_annex_b(self):
        data = _load(_paths.SAMPLE_RAW)
        self.assertFalse(has_annex_b(data))
        # Fallback: empty strings everywhere
        a = parse_annex_b(data)
        self.assertEqual(a["date_of_acquisition"], "")
        self.assertEqual(a["image_ref"], "")
        self.assertEqual(a["product_name"], "")
        self.assertEqual(a["product_version"], "")
        self.assertEqual(a["modifications"], "")

    def test_trivy_has_no_annex_b(self):
        data = _load(_paths.SAMPLE_TRIVY)
        self.assertFalse(has_annex_b(data))
        a = parse_annex_b(data)
        self.assertEqual(a["image_ref"], "")

    def test_merged_returns_all_five_fields(self):
        data = _load(_paths.SAMPLE_MERGED)
        self.assertTrue(has_annex_b(data))
        a = parse_annex_b(data)
        self.assertEqual(a["image_ref"], "ubuntu:24.04")
        self.assertEqual(a["product_name"], "ubuntu")
        self.assertEqual(a["product_version"], "24.04")
        self.assertEqual(a["modifications"], "none")
        self.assertEqual(a["date_of_acquisition"], "2026-06-22T12:42:13Z")


class TestComponentAnnexBSource(unittest.TestCase):
    def test_raw_components_have_empty_annex_b_source(self):
        data = _load(_paths.SAMPLE_RAW)
        result = get_components(data, type_filter="library", limit=5)
        self.assertGreater(len(result["components"]), 0)
        for c in result["components"]:
            self.assertEqual(c["annex_b_source"], "")

    def test_merged_libraries_have_annex_b_source(self):
        data = _load(_paths.SAMPLE_MERGED)
        result = get_components(data, type_filter="library", limit=5)
        for c in result["components"]:
            self.assertEqual(c["annex_b_source"], "apt")

    def test_merged_files_have_empty_annex_b_source(self):
        data = _load(_paths.SAMPLE_MERGED)
        result = get_components(data, type_filter="file", limit=5)
        for c in result["components"]:
            self.assertEqual(c["annex_b_source"], "")

    def test_grouped_carries_annex_b_source(self):
        data = _load(_paths.SAMPLE_MERGED)
        result = get_grouped_components(data, type_filter="library", limit=5)
        # at least one library appears with the source
        self.assertGreater(len(result["components"]), 0)
        sources = {c.get("annex_b_source") for c in result["components"]}
        self.assertIn("apt", sources)


class TestDependencies(unittest.TestCase):
    def test_raw_has_dependencies(self):
        data = _load(_paths.SAMPLE_RAW)
        deps = parse_dependencies(data)
        self.assertEqual(len(deps), 83)

    def test_trivy_and_merged_match_raw(self):
        raw = parse_dependencies(_load(_paths.SAMPLE_RAW))
        trivy = parse_dependencies(_load(_paths.SAMPLE_TRIVY))
        merged = parse_dependencies(_load(_paths.SAMPLE_MERGED))
        self.assertEqual(set(raw.keys()), set(trivy.keys()))
        self.assertEqual(set(raw.keys()), set(merged.keys()))

    def test_adjacency_shape(self):
        data = _load(_paths.SAMPLE_MERGED)
        deps = parse_dependencies(data)
        apt_ref = "pkg:deb/ubuntu/apt@2.8.3?arch=amd64&distro=ubuntu-24.04&package-id=bfe0855a529838fa"
        self.assertIn(apt_ref, deps)
        self.assertGreater(len(deps[apt_ref]), 0)

    def test_missing_dependencies_default(self):
        self.assertEqual(parse_dependencies({}), {})
        self.assertEqual(parse_dependencies({"dependencies": []}), {})


class TestSummary(unittest.TestCase):
    def test_raw_summary_works(self):
        data = _load(_paths.SAMPLE_RAW)
        s = get_summary(data)
        self.assertEqual(s["total_components"], 2356)
        # Ubuntu 24.04: 92 libraries, 2263 files, 1 operating-system
        self.assertEqual(s["by_type"].get("library"), 92)
        self.assertEqual(s["by_type"].get("file"), 2263)
        self.assertEqual(s["by_type"].get("operating-system"), 1)

    def test_merged_summary_identical_component_breakdown(self):
        data = _load(_paths.SAMPLE_MERGED)
        s = get_summary(data)
        self.assertEqual(s["total_components"], 2356)
        self.assertEqual(s["by_type"].get("library"), 92)


if __name__ == "__main__":
    unittest.main()
