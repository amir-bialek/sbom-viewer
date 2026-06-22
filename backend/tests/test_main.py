import importlib
import os
import shutil
import tempfile
import unittest

from fastapi import HTTPException

import _paths  # noqa: F401


class TestMainEndpoints(unittest.TestCase):
    """Direct calls to the FastAPI handler functions.

    Avoids depending on httpx/TestClient. Endpoints are thin wrappers
    around the parser; we exercise the view-routing + error branches.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="sbom-viewer-test-")
        ns = os.path.join(self.tmp, "ubuntu")
        os.makedirs(ns, exist_ok=True)
        shutil.copy(_paths.SAMPLE_RAW, os.path.join(ns, "24.04.cdx.json"))
        shutil.copy(_paths.SAMPLE_TRIVY, os.path.join(ns, "24.04.trivy.cdx.json"))
        shutil.copy(_paths.SAMPLE_MERGED, os.path.join(ns, "24.04.enriched.cdx.json"))

        os.makedirs(os.path.join(self.tmp, "lonely"), exist_ok=True)
        shutil.copy(_paths.SAMPLE_RAW, os.path.join(self.tmp, "lonely", "v1.cdx.json"))

        os.environ["STORAGE_PATH"] = self.tmp

        import app.s3_client as s3
        importlib.reload(s3)
        import app.main as main
        importlib.reload(main)
        self.main = main

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_list_sboms_has_flags(self):
        items = self.main.api_list_sboms()
        ids = {i["id"]: i for i in items}
        self.assertIn("ubuntu/24.04", ids)
        self.assertIn("lonely/v1", ids)
        for i in items:
            self.assertIn("has_sbom", i)
            self.assertIn("has_trivy", i)
            self.assertIn("has_merged", i)

    def test_summary_sbom_view_has_no_vuln_or_annex_b(self):
        s = self.main.api_sbom_summary("ubuntu/24.04", view="sbom")
        self.assertNotIn("vulnerability_counts", s)
        self.assertNotIn("annex_b", s)

    def test_summary_trivy_view_has_vuln_counts_only(self):
        s = self.main.api_sbom_summary("ubuntu/24.04", view="trivy")
        self.assertIn("vulnerability_counts", s)
        self.assertNotIn("annex_b", s)
        self.assertEqual(s["vulnerability_counts"]["medium"], 3)
        self.assertEqual(s["vulnerability_counts"]["low"], 1)

    def test_summary_merged_view_has_both(self):
        s = self.main.api_sbom_summary("ubuntu/24.04", view="merged")
        self.assertIn("vulnerability_counts", s)
        self.assertIn("annex_b", s)
        self.assertEqual(s["annex_b"]["image_ref"], "ubuntu:24.04")

    def test_summary_404_when_view_file_missing(self):
        with self.assertRaises(HTTPException) as ctx:
            self.main.api_sbom_summary("lonely/v1", view="trivy")
        self.assertEqual(ctx.exception.status_code, 404)
        with self.assertRaises(HTTPException) as ctx:
            self.main.api_sbom_summary("lonely/v1", view="merged")
        self.assertEqual(ctx.exception.status_code, 404)

    def test_summary_400_on_bad_view(self):
        with self.assertRaises(HTTPException) as ctx:
            self.main.api_sbom_summary("ubuntu/24.04", view="garbage")
        self.assertEqual(ctx.exception.status_code, 400)

    def test_components_grouped_respects_view(self):
        raw = self.main.api_sbom_components_grouped(
            "ubuntu/24.04", view="sbom", type="library", name=None, offset=0, limit=200
        )
        merged = self.main.api_sbom_components_grouped(
            "ubuntu/24.04", view="merged", type="library", name=None, offset=0, limit=200
        )
        self.assertEqual(raw["total"], merged["total"])
        # annex_b_source only populated in merged view
        raw_sources = {c.get("annex_b_source") for c in raw["components"]}
        merged_sources = {c.get("annex_b_source") for c in merged["components"]}
        self.assertEqual(raw_sources, {""})
        self.assertIn("OS package (Debian/Ubuntu)", merged_sources)

    def test_vulnerabilities_list_trivy(self):
        out = self.main.api_sbom_vulnerabilities("ubuntu/24.04", view="trivy")
        self.assertEqual(len(out["vulnerabilities"]), 4)

    def test_vulnerabilities_list_rejects_sbom_view(self):
        with self.assertRaises(HTTPException) as ctx:
            self.main.api_sbom_vulnerabilities("ubuntu/24.04", view="sbom")
        self.assertEqual(ctx.exception.status_code, 400)

    def test_vulnerability_detail_happy_path(self):
        d = self.main.api_sbom_vulnerability_detail(
            "ubuntu/24.04", "CVE-2024-2236", view="merged"
        )
        self.assertEqual(d["id"], "CVE-2024-2236")
        self.assertEqual(len(d["ratings"]), 6)
        self.assertEqual(d["source"], "ubuntu")

    def test_vulnerability_detail_unknown_cve(self):
        with self.assertRaises(HTTPException) as ctx:
            self.main.api_sbom_vulnerability_detail(
                "ubuntu/24.04", "CVE-9999-0001", view="merged"
            )
        self.assertEqual(ctx.exception.status_code, 404)

    def test_annex_b_endpoint_happy_path(self):
        a = self.main.api_sbom_annex_b("ubuntu/24.04")
        self.assertEqual(a["image_ref"], "ubuntu:24.04")
        self.assertEqual(a["product_version"], "24.04")

    def test_annex_b_endpoint_404_when_merged_missing(self):
        with self.assertRaises(HTTPException) as ctx:
            self.main.api_sbom_annex_b("lonely/v1")
        self.assertEqual(ctx.exception.status_code, 404)


if __name__ == "__main__":
    unittest.main()
