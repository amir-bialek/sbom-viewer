import importlib
import json
import os
import shutil
import tempfile
import unittest

import _paths  # noqa: F401


class TestS3ClientListAndDownload(unittest.TestCase):
    def setUp(self):
        # Fresh tmpdir laid out like STORAGE_PATH
        self.tmp = tempfile.mkdtemp(prefix="sbom-viewer-test-")
        self.ns = os.path.join(self.tmp, "ubuntu")
        os.makedirs(self.ns, exist_ok=True)
        # Copy all three sample siblings to share a base id "ubuntu/24.04"
        shutil.copy(_paths.SAMPLE_RAW, os.path.join(self.ns, "24.04.cdx.json"))
        shutil.copy(_paths.SAMPLE_TRIVY, os.path.join(self.ns, "24.04.trivy.cdx.json"))
        shutil.copy(_paths.SAMPLE_MERGED, os.path.join(self.ns, "24.04.enriched.cdx.json"))

        # Also drop a raw-only sibling — must still list
        os.makedirs(os.path.join(self.tmp, "lonely"), exist_ok=True)
        shutil.copy(_paths.SAMPLE_RAW, os.path.join(self.tmp, "lonely", "v1.cdx.json"))

        os.environ["STORAGE_PATH"] = self.tmp
        # Reimport so STORAGE_PATH and _cache reflect the test env
        import app.s3_client as mod
        importlib.reload(mod)
        self.mod = mod

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_list_filters_out_sibling_files(self):
        items = self.mod.list_sboms()
        ids = sorted(i["id"] for i in items)
        # Exactly two raw SBOM ids — the .trivy/.enriched siblings must not show
        self.assertEqual(ids, ["lonely/v1", "ubuntu/24.04"])

    def test_list_flags(self):
        items = {i["id"]: i for i in self.mod.list_sboms()}
        ubuntu = items["ubuntu/24.04"]
        self.assertTrue(ubuntu["has_sbom"])
        self.assertTrue(ubuntu["has_trivy"])
        self.assertTrue(ubuntu["has_merged"])
        lonely = items["lonely/v1"]
        self.assertTrue(lonely["has_sbom"])
        self.assertFalse(lonely["has_trivy"])
        self.assertFalse(lonely["has_merged"])

    def test_download_sbom_picks_right_view(self):
        raw = self.mod.download_sbom("ubuntu/24.04", self.mod.View.SBOM)
        trivy = self.mod.download_sbom("ubuntu/24.04", self.mod.View.TRIVY)
        merged = self.mod.download_sbom("ubuntu/24.04", self.mod.View.MERGED)
        self.assertEqual(len(raw["vulnerabilities"] if "vulnerabilities" in raw else []), 0)
        self.assertEqual(len(trivy["vulnerabilities"]), 4)
        self.assertEqual(len(merged["vulnerabilities"]), 4)
        # spec versions differ — sanity check we returned different files
        self.assertEqual(raw.get("specVersion"), "1.6")
        self.assertEqual(trivy.get("specVersion"), "1.7")
        self.assertEqual(merged.get("specVersion"), "1.6")

    def test_download_missing_view_returns_none(self):
        # lonely/v1 has no trivy/enriched sibling
        self.assertIsNone(self.mod.download_sbom("lonely/v1", self.mod.View.TRIVY))
        self.assertIsNone(self.mod.download_sbom("lonely/v1", self.mod.View.MERGED))

    def test_cache_key_is_per_view(self):
        # Reset cache; verify a sequence of view loads does not evict each other
        self.mod._cache.clear()
        a = self.mod.download_sbom("ubuntu/24.04", self.mod.View.SBOM)
        b = self.mod.download_sbom("ubuntu/24.04", self.mod.View.TRIVY)
        c = self.mod.download_sbom("ubuntu/24.04", self.mod.View.MERGED)
        self.assertIn(("ubuntu/24.04", "sbom"), self.mod._cache)
        self.assertIn(("ubuntu/24.04", "trivy"), self.mod._cache)
        self.assertIn(("ubuntu/24.04", "merged"), self.mod._cache)
        # And re-reading hits cache, not disk
        self.assertIs(a, self.mod.download_sbom("ubuntu/24.04", self.mod.View.SBOM))
        self.assertIs(b, self.mod.download_sbom("ubuntu/24.04", self.mod.View.TRIVY))
        self.assertIs(c, self.mod.download_sbom("ubuntu/24.04", self.mod.View.MERGED))

    def test_unknown_id_returns_none(self):
        self.assertIsNone(self.mod.download_sbom("nope", self.mod.View.SBOM))

    def test_list_includes_enriched_only_entries(self):
        os.makedirs(os.path.join(self.tmp, "enriched-only"), exist_ok=True)
        shutil.copy(_paths.SAMPLE_MERGED, os.path.join(self.tmp, "enriched-only", "v1.enriched.cdx.json"))

        items = {i["id"]: i for i in self.mod.list_sboms()}
        self.assertIn("enriched-only/v1", items)
        eo = items["enriched-only/v1"]
        self.assertTrue(eo["has_sbom"])
        self.assertTrue(eo["has_merged"])
        self.assertFalse(eo["has_trivy"])

    def test_download_sbom_falls_back_to_enriched(self):
        os.makedirs(os.path.join(self.tmp, "enriched-only"), exist_ok=True)
        shutil.copy(_paths.SAMPLE_MERGED, os.path.join(self.tmp, "enriched-only", "v1.enriched.cdx.json"))

        data = self.mod.download_sbom("enriched-only/v1", self.mod.View.SBOM)
        self.assertIsNotNone(data)
        self.assertIn("vulnerabilities", data)


if __name__ == "__main__":
    unittest.main()
