import json
import os
import subprocess
import sys
import tempfile
import unittest


REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SCRIPT = os.path.join(REPO_ROOT, "scripts", "merge-trivy-vulns.py")

REAL_SYFT = "/tmp/sbom-artifact/syft.cdx.json"
REAL_TRIVY = "/tmp/sbom-artifact/trivy.cdx.json"
AIDRIVER_SYFT = "/tmp/aidriver-artifact/syft.cdx.json"
AIDRIVER_TRIVY = "/tmp/aidriver-artifact/trivy.cdx.json"


def _syft_doc(components=None, dependencies=None):
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:11111111-1111-1111-1111-111111111111",
        "version": 1,
        "metadata": {
            "timestamp": "2025-06-01T00:00:00Z",
            "tools": {"components": [{"type": "application", "name": "syft", "version": "1.42.3"}]},
            "component": {"type": "container", "name": "imagryhub/test", "version": "1.0"},
            "properties": [
                {"name": "syft:image:labels:org.opencontainers.image.title", "value": "test"},
            ],
        },
        "components": components if components is not None else [],
        "dependencies": dependencies if dependencies is not None else [],
    }


def _trivy_doc(vulnerabilities=None):
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:22222222-2222-2222-2222-222222222222",
        "version": 1,
        "metadata": {
            "timestamp": "2025-06-01T00:05:00Z",
            "tools": {"components": [{"type": "application", "name": "trivy", "version": "0.71.1"}]},
        },
        "vulnerabilities": vulnerabilities if vulnerabilities is not None else [],
    }


def _run_merger(syft_path, trivy_path, out_path):
    return subprocess.run(
        [sys.executable, SCRIPT, syft_path, trivy_path, out_path],
        capture_output=True,
        text=True,
    )


class MergeTrivyVulnsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.syft_path = os.path.join(self.tmp.name, "syft.cdx.json")
        self.trivy_path = os.path.join(self.tmp.name, "trivy.cdx.json")
        self.out_path = os.path.join(self.tmp.name, "out.cdx.json")

    def _write(self, path, doc):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(doc, f)

    def test_happy_path_graft(self):
        ref = "pkg:deb/ubuntu/libfoo@1.2.3?arch=amd64&distro=ubuntu-24.04&package-id=abcdef0123456789"
        syft = _syft_doc(components=[{
            "type": "library",
            "name": "libfoo",
            "version": "1.2.3",
            "bom-ref": ref,
            "purl": "pkg:deb/ubuntu/libfoo@1.2.3?arch=amd64&distro=ubuntu-24.04",
        }])
        trivy = _trivy_doc(vulnerabilities=[{
            "id": "CVE-2024-12345",
            "ratings": [{"source": {"name": "nvd"}, "severity": "high"}],
            "affects": [{"ref": ref}],
        }])
        self._write(self.syft_path, syft)
        self._write(self.trivy_path, trivy)

        result = _run_merger(self.syft_path, self.trivy_path, self.out_path)

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertEqual(
            result.stdout.strip(),
            "merged 1 vulnerabilities across 1 (CVE, component) pairs",
        )
        with open(self.out_path) as f:
            out = json.load(f)
        self.assertEqual(len(out["vulnerabilities"]), 1)
        self.assertEqual(out["vulnerabilities"][0]["affects"][0]["ref"], ref)

    def test_drift_detection(self):
        good_ref = "pkg:deb/ubuntu/libfoo@1.2.3?package-id=aaaaaaaaaaaaaaaa"
        bad_ref = "pkg:deb/ubuntu/libfoo@1.2.3"
        syft = _syft_doc(components=[{
            "type": "library",
            "name": "libfoo",
            "version": "1.2.3",
            "bom-ref": good_ref,
        }])
        trivy = _trivy_doc(vulnerabilities=[{
            "id": "CVE-2024-99999",
            "ratings": [{"source": {"name": "nvd"}, "severity": "medium"}],
            "affects": [{"ref": bad_ref}],
        }])
        self._write(self.syft_path, syft)
        self._write(self.trivy_path, trivy)

        result = _run_merger(self.syft_path, self.trivy_path, self.out_path)

        self.assertEqual(result.returncode, 1)
        self.assertIn("CVE-2024-99999", result.stderr)
        self.assertIn(bad_ref, result.stderr)
        self.assertFalse(os.path.exists(self.out_path))

    def test_inventory_invariant(self):
        ref = "pkg:deb/ubuntu/libbar@2.0.0?package-id=bbbbbbbbbbbbbbbb"
        syft = _syft_doc(
            components=[
                {"type": "library", "name": "libbar", "version": "2.0.0", "bom-ref": ref},
                {"type": "operating-system", "name": "ubuntu", "version": "24.04", "bom-ref": "os-ubuntu"},
            ],
            dependencies=[{"ref": ref, "dependsOn": []}],
        )
        trivy = _trivy_doc(vulnerabilities=[{
            "id": "CVE-2025-0001",
            "ratings": [{"source": {"name": "nvd"}, "severity": "low"}],
            "affects": [{"ref": ref}],
        }])
        self._write(self.syft_path, syft)
        self._write(self.trivy_path, trivy)

        result = _run_merger(self.syft_path, self.trivy_path, self.out_path)
        self.assertEqual(result.returncode, 0, msg=result.stderr)

        with open(self.syft_path) as f:
            syft_in = json.load(f)
        with open(self.out_path) as f:
            out = json.load(f)

        for key in ("metadata", "components", "dependencies", "serialNumber", "specVersion"):
            self.assertEqual(out.get(key), syft_in.get(key), msg=f"{key} mutated")

    def test_vulnerability_value_preservation(self):
        ref1 = "pkg:deb/ubuntu/libqux@3.1.4?package-id=cccccccccccccccc"
        ref2 = "pkg:pypi/somepkg@4.5.6?package-id=dddddddddddddddd"
        syft = _syft_doc(components=[
            {"type": "library", "name": "libqux", "version": "3.1.4", "bom-ref": ref1},
            {"type": "library", "name": "somepkg", "version": "4.5.6", "bom-ref": ref2},
        ])
        rich_vulns = [
            {
                "id": "CVE-2024-11111",
                "ratings": [
                    {"source": {"name": "nvd"}, "severity": "critical", "score": 9.8, "method": "CVSSv31"},
                    {"source": {"name": "ghsa"}, "severity": "high"},
                ],
                "affects": [{"ref": ref1, "versions": [{"version": "3.1.4", "status": "affected"}]}],
                "cwes": [79, 89],
                "description": "A serious flaw in libqux.",
                "recommendation": "Upgrade to 3.1.5 or later.",
                "advisories": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-11111"}],
                "analysis": {"state": "in_triage"},
                "properties": [{"name": "aquasecurity:trivy:FixedVersion", "value": "3.1.5"}],
            },
            {
                "id": "CVE-2024-22222",
                "ratings": [{"source": {"name": "nvd"}, "severity": "medium", "score": 5.5}],
                "affects": [{"ref": ref2}],
                "cwes": [120],
                "description": "Buffer issue in somepkg.",
                "recommendation": "Update to 4.5.7.",
                "advisories": [{"url": "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz"}],
                "analysis": {"state": "not_affected", "justification": "code_not_reachable"},
                "properties": [{"name": "aquasecurity:trivy:FixedVersion", "value": "4.5.7"}],
            },
        ]
        trivy = _trivy_doc(vulnerabilities=rich_vulns)
        self._write(self.syft_path, syft)
        self._write(self.trivy_path, trivy)

        result = _run_merger(self.syft_path, self.trivy_path, self.out_path)
        self.assertEqual(result.returncode, 0, msg=result.stderr)

        with open(self.out_path) as f:
            out = json.load(f)
        self.assertEqual(out["vulnerabilities"], rich_vulns)

    def test_real_file_smoke(self):
        if not (os.path.exists(REAL_SYFT) and os.path.exists(REAL_TRIVY)):
            self.skipTest(f"missing real artifacts at {REAL_SYFT} and/or {REAL_TRIVY}")

        result = _run_merger(REAL_SYFT, REAL_TRIVY, self.out_path)
        self.assertEqual(result.returncode, 0, msg=result.stderr)

        with open(REAL_SYFT) as f:
            syft_in = json.load(f, strict=False)
        with open(self.out_path) as f:
            out = json.load(f)

        self.assertEqual(len(out["components"]), 2356)
        self.assertEqual(len(out["dependencies"]), 83)
        self.assertEqual(len(out["vulnerabilities"]), 4)
        self.assertEqual(out["metadata"]["properties"], syft_in["metadata"]["properties"])
        self.assertEqual(out["metadata"]["tools"]["components"][0]["name"], "syft")
        self.assertEqual(out["specVersion"], "1.6")

        bom_refs = {c.get("bom-ref") for c in out["components"] if c.get("bom-ref")}
        for vuln in out["vulnerabilities"]:
            for affect in vuln.get("affects", []):
                self.assertIn(affect["ref"], bom_refs)

    def test_aidriver_scale_smoke(self):
        if not (os.path.exists(AIDRIVER_SYFT) and os.path.exists(AIDRIVER_TRIVY)):
            self.skipTest(
                f"missing aidriver artifact at {AIDRIVER_SYFT} and/or {AIDRIVER_TRIVY} "
                "(workflow run 27942610904 has not landed yet)"
            )

        result = _run_merger(AIDRIVER_SYFT, AIDRIVER_TRIVY, self.out_path)
        self.assertEqual(result.returncode, 0, msg=result.stderr)

        with open(AIDRIVER_SYFT) as f:
            syft_in = json.load(f, strict=False)
        with open(self.out_path) as f:
            out = json.load(f)

        self.assertGreater(len(out["components"]), 60000)
        self.assertGreater(len(out["dependencies"]), 1000)
        self.assertGreater(len(out["vulnerabilities"]), 0)
        self.assertEqual(out["metadata"]["properties"], syft_in["metadata"]["properties"])

        bom_refs = {c.get("bom-ref") for c in out["components"] if c.get("bom-ref")}
        for vuln in out["vulnerabilities"]:
            for affect in vuln.get("affects", []):
                self.assertIn(affect["ref"], bom_refs)


if __name__ == "__main__":
    unittest.main()
