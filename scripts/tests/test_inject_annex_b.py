import json
import os
import subprocess
import sys
import tempfile
import unittest


REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SCRIPT = os.path.join(REPO_ROOT, "scripts", "inject-annex-b.py")

REAL_MERGED = "/tmp/sbom-artifact/merged.cdx.json"


def _merged_doc(components=None, metadata_overrides=None):
    metadata = {
        "timestamp": "2025-06-01T12:00:00Z",
        "tools": {"components": [{"type": "application", "name": "syft", "version": "1.42.3"}]},
        "component": {"type": "container", "name": "imagryhub/aidriver", "version": "Dev-0.10"},
        "properties": [
            {"name": "syft:image:labels:org.opencontainers.image.title", "value": "aidriver"},
        ],
    }
    if metadata_overrides:
        for k, v in metadata_overrides.items():
            metadata[k] = v
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:33333333-3333-3333-3333-333333333333",
        "version": 1,
        "metadata": metadata,
        "components": components if components is not None else [],
        "dependencies": [],
    }


def _run_injector(in_path, out_path):
    return subprocess.run(
        [sys.executable, SCRIPT, in_path, out_path],
        capture_output=True,
        text=True,
    )


def _find_prop(props, name):
    for p in props or []:
        if p.get("name") == name:
            return p.get("value")
    return None


def _has_prop(props, name):
    for p in props or []:
        if p.get("name") == name:
            return True
    return False


class InjectAnnexBTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.in_path = os.path.join(self.tmp.name, "in.cdx.json")
        self.out_path = os.path.join(self.tmp.name, "out.cdx.json")

    def _write(self, path, doc):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(doc, f)

    def test_document_level_injection(self):
        doc = _merged_doc()
        self._write(self.in_path, doc)

        result = _run_injector(self.in_path, self.out_path)
        self.assertEqual(result.returncode, 0, msg=result.stderr)

        with open(self.out_path) as f:
            out = json.load(f)

        props = out["metadata"]["properties"]
        self.assertEqual(
            _find_prop(props, "imagry:annex-b:date-of-acquisition"),
            "2025-06-01T12:00:00Z",
        )
        self.assertEqual(
            _find_prop(props, "imagry:annex-b:image-ref"),
            "imagryhub/aidriver:Dev-0.10",
        )
        self.assertEqual(_find_prop(props, "imagry:annex-b:product-name"), "aidriver")
        self.assertEqual(_find_prop(props, "imagry:annex-b:product-version"), "Dev-0.10")
        self.assertEqual(_find_prop(props, "imagry:annex-b:modifications"), "none")
        self.assertEqual(
            _find_prop(props, "syft:image:labels:org.opencontainers.image.title"),
            "aidriver",
        )

    def test_per_library_source_derivation(self):
        components = [
            {"type": "library", "name": "libdeb", "purl": "pkg:deb/ubuntu/libdeb@1.0.0"},
            {"type": "library", "name": "librpm", "purl": "pkg:rpm/fedora/librpm@1.0.0"},
            {"type": "library", "name": "libapk", "purl": "pkg:apk/alpine/libapk@1.0.0"},
            {"type": "library", "name": "libpypi", "purl": "pkg:pypi/libpypi@1.0.0"},
            {"type": "library", "name": "libnpm", "purl": "pkg:npm/libnpm@1.0.0"},
            {"type": "library", "name": "libgolang", "purl": "pkg:golang/example.com/libgolang@v1.0.0"},
            {"type": "library", "name": "libcargo", "purl": "pkg:cargo/libcargo@1.0.0"},
            {"type": "library", "name": "libgem", "purl": "pkg:gem/libgem@1.0.0"},
            {"type": "library", "name": "libmaven", "purl": "pkg:maven/org.example/libmaven@1.0.0"},
            {"type": "library", "name": "libgeneric", "purl": "pkg:generic/libgeneric@1.0.0"},
            {"type": "library", "name": "libcomposer", "purl": "pkg:composer/foo/bar@1.0.0"},
            {
                "type": "library",
                "name": "libsyftpy",
                "properties": [{"name": "syft:package:type", "value": "python"}],
            },
            {"type": "library", "name": "libunknown"},
        ]
        doc = _merged_doc(components=components)
        self._write(self.in_path, doc)

        result = _run_injector(self.in_path, self.out_path)
        self.assertEqual(result.returncode, 0, msg=result.stderr)

        with open(self.out_path) as f:
            out = json.load(f)

        by_name = {c["name"]: c for c in out["components"]}
        expectations = {
            "libdeb": "OS package (Debian/Ubuntu)",
            "librpm": "OS package (RPM)",
            "libapk": "OS package (Alpine)",
            "libpypi": "Open source Python library",
            "libnpm": "Open source npm library",
            "libgolang": "Open source Go library",
            "libcargo": "Open source Rust crate",
            "libgem": "Open source Ruby gem",
            "libmaven": "Open source Java/Maven library",
            "libgeneric": "Open source library (generic)",
            "libcomposer": "Open source library (composer)",
            "libsyftpy": "Open source library (python)",
            "libunknown": "Unknown source",
        }
        for name, expected in expectations.items():
            self.assertIn(name, by_name)
            actual = _find_prop(by_name[name].get("properties", []), "imagry:annex-b:source")
            self.assertEqual(actual, expected, msg=f"{name}: got {actual!r}")

    def test_idempotency(self):
        components = [
            {"type": "library", "name": "libdeb", "purl": "pkg:deb/ubuntu/libdeb@1.0.0"},
            {"type": "library", "name": "libpypi", "purl": "pkg:pypi/libpypi@1.0.0"},
            {"type": "library", "name": "libnpm", "purl": "pkg:npm/libnpm@1.0.0"},
            {"type": "library", "name": "libunknown"},
        ]
        doc = _merged_doc(components=components)
        self._write(self.in_path, doc)

        first_out = os.path.join(self.tmp.name, "first.cdx.json")
        second_out = os.path.join(self.tmp.name, "second.cdx.json")

        result1 = _run_injector(self.in_path, first_out)
        self.assertEqual(result1.returncode, 0, msg=result1.stderr)

        result2 = _run_injector(first_out, second_out)
        self.assertEqual(result2.returncode, 0, msg=result2.stderr)

        with open(first_out, "rb") as f:
            first_bytes = f.read()
        with open(second_out, "rb") as f:
            second_bytes = f.read()
        self.assertEqual(first_bytes, second_bytes)

    def test_non_library_components_skipped(self):
        components = [
            {"type": "library", "name": "libfoo", "purl": "pkg:deb/ubuntu/libfoo@1.0.0"},
            {"type": "file", "name": "/etc/passwd"},
            {"type": "operating-system", "name": "ubuntu", "version": "24.04"},
            {"type": "application", "name": "someapp", "version": "0.1"},
        ]
        doc = _merged_doc(components=components)
        self._write(self.in_path, doc)

        result = _run_injector(self.in_path, self.out_path)
        self.assertEqual(result.returncode, 0, msg=result.stderr)

        with open(self.out_path) as f:
            out = json.load(f)

        by_name = {c["name"]: c for c in out["components"]}
        self.assertTrue(
            _has_prop(by_name["libfoo"].get("properties", []), "imagry:annex-b:source")
        )
        for skipped_name in ("/etc/passwd", "ubuntu", "someapp"):
            comp = by_name[skipped_name]
            self.assertFalse(
                _has_prop(comp.get("properties", []), "imagry:annex-b:source"),
                msg=f"{skipped_name} should not have imagry:annex-b:source",
            )

    def test_real_file_smoke(self):
        if not os.path.exists(REAL_MERGED):
            self.skipTest(f"missing real merged artifact at {REAL_MERGED}")

        result = _run_injector(REAL_MERGED, self.out_path)
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertEqual(
            result.stdout.strip(),
            "injected Annex B metadata: 5 document-level keys, 92 components updated",
        )

        with open(self.out_path) as f:
            out = json.load(f)

        props = out["metadata"]["properties"]
        for key in (
            "imagry:annex-b:date-of-acquisition",
            "imagry:annex-b:image-ref",
            "imagry:annex-b:product-name",
            "imagry:annex-b:product-version",
            "imagry:annex-b:modifications",
        ):
            self.assertIsNotNone(_find_prop(props, key), msg=f"missing {key}")

        self.assertEqual(_find_prop(props, "imagry:annex-b:image-ref"), "ubuntu:24.04")
        self.assertEqual(_find_prop(props, "imagry:annex-b:product-name"), "ubuntu")

        lib_with_deb = 0
        file_with_source = 0
        os_with_source = 0
        for comp in out["components"]:
            ctype = comp.get("type")
            source = _find_prop(comp.get("properties", []), "imagry:annex-b:source")
            if ctype == "library" and source == "OS package (Debian/Ubuntu)":
                lib_with_deb += 1
            if ctype == "file" and source is not None:
                file_with_source += 1
            if ctype == "operating-system" and source is not None:
                os_with_source += 1
        self.assertEqual(lib_with_deb, 92)
        self.assertEqual(file_with_source, 0)
        self.assertEqual(os_with_source, 0)

        self.assertEqual(len(out["components"]), 2356)
        self.assertEqual(len(out["dependencies"]), 83)
        self.assertEqual(len(out["vulnerabilities"]), 4)
        self.assertEqual(out["metadata"]["tools"]["components"][0]["name"], "syft")
        self.assertEqual(out["specVersion"], "1.6")


if __name__ == "__main__":
    unittest.main()
