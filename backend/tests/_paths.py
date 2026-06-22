"""Shared path helpers for backend tests.

Importing this module adds the backend/ directory to sys.path so test
modules can do `from app.sbom_parser import ...` regardless of CWD.
"""
import os
import sys

_BACKEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

REPO_ROOT = os.path.abspath(os.path.join(_BACKEND_DIR, ".."))
SAMPLE_DIR = os.path.join(REPO_ROOT, "data-sample", "ubuntu")

SAMPLE_RAW = os.path.join(SAMPLE_DIR, "24.04.cdx.json")
SAMPLE_TRIVY = os.path.join(SAMPLE_DIR, "24.04.trivy.cdx.json")
SAMPLE_MERGED = os.path.join(SAMPLE_DIR, "24.04.enriched.cdx.json")
