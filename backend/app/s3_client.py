import json
import os
import time
from enum import Enum
from pathlib import Path

CACHE_TTL = 300
MAX_CACHE_ENTRIES = 20

_cache: dict[tuple[str, str], tuple[float, dict]] = {}

STORAGE_PATH = Path(os.environ.get("STORAGE_PATH", "/app/storage"))


class View(str, Enum):
    SBOM = "sbom"
    TRIVY = "trivy"
    MERGED = "merged"


_VIEW_SUFFIX = {
    View.SBOM: ".cdx.json",
    View.TRIVY: ".trivy.cdx.json",
    View.MERGED: ".enriched.cdx.json",
}


def _evict_cache():
    if len(_cache) > MAX_CACHE_ENTRIES:
        oldest_key = min(_cache, key=lambda k: _cache[k][0])
        del _cache[oldest_key]


def _load_and_cache(key: tuple[str, str], path: Path) -> dict:
    now = time.time()
    if key in _cache:
        ts, data = _cache[key]
        if now - ts < CACHE_TTL:
            return data

    with open(path) as f:
        data = json.load(f)
    _cache[key] = (now, data)
    _evict_cache()
    return data


def _path_for(sbom_id: str, view: View) -> Path:
    return STORAGE_PATH / f"{sbom_id}{_VIEW_SUFFIX[view]}"


def list_sboms() -> list[dict]:
    results = []
    if not STORAGE_PATH.exists():
        return results

    for f in sorted(STORAGE_PATH.rglob("*.cdx.json")):
        name = f.name
        if name.endswith(".trivy.cdx.json") or name.endswith(".enriched.cdx.json"):
            continue

        rel = f.relative_to(STORAGE_PATH)
        sbom_id = str(rel.with_suffix("").with_suffix(""))
        parts = sbom_id.rsplit("/", 1)
        image = parts[0] if len(parts) > 1 else sbom_id
        version = parts[1] if len(parts) > 1 else ""

        data = _load_and_cache((sbom_id, View.SBOM.value), f)
        timestamp = data.get("metadata", {}).get("timestamp", "")

        trivy_path = _path_for(sbom_id, View.TRIVY)
        merged_path = _path_for(sbom_id, View.MERGED)

        results.append({
            "id": sbom_id,
            "image": image,
            "version": version,
            "timestamp": timestamp,
            "has_sbom": True,
            "has_trivy": trivy_path.exists(),
            "has_merged": merged_path.exists(),
        })

    return results


def download_sbom(sbom_id: str, view: View = View.SBOM) -> dict | None:
    path = _path_for(sbom_id, view)
    if not path.exists():
        return None

    key = (sbom_id, view.value)
    return _load_and_cache(key, path)
