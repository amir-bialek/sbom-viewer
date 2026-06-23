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


_SUFFIX_BY_LENGTH = (
    (".trivy.cdx.json", View.TRIVY),
    (".enriched.cdx.json", View.MERGED),
    (".cdx.json", View.SBOM),
)


def list_sboms() -> list[dict]:
    if not STORAGE_PATH.exists():
        return []

    grouped: dict[str, dict[View, Path]] = {}
    for f in STORAGE_PATH.rglob("*.cdx.json"):
        rel = str(f.relative_to(STORAGE_PATH))
        for suffix, view in _SUFFIX_BY_LENGTH:
            if rel.endswith(suffix):
                sbom_id = rel[: -len(suffix)]
                grouped.setdefault(sbom_id, {})[view] = f
                break

    results = []
    for sbom_id in sorted(grouped):
        paths = grouped[sbom_id]
        has_raw = View.SBOM in paths
        has_merged = View.MERGED in paths
        has_trivy = View.TRIVY in paths

        ts_view = View.SBOM if has_raw else View.MERGED if has_merged else View.TRIVY
        data = _load_and_cache((sbom_id, ts_view.value), paths[ts_view])
        timestamp = data.get("metadata", {}).get("timestamp", "")

        parts = sbom_id.rsplit("/", 1)
        image = parts[0] if len(parts) > 1 else sbom_id
        version = parts[1] if len(parts) > 1 else ""

        results.append({
            "id": sbom_id,
            "image": image,
            "version": version,
            "timestamp": timestamp,
            "has_sbom": has_raw or has_merged,
            "has_trivy": has_trivy,
            "has_merged": has_merged,
        })

    return results


def download_sbom(sbom_id: str, view: View = View.SBOM) -> dict | None:
    path = _path_for(sbom_id, view)
    if path.exists():
        return _load_and_cache((sbom_id, view.value), path)
    if view == View.SBOM:
        fallback = _path_for(sbom_id, View.MERGED)
        if fallback.exists():
            return _load_and_cache((sbom_id, View.MERGED.value), fallback)
    return None
