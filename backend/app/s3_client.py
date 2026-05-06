import json
import os
import time
from pathlib import Path

CACHE_TTL = 300
MAX_CACHE_ENTRIES = 20

_cache: dict[str, tuple[float, dict]] = {}

STORAGE_PATH = Path(os.environ.get("STORAGE_PATH", "/app/storage"))


def _evict_cache():
    if len(_cache) > MAX_CACHE_ENTRIES:
        oldest_key = min(_cache, key=lambda k: _cache[k][0])
        del _cache[oldest_key]


def _load_and_cache(key: str, path: Path) -> dict:
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


def list_sboms() -> list[dict]:
    results = []
    if not STORAGE_PATH.exists():
        return results

    for f in sorted(STORAGE_PATH.rglob("*.cdx.json")):
        rel = f.relative_to(STORAGE_PATH)
        sbom_id = str(rel.with_suffix("").with_suffix(""))
        parts = sbom_id.rsplit("/", 1)
        image = parts[0] if len(parts) > 1 else sbom_id
        version = parts[1] if len(parts) > 1 else ""

        data = _load_and_cache(sbom_id, f)
        timestamp = data.get("metadata", {}).get("timestamp", "")

        results.append({
            "id": sbom_id,
            "image": image,
            "version": version,
            "timestamp": timestamp,
        })

    return results


def download_sbom(sbom_id: str) -> dict | None:
    now = time.time()
    if sbom_id in _cache:
        ts, data = _cache[sbom_id]
        if now - ts < CACHE_TTL:
            return data

    path = STORAGE_PATH / f"{sbom_id}.cdx.json"
    if not path.exists():
        return None

    return _load_and_cache(sbom_id, path)
