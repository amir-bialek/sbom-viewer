from typing import Any

ANNEX_B_PREFIX = "imagry:annex-b:"
ANNEX_B_FIELDS = (
    "date-of-acquisition",
    "image-ref",
    "product-name",
    "product-version",
    "modifications",
)


def parse_metadata(data: dict) -> dict:
    metadata = data.get("metadata", {})
    component = metadata.get("component", {})
    tools = metadata.get("tools", {})
    tool_name = ""
    tool_components = tools.get("components", []) if isinstance(tools, dict) else []
    if tool_components:
        t = tool_components[0]
        tool_name = f"{t.get('name', '')} {t.get('version', '')}".strip()

    return {
        "image": component.get("name", ""),
        "version": component.get("version", ""),
        "timestamp": metadata.get("timestamp", ""),
        "tool": tool_name,
    }


def _component_annex_b_source(component: dict) -> str:
    for prop in component.get("properties", []) or []:
        if prop.get("name") == f"{ANNEX_B_PREFIX}source":
            return prop.get("value", "") or ""
    return ""


def get_summary(data: dict) -> dict:
    meta = parse_metadata(data)
    components = data.get("components", [])

    by_type: dict[str, int] = {}
    with_licenses = 0
    with_purl = 0

    for c in components:
        ctype = c.get("type", "unknown")
        by_type[ctype] = by_type.get(ctype, 0) + 1
        if c.get("licenses"):
            with_licenses += 1
        if c.get("purl"):
            with_purl += 1

    return {
        **meta,
        "total_components": len(components),
        "by_type": by_type,
        "with_licenses": with_licenses,
        "with_purl": with_purl,
    }


def _extract_licenses(component: dict) -> list[str]:
    licenses = []
    for entry in component.get("licenses", []):
        lic = entry.get("license", {})
        lid = lic.get("id") or lic.get("name", "")
        if lid:
            licenses.append(lid)
    return licenses


def get_grouped_components(
    data: dict,
    type_filter: str | None = None,
    name_filter: str | None = None,
    offset: int = 0,
    limit: int = 100,
) -> dict[str, Any]:
    components = data.get("components", [])

    filtered = components
    if type_filter:
        filtered = [c for c in filtered if c.get("type") == type_filter]
    if name_filter:
        name_lower = name_filter.lower()
        filtered = [c for c in filtered if name_lower in c.get("name", "").lower()]

    groups: dict[str, dict] = {}
    for c in filtered:
        key = f"{c.get('name', '')}|||{c.get('version', '')}|||{c.get('type', '')}"
        annex_source = _component_annex_b_source(c)
        if key in groups:
            groups[key]["count"] += 1
            purl = c.get("purl", "")
            if purl and purl not in groups[key]["purls"]:
                groups[key]["purls"].append(purl)
            for lic in _extract_licenses(c):
                if lic not in groups[key]["licenses"]:
                    groups[key]["licenses"].append(lic)
            if annex_source and not groups[key]["annex_b_source"]:
                groups[key]["annex_b_source"] = annex_source
        else:
            purl = c.get("purl", "")
            groups[key] = {
                "name": c.get("name", ""),
                "version": c.get("version", ""),
                "type": c.get("type", ""),
                "licenses": _extract_licenses(c),
                "purls": [purl] if purl else [],
                "count": 1,
                "annex_b_source": annex_source,
            }

    sorted_groups = sorted(groups.values(), key=lambda g: (-g["count"], g["name"]))
    total = len(sorted_groups)
    page = sorted_groups[offset : offset + limit]

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "components": page,
    }


def get_components(
    data: dict,
    type_filter: str | None = None,
    name_filter: str | None = None,
    offset: int = 0,
    limit: int = 100,
) -> dict[str, Any]:
    components = data.get("components", [])

    filtered = components
    if type_filter:
        filtered = [c for c in filtered if c.get("type") == type_filter]
    if name_filter:
        name_lower = name_filter.lower()
        filtered = [c for c in filtered if name_lower in c.get("name", "").lower()]

    total = len(filtered)
    page = filtered[offset : offset + limit]

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "components": [
            {
                "name": c.get("name", ""),
                "version": c.get("version", ""),
                "type": c.get("type", ""),
                "purl": c.get("purl", ""),
                "licenses": _extract_licenses(c),
                "annex_b_source": _component_annex_b_source(c),
            }
            for c in page
        ],
    }


def pick_severity(ratings: list[dict], source_name: str | None) -> tuple[str, float | None]:
    """Return (severity, score) per D1.

    1. Prefer the rating whose source.name == source_name; else
    2. The rating with the highest CVSSv3.1 score; else
    3. The first non-empty severity string.
    Score is the highest CVSSv3.1 score across all ratings regardless of source.
    """
    if not ratings:
        return ("", None)

    # CVSS = highest CVSSv3.1 score across all ratings
    cvss = None
    for r in ratings:
        if r.get("method") == "CVSSv31" and isinstance(r.get("score"), (int, float)):
            if cvss is None or r["score"] > cvss:
                cvss = float(r["score"])

    # Rule 1: matching source
    if source_name:
        for r in ratings:
            src = (r.get("source") or {}).get("name", "")
            if src == source_name:
                sev = r.get("severity") or ""
                return (sev, cvss)

    # Rule 2: highest CVSSv3.1 score wins
    best = None
    best_score = None
    for r in ratings:
        if r.get("method") == "CVSSv31" and isinstance(r.get("score"), (int, float)):
            if best_score is None or r["score"] > best_score:
                best_score = float(r["score"])
                best = r
    if best is not None:
        return (best.get("severity") or "", cvss)

    # Rule 3: first non-empty severity
    for r in ratings:
        sev = r.get("severity") or ""
        if sev:
            return (sev, cvss)

    return ("", cvss)


def _fixed_version_from_affects(affects: list[dict]) -> str:
    for a in affects or []:
        for v in a.get("versions", []) or []:
            if v.get("status") == "unaffected" and v.get("version"):
                return v["version"]
    return ""


def _component_index(data: dict) -> dict[str, dict]:
    idx: dict[str, dict] = {}
    for c in data.get("components", []) or []:
        ref = c.get("bom-ref")
        if ref:
            idx[ref] = c
    return idx


def parse_vulnerabilities(data: dict) -> list[dict]:
    """Return normalized vulnerability rows, one per CVE (D2).

    Each row has:
      id, severity, score, source, fixed_version, description, published,
      affected_components: [{name, version, purl, bom_ref}]
    """
    vulns = data.get("vulnerabilities", []) or []
    if not vulns:
        return []

    cidx = _component_index(data)
    rows: list[dict] = []
    for v in vulns:
        ratings = v.get("ratings", []) or []
        source_name = (v.get("source") or {}).get("name", "") or None
        severity, score = pick_severity(ratings, source_name)

        affected: list[dict] = []
        for a in v.get("affects", []) or []:
            ref = a.get("ref", "")
            comp = cidx.get(ref, {})
            affected.append({
                "name": comp.get("name", ""),
                "version": comp.get("version", ""),
                "purl": comp.get("purl", ""),
                "bom_ref": ref,
            })

        rows.append({
            "id": v.get("id", ""),
            "severity": severity,
            "score": score,
            "source": source_name or "",
            "fixed_version": _fixed_version_from_affects(v.get("affects", [])),
            "description": v.get("description", ""),
            "published": v.get("published", ""),
            "updated": v.get("updated", ""),
            "affected_components": affected,
        })

    return rows


def get_vulnerability_counts(data: dict) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    for row in parse_vulnerabilities(data):
        sev = (row.get("severity") or "").lower()
        if sev in counts:
            counts[sev] += 1
        else:
            counts["unknown"] += 1
    return counts


def get_vulnerability_detail(data: dict, cve_id: str) -> dict | None:
    vulns = data.get("vulnerabilities", []) or []
    for v in vulns:
        if v.get("id") == cve_id:
            ratings = v.get("ratings", []) or []
            source_name = (v.get("source") or {}).get("name", "") or None
            severity, score = pick_severity(ratings, source_name)

            cidx = _component_index(data)
            affected = []
            for a in v.get("affects", []) or []:
                ref = a.get("ref", "")
                comp = cidx.get(ref, {})
                affected.append({
                    "name": comp.get("name", ""),
                    "version": comp.get("version", ""),
                    "purl": comp.get("purl", ""),
                    "bom_ref": ref,
                    "versions": a.get("versions", []) or [],
                })

            return {
                "id": v.get("id", ""),
                "severity": severity,
                "score": score,
                "source": source_name or "",
                "fixed_version": _fixed_version_from_affects(v.get("affects", [])),
                "description": v.get("description", ""),
                "published": v.get("published", ""),
                "updated": v.get("updated", ""),
                "cwes": v.get("cwes", []) or [],
                "advisories": v.get("advisories", []) or [],
                "ratings": ratings,
                "affected_components": affected,
            }
    return None


def parse_annex_b(data: dict) -> dict[str, str]:
    """Return the five imagry:annex-b:* document-level fields.

    Keys are snake_case derived from the property suffix.
    Missing fields default to empty string.
    """
    result = {
        "date_of_acquisition": "",
        "image_ref": "",
        "product_name": "",
        "product_version": "",
        "modifications": "",
    }
    props = (data.get("metadata") or {}).get("properties", []) or []
    for p in props:
        name = p.get("name", "")
        if not name.startswith(ANNEX_B_PREFIX):
            continue
        suffix = name[len(ANNEX_B_PREFIX):]
        if suffix in ANNEX_B_FIELDS:
            result[suffix.replace("-", "_")] = p.get("value", "") or ""
    return result


def has_annex_b(data: dict) -> bool:
    props = (data.get("metadata") or {}).get("properties", []) or []
    for p in props:
        if (p.get("name") or "").startswith(ANNEX_B_PREFIX):
            return True
    return False


def parse_dependencies(data: dict) -> dict[str, list[str]]:
    """Return {ref: [child_refs]} adjacency map. Empty when missing."""
    deps = data.get("dependencies", []) or []
    result: dict[str, list[str]] = {}
    for d in deps:
        ref = d.get("ref")
        if not ref:
            continue
        result[ref] = list(d.get("dependsOn", []) or [])
    return result
