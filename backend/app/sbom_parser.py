from typing import Any


def parse_metadata(data: dict) -> dict:
    metadata = data.get("metadata", {})
    component = metadata.get("component", {})
    tools = metadata.get("tools", {})
    tool_name = ""
    tool_components = tools.get("components", [])
    if tool_components:
        t = tool_components[0]
        tool_name = f"{t.get('name', '')} {t.get('version', '')}".strip()

    return {
        "image": component.get("name", ""),
        "version": component.get("version", ""),
        "timestamp": metadata.get("timestamp", ""),
        "tool": tool_name,
    }


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
        if key in groups:
            groups[key]["count"] += 1
            purl = c.get("purl", "")
            if purl and purl not in groups[key]["purls"]:
                groups[key]["purls"].append(purl)
            for lic in _extract_licenses(c):
                if lic not in groups[key]["licenses"]:
                    groups[key]["licenses"].append(lic)
        else:
            purl = c.get("purl", "")
            groups[key] = {
                "name": c.get("name", ""),
                "version": c.get("version", ""),
                "type": c.get("type", ""),
                "licenses": _extract_licenses(c),
                "purls": [purl] if purl else [],
                "count": 1,
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
            }
            for c in page
        ],
    }
