"""Inject Annex B compliance metadata as CycloneDX properties into a merged SBOM."""

import copy
import json
import sys


PURL_SOURCE_MAP = {
    "deb": "apt",
    "rpm": "rpm",
    "apk": "apk",
    "pypi": "pypi",
    "npm": "npm",
    "golang": "golang",
    "cargo": "cargo",
    "gem": "gem",
    "maven": "maven",
    "generic": "generic",
}


# Kept in sync with backend/app/sbom_parser.py:CATALOGER_INSTALLED_VIA_MAP.
CATALOGER_INSTALLED_VIA_MAP = {
    "dpkg-db-cataloger": "apt",
    "apk-db-cataloger": "apk",
    "rpm-db-cataloger": "rpm",
    "rpm-file-cataloger": "rpm",
    "go-module-binary-cataloger": "go-binary",
    "go-module-file-cataloger": "go-source",
    "binary-classifier-cataloger": "copied-binary",
}


def load(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f, strict=False)


def upsert_property(props, name, value):
    for prop in props:
        if prop.get("name") == name:
            prop["value"] = value
            return
    props.append({"name": name, "value": value})


def purl_ecosystem(purl):
    if not isinstance(purl, str) or not purl.startswith("pkg:"):
        return None
    rest = purl[len("pkg:"):]
    slash = rest.find("/")
    if slash <= 0:
        return None
    return rest[:slash].lower()


def derive_source(component):
    purl = component.get("purl")
    eco = purl_ecosystem(purl)
    if eco is not None:
        if eco in PURL_SOURCE_MAP:
            return PURL_SOURCE_MAP[eco]
        return eco

    for prop in component.get("properties", []) or []:
        if prop.get("name") == "syft:package:type":
            return prop.get("value") or "generic"

    return "generic"


def _component_found_by(component):
    for prop in component.get("properties", []) or []:
        if prop.get("name") == "syft:package:foundBy":
            return prop.get("value") or ""
    return ""


def _component_location_paths(component):
    paths = []
    for prop in component.get("properties", []) or []:
        name = prop.get("name") or ""
        if name.startswith("syft:location:") and name.endswith(":path"):
            value = prop.get("value")
            if value:
                paths.append(value)
    evidence = component.get("evidence") or {}
    for occ in evidence.get("occurrences", []) or []:
        loc = occ.get("location")
        if isinstance(loc, str) and loc:
            paths.append(loc)
        elif isinstance(loc, dict):
            value = loc.get("path") or loc.get("file")
            if value:
                paths.append(value)
    return paths


def derive_installed_via(component):
    found_by = _component_found_by(component)
    if found_by in CATALOGER_INSTALLED_VIA_MAP:
        return CATALOGER_INSTALLED_VIA_MAP[found_by]

    paths = _component_location_paths(component)
    if "python" in found_by and any("/site-packages/" in p for p in paths):
        return "pip"
    if ("javascript" in found_by or "npm" in found_by) and any(
        "/node_modules/" in p for p in paths
    ):
        return "npm"

    return "unknown"


def product_name(image_name):
    if not isinstance(image_name, str):
        return ""
    segment = image_name.rsplit("/", 1)[-1]
    return segment


def inject_document_level(doc):
    metadata = doc.setdefault("metadata", {})
    if "properties" not in metadata or metadata["properties"] is None:
        metadata["properties"] = []
    props = metadata["properties"]

    component = metadata.get("component", {}) or {}
    name = component.get("name", "")
    version = component.get("version", "")
    timestamp = metadata.get("timestamp", "")

    entries = [
        ("imagry:annex-b:date-of-acquisition", timestamp),
        ("imagry:annex-b:image-ref", f"{name}:{version}"),
        ("imagry:annex-b:product-name", product_name(name)),
        ("imagry:annex-b:product-version", version),
        ("imagry:annex-b:modifications", "none"),
    ]

    for key, value in entries:
        upsert_property(props, key, value)

    return len(entries)


def inject_components(doc):
    updated = 0
    for component in doc.get("components", []) or []:
        if component.get("type") != "library":
            continue
        if "properties" not in component or component["properties"] is None:
            component["properties"] = []
        upsert_property(
            component["properties"],
            "imagry:annex-b:source",
            derive_source(component),
        )
        upsert_property(
            component["properties"],
            "imagry:annex-b:installed-via",
            derive_installed_via(component),
        )
        updated += 1
    return updated


def main(argv):
    if len(argv) != 3:
        print(
            "usage: inject-annex-b.py <input.cdx.json> <output.cdx.json>",
            file=sys.stderr,
        )
        return 2

    in_path, out_path = argv[1], argv[2]

    doc = load(in_path)
    output = copy.deepcopy(doc)

    doc_keys = inject_document_level(output)
    comp_updated = inject_components(output)

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(output, f)

    print(
        f"injected Annex B metadata: {doc_keys} document-level keys, {comp_updated} components updated"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
