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
