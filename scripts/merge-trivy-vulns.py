"""Graft Trivy vulnerabilities[] onto a Syft CycloneDX document."""

import copy
import json
import sys


def load(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f, strict=False)


def main(argv):
    if len(argv) != 4:
        print(
            "usage: merge-trivy-vulns.py <syft.cdx.json> <trivy.cdx.json> <output.cdx.json>",
            file=sys.stderr,
        )
        return 2

    syft_path, trivy_path, out_path = argv[1], argv[2], argv[3]

    syft = load(syft_path)
    trivy = load(trivy_path)

    syft_refs = {c.get("bom-ref") for c in syft.get("components", []) if c.get("bom-ref")}

    vulns = trivy.get("vulnerabilities", [])
    affects_count = 0
    for vuln in vulns:
        cve_id = vuln.get("id", "<unknown>")
        for affect in vuln.get("affects", []):
            ref = affect.get("ref")
            affects_count += 1
            if ref not in syft_refs:
                print(
                    f"drift detected: CVE {cve_id} has affects.ref {ref!r} not present in Syft bom-refs",
                    file=sys.stderr,
                )
                return 1

    output = copy.deepcopy(syft)
    output["vulnerabilities"] = vulns

    if output.get("serialNumber") != syft.get("serialNumber"):
        print("inventory drift: serialNumber changed", file=sys.stderr)
        return 1
    if output.get("specVersion") != syft.get("specVersion"):
        print("inventory drift: specVersion changed", file=sys.stderr)
        return 1
    if output.get("metadata") != syft.get("metadata"):
        print("inventory drift: metadata changed", file=sys.stderr)
        return 1
    if output.get("components") != syft.get("components"):
        print("inventory drift: components changed", file=sys.stderr)
        return 1
    if output.get("dependencies") != syft.get("dependencies"):
        print("inventory drift: dependencies changed", file=sys.stderr)
        return 1

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(output, f)

    print(f"merged {len(vulns)} vulnerabilities across {affects_count} (CVE, component) pairs")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
