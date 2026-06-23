# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

Two loosely-related deliverables share this repo:

1. **SBOM Viewer dashboard** — a FastAPI backend + Next.js frontend that visualizes CycloneDX SBOM files. The deployable artifacts are two Docker images (`bialekamir/sbom-viewer:backend-vX.Y.Z`, `frontend-vX.Y.Z`) and two Helm charts.
2. **SBOM enrichment composite action** — [actions/enrich-sbom/](actions/enrich-sbom/) wraps two Python scripts in [scripts/](scripts/) (`merge-trivy-vulns.py`, `inject-annex-b.py`) and is consumed by external callers via `amir-bialek/sbom-viewer/actions/enrich-sbom@enrich-sbom-vX.Y.Z`. It does not interact with the viewer at runtime.

When a change spans both, treat them as separate units — they have separate version tags, separate CI jobs, and no shared code.

## Local development

From the repo root:

```bash
docker compose up                       # builds + runs backend (:8000) and frontend (:3000); mounts data-sample/ into backend at /data
python3 -m unittest discover -s scripts/tests -v   # only the enrichment scripts have unit tests
```

Frontend dev workflow (inside [frontend/](frontend/)):

```bash
npm install
npm run dev      # next dev (no docker)
npm run lint
npm run build
```

There are no backend unit tests. The data-sample/ directory holds enough CycloneDX fixtures (including pre-enriched ones at `data-sample/ubuntu/24.04.*.cdx.json`) to exercise list/summary/components paths against a running backend.

## Architecture you can't infer from one file

### sbom_id is a path, not a UUID

The backend recursively scans `STORAGE_PATH` for `*.cdx.json` files and derives `sbom_id` from the relative path with both suffixes stripped. So `STORAGE_PATH/myorg/myimage/v1.0.0.cdx.json` → `sbom_id = "myorg/myimage/v1.0.0"`. The FastAPI routes use `{sbom_id:path}` because the id contains slashes; the Next.js proxy at [frontend/src/app/api/sboms/[...path]/route.ts](frontend/src/app/api/sboms/[...path]/route.ts) reconstructs the id from `params.path` by treating the last segment (or last two, when it's `components/grouped`) as the action and joining the rest. If you add a new backend endpoint, you must update the proxy's allow-list and the segment-splitting logic in parallel.

### Storage is "filesystem only" in code, "S3 in prod" via CSI

The backend never speaks S3 — see [backend/app/s3_client.py](backend/app/s3_client.py); the module name is misleading. It only does `open()` on local paths. In Kubernetes, the bucket is mounted as a read-only PVC (`sbom-viewer-storage`, storage class `s3-csi`) via the Mountpoint for Amazon S3 CSI driver, configured in [helm/sbom-viewer-backend/values.yaml](helm/sbom-viewer-backend/values.yaml). Locally, docker-compose bind-mounts [data-sample/](data-sample/) to `/data`. Don't add an S3 SDK dependency — the storage abstraction is "anything mounted at `STORAGE_PATH`".

### In-memory cache, 5-min TTL, 20-entry cap

[backend/app/s3_client.py](backend/app/s3_client.py) caches parsed SBOM dicts in a process-local dict with a 5-minute TTL and evicts the oldest entry when over 20 entries. `list_sboms()` populates the cache as a side effect (it reads `metadata.timestamp` from every file). Multi-pod deployments don't share this cache and there is no invalidation hook for newly uploaded SBOMs — they appear on the next directory scan but their parsed dict still respects the 5-minute TTL.

### Two components endpoints

`/api/sboms/{id}/components` returns raw filtered/paged components; `/api/sboms/{id}/components/grouped` deduplicates by `(name, version, type)` and aggregates `purls`, `licenses`, and `count` — the frontend dashboard uses the grouped variant by default (see [frontend/src/app/page.tsx](frontend/src/app/page.tsx)). Both share filter semantics (`type` exact match, `name` substring case-insensitive).

### Enrichment pipeline contract

[scripts/merge-trivy-vulns.py](scripts/merge-trivy-vulns.py) is paranoid by design: it grafts only Trivy's `vulnerabilities[]` onto the Syft document and refuses to write output if Trivy mutated `serialNumber`, `specVersion`, `metadata`, `components`, or `dependencies`, or if any `affects.ref` doesn't map to a Syft `bom-ref`. This is the inventory-integrity guard — if you change it, you're opting into trusting Trivy to redefine the SBOM identity, which is not what callers want.

[scripts/inject-annex-b.py](scripts/inject-annex-b.py) adds CycloneDX `properties` with the `imagry:annex-b:*` namespace at the document level (always) and per-component for `type == "library"` (source field derived from purl ecosystem via `PURL_SOURCE_MAP`). Don't rename the property prefix without updating downstream consumers — the namespace is the API.

The composite action calls those scripts via `${{ github.action_path }}/../../scripts/...`, so the scripts must remain at the repo root under `scripts/` for the action to work when checked out as `amir-bialek/sbom-viewer/actions/enrich-sbom@<tag>`.

## CI topology

[build-push.yml](.github/workflows/build-push.yml) handles two flows:

- `pull_request` → builds both `backend` and `frontend` images (matrix), `push: false`.
- `workflow_dispatch` (with `type` input) → bumps `${type}-vX.Y.Z` semver from existing git tags, builds and pushes both `${REPO}:${NEW_TAG}` and `${REPO}:${TYPE}-latest`, then creates and pushes a git tag. Tag-bump rule is `awk -F. 'BEGIN{OFS="."}{$NF+=1;print}'` — patch only.

[tests.yml](.github/workflows/tests.yml) runs only on changes to `scripts/`, `actions/`, or itself. The `action-self-test` job exercises the composite action end-to-end against an alpine:3.18 Syft fixture and asserts the output is valid CycloneDX.

[scan-image-sbom.yml](.github/workflows/scan-image-sbom.yml) is the user-facing entrypoint: a `workflow_dispatch` that takes a Docker Hub image, generates a Syft SBOM, optionally enriches with Trivy + Annex B, and uploads as an artifact. The `enrich-sbom` action is referenced by a pinned tag (`@enrich-sbom-v1.0.0`), not by `@main` — bump the tag when releasing changes to the action.

## Conventions

- Don't add an HTTP/S3 client to the backend — storage is filesystem-only by design.
- When adding a backend route or query param, also update [frontend/src/app/api/sboms/[...path]/route.ts](frontend/src/app/api/sboms/[...path]/route.ts) and the relevant TypeScript types in [frontend/src/types/SbomTypes.ts](frontend/src/types/SbomTypes.ts).
- Frontend image is `output: "standalone"` Next.js — see [frontend/next.config.ts](frontend/next.config.ts) and [frontend/Dockerfile](frontend/Dockerfile). The runner copies `.next/standalone` and runs `node server.js` via [frontend/docker-init.sh](frontend/docker-init.sh); regular `next start` is not used in the image.
- Enrichment scripts must stay pure-stdlib Python — the composite action uses `python3` directly without installing requirements.
