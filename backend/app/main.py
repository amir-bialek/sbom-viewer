from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from .s3_client import View, download_sbom, list_sboms
from .sbom_parser import (
    get_components,
    get_grouped_components,
    get_summary,
    get_vulnerability_counts,
    get_vulnerability_detail,
    has_annex_b,
    parse_annex_b,
    parse_vulnerabilities,
)

app = FastAPI(title="SBOM Viewer API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def _parse_view(view: str) -> View:
    try:
        return View(view)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"invalid view '{view}' (expected one of: sbom, trivy, merged)",
        )


def _load(sbom_id: str, view: View) -> dict:
    data = download_sbom(sbom_id, view)
    if not data:
        raise HTTPException(status_code=404, detail="SBOM not found")
    return data


@app.get("/api/sboms")
def api_list_sboms():
    return list_sboms()


@app.get("/api/sboms/{sbom_id:path}/summary")
def api_sbom_summary(
    sbom_id: str,
    view: str = Query("sbom"),
):
    v = _parse_view(view)
    data = _load(sbom_id, v)
    summary = get_summary(data)
    if v in (View.TRIVY, View.MERGED):
        summary["vulnerability_counts"] = get_vulnerability_counts(data)
    if v == View.MERGED:
        summary["annex_b"] = parse_annex_b(data)
    return summary


@app.get("/api/sboms/{sbom_id:path}/components/grouped")
def api_sbom_components_grouped(
    sbom_id: str,
    view: str = Query("sbom"),
    type: str | None = Query(None),
    name: str | None = Query(None),
    offset: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
):
    v = _parse_view(view)
    data = _load(sbom_id, v)
    return get_grouped_components(data, type_filter=type, name_filter=name, offset=offset, limit=limit)


@app.get("/api/sboms/{sbom_id:path}/components")
def api_sbom_components(
    sbom_id: str,
    view: str = Query("sbom"),
    type: str | None = Query(None),
    name: str | None = Query(None),
    offset: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
):
    v = _parse_view(view)
    data = _load(sbom_id, v)
    return get_components(data, type_filter=type, name_filter=name, offset=offset, limit=limit)


@app.get("/api/sboms/{sbom_id:path}/vulnerabilities")
def api_sbom_vulnerabilities(
    sbom_id: str,
    view: str = Query("trivy"),
):
    v = _parse_view(view)
    if v == View.SBOM:
        raise HTTPException(
            status_code=400,
            detail="vulnerabilities require view=trivy or view=merged",
        )
    data = _load(sbom_id, v)
    return {"vulnerabilities": parse_vulnerabilities(data)}


@app.get("/api/sboms/{sbom_id:path}/vulnerabilities/{cve_id}")
def api_sbom_vulnerability_detail(
    sbom_id: str,
    cve_id: str,
    view: str = Query("trivy"),
):
    v = _parse_view(view)
    if v == View.SBOM:
        raise HTTPException(
            status_code=400,
            detail="vulnerabilities require view=trivy or view=merged",
        )
    data = _load(sbom_id, v)
    detail = get_vulnerability_detail(data, cve_id)
    if detail is None:
        raise HTTPException(status_code=404, detail="vulnerability not found")
    return detail


@app.get("/api/sboms/{sbom_id:path}/annex-b")
def api_sbom_annex_b(sbom_id: str):
    data = download_sbom(sbom_id, View.MERGED)
    if not data:
        raise HTTPException(status_code=404, detail="merged SBOM not found")
    if not has_annex_b(data):
        raise HTTPException(
            status_code=400,
            detail="file is not a merged SBOM (no Annex B fields)",
        )
    return parse_annex_b(data)
