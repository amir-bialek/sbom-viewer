from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from .s3_client import download_sbom, list_sboms
from .sbom_parser import get_components, get_grouped_components, get_summary

app = FastAPI(title="SBOM Viewer API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/sboms")
def api_list_sboms():
    return list_sboms()


@app.get("/api/sboms/{sbom_id:path}/summary")
def api_sbom_summary(sbom_id: str):
    data = download_sbom(sbom_id)
    if not data:
        raise HTTPException(status_code=404, detail="SBOM not found")
    return get_summary(data)


@app.get("/api/sboms/{sbom_id:path}/components/grouped")
def api_sbom_components_grouped(
    sbom_id: str,
    type: str | None = Query(None),
    name: str | None = Query(None),
    offset: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
):
    data = download_sbom(sbom_id)
    if not data:
        raise HTTPException(status_code=404, detail="SBOM not found")
    return get_grouped_components(data, type_filter=type, name_filter=name, offset=offset, limit=limit)


@app.get("/api/sboms/{sbom_id:path}/components")
def api_sbom_components(
    sbom_id: str,
    type: str | None = Query(None),
    name: str | None = Query(None),
    offset: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
):
    data = download_sbom(sbom_id)
    if not data:
        raise HTTPException(status_code=404, detail="SBOM not found")
    return get_components(data, type_filter=type, name_filter=name, offset=offset, limit=limit)
