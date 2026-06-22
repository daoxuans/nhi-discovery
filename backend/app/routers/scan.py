"""Scan API — 主动发现扫描（Phase 3 实现，Phase 1 占位）。"""

import logging

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/scan", tags=["scan"])


@router.post("/trigger")
async def trigger_scan(request: Request, body: dict = None):
    return JSONResponse(
        {"detail": "Not implemented in Phase 1 — Scan module arrives in Phase 3"},
        status_code=501,
    )


@router.get("/task/{task_id}")
async def get_scan_task(request: Request, task_id: int):
    db = request.app.state.db
    task = db.get_scan_task(task_id)
    if not task:
        return JSONResponse({"detail": "task not found"}, status_code=404)
    return task


@router.get("/findings")
async def list_scan_findings(
    request: Request,
    ip: str = Query(None),
    service: str = Query(None),
    port: int = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    db = request.app.state.db
    findings = db.search_scan_findings(
        ip=ip, service=service, port=port, limit=limit, offset=offset
    )
    return {"findings": findings, "total": len(findings)}


@router.get("/services")
async def list_scan_services(
    request: Request,
    vendor: str = Query(None),
    svc_type: str = Query(None),
    ip: str = Query(None),
    limit: int = Query(100, ge=1, le=500),
):
    db = request.app.state.db
    services = db.list_ai_services(
        vendor=vendor, svc_type=svc_type, ip=ip, limit=limit
    )
    return {"services": services, "total": len(services)}


@router.get("/cve")
async def list_scan_cves(
    request: Request,
    service: str = Query(None),
    severity: str = Query(None),
    limit: int = Query(50, ge=1, le=500),
):
    db = request.app.state.db
    cves = db.search_cves(service=service, severity=severity, limit=limit)
    return {"cves": cves, "total": len(cves)}
