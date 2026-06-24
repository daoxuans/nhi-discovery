"""Scan API — 主动发现扫描（Phase 3 实现）。"""

import asyncio
import logging

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.core.db import Database, now_cst
from app.scan.target_manager import list_targets
from app.scan.scan_runner import create_scan_task, run_scan_with_taskid

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/scan", tags=["scan"])

_running_tasks: dict = {}


class TriggerBody(BaseModel):
    target_id: int = None
    cidr: str = None
    scan_strategy: str = "full"


def _get_db(request: Request) -> Database:
    return request.app.state.db


@router.post("/trigger")
async def trigger_scan(request: Request, body: TriggerBody = None):
    """手动触发扫描。"""
    db = _get_db(request)
    body = body or TriggerBody()
    try:
        task_id, task_uuid, cidr, target = create_scan_task(
            db, body.target_id, body.cidr, "manual"
        )
    except ValueError as e:
        return JSONResponse({"detail": str(e)}, status_code=400)

    async def _bg():
        try:
            await run_scan_with_taskid(db, task_id, target, cidr, "manual")
        except Exception as e:
            logger.error(f"bg scan {task_id} failed: {e}", exc_info=True)
            db.update_scan_task(task_id, status="failed", finished_at=now_cst(),
                                error_msg=str(e))

    _running_tasks[task_id] = asyncio.create_task(_bg())
    return {"task_id": task_id, "task_uuid": task_uuid, "status": "queued", "cidr": cidr}


@router.get("/task/{task_id}")
async def get_scan_task(request: Request, task_id: int):
    db = _get_db(request)
    task = db.get_scan_task(task_id)
    if not task:
        return JSONResponse({"detail": "task not found"}, status_code=404)
    return task


@router.get("/tasks")
async def list_scan_tasks(request: Request, limit: int = Query(20, ge=1, le=100),
                          offset: int = Query(0, ge=0)):
    db = _get_db(request)
    with db.lock:
        rows = db.conn.execute(
            "SELECT * FROM scan_tasks ORDER BY created_at DESC LIMIT ? OFFSET ?", (limit, offset)
        ).fetchall()
        total = db.conn.execute("SELECT COUNT(*) FROM scan_tasks").fetchone()[0]
    return {"tasks": [dict(r) for r in rows], "total": total}


@router.get("/findings")
async def list_scan_findings(
    request: Request,
    ip: str = Query(None),
    service: str = Query(None),
    port: int = Query(None),
    task_id: int = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    db = _get_db(request)
    findings = db.search_scan_findings(
        ip=ip, service=service, port=port, task_id=task_id,
        limit=limit, offset=offset,
    )
    total = db.count_scan_findings(ip=ip, service=service, port=port, task_id=task_id)
    return {"findings": findings, "total": total, "limit": limit, "offset": offset}


@router.get("/services")
async def list_scan_services(
    request: Request,
    vendor: str = Query(None),
    svc_type: str = Query(None),
    ip: str = Query(None),
    lifecycle_state: str = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    db = _get_db(request)
    services = db.list_ai_services(
        vendor=vendor, svc_type=svc_type, ip=ip,
        lifecycle_state=lifecycle_state, limit=limit, offset=offset,
    )
    total = db.count_ai_services(vendor=vendor, svc_type=svc_type, ip=ip,
                                 lifecycle_state=lifecycle_state)
    return {"services": services, "total": total, "limit": limit, "offset": offset}


@router.get("/cve")
async def list_scan_cves(
    request: Request,
    service: str = Query(None),
    severity: str = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    db = _get_db(request)
    cves = db.search_cves(service=service, severity=severity, limit=limit, offset=offset)
    total = db.count_cves(service=service, severity=severity)
    return {"cves": cves, "total": total, "limit": limit, "offset": offset}


@router.get("/targets")
async def list_scan_targets(request: Request, enabled_only: bool = False):
    db = _get_db(request)
    return {"targets": list_targets(db, enabled_only=enabled_only)}
