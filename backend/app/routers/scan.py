"""Scan API — 主动发现扫描（Phase 3 实现）。"""

import asyncio
import ipaddress
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

# 速率档位 → (nmap pps, per_target_qps, nmap -T)
_SPEED_PROFILES = {
    "slow":   (100,  5,  "-T2"),
    "normal": (500,  10, "-T3"),
    "fast":   (2000, 30, "-T4"),
}


class TriggerBody(BaseModel):
    target_id: int = None
    cidr: str = None
    scan_range: str = None   # IP / IP1-IP2 / CIDR（语义更清晰，向后兼容 cidr）
    scan_strategy: str = "full"
    speed: str = "normal"    # slow / normal / fast


class TargetBody(BaseModel):
    name: str = None
    cidr: str = None
    scan_strategy: str = None
    schedule_interval: int = None
    speed: str = None
    enabled: int = None


def _validate_scan_range(expr: str):
    """校验 IP / IP1-IP2 / CIDR 三种格式。返回 (ok, error_msg)。"""
    if not expr or not expr.strip():
        return False, "scan_range is empty"
    expr = expr.strip()
    # CIDR
    try:
        ipaddress.ip_network(expr, strict=False)
        return True, None
    except ValueError:
        pass
    # 单 IP
    try:
        ipaddress.ip_address(expr)
        return True, None
    except ValueError:
        pass
    # IP1-IP2 范围
    if "-" in expr:
        parts = expr.split("-", 1)
        try:
            a, b = ipaddress.ip_address(parts[0].strip()), ipaddress.ip_address(parts[1].strip())
            if a.version != b.version:
                return False, "IP range version mismatch"
            return True, None
        except ValueError:
            return False, f"invalid IP range: {expr}"
    return False, f"invalid scan range: {expr}"


def _get_db(request: Request) -> Database:
    return request.app.state.db


@router.post("/trigger")
async def trigger_scan(request: Request, body: TriggerBody = None):
    """手动触发扫描。支持 scan_range (IP/范围/CIDR) + speed 档位。"""
    db = _get_db(request)
    body = body or TriggerBody()

    # 解析扫描范围：优先 scan_range，回退 cidr
    scan_range = body.scan_range or body.cidr
    if scan_range:
        ok, err = _validate_scan_range(scan_range)
        if not ok:
            return JSONResponse({"detail": err}, status_code=400)
    # speed 校验
    if body.speed not in _SPEED_PROFILES:
        return JSONResponse({"detail": f"invalid speed: {body.speed}"}, status_code=400)

    try:
        task_id, task_uuid, cidr, target = create_scan_task(
            db, body.target_id, scan_range, "manual",
            speed=body.speed if scan_range else None,
            scan_strategy=body.scan_strategy if scan_range else None,
        )
    except ValueError as e:
        return JSONResponse({"detail": str(e)}, status_code=400)

    async def _bg():
        try:
            await run_scan_with_taskid(
                db, task_id, target, cidr, "manual",
                speed=body.speed if scan_range else None,
            )
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


@router.post("/targets")
async def create_target(request: Request, body: TargetBody):
    """创建定时扫描目标。校验 scan_range 格式。"""
    db = _get_db(request)
    if not body.name or not body.cidr:
        return JSONResponse({"detail": "name and cidr required"}, status_code=400)
    ok, err = _validate_scan_range(body.cidr)
    if not ok:
        return JSONResponse({"detail": err}, status_code=400)
    try:
        target_id = db.insert_scan_target(
            name=body.name, cidr=body.cidr,
            scan_strategy=body.scan_strategy or "ai_ports_only",
            full_interval=body.schedule_interval if body.schedule_interval is not None else 1800,
            incr_interval=300,
            enabled=body.enabled if body.enabled is not None else 0,
        )
    except Exception as e:
        return JSONResponse({"detail": str(e)}, status_code=400)
    # 持久化 speed（scan_targets 表有 speed 列时更新；无则忽略）
    if body.speed:
        db.update_scan_target(target_id, speed=body.speed)
    t = db.get_scan_target(target_id)
    return t


@router.patch("/targets/{target_id}")
async def update_target(request: Request, target_id: int, body: TargetBody):
    """更新扫描目标配置（PATCH 式部分更新）。"""
    db = _get_db(request)
    if not db.get_scan_target(target_id):
        return JSONResponse({"detail": "target not found"}, status_code=404)
    if body.cidr is not None:
        ok, err = _validate_scan_range(body.cidr)
        if not ok:
            return JSONResponse({"detail": err}, status_code=400)
    fields = {}
    if body.name is not None: fields["name"] = body.name
    if body.cidr is not None: fields["cidr"] = body.cidr
    if body.scan_strategy is not None: fields["scan_strategy"] = body.scan_strategy
    if body.schedule_interval is not None: fields["full_interval"] = body.schedule_interval
    if body.speed is not None: fields["speed"] = body.speed
    if body.enabled is not None: fields["enabled"] = body.enabled
    if not fields:
        return JSONResponse({"detail": "no fields to update"}, status_code=400)
    try:
        db.update_scan_target(target_id, **fields)
    except Exception as e:
        return JSONResponse({"detail": str(e)}, status_code=400)
    return db.get_scan_target(target_id)


@router.delete("/targets/{target_id}")
async def delete_target(request: Request, target_id: int):
    """删除扫描目标。"""
    db = _get_db(request)
    if not db.get_scan_target(target_id):
        return JSONResponse({"detail": "target not found"}, status_code=404)
    db.delete_scan_target(target_id)
    return {"deleted": target_id}
