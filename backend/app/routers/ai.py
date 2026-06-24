"""AI API — ai_events 和 ai_endpoints 查询（Probe 侧）。"""

import logging

from fastapi import APIRouter, Query, Request

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/ai", tags=["ai"])


def _get_db(request: Request):
    return request.app.state.db


@router.get("/events")
async def list_ai_events(
    request: Request,
    ai_agent: str = Query(None),
    ai_vendor: str = Query(None),
    ai_service: str = Query(None),
    src_ip: str = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    db = _get_db(request)
    events = db.search_ai_events(
        ai_agent=ai_agent, ai_vendor=ai_vendor,
        ai_service=ai_service, src_ip=src_ip,
        limit=limit, offset=offset,
    )
    total = db.count_ai_events(
        ai_agent=ai_agent, ai_vendor=ai_vendor,
        ai_service=ai_service, src_ip=src_ip,
    )
    return {"events": events, "total": total, "limit": limit, "offset": offset}


@router.get("/events/stats")
async def ai_events_stats(
    request: Request,
    time_range: str = Query("all", description="1h / 24h / 7d / all"),
):
    db = _get_db(request)
    return db.ai_events_stats(time_range=time_range)


@router.get("/endpoints")
async def list_ai_endpoints(
    request: Request,
    role: str = Query(None),
    ip: str = Query(None),
    name: str = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    db = _get_db(request)
    endpoints = db.list_ai_endpoints(role=role, ip=ip, name=name, limit=limit, offset=offset)
    total = db.count_ai_endpoints(role=role, ip=ip, name=name)
    return {"endpoints": endpoints, "total": total, "limit": limit, "offset": offset}


@router.get("/endpoint/{ip}")
async def get_ai_endpoint(request: Request, ip: str):
    db = _get_db(request)
    return db.get_ai_endpoint(ip=ip)
