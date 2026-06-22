"""Stats API — flows 历史与聚合统计（DB 聚合，无 Aggregator）。"""

import logging

from fastapi import APIRouter, Query, Request

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1", tags=["stats"])


def _get_db(request: Request):
    return request.app.state.db


@router.get("/flows")
async def list_flows(
    request: Request,
    proto: str = Query(None),
    ip: str = Query(None),
    hostname: str = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    db = _get_db(request)
    flows = db.search_flows(
        proto=proto, ip=ip, hostname=hostname, limit=limit, offset=offset
    )
    total = db.count_flows()
    return {"flows": flows, "total": total, "limit": limit, "offset": offset}


@router.get("/flows/stats")
async def flow_stats(request: Request):
    db = _get_db(request)
    return db.flow_stats()
