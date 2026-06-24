"""Assets API — 双源融合资产视图（Phase 4 实现，Phase 1 占位查询）。"""

import logging

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/assets", tags=["assets"])


@router.get("/fused")
async def list_fused_assets(
    request: Request,
    ip: str = Query(None),
    svc_type: str = Query(None),
    source: str = Query("all", description="all / both / scan / probe"),
    risk_level: str = Query(None),
    lifecycle_state: str = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    db = request.app.state.db
    # Phase 1: 返回融合查询（ai_services LEFT JOIN ai_endpoints）
    # Phase 4 会完善 probe-only 资产（终端 Agent）
    src = None if source == "all" else source
    return db.get_fused_assets(
        ip=ip, svc_type=svc_type, source=src,
        risk_level=risk_level, lifecycle_state=lifecycle_state,
        limit=limit, offset=offset,
    )
