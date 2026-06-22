"""ISG-Probe + ISG-Scan 双引擎 NHI 后端 — FastAPI 入口。"""

import logging
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.core.db import Database

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"NHI Discovery starting (port {settings.port})")
    logger.info(f"DB: {settings.db_path}")
    logger.info(f"Distributor socket: {settings.distributor_socket}")

    # ── Database ──
    db = Database()
    db.upsert_session(settings.session_id, "running")
    app.state.db = db

    # Probe consumer (Phase 2 启动；Phase 1 留空)
    app.state.db_writer = None
    app.state.ai_writer = None
    app.state.consumer = None
    # Scan scheduler (Phase 4 启动；Phase 1 留空)
    app.state.scan_scheduler = None

    logger.info("NHI Discovery ready (Phase 1: fusion layer only)")
    yield

    logger.info("NHI Discovery shutting down ...")
    if getattr(app.state, "consumer", None):
        app.state.consumer.stop()
    if getattr(app.state, "db_writer", None):
        app.state.db_writer.stop()
    if getattr(app.state, "scan_scheduler", None):
        app.state.scan_scheduler.shutdown()
    db.close()
    logger.info("NHI Discovery stopped")


app = FastAPI(
    title="NHI Discovery",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routers
from app.routers import stats, ai, scan, assets  # noqa: E402

app.include_router(stats.router)
app.include_router(ai.router)
app.include_router(scan.router)
app.include_router(assets.router)


@app.get("/api/v1/health")
async def health():
    db = app.state.db
    counts = db.table_counts()
    return {
        "status": "ok",
        "db_path": settings.db_path,
        "db_size_bytes": db.db_file_size(),
        "tables": counts,
        "distributor_socket": settings.distributor_socket,
        "probe_consumer": "running" if app.state.consumer else "stopped",
        "scan_scheduler": "running" if app.state.scan_scheduler else "stopped",
    }
