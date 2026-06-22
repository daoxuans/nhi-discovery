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

    # ── 种子数据：Scan targets + CVE ──
    from app.scan.target_manager import seed_if_empty
    from app.scan.cve_updater import seed_initial_cves
    seed_if_empty(db)
    seed_initial_cves(db)

    # ── Probe: DbWriter + AiWriter + EventConsumer ──
    from app.probe.db_writer import DbWriter
    from app.probe.ai_writer import AiWriter
    from app.probe.event_consumer import EventConsumer

    db_writer = DbWriter(
        settings.session_id, db,
        batch_interval=settings.db_writer_batch_interval,
        batch_size=settings.db_writer_batch_size,
    )
    db_writer.start()
    app.state.db_writer = db_writer

    ai_writer = AiWriter(db)
    app.state.ai_writer = ai_writer

    consumer = EventConsumer(
        db, db_writer, ai_writer,
        socket_path=settings.distributor_socket,
        ndpisrvd_py=settings.ndpisrvd_py,
    )
    consumer.start()
    app.state.consumer = consumer

    # ── Scan scheduler ──
    if settings.scan_scheduler_enabled:
        from app.scan.scheduler import ScanScheduler
        scan_scheduler = ScanScheduler(db)
        scan_scheduler.start()
        app.state.scan_scheduler = scan_scheduler
    else:
        app.state.scan_scheduler = None
        logger.info("ScanScheduler disabled (SCAN_SCHEDULER_ENABLED=0)")

    logger.info("NHI Discovery ready (Probe + Scan)")
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
    version="0.3.0",
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
    consumer = getattr(app.state, "consumer", None)
    db_writer = getattr(app.state, "db_writer", None)
    return {
        "status": "ok",
        "db_path": settings.db_path,
        "db_size_bytes": db.db_file_size(),
        "tables": counts,
        "distributor_socket": settings.distributor_socket,
        "probe_consumer": "running" if consumer and consumer._running else "stopped",
        "probe_last_event_at": consumer.last_event_at if consumer else None,
        "probe_event_count": consumer._event_count if consumer else 0,
        "db_writer_queue_depth": db_writer.queue_depth if db_writer else 0,
        "scan_scheduler": "running" if getattr(app.state, "scan_scheduler", None) else "stopped",
    }
