"""数据保留策略 — 每日 02:00 清理过期数据。"""

import logging
from pathlib import Path

from app.core.db import Database
from app.config import settings

logger = logging.getLogger(__name__)


def run_daily_cleanup(db: Database) -> dict:
    """清理过期数据，返回各表删除行数。"""
    deleted = {}
    with db.lock:
        # flows: 90 天
        cur = db.conn.execute(
            f"DELETE FROM flows WHERE created_at < datetime('now', '-{settings.retention_flows_days} days')"
        )
        deleted["flows"] = cur.rowcount
        # ai_events: 180 天
        cur = db.conn.execute(
            f"DELETE FROM ai_events WHERE created_at < datetime('now', '-{settings.retention_ai_events_days} days')"
        )
        deleted["ai_events"] = cur.rowcount
        # scan_findings: 90 天
        cur = db.conn.execute(
            f"DELETE FROM scan_findings WHERE created_at < datetime('now', '-{settings.retention_scan_findings_days} days')"
        )
        deleted["scan_findings"] = cur.rowcount
        # scan_tasks: 90 天
        cur = db.conn.execute(
            f"DELETE FROM scan_tasks WHERE created_at < datetime('now', '-{settings.retention_scan_tasks_days} days')"
        )
        deleted["scan_tasks"] = cur.rowcount
        # asset_lifecycle: 365 天
        cur = db.conn.execute(
            f"DELETE FROM asset_lifecycle WHERE occurred_at < datetime('now', '-{settings.retention_lifecycle_days} days')"
        )
        deleted["asset_lifecycle"] = cur.rowcount
        db.conn.commit()
        # 增量压缩（不锁库）
        try:
            db.conn.execute("PRAGMA incremental_vacuum(500)")
        except Exception as e:
            logger.warning(f"incremental_vacuum failed: {e}")
    logger.info(f"retention cleanup: {deleted}")
    return deleted


class RetentionScheduler:
    """保留策略调度器（Phase 1 占位，Phase 5 接 APScheduler）。"""

    def __init__(self, db: Database):
        self.db = db
        self._registered = False

    def register(self, scheduler):
        """注册到 APScheduler，每日 02:00 执行。"""
        from apscheduler.triggers.cron import CronTrigger
        scheduler.add_job(
            run_daily_cleanup, CronTrigger(hour=2, minute=0),
            args=[self.db], id="retention_daily", replace_existing=True
        )
        self._registered = True
        logger.info("RetentionScheduler registered (daily 02:00)")
