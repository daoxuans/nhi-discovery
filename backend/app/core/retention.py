"""数据保留策略 — 分批清理过期数据，独立于 ScanScheduler 运行。

设计要点：
- 分批 DELETE（每批 10000 行，逐批 commit 释放锁），避免单大事务导致
  写锁长持有 + WAL 暴涨 + 阻塞其他写入者（R2）。
- 作为独立后台线程在 main.py lifespan 启动，不依赖 SCAN_SCHEDULER_ENABLED
  （R1：scheduler 默认关闭时 retention 也跟着不跑，DB 无限增长）。
"""

import logging
import threading
import time
from typing import Optional

from app.core.db import Database
from app.config import settings

logger = logging.getLogger(__name__)

# 每批删除行数；分批 commit 让写锁分多次短持，不阻塞消费链路
_BATCH_SIZE = 10000
# 每批之间小睡，给 EventConsumer/DbWriter 抢写锁的窗口
_BATCH_SLEEP = 0.05
# 单表最多连续删除的批数上限，避免一次清理跑太久；下次循环再继续
_MAX_BATCHES_PER_TABLE = 200


def _delete_in_batches(db: Database, table: str, ts_column: str, days: int,
                       label: str) -> int:
    """分批删除 table 中 ts_column 早于 days 天的行。返回总删除行数。"""
    total = 0
    cutoff = f"datetime('now', '-{int(days)} days')"
    for _ in range(_MAX_BATCHES_PER_TABLE):
        with db.lock:
            cur = db.conn.execute(
                f"DELETE FROM {table} WHERE rowid IN ("
                f"SELECT rowid FROM {table} WHERE {ts_column} < {cutoff} "
                f"ORDER BY rowid LIMIT {_BATCH_SIZE})"
            )
            db.conn.commit()
        n = cur.rowcount
        total += n
        if n < _BATCH_SIZE:
            break  # 没有更多过期行了
        time.sleep(_BATCH_SLEEP)
    if total > 0:
        logger.info(f"retention {label}: deleted {total} rows (batched)")
    return total


def run_daily_cleanup(db: Database) -> dict:
    """清理过期数据，返回各表删除行数。分批 commit，避免大事务。"""
    deleted = {}
    # flows: 90 天（默认）
    deleted["flows"] = _delete_in_batches(
        db, "flows", "created_at", settings.retention_flows_days, "flows")
    # ai_events: 180 天
    deleted["ai_events"] = _delete_in_batches(
        db, "ai_events", "created_at", settings.retention_ai_events_days, "ai_events")
    # scan_findings: 90 天
    deleted["scan_findings"] = _delete_in_batches(
        db, "scan_findings", "created_at", settings.retention_scan_findings_days, "scan_findings")
    # scan_tasks: 90 天
    deleted["scan_tasks"] = _delete_in_batches(
        db, "scan_tasks", "created_at", settings.retention_scan_tasks_days, "scan_tasks")
    # asset_lifecycle: 365 天（按 occurred_at）
    deleted["asset_lifecycle"] = _delete_in_batches(
        db, "asset_lifecycle", "occurred_at", settings.retention_lifecycle_days, "asset_lifecycle")

    # 增量压缩回收空间（不锁库）
    try:
        with db.lock:
            db.conn.execute("PRAGMA incremental_vacuum(500)")
    except Exception as e:
        logger.warning(f"incremental_vacuum failed: {e}")

    logger.info(f"retention cleanup: {deleted}")
    return deleted


class RetentionScheduler:
    """保留策略后台线程。

    独立于 ScanScheduler 运行：即使 SCAN_SCHEDULER_ENABLED=0（不自动扫描），
    数据保留清理仍按 retention_interval_hours 周期执行，防止 DB 无限增长。

    间隔由 RETENTION_INTERVAL_HOURS 控制（默认 6 小时），首次启动延迟
    RETENTION_STARTUP_DELAY 秒（默认 60s，避开启动峰值）。
    """

    def __init__(self, db: Database,
                 interval_hours: Optional[float] = None,
                 startup_delay: Optional[float] = None):
        self.db = db
        self._interval = (interval_hours if interval_hours is not None
                          else float(__import__("os").getenv("RETENTION_INTERVAL_HOURS", "6")))
        self._startup_delay = (startup_delay if startup_delay is not None
                               else float(__import__("os").getenv("RETENTION_STARTUP_DELAY", "60")))
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._last_result: Optional[dict] = None

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True, name="retention")
        self._thread.start()
        logger.info(f"RetentionScheduler started (every {self._interval}h, "
                    f"first run in {self._startup_delay}s)")

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=10)
        logger.info(f"RetentionScheduler stopped (last_result={self._last_result})")

    @property
    def running(self) -> bool:
        return self._running

    @property
    def last_result(self) -> Optional[dict]:
        return self._last_result

    def _run(self):
        # 首次延迟，避开启动峰值
        time.sleep(self._startup_delay)
        while self._running:
            try:
                self._last_result = run_daily_cleanup(self.db)
            except Exception as e:
                logger.error(f"retention cycle failed: {type(e).__name__}: {e}", exc_info=True)
                self._last_result = {"error": str(e)}
            # 间隔（小时 → 秒）
            time.sleep(self._interval * 3600)
