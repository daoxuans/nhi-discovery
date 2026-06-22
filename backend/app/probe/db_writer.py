"""DbWriter — 异步批量写入 flows（executemany，单事务 commit）。

吸取 Probe 旧实现教训：旧版逐行 INSERT+COMMIT（200条=200次fsync）。
改用 executemany 批量，500 条/事务，fsync 1 次，吞吐 5-10x。
"""

import logging
import queue
import threading
import time
from typing import Dict, Optional

from app.core.db import Database

logger = logging.getLogger(__name__)


class DbWriter:
    """异步 DB 写入器 — 生产-消费者模式。"""

    def __init__(self, session_id: str, db: Database,
                 batch_interval: float = 1.0, batch_size: int = 500):
        self.session_id = session_id
        self.db = db
        self._batch_interval = batch_interval
        self._batch_size = batch_size
        self._queue: queue.Queue = queue.Queue(maxsize=20000)
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._dropped = 0
        self._written = 0

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        logger.info(f"DbWriter started (batch_size={self._batch_size})")

    def stop(self):
        self._running = False
        self._flush(force=True)
        if self._thread:
            self._thread.join(timeout=5)
        if self._dropped > 0:
            logger.warning(f"DbWriter dropped {self._dropped} events total")
        logger.info(f"DbWriter stopped (written={self._written})")

    def enqueue(self, json_dict: Dict):
        try:
            self._queue.put_nowait(json_dict)
        except queue.Full:
            self._dropped += 1
            if self._dropped % 500 == 0:
                logger.warning(f"DbWriter dropped {self._dropped} (queue full)")

    @property
    def queue_depth(self) -> int:
        return self._queue.qsize()

    def _run(self):
        while self._running:
            time.sleep(self._batch_interval)
            self._flush(force=False)

    def _flush(self, force: bool):
        batch = []
        limit = 0 if force else self._batch_size
        while not self._queue.empty():
            try:
                batch.append(self._queue.get_nowait())
            except queue.Empty:
                break
            if limit and len(batch) >= limit:
                break
        if not batch:
            return
        # 批量 executemany；失败 fallback 逐行
        try:
            written = self.db.insert_flows_batch(self.session_id, batch)
            self._written += written
            logger.debug(f"DbWriter flushed {written} flows (batch)")
        except Exception as e:
            logger.error(f"batch insert failed ({e}), fallback to per-row")
            for event in batch:
                try:
                    self.db.insert_flow(self.session_id, event)
                    self._written += 1
                except Exception as e2:
                    logger.error(f"per-row insert failed: {e2}")
