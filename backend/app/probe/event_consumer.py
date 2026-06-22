"""EventConsumer — 消费 nDPIsrvd distributor.sock 的 flow 事件。

改写要点（vs 旧实现）：
- 移除 Aggregator 依赖
- 加 JSON filter 只订阅 flow 事件（过滤 packet-flow 噪音）
- 对接 AiWriter（detected/detection-update → ai_events + ai_endpoints）
- 无 category 门控（路径 B）
"""

import importlib.util
import logging
import os
import threading
import time
from typing import Optional

from app.core.db import Database
from app.probe.db_writer import DbWriter
from app.probe.ai_writer import AiWriter

logger = logging.getLogger(__name__)

# nDPIsrvd.py 路径（动态 import，避免打包问题）
_NDPISRVD_PY = os.getenv("NDPISRVD_PY", "/opt/nDPId/dependencies/nDPIsrvd.py")

# JSON filter：只处理 flow 级事件，过滤 packet-flow 噪音
_FLOW_FILTER = "json_dict.get('flow_event_name','') in ('detected','end','idle','detection-update')"


def _load_ndpisrvd():
    spec = importlib.util.spec_from_file_location("nDPIsrvd", _NDPISRVD_PY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class EventConsumer:
    """消费 nDPIsrvd 事件，后台线程运行。"""

    def __init__(self, db: Database, db_writer: DbWriter, ai_writer: AiWriter,
                 socket_path: str, ndpisrvd_py: str = None):
        self.db = db
        self.db_writer = db_writer
        self.ai_writer = ai_writer
        self.socket_path = socket_path
        global _NDPISRVD_PY
        if ndpisrvd_py:
            _NDPISRVD_PY = ndpisrvd_py
        self._ndpisrvd = _load_ndpisrvd()
        self._socket = None
        self._thread = None
        self._running = False
        self._last_event_at = None
        self._event_count = 0

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        logger.info("EventConsumer started")

    def stop(self):
        self._running = False
        if self._socket:
            try:
                self._socket.sock.close()
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=5)
        logger.info(f"EventConsumer stopped (events={self._event_count})")

    @property
    def last_event_at(self):
        return self._last_event_at

    def _run(self):
        while self._running:
            try:
                self._socket = self._ndpisrvd.nDPIsrvdSocket()
                # 加 JSON filter（必须在 connect 后、loop 前）
                self._socket.addFilter(_FLOW_FILTER)
                logger.info(f"Connecting to nDPIsrvd at {self.socket_path}")
                self._socket.connect(self.socket_path)
                self._socket.timeout(5.0)
                self._socket.loop(self._on_json, self._on_cleanup,
                                  {"db_writer": self.db_writer,
                                   "ai_writer": self.ai_writer})
            except self._ndpisrvd.SocketConnectionBroken as e:
                logger.warning(f"nDPIsrvd disconnected: {e}")
            except self._ndpisrvd.SocketTimeout:
                pass
            except Exception as e:
                logger.error(f"Consumer error: {type(e).__name__}: {e}")
            finally:
                try:
                    if self._socket:
                        self._socket.sock.close()
                except Exception:
                    pass
                self._socket = None
            if self._running:
                time.sleep(2)

    def _on_json(self, json_dict, instance, current_flow, user_data):
        self._event_count += 1
        self._last_event_at = time.time()
        dbw = user_data["db_writer"]
        aiw = user_data["ai_writer"]

        event = json_dict.get("flow_event_name", "")
        if event in ("end", "idle"):
            dbw.enqueue(json_dict)
        elif event in ("detected", "detection-update"):
            aiw.insert(json_dict)
        return True

    @staticmethod
    def _on_cleanup(instance, current_flow, user_data):
        return True
