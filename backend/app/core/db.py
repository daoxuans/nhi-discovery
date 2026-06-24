"""统一 SQLite 数据库 — 9 表 schema + 所有查询方法。

融合层物理基础：Probe 的 flows/ai_events/ai_endpoints 与 Scan 的
scan_targets/scan_tasks/scan_findings/ai_services/cve_records/asset_lifecycle
共存在同一 DB 文件，双源融合通过普通 SQL JOIN 实现。
"""

import json
import logging
import sqlite3
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def _mono():
    """单调时钟，用于缓存 TTL（不用 wall clock 避免系统时间跳变）。"""
    return time.monotonic()


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS sessions (
    id          TEXT PRIMARY KEY,
    status      TEXT NOT NULL DEFAULT 'idle',
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    started_at  TEXT,
    stopped_at  TEXT,
    error_msg   TEXT
);

CREATE TABLE IF NOT EXISTS flows (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT NOT NULL,
    flow_id         INTEGER NOT NULL,
    thread_id       INTEGER,
    src_ip          TEXT,
    dst_ip          TEXT,
    src_port        INTEGER,
    dst_port        INTEGER,
    l4_proto        TEXT,
    proto           TEXT,
    proto_id        TEXT,
    category        TEXT,
    breed           TEXT,
    hostname        TEXT,
    confidence      TEXT,
    risk_count      INTEGER DEFAULT 0,
    entropy         REAL,
    detected_os     TEXT,
    src_bytes       INTEGER DEFAULT 0,
    dst_bytes       INTEGER DEFAULT 0,
    src_packets     INTEGER DEFAULT 0,
    dst_packets     INTEGER DEFAULT 0,
    first_seen_usec INTEGER,
    last_seen_usec  INTEGER,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);
CREATE INDEX IF NOT EXISTS idx_flows_session ON flows(session_id);
CREATE INDEX IF NOT EXISTS idx_flows_proto   ON flows(proto);
CREATE INDEX IF NOT EXISTS idx_flows_time    ON flows(created_at);
CREATE INDEX IF NOT EXISTS idx_flows_ip      ON flows(src_ip, dst_ip);
CREATE INDEX IF NOT EXISTS idx_flows_category ON flows(category) WHERE category IS NOT NULL;

CREATE TABLE IF NOT EXISTS ai_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id         INTEGER NOT NULL,
    src_ip          TEXT NOT NULL,
    dst_ip          TEXT,
    src_port        INTEGER,
    dst_port        INTEGER,
    l4_proto        TEXT,
    proto           TEXT,
    proto_id        TEXT,
    hostname        TEXT,
    confidence      TEXT,
    ai_vendor       TEXT,
    ai_service      TEXT,
    ai_svc_type     TEXT,
    ai_color        TEXT,
    ai_agent        TEXT,
    ai_agent_vendor TEXT,
    ai_agent_score  REAL,
    ja4             TEXT,
    ja3             TEXT,
    user_agent      TEXT,
    mcp_method      TEXT,
    mcp_tool_name   TEXT,
    ollama_action   TEXT,
    ollama_model    TEXT,
    vllm_action     TEXT,
    vllm_model      TEXT,
    triton_endpoint TEXT,
    triton_model    TEXT,
    event_type      TEXT NOT NULL DEFAULT 'detected',
    first_seen_usec INTEGER,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_ai_events_flow   ON ai_events(flow_id);
CREATE INDEX IF NOT EXISTS idx_ai_events_vendor ON ai_events(ai_vendor);
CREATE INDEX IF NOT EXISTS idx_ai_events_agent  ON ai_events(ai_agent);
CREATE INDEX IF NOT EXISTS idx_ai_events_svc    ON ai_events(ai_service);
CREATE INDEX IF NOT EXISTS idx_ai_events_time   ON ai_events(created_at);
CREATE INDEX IF NOT EXISTS idx_ai_events_ip     ON ai_events(src_ip);
CREATE INDEX IF NOT EXISTS idx_ai_events_time_vendor ON ai_events(created_at, ai_vendor);
CREATE INDEX IF NOT EXISTS idx_ai_events_vendor_time ON ai_events(ai_vendor, created_at);
CREATE INDEX IF NOT EXISTS idx_ai_events_hostname_notnull ON ai_events(hostname) WHERE hostname IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ai_events_ja4_notnull     ON ai_events(ja4) WHERE ja4 IS NOT NULL;

CREATE TABLE IF NOT EXISTS ai_endpoints (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ip              TEXT NOT NULL,
    role            TEXT NOT NULL,
    name            TEXT NOT NULL,
    vendor          TEXT,
    category        TEXT,
    ja4_list        TEXT,
    user_agent      TEXT,
    models          TEXT,
    flow_count      INTEGER DEFAULT 1,
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    lifecycle_state TEXT DEFAULT 'active',
    miss_count      INTEGER DEFAULT 0,
    scan_seen       INTEGER DEFAULT 0,
    scan_last_seen  TEXT,
    fused_confidence REAL,
    UNIQUE(ip, role, name)
);
CREATE INDEX IF NOT EXISTS idx_ai_endpoints_ip   ON ai_endpoints(ip);
CREATE INDEX IF NOT EXISTS idx_ai_endpoints_role ON ai_endpoints(role);
CREATE INDEX IF NOT EXISTS idx_ai_endpoints_name ON ai_endpoints(name);
CREATE INDEX IF NOT EXISTS idx_ai_endpoints_lifecycle ON ai_endpoints(lifecycle_state);

CREATE TABLE IF NOT EXISTS scan_targets (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT NOT NULL UNIQUE,
    cidr            TEXT NOT NULL,
    scan_strategy   TEXT NOT NULL DEFAULT 'deep',
    full_interval   INTEGER DEFAULT 1800,
    incr_interval   INTEGER DEFAULT 300,
    rate_limit_pps  INTEGER DEFAULT 500,
    per_target_qps  INTEGER DEFAULT 10,
    scan_window     TEXT DEFAULT '00:00-06:00',
    enabled         INTEGER DEFAULT 0,
    speed           TEXT DEFAULT 'normal',
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS scan_tasks (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    task_uuid       TEXT NOT NULL UNIQUE,
    target_id       INTEGER,
    task_type       TEXT NOT NULL DEFAULT 'manual',
    status          TEXT NOT NULL DEFAULT 'queued',
    started_at      TEXT,
    finished_at     TEXT,
    targets_scanned INTEGER DEFAULT 0,
    ports_scanned   INTEGER DEFAULT 0,
    findings_count  INTEGER DEFAULT 0,
    progress_total  INTEGER DEFAULT 0,
    progress_done   INTEGER DEFAULT 0,
    progress_phase  TEXT,
    error_msg       TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (target_id) REFERENCES scan_targets(id)
);
CREATE INDEX IF NOT EXISTS idx_scan_tasks_target ON scan_tasks(target_id);
CREATE INDEX IF NOT EXISTS idx_scan_tasks_status ON scan_tasks(status);
CREATE INDEX IF NOT EXISTS idx_scan_tasks_time   ON scan_tasks(created_at);

CREATE TABLE IF NOT EXISTS scan_findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id         INTEGER NOT NULL,
    ip              TEXT NOT NULL,
    port            INTEGER NOT NULL,
    proto           TEXT,
    state           TEXT,
    service_raw     TEXT,
    banner          TEXT,
    api_path        TEXT,
    api_status      INTEGER,
    api_response    TEXT,
    models_detected TEXT,
    version_detected TEXT,
    favicon_hash    TEXT,
    html_features   TEXT,
    platform_guess  TEXT,
    ai_vendor       TEXT,
    ai_service      TEXT,
    ai_svc_type     TEXT,
    confidence      REAL,
    found_at        TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (task_id) REFERENCES scan_tasks(id)
);
CREATE INDEX IF NOT EXISTS idx_scan_findings_ip      ON scan_findings(ip);
CREATE INDEX IF NOT EXISTS idx_scan_findings_port    ON scan_findings(port);
CREATE INDEX IF NOT EXISTS idx_scan_findings_service ON scan_findings(ai_service);
CREATE INDEX IF NOT EXISTS idx_scan_findings_task    ON scan_findings(task_id);
CREATE INDEX IF NOT EXISTS idx_scan_findings_time    ON scan_findings(created_at);

CREATE TABLE IF NOT EXISTS ai_services (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ip              TEXT NOT NULL,
    port            INTEGER NOT NULL,
    service         TEXT NOT NULL,
    vendor          TEXT,
    svc_type        TEXT,
    version         TEXT,
    models          TEXT,
    lifecycle_state TEXT DEFAULT 'active',
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    scan_count      INTEGER DEFAULT 1,
    miss_count      INTEGER DEFAULT 0,
    probe_seen      INTEGER DEFAULT 0,
    probe_last_flow TEXT,
    fused_confidence REAL,
    risk_level      TEXT,
    cve_count       INTEGER DEFAULT 0,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(ip, port, service)
);
CREATE INDEX IF NOT EXISTS idx_ai_services_ip      ON ai_services(ip);
CREATE INDEX IF NOT EXISTS idx_ai_services_service ON ai_services(service);
CREATE INDEX IF NOT EXISTS idx_ai_services_state   ON ai_services(lifecycle_state);
CREATE INDEX IF NOT EXISTS idx_ai_services_risk    ON ai_services(risk_level);

CREATE TABLE IF NOT EXISTS cve_records (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id          TEXT NOT NULL,
    service         TEXT NOT NULL,
    vendor          TEXT,
    affected_version TEXT NOT NULL,
    severity        TEXT NOT NULL,
    cvss_score      REAL,
    description     TEXT,
    reference_url   TEXT,
    published_at    TEXT,
    updated_at      TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(cve_id, service, affected_version)
);
CREATE INDEX IF NOT EXISTS idx_cve_service  ON cve_records(service);
CREATE INDEX IF NOT EXISTS idx_cve_severity ON cve_records(severity);

CREATE TABLE IF NOT EXISTS asset_lifecycle (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ip              TEXT NOT NULL,
    port            INTEGER,
    service         TEXT,
    event_type      TEXT NOT NULL,
    old_state       TEXT,
    new_state       TEXT,
    detail          TEXT,
    occurred_at     TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_lifecycle_ip   ON asset_lifecycle(ip);
CREATE INDEX IF NOT EXISTS idx_lifecycle_time ON asset_lifecycle(occurred_at);
"""

INSERT_FLOW_SQL = """INSERT INTO flows
    (session_id, flow_id, thread_id,
     src_ip, dst_ip, src_port, dst_port, l4_proto,
     proto, proto_id, category, breed, hostname, confidence,
     risk_count, entropy, detected_os,
     src_bytes, dst_bytes, src_packets, dst_packets,
     first_seen_usec, last_seen_usec)
    VALUES (?,?,?, ?,?,?,?,?, ?,?,?,?,?,?,?, ?,?,?, ?,?,?, ?,?)"""


def now_cst() -> str:
    """CST (UTC+8) 当前时间字符串。"""
    return (datetime.utcnow() + timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S")


def safe_json_loads(s, default):
    if not s:
        return default
    try:
        return json.loads(s)
    except Exception:
        return default


class Database:
    """SQLite 封装，线程安全。"""

    def __init__(self, db_path: str = None):
        from app.config import settings
        self._db_path = db_path or settings.db_path
        self._lock = threading.Lock()
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        # 主（写）连接：被 batch 写线程（DbWriter/AiWriter）持有
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA wal_autocheckpoint=1000")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.row_factory = sqlite3.Row
        self._init_schema()
        # 只读连接：API 请求用，与写连接隔离，写线程持写锁时不阻塞读
        self._read_conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._read_conn.execute("PRAGMA journal_mode=WAL")
        self._read_conn.execute("PRAGMA query_only=ON")
        self._read_conn.row_factory = sqlite3.Row
        # stats 结果缓存：{time_range: (mono_ts, result)}，TTL 30s
        self._stats_cache: Dict[str, Any] = {}
        self._flow_stats_cache: Optional[Any] = None  # (mono_ts, result)
        self._table_counts_cache: Optional[Any] = None  # (mono_ts, result) TTL 10s

    def _init_schema(self):
        with self._lock:
            self._conn.executescript(SCHEMA_SQL)
            # 平滑升级：老库 scan_targets 无 speed 列时补上
            self._migrate_scan_targets()
            # 平滑升级：老库 scan_tasks 无进度列时补上
            self._migrate_scan_tasks()
            self._conn.commit()

    def _migrate_scan_targets(self):
        """老库 scan_targets 加 speed 列（IF NOT EXISTS 模式）。"""
        cols = {r["name"] for r in self._conn.execute("PRAGMA table_info(scan_targets)").fetchall()}
        if "speed" not in cols:
            self._conn.execute(
                "ALTER TABLE scan_targets ADD COLUMN speed TEXT DEFAULT 'normal'"
            )
            logger.info("migrated scan_targets: added column speed")

    def _migrate_scan_tasks(self):
        """老库 scan_tasks 加进度列（Phase 4 scan progress）。"""
        task_cols = {r["name"] for r in self._conn.execute("PRAGMA table_info(scan_tasks)").fetchall()}
        if "progress_total" not in task_cols:
            self._conn.execute(
                "ALTER TABLE scan_tasks ADD COLUMN progress_total INTEGER DEFAULT 0"
            )
            logger.info("migrated scan_tasks: added column progress_total")
        if "progress_done" not in task_cols:
            self._conn.execute(
                "ALTER TABLE scan_tasks ADD COLUMN progress_done INTEGER DEFAULT 0"
            )
            logger.info("migrated scan_tasks: added column progress_done")
        if "progress_phase" not in task_cols:
            self._conn.execute(
                "ALTER TABLE scan_tasks ADD COLUMN progress_phase TEXT"
            )
            logger.info("migrated scan_tasks: added column progress_phase")

    @property
    def conn(self):
        return self._conn

    @property
    def rconn(self):
        """只读连接，供 API 读查询使用（与写连接隔离）。"""
        return self._read_conn

    @property
    def lock(self):
        return self._lock

    def close(self):
        with self._lock:
            self._conn.close()
            self._read_conn.close()

    # ──────────────── Sessions ────────────────

    def upsert_session(self, session_id, status, started_at=None,
                       stopped_at=None, error_msg=None):
        with self._lock:
            self._conn.execute(
                """INSERT INTO sessions (id, status, started_at, stopped_at, error_msg)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(id) DO UPDATE SET
                       status=excluded.status,
                       started_at=COALESCE(excluded.started_at, started_at),
                       stopped_at=COALESCE(excluded.stopped_at, stopped_at),
                       error_msg=COALESCE(excluded.error_msg, error_msg)""",
                (session_id, status, started_at, stopped_at, error_msg),
            )
            self._conn.commit()

    # ──────────────── Flows (Probe) ────────────────

    def _flow_tuple(self, session_id, data):
        ndpi = data.get("ndpi", {}) or {}
        flow_risk = ndpi.get("flow_risk", {}) or {}
        confidence_raw = ndpi.get("confidence", {})
        if isinstance(confidence_raw, dict):
            confidence = next(iter(confidence_raw.values()), None)
        else:
            confidence = confidence_raw
        entropy = ndpi.get("entropy")
        http = ndpi.get("http", {}) or {}
        detected_os = (http.get("detected_os", "") or "") if isinstance(http, dict) else ""
        return (
            session_id,
            data.get("flow_id"),
            data.get("thread_id"),
            data.get("src_ip"),
            data.get("dst_ip"),
            data.get("src_port"),
            data.get("dst_port"),
            str(data.get("l4_proto", "") or ""),
            ndpi.get("proto"),
            ndpi.get("proto_id"),
            ndpi.get("category"),
            ndpi.get("breed"),
            ndpi.get("hostname"),
            str(confidence or ""),
            len(flow_risk) if isinstance(flow_risk, dict) else 0,
            entropy,
            detected_os,
            data.get("flow_src_tot_l4_payload_len", 0) or 0,
            data.get("flow_dst_tot_l4_payload_len", 0) or 0,
            data.get("flow_src_packets_processed", 0) or 0,
            data.get("flow_dst_packets_processed", 0) or 0,
            data.get("flow_first_seen", 0) or 0,
            max(data.get("flow_src_last_pkt_time", 0) or 0,
                data.get("flow_dst_last_pkt_time", 0) or 0),
        )

    def insert_flow(self, session_id, data) -> int:
        with self._lock:
            cur = self._conn.execute(INSERT_FLOW_SQL, self._flow_tuple(session_id, data))
            self._conn.commit()
            return cur.lastrowid

    def insert_flows_batch(self, session_id, data_list: List[Dict]) -> int:
        if not data_list:
            return 0
        tuples = [self._flow_tuple(session_id, d) for d in data_list]
        with self._lock:
            try:
                self._conn.executemany(INSERT_FLOW_SQL, tuples)
                self._conn.commit()
                return len(tuples)
            except Exception:
                self._conn.rollback()
                raise

    def search_flows(self, session_id=None, proto=None, ip=None,
                     hostname=None, limit=100, offset=0) -> List[Dict]:
        conditions, params = [], []
        if session_id:
            conditions.append("session_id = ?"); params.append(session_id)
        if proto:
            conditions.append("proto LIKE ?"); params.append(f"%{proto}%")
        if ip:
            conditions.append("(src_ip LIKE ? OR dst_ip LIKE ?)")
            params.extend([f"%{ip}%", f"%{ip}%"])
        if hostname:
            conditions.append("hostname LIKE ?"); params.append(f"%{hostname}%")
        where = (" WHERE " + " AND ".join(conditions)) if conditions else ""
        sql = f"SELECT * FROM flows{where} ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        rows = self._read_conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def count_flows(self, session_id=None) -> int:
        sql = "SELECT COUNT(*) FROM flows"
        params = []
        if session_id:
            sql += " WHERE session_id=?"; params.append(session_id)
        return self._read_conn.execute(sql, params).fetchone()[0]

    def flow_stats(self) -> Dict:
        cached = self._flow_stats_cache
        if cached and (_mono() - cached[0]) < 30.0:
            return cached[1]
        rc = self._read_conn
        total = rc.execute("SELECT COUNT(*) FROM flows").fetchone()[0]
        protocols = [dict(r) for r in rc.execute(
            "SELECT proto as name, COUNT(*) as count FROM flows "
            "WHERE proto IS NOT NULL GROUP BY proto ORDER BY count DESC LIMIT 30"
        ).fetchall()]
        categories = [dict(r) for r in rc.execute(
            "SELECT category as name, COUNT(*) as count FROM flows "
            "WHERE category IS NOT NULL GROUP BY category ORDER BY count DESC LIMIT 20"
        ).fetchall()]
        det = rc.execute(
            "SELECT CASE WHEN category IS NOT NULL THEN 'detected' ELSE 'not-detected' END as k, "
            "COUNT(*) as c FROM flows GROUP BY k"
        ).fetchall()
        detection = {r["k"]: r["c"] for r in det}
        risk_row = rc.execute(
            "SELECT SUM(CASE WHEN risk_count>0 THEN 1 ELSE 0 END) as risky_flows, "
            "SUM(risk_count) as total_risks FROM flows"
        ).fetchone()
        result = {
            "total": total,
            "protocols": protocols,
            "categories": categories,
            "detection": detection,
            "risks": dict(risk_row) if risk_row else {},
        }
        self._flow_stats_cache = (_mono(), result)
        return result

    # ──────────────── ai_events (Probe Layer1/2 流水) ────────────────

    def insert_ai_event(self, e: Dict) -> int:
        cols = ["flow_id", "src_ip", "dst_ip", "src_port", "dst_port", "l4_proto",
                "proto", "proto_id", "hostname", "confidence",
                "ai_vendor", "ai_service", "ai_svc_type", "ai_color",
                "ai_agent", "ai_agent_vendor", "ai_agent_score",
                "ja4", "ja3", "user_agent",
                "mcp_method", "mcp_tool_name",
                "ollama_action", "ollama_model",
                "vllm_action", "vllm_model",
                "triton_endpoint", "triton_model",
                "event_type", "first_seen_usec"]
        placeholders = ",".join(["?"] * len(cols))
        sql = f"INSERT INTO ai_events ({','.join(cols)}) VALUES ({placeholders})"
        params = (
            e.get("flow_id"), e.get("src_ip"), e.get("dst_ip"),
            e.get("src_port"), e.get("dst_port"), e.get("l4_proto"),
            e.get("proto"), e.get("proto_id"), e.get("hostname"), e.get("confidence"),
            e.get("ai_vendor"), e.get("ai_service"), e.get("ai_svc_type"), e.get("ai_color"),
            e.get("ai_agent"), e.get("ai_agent_vendor"), e.get("ai_agent_score"),
            e.get("ja4"), e.get("ja3"), e.get("user_agent"),
            e.get("mcp_method"), e.get("mcp_tool_name"),
            e.get("ollama_action"), e.get("ollama_model"),
            e.get("vllm_action"), e.get("vllm_model"),
            e.get("triton_endpoint"), e.get("triton_model"),
            e.get("event_type", "detected"), e.get("first_seen_usec"),
        )
        with self._lock:
            cur = self._conn.execute(sql, params)
            self._conn.commit()
            return cur.lastrowid

    # ai_events 列顺序（批量写入复用）
    _AI_EVENT_COLS = ["flow_id", "src_ip", "dst_ip", "src_port", "dst_port", "l4_proto",
                      "proto", "proto_id", "hostname", "confidence",
                      "ai_vendor", "ai_service", "ai_svc_type", "ai_color",
                      "ai_agent", "ai_agent_vendor", "ai_agent_score",
                      "ja4", "ja3", "user_agent",
                      "mcp_method", "mcp_tool_name",
                      "ollama_action", "ollama_model",
                      "vllm_action", "vllm_model",
                      "triton_endpoint", "triton_model",
                      "event_type", "first_seen_usec"]

    def insert_ai_events_batch(self, events: List[Dict]) -> int:
        """批量 INSERT ai_events（executemany 单事务 commit），吞吐 ~10x。"""
        if not events:
            return 0
        cols = self._AI_EVENT_COLS
        placeholders = ",".join(["?"] * len(cols))
        sql = f"INSERT INTO ai_events ({','.join(cols)}) VALUES ({placeholders})"
        tuples = [
            (e.get("flow_id"), e.get("src_ip"), e.get("dst_ip"),
             e.get("src_port"), e.get("dst_port"), e.get("l4_proto"),
             e.get("proto"), e.get("proto_id"), e.get("hostname"), e.get("confidence"),
             e.get("ai_vendor"), e.get("ai_service"), e.get("ai_svc_type"), e.get("ai_color"),
             e.get("ai_agent"), e.get("ai_agent_vendor"), e.get("ai_agent_score"),
             e.get("ja4"), e.get("ja3"), e.get("user_agent"),
             e.get("mcp_method"), e.get("mcp_tool_name"),
             e.get("ollama_action"), e.get("ollama_model"),
             e.get("vllm_action"), e.get("vllm_model"),
             e.get("triton_endpoint"), e.get("triton_model"),
             e.get("event_type", "detected"), e.get("first_seen_usec"))
            for e in events
        ]
        with self._lock:
            try:
                self._conn.executemany(sql, tuples)
                self._conn.commit()
                return len(tuples)
            except Exception:
                self._conn.rollback()
                raise

    def _ai_event_filter(self, ai_agent, ai_vendor, ai_service, src_ip):
        conditions, params = [], []
        if ai_agent:
            conditions.append("ai_agent LIKE ?"); params.append(f"%{ai_agent}%")
        if ai_vendor:
            conditions.append("ai_vendor LIKE ?"); params.append(f"%{ai_vendor}%")
        if ai_service:
            conditions.append("ai_service LIKE ?"); params.append(f"%{ai_service}%")
        if src_ip:
            conditions.append("src_ip LIKE ?"); params.append(f"%{src_ip}%")
        return conditions, params

    def search_ai_events(self, ai_agent=None, ai_vendor=None, ai_service=None,
                         src_ip=None, limit=50, offset=0) -> List[Dict]:
        conditions, params = self._ai_event_filter(ai_agent, ai_vendor, ai_service, src_ip)
        where = (" WHERE " + " AND ".join(conditions)) if conditions else ""
        sql = f"SELECT * FROM ai_events{where} ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        # 读查询用只读连接，不被写线程阻塞
        rows = self._read_conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def count_ai_events(self, ai_agent=None, ai_vendor=None,
                        ai_service=None, src_ip=None) -> int:
        conditions, params = self._ai_event_filter(ai_agent, ai_vendor, ai_service, src_ip)
        where = (" WHERE " + " AND ".join(conditions)) if conditions else ""
        return self._read_conn.execute(f"SELECT COUNT(*) FROM ai_events{where}", params).fetchone()[0]

    def ai_events_stats(self, time_range="all") -> Dict:
        """统计聚合。结果按 time_range 做 30s 内存缓存（Dashboard 30s 轮询命中缓存 <1ms）。
        合并查询 + 只读连接，避免被写线程阻塞。
        """
        now_mono = _mono()
        cached = self._stats_cache.get(time_range)
        if cached and (now_mono - cached[0]) < 30.0:
            return cached[1]

        result = self._ai_events_stats_uncached(time_range)
        self._stats_cache[time_range] = (now_mono, result)
        return result

    def _ai_events_stats_uncached(self, time_range="all") -> Dict:
        if time_range == "1h":
            time_cond = "created_at >= datetime('now','-1 hour')"
        elif time_range == "24h":
            time_cond = "created_at >= datetime('now','-1 day')"
        elif time_range == "7d":
            time_cond = "created_at >= datetime('now','-7 days')"
        else:
            time_cond = None

        base = f"FROM ai_events WHERE {time_cond}" if time_cond else "FROM ai_events"
        confirmed_base = f"{base} {'AND' if time_cond else 'WHERE'} ai_vendor IS NOT NULL"

        rc = self._read_conn
        # total + confirmed 合并为一次扫描
        row = rc.execute(
            f"SELECT COUNT(*), SUM(CASE WHEN ai_vendor IS NOT NULL THEN 1 ELSE 0 END) {base}"
        ).fetchone()
        total, confirmed = row[0], row[1] or 0
        flows_total = rc.execute("SELECT COUNT(*) FROM flows").fetchone()[0]
        top_ja4 = [dict(r) for r in rc.execute(
            f"SELECT ja4, COUNT(*) as count {confirmed_base} "
            f"AND ja4 IS NOT NULL AND ja4 != '' GROUP BY ja4 ORDER BY count DESC LIMIT 10"
        ).fetchall()]
        top_hostnames = [dict(r) for r in rc.execute(
            f"SELECT hostname, COUNT(*) as count {confirmed_base} "
            f"AND hostname IS NOT NULL AND hostname != '' GROUP BY hostname ORDER BY count DESC LIMIT 10"
        ).fetchall()]

        def _grp(col):
            col_base = f"FROM ai_events WHERE {time_cond} AND {col} IS NOT NULL" if time_cond \
                       else f"FROM ai_events WHERE {col} IS NOT NULL"
            return {r["name"]: r["count"]
                    for r in rc.execute(f"SELECT {col} as name, COUNT(*) as count {col_base} GROUP BY {col} ORDER BY count DESC").fetchall()}

        percentage = round(confirmed / flows_total * 100, 2) if flows_total else 0.0
        return {
            "total": total,
            "confirmed": confirmed,
            "percentage": percentage,
            "percentage_note": "confirmed(ai_vendor非空) / flows",
            "vendor_counts": _grp("ai_vendor"),
            "service_counts": _grp("ai_service"),
            "agent_counts": _grp("ai_agent"),
            "svc_type_counts": _grp("ai_svc_type"),
            "top_ja4": top_ja4,
            "top_hostnames": top_hostnames,
        }

    # ──────────────── ai_endpoints (Probe UPSERT) ────────────────

    def upsert_ai_endpoint(self, ip, role, name, vendor=None, category=None,
                           ja4_append=None, user_agent=None, models_append=None,
                           source="probe"):
        """UPSERT ai_endpoints。重新发现即复活（lifecycle_state=active, miss_count=0）。"""
        now = now_cst()
        with self._lock:
            row = self._conn.execute(
                "SELECT id, ja4_list, models, flow_count FROM ai_endpoints "
                "WHERE ip=? AND role=? AND name=?",
                (ip, role, name)
            ).fetchone()
            if row is None:
                ja4_list = json.dumps([ja4_append], ensure_ascii=False) if ja4_append else "[]"
                models = json.dumps(models_append or [], ensure_ascii=False) if models_append else "[]"
                self._conn.execute(
                    """INSERT INTO ai_endpoints
                    (ip, role, name, vendor, category, ja4_list, user_agent, models,
                     flow_count, first_seen, last_seen, created_at, lifecycle_state, miss_count)
                    VALUES (?,?,?,?,?, ?,?,?, 1, ?,?, ?, 'active', 0)""",
                    (ip, role, name, vendor, category, ja4_list, user_agent, models,
                     now, now, now)
                )
                new_id = self._conn.execute(
                    "SELECT id FROM ai_endpoints WHERE ip=? AND role=? AND name=?",
                    (ip, role, name)
                ).fetchone()[0]
                is_new = True
            else:
                ja4_list = safe_json_loads(row["ja4_list"], [])
                if ja4_append and ja4_append not in ja4_list:
                    ja4_list.append(ja4_append)
                models = safe_json_loads(row["models"], [])
                if models_append:
                    for m in models_append:
                        if m and m not in models:
                            models.append(m)
                sets = [
                    "flow_count = flow_count + 1",
                    "last_seen = ?",
                    "lifecycle_state = 'active'",
                    "miss_count = 0",
                    "ja4_list = ?",
                    "models = ?",
                ]
                params: List[Any] = [now, json.dumps(ja4_list, ensure_ascii=False),
                                     json.dumps(models, ensure_ascii=False)]
                if vendor:
                    sets.append("vendor = ?"); params.append(vendor)
                if category:
                    sets.append("category = ?"); params.append(category)
                if user_agent:
                    sets.append("user_agent = ?"); params.append(user_agent)
                params.extend([ip, role, name])
                self._conn.execute(
                    f"UPDATE ai_endpoints SET {', '.join(sets)} "
                    f"WHERE ip=? AND role=? AND name=?", params
                )
                new_id = row["id"]
                is_new = False
            self._conn.execute(
                "INSERT INTO asset_lifecycle (ip, service, event_type, new_state, detail) "
                "VALUES (?, ?, 'discovered', 'active', ?)",
                (ip, name, json.dumps({"role": role, "source": source, "new": is_new}, ensure_ascii=False))
            )
            self._conn.commit()
            return new_id

    def list_ai_endpoints(self, role=None, ip=None, name=None,
                          limit=100, offset=0) -> List[Dict]:
        conditions, params = [], []
        if role:
            conditions.append("role=?"); params.append(role)
        if ip:
            conditions.append("ip=?"); params.append(ip)
        if name:
            conditions.append("name LIKE ?"); params.append(f"%{name}%")
        where = (" WHERE " + " AND ".join(conditions)) if conditions else ""
        sql = f"SELECT * FROM ai_endpoints{where} ORDER BY flow_count DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        rows = self._read_conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def count_ai_endpoints(self, role=None, ip=None, name=None) -> int:
        conditions, params = [], []
        if role:
            conditions.append("role=?"); params.append(role)
        if ip:
            conditions.append("ip=?"); params.append(ip)
        if name:
            conditions.append("name LIKE ?"); params.append(f"%{name}%")
        where = (" WHERE " + " AND ".join(conditions)) if conditions else ""
        return self._read_conn.execute(f"SELECT COUNT(*) FROM ai_endpoints{where}", params).fetchone()[0]

    def get_ai_endpoint(self, ip: str) -> Dict:
        rc = self._read_conn
        agents = [dict(r) for r in rc.execute(
            "SELECT * FROM ai_endpoints WHERE ip=? AND role='agent' ORDER BY flow_count DESC",
            (ip,)
        ).fetchall()]
        services = [dict(r) for r in rc.execute(
            "SELECT * FROM ai_endpoints WHERE ip=? AND role='service' ORDER BY flow_count DESC",
            (ip,)
        ).fetchall()]
        timeline = [dict(r) for r in rc.execute(
            "SELECT * FROM asset_lifecycle WHERE ip=? ORDER BY occurred_at DESC LIMIT 20",
            (ip,)
        ).fetchall()]
        scan_svcs = [dict(r) for r in rc.execute(
            "SELECT port, service, vendor, version, lifecycle_state, scan_count, last_seen "
            "FROM ai_services WHERE ip=? ORDER BY scan_count DESC", (ip,)
        ).fetchall()]
        return {
            "ip": ip,
            "agents": agents,
            "services": services,
            "scan_services": scan_svcs,
            "timeline": timeline,
        }

    # ──────────────── Scan: targets ────────────────

    def insert_scan_target(self, name, cidr, scan_strategy="full",
                           full_interval=1800, incr_interval=300,
                           rate_limit_pps=500, per_target_qps=10,
                           scan_window="00:00-06:00", enabled=0) -> int:
        with self._lock:
            cur = self._conn.execute(
                """INSERT INTO scan_targets
                (name, cidr, scan_strategy, full_interval, incr_interval,
                 rate_limit_pps, per_target_qps, scan_window, enabled)
                VALUES (?,?,?,?,?, ?,?,?,?)""",
                (name, cidr, scan_strategy, full_interval, incr_interval,
                 rate_limit_pps, per_target_qps, scan_window, enabled)
            )
            self._conn.commit()
            return cur.lastrowid

    def update_scan_target(self, target_id: int, **fields) -> bool:
        """PATCH 式更新 scan_targets。支持 name/cidr/scan_strategy/full_interval/speed/enabled。"""
        allowed = {"name", "cidr", "scan_strategy", "full_interval",
                   "incr_interval", "rate_limit_pps", "per_target_qps",
                   "scan_window", "enabled", "speed"}
        sets, params = [], []
        for k, v in fields.items():
            if k in allowed and v is not None:
                sets.append(f"{k}=?"); params.append(v)
        if not sets:
            return False
        params.append(target_id)
        with self._lock:
            cur = self._conn.execute(
                f"UPDATE scan_targets SET {', '.join(sets)} WHERE id=?", params
            )
            self._conn.commit()
            return cur.rowcount > 0

    def delete_scan_target(self, target_id: int) -> bool:
        with self._lock:
            cur = self._conn.execute("DELETE FROM scan_targets WHERE id=?", (target_id,))
            self._conn.commit()
            return cur.rowcount > 0

    def list_scan_targets(self, enabled_only=False) -> List[Dict]:
        sql = "SELECT * FROM scan_targets"
        if enabled_only:
            sql += " WHERE enabled=1"
        sql += " ORDER BY id"
        rows = self._read_conn.execute(sql).fetchall()
        return [dict(r) for r in rows]

    def get_scan_target(self, target_id) -> Optional[Dict]:
        row = self._read_conn.execute(
            "SELECT * FROM scan_targets WHERE id=?", (target_id,)
        ).fetchone()
        return dict(row) if row else None

    # ──────────────── Scan: tasks ────────────────

    def insert_scan_task(self, task_uuid, target_id, task_type="manual") -> int:
        with self._lock:
            cur = self._conn.execute(
                """INSERT INTO scan_tasks (task_uuid, target_id, task_type, status)
                   VALUES (?, ?, ?, 'queued')""",
                (task_uuid, target_id, task_type)
            )
            self._conn.commit()
            return cur.lastrowid

    def update_scan_task(self, task_id, status=None, started_at=None,
                         finished_at=None, targets_scanned=None,
                         ports_scanned=None, findings_count=None,
                         progress_total=None, progress_done=None,
                         progress_phase=None, error_msg=None):
        sets, params = [], []
        if status: sets.append("status=?"); params.append(status)
        if started_at: sets.append("started_at=?"); params.append(started_at)
        if finished_at: sets.append("finished_at=?"); params.append(finished_at)
        if targets_scanned is not None: sets.append("targets_scanned=?"); params.append(targets_scanned)
        if ports_scanned is not None: sets.append("ports_scanned=?"); params.append(ports_scanned)
        if findings_count is not None: sets.append("findings_count=?"); params.append(findings_count)
        if progress_total is not None: sets.append("progress_total=?"); params.append(progress_total)
        if progress_done is not None: sets.append("progress_done=?"); params.append(progress_done)
        if progress_phase is not None: sets.append("progress_phase=?"); params.append(progress_phase)
        if error_msg: sets.append("error_msg=?"); params.append(error_msg)
        if not sets:
            return
        params.append(task_id)
        with self._lock:
            self._conn.execute(f"UPDATE scan_tasks SET {', '.join(sets)} WHERE id=?", params)
            self._conn.commit()

    def recover_stuck_tasks(self) -> int:
        """启动恢复：把 status='running' 的任务标记为 failed。

        服务器重启后，内存中的后台扫描任务已丢失，但 DB 里仍记 'running'，
        前端会永远显示运行中。启动时调用此方法清理（R3）。
        返回恢复的任务数。
        """
        now = now_cst()
        with self._lock:
            cur = self._conn.execute(
                "UPDATE scan_tasks SET status='failed', finished_at=?, "
                "error_msg='interrupted by server restart' "
                "WHERE status='running' OR status='queued'",
                (now,)
            )
            self._conn.commit()
        n = cur.rowcount
        if n > 0:
            logger.info(f"recovered {n} stuck scan_tasks (running/queued → failed)")
        return n

    def get_scan_task(self, task_id) -> Optional[Dict]:
        row = self._read_conn.execute(
            "SELECT * FROM scan_tasks WHERE id=?", (task_id,)
        ).fetchone()
        return dict(row) if row else None

    def get_scan_task_by_uuid(self, task_uuid) -> Optional[Dict]:
        row = self._read_conn.execute(
            "SELECT * FROM scan_tasks WHERE task_uuid=?", (task_uuid,)
        ).fetchone()
        return dict(row) if row else None

    # ──────────────── Scan: findings ────────────────

    def insert_scan_findings_batch(self, findings: List[Dict]) -> int:
        if not findings:
            return 0
        cols = ["task_id", "ip", "port", "proto", "state", "service_raw", "banner",
                "api_path", "api_status", "api_response", "models_detected", "version_detected",
                "favicon_hash", "html_features", "platform_guess",
                "ai_vendor", "ai_service", "ai_svc_type", "confidence", "found_at"]
        placeholders = ",".join(["?"] * len(cols))
        sql = f"INSERT INTO scan_findings ({','.join(cols)}) VALUES ({placeholders})"
        tuples = []
        now = now_cst()
        for f in findings:
            models = f.get("models_detected")
            if isinstance(models, list):
                models = json.dumps(models, ensure_ascii=False)
            html_feat = f.get("html_features")
            if isinstance(html_feat, list):
                html_feat = json.dumps(html_feat, ensure_ascii=False)
            api_resp = f.get("api_response")
            if api_resp:
                api_resp = str(api_resp)[:500]
            tuples.append((
                f.get("task_id"), f.get("ip"), f.get("port"), f.get("proto"),
                f.get("state", "open"), f.get("service_raw"), f.get("banner"),
                f.get("api_path"), f.get("api_status"), api_resp,
                models, f.get("version_detected"),
                f.get("favicon_hash"), html_feat, f.get("platform_guess"),
                f.get("ai_vendor"), f.get("ai_service"), f.get("ai_svc_type"),
                f.get("confidence"), f.get("found_at") or now,
            ))
        with self._lock:
            try:
                self._conn.executemany(sql, tuples)
                self._conn.commit()
                return len(tuples)
            except Exception:
                self._conn.rollback()
                raise

    def search_scan_findings(self, ip=None, service=None, port=None,
                             task_id=None, limit=50, offset=0) -> List[Dict]:
        conditions, params = [], []
        if ip: conditions.append("ip=?"); params.append(ip)
        if service: conditions.append("ai_service LIKE ?"); params.append(f"%{service}%")
        if port: conditions.append("port=?"); params.append(port)
        if task_id: conditions.append("task_id=?"); params.append(task_id)
        where = (" WHERE " + " AND ".join(conditions)) if conditions else ""
        sql = f"SELECT * FROM scan_findings{where} ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        rows = self._read_conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def count_scan_findings(self, ip=None, service=None, port=None, task_id=None) -> int:
        conditions, params = [], []
        if ip: conditions.append("ip=?"); params.append(ip)
        if service: conditions.append("ai_service LIKE ?"); params.append(f"%{service}%")
        if port: conditions.append("port=?"); params.append(port)
        if task_id: conditions.append("task_id=?"); params.append(task_id)
        where = (" WHERE " + " AND ".join(conditions)) if conditions else ""
        return self._read_conn.execute(f"SELECT COUNT(*) FROM scan_findings{where}", params).fetchone()[0]

    # ──────────────── Scan: ai_services UPSERT ────────────────

    def upsert_ai_service(self, ip, port, service, vendor=None, svc_type=None,
                          version=None, models=None, source="scan") -> int:
        now = now_cst()
        with self._lock:
            row = self._conn.execute(
                "SELECT id, models, scan_count FROM ai_services "
                "WHERE ip=? AND port=? AND service=?",
                (ip, port, service)
            ).fetchone()
            if row is None:
                models_json = json.dumps(models or [], ensure_ascii=False)
                self._conn.execute(
                    """INSERT INTO ai_services
                    (ip, port, service, vendor, svc_type, version, models,
                     lifecycle_state, first_seen, last_seen, scan_count, miss_count,
                     updated_at)
                    VALUES (?,?,?,?,?,?, ?, 'active', ?,?, 1, 0, ?)""",
                    (ip, port, service, vendor, svc_type, version, models_json,
                     now, now, now)
                )
                new_id = self._conn.execute(
                    "SELECT id FROM ai_services WHERE ip=? AND port=? AND service=?",
                    (ip, port, service)
                ).fetchone()[0]
                self._conn.execute(
                    "INSERT INTO asset_lifecycle (ip, port, service, event_type, new_state, detail) "
                    "VALUES (?, ?, ?, 'discovered', 'active', ?)",
                    (ip, port, service, json.dumps({"source": source}, ensure_ascii=False))
                )
                is_new = True
            else:
                existing_models = safe_json_loads(row["models"], [])
                if models:
                    for m in models:
                        if m and m not in existing_models:
                            existing_models.append(m)
                sets = [
                    "last_seen = ?", "scan_count = scan_count + 1",
                    "miss_count = 0", "lifecycle_state = 'active'",
                    "models = ?", "updated_at = ?",
                ]
                params = [now, json.dumps(existing_models, ensure_ascii=False), now]
                if vendor: sets.append("vendor=?"); params.append(vendor)
                if svc_type: sets.append("svc_type=?"); params.append(svc_type)
                if version: sets.append("version=?"); params.append(version)
                params.append(ip); params.append(port); params.append(service)
                self._conn.execute(
                    f"UPDATE ai_services SET {', '.join(sets)} WHERE ip=? AND port=? AND service=?",
                    params
                )
                new_id = row["id"]
                is_new = False
            self._conn.commit()
            return new_id

    def list_ai_services(self, vendor=None, svc_type=None, ip=None,
                         lifecycle_state=None, limit=100, offset=0) -> List[Dict]:
        conditions, params = [], []
        if vendor: conditions.append("vendor=?"); params.append(vendor)
        if svc_type: conditions.append("svc_type=?"); params.append(svc_type)
        if ip: conditions.append("ip=?"); params.append(ip)
        if lifecycle_state: conditions.append("lifecycle_state=?"); params.append(lifecycle_state)
        where = (" WHERE " + " AND ".join(conditions)) if conditions else ""
        sql = f"SELECT * FROM ai_services{where} ORDER BY scan_count DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        rows = self._read_conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def count_ai_services(self, vendor=None, svc_type=None, ip=None, lifecycle_state=None) -> int:
        conditions, params = [], []
        if vendor: conditions.append("vendor=?"); params.append(vendor)
        if svc_type: conditions.append("svc_type=?"); params.append(svc_type)
        if ip: conditions.append("ip=?"); params.append(ip)
        if lifecycle_state: conditions.append("lifecycle_state=?"); params.append(lifecycle_state)
        where = (" WHERE " + " AND ".join(conditions)) if conditions else ""
        return self._read_conn.execute(f"SELECT COUNT(*) FROM ai_services{where}", params).fetchone()[0]

    def list_ai_service_ips(self) -> List[Dict]:
        """Scan 融合用：取所有 ai_services 的 ip/port/service/version。"""
        rows = self._read_conn.execute(
            "SELECT ip, port, service, vendor, version FROM ai_services "
            "WHERE lifecycle_state='active'"
        ).fetchall()
        return [dict(r) for r in rows]

    def update_ai_service_fusion(self, ip, port, service, probe_seen=None,
                                 probe_last_flow=None, fused_confidence=None,
                                 risk_level=None, cve_count=None):
        sets, params = [], []
        if probe_seen is not None: sets.append("probe_seen=?"); params.append(probe_seen)
        if probe_last_flow is not None: sets.append("probe_last_flow=?"); params.append(probe_last_flow)
        if fused_confidence is not None: sets.append("fused_confidence=?"); params.append(fused_confidence)
        if risk_level is not None: sets.append("risk_level=?"); params.append(risk_level)
        if cve_count is not None: sets.append("cve_count=?"); params.append(cve_count)
        if not sets:
            return
        params.extend([ip, port, service])
        with self._lock:
            self._conn.execute(
                f"UPDATE ai_services SET {', '.join(sets)} WHERE ip=? AND port=? AND service=?",
                params
            )
            self._conn.commit()

    def update_ai_endpoint_fusion(self, ip, scan_seen=None, scan_last_seen=None,
                                  fused_confidence=None, name=None):
        """更新 ai_endpoints 融合字段。

        name: 若提供则按 (ip, role='service', name) 精确匹配，避免一 IP 多服务
        时全标 scan_seen（M4）。不传则回退到按 ip+role 全量更新（向后兼容）。
        """
        sets, params = [], []
        if scan_seen is not None: sets.append("scan_seen=?"); params.append(scan_seen)
        if scan_last_seen is not None: sets.append("scan_last_seen=?"); params.append(scan_last_seen)
        if fused_confidence is not None: sets.append("fused_confidence=?"); params.append(fused_confidence)
        if not sets:
            return
        params.append(ip)
        where = "WHERE ip=? AND role='service'"
        if name is not None:
            where += " AND name=?"
            params.append(name)
        with self._lock:
            self._conn.execute(
                f"UPDATE ai_endpoints SET {', '.join(sets)} {where}", params
            )
            self._conn.commit()

    def get_probe_endpoints_for_ip(self, ip):
        """Scan 融合用：查 Probe ai_endpoints(role=service) 该 IP。"""
        rows = self._read_conn.execute(
            "SELECT name, vendor, category, last_seen, flow_count FROM ai_endpoints "
            "WHERE ip=? AND role='service'", (ip,)
        ).fetchall()
        return [dict(r) for r in rows]

    def list_active_endpoint_ips(self):
        """Probe 侧融合用：所有 active 的 service 端点 ip + last_seen。"""
        rows = self._read_conn.execute(
            "SELECT ip, last_seen FROM ai_endpoints "
            "WHERE role='service' AND lifecycle_state='active'"
        ).fetchall()
        return [dict(r) for r in rows]

    # ──────────────── CVE ────────────────

    def upsert_cve_records_batch(self, records: List[Dict]) -> int:
        if not records:
            return 0
        sql = """INSERT INTO cve_records
            (cve_id, service, vendor, affected_version, severity, cvss_score,
             description, reference_url, published_at)
            VALUES (?,?,?,?,?,?, ?,?,?)
            ON CONFLICT(cve_id, service, affected_version) DO UPDATE SET
                severity=excluded.severity, cvss_score=excluded.cvss_score,
                description=excluded.description, updated_at=datetime('now')"""
        tuples = [(
            r.get("cve_id"), r.get("service"), r.get("vendor"),
            r.get("affected_version"), r.get("severity"), r.get("cvss_score"),
            r.get("description"), r.get("reference_url"), r.get("published_at"),
        ) for r in records]
        with self._lock:
            self._conn.executemany(sql, tuples)
            self._conn.commit()
            return len(tuples)

    def search_cves(self, service=None, severity=None, limit=50, offset=0) -> List[Dict]:
        conditions, params = [], []
        if service: conditions.append("service=?"); params.append(service)
        if severity: conditions.append("severity=?"); params.append(severity)
        where = (" WHERE " + " AND ".join(conditions)) if conditions else ""
        sql = f"SELECT * FROM cve_records{where} ORDER BY cvss_score DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        rows = self._read_conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def count_cves(self, service=None, severity=None) -> int:
        conditions, params = [], []
        if service: conditions.append("service=?"); params.append(service)
        if severity: conditions.append("severity=?"); params.append(severity)
        where = (" WHERE " + " AND ".join(conditions)) if conditions else ""
        return self._read_conn.execute(f"SELECT COUNT(*) FROM cve_records{where}", params).fetchone()[0]

    def list_all_cves(self) -> List[Dict]:
        rows = self._read_conn.execute(
            "SELECT * FROM cve_records ORDER BY cvss_score DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    # ──────────────── asset_lifecycle ────────────────

    def insert_lifecycle_event(self, ip, port=None, service=None, event_type="discovered",
                               old_state=None, new_state=None, detail=None):
        with self._lock:
            self._conn.execute(
                "INSERT INTO asset_lifecycle (ip, port, service, event_type, old_state, new_state, detail) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (ip, port, service, event_type, old_state, new_state,
                 json.dumps(detail, ensure_ascii=False) if isinstance(detail, dict) else detail)
            )
            self._conn.commit()

    def list_asset_lifecycle(self, ip=None, limit=50, offset=0) -> List[Dict]:
        sql = "SELECT * FROM asset_lifecycle"
        params = []
        if ip:
            sql += " WHERE ip=?"; params.append(ip)
        sql += " ORDER BY occurred_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    # ──────────────── 融合查询 ────────────────

    def get_fused_assets(self, ip=None, svc_type=None, source=None,
                         risk_level=None, lifecycle_state=None,
                         limit=100, offset=0) -> Dict:
        conditions, params = [], []
        if ip:
            conditions.append("s.ip=?"); params.append(ip)
        if svc_type:
            conditions.append("s.svc_type=?"); params.append(svc_type)
        if risk_level:
            conditions.append("s.risk_level=?"); params.append(risk_level)
        if lifecycle_state:
            conditions.append("s.lifecycle_state=?"); params.append(lifecycle_state)
        if source == "both":
            conditions.append("s.probe_seen=1")
        elif source == "scan":
            conditions.append("s.probe_seen=0")
        # source=None → no filter, show all
        where = (" WHERE " + " AND ".join(conditions)) if conditions else ""
        sql = f"""SELECT s.ip, s.port, s.service, s.vendor, s.svc_type, s.version,
                         s.models, s.lifecycle_state, s.scan_count, s.last_seen AS scan_last_seen,
                         s.probe_seen, s.probe_last_flow, s.fused_confidence,
                         s.risk_level, s.cve_count,
                         e.flow_count AS probe_flow_count,
                         e.last_seen AS probe_last_seen,
                         e.name AS probe_endpoint_name
                  FROM ai_services s
                  LEFT JOIN ai_endpoints e ON s.ip=e.ip AND e.role='service'
                  {where}
                  ORDER BY s.fused_confidence DESC NULLS LAST, s.risk_level, s.scan_count DESC
                  LIMIT ? OFFSET ?"""
        list_params = params + [limit, offset]
        rc = self._read_conn
        rows = rc.execute(sql, list_params).fetchall()
        # COUNT(DISTINCT s.id) 避免 LEFT JOIN 一对多时 total 重复计数（M1）
        total = rc.execute(
            f"SELECT COUNT(DISTINCT s.id) FROM ai_services s LEFT JOIN ai_endpoints e "
            f"ON s.ip=e.ip AND e.role='service' {where}", params
        ).fetchone()[0]
        return {"assets": [dict(r) for r in rows], "total": total}

    # ──────────────── 表行数（health 用）────────────────

    def table_counts(self) -> Dict[str, int]:
        """9 表 COUNT。加 10s 缓存（health 每 10s 轮询，命中缓存避免 9 次扫描）。"""
        now_mono = _mono()
        cached = self._table_counts_cache
        if cached and (now_mono - cached[0]) < 10.0:
            return cached[1]
        tables = ["flows", "ai_events", "ai_endpoints", "scan_targets",
                  "scan_tasks", "scan_findings", "ai_services", "cve_records",
                  "asset_lifecycle"]
        result = {}
        rc = self._read_conn
        for t in tables:
            try:
                result[t] = rc.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
            except Exception as e:
                logger.warning(f"table_counts {t} failed: {e}")
                result[t] = 0
        self._table_counts_cache = (now_mono, result)
        return result

    def db_file_size(self) -> int:
        try:
            return Path(self._db_path).stat().st_size
        except Exception:
            return 0
