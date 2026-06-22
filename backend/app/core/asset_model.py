"""资产生命周期状态机。

状态流转：active → dormant → decommissioned
- active: 近期被发现（Scan 命中 或 Probe 有流量）
- dormant: 连续 3 轮 Scan 未发现 且 Probe 7 天无流量
- decommissioned: dormant 持续 30 天
复活：dormant/decommissioned 任一源重新发现 → active
"""

import json
import logging
from datetime import datetime, timedelta

from app.core.db import Database, now_cst

logger = logging.getLogger(__name__)

ACTIVE = "active"
DORMANT = "dormant"
DECOMMISSIONED = "decommissioned"

MISS_THRESHOLD = 3          # 连续 3 轮 Scan 未发现
PROBE_DORMANT_DAYS = 7      # Probe 7 天无流量
DORMANT_EXPIRE_DAYS = 30    # dormant 持续 30 天 → decommissioned


def record_discovery(db: Database, ip, port=None, service=None, source="scan"):
    """记录一次发现。新资产或 dormant 资产复活。"""
    # 判断当前状态（ai_services 或 ai_endpoints）
    with db.lock:
        if port is not None:
            row = db.conn.execute(
                "SELECT lifecycle_state FROM ai_services WHERE ip=? AND port=? AND service=?",
                (ip, port, service)
            ).fetchone()
        else:
            row = db.conn.execute(
                "SELECT lifecycle_state FROM ai_endpoints WHERE ip=? AND role='service'",
                (ip,)
            ).fetchone()
    old_state = row["lifecycle_state"] if row else None
    if old_state in (DORMANT, DECOMMISSIONED):
        db.insert_lifecycle_event(
            ip, port, service, "resurrected", old_state, ACTIVE,
            {"source": source}
        )
        logger.info("asset resurrected", extra={"ip": ip, "port": port, "service": service, "old": old_state})


def record_miss(db: Database, ip, port, service):
    """Scan 未发现已知 ai_service 时调用，miss_count += 1。"""
    with db.lock:
        row = db.conn.execute(
            "SELECT miss_count FROM ai_services WHERE ip=? AND port=? AND service=?",
            (ip, port, service)
        ).fetchone()
        if row is None:
            return
        db.conn.execute(
            "UPDATE ai_services SET miss_count = miss_count + 1 WHERE ip=? AND port=? AND service=?",
            (ip, port, service)
        )
        db.conn.commit()


def check_lifecycle_transitions(db: Database):
    """定时任务：扫描所有 active/dormant 资产，按规则流转状态。

    active → dormant: miss_count >= 3 且 Probe 7 天无流量
    dormant → decommissioned: dormant 持续 30 天
    同步检查 ai_services 和 ai_endpoints。
    """
    now = now_cst()
    cutoff_probe = (datetime.utcnow() + timedelta(hours=8) - timedelta(days=PROBE_DORMANT_DAYS)).strftime("%Y-%m-%d %H:%M:%S")
    cutoff_dormant = (datetime.utcnow() + timedelta(hours=8) - timedelta(days=DORMANT_EXPIRE_DAYS)).strftime("%Y-%m-%d %H:%M:%S")
    transitions = 0

    with db.lock:
        # ── ai_services: active → dormant ──
        rows = db.conn.execute(
            """SELECT ip, port, service FROM ai_services
               WHERE lifecycle_state='active' AND miss_count >= ?
               AND NOT EXISTS (
                   SELECT 1 FROM ai_endpoints
                   WHERE ip=ai_services.ip AND role='service'
                   AND last_seen > ?
               )""",
            (MISS_THRESHOLD, cutoff_probe)
        ).fetchall()
        for r in rows:
            db.conn.execute(
                "UPDATE ai_services SET lifecycle_state='dormant' WHERE ip=? AND port=? AND service=?",
                (r["ip"], r["port"], r["service"])
            )
            db.conn.execute(
                "INSERT INTO asset_lifecycle (ip, port, service, event_type, old_state, new_state, detail) "
                "VALUES (?, ?, ?, 'dormant', 'active', 'dormant', ?)",
                (r["ip"], r["port"], r["service"],
                 json.dumps({"reason": "miss_threshold_and_no_probe_flow"}))
            )
            transitions += 1

        # ── ai_services: dormant → decommissioned ──
        rows = db.conn.execute(
            """SELECT ip, port, service FROM ai_services
               WHERE lifecycle_state='dormant' AND last_seen < ?""",
            (cutoff_dormant,)
        ).fetchall()
        for r in rows:
            db.conn.execute(
                "UPDATE ai_services SET lifecycle_state='decommissioned' WHERE ip=? AND port=? AND service=?",
                (r["ip"], r["port"], r["service"])
            )
            db.conn.execute(
                "INSERT INTO asset_lifecycle (ip, port, service, event_type, old_state, new_state, detail) "
                "VALUES (?, ?, ?, 'decommissioned', 'dormant', 'decommissioned', ?)",
                (r["ip"], r["port"], r["service"],
                 json.dumps({"reason": "dormant_expired"}))
            )
            transitions += 1

        # ── ai_endpoints: active → dormant (Probe 侧) ──
        rows = db.conn.execute(
            """SELECT ip, role, name FROM ai_endpoints
               WHERE lifecycle_state='active' AND last_seen < ?""",
            (cutoff_probe,)
        ).fetchall()
        for r in rows:
            db.conn.execute(
                "UPDATE ai_endpoints SET lifecycle_state='dormant' WHERE ip=? AND role=? AND name=?",
                (r["ip"], r["role"], r["name"])
            )
            db.conn.execute(
                "INSERT INTO asset_lifecycle (ip, service, event_type, old_state, new_state, detail) "
                "VALUES (?, ?, 'dormant', 'active', 'dormant', ?)",
                (r["ip"], r["name"],
                 json.dumps({"role": r["role"], "reason": "no_flow_7d"}))
            )
            transitions += 1

        # ── ai_endpoints: dormant → decommissioned ──
        rows = db.conn.execute(
            """SELECT ip, role, name FROM ai_endpoints
               WHERE lifecycle_state='dormant' AND last_seen < ?""",
            (cutoff_dormant,)
        ).fetchall()
        for r in rows:
            db.conn.execute(
                "UPDATE ai_endpoints SET lifecycle_state='decommissioned' WHERE ip=? AND role=? AND name=?",
                (r["ip"], r["role"], r["name"])
            )
            db.conn.execute(
                "INSERT INTO asset_lifecycle (ip, service, event_type, old_state, new_state, detail) "
                "VALUES (?, ?, 'decommissioned', 'dormant', 'decommissioned', ?)",
                (r["ip"], r["name"],
                 json.dumps({"role": r["role"], "reason": "dormant_expired"}))
            )
            transitions += 1

        db.conn.commit()
    if transitions:
        logger.info(f"lifecycle transitions: {transitions}")
    return transitions
