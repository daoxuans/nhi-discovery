"""Target Manager — 扫描目标网段配置 CRUD + 种子数据。"""

import logging

from app.core.db import Database

logger = logging.getLogger(__name__)

# 默认种子目标（enabled=0，需运维显式启用）
_SEED_TARGETS = [
    {"name": "office", "cidr": "192.168.1.0/24", "scan_strategy": "ai_ports_only",
     "full_interval": 7200, "incr_interval": 600},
    {"name": "gpu", "cidr": "10.10.20.0/24", "scan_strategy": "full",
     "full_interval": 1800, "incr_interval": 300},
    {"name": "server", "cidr": "10.10.30.0/24", "scan_strategy": "web_only",
     "full_interval": 1800, "incr_interval": 300},
]


def seed_if_empty(db: Database):
    """scan_targets 为空时插入种子数据。"""
    existing = db.list_scan_targets()
    if existing:
        return
    for t in _SEED_TARGETS:
        db.insert_scan_target(
            name=t["name"], cidr=t["cidr"], scan_strategy=t["scan_strategy"],
            full_interval=t["full_interval"], incr_interval=t["incr_interval"],
            enabled=0,
        )
    logger.info(f"seeded {len(_SEED_TARGETS)} scan targets (all disabled)")


def list_targets(db: Database, enabled_only=False):
    return db.list_scan_targets(enabled_only=enabled_only)


def get_target(db: Database, target_id: int):
    return db.get_scan_target(target_id)
