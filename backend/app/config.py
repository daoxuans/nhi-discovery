"""统一应用配置。"""

import os
from dataclasses import dataclass, field


@dataclass
class Settings:
    # ── 数据库 ──
    db_path: str = field(
        default_factory=lambda: os.getenv(
            "DB_PATH", "/opt/nhi-discovery/backend/data/ndpid.db"
        )
    )
    host: str = field(default_factory=lambda: os.getenv("HOST", "0.0.0.0"))
    port: int = field(default_factory=lambda: int(os.getenv("PORT", "8000")))
    data_dir: str = field(
        default_factory=lambda: os.getenv(
            "DATA_DIR", "/opt/nhi-discovery/backend/data"
        )
    )

    # ── Probe (被动发现) ──
    # 实际消费的是 distributor socket（原 collector_socket 命名混淆，已重命名）
    distributor_socket: str = field(
        default_factory=lambda: os.getenv(
            "DISTRIBUTOR_SOCKET", "/tmp/ndpid-distributor.sock"
        )
    )
    ndpisrvd_py: str = field(
        default_factory=lambda: os.getenv(
            "NDPISRVD_PY", "/opt/nDPId/dependencies/nDPIsrvd.py"
        )
    )
    session_id: str = field(default_factory=lambda: os.getenv("SESSION_ID", "default"))

    # ── DbWriter (Probe flows 批量写入) ──
    db_writer_batch_interval: float = field(
        default_factory=lambda: float(os.getenv("DB_WRITER_BATCH_INTERVAL", "1.0"))
    )
    db_writer_batch_size: int = field(
        default_factory=lambda: int(os.getenv("DB_WRITER_BATCH_SIZE", "500"))
    )

    # ── Scan (主动发现) ──
    scan_global_pps: int = field(
        default_factory=lambda: int(os.getenv("SCAN_GLOBAL_PPS", "500"))
    )
    scan_per_target_qps: int = field(
        default_factory=lambda: int(os.getenv("SCAN_PER_TARGET_QPS", "10"))
    )
    scan_window: str = field(
        default_factory=lambda: os.getenv("SCAN_WINDOW", "00:00-06:00")
    )
    scan_concurrency: int = field(
        default_factory=lambda: int(os.getenv("SCAN_CONCURRENCY", "64"))
    )
    scan_api_timeout: float = field(
        default_factory=lambda: float(os.getenv("SCAN_API_TIMEOUT", "3.0"))
    )
    scan_port_timeout: int = field(
        default_factory=lambda: int(os.getenv("SCAN_PORT_TIMEOUT", "300"))
    )
    # Scan 调度器是否启用自动扫描（默认 False，需运维显式启用 scan_targets）
    scan_scheduler_enabled: bool = field(
        default_factory=lambda: os.getenv("SCAN_SCHEDULER_ENABLED", "0") == "1"
    )

    # ── 数据保留策略 ──
    retention_flows_days: int = field(
        default_factory=lambda: int(os.getenv("RETENTION_FLOWS_DAYS", "90"))
    )
    retention_ai_events_days: int = field(
        default_factory=lambda: int(os.getenv("RETENTION_AI_EVENTS_DAYS", "180"))
    )
    retention_scan_findings_days: int = field(
        default_factory=lambda: int(os.getenv("RETENTION_SCAN_FINDINGS_DAYS", "90"))
    )
    retention_scan_tasks_days: int = field(
        default_factory=lambda: int(os.getenv("RETENTION_SCAN_TASKS_DAYS", "90"))
    )
    retention_lifecycle_days: int = field(
        default_factory=lambda: int(os.getenv("RETENTION_LIFECYCLE_DAYS", "365"))
    )


settings = Settings()
