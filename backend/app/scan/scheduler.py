"""Scan Scheduler — APScheduler AsyncIOScheduler。

定时任务：
  - Full scan: cron 00:00-06:00 每 30min（仅 enabled targets）
  - Incremental: 每 5min（已知 ai_services 活跃度复核）
  - CVE 复扫: 每日 02:30
  - Lifecycle check: 每日 03:00
  - Retention: 每日 02:00
默认不自动启动全量扫描（scan_targets.enabled 默认 0）。
"""

import asyncio
import logging

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

from app.config import settings
from app.core.db import Database
from app.scan.scan_runner import create_scan_task, run_scan_with_taskid
from app.scan.result_correlator import correlate_scan_results
from app.core.asset_model import check_lifecycle_transitions
from app.core.retention import run_daily_cleanup
from app.scan.cve_updater import update_from_nvd

logger = logging.getLogger(__name__)


class ScanScheduler:
    def __init__(self, db: Database):
        self.db = db
        self.scheduler = AsyncIOScheduler()

    def start(self):
        # ── 全量扫描：00:00-06:00 每 30min，仅 enabled targets ──
        self.scheduler.add_job(
            _run_full_scan, CronTrigger(hour="0-5", minute="*/30"),
            args=[self.db], id="full_scan", replace_existing=True,
        )
        # ── 增量扫描：每 5min ──
        self.scheduler.add_job(
            _run_incremental_scan, CronTrigger(minute="*/5"),
            args=[self.db], id="incremental_scan", replace_existing=True,
        )
        # ── CVE 复扫：每日 02:30 ──
        self.scheduler.add_job(
            _run_cve_rescan, CronTrigger(hour=2, minute=30),
            args=[self.db], id="cve_rescan", replace_existing=True,
        )
        # ── Lifecycle check：每日 03:00 ──
        self.scheduler.add_job(
            check_lifecycle_transitions, CronTrigger(hour=3, minute=0),
            args=[self.db], id="lifecycle_check", replace_existing=True,
        )
        # ── Retention：每日 02:00 ──
        self.scheduler.add_job(
            run_daily_cleanup, CronTrigger(hour=2, minute=0),
            args=[self.db], id="retention_daily", replace_existing=True,
        )
        # ── NVD 更新：每日 02:15 ──
        self.scheduler.add_job(
            update_from_nvd, CronTrigger(hour=2, minute=15),
            args=[self.db], id="nvd_update", replace_existing=True,
        )
        self.scheduler.start()
        logger.info("ScanScheduler started (full=00-05/30min, incr=*/5min, "
                    "cve=02:30, lifecycle=03:00, retention=02:00, nvd=02:15)")

    def shutdown(self):
        self.scheduler.shutdown(wait=False)
        logger.info("ScanScheduler stopped")


async def _run_full_scan(db: Database):
    """对 enabled=1 的 scan_targets 执行全量扫描。"""
    targets = db.list_scan_targets(enabled_only=True)
    if not targets:
        return
    for target in targets:
        try:
            task_id, _, cidr, tgt = create_scan_task(db, target["id"], None, "full")
            await run_scan_with_taskid(db, task_id, tgt, cidr, "full")
            correlate_scan_results(db, task_id)
            _mark_misses(db, task_id, cidr)
        except Exception as e:
            logger.error(f"full scan target {target['name']} failed: {e}", exc_info=True)


async def _run_incremental_scan(db: Database):
    """增量扫描：仅扫已知 ai_services 的端口复核活跃度。"""
    from app.scan.workers.port_prober import probe_ports
    from app.scan.workers.api_prober import probe_api, PORT_API_MAP
    import aiohttp
    services = db.list_ai_service_ips()
    if not services:
        return
    async with aiohttp.ClientSession() as session:
        for svc in services[:50]:  # 限制每轮 50 个
            try:
                if svc["port"] in PORT_API_MAP:
                    api_finding = await probe_api(session, svc["ip"], svc["port"],
                                                  settings.scan_api_timeout)
                    if api_finding and api_finding.api_status == 200:
                        db.upsert_ai_service(
                            ip=svc["ip"], port=svc["port"], service=svc["service"],
                            vendor=svc.get("vendor"),
                            version=api_finding.version_detected,
                            models=api_finding.models_detected, source="scan",
                        )
            except Exception as e:
                logger.warning(f"incremental probe failed {svc['ip']}:{svc['port']}: {type(e).__name__}: {e}")


async def _run_cve_rescan(db: Database):
    """CVE 库更新后对已知版本重扫。"""
    from app.scan.workers.version_extractor import correlate_cve
    services = db.list_ai_service_ips()
    for svc in services:
        cves = correlate_cve(db, svc.get("vendor"), None)
        if cves:
            risk = "high" if any(c.get("severity") in ("critical", "high") for c in cves) else "medium"
            db.update_ai_service_fusion(
                svc["ip"], svc["port"], svc["service"],
                risk_level=risk, cve_count=len(cves),
            )


def _mark_misses(db: Database, task_id: int, cidr: str = None):
    """本轮未发现的已知 ai_services → miss_count += 1。

    关键修复：只标记落在本轮扫描 CIDR 范围内的服务。旧实现无脑标记所有
    active 服务，导致每个网段扫描后全网段服务都 +1 miss，~15 分钟内全部
    误判为 dormant。
    """
    from app.core.asset_model import record_miss
    import ipaddress

    # 取本轮 scan_findings 命中的 IP 集合（命中即不算 miss）
    with db.lock:
        found_rows = db.conn.execute(
            "SELECT DISTINCT ip FROM scan_findings WHERE task_id=?", (task_id,)
        ).fetchall()
    found_ips = {r["ip"] for r in found_rows}

    # 只考虑本轮扫描 CIDR 范围内的 active 服务
    networks = []
    if cidr:
        for part in str(cidr).replace(",", " ").split():
            try:
                networks.append(ipaddress.ip_network(part, strict=False))
            except ValueError:
                pass

    with db.lock:
        rows = db.conn.execute(
            "SELECT ip, port, service FROM ai_services WHERE lifecycle_state='active'"
        ).fetchall()

    for r in rows:
        ip = r["ip"]
        # 若指定了 CIDR，只处理落在范围内的 IP；范围外本轮根本没扫，不应计 miss
        if networks:
            try:
                ip_obj = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if not any(ip_obj in net for net in networks):
                continue
        # 命中的不算 miss
        if ip in found_ips:
            continue
        record_miss(db, ip, r["port"], r["service"])
