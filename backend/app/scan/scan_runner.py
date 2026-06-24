"""Scan Runner — 编排核心：5 个 Prober 串/并 + ai_services UPSERT + CVE 关联。

deep 策略：每个 IP 独立流水线（边扫边出结果）：
  1. nmap -sn 探活 → 存活 IP 列表
  2. 每 IP 管道并行（Semaphore(8)）：
     a. probe_ports_single（-Pn 全端口）→ 得到开放端口
     b. 立刻对这些端口做内容指纹（API/Web/容器）
     c. 立刻写入 scan_findings + ai_services + CVE 关联
     d. 更新进度 done/total
  3. 全部 IP 完成后做双源融合

quick 策略保留原有单次 nmap 快扫。
"""

import asyncio
import logging
import uuid
from typing import List

import aiohttp

from app.config import settings
from app.core.db import Database, now_cst
from app.scan.rate_limiter import GlobalRateLimiter, PerTargetRateLimiter
from app.scan.workers.port_prober import (
    probe_ports, probe_live, probe_ports_single, PortFinding, QUICK_PORTS,
)
from app.scan.workers.api_prober import probe_api, ApiFinding, PORT_API_MAP
from app.scan.workers.web_fingerprinter import fingerprint_web, WebFinding
from app.scan.workers.container_prober import probe_container, ContainerFinding
from app.scan.workers.version_extractor import extract_version, correlate_cve

logger = logging.getLogger(__name__)


def _risk_from_cves(cves: List[dict]) -> str:
    if not cves:
        return "low"
    severities = [c.get("severity", "low") for c in cves]
    if "critical" in severities or "high" in severities:
        return "high"
    if "medium" in severities:
        return "medium"
    return "low"


_SPEED_PROFILES = {
    "slow":   {"rate_pps": 100,  "per_target_qps": 5,  "nmap_T": "-T2"},
    "normal": {"rate_pps": 500,  "per_target_qps": 10, "nmap_T": "-T3"},
    "fast":   {"rate_pps": 2000, "per_target_qps": 30, "nmap_T": "-T4"},
}


def create_scan_task(db: Database, target_id, cidr, task_type="manual",
                     speed=None, scan_strategy=None):
    """创建扫描任务行，返回 (task_id, task_uuid, resolved_cidr, target)。

    speed/scan_strategy 仅在 ad-hoc（无 target_id）扫描时生效，覆盖默认。
    """
    task_uuid = str(uuid.uuid4())[:13] + "-scan"
    target = db.get_scan_target(target_id) if target_id else None
    if target:
        cidr = target["cidr"]
    if not cidr:
        raise ValueError("cidr or target_id required")
    task_id = db.insert_scan_task(task_uuid, target_id, task_type)
    return task_id, task_uuid, cidr, target


async def run_scan_with_taskid(db: Database, task_id: int, target, cidr: str,
                               task_type: str = "manual", speed: str = None):
    """对已存在的 task_id 执行扫描核心逻辑。

    速率优先级：显式 speed > target.speed > target.rate_limit_pps > 默认。

    deep 策略：
      1. nmap -sn 探活 → 存活 IP 列表
      2. 逐 IP 全端口扫描（-Pn），8 路并行，每完成一个 IP 更新进度
      3. 逐端口内容指纹，每完成一个端口更新进度
    quick 策略：单次 nmap 快扫 10 个 AI 默认端口。
    """
    speed = speed or (target.get("speed") if target else None) or "normal"
    profile = _SPEED_PROFILES.get(speed, _SPEED_PROFILES["normal"])
    rate_pps = profile["rate_pps"]
    per_target_qps = profile["per_target_qps"]
    nmap_T = profile["nmap_T"]

    scan_strategy = (target["scan_strategy"] if target else "deep")
    concurrency = settings.scan_concurrency
    api_timeout = settings.scan_api_timeout

    db.update_scan_task(task_id, status="running", started_at=now_cst())
    logger.info(f"scan task {task_id} ({task_type}) started for {cidr} "
                f"(strategy={scan_strategy}, speed={speed}, pps={rate_pps}, T={nmap_T})")

    try:
        if scan_strategy == "quick":
            # 快速探测：单次 nmap 扫 10 个 AI 默认端口
            port_findings: List[PortFinding] = await probe_ports(
                cidr, QUICK_PORTS, rate_pps,
                timeout=settings.scan_port_timeout, nmap_timing=nmap_T,
            )
            db.update_scan_task(task_id, targets_scanned=len(port_findings))
            logger.info(f"scan {task_id}: {len(port_findings)} open ports found")

            if not port_findings:
                db.update_scan_task(task_id, status="done", finished_at=now_cst(),
                                  findings_count=0)
                return task_id

            # quick 策略也做内容指纹（和原来一样）
            global_limiter = GlobalRateLimiter(rate_pps)
            target_limiter = PerTargetRateLimiter(per_target_qps)
            sem = asyncio.Semaphore(concurrency)
            scan_findings = []
            ai_service_upserts = []
            async with aiohttp.ClientSession() as session:
                await asyncio.gather(*[
                    _probe_one_port(db, task_id, pf, session, sem, global_limiter,
                                   target_limiter, api_timeout, ai_service_upserts,
                                   scan_findings) for pf in port_findings
                ])
            await _write_scan_results(db, task_id, scan_findings, ai_service_upserts,
                                      len(port_findings))
        else:
            # 深度指纹：每 IP 独立管道 — 探活 → 端口扫描 → 内容指纹 → 即时写库
            await _run_deep_scan_pipeline(
                db, task_id, cidr, rate_pps, nmap_T, per_target_qps,
                concurrency, api_timeout,
            )

        # ── 双源融合 ──
        try:
            from app.scan.result_correlator import correlate_scan_results
            result = correlate_scan_results(db, task_id)
            logger.info(f"scan task {task_id} fusion: {result}")
        except Exception as e:
            logger.error(f"correlate failed for task {task_id}: {e}", exc_info=True)

        return task_id

    except Exception as e:
        logger.error(f"scan task {task_id} failed: {type(e).__name__}: {e}", exc_info=True)
        db.update_scan_task(task_id, status="failed", finished_at=now_cst(),
                            error_msg=f"{type(e).__name__}: {e}")
        return task_id


async def _probe_one_port(db: Database, task_id: int, pf: PortFinding,
                          session: aiohttp.ClientSession, sem: asyncio.Semaphore,
                          global_limiter: GlobalRateLimiter,
                          target_limiter: PerTargetRateLimiter,
                          api_timeout: float,
                          ai_service_upserts: List[dict],
                          scan_findings: List[dict]):
    """对单个开放端口做内容指纹探测。"""
    async with sem:
        await global_limiter.acquire()
        await target_limiter.acquire(pf.ip)
        finding_dict = {
            "task_id": task_id, "ip": pf.ip, "port": pf.port,
            "proto": pf.proto, "state": pf.state,
            "service_raw": pf.service_raw, "banner": pf.banner,
            "found_at": now_cst(),
        }
        api_finding = None
        web_finding = None
        container_finding = None

        if pf.port in PORT_API_MAP:
            api_finding = await probe_api(session, pf.ip, pf.port, api_timeout)
            if api_finding:
                finding_dict.update({
                    "api_path": api_finding.api_path,
                    "api_status": api_finding.api_status,
                    "api_response": api_finding.api_response,
                    "models_detected": api_finding.models_detected,
                    "version_detected": api_finding.version_detected,
                    "ai_vendor": api_finding.vendor,
                    "ai_service": api_finding.service,
                    "ai_svc_type": api_finding.svc_type,
                    "confidence": api_finding.confidence,
                })
                if (api_finding.confidence >= 0.6
                        and api_finding.vendor
                        and api_finding.service):
                    ai_service_upserts.append({
                        "ip": pf.ip, "port": pf.port,
                        "vendor": api_finding.vendor,
                        "service": api_finding.service,
                        "svc_type": api_finding.svc_type,
                        "version": api_finding.version_detected,
                        "models": api_finding.models_detected,
                    })

        if not (api_finding and api_finding.vendor):
            web_finding = await fingerprint_web(session, pf.ip, pf.port, api_timeout)
            if web_finding:
                finding_dict.update({
                    "favicon_hash": web_finding.favicon_hash,
                    "html_features": web_finding.html_features,
                    "platform_guess": web_finding.platform_guess,
                    "confidence": web_finding.confidence,
                    "ai_vendor": web_finding.platform_guess,
                    "ai_service": web_finding.platform_guess,
                    "ai_svc_type": "AI_Platform" if web_finding.platform_guess else None,
                })
                if web_finding.platform_guess and web_finding.confidence >= 0.7:
                    ai_service_upserts.append({
                        "ip": pf.ip, "port": pf.port,
                        "vendor": web_finding.platform_guess,
                        "service": web_finding.platform_guess,
                        "svc_type": "AI_Platform",
                        "version": None, "models": [],
                    })

        if pf.port in (2375, 2376, 6443):
            container_finding = await probe_container(session, pf.ip, pf.port, api_timeout)
            if container_finding:
                finding_dict.update({
                    "api_path": f"/{container_finding.kind}",
                    "api_status": 200,
                    "api_response": ",".join(container_finding.ai_workloads)[:200],
                    "ai_vendor": container_finding.kind,
                    "ai_service": container_finding.kind,
                    "ai_svc_type": "Container",
                    "confidence": container_finding.confidence,
                })
                if container_finding.ai_workloads:
                    ai_service_upserts.append({
                        "ip": pf.ip, "port": pf.port,
                        "vendor": container_finding.kind,
                        "service": container_finding.kind,
                        "svc_type": "Container",
                        "version": None,
                        "models": container_finding.ai_workloads,
                    })

        scan_findings.append(finding_dict)


async def _write_scan_results(db: Database, task_id: int,
                              scan_findings: List[dict],
                              ai_service_upserts: List[dict],
                              ports_scanned: int):
    """写扫描结果：scan_findings + ai_services + CVE 关联 + 标记完成。"""
    if scan_findings:
        db.insert_scan_findings_batch(scan_findings)

    cached_cves = db.list_all_cves()
    for svc in ai_service_upserts:
        db.upsert_ai_service(
            ip=svc["ip"], port=svc["port"], service=svc["service"],
            vendor=svc["vendor"], svc_type=svc["svc_type"],
            version=svc["version"], models=svc["models"], source="scan",
        )
        cves = correlate_cve(db, svc["vendor"], svc["version"], cached_cves=cached_cves)
        if cves:
            risk = _risk_from_cves(cves)
            db.update_ai_service_fusion(
                svc["ip"], svc["port"], svc["service"],
                risk_level=risk, cve_count=len(cves),
            )
            for cve in cves:
                db.insert_lifecycle_event(
                    ip=svc["ip"], port=svc["port"], service=svc["service"],
                    event_type="discovered", new_state=risk,
                    detail={"cve": cve["cve_id"], "severity": cve["severity"]},
                )

    db.update_scan_task(
        task_id, status="done", finished_at=now_cst(),
        ports_scanned=ports_scanned, findings_count=len(scan_findings),
    )
    logger.info(f"scan task {task_id} done: {len(scan_findings)} findings, "
                f"{len(ai_service_upserts)} AI services")


async def _run_deep_scan_pipeline(db: Database, task_id: int, cidr: str,
                                  rate_pps: int, nmap_T: str,
                                  per_target_qps: int, concurrency: int,
                                  api_timeout: float):
    """deep 策略：每 IP 独立管道。

    每个存活 IP 做：端口扫描 → 内容指纹 → 即时写库。
    8 路并行管道，每完成一个 IP 更新一次进度。
    """
    # Step 1: 探活
    db.update_scan_task(task_id, progress_phase="host_discovery", progress_total=0, progress_done=0)
    live_ips = await probe_live(cidr)
    total = len(live_ips)
    if total == 0:
        logger.info(f"scan {task_id}: no live hosts, done")
        db.update_scan_task(task_id, status="done", finished_at=now_cst(), findings_count=0)
        return

    db.update_scan_task(
        task_id, progress_phase="port_scan",
        progress_total=total, progress_done=0,
    )

    # Step 2: 每 IP 独立管道，8 路并发
    pipe_sem = asyncio.Semaphore(8)
    content_sem = asyncio.Semaphore(concurrency)
    progress_lock = asyncio.Lock()
    completed = 0
    total_scan_findings = 0
    total_ai_services = 0

    async def _pipeline_one_ip(ip: str):
        """一个 IP 的完整管道：端口扫描 → 内容指纹 → 写库。"""
        nonlocal completed, total_scan_findings, total_ai_services

        async with pipe_sem:
            # 2a. 单 IP 全端口扫描
            port_findings = await probe_ports_single(
                ip, rate_pps, timeout=settings.scan_port_timeout,
                nmap_timing=nmap_T,
            )

            if port_findings:
                # 2b. 对这些端口做内容指纹
                gl = GlobalRateLimiter(rate_pps)
                ptl = PerTargetRateLimiter(per_target_qps)
                ip_findings = []
                ip_services = []
                async with aiohttp.ClientSession() as session:
                    tasks = [
                        _probe_one_port(
                            db, task_id, pf, session, content_sem, gl, ptl,
                            api_timeout, ip_services, ip_findings,
                        ) for pf in port_findings
                    ]
                    await asyncio.gather(*tasks)

                # 2c. 即时写库
                if ip_findings:
                    db.insert_scan_findings_batch(ip_findings)
                cached_cves = db.list_all_cves()
                for svc in ip_services:
                    db.upsert_ai_service(**{k: svc[k] for k in
                        ("ip", "port", "service", "vendor", "svc_type", "version", "models")},
                        source="scan")
                    cves = correlate_cve(db, svc["vendor"], svc["version"], cached_cves=cached_cves)
                    if cves:
                        risk = _risk_from_cves(cves)
                        db.update_ai_service_fusion(
                            svc["ip"], svc["port"], svc["service"],
                            risk_level=risk, cve_count=len(cves),
                        )
                total_scan_findings += len(ip_findings)
                total_ai_services += len(ip_services)

        # 2d. 更新进度
        async with progress_lock:
            completed += 1
            cur = completed
        db.update_scan_task(task_id, progress_done=cur,
                           findings_count=total_scan_findings)
        logger.info(f"scan {task_id}: IP {ip} done ({cur}/{total}), "
                    f"{len(port_findings)} ports, {len(ip_services) if port_findings else 0} AI")

    await asyncio.gather(*[_pipeline_one_ip(ip) for ip in live_ips])

    # 标记完成
    db.update_scan_task(task_id, status="done", finished_at=now_cst(),
                       findings_count=total_scan_findings)
    logger.info(f"scan {task_id} done: {total} hosts → {total_scan_findings} findings, "
                f"{total_ai_services} AI services")


async def run_scan(db: Database, target_id: int = None, cidr: str = None,
                   task_type: str = "manual") -> int:
    """便捷入口：创建 task + 执行。"""
    task_id, task_uuid, cidr, target = create_scan_task(db, target_id, cidr, task_type)
    return await run_scan_with_taskid(db, task_id, target, cidr, task_type)
