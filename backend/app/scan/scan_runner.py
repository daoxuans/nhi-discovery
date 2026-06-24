"""Scan Runner — 编排核心：5 个 Prober 串/并 + ai_services UPSERT + CVE 关联。

流程：
  Stage 1 Port Prober (nmap, 全网段串行)
  Stage 2-5 对每个开放端口并发 (Semaphore(64))：
    - AI 框架端口 → API Prober
    - Web 端口 → Web Fingerprinter
    - Docker/K8s 端口 → Container Prober
    - 统一 → Version Extractor + CVE Correlator
  → insert_scan_findings_batch + upsert_ai_service
"""

import asyncio
import logging
import uuid
from typing import List

import aiohttp

from app.config import settings
from app.core.db import Database, now_cst
from app.scan.rate_limiter import GlobalRateLimiter, PerTargetRateLimiter
from app.scan.workers.port_prober import probe_ports, PortFinding, AI_PORTS, WEB_PORTS
from app.scan.workers.api_prober import probe_api, ApiFinding, PORT_API_MAP
from app.scan.workers.web_fingerprinter import fingerprint_web, WebFinding, WEB_PORTS as WEB_FP_PORTS
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
    """
    # 解析速率档位：优先显式 speed，其次 target 的 speed 列，最后回退默认
    speed = speed or (target.get("speed") if target else None) or "normal"
    profile = _SPEED_PROFILES.get(speed, _SPEED_PROFILES["normal"])
    rate_pps = profile["rate_pps"]
    per_target_qps = profile["per_target_qps"]
    nmap_T = profile["nmap_T"]

    scan_strategy = (target["scan_strategy"] if target else "full")
    concurrency = settings.scan_concurrency
    api_timeout = settings.scan_api_timeout

    db.update_scan_task(task_id, status="running", started_at=now_cst())
    logger.info(f"scan task {task_id} ({task_type}) started for {cidr} "
                f"(strategy={scan_strategy}, speed={speed}, pps={rate_pps}, T={nmap_T})")

    try:
        # ── Stage 1: Port Prober ──
        if scan_strategy == "ai_ports_only":
            ports = AI_PORTS
        elif scan_strategy == "web_only":
            ports = WEB_PORTS
        else:
            ports = list(set(AI_PORTS + WEB_PORTS))

        port_findings: List[PortFinding] = await probe_ports(
            cidr, ports, rate_pps, timeout=settings.scan_port_timeout, nmap_timing=nmap_T
        )
        db.update_scan_task(task_id, targets_scanned=len(port_findings))
        logger.info(f"scan {task_id}: {len(port_findings)} open ports found")

        if not port_findings:
            db.update_scan_task(task_id, status="done", finished_at=now_cst(), findings_count=0)
            return task_id

        # ── Stage 2-5: 并发探测每个开放端口 ──
        global_limiter = GlobalRateLimiter(rate_pps)
        target_limiter = PerTargetRateLimiter(per_target_qps)
        sem = asyncio.Semaphore(concurrency)
        scan_findings = []
        ai_service_upserts = []

        async with aiohttp.ClientSession() as session:

            async def _probe_one(pf: PortFinding):
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
                            # 始终记录探测结果（审计用），但 ai_vendor 仅在确认时填
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
                            # 仅高置信度（有模型或健康检查通过）才进 ai_services
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

                    if pf.port in WEB_FP_PORTS and not (api_finding and api_finding.vendor):
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

            await asyncio.gather(*[_probe_one(pf) for pf in port_findings])

        # ── 写入 scan_findings ──
        if scan_findings:
            db.insert_scan_findings_batch(scan_findings)

        # ── UPSERT ai_services + CVE 关联 ──
        # 一次扫描只 load 一次全量 CVE（B7：避免每服务重复全表读）
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
            ports_scanned=len(port_findings), findings_count=len(scan_findings),
        )
        logger.info(f"scan task {task_id} done: {len(scan_findings)} findings, "
                    f"{len(ai_service_upserts)} AI services")

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


async def run_scan(db: Database, target_id: int = None, cidr: str = None,
                   task_type: str = "manual") -> int:
    """便捷入口：创建 task + 执行。"""
    task_id, task_uuid, cidr, target = create_scan_task(db, target_id, cidr, task_type)
    return await run_scan_with_taskid(db, task_id, target, cidr, task_type)
