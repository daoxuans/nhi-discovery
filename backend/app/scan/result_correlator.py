"""Result Correlator — 双源融合执行核心。

Scan 完成后调用 correlate_scan_results：
  - 对每个 ai_service 查 Probe ai_endpoints(role=service) 同 IP
  - 命中 → fused_confidence=0.95, probe_seen=1, probe_last_flow
  - 未命中 → fused_confidence=0.75, probe_seen=0
  - 双向回写 ai_services + ai_endpoints
  - 冲突（Scan A vs Probe B）→ fused=0.30 + conflict 事件
"""

import logging

from app.core.db import Database, now_cst
from app.core.fusion import (compute_fused_confidence, CONF_DUAL_VERIFIED,
                             CONF_SCAN_ONLY_VERIFIED, CONF_PROBE_ONLY, CONF_CONFLICT)

logger = logging.getLogger(__name__)


def correlate_scan_results(db: Database, task_id: int):
    """扫描完成后融合本轮发现的 ai_services 与 Probe ai_endpoints。"""
    # 本轮发现的 ai_services（按 ip 去重）
    scan_services = db.list_ai_service_ips()
    if not scan_services:
        logger.info(f"correlate task {task_id}: no ai_services to fuse")
        return {"fused": 0, "dual": 0, "scan_only": 0, "conflicts": 0}

    fused = 0
    dual = 0
    scan_only = 0
    conflicts = 0

    for svc in scan_services:
        ip = svc["ip"]
        port = svc["port"]
        service = svc["service"]
        # 查 Probe 侧该 IP 的 service 端点
        probe_endpoints = db.get_probe_endpoints_for_ip(ip)
        probe_hit = len(probe_endpoints) > 0
        # 冲突检测：Scan service 与 Probe endpoint name 不一致
        conflict = False
        probe_last_flow = None
        if probe_hit:
            probe_last_flow = probe_endpoints[0]["last_seen"]
            for pe in probe_endpoints:
                if pe["name"].lower() not in (service or "").lower() and \
                   (service or "").lower() not in pe["name"].lower():
                    # 名称不一致 → 冲突
                    conflict = True
                    break

        # 计算融合置信度（Scan 命中视为 api_verified，因 upsert 前已验证）
        if conflict:
            fused_conf = CONF_CONFLICT
            conflicts += 1
            db.insert_lifecycle_event(
                ip=ip, port=port, service=service,
                event_type="conflict", new_state=str(fused_conf),
                detail={"scan_service": service,
                        "probe_services": [pe["name"] for pe in probe_endpoints]},
            )
        else:
            fused_conf = compute_fused_confidence(
                scan_hit=True, probe_hit=probe_hit, scan_api_verified=True
            )
            if probe_hit:
                dual += 1
            else:
                scan_only += 1

        # 回写 ai_services
        db.update_ai_service_fusion(
            ip, port, service,
            probe_seen=1 if probe_hit else 0,
            probe_last_flow=probe_last_flow,
            fused_confidence=fused_conf,
        )
        # 回写 ai_endpoints（反向：Probe 侧标记 scan_seen）
        if probe_hit:
            db.update_ai_endpoint_fusion(
                ip, scan_seen=1, scan_last_seen=now_cst(),
                fused_confidence=fused_conf,
            )
        fused += 1

    logger.info(f"correlate task {task_id}: fused={fused}, dual={dual}, "
                f"scan_only={scan_only}, conflicts={conflicts}")
    return {"fused": fused, "dual": dual, "scan_only": scan_only, "conflicts": conflicts}


def correlate_probe_to_scan(db: Database, ip: str):
    """Probe 新增 service 端点时，反向检查 Scan 侧是否见过该 IP。

    可选：在 AiWriter.upsert_ai_endpoint 后调用，补全 Probe-only 资产的融合信号。
    """
    scan_svcs = [s for s in db.list_ai_service_ips() if s["ip"] == ip]
    scan_hit = len(scan_svcs) > 0
    if scan_hit:
        # Scan 已见过，由 correlate_scan_results 处理
        return
    # Probe 单源：fused=0.60
    db.update_ai_endpoint_fusion(ip, scan_seen=0, fused_confidence=CONF_PROBE_ONLY)
