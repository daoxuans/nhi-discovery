"""双源融合 — 置信度矩阵 + 权威源裁决。

融合键：Scan.ai_services.ip ←→ Probe.ai_endpoints.ip (role='service')
"""

# 置信度常量
CONF_DUAL_VERIFIED = 0.95   # Scan 命中(端口+API) + Probe 有流量
CONF_DUAL_PORT = 0.70       # Scan 命中(仅端口) + Probe 有流量
CONF_SCAN_ONLY_VERIFIED = 0.75  # Scan 命中(端口+API) + Probe 无流量（静默服务）
CONF_SCAN_ONLY_PORT = 0.40  # Scan 仅端口 + Probe 无流量（残留端口）
CONF_PROBE_ONLY = 0.60      # Scan 未命中 + Probe 有流量（终端 Agent 或非扫描网段）
CONF_CONFLICT = 0.30        # Scan 发现 A 但 Probe 流量指向 B（端口复用/冲突）


def compute_fused_confidence(scan_hit: bool, probe_hit: bool,
                             scan_api_verified: bool) -> float:
    """根据双源命中情况计算融合置信度。"""
    if scan_hit and probe_hit:
        return CONF_DUAL_VERIFIED if scan_api_verified else CONF_DUAL_PORT
    if scan_hit and not probe_hit:
        return CONF_SCAN_ONLY_VERIFIED if scan_api_verified else CONF_SCAN_ONLY_PORT
    if not scan_hit and probe_hit:
        return CONF_PROBE_ONLY
    return 0.0


# 属性权威源裁决：冲突时取权威源
SCAN_AUTHORITATIVE = {"version", "cve_count", "risk_level", "port", "proto", "models"}
PROBE_AUTHORITATIVE = {"agent", "flow_count", "frequency", "ja4", "user_agent"}


def resolve_authority(field: str, scan_value, probe_value):
    """冲突时按权威源裁决。"""
    if field in SCAN_AUTHORITATIVE:
        return scan_value
    if field in PROBE_AUTHORITATIVE:
        return probe_value
    # lifecycle_state: 双源加权（任一 active 则 active）
    if field == "lifecycle_state":
        if scan_value == "active" or probe_value == "active":
            return "active"
        if scan_value == "dormant" or probe_value == "dormant":
            return "dormant"
        return "decommissioned"
    return probe_value  # 默认取 Probe
