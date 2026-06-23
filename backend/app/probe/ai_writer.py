"""AiWriter — AI 事件持久化（新增核心）。

detected/detection-update 事件 → 提取信号 → discover_ai_service + infer_agent
→ 单事务 3 行：INSERT ai_events + UPSERT ai_endpoints(service行 + agent行)。

路径 B：无 category 门控，对所有 detected 事件调 discover_ai_service()，
非 AI 流返回 None 自然过滤。svc/agent 为 None 时 ai_events 仍写入（保留原始信号）。
"""

import logging
from typing import Dict, Optional

from app.core.db import Database
from app.probe.ai_service import discover_ai_service
from app.probe.ai_agent import infer_agent

logger = logging.getLogger(__name__)


def _get_nested(ndpi: dict, *keys, default=None):
    """安全遍历嵌套 dict。"""
    v = ndpi
    for k in keys:
        if isinstance(v, dict):
            v = v.get(k)
        else:
            return default
    return v if v is not None else default


# Agent 名 → 默认 svc_type 映射（当 service 未识别时兜底分类）
_AGENT_CATEGORY_FALLBACK = {
    "Claude Code": "AI_Coding",
    "Codex CLI": "AI_Coding",
    "Cursor": "AI_Coding",
    "GitHub Copilot": "AI_Coding",
    "Qoder": "AI_Coding",
    "Trae": "AI_Coding",
    "CodeBuddy": "AI_Coding",
    "Lingma": "AI_Coding",
    "Lingma (通义灵码)": "AI_Coding",
    "Windsurf": "AI_Coding",
    "Cline": "AI_Coding",
    "WorkBuddy / CodeBuddy": "AI_Coding",
    "Claude Web": "LLM_Web",
    "ChatGPT Web": "LLM_Web",
    "DeepSeek Chat Web": "LLM_Web",
    "Doubao Client (豆包)": "LLM_Web",
    "Claude Client": "LLM_API",
    "OpenAI Client": "LLM_API",
    "DeepSeek Client": "LLM_API",
    "Ollama Client": "LLM_Local",
    "vLLM Client": "LLM_Local",
    "Triton Client": "LLM_Local",
    "MCP Agent": "AI_Protocol",
    "OpenRouter Client": "LLM_Gateway",
    "Ruijie Gateway Client": "LLM_Gateway",
    "Portkey Client": "LLM_Gateway",
}


def _infer_agent_category(agent_name: str) -> str:
    """根据 agent 名推断 svc_type（service 未识别时的兜底）。"""
    if not agent_name:
        return "Unknown"
    # 精确匹配
    if agent_name in _AGENT_CATEGORY_FALLBACK:
        return _AGENT_CATEGORY_FALLBACK[agent_name]
    name_lower = agent_name.lower()
    # 关键词匹配
    if any(k in name_lower for k in ("code", "cursor", "copilot", "qoder", "trae", "cline", "windsurf", "lingma")):
        return "AI_Coding"
    if "web" in name_lower:
        return "LLM_Web"
    if any(k in name_lower for k in ("ollama", "vllm", "triton", "llama")):
        return "LLM_Local"
    if any(k in name_lower for k in ("gateway", "router", "proxy")):
        return "LLM_Gateway"
    if "client" in name_lower:
        return "LLM_API"
    if "mcp" in name_lower:
        return "AI_Protocol"
    return "Unknown"


def _extract_signals(ndpi: dict) -> Dict:
    """从 ndpi 子对象提取 12 种信号 + 基础字段。None/空统一为 None。"""
    tls = ndpi.get("tls") if isinstance(ndpi.get("tls"), dict) else {}
    http = ndpi.get("http") if isinstance(ndpi.get("http"), dict) else {}
    mcp = ndpi.get("mcp") if isinstance(ndpi.get("mcp"), dict) else {}
    ollama = ndpi.get("ollama") if isinstance(ndpi.get("ollama"), dict) else {}
    vllm = ndpi.get("vllm") if isinstance(ndpi.get("vllm"), dict) else {}
    triton = ndpi.get("triton") if isinstance(ndpi.get("triton"), dict) else {}

    def _s(v):
        if v is None:
            return None
        s = str(v).strip()
        return s if s else None

    return {
        "ja4": _s(tls.get("ja4")),
        "ja3": _s(tls.get("ja3s") or tls.get("ja3")),
        "user_agent": _s(http.get("user_agent")),
        "mcp_method": _s(mcp.get("method")),
        "mcp_tool_name": _s(mcp.get("tool_name")),
        "ollama_action": _s(ollama.get("action")),
        "ollama_model": _s(ollama.get("model")),
        "vllm_action": _s(vllm.get("action")),
        "vllm_model": _s(vllm.get("model")),
        "triton_endpoint": _s(triton.get("endpoint")),
        "triton_model": _s(triton.get("model")),
    }


class AiWriter:
    """AI 事件持久化写入器（同步，无队列）。"""

    def __init__(self, db: Database):
        self.db = db
        self._count = 0

    def insert(self, json_dict: dict):
        """处理一个 detected/detection-update 事件。异常只记日志不抛。"""
        try:
            ndpi = json_dict.get("ndpi", {}) or {}
            if not isinstance(ndpi, dict):
                ndpi = {}
            signals = _extract_signals(ndpi)

            # Layer 1: AI 服务发现（路径 B：无条件调用，不用 category 门控）
            svc = discover_ai_service(ndpi)
            # Layer 2: AI Agent 推断
            agent = infer_agent(ndpi)

            # 组装 ai_events 行
            confidence_raw = ndpi.get("confidence", {})
            if isinstance(confidence_raw, dict):
                confidence = next(iter(confidence_raw.values()), None)
            else:
                confidence = confidence_raw

            event = {
                "flow_id": json_dict.get("flow_id"),
                "src_ip": json_dict.get("src_ip"),
                "dst_ip": json_dict.get("dst_ip"),
                "src_port": json_dict.get("src_port"),
                "dst_port": json_dict.get("dst_port"),
                "l4_proto": str(json_dict.get("l4_proto", "") or ""),
                "proto": ndpi.get("proto"),
                "proto_id": ndpi.get("proto_id"),
                "hostname": ndpi.get("hostname"),
                "confidence": str(confidence) if confidence else None,
                # Layer 1 结果
                "ai_vendor": svc["vendor"] if svc else None,
                "ai_service": svc["service"] if svc else None,
                "ai_svc_type": svc["svc_type"] if svc else None,
                "ai_color": svc["color"] if svc else None,
                # Layer 2 结果
                "ai_agent": agent["agent"] if agent else None,
                "ai_agent_vendor": agent["vendor"] if agent else None,
                "ai_agent_score": agent.get("confidence") if agent else None,
                # 原始信号
                "ja4": signals["ja4"],
                "ja3": signals["ja3"],
                "user_agent": signals["user_agent"],
                "mcp_method": signals["mcp_method"],
                "mcp_tool_name": signals["mcp_tool_name"],
                "ollama_action": signals["ollama_action"],
                "ollama_model": signals["ollama_model"],
                "vllm_action": signals["vllm_action"],
                "vllm_model": signals["vllm_model"],
                "triton_endpoint": signals["triton_endpoint"],
                "triton_model": signals["triton_model"],
                "event_type": json_dict.get("flow_event_name", "detected"),
                "first_seen_usec": json_dict.get("flow_first_seen"),
            }

            # 单事务写 3 行（ai_events + 2 行 ai_endpoints）
            self.db.insert_ai_event(event)

            src_ip = json_dict.get("src_ip")
            dst_ip = json_dict.get("dst_ip")

            # service 行：ip=dst_ip（仅当识别出 AI 服务）
            # DNS 流量的 dst_ip 是 DNS 服务器（网关），不是真实 AI 服务 IP，必须排除
            _proto = (ndpi.get('proto') or '').upper()
            _is_dns = _proto in ('DNS', 'MDNS', 'LLMNR') or str(json_dict.get('dst_port', '')) == '53'
            if svc and dst_ip and not _is_dns:
                models_append = []
                for m in (signals["ollama_model"], signals["vllm_model"], signals["triton_model"]):
                    if m:
                        models_append.append(m)
                self.db.upsert_ai_endpoint(
                    ip=dst_ip, role="service", name=svc["service"],
                    vendor=svc["vendor"], category=svc["svc_type"],
                    models_append=models_append or None,
                    source="probe",
                )

            # agent 行：ip=src_ip（仅当识别出 Agent 客户端）
            if agent and src_ip:
                # category 由 agent 身份决定（兜底推断），不随 svc 变化
                # —— GitHub Copilot 永远是 AI_Coding，即使该流访问的是 LLM_Web 服务
                agent_category = _infer_agent_category(agent["agent"])
                self.db.upsert_ai_endpoint(
                    ip=src_ip, role="agent", name=agent["agent"],
                    vendor=agent["vendor"],
                    category=agent_category,
                    ja4_append=signals["ja4"],
                    user_agent=signals["user_agent"],
                    source="probe",
                )

            self._count += 1
            if self._count % 100 == 0:
                logger.info(f"AiWriter inserted {self._count} AI events")
        except Exception as e:
            logger.error(f"AiWriter insert failed: {type(e).__name__}: {e}", exc_info=True)
