"""AiWriter — AI 事件持久化（异步批量写入）。

detected/detection-update 事件 → 提取信号 → discover_ai_service + infer_agent
→ 入内存队列 → 后台线程批量 INSERT ai_events + 批量 UPSERT ai_endpoints。

异步批量的目的：消费回调（_on_json）不阻塞 nDPIsrvd loop，避免
"remote too slow" buffer overflow 丢事件。批量 executemany + 单事务 commit，
SQLite 写锁串行化只在 commit 瞬间发生，吞吐提升 ~10x。
"""

import logging
import queue
import threading
import time
from typing import Dict, List, Optional

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
    """AI 事件持久化写入器（异步批量，生产-消费者模式）。

    insert() 只做信号提取 + 入队（O(1)，不碰 DB），后台线程批量落盘。
    """

    def __init__(self, db: Database, batch_interval: float = 1.0, batch_size: int = 200):
        self.db = db
        self._batch_interval = batch_interval
        self._batch_size = batch_size
        self._queue: "queue.Queue[Optional[Dict]]" = queue.Queue(maxsize=20000)
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._count = 0
        self._written = 0
        self._dropped = 0

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        logger.info(f"AiWriter started (batch_size={self._batch_size})")

    def stop(self):
        self._running = False
        # 哨兵唤醒等待中的 flush 线程
        try:
            self._queue.put_nowait(None)
        except queue.Full:
            pass
        if self._thread:
            self._thread.join(timeout=10)
        if self._dropped > 0:
            logger.warning(f"AiWriter dropped {self._dropped} events total (queue full)")
        logger.info(f"AiWriter stopped (received={self._count} written={self._written})")

    @property
    def queue_depth(self) -> int:
        return self._queue.qsize()

    def insert(self, json_dict: dict):
        """处理一个 detected/detection-update 事件：提取信号 + 入队。异常只记日志不抛。"""
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

            src_ip = json_dict.get("src_ip")
            _proto = (ndpi.get('proto') or '').upper()
            _is_dns = _proto in ('DNS', 'MDNS', 'LLMNR') or str(json_dict.get('dst_port', '')) == '53'

            event = {
                "flow_id": json_dict.get("flow_id"),
                "src_ip": src_ip,
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

            # 端点 upsert 也推迟到批量阶段，这里只收集指令
            endpoint_ops: List[Dict] = []
            # service 行：ip=dst_ip（仅当识别出 AI 服务）
            # DNS 流量的 dst_ip 是 DNS 服务器（网关），不是真实 AI 服务 IP，必须排除
            dst_ip_real = json_dict.get("dst_ip")
            if svc and dst_ip_real and not _is_dns:
                models_append = []
                for m in (signals["ollama_model"], signals["vllm_model"], signals["triton_model"]):
                    if m:
                        models_append.append(m)
                endpoint_ops.append({
                    "ip": dst_ip_real, "role": "service", "name": svc["service"],
                    "vendor": svc["vendor"], "category": svc["svc_type"],
                    "ja4_append": None, "user_agent": None,
                    "models_append": models_append or None, "source": "probe",
                })

            # agent 行：ip=src_ip（仅当识别出 Agent 客户端）
            if agent and src_ip:
                agent_category = _infer_agent_category(agent["agent"])
                endpoint_ops.append({
                    "ip": src_ip, "role": "agent", "name": agent["agent"],
                    "vendor": agent["vendor"], "category": agent_category,
                    "ja4_append": signals["ja4"], "user_agent": signals["user_agent"],
                    "models_append": None, "source": "probe",
                })

            self._count += 1
            try:
                self._queue.put_nowait({"event": event, "endpoints": endpoint_ops})
            except queue.Full:
                self._dropped += 1
                if self._dropped % 500 == 0:
                    logger.warning(f"AiWriter dropped {self._dropped} (queue full)")
        except Exception as e:
            logger.error(f"AiWriter insert failed: {type(e).__name__}: {e}", exc_info=True)

    def _run(self):
        while self._running:
            time.sleep(self._batch_interval)
            self._flush(force=False)
        # 退出前冲刷剩余
        self._flush(force=True)

    def _flush(self, force: bool):
        batch = []
        limit = 0 if force else self._batch_size
        while not self._queue.empty():
            try:
                item = self._queue.get_nowait()
            except queue.Empty:
                break
            if item is None:  # 哨兵
                continue
            batch.append(item)
            if limit and len(batch) >= limit:
                break
        if not batch:
            return

        events = [b["event"] for b in batch]
        all_endpoints: List[Dict] = []
        for b in batch:
            all_endpoints.extend(b["endpoints"])

        # 批量 INSERT ai_events（executemany 单事务）
        try:
            written = self.db.insert_ai_events_batch(events)
            self._written += written
        except Exception as e:
            logger.error(f"AiWriter batch insert failed ({e}), fallback to per-row")
            for ev in events:
                try:
                    self.db.insert_ai_event(ev)
                    self._written += 1
                except Exception as e2:
                    logger.error(f"AiWriter per-row insert failed: {e2}")

        # 批量 UPSERT ai_endpoints（逐条但同一连接，锁开销小）
        for op in all_endpoints:
            try:
                self.db.upsert_ai_endpoint(**op)
            except Exception as e:
                logger.error(f"AiWriter upsert failed ({op.get('ip')}/{op.get('role')}): {e}")

        if self._written % 1000 < self._batch_size:
            logger.info(f"AiWriter written={self._written} queue={self._queue.qsize()}")
