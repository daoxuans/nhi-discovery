"""API Prober — aiohttp 验证 AI 框架端口。

端口 → API 路径映射 + 响应 JSON 解析（OpenAI 兼容 + Ollama 格式）+ 模型名标准化 + 版本提取。
"""

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import List, Optional

import aiohttp

logger = logging.getLogger(__name__)

# 端口 → (api_path, vendor, service, svc_type) 映射
PORT_API_MAP = {
    11434: ("/api/tags", "Ollama", "Ollama Server", "LLM_Local"),
    8000:  ("/v1/models", "vLLM", "vLLM Server", "LLM_Local"),   # 可能也是 Llama.cpp/LM Studio
    8001:  ("/v2/health/ready", "NVIDIA", "Triton Server", "LLM_Local"),
    8080:  ("/v1/models", "LlamaCpp", "Llama.cpp Server", "LLM_Local"),
    12345: ("/v1/models", "LMStudio", "LM Studio", "LLM_Local"),
    80:    ("/", None, None, None),       # TGI 或 Web 平台
    3000:  ("/api/status", "OneAPI", "One API", "AI_Gateway"),
    5001:  ("/api/status", "OneAPI", "One API", "AI_Gateway"),
}

# 健康检查类端口（只需 200，无需解析模型）
HEALTH_CHECK_PORTS = {8001}


@dataclass
class ApiFinding:
    ip: str
    port: int
    api_path: str
    api_status: Optional[int]
    api_response: str
    models_detected: List[str] = field(default_factory=list)
    version_detected: Optional[str] = None
    vendor: Optional[str] = None
    service: Optional[str] = None
    svc_type: Optional[str] = None
    confidence: float = 0.0


def _normalize_model(name: str) -> str:
    """模型名标准化：llama3:latest → llama3；Qwen/Qwen2-72B-Instruct → qwen2-72b-instruct"""
    n = name.strip()
    # 去掉 :tag
    n = n.split(":")[0]
    # 去掉组织前缀 Qwen/
    if "/" in n:
        n = n.split("/")[-1]
    # 小写
    n = n.lower()
    # 统一分隔符
    n = n.replace("_", "-")
    return n


def _parse_models(data: dict, port: int) -> List[str]:
    """从 API 响应解析模型列表（OpenAI 兼容 + Ollama 格式）。"""
    models = []
    if port == 11434:  # Ollama /api/tags
        for m in data.get("models", []) or []:
            name = m.get("name") or m.get("model")
            if name:
                models.append(_normalize_model(name))
    else:  # OpenAI 兼容 /v1/models
        for m in data.get("data", []) or []:
            mid = m.get("id") or m.get("model")
            if mid:
                models.append(_normalize_model(mid))
    return models


def _extract_version(headers, body: dict, port: int) -> Optional[str]:
    """从 HTTP 头或响应体提取版本号。"""
    # HTTP 头 server: vllm/0.4.2
    server = headers.get("Server", "") if headers else ""
    m = re.search(r"vllm/([\d.]+)", server, re.IGNORECASE)
    if m:
        return m.group(1)
    # Ollama /api/version 风格（响应体含 version 字段）
    if isinstance(body, dict) and body.get("version"):
        return str(body["version"])
    return None


async def probe_api(session: aiohttp.ClientSession, ip: str, port: int,
                    timeout: float = 3.0) -> Optional[ApiFinding]:
    """探测单个端口的 API。"""
    mapping = PORT_API_MAP.get(port)
    if not mapping:
        return None
    api_path, default_vendor, default_service, default_svc_type = mapping
    url = f"http://{ip}:{port}{api_path}"
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
            status = resp.status
            text = await resp.text()
            # 非 200：端口开放但不是该 AI 框架（撞库），不标 ai_vendor
            if status != 200:
                return ApiFinding(
                    ip=ip, port=port, api_path=api_path,
                    api_status=status, api_response=text[:200],
                    vendor=None, service=None, svc_type=None,
                    confidence=0.1,  # 仅表示"探测过但未确认"
                )
            # 健康检查类（Triton /v2/health/ready 200 即确认）
            if port in HEALTH_CHECK_PORTS:
                return ApiFinding(
                    ip=ip, port=port, api_path=api_path,
                    api_status=status, api_response="healthy",
                    vendor=default_vendor, service=default_service, svc_type=default_svc_type,
                    confidence=0.85,
                )
            # 解析 JSON
            import json as _json
            try:
                data = _json.loads(text)
            except Exception:
                # 200 但非 JSON：可能是普通 Web 服务撞了 AI 端口，不标 ai_vendor
                return ApiFinding(
                    ip=ip, port=port, api_path=api_path,
                    api_status=status, api_response=text[:200],
                    vendor=None, service=None, svc_type=None,
                    confidence=0.15,
                )
            models = _parse_models(data, port)
            version = _extract_version(resp.headers, data, port)
            # 有模型列表 → 高置信度确认；无模型但 200+JSON → 中置信度（可能空模型库）
            if models:
                conf = 0.9
                vendor, service, svc_type = default_vendor, default_service, default_svc_type
            else:
                # 200 + 合法 JSON 但无模型：弱确认（如 Ollama 空库），仍标 vendor 但低置信
                conf = 0.5
                vendor, service, svc_type = default_vendor, default_service, default_svc_type
            return ApiFinding(
                ip=ip, port=port, api_path=api_path,
                api_status=status, api_response=text[:200],
                models_detected=models, version_detected=version,
                vendor=vendor, service=service, svc_type=svc_type,
                confidence=conf,
            )
    except asyncio.TimeoutError:
        return None
    except aiohttp.ClientError as e:
        logger.debug(f"api probe {url}: {type(e).__name__}")
        return None
    except Exception as e:
        logger.debug(f"api probe {url} failed: {type(e).__name__}: {e}")
        return None
