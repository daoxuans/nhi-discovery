"""Container Prober — Docker 2375/2376 + K8s 6443 未授权访问探测。"""

import asyncio
import logging
from dataclasses import dataclass, field
from typing import List, Optional

import aiohttp

logger = logging.getLogger(__name__)

# AI 相关镜像关键词
AI_IMAGE_KEYWORDS = ["pytorch", "tensorflow", "ollama", "vllm", "dify", "coze",
                     "langchain", "continuumio/miniconda", "nvidia/cuda", "triton"]
# AI 相关 Pod/namespace 关键词
AI_POD_KEYWORDS = ["model", "llm", "agent", "inference", "rag", "embedding",
                    "ollama", "vllm", "dify", "triton"]


@dataclass
class ContainerFinding:
    ip: str
    port: int
    kind: str  # docker / k8s
    unauthorized: bool = False
    ai_workloads: List[str] = field(default_factory=list)
    confidence: float = 0.0


async def _probe_docker(session, ip, port, timeout):
    url = f"http://{ip}:{port}/containers/json"
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
            if resp.status == 401 or resp.status == 403:
                return ContainerFinding(ip=ip, port=port, kind="docker",
                                        unauthorized=False, confidence=0.5)  # 需认证也算暴露
            if resp.status != 200:
                return None
            import json as _json
            data = _json.loads(await resp.text())
            ai_images = []
            for c in data or []:
                image = (c.get("Image") or "").lower()
                if any(k in image for k in AI_IMAGE_KEYWORDS):
                    ai_images.append(image)
            return ContainerFinding(
                ip=ip, port=port, kind="docker", unauthorized=len(ai_images) > 0,
                ai_workloads=ai_images, confidence=0.95 if ai_images else 0.6,
            )
    except Exception:
        return None


async def _probe_k8s(session, ip, port, timeout):
    url = f"https://{ip}:{port}/api/v1/pods"
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout),
                               ssl=False) as resp:
            if resp.status == 401 or resp.status == 403:
                return ContainerFinding(ip=ip, port=port, kind="k8s",
                                        unauthorized=False, confidence=0.5)
            if resp.status != 200:
                return None
            import json as _json
            data = _json.loads(await resp.text())
            ai_pods = []
            for item in (data.get("items") or []):
                meta = item.get("metadata", {}) or {}
                ns = (meta.get("namespace") or "").lower()
                name = (meta.get("name") or "").lower()
                if any(k in ns or k in name for k in AI_POD_KEYWORDS):
                    ai_pods.append(f"{ns}/{name}")
            return ContainerFinding(
                ip=ip, port=port, kind="k8s", unauthorized=len(ai_pods) > 0,
                ai_workloads=ai_pods, confidence=0.95 if ai_pods else 0.6,
            )
    except Exception:
        return None


async def probe_container(session, ip, port, timeout=3.0):
    if port in (2375, 2376):
        return await _probe_docker(session, ip, port, timeout)
    if port == 6443:
        return await _probe_k8s(session, ip, port, timeout)
    return None
