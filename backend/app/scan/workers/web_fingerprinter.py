"""Web Fingerprinter — favicon mmh3 哈希 + HTML 特征识别 AI 平台。"""

import asyncio
import base64
import logging
from dataclasses import dataclass, field
from typing import List, Optional

import aiohttp

logger = logging.getLogger(__name__)

# 已知平台 favicon mmh3 哈希库（需预先采集；先留空，Phase 3 后补）
PLATFORM_FAVICON_HASHES = {
    # "1234567890": "Dify",
}

# 平台 HTML 特征签名
PLATFORM_HTML_SIGNATURES = {
    "Dify": ["window.dify", "/_next/static/chunks/app/", 'id="dify"'],
    "Coze": ["window.__coze", "coze-config"],
    "n8n": ['id="n8n"', "window.n8n"],
    "Flowise": ["window.flowise", "<title>Flowise"],
    "One API": ["One API", 'id="root"'],
    "LangFuse": ["Langfuse", "__NEXT_DATA__"],
    "LangSmith": ["LangSmith", "smith.langchain"],
    "TGI": ["Text Generation Inference"],
}

WEB_PORTS = {80, 443, 3000, 5001, 8000, 8080, 8443}


@dataclass
class WebFinding:
    ip: str
    port: int
    favicon_hash: Optional[str] = None
    html_features: List[str] = field(default_factory=list)
    platform_guess: Optional[str] = None
    confidence: float = 0.0


def _favicon_hash(content: bytes) -> Optional[str]:
    """计算 favicon mmh3 哈希（Shodan/FOFA 兼容格式）。"""
    try:
        import mmh3
        b64 = base64.encodebytes(content).decode()
        return str(mmh3.hash(b64))
    except Exception:
        return None


async def fingerprint_web(session: aiohttp.ClientSession, ip: str, port: int,
                          timeout: float = 3.0) -> Optional[WebFinding]:
    """对 Web 端口做平台指纹识别。"""
    scheme = "https" if port in (443, 8443) else "http"
    base = f"{scheme}://{ip}:{port}"
    finding = WebFinding(ip=ip, port=port)

    async def _get_favicon():
        try:
            async with session.get(f"{base}/favicon.ico",
                                   timeout=aiohttp.ClientTimeout(total=timeout),
                                   ssl=False) as resp:
                if resp.status == 200:
                    content = await resp.read()
                    finding.favicon_hash = _favicon_hash(content)
        except Exception:
            pass

    async def _get_html():
        try:
            async with session.get(base, timeout=aiohttp.ClientTimeout(total=timeout),
                                   ssl=False) as resp:
                if resp.status != 200:
                    return
                html = await resp.text(errors="replace")
                # HTML 特征匹配
                for platform, sigs in PLATFORM_HTML_SIGNATURES.items():
                    matched = [s for s in sigs if s.lower() in html.lower()]
                    if matched:
                        finding.html_features.extend(matched)
                        if not finding.platform_guess or len(matched) > 2:
                            finding.platform_guess = platform
                            finding.confidence = max(finding.confidence, 0.75)
        except Exception:
            pass

    await asyncio.gather(_get_favicon(), _get_html())

    # favicon 哈希比对
    if finding.favicon_hash and finding.favicon_hash in PLATFORM_FAVICON_HASHES:
        finding.platform_guess = PLATFORM_FAVICON_HASHES[finding.favicon_hash]
        finding.confidence = max(finding.confidence, 0.9)

    if finding.platform_guess or finding.favicon_hash or finding.html_features:
        return finding
    return None
