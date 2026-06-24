"""Web Fingerprinter — favicon mmh3 哈希 + HTML/响应头特征识别 AI 平台与 Agent。

核心原则：AI agent 端口常被用户自定义（如 1Panel 容器随机分配），
固定端口字典不可靠。因此对所有 web 开放端口统一做内容指纹，
靠响应内容（title / 全局变量 / CSP / 特征字符串）识别，
而非依赖端口归属。
"""

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

# 平台 HTML/响应特征签名。
# 每个平台一组特征串（任一命中即认定），区分大小写用 lower() 比较。
# 这些是"内容指纹"——不管 agent 部署在哪个端口，只要响应里有这些特征就能识别。
PLATFORM_HTML_SIGNATURES = {
    # AI 应用编排平台
    "Dify": ["window.dify", "/_next/static/chunks/app/", 'id="dify"'],
    "Coze": ["window.__coze", "coze-config"],
    "n8n": ['id="n8n"', "window.n8n"],
    "Flowise": ["window.flowise", "<title>Flowise"],
    "One API": ["One API", 'id="root"'],
    "LangFuse": ["Langfuse", "__NEXT_DATA__"],
    "LangSmith": ["LangSmith", "smith.langchain"],
    "TGI": ["Text Generation Inference"],
    "LangServe": ["/openapi.json", "/invoke", "/stream", "langchain"],
    "Ray Dashboard": ["Ray Dashboard", "ray-dashboard"],
    # AI Agent 控制台（端口常自定义，靠 title/全局变量识别）
    "OpenClaw": ["OpenClaw Control", "openclaw.control.settings", "openclaw-mount-fallback"],
    "Hermes Agent": ["Hermes Agent - Dashboard", "__HERMES_SESSION_TOKEN__", "__HERMES_AUTH_REQUIRED__"],
    "Hermes": ["Hermes Agent", "__HERMES_"],
}

# 响应头特征：CSP/Server 等头部含 AI 相关域名时，强烈提示是 AI agent。
# 例如 OpenClaw 的 CSP 含 connect-src https://api.openai.com。
AI_HEADER_SIGNATURES = {
    "connect-src": ["api.openai.com", "api.anthropic.com", "generativelanguage.googleapis.com",
                    "api.deepseek.com", "dashscope.aliyuncs.com"],
}

# HTTP(s) web 端口（用于 web_only / full 策略做指纹）
WEB_PORTS = {80, 443, 3000, 5001, 8000, 8080, 8443, 8888}


@dataclass
class WebFinding:
    ip: str
    port: int
    favicon_hash: Optional[str] = None
    html_features: List[str] = field(default_factory=list)
    header_features: List[str] = field(default_factory=list)
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
    """对 Web 端口做平台指纹识别。

    策略：
      - HTTP GET 取首页 HTML，匹配 title/全局变量/特征串
      - 检查响应头（CSP 等）是否含 AI 域名
      - 取 /favicon.ico 做 mmh3 哈希比对
    任一特征命中即认定平台身份。不依赖端口号。
    """
    scheme = "https" if port in (443, 8443) else "http"
    base = f"{scheme}://{ip}:{port}"
    finding = WebFinding(ip=ip, port=port)

    async def _get_favicon():
        try:
            async with session.get(f"{base}/favicon.ico",
                                   timeout=aiohttp.ClientTimeout(total=timeout),
                                   ssl=False, allow_redirects=True) as resp:
                if resp.status == 200:
                    content = await resp.read()
                    finding.favicon_hash = _favicon_hash(content)
        except Exception:
            pass

    async def _get_html():
        try:
            async with session.get(base, timeout=aiohttp.ClientTimeout(total=timeout),
                                   ssl=False, allow_redirects=True) as resp:
                # 收集响应头特征（CSP / Server 等）
                _collect_header_features(resp.headers, finding)
                if resp.status not in (200, 405):
                    # 405 常见于只允许 GET 的 SPA（如 Hermes），仍读 body
                    if resp.status != 405:
                        return
                html = await resp.text(errors="replace")
                # HTML 特征匹配
                html_lower = html.lower()
                for platform, sigs in PLATFORM_HTML_SIGNATURES.items():
                    matched = [s for s in sigs if s.lower() in html_lower]
                    if matched:
                        finding.html_features.extend(matched)
                        if not finding.platform_guess or len(matched) >= 2:
                            finding.platform_guess = platform
                            # 命中 2+ 特征或专属全局变量 → 高置信
                            finding.confidence = max(finding.confidence, 0.9 if len(matched) >= 2 else 0.75)
        except Exception:
            pass

    await asyncio.gather(_get_favicon(), _get_html())

    # favicon 哈希比对
    if finding.favicon_hash and finding.favicon_hash in PLATFORM_FAVICON_HASHES:
        finding.platform_guess = PLATFORM_FAVICON_HASHES[finding.favicon_hash]
        finding.confidence = max(finding.confidence, 0.9)

    # 响应头命中 AI 域名：即使没匹配到平台名，也提示是 AI agent（中置信）
    if finding.header_features and not finding.platform_guess:
        finding.platform_guess = finding.header_features[0]
        finding.confidence = max(finding.confidence, 0.6)

    if finding.platform_guess or finding.favicon_hash or finding.html_features or finding.header_features:
        return finding
    return None


def _collect_header_features(headers, finding: WebFinding):
    """从响应头提取 AI 相关特征（CSP 含 api.openai.com 等）。"""
    try:
        for hname, keywords in AI_HEADER_SIGNATURES.items():
            val = headers.get(hname, "") or ""
            val_lower = val.lower()
            for kw in keywords:
                if kw.lower() in val_lower:
                    feat = f"{hname}:{kw}"
                    if feat not in finding.header_features:
                        finding.header_features.append(feat)
    except Exception:
        pass
