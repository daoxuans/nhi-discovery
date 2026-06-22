"""
AI Service Discovery — Layer 1
Maps network traffic to AI services based on hostname, protocol and nDPI metadata.

Output: {vendor, service, service_type, color, confidence}
"""

from typing import Dict, List, Optional

AI_SERVICE_RULES: List[Dict] = [
    # ── Major LLM API Providers ────────────────────────────────
    # Protocol-based rules (custom dissector matches)
    {"proto": "mcp",             "hostname": "*", "vendor": "MCP",      "service": "MCP (Model Context Protocol)", "svc_type": "AI_Protocol",  "color": "#d97706"},
    {"proto": "ollama",          "hostname": "*", "vendor": "Ollama",   "service": "Ollama Server",                "svc_type": "LLM_Local",   "color": "#6366f1"},
    {"proto": "vllm",            "hostname": "*", "vendor": "vLLM",     "service": "vLLM Server",                  "svc_type": "LLM_Local",   "color": "#2563eb"},
    {"proto": "nvidia_triton",   "hostname": "*", "vendor": "NVIDIA",   "service": "Triton Server",                "svc_type": "LLM_Local",   "color": "#76b900"},
    {"proto": "githubcopilot",   "hostname": "*", "vendor": "GitHub",   "service": "Copilot",              "svc_type": "AI_Coding",   "color": "#24292e"},
    {"proto": "github_copilot",  "hostname": "*", "vendor": "GitHub",   "service": "Copilot",              "svc_type": "AI_Coding",   "color": "#24292e"},
    {"proto": "trae",            "hostname": "*", "vendor": "ByteDance","service": "Trae IDE",             "svc_type": "AI_Coding",   "color": "#ef4444"},

    # ── Western LLM Providers ───────────────────────────────────
    {"proto": "*", "hostname": "api.anthropic.com",                "vendor": "Anthropic",  "service": "Claude API",       "svc_type": "LLM_API",     "color": "#d97706"},
    {"proto": "*", "hostname": "claude.ai",                        "vendor": "Anthropic",  "service": "Claude Web",       "svc_type": "LLM_Web",     "color": "#d97706"},
    {"proto": "*", "hostname": "api.openai.com",                   "vendor": "OpenAI",     "service": "GPT API",          "svc_type": "LLM_API",     "color": "#10a37f"},
    {"proto": "*", "hostname": "chatgpt.com",                      "vendor": "OpenAI",     "service": "ChatGPT",          "svc_type": "LLM_Web",     "color": "#10a37f"},
    {"proto": "*", "hostname": "oaiusercontent.com",               "vendor": "OpenAI",     "service": "ChatGPT CDN",      "svc_type": "LLM_Web",     "color": "#10a37f"},
    {"proto": "*", "hostname": "api.groq.com",                     "vendor": "Groq",       "service": "Groq API",         "svc_type": "LLM_API",     "color": "#f55036"},
    {"proto": "*", "hostname": "api.deepseek.com",                 "vendor": "DeepSeek",   "service": "DeepSeek API",     "svc_type": "LLM_API",     "color": "#4d6bfe"},
    {"proto": "*", "hostname": "platform.deepseek.com",            "vendor": "DeepSeek",   "service": "DeepSeek Platform","svc_type": "LLM_API",     "color": "#4d6bfe"},
    {"proto": "*", "hostname": "chat.deepseek.com",                "vendor": "DeepSeek",   "service": "DeepSeek Chat",    "svc_type": "LLM_Web",     "color": "#4d6bfe"},
    {"proto": "*", "hostname": "hif-leim.deepseek.com",            "vendor": "DeepSeek",   "service": "DeepSeek HIF",     "svc_type": "LLM_Web",     "color": "#4d6bfe"},
    {"proto": "*", "hostname": "deepseek.com",                     "vendor": "DeepSeek",   "service": "DeepSeek Web",     "svc_type": "LLM_Web",     "color": "#4d6bfe"},
    {"proto": "*", "hostname": "fe-static.deepseek.com",           "vendor": "DeepSeek",   "service": "DeepSeek CDN",     "svc_type": "LLM_Web",     "color": "#4d6bfe"},
    {"proto": "*", "hostname": "cdn.deepseek.com",                 "vendor": "DeepSeek",   "service": "DeepSeek CDN",     "svc_type": "LLM_Web",     "color": "#4d6bfe"},
    {"proto": "*", "hostname": "generativelanguage.googleapis.com","vendor": "Google",     "service": "Gemini API",       "svc_type": "LLM_API",     "color": "#4285f4"},
    {"proto": "*", "hostname": "gemini.google.com",                "vendor": "Google",     "service": "Gemini Web",       "svc_type": "LLM_Web",     "color": "#4285f4"},
    {"proto": "*", "hostname": "cognitive.microsoft.com",          "vendor": "Microsoft",  "service": "Azure AI",         "svc_type": "LLM_API",     "color": "#0078d4"},
    {"proto": "*", "hostname": "api.mistral.ai",                   "vendor": "Mistral",    "service": "Mistral API",      "svc_type": "LLM_API",     "color": "#f97316"},
    {"proto": "*", "hostname": "api.cohere.ai",                    "vendor": "Cohere",     "service": "Cohere API",       "svc_type": "LLM_API",     "color": "#22c55e"},
    {"proto": "*", "hostname": "meta.ai",                          "vendor": "Meta",       "service": "Meta AI",          "svc_type": "LLM_Web",     "color": "#1877f2"},
    {"proto": "*", "hostname": "api.meta.ai",                      "vendor": "Meta",       "service": "Llama API",        "svc_type": "LLM_API",     "color": "#1877f2"},
    {"proto": "*", "hostname": "x.ai",                             "vendor": "xAI",         "service": "Grok",            "svc_type": "LLM_Web",     "color": "#000000"},
    {"proto": "*", "hostname": "api.x.ai",                         "vendor": "xAI",         "service": "Grok API",        "svc_type": "LLM_API",     "color": "#000000"},
    {"proto": "*", "hostname": "perplexity.ai",                    "vendor": "Perplexity", "service": "Perplexity",       "svc_type": "LLM_Web",     "color": "#22c55e"},
    {"proto": "*", "hostname": "api.perplexity.ai",                "vendor": "Perplexity", "service": "Perplexity API",   "svc_type": "LLM_API",     "color": "#22c55e"},

    # ── Chinese LLM Providers ───────────────────────────────────
    {"proto": "*", "hostname": "api.moonshot.cn",                  "vendor": "Moonshot",   "service": "Kimi API",         "svc_type": "LLM_API",     "color": "#8b5cf6"},
    {"proto": "*", "hostname": "ark.cn",                           "vendor": "ByteDance",  "service": "Doubao/Ark",       "svc_type": "LLM_API",     "color": "#ef4444"},
    {"proto": "*", "hostname": "api5-normal-gl.doubao.com",        "vendor": "ByteDance",  "service": "Doubao API",       "svc_type": "LLM_API",     "color": "#ef4444"},
    {"proto": "*", "hostname": "api5-normal-lq.doubao.com",        "vendor": "ByteDance",  "service": "Doubao API",       "svc_type": "LLM_API",     "color": "#ef4444"},
    {"proto": "*", "hostname": "ime.doubao.com",                   "vendor": "ByteDance",  "service": "Doubao IME",       "svc_type": "LLM_Web",     "color": "#ef4444"},
    {"proto": "*", "hostname": "www.doubao.com",                   "vendor": "ByteDance",  "service": "Doubao Web",       "svc_type": "LLM_Web",     "color": "#ef4444"},
    {"proto": "*", "hostname": "logifier.doubao.com",              "vendor": "ByteDance",  "service": "Doubao Logifier",  "svc_type": "LLM_Web",     "color": "#ef4444"},
    {"proto": "*", "hostname": "mcs.doubao.com",                   "vendor": "ByteDance",  "service": "Doubao MCS",       "svc_type": "LLM_Web",     "color": "#ef4444"},
    {"proto": "*", "hostname": "opt.doubao.com",                   "vendor": "ByteDance",  "service": "Doubao OPT",       "svc_type": "LLM_Web",     "color": "#ef4444"},
    {"proto": "*", "hostname": "frontier-audio-ime-quic.doubao.com","vendor": "ByteDance",  "service": "Doubao Audio IME", "svc_type": "LLM_Web",     "color": "#ef4444"},
    {"proto": "*", "hostname": "frontier-audio-ime-ws.doubao.com", "vendor": "ByteDance",  "service": "Doubao Audio IME", "svc_type": "LLM_Web",     "color": "#ef4444"},
    {"proto": "*", "hostname": "tongyi.aliyun.com",                "vendor": "Alibaba",    "service": "Tongyi Qwen",      "svc_type": "LLM_API",     "color": "#ff6a00"},
    {"proto": "*", "hostname": "dashscope.aliyuncs.com",           "vendor": "Alibaba",    "service": "DashScope",        "svc_type": "LLM_API",     "color": "#ff6a00"},
    {"proto": "*", "hostname": "qianfan.baidubce.com",             "vendor": "Baidu",      "service": "Qianfan API",      "svc_type": "LLM_API",     "color": "#2932e1"},
    {"proto": "*", "hostname": "yiyan.baidu.com",                  "vendor": "Baidu",      "service": "ERNIE Bot",        "svc_type": "LLM_Web",     "color": "#2932e1"},
    {"proto": "*", "hostname": "bigmodel.cn",                      "vendor": "Zhipu AI",   "service": "GLM Platform",     "svc_type": "LLM_API",     "color": "#3b82f6"},
    {"proto": "*", "hostname": "open.bigmodel.cn",                 "vendor": "Zhipu AI",   "service": "GLM API",          "svc_type": "LLM_API",     "color": "#3b82f6"},
    {"proto": "*", "hostname": "api.bigmodel.cn",                  "vendor": "Zhipu AI",   "service": "GLM API",          "svc_type": "LLM_API",     "color": "#3b82f6"},
    {"proto": "*", "hostname": "hunyuan.tencent.com",              "vendor": "Tencent",    "service": "Hunyuan",          "svc_type": "LLM",         "color": "#0052d9"},
    {"proto": "*", "hostname": "hunyuan.tencentcloudapi.com",      "vendor": "Tencent",    "service": "Hunyuan API",      "svc_type": "LLM_API",     "color": "#0052d9"},
    {"proto": "*", "hostname": "spark-api.xf-yun.com",             "vendor": "iFlytek",    "service": "Spark API",        "svc_type": "LLM_API",     "color": "#1890ff"},
    {"proto": "*", "hostname": "sensetime.com",                    "vendor": "SenseTime",  "service": "SenseNova",        "svc_type": "LLM_API",      "color": "#f97316"},
    {"proto": "*", "hostname": "skywork.com",                      "vendor": "Skywork",    "service": "Skywork API",      "svc_type": "LLM_API",      "color": "#8b5cf6"},
    {"proto": "*", "hostname": "minimax.chat",                     "vendor": "MiniMax",    "service": "MiniMax",          "svc_type": "LLM",          "color": "#ef4444"},
    {"proto": "*", "hostname": "siliconflow.cn",                   "vendor": "SiliconFlow","service": "SiliconFlow",       "svc_type": "LLM_API",      "color": "#6366f1"},
    {"proto": "*", "hostname": "ollama.com",                       "vendor": "Ollama",     "service": "Ollama Hub",        "svc_type": "LLM_Web",      "color": "#6366f1"},
    {"proto": "*", "hostname": "xiaomimimo.com",                   "vendor": "Xiaomi",     "service": "MiMo LLM",         "svc_type": "LLM",           "color": "#ff6900"},
    {"proto": "*", "hostname": "vcode-od.vivo.com.cn",             "vendor": "Vivo",       "service": "Vivo BlueLM",      "svc_type": "LLM",          "color": "#1890ff"},

    # ── AI Coding Tools (IDE/Platform endpoints) ────────────────
    {"proto": "*", "hostname": "cursor.sh",                        "vendor": "Cursor",      "service": "Cursor IDE",       "svc_type": "AI_Coding",   "color": "#6366f1"},
    {"proto": "*", "hostname": "api.qoder.com",                    "vendor": "Qoder",       "service": "Qoder",            "svc_type": "AI_Coding",   "color": "#6366f1"},
    {"proto": "*", "hostname": "qoder.com",                        "vendor": "Qoder",       "service": "Qoder",            "svc_type": "AI_Coding",   "color": "#6366f1"},
    {"proto": "*", "hostname": "api5.qoder.com.cn",                "vendor": "Qoder",       "service": "Qoder",            "svc_type": "AI_Coding",   "color": "#6366f1"},
    {"proto": "*", "hostname": "download.qoder.com",               "vendor": "Qoder",       "service": "Qoder Download",   "svc_type": "AI_Coding",   "color": "#6366f1"},
    {"proto": "*", "hostname": "trae.cn",                          "vendor": "ByteDance",   "service": "Trae IDE",         "svc_type": "AI_Coding",   "color": "#ef4444"},
    {"proto": "*", "hostname": "trae.ai",                          "vendor": "ByteDance",   "service": "Trae IDE",         "svc_type": "AI_Coding",   "color": "#ef4444"},
    {"proto": "*", "hostname": "api.trae.cn",                      "vendor": "ByteDance",   "service": "Trae API",         "svc_type": "AI_Coding",   "color": "#ef4444"},
    {"proto": "*", "hostname": "codebuddy.cn",                     "vendor": "Tencent",     "service": "CodeBuddy",        "svc_type": "AI_Coding",   "color": "#0052d9"},
    {"proto": "*", "hostname": "workbuddy.tencent.com",            "vendor": "Tencent",     "service": "WorkBuddy",         "svc_type": "AI_Coding",   "color": "#0052d9"},
    {"proto": "*", "hostname": "windsurf.ai",                      "vendor": "Codeium",     "service": "Windsurf",          "svc_type": "AI_Coding",   "color": "#8b5cf6"},
    {"proto": "*", "hostname": "bolt.new",                         "vendor": "Bolt",        "service": "Bolt.new",          "svc_type": "AI_Coding",   "color": "#22c55e"},
    {"proto": "*", "hostname": "lovable.dev",                      "vendor": "Lovable",     "service": "Lovable",           "svc_type": "AI_Coding",   "color": "#ec4899"},
    {"proto": "*", "hostname": "replit.com",                       "vendor": "Replit",      "service": "Replit Agent",      "svc_type": "AI_Coding",   "color": "#f97316"},
    {"proto": "*", "hostname": "v0.dev",                           "vendor": "Vercel",      "service": "v0",                "svc_type": "AI_Coding",   "color": "#000000"},
    {"proto": "*", "hostname": "lingma-api.tongyi.aliyun.com",     "vendor": "Alibaba",     "service": "Lingma (通义灵码)",  "svc_type": "AI_Coding",   "color": "#ff6a00"},

    # ── GitHub Copilot endpoints ──────────────────────────────────
    {"proto": "*", "hostname": "api.githubcopilot.com",             "vendor": "GitHub", "service": "Copilot API",     "svc_type": "AI_Coding", "color": "#24292e"},
    {"proto": "*", "hostname": "api.individual.githubcopilot.com",  "vendor": "GitHub", "service": "Copilot API",     "svc_type": "AI_Coding", "color": "#24292e"},
    {"proto": "*", "hostname": "proxy.individual.githubcopilot.com","vendor": "GitHub", "service": "Copilot Proxy",   "svc_type": "AI_Coding", "color": "#24292e"},
    {"proto": "*", "hostname": "telemetry.individual.githubcopilot.com","vendor":"GitHub","service":"Copilot Telemetry","svc_type":"AI_Coding","color": "#24292e"},
    {"proto": "*", "hostname": "default.exp-tas.com",               "vendor": "GitHub", "service": "Copilot Auth",    "svc_type": "AI_Coding", "color": "#24292e"},

    # ── AI API Aggregators / Gateways ───────────────────────────
    {"proto": "*", "hostname": "openrouter.ai",                    "vendor": "OpenRouter",  "service": "OpenRouter",        "svc_type": "LLM_Gateway", "color": "#8b5cf6"},
    {"proto": "*", "hostname": "portkey.ai",                       "vendor": "Portkey",     "service": "Portkey Gateway",   "svc_type": "LLM_Gateway", "color": "#6366f1"},
    {"proto": "*", "hostname": "dmxapi.com",                       "vendor": "DMX API",     "service": "DMX API Gateway",   "svc_type": "LLM_Gateway", "color": "#d97706"},
    {"proto": "*", "hostname": "closeai-proxy.com",                "vendor": "CloseAI",     "service": "CloseAI Proxy",     "svc_type": "LLM_Gateway", "color": "#ef4444"},
    {"proto": "*", "hostname": "uniapi.ruijie.com.cn",             "vendor": "Ruijie",      "service": "AI Gateway",        "svc_type": "LLM_Gateway", "color": "#ff5722"},

    # 注：Ruijie AQ / Sentinel / Learning / SID / OA / Bugs / SSO / EFA /
    #     Resource / YF Release / Web Gateway / HCM / IG0011 / ITSM 等
    #     *.ruijie.com.cn 内部业务平台不属于 AI 相关协议，已从 AI 规则表移除。
    #     仅 uniapi.ruijie.com.cn（LLM 网关入口）保留为 AI_Gateway。
]


def discover_ai_service(ndpi: dict) -> Optional[dict]:
    """Match an nDPI flow against AI service rules.

    Returns:
        {vendor, service, svc_type, color} or None if not AI traffic.
    """
    proto = (ndpi.get("proto") or "").lower().replace(".", "").replace("-", "").replace("_", "")
    hostname = (ndpi.get("hostname") or "").strip().lower()

    if not proto and not hostname:
        return None

    # Also check nDPI metadata sub-objects for local AI protocols
    for ai_key in ("mcp", "ollama", "vllm"):
        if isinstance(ndpi.get(ai_key), dict):
            # nDPI detected this protocol, try service rules with proto match
            pass

    for rule in AI_SERVICE_RULES:
        # Protocol match
        if rule["proto"] != "*":
            if rule["proto"] not in proto and not proto.endswith(rule["proto"]):
                continue

        # Hostname match
        if rule["hostname"] != "*":
            if not hostname:
                continue
            if hostname != rule["hostname"] and not hostname.endswith("." + rule["hostname"]):
                continue

        return {
            "vendor": rule["vendor"],
            "service": rule["service"],
            "svc_type": rule["svc_type"],
            "color": rule["color"],
        }

    return None
