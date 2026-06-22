"""
AI Agent Inference — Layer 2

Multi-signal weighted scoring engine that identifies which AI client tool
(Claude Code, Codex CLI, Cursor, GitHub Copilot, etc.) is making each AI-related
network flow.

Signals used:
  - ndpi.hostname         TLS SNI / HTTP Host header
  - ndpi.proto            nDPI protocol name
  - ndpi.tls.ja4          TLS client fingerprint
  - ndpi.http.user_agent  HTTP User-Agent (cleartext only)
  - ndpi.mcp.method       MCP JSON-RPC method (new)
  - ndpi.mcp.tool_name    MCP tool name (new)
  - ndpi.ollama.action    Ollama API endpoint action (new)
  - ndpi.ollama.model     Ollama model name (new)
  - ndpi.vllm.action      vLLM API endpoint action (new)
  - ndpi.vllm.model       vLLM model name (new)
  - ndpi.triton.endpoint  NVIDIA Triton endpoint path (new)
  - ndpi.triton.model     NVIDIA Triton model name (new)

Scoring: each agent has a set of evidence rules with weights.
Final agent = highest cumulative score above min_confidence.
"""

from typing import Dict, List, Optional, Tuple
import logging

logger = logging.getLogger(__name__)

# ── Helper ─────────────────────────────────────────────────────

def _extract_ja4(ndpi: dict) -> str:
    tls = ndpi.get("tls", {})
    return (tls.get("ja4", "") or "") if isinstance(tls, dict) else ""

def _extract_user_agent(ndpi: dict) -> str:
    http = ndpi.get("http", {})
    return (http.get("user_agent", "") or "").lower() if isinstance(http, dict) else ""

def _get_nested(ndpi: dict, *keys, default="") -> str:
    """Safely traverse nested ndpi dicts."""
    v = ndpi
    for k in keys:
        if isinstance(v, dict):
            v = v.get(k, default)
        else:
            return default
    return (v or default)

# ── Agent Inference Rules ──────────────────────────────────────

# Each rule = (agent_name, vendor, list_of_evidence, min_confidence)
# Each evidence = (signal_name, pattern, weight)
#   signal_name: "hostname" | "proto" | "ja4" | "user_agent"
#                | "mcp_method" | "mcp_tool" | "ollama_action"
#                | "ollama_model" | "vllm_action" | "vllm_model"
#                | "triton_endpoint" | "triton_model"
# weight: 0.0 .. 1.0, overall score = sum(matched weights)
# min_confidence: minimum thresholed to select this agent

AGENT_INFERENCE_RULES: List[Dict] = [
    # ════════════════════════════════════════════════════════════
    # Anthropic / Claude 系列
    # ════════════════════════════════════════════════════════════
    {
        "agent": "Claude Code",
        "vendor": "Anthropic",
        "evidence": [
            ("hostname",       "api.anthropic.com",                     0.30),
            ("ja4",            "t13d1714h1_5b57614c22b0_43ade6aba3df",  0.60),
            ("ja4",            "t13d1714h1",                            0.45),
            ("ja4",            "t13d1715h1_5b57614c22b0_e8ed158c4d85",  0.55),
            ("user_agent",     "claude-code",                           0.90),
            ("user_agent",     "anthropic-sdk",                         0.60),
            ("ja4",            "8faff15",                               0.50),
            ("mcp_method",     "tools/call",                            0.40),
            ("mcp_method",     "tools/list",                            0.30),
            ("mcp_tool",       "read_file",                             0.30),
            ("mcp_tool",       "write_file",                            0.30),
            ("mcp_tool",       "replace_in_file",                       0.30),
            ("mcp_tool",       "execute_command",                       0.30),
            ("proto",          "mcp",                                   0.25),
        ],
        "min_confidence": 0.45,
    },
    {
        "agent": "Claude Web",
        "vendor": "Anthropic",
        "evidence": [
            ("hostname",       "claude.ai",                             0.80),
        ],
        "min_confidence": 0.30,
    },
    {
        "agent": "Claude Client (generic)",
        "vendor": "Anthropic",
        "evidence": [
            ("hostname",       "api.anthropic.com",                     0.20),
            ("ja4",            "t13d1714h1_5b57614c22b0_43ade6aba3df",  0.50),
            ("ja4",            "t13d1714h1",                            0.35),
            ("ja4",            "8faff15",                               0.40),
        ],
        "min_confidence": 0.30,
    },

    # ════════════════════════════════════════════════════════════
    # OpenAI 系列
    # ════════════════════════════════════════════════════════════
    {
        "agent": "Codex CLI",
        "vendor": "OpenAI",
        "evidence": [
            ("hostname",       "api.openai.com",                        0.20),
            ("user_agent",     "codex-cli",                             0.90),
            ("user_agent",     "openai-sdk",                            0.60),
            ("ja4",            "5b57614",                               0.50),
        ],
        "min_confidence": 0.45,
    },
    {
        "agent": "ChatGPT Web",
        "vendor": "OpenAI",
        "evidence": [
            ("hostname",       "chatgpt.com",                           0.80),
            ("hostname",       "oaiusercontent.com",                    0.60),
        ],
        "min_confidence": 0.30,
    },
    {
        "agent": "OpenAI Client (generic)",
        "vendor": "OpenAI",
        "evidence": [
            ("hostname",       "api.openai.com",                        0.15),
        ],
        "min_confidence": 0.10,
    },

    # ════════════════════════════════════════════════════════════
    # GitHub Copilot
    # ════════════════════════════════════════════════════════════
    {
        "agent": "GitHub Copilot",
        "vendor": "GitHub",
        "evidence": [
            ("proto",          "githubcopilot",                         0.90),
            ("proto",          "github_copilot",                        0.90),
            ("hostname",       "githubcopilot.com",                     0.80),
            ("hostname",       "api.githubcopilot.com",                 0.70),
            ("hostname",       "api.individual.githubcopilot.com",      0.65),
            ("hostname",       "proxy.individual.githubcopilot.com",    0.55),
            ("hostname",       "telemetry.individual.githubcopilot.com",0.55),
            ("hostname",       "default.exp-tas.com",                   0.50),
            ("ja4",            "t13d1813h1_5d04281c6031_02c8e53ee398",  0.60),
            ("ja4",            "t13d1517h2_8daaf6152771_b6f405a00624",  0.50),
            ("ja4",            "t13d181200_5d04281c6031_02c8e53ee398",  0.50),
            ("ja4",            "t13d181100_5d04281c6031_d5fe2c511efa",  0.45),
            ("user_agent",     "githubcopilot",                         0.90),
        ],
        "min_confidence": 0.30,
    },

    # ════════════════════════════════════════════════════════════
    # Cursor IDE
    # ════════════════════════════════════════════════════════════
    {
        "agent": "Cursor",
        "vendor": "Cursor",
        "evidence": [
            ("hostname",       "cursor.sh",                             0.80),
            ("user_agent",     "cursor",                                0.70),
        ],
        "min_confidence": 0.30,
    },

    # ════════════════════════════════════════════════════════════
    # Aider
    # ════════════════════════════════════════════════════════════
    {
        "agent": "Aider",
        "vendor": "Aider",
        "evidence": [
            ("user_agent",     "aider",                                 0.80),
        ],
        "min_confidence": 0.30,
    },

    # ════════════════════════════════════════════════════════════
    # Continue
    # ════════════════════════════════════════════════════════════
    {
        "agent": "Continue",
        "vendor": "Continue",
        "evidence": [
            ("user_agent",     "continue",                              0.80),
        ],
        "min_confidence": 0.30,
    },

    # ════════════════════════════════════════════════════════════
    # Chinese AI Agent 工具
    # ════════════════════════════════════════════════════════════
    {
        "agent": "Qoder",
        "vendor": "Qoder",
        "evidence": [
            ("hostname",       "api.qoder.com",                         0.60),
            ("hostname",       "qoder.com",                             0.50),
            ("hostname",       "api5.qoder.com.cn",                     0.60),
            ("hostname",       "download.qoder.com",                    0.50),
            ("ja4",            "t13d191100_9dc949149365_e5728521abd4",  0.55),
            ("ja4",            "t13d1912h2_9dc949149365_e5728521abd4",  0.55),
        ],
        "min_confidence": 0.30,
    },
    {
        "agent": "Trae",
        "vendor": "ByteDance",
        "evidence": [
            ("proto",          "trae",                                  0.70),
            ("hostname",       "trae.cn",                               0.50),
            ("hostname",       "trae.ai",                               0.50),
            ("hostname",       "api.trae.cn",                           0.55),
            ("ja4",            "t13d1516h2_8daaf6152771_e5627efa2ab1",  0.50),
        ],
        "min_confidence": 0.30,
    },
    {
        "agent": "WorkBuddy / CodeBuddy",
        "vendor": "Tencent",
        "evidence": [
            ("hostname",       "codebuddy.cn",                          0.60),
            ("hostname",       "workbuddy.tencent.com",                 0.60),
        ],
        "min_confidence": 0.30,
    },
    {
        "agent": "Lingma (通义灵码)",
        "vendor": "Alibaba",
        "evidence": [
            ("hostname",       "lingma-api.tongyi.aliyun.com",          0.70),
            ("ja4",            "t13d1911h2_9dc949149365_e7c285222651",  0.55),
        ],
        "min_confidence": 0.30,
    },
    {
        "agent": "DeepSeek Client",
        "vendor": "DeepSeek",
        "evidence": [
            ("hostname",       "chat.deepseek.com",                     0.60),
            ("hostname",       "platform.deepseek.com",                 0.55),
            ("hostname",       "hif-leim.deepseek.com",                 0.55),
            ("hostname",       "api.deepseek.com",                      0.50),
            ("ja4",            "t13d1517h2_8daaf6152771_b6f405a00624",  0.50),
            ("ja4",            "t13d1812h1_5d04281c6031_ef7df7f74e48",  0.55),
        ],
        "min_confidence": 0.30,
    },
    {
        "agent": "Doubao Client (豆包)",
        "vendor": "ByteDance",
        "evidence": [
            ("hostname",       "www.doubao.com",                        0.60),
            ("hostname",       "ime.doubao.com",                        0.55),
            ("hostname",       "api5-normal-gl.doubao.com",             0.55),
            ("hostname",       "logifier.doubao.com",                   0.50),
            ("hostname",       "mcs.doubao.com",                        0.50),
            ("hostname",       "opt.doubao.com",                        0.45),
            ("hostname",       "frontier-audio-ime-quic.doubao.com",    0.45),
            ("hostname",       "frontier-audio-ime-ws.doubao.com",      0.45),
            ("ja4",            "t13d1011h1_61a7ad8aa9b6_3fcd1a44f3e3",  0.55),
            ("ja4",            "t13d1516h2_8daaf6152771_e5627efa2ab1",  0.50),
            ("ja4",            "t13d1516h2_8daaf6152771_9b887d9acb53",  0.50),
            ("ja4",            "t13d1516h2_8daaf6152771_d242e1a2e0a0",  0.45),
            ("ja4",            "t13d1517h1_8daaf6152771_6cdcb247c39b",  0.45),
        ],
        "min_confidence": 0.30,
    },

    # ════════════════════════════════════════════════════════════
    # Local LLM clients  (connected to Ollama/vLLM/Triton)
    # ════════════════════════════════════════════════════════════
    {
        "agent": "Ollama Client",
        "vendor": "Ollama",
        "evidence": [
            ("proto",          "ollama",                                0.70),
            ("ollama_action",  "chat",                                  0.15),
            ("ollama_action",  "generate",                              0.15),
        ],
        "min_confidence": 0.20,
    },
    {
        "agent": "vLLM Client",
        "vendor": "vLLM",
        "evidence": [
            ("proto",          "vllm",                                  0.70),
            ("vllm_action",    "chat/completions",                      0.15),
            ("vllm_action",    "completions",                           0.15),
        ],
        "min_confidence": 0.20,
    },
    {
        "agent": "Triton Client",
        "vendor": "NVIDIA",
        "evidence": [
            ("proto",          "nvidia_triton",                         0.70),
            ("triton_endpoint","/v2/models",                            0.15),
            ("triton_endpoint","/v2/health",                            0.10),
        ],
        "min_confidence": 0.20,
    },
    {
        "agent": "MCP Agent",
        "vendor": "Various",
        "evidence": [
            ("proto",          "mcp",                                   0.60),
            ("mcp_method",     "initialize",                            0.20),
        ],
        "min_confidence": 0.20,
    },

    # ════════════════════════════════════════════════════════════
    # Other AI Coding Tools (identified mainly by hostname)
    # ════════════════════════════════════════════════════════════
    {
        "agent": "Windsurf",
        "vendor": "Codeium",
        "evidence": [("hostname", "windsurf.ai",          0.60)],
        "min_confidence": 0.30,
    },
    {
        "agent": "Bolt",
        "vendor": "Bolt",
        "evidence": [("hostname", "bolt.new",             0.60)],
        "min_confidence": 0.30,
    },
    {
        "agent": "Lovable",
        "vendor": "Lovable",
        "evidence": [("hostname", "lovable.dev",          0.60)],
        "min_confidence": 0.30,
    },
    {
        "agent": "Replit Agent",
        "vendor": "Replit",
        "evidence": [("hostname", "replit.com",           0.50)],
        "min_confidence": 0.30,
    },

    # ════════════════════════════════════════════════════════════
    # LLM API Gateway clients
    # ════════════════════════════════════════════════════════════
    {
        "agent": "OpenRouter Client",
        "vendor": "OpenRouter",
        "evidence": [("hostname", "openrouter.ai",        0.60)],
        "min_confidence": 0.30,
    },
    {
        "agent": "Portkey Client",
        "vendor": "Portkey",
        "evidence": [("hostname", "portkey.ai",           0.60)],
        "min_confidence": 0.30,
    },
    {
        "agent": "Ruijie Gateway Client",
        "vendor": "Ruijie",
        "evidence": [
            ("hostname", "uniapi.ruijie.com.cn",             0.50),
            ("ja4",      "t13d1812h1_85036bcba153_d41ae481755e", 0.50),
            ("ja4",      "t13d1714h1_5b57614c22b0_43ade6aba3df", 0.40),
        ],
        "min_confidence": 0.30,
    },
    # 注：Ruijie AQ / Learning / Internal Client 等非 AI 内部业务客户端
    #     已从 Agent 推断规则表移除（aq/sentinel/learning/sid/oa/bugs/sso/
    #     efa/resource/yfrelease/web-gw/hcm/ig0011/itsm 等非 AI 协议）。
    #     仅 Ruijie Gateway Client（uniapi.ruijie.com.cn LLM 网关）保留。
]


# ── Inference Engine ───────────────────────────────────────────

def _collect_signals(ndpi: dict) -> Dict[str, str]:
    """Extract all available signals from an nDPI flow."""
    signals = {
        "hostname":       (ndpi.get("hostname") or "").lower(),
        "proto":          (ndpi.get("proto") or "").lower(),
        "ja4":            _extract_ja4(ndpi),
        "user_agent":     _extract_user_agent(ndpi),
        "mcp_method":     _get_nested(ndpi, "mcp", "method"),
        "mcp_tool":       _get_nested(ndpi, "mcp", "tool_name"),
        "ollama_action":  _get_nested(ndpi, "ollama", "action"),
        "ollama_model":   _get_nested(ndpi, "ollama", "model"),
        "vllm_action":    _get_nested(ndpi, "vllm", "action"),
        "vllm_model":     _get_nested(ndpi, "vllm", "model"),
        "triton_endpoint":_get_nested(ndpi, "triton", "endpoint"),
        "triton_model":   _get_nested(ndpi, "triton", "model"),
    }
    return {k: v for k, v in signals.items() if v}


def _score_agent(agent_rule: Dict, signals: Dict[str, str]) -> float:
    """Score a single agent rule against available signals."""
    score = 0.0
    seen_signals = set()
    for signal_name, pattern, weight in agent_rule["evidence"]:
        value = signals.get(signal_name, "")
        if not value:
            continue
        if signal_name not in seen_signals:
            seen_signals.add(signal_name)
        # Substring match
        if pattern.lower() in value.lower():
            score += weight
    return score


def infer_agent(ndpi: dict) -> Optional[dict]:
    """Identify which AI Agent client is making this flow.

    Args:
        ndpi: Full nDPI sub-object from the JSON event.

    Returns:
        {agent, vendor, confidence, evidences} or None if no agent identified.
    """
    signals = _collect_signals(ndpi)
    if not signals:
        return None

    best_score = 0.0
    best_agent = None

    for rule in AGENT_INFERENCE_RULES:
        score = _score_agent(rule, signals)
        if score >= rule["min_confidence"] and score > best_score:
            best_score = score
            best_agent = {
                "agent": rule["agent"],
                "vendor": rule["vendor"],
                "confidence": round(score, 2),
            }

    return best_agent
