"""CVE Updater — 种子 CVE + NVD 拉取（Phase 5 实现）。"""

import logging

from app.core.db import Database

logger = logging.getLogger(__name__)

# 初始种子 CVE（内建已知 AI 框架漏洞）
_SEED_CVES = [
    {
        "cve_id": "CVE-2024-37032",
        "service": "Ollama",
        "vendor": "Ollama",
        "affected_version": "< 0.1.46",
        "severity": "high",
        "cvss_score": 9.8,
        "description": "Ollama < 0.1.46 远程代码执行（路径穿越导致任意文件写）",
        "reference_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-37032",
        "published_at": "2024-06-04",
    },
    {
        "cve_id": "CVE-2024-22420",
        "service": "Dify",
        "vendor": "Dify",
        "affected_version": "< 0.6.0",
        "severity": "medium",
        "cvss_score": 7.5,
        "description": "Dify < 0.6.0 未授权 API 访问，可枚举应用与数据",
        "reference_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-22420",
        "published_at": "2024-01-15",
    },
    {
        "cve_id": "OLLAMA-RCE-0.1.34",
        "service": "Ollama",
        "vendor": "Ollama",
        "affected_version": "< 0.1.34",
        "severity": "critical",
        "cvss_score": 10.0,
        "description": "Ollama < 0.1.34 未授权模型拉取/删除（默认无认证）",
        "reference_url": "",
        "published_at": "2024-02-01",
    },
    {
        "cve_id": "DOCKER-UNAUTH-2375",
        "service": "Docker",
        "vendor": "Docker",
        "affected_version": "*",
        "severity": "critical",
        "cvss_score": 9.8,
        "description": "Docker daemon 2375/2376 端口未授权暴露，可完全接管宿主机",
        "reference_url": "",
        "published_at": "2024-01-01",
    },
    {
        "cve_id": "K8S-UNAUTH-6443",
        "service": "Kubernetes",
        "vendor": "Kubernetes",
        "affected_version": "*",
        "severity": "critical",
        "cvss_score": 9.8,
        "description": "Kubernetes API Server 6443 端口未授权暴露，可枚举/创建 Pod",
        "reference_url": "",
        "published_at": "2024-01-01",
    },
    {
        "cve_id": "VLLM-0.4.0",
        "service": "vLLM",
        "vendor": "vLLM",
        "affected_version": "< 0.4.0",
        "severity": "medium",
        "cvss_score": 6.5,
        "description": "vLLM < 0.4.0 模型提权问题",
        "reference_url": "",
        "published_at": "2024-03-01",
    },
]


def seed_initial_cves(db: Database):
    """cve_records 为空时插入种子数据。"""
    existing = db.list_all_cves()
    if existing:
        return
    db.upsert_cve_records_batch(_SEED_CVES)
    logger.info(f"seeded {len(_SEED_CVES)} initial CVE records")


async def update_from_nvd(db: Database):
    """从 NVD 拉取最新 CVE（Phase 5 实现）。"""
    # TODO Phase 5: aiohttp 拉 https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json
    # 筛选 AI 相关 service → UPSERT
    logger.info("update_from_nvd: stub (Phase 5)")
    return 0
