"""Version Extractor + CVE Correlator — 版本号提取与漏洞关联。"""

import logging
import re
from typing import List, Optional

from app.core.db import Database
from app.scan.workers.api_prober import ApiFinding
from app.scan.workers.web_fingerprinter import WebFinding
from app.scan.workers.port_prober import PortFinding

logger = logging.getLogger(__name__)


def extract_version(api_finding: Optional[ApiFinding],
                    web_finding: Optional[WebFinding],
                    port_finding: Optional[PortFinding]) -> Optional[str]:
    """版本优先级：API body > HTTP 头 > banner。"""
    if api_finding and api_finding.version_detected:
        return api_finding.version_detected
    if port_finding and port_finding.banner:
        # banner 形如 "vllm 0.4.2"
        m = re.search(r"(\d+\.\d+(?:\.\d+)?)", port_finding.banner)
        if m:
            return m.group(1)
    return None


def _parse_version(v: str):
    """解析版本号为可比较的元组。"""
    parts = re.findall(r"\d+", v)
    return tuple(int(p) for p in parts[:3]) + (0,) * (3 - len(parts[:3]))


def version_match(version: Optional[str], affected: str) -> bool:
    """判断 version 是否落在 affected 表达式内。
    affected 形如 '< 0.1.46' / '>= 0.4.0, < 0.5.0' / '*' / '<= x'
    """
    if not version or not affected or affected == "*":
        return affected == "*"
    v = _parse_version(version)
    for clause in affected.split(","):
        clause = clause.strip()
        m = re.match(r"(<=|>=|<|>|=)?\s*([\d.]+)", clause)
        if not m:
            continue
        op = m.group(1) or "="
        target = _parse_version(m.group(2))
        if op == "<" and not (v < target):
            return False
        if op == "<=" and not (v <= target):
            return False
        if op == ">" and not (v > target):
            return False
        if op == ">=" and not (v >= target):
            return False
        if op == "=" and not (v == target):
            return False
    return True


def correlate_cve(db: Database, service: str, version: Optional[str]) -> List[dict]:
    """查询某服务某版本关联的 CVE。"""
    all_cves = db.list_all_cves()
    matched = []
    for cve in all_cves:
        if cve.get("service") and cve["service"].lower() not in (service or "").lower():
            continue
        if version_match(version, cve.get("affected_version", "*")):
            matched.append(cve)
    return matched
