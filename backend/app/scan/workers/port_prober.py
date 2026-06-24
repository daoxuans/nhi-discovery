"""Port Prober — nmap subprocess + XML 解析。

root 用 -sS（SYN scan），非 root 用 -sT（connect scan）。
全局 --max-rate 限速。
"""

import asyncio
import logging
import os
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import List

logger = logging.getLogger(__name__)

# AI 框架默认端口 + 常见 Web 端口
# 设计原则：AI agent 端口常被用户自定义（如 1Panel 随机分配），固定列表不可靠。
# - AI_PORTS: 仅列"高置信度默认端口"（AI 框架出厂默认值），用于 ai_ports_only 快速探测。
#   不含 80/443/3000/8000/8080 等通用 web 端口（那些走 web_only / full）。
# - 发现自定义端口的 AI agent 靠 full 策略全端口扫描 + web_fingerprinter 内容指纹。
# - 同时在 full 策略里扩展常见 AI 端口，避免漏扫已知框架。
AI_PORTS = [
    11434,   # Ollama
    7860,    # Gradio
    8501,    # Streamlit
    8001,    # Triton
    12345,   # LM Studio
    9000,    # TGI (Text Generation Inference)
    5000,    # 常见 LLM 推理 (Flask/Gunicorn/MLflow)
    8265,    # Ray Dashboard
    19530,   # Milvus 向量库
    6333,    # Qdrant 向量库
]
# WEB_PORTS：通用 web 端口，web_only 策略用；web_fingerprinter 对这些端口做内容指纹
WEB_PORTS = [80, 443, 3000, 5001, 8000, 8080, 8443, 8888]
# FULL_PORTS：full 策略扫描的端口集合 = AI 默认端口 + web 端口 + 更多可能部署 agent 的端口
# 覆盖常见自定义 agent 部署区间，配合内容指纹发现非标准端口 agent
FULL_PORTS = sorted(set(
    AI_PORTS
    + WEB_PORTS
    + [5678, 8888, 9119, 9120, 18789, 18791,   # 已知 agent 自定义端口区间
       8889, 9999, 11434, 8000, 8001, 8080,     # 备用
       7860, 7861, 8501, 8502,                  # Gradio/Streamlit 备用
       2375, 2376, 6443, 10250, 16443]          # 容器/K8s（探测未授权）
))


@dataclass
class PortFinding:
    ip: str
    port: int
    proto: str
    state: str
    service_raw: str
    banner: str


def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


async def probe_ports(cidr: str, ports: List[int], rate_pps: int,
                      timeout: int = 300, nmap_timing: str = "-T3") -> List[PortFinding]:
    """对 cidr 扫指定端口，返回开放端口列表。nmap_timing 控制 -T 档位。"""
    scan_type = "-sS" if _is_root() else "-sT"
    port_str = ",".join(str(p) for p in sorted(set(ports)))
    cmd = [
        "nmap", scan_type, nmap_timing, f"--max-rate={rate_pps}",
        "-p", port_str, "-oX", "-", "--webxml",
        "-n",  # 不做 DNS 反解，加速
        cidr,
    ]
    logger.info(f"nmap: {' '.join(cmd)}")
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            logger.warning(f"nmap timeout ({timeout}s) for {cidr}")
            return []
        if proc.returncode not in (0, 1):  # nmap 1 = no hosts up，不算错
            logger.warning(f"nmap rc={proc.returncode}: {stderr.decode(errors='replace')[:200]}")
            return []
        return _parse_nmap_xml(stdout.decode(errors="replace"))
    except FileNotFoundError:
        logger.error("nmap not installed")
        return []
    except Exception as e:
        logger.error(f"port probe failed: {type(e).__name__}: {e}")
        return []


def _parse_nmap_xml(xml_str: str) -> List[PortFinding]:
    """解析 nmap XML 输出，返回 open 端口。"""
    findings = []
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError as e:
        logger.error(f"nmap XML parse error: {e}")
        return findings
    for host in root.findall("host"):
        addr_elem = host.find("address")
        if addr_elem is None:
            continue
        ip = addr_elem.get("addr", "")
        state_elem = host.find("status")
        if state_elem is not None and state_elem.get("state") != "up":
            continue
        ports_elem = host.find("ports")
        if ports_elem is None:
            continue
        for port in ports_elem.findall("port"):
            port_id = port.get("portid")
            if not port_id:
                continue
            proto = port.get("protocol", "tcp")
            state_e = port.find("state")
            state = state_e.get("state", "") if state_e is not None else ""
            if state != "open":
                continue
            service_e = port.find("service")
            service_raw = service_e.get("name", "") if service_e is not None else ""
            product = service_e.get("product", "") if service_e is not None else ""
            version = service_e.get("version", "") if service_e is not None else ""
            banner = " ".join(filter(None, [product, version])).strip()
            findings.append(PortFinding(
                ip=ip, port=int(port_id), proto=proto,
                state=state, service_raw=service_raw, banner=banner,
            ))
    return findings
