"""Port Prober — nmap subprocess + XML 解析。

root 用 -sS（SYN scan），非 root 用 -sT（connect scan）。
全局 --max-rate 限速。

设计原则：AI agent 端口常被用户自定义（如 1Panel 容器随机分配），固定列表不可靠。
两策略：
  - 快速探测（quick）：只扫 AI 框架出厂默认端口，10 端口，秒级。适用快速巡检。
  - 深度指纹（deep）：全端口 1-65535 TCP SYN 扫描 + 内容指纹，无遗漏，零维护。
    单 IP 约 33s (2000pps)，/24 网段约 2-3 分钟。
"""

import asyncio
import logging
import os
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import List

logger = logging.getLogger(__name__)

# 快速探测：AI 框架出厂默认端口（研发不改端口时秒发现）
QUICK_PORTS = [
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
    """快扫：对 cidr 扫指定端口，返回开放端口列表。nmap_timing 控制 -T 档位。"""
    scan_type = "-sS" if _is_root() else "-sT"
    port_str = ",".join(str(p) for p in sorted(set(ports)))
    cmd = [
        "nmap", scan_type, nmap_timing, f"--max-rate={rate_pps}",
        "-p", port_str, "-oX", "-", "--webxml",
        "-n",  # 不做 DNS 反解，加速
        cidr,
    ]
    logger.info(f"nmap quick: {' '.join(cmd)}")
    return await _run_nmap(cmd, cidr, timeout)


async def probe_ports_full(cidr: str, rate_pps: int,
                           timeout: int = 600, nmap_timing: str = "-T4") -> List[PortFinding]:
    """深度指纹：全端口 1-65535 TCP SYN 扫描，无遗漏。

    -p 1-65535 覆盖所有 TCP 端口，nmap 并行扫描多台主机。
    配合 web_fingerprinter 内容指纹，1Panel/自定义端口的 agent 无死角。
    单 IP 约 33s @ 2000pps；/24 网段约 2-3 min。
    """
    scan_type = "-sS" if _is_root() else "-sT"
    cmd = [
        "nmap", scan_type, nmap_timing, f"--max-rate={rate_pps}",
        "-p", "1-65535", "-oX", "-", "--webxml",
        "-n",
        cidr,
    ]
    logger.info(f"nmap deep (full-port): {' '.join(cmd)}")
    return await _run_nmap(cmd, cidr, timeout)


async def _run_nmap(cmd: List[str], cidr: str, timeout: int) -> List[PortFinding]:
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
