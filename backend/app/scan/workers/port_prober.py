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
AI_PORTS = [11434, 8000, 8001, 8080, 12345, 80, 443, 3000, 5001, 5678, 2375, 2376, 6443]
WEB_PORTS = [80, 443, 3000, 5001, 8000, 8080, 8443]


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
                      timeout: int = 300) -> List[PortFinding]:
    """对 cidr 扫指定端口，返回开放端口列表。"""
    scan_type = "-sS" if _is_root() else "-sT"
    port_str = ",".join(str(p) for p in sorted(set(ports)))
    cmd = [
        "nmap", scan_type, "-T3", f"--max-rate={rate_pps}",
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
