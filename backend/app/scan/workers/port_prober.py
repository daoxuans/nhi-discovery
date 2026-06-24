"""Port Prober — nmap subprocess + XML 解析。

root 用 -sS（SYN scan），非 root 用 -sT（connect scan）。
全局 --max-rate 限速。

设计原则：AI agent 端口常被用户自定义（如 1Panel 容器随机分配），固定列表不可靠。
两策略：
  - 快速探测（quick）：只扫 AI 框架出厂默认端口，10 端口，秒级。适用快速巡检。
  - 深度指纹（deep）：三步流程 — 探活 → 逐 IP 全端口 → 内容指纹。
    Step 1: nmap -sn 发现存活主机（比默认探活更可靠，防火墙也不漏）。
    Step 2: 每 IP 单独 nmap -Pn -p 1-65535，并行 8 路，逐 IP 更新进度。
    Step 3: 对开放端口做内容探测（API/Web 指纹/容器）。
"""

import asyncio
import ipaddress
import logging
import os
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Callable, List, Optional

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


async def probe_live(cidr: str, timeout: int = 30) -> List[str]:
    """Step 1: 发现存活主机。返回存活 IP 列表。

    nmap -sn: ICMP echo + TCP 443 SYN + TCP 80 ACK + ARP (局域网)。
    比 nmap 默认探活更可靠——有防火墙的主机也会被 443/80 探针发现。
    局域网 ARP 探针能发现全部在线主机（包括 drop 所有入站 IP 包的）。
    """
    cmd = ["nmap", "-sn", "-n", "-oX", "-", cidr]
    logger.info(f"nmap ping sweep: {' '.join(cmd)}")
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            logger.warning(f"nmap ping sweep timeout ({timeout}s) for {cidr}")
            return []
        root = ET.fromstring(stdout.decode(errors="replace"))
        ips = []
        for host in root.findall("host"):
            addr = host.find("address")
            status = host.find("status")
            if addr is not None and status is not None and status.get("state") == "up":
                ips.append(addr.get("addr", ""))
        logger.info(f"ping sweep {cidr}: {len(ips)} live hosts")
        return sorted(ips, key=lambda x: ipaddress.ip_address(x))
    except ET.ParseError as e:
        logger.error(f"nmap ping sweep XML parse error: {e}")
        return []
    except FileNotFoundError:
        logger.error("nmap not installed")
        return []
    except Exception as e:
        logger.error(f"nmap ping sweep failed: {type(e).__name__}: {e}")
        return []


async def probe_ports_single(ip: str, rate_pps: int,
                             timeout: int = 45,
                             nmap_timing: str = "-T4") -> List[PortFinding]:
    """Step 2: 单 IP 全端口扫描（跳过主机发现，-Pn 不漏防火墙主机）。

    对单一 IP 扫 1-65535。调用方并行 N 路，每完成一路回调更新进度。
    """
    scan_type = "-sS" if _is_root() else "-sT"
    cmd = [
        "nmap", scan_type, nmap_timing, f"--max-rate={rate_pps}",
        "-p", "1-65535", "-Pn", "-oX", "-", "--webxml",
        "-n", ip,
    ]
    logger.info(f"nmap single-ip full: {' '.join(cmd)}")
    return await _run_nmap(cmd, ip, timeout)


async def probe_ports_full(cidr: str, rate_pps: int,
                           timeout: int = 600, nmap_timing: str = "-T4") -> List[PortFinding]:
    """深度指纹（保留兼容）：全端口 1-65535 TCP SYN 扫描，无遗漏。

    新三步流程推荐用 probe_live + probe_ports_single 代替，获得逐 IP 进度。
    此函数保留供 quick 策略和向后兼容。
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


async def probe_ports_full_with_progress(
    cidr: str, rate_pps: int, nmap_timing: str,
    on_progress: Callable[[int, int], None],   # async (done, total)
    port_timeout: int = 45,
) -> List[PortFinding]:
    """三步深度扫描（带进度回调）。

    1. nmap -sn 探活 → 得到存活 IP 列表
    2. 对每个 IP 并行 probe_ports_single（-Pn），Semaphore(8)，
       每完成一个 IP 回调 on_progress(done, total)
    3. 返回全量 PortFinding 列表

    on_progress: async callable(done, total)，每次 IP 扫描完成时调用。
    """
    live_ips = await probe_live(cidr)
    total = len(live_ips)
    if total == 0:
        logger.info(f"scan {cidr}: no live hosts")
        return []

    sem = asyncio.Semaphore(8)  # 8 路并行单 IP nmap
    progress_lock = asyncio.Lock()
    results: List[List[PortFinding]] = []
    completed = 0

    async def _scan_one(ip: str):
        nonlocal completed
        async with sem:
            findings = await probe_ports_single(
                ip, rate_pps, timeout=port_timeout, nmap_timing=nmap_timing,
            )
        async with progress_lock:
            results.append(findings)
            completed += 1
            cur = completed
        if on_progress:
            try:
                await on_progress(cur, total)
            except Exception as e:
                logger.warning(f"on_progress error: {e}")
        return findings

    await asyncio.gather(*[_scan_one(ip) for ip in live_ips])

    all_findings: List[PortFinding] = []
    for r in results:
        all_findings.extend(r)
    logger.info(f"scan {cidr}: {len(live_ips)} hosts → {len(all_findings)} open ports")
    return all_findings


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
