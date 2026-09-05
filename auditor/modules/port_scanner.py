"""端口与服务扫描: TCP connect 扫描 + banner 抓取。"""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

from ..utils import Finding, HIGH, INFO, LOW, MEDIUM, resolve_host, run_concurrent

# 默认扫描的常见端口(Top 100 简化版)
DEFAULT_PORTS = [
    20, 21, 22, 23, 25, 26, 53, 80, 81, 110, 111, 113, 119, 135, 139,
    143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515,
    548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027,
    1080, 1095, 1098, 1099, 1100, 1433, 1434, 1521, 1723, 1725, 1900,
    2000, 2049, 2082, 2083, 2086, 2087, 2095, 2096, 2181, 2375, 2376,
    2483, 2484, 2638, 3000, 3128, 3306, 3389, 3478, 3690, 3702, 4000,
    4369, 4489, 5000, 5001, 5060, 5432, 5500, 5666, 5800, 5900, 5901,
    5984, 6000, 6379, 6443, 6660, 6661, 6666, 6667, 6668, 6669, 7000,
    7001, 7474, 7547, 7777, 8000, 8001, 8008, 8009, 8010, 8069, 8080,
    8081, 8086, 8088, 8090, 8161, 8333, 8443, 8444, 8888, 9000, 9001,
    9009, 9042, 9090, 9092, 9100, 9200, 9300, 9418, 9999, 10000, 10001,
    11211, 15672, 16992, 16993, 17000, 18080, 19999, 20000, 25565, 27015,
    27017, 27018, 27019, 28015, 50070, 50075, 50090, 61613, 61614,
]

# 常见端口对应服务
COMMON_SERVICES = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 81: "HTTP", 110: "POP3", 111: "RPC",
    119: "NNTP", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP", 179: "BGP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 513: "rlogin", 514: "syslog",
    515: "LPD", 587: "SMTP", 631: "IPP", 646: "LDP", 873: "rsync",
    990: "FTPS", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1433: "MSSQL",
    1521: "Oracle", 1723: "PPTP", 2049: "NFS", 2375: "Docker", 2376: "Docker",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    7001: "WebLogic", 8000: "HTTP", 8080: "HTTP-Proxy", 8443: "HTTPS",
    9000: "PHP-FPM/Portainer", 9200: "Elasticsearch", 9300: "ES-Transport",
    11211: "Memcached", 27017: "MongoDB", 27018: "MongoDB", 50070: "HDFS",
}

# 高危端口(明文/弱认证服务,不应暴露公网)
HIGH_RISK_PORTS = {23, 21, 69, 161, 389, 445, 512, 513, 514, 873, 1099, 1521, 2049, 2375, 2376, 6379, 11211, 27017}

# banner 探针: 不同协议发送的探测数据
BANNER_PROBES = {
    21: b"HEAD / HTTP/1.0\r\n\r\n",
    22: b"",
    25: b"EHLO audit\r\n",
    80: b"HEAD / HTTP/1.0\r\n\r\n",
    443: None,  # HTTPS,不直接抓 banner
    3306: b"",
    6379: b"PING\r\n",
    11211: b"version\r\n",
    27017: b"",
}


def parse_ports(ports_str: str) -> List[int]:
    """解析端口字符串: '80,443,1000-1005'。"""
    if not ports_str:
        return DEFAULT_PORTS
    result: List[int] = []
    for part in ports_str.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            try:
                lo_i, hi_i = int(lo), int(hi)
                result.extend(range(lo_i, hi_i + 1))
            except ValueError:
                continue
        else:
            try:
                result.append(int(part))
            except ValueError:
                continue
    return sorted(set(result))


def scan_one_port(host: str, port: int, timeout: float) -> dict:
    """扫描单个端口,返回结果字典。"""
    result = {"port": port, "state": "closed", "service": "", "banner": ""}
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        if sock.connect_ex((host, port)) == 0:
            result["state"] = "open"
            result["service"] = COMMON_SERVICES.get(port, "")
            banner = _grab_banner(host, port, timeout)
            if banner:
                result["banner"] = banner
    except (socket.error, OSError):
        pass
    finally:
        sock.close()
    return result


def _grab_banner(host: str, port: int, timeout: float, max_bytes: int = 256) -> str:
    """抓取端口 banner,返回截断后的字符串。"""
    probe = BANNER_PROBES.get(port, b"")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        if probe:
            try:
                sock.sendall(probe)
            except socket.error:
                pass
        try:
            data = sock.recv(max_bytes)
        except socket.timeout:
            data = b""
        # 清理非可打印字符
        banner = data.decode("utf-8", errors="ignore").strip()
        # 截取首行
        if banner:
            banner = banner.splitlines()[0][:120] if "\n" in banner else banner[:120]
        return banner
    except (socket.error, OSError):
        return ""
    finally:
        sock.close()


def scan_ports(
    host: str,
    ports: List[int],
    timeout: float = 3.0,
    max_workers: int = 50,
) -> List[dict]:
    """并发扫描端口号列表,返回开放端口结果。"""
    workers = max(1, min(max_workers, len(ports))) if ports else 1
    results: List[dict] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(scan_one_port, host, port, timeout): port for port in ports
        }
        for future in as_completed(futures):
            try:
                res = future.result()
                if res["state"] == "open":
                    results.append(res)
            except Exception:
                continue
    results.sort(key=lambda r: r["port"])
    return results


def to_findings(host: str, port_results: List[dict]) -> List[Finding]:
    """将端口扫描结果转换为审计发现列表。"""
    findings: List[Finding] = []
    if not port_results:
        findings.append(
            Finding(
                module="port",
                severity=INFO,
                title=f"{host}: 无开放端口",
                detail="未检测到任何开放端口,目标可能离线或被防火墙过滤。",
            )
        )
        return findings

    findings.append(
        Finding(
            module="port",
            severity=INFO,
            title=f"{host}: 发现 {len(port_results)} 个开放端口",
            detail="开放端口列表见下方端口表。",
        )
    )

    for r in port_results:
        port = r["port"]
        service = r["service"] or "unknown"
        banner = r.get("banner", "")

        # 高危端口暴露
        if port in HIGH_RISK_PORTS:
            findings.append(
                Finding(
                    module="port",
                    severity=HIGH,
                    title=f"{host}: 高危端口 {port} ({service}) 开放",
                    detail="该端口对应的服务通常不应直接暴露在公网。",
                    evidence=banner or "",
                    recommendation=f"如非必要,关闭端口 {port} 或通过防火墙限制访问来源。",
                )
            )
        # 明文服务(可被嗅探)
        elif port in (21, 23, 25, 109, 110, 143, 513, 514):
            findings.append(
                Finding(
                    module="port",
                    severity=MEDIUM,
                    title=f"{host}: 明文服务端口 {port} ({service}) 开放",
                    detail="该服务传输数据未加密,可能被中间人嗅探凭据。",
                    evidence=banner or "",
                    recommendation=f"升级到加密版本(如 SSH 替代 Telnet、IMAPS 替代 IMAP),或关闭 {port}。",
                )
            )
        # 数据库/缓存端口暴露
        elif port in (3306, 5432, 6379, 11211, 27017, 1521, 9200):
            findings.append(
                Finding(
                    module="port",
                    severity=MEDIUM,
                    title=f"{host}: 数据库/缓存端口 {port} ({service}) 开放",
                    detail="数据库服务不应直接暴露到公网,易受未授权访问和暴力破解。",
                    evidence=banner or "",
                    recommendation="限制数据库端口仅监听内网,通过应用层访问。",
                )
            )
        else:
            # 普通开放端口
            if banner:
                findings.append(
                    Finding(
                        module="port",
                        severity=LOW,
                        title=f"{host}: 端口 {port} ({service}) 暴露 banner 信息",
                        detail="服务主动返回版本信息,有助于攻击者指纹识别。",
                        evidence=banner,
                        recommendation="关闭服务的版本回显(如 SSH GSSAPIAuthentication、Apache ServerTokens)。"
                    )
                )

        # banner 中泄露版本号
        if banner and any(kw in banner.lower() for kw in ("version", "ubuntu", "debian", "openssh", "apache", "nginx", "mysql")):
            findings.append(
                Finding(
                    module="port",
                    severity=LOW,
                    title=f"{host}: 端口 {port} 服务版本泄露",
                    detail=f"banner 包含版本信息: {banner}",
                    evidence=banner,
                    recommendation="隐藏服务版本号,减少攻击面。",
                )
            )

    return findings
