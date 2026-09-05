"""目标解析: 支持 IP / 域名 / CIDR / IP 范围。"""

from __future__ import annotations

import ipaddress
import re
from typing import List, Union

from .utils import resolve_host

# IP 范围正则: 10.0.0.1-50 或 10.0.0.1-10.0.0.50
RANGE_PATTERN = re.compile(
    r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})-(\d{1,3}(?:\.\d{1,3}\.\d{1,3}\.\d{1,3})?)$"
)


def parse_target(target: str) -> List[str]:
    """将单个目标字符串解析为主机列表(IP 字符串)。

    支持:
      - 单个 IP: 192.168.1.1
      - 域名: example.com (会解析为 IP)
      - CIDR: 192.168.1.0/24
      - IP 范围: 192.168.1.1-50 或 192.168.1.1-192.168.1.50

    返回去重后的 IP 地址列表。
    """
    target = target.strip()
    if not target:
        return []

    # CIDR
    if "/" in target:
        return _expand_cidr(target)

    # IP 范围 a-b
    if "-" in target and not target.startswith("-"):
        range_result = _expand_range(target)
        if range_result is not None:
            return range_result

    # 单个 IP
    if _is_ipv4(target):
        return [target]

    # 域名: 解析为 IP
    ip = resolve_host(target)
    if ip:
        return [ip]
    # 无法解析时,返回原值让扫描器自行处理(可能仍是有效主机名)
    return [target]


def parse_targets(targets: List[str]) -> List[str]:
    """批量解析多个目标,返回去重后的 IP/主机列表。"""
    seen = set()
    result: List[str] = []
    for t in targets:
        for host in parse_target(t):
            key = host.lower() if not _is_ipv4(host) else host
            if key not in seen:
                seen.add(key)
                result.append(host)
    return result


def _is_ipv4(addr: str) -> bool:
    try:
        ipaddress.IPv4Address(addr)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def _expand_cidr(cidr: str) -> List[str]:
    try:
        net = ipaddress.IPv4Network(cidr, strict=False)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
        return [cidr]
    # 网段过大时限制为主机位,跳过网络地址和广播地址
    hosts = [str(ip) for ip in net.hosts()]
    if not hosts:
        # /32 时 hosts() 为空,返回网络地址本身
        return [str(net.network_address)]
    return hosts


def _expand_range(spec: str) -> Union[List[str], None]:
    match = RANGE_PATTERN.match(spec)
    if not match:
        return None
    start_str, end_str = match.group(1), match.group(2)
    if not _is_ipv4(start_str):
        return None

    start_ip = ipaddress.IPv4Address(start_str)
    # 末段简写: 192.168.1.1-50 → 192.168.1.50
    if "." not in end_str:
        prefix = ".".join(start_str.split(".")[:3])
        end_str_full = f"{prefix}.{end_str}"
    else:
        end_str_full = end_str
    if not _is_ipv4(end_str_full):
        return None
    end_ip = ipaddress.IPv4Address(end_str_full)

    if int(end_ip) < int(start_ip):
        start_ip, end_ip = end_ip, start_ip

    # 限制范围大小,避免误输入导致巨大列表
    count = int(end_ip) - int(start_ip) + 1
    if count > 65536:
        return [spec]

    return [str(ipaddress.IPv4Address(i)) for i in range(int(start_ip), int(end_ip) + 1)]
