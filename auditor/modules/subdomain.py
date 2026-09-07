"""子域名枚举模块: 通过 DNS 暴力枚举发现目标的子域名。

策略(纯标准库,零外部依赖):
1. 内置常见子域名字典(约 40 条高频前缀)
2. 对每个候选子域名做 DNS A 记录查询
3. 解析成功即视为存在的子域名
4. 发现的子域名可作为新目标送入后续审计流程

注意: 仅限授权审计使用。
"""

from __future__ import annotations

import socket
from typing import Callable, List, Optional

from ..utils import Finding, run_concurrent

# 内置高频子域名字典(可扩展)
DEFAULT_WORDLIST: List[str] = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "dns", "dns1", "dns2", "admin", "portal", "api", "app", "dev", "test",
    "staging", "stage", "prod", "vpn", "m", "mobile", "blog", "shop", "store",
    "cdn", "static", "img", "images", "media", "git", "gitlab", "jenkins",
    "ci", "build", "monitor", "status", "docs", "wiki", "help", "support",
    "secure", "login", "sso", "auth", "oauth", "dashboard", "panel",
]


def enumerate_subdomains(
    domain: str,
    wordlist: Optional[List[str]] = None,
    threads: int = 20,
    timeout: float = 2.0,
    resolver: Callable[[str], Optional[str]] = None,
) -> List[str]:
    """对域名做子域名枚举,返回解析成功的子域名列表。

    Args:
        domain: 根域名,如 example.com
        wordlist: 子域名前缀列表,默认使用 DEFAULT_WORDLIST
        threads: 并发线程数
        timeout: DNS 查询超时
        resolver: 可选的自定义解析函数,默认用 socket.gethostbyname
    """
    if not domain or domain.lower() in ("localhost", "127.0.0.1"):
        # 非域名/IP 目标不做子域名枚举
        return []

    words = wordlist if wordlist is not None else DEFAULT_WORDLIST
    candidates = [f"{w}.{domain}".lower() for w in words]
    # 去重保序
    seen = set()
    candidates = [c for c in candidates if not (c in seen or seen.add(c))]

    if resolver is None:
        def _default_resolver(name: str) -> Optional[str]:
            try:
                return socket.gethostbyname(name)
            except (socket.gaierror, socket.herror, socket.timeout, OSError):
                return None
        resolver = _default_resolver

    # 临时缩短 socket 超时,避免单个查询阻塞过久
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        results = run_concurrent(resolver, candidates, max_workers=threads)
    finally:
        socket.setdefaulttimeout(old_timeout)

    found = [c for c, ip in zip(candidates, results) if ip]
    return found


def to_findings(domain: str, found_subdomains: List[str]) -> List[Finding]:
    """将子域名枚举结果转为 Finding 列表。"""
    findings: List[Finding] = []
    if not found_subdomains:
        return findings

    # 发现子域名本身是信息泄露级别的发现(INFO)
    findings.append(Finding(
        module="subdomain",
        severity="info",
        title=f"发现 {len(found_subdomains)} 个子域名",
        detail=f"根域名 {domain} 下解析成功的子域名: {', '.join(found_subdomains[:10])}{'...' if len(found_subdomains) > 10 else ''}",
        evidence="\n".join(found_subdomains),
        recommendation="核实所有子域名均为已知资产;未知子域名可能被用于钓鱼或影子 IT,建议纳入资产管理。",
    ))

    # 检查是否有高危子域名(暴露管理面板等)
    high_risk_keywords = ["admin", "login", "sso", "auth", "jenkins", "gitlab", "ci", "build"]
    risky = [s for s in found_subdomains if any(k in s for k in high_risk_keywords)]
    if risky:
        findings.append(Finding(
            module="subdomain",
            severity="medium",
            title="发现可能暴露管理/CI 接口的子域名",
            detail=f"高危关键词子域名: {', '.join(risky)}",
            evidence="\n".join(risky),
            recommendation="管理面板/CI 接口应限制访问来源 IP、强制认证,并避免公网直接暴露。",
        ))

    return findings
