"""审计流水线编排: 解析目标 → 运行各模块 → 汇总 → 生成报告。"""

from __future__ import annotations

from typing import List, Optional

from .modules import compliance as compliance_mod
from .modules import port_scanner, ssl_checker, web_auditor
from .reporters.html_reporter import generate_report
from .target import parse_targets
from .utils import HostResult, INFO, Finding, resolve_host, run_concurrent


def audit_host(
    host: str,
    ports: List[int],
    timeout: float,
    threads: int,
    modules: List[str],
) -> HostResult:
    """对单台主机运行选定的审计模块,返回 HostResult。"""
    ip = resolve_host(host)
    hr = HostResult(host=host, ip=ip)

    # 端口扫描
    if "port" in modules:
        try:
            port_results = port_scanner.scan_ports(
                host, ports, timeout=timeout, max_workers=threads
            )
            hr.ports = port_results
            for f in port_scanner.to_findings(host, port_results):
                hr.findings.append(f)
        except Exception as e:
            hr.findings.append(
                Finding(module="port", severity=INFO,
                        title=f"{host}: 端口扫描失败",
                        detail=str(e))
            )

    # SSL/TLS 检查(443 端口开放或指定模块时)
    if "ssl" in modules:
        ssl_port = 443
        # 仅当 443 开放或目标明确为 HTTPS 时检查
        if any(p["port"] == 443 for p in hr.ports) or _looks_like_https(host):
            try:
                ssl_info = ssl_checker.check_ssl(host, port=ssl_port, timeout=timeout)
                hr.ssl_info = ssl_info
                for f in ssl_checker.to_findings(host, ssl_info):
                    hr.findings.append(f)
            except Exception as e:
                hr.findings.append(
                    Finding(module="ssl", severity=INFO,
                            title=f"{host}: SSL 检查失败",
                            detail=str(e))
                )

    # Web 安全检测
    if "web" in modules:
        # 自动选协议和端口
        web_port, use_https = _pick_web_port(host, hr.ports)
        if web_port:
            try:
                web_info = web_auditor.audit_web(host, port=web_port, use_https=use_https)
                hr.web_info = web_info
                for f in web_auditor.to_findings(host, web_info):
                    hr.findings.append(f)
            except Exception as e:
                hr.findings.append(
                    Finding(module="web", severity=INFO,
                            title=f"{host}: Web 检测失败",
                            detail=str(e))
                )

    # 合规检查(聚合其他模块结果)
    if "compliance" in modules:
        try:
            comp = compliance_mod.check_compliance(hr)
            hr.compliance_info = comp
            for f in compliance_mod.to_findings(host, comp):
                hr.findings.append(f)
        except Exception as e:
            hr.findings.append(
                Finding(module="compliance", severity=INFO,
                        title=f"{host}: 合规检查失败",
                        detail=str(e))
            )

    return hr


def run_audit(
    targets: List[str],
    ports: List[int],
    timeout: float = 3.0,
    threads: int = 10,
    modules: Optional[List[str]] = None,
    output_path: str = "audit_report.html",
    target_info: str = "",
    verbose: bool = False,
) -> str:
    """运行完整审计流程,返回 HTML 报告路径。"""
    if modules is None:
        modules = ["port", "ssl", "web", "compliance"]

    # 解析目标为 IP/主机列表
    hosts = parse_targets(targets)
    if not hosts:
        hosts = list(targets)

    if verbose:
        print(f"[*] 解析到 {len(hosts)} 台主机: {', '.join(hosts[:5])}{'...' if len(hosts) > 5 else ''}")
        print(f"[*] 启用模块: {', '.join(modules)}")
        print(f"[*] 端口数: {len(ports)}, 超时: {timeout}s, 并发: {threads}")

    # 并发审计每台主机(每台主机内部也已并发)
    host_results = run_concurrent(
        lambda h: audit_host(h, ports, timeout, threads, modules),
        hosts,
        max_workers=max(1, min(threads, len(hosts))) if hosts else 1,
    )

    # 按原顺序重排
    host_results.sort(key=lambda hr: hosts.index(hr.host) if hr.host in hosts else 999)

    if verbose:
        total_findings = sum(len(hr.findings) for hr in host_results)
        high_count = sum(
            1 for hr in host_results for f in hr.findings if f.severity in ("critical", "high")
        )
        print(f"[*] 审计完成: {len(host_results)} 台主机, {total_findings} 条发现, {high_count} 条高危")

    return generate_report(host_results, output_path, target_info=target_info or ", ".join(targets))


def _looks_like_https(host: str) -> bool:
    """域名特征判断是否可能是 HTTPS 服务。"""
    if not host:
        return False
    # 非纯 IP 字符串视为域名,可能提供 HTTPS
    try:
        import ipaddress
        ipaddress.IPv4Address(host)
        return False
    except (ipaddress.AddressValueError, ValueError):
        return True


def _pick_web_port(host: str, ports: List[dict]):
    """从开放端口中选择 Web 端口,返回 (port, use_https)。"""
    open_ports = {p["port"] for p in ports}
    if 443 in open_ports:
        return 443, True
    if 80 in open_ports:
        return 80, False
    if 8080 in open_ports:
        return 8080, False
    if 8443 in open_ports:
        return 8443, True
    # 未发现 Web 端口,若主机像域名则试 80/443
    if _looks_like_https(host):
        return 443, True
    return 0, False
