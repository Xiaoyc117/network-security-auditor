"""公共工具: 风险评级、DNS 解析、并发执行、HTML 转义。"""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Iterable, List, Optional, Tuple, TypeVar

T = TypeVar("T")
R = TypeVar("R")

# 风险等级常量
CRITICAL = "critical"
HIGH = "high"
MEDIUM = "medium"
LOW = "low"
INFO = "info"

# 风险等级权重(用于合规得分计算)
SEVERITY_WEIGHT = {
    CRITICAL: 100,
    HIGH: 60,
    MEDIUM: 30,
    LOW: 10,
    INFO: 0,
}

# HTML 报告中风险徽章颜色
SEVERITY_COLOR = {
    CRITICAL: "#c0392b",
    HIGH: "#e74c3c",
    MEDIUM: "#f39c12",
    LOW: "#f1c40f",
    INFO: "#7f8c8d",
}

# 中文风险标签
SEVERITY_LABEL = {
    CRITICAL: "严重",
    HIGH: "高危",
    MEDIUM: "中危",
    LOW: "低危",
    INFO: "信息",
}

# 风险排序顺序(用于报告展示)
SEVERITY_ORDER = [CRITICAL, HIGH, MEDIUM, LOW, INFO]


@dataclass
class Finding:
    """单条审计发现。"""

    module: str  # 来源模块: port/ssl/web/compliance
    severity: str  # 风险等级
    title: str  # 简要描述
    detail: str = ""  # 详细说明
    evidence: str = ""  # 证据/原始数据
    recommendation: str = ""  # 修复建议


@dataclass
class HostResult:
    """单台主机的审计结果。"""

    host: str
    ip: str = ""
    findings: List[Finding] = field(default_factory=list)
    # 各模块原始结果,供合规模块和报告使用
    ports: List[dict] = field(default_factory=list)
    ssl_info: Optional[dict] = None
    web_info: Optional[dict] = None
    compliance_info: Optional[dict] = None

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    @property
    def severity_counts(self) -> dict:
        counts = {s: 0 for s in SEVERITY_ORDER}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    @property
    def has_high_or_above(self) -> bool:
        return any(f.severity in (CRITICAL, HIGH) for f in self.findings)


def resolve_host(host: str) -> str:
    """将主机名解析为 IPv4 地址; 输入已是 IP 则原样返回。"""
    try:
        socket.inet_aton(host)
        return host
    except OSError:
        pass
    try:
        info = socket.getaddrinfo(host, None, socket.AF_INET)
        if info:
            return info[0][4][0]
    except socket.gaierror:
        pass
    return ""


def run_concurrent(
    func: Callable[[T], R],
    items: Iterable[T],
    max_workers: int = 10,
) -> List[R]:
    """并发执行 func(item),返回按完成顺序的结果(忽略异常项)。"""
    results: List[R] = []
    items_list = list(items)
    if not items_list:
        return results
    workers = max(1, min(max_workers, len(items_list)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(func, item): item for item in items_list}
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception:
                continue
    return results


def html_escape(text: str) -> str:
    """转义 HTML 特殊字符。"""
    if text is None:
        return ""
    text = str(text)
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def now_str() -> str:
    """当前时间字符串(用于报告时间戳)。"""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def severity_rank(sev: str) -> int:
    """风险等级排序值,越小越严重(CRITICAL=0, INFO=4)。"""
    return SEVERITY_ORDER.index(sev) if sev in SEVERITY_ORDER else len(SEVERITY_ORDER)


def sort_findings(findings: List[Finding]) -> List[Finding]:
    """按风险等级排序发现,最严重的在前。"""
    return sorted(findings, key=lambda f: severity_rank(f.severity))
