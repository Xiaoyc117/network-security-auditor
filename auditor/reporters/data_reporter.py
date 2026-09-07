"""结构化数据报告生成: JSON 和 CSV 格式,便于程序处理和二次分析。"""

from __future__ import annotations

import csv
import json
from typing import List

from ..utils import Finding, HostResult, now_str


def host_to_dict(hr: HostResult) -> dict:
    """将单主机审计结果转为可序列化字典。"""
    return {
        "host": hr.host,
        "ip": hr.ip,
        "severity_counts": hr.severity_counts,
        "ports": hr.ports,
        "ssl": hr.ssl_info,
        "web": hr.web_info,
        "compliance": hr.compliance_info,
        "findings": [
            {
                "module": f.module,
                "severity": f.severity,
                "title": f.title,
                "detail": f.detail,
                "evidence": f.evidence,
                "recommendation": f.recommendation,
            }
            for f in hr.findings
        ],
    }


def generate_json(host_results: List[HostResult], output_path: str, target_info: str = "") -> str:
    """生成 JSON 格式审计报告。"""
    summary = {
        "total_hosts": len(host_results),
        "total_findings": sum(len(hr.findings) for hr in host_results),
        "severity_counts": _aggregate_severity(host_results),
        "generated_at": now_str(),
        "target": target_info,
    }
    data = {
        "summary": summary,
        "hosts": [host_to_dict(hr) for hr in host_results],
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    return output_path


def generate_csv(host_results: List[HostResult], output_path: str) -> str:
    """生成 CSV 格式审计报告(每条发现一行)。"""
    fieldnames = [
        "host", "ip", "module", "severity", "title",
        "detail", "evidence", "recommendation",
    ]
    with open(output_path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for hr in host_results:
            for finding in hr.findings:
                writer.writerow({
                    "host": hr.host,
                    "ip": hr.ip,
                    "module": finding.module,
                    "severity": finding.severity,
                    "title": finding.title,
                    "detail": finding.detail,
                    "evidence": finding.evidence,
                    "recommendation": finding.recommendation,
                })
    return output_path


def _aggregate_severity(host_results: List[HostResult]) -> dict:
    """汇总所有主机的风险等级计数。"""
    from ..utils import SEVERITY_ORDER
    counts = {s: 0 for s in SEVERITY_ORDER}
    for hr in host_results:
        for sev, n in hr.severity_counts.items():
            counts[sev] = counts.get(sev, 0) + n
    return counts
