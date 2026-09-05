"""合规与配置检查: 基于 OWASP/CIS 基线评估其他模块的发现。"""

from __future__ import annotations

from typing import List

from ..utils import (
    CRITICAL,
    Finding,
    HIGH,
    HostResult,
    INFO,
    LOW,
    MEDIUM,
    SEVERITY_WEIGHT,
    severity_rank,
)

# 合规规则定义
# 每条规则: id, name, severity, check(函数,接收 HostResult 返回 bool 是否违规), advice
COMPLIANCE_RULES = [
    {
        "id": "CIS-NET-001",
        "name": "不应暴露明文远程登录服务(Telnet/rlogin)",
        "severity": HIGH,
        "advice": "禁用 Telnet(23)、rlogin(513),使用 SSH 替代。",
    },
    {
        "id": "CIS-NET-002",
        "name": "数据库/缓存服务不应直接暴露公网",
        "severity": HIGH,
        "advice": "MySQL/PostgreSQL/Redis/MongoDB/Memcached 仅监听内网。",
    },
    {
        "id": "OWASP-CRYPTO-001",
        "name": "HTTPS 服务不应启用 TLS 1.0 / 1.1",
        "severity": HIGH,
        "advice": "禁用 TLS 1.0/1.1,仅启用 TLS 1.2+。",
    },
    {
        "id": "OWASP-CRYPTO-002",
        "name": "SSL 证书不应过期或自签名",
        "severity": MEDIUM,
        "advice": "使用受信任 CA 签发的证书并定期续期。",
    },
    {
        "id": "OWASP-HEADER-001",
        "name": "Web 服务应配置 HSTS",
        "severity": MEDIUM,
        "advice": "配置 Strict-Transport-Security 头。",
    },
    {
        "id": "OWASP-HEADER-002",
        "name": "Web 服务应配置 CSP",
        "severity": MEDIUM,
        "advice": "配置 Content-Security-Policy 头以防御 XSS。",
    },
    {
        "id": "OWASP-EXPOSE-001",
        "name": "不应暴露源代码/备份/凭据文件",
        "severity": CRITICAL,
        "advice": "删除 .git/.env/备份文件,并配置服务器禁止访问。",
    },
    {
        "id": "OWASP-EXPOSE-002",
        "name": "管理后台不应公网可直接访问",
        "severity": MEDIUM,
        "advice": "管理路径增加 IP 白名单或 VPN 访问。",
    },
    {
        "id": "CIS-PORT-001",
        "name": "SMB/RDP 不应暴露公网",
        "severity": HIGH,
        "advice": "445/3389 端口通过 VPN/堡垒机访问,不直接暴露。",
    },
    {
        "id": "OWASP-VERSION-001",
        "name": "不应泄露服务/应用版本号",
        "severity": LOW,
        "advice": "关闭 Server banner、ServerTokens、server_tokens。",
    },
]

# 端口分组(用于规则匹配)
TELNET_PORTS = {23, 513, 514}
DB_PORTS = {3306, 5432, 6379, 11211, 27017, 1521, 9200, 9300, 1433}
FILE_LEAK_PATHS = ("/.git", "/.env", "/backup", "/dump", "/.htaccess", "/.ssh", "/.aws", "/phpinfo")
ADMIN_PATHS = ("/admin", "/administrator", "/wp-admin", "/wp-login", "/phpmyadmin", "/console")
SMB_RDP_PORTS = {445, 3389}


def check_compliance(host_result: HostResult) -> dict:
    """对单台主机的审计结果做合规评估。

    返回:
      {score: 0-100, total_rules, failed: [], passed: [], rule_results: [{rule, status, ...}]}
    """
    rule_results = []

    for rule in COMPLIANCE_RULES:
        violated, evidence = _evaluate_rule(rule, host_result)
        rule_results.append({
            "id": rule["id"],
            "name": rule["name"],
            "severity": rule["severity"],
            "status": "fail" if violated else "pass",
            "advice": rule["advice"] if violated else "",
            "evidence": evidence,
        })

    failed = [r for r in rule_results if r["status"] == "fail"]
    passed = [r for r in rule_results if r["status"] == "pass"]
    total = len(COMPLIANCE_RULES)
    # 合规得分 = 通过规则数 / 总规则数 * 100,违规严重度做扣分
    base_score = (len(passed) / total) * 100 if total else 0
    # 每条违规按严重度扣分,最低 0
    penalty = 0
    for f in failed:
        penalty += SEVERITY_WEIGHT.get(f["severity"], 20) * 0.2
    score = max(0.0, base_score - penalty)

    return {
        "score": round(score, 1),
        "total_rules": total,
        "passed_count": len(passed),
        "failed_count": len(failed),
        "rule_results": rule_results,
    }


def _evaluate_rule(rule: dict, hr: HostResult):
    """评估单条规则是否被违反,返回 (是否违反, 证据字符串)。"""
    rid = rule["id"]

    if rid == "CIS-NET-001":
        bad_ports = [p for p in hr.ports if p["port"] in TELNET_PORTS]
        if bad_ports:
            return True, f"开放端口: {', '.join(str(p['port']) for p in bad_ports)}"
        return False, ""

    if rid == "CIS-NET-002":
        bad_ports = [p for p in hr.ports if p["port"] in DB_PORTS]
        if bad_ports:
            return True, f"数据库端口暴露: {', '.join(str(p['port']) for p in bad_ports)}"
        return False, ""

    if rid == "CIS-PORT-001":
        bad_ports = [p for p in hr.ports if p["port"] in SMB_RDP_PORTS]
        if bad_ports:
            return True, f"SMB/RDP 端口暴露: {', '.join(str(p['port']) for p in bad_ports)}"
        return False, ""

    if rid in ("OWASP-CRYPTO-001", "OWASP-CRYPTO-002"):
        if not hr.ssl_info or hr.ssl_info.get("error"):
            return False, "未启用 HTTPS 或无法检查(本规则不适用)"
        protocols = hr.ssl_info.get("protocols", {})
        if rid == "OWASP-CRYPTO-001":
            weak_on = [k for k, v in protocols.items() if v and k in ("TLSv1", "TLSv1.1", "SSLv3")]
            if weak_on:
                return True, f"启用弱协议: {', '.join(weak_on)}"
            return False, ""
        # 证书过期/自签名
        cert = hr.ssl_info.get("cert") or {}
        issues = []
        if cert.get("self_signed"):
            issues.append("自签名证书")
        # 过期
        for f in hr.findings:
            if f.module == "ssl" and "证书已过期" in f.title:
                issues.append("证书已过期")
        if issues:
            return True, "; ".join(issues)
        return False, ""

    if rid == "OWASP-HEADER-001":
        web = hr.web_info or {}
        if web.get("error"):
            return False, "Web 服务不可达(本规则不适用)"
        missing = [m for m in web.get("missing_headers", []) if m["header"] == "strict-transport-security"]
        if missing:
            return True, "缺失 HSTS 头"
        return False, ""

    if rid == "OWASP-HEADER-002":
        web = hr.web_info or {}
        if web.get("error"):
            return False, "Web 服务不可达(本规则不适用)"
        missing = [m for m in web.get("missing_headers", []) if m["header"] == "content-security-policy"]
        if missing:
            return True, "缺失 CSP 头"
        return False, ""

    if rid == "OWASP-EXPOSE-001":
        web = hr.web_info or {}
        sensitive = [
            s for s in web.get("sensitive_paths", [])
            if any(s["path"].startswith(p) for p in FILE_LEAK_PATHS)
        ]
        if sensitive:
            return True, f"敏感文件暴露: {', '.join(s['path'] for s in sensitive)}"
        return False, ""

    if rid == "OWASP-EXPOSE-002":
        web = hr.web_info or {}
        if web.get("error"):
            return False, "Web 服务不可达(本规则不适用)"
        sensitive = [
            s for s in web.get("sensitive_paths", [])
            if any(s["path"].startswith(p) for p in ADMIN_PATHS)
        ]
        if sensitive:
            return True, f"管理路径可访问: {', '.join(s['path'] for s in sensitive)}"
        return False, ""

    if rid == "OWASP-VERSION-001":
        # 检查 findings 是否有版本泄露
        version_findings = [f for f in hr.findings if f.module in ("port", "web") and ("版本" in f.title or "Server" in f.title or "banner" in f.title)]
        if version_findings:
            return True, "; ".join(f.title for f in version_findings)
        return False, ""

    return False, ""


def to_findings(host: str, compliance: dict) -> List[Finding]:
    """将合规违规项转为审计发现(用于报告展示)。"""
    findings: List[Finding] = []
    for r in compliance.get("rule_results", []):
        if r["status"] == "fail":
            findings.append(
                Finding(
                    module="compliance",
                    severity=r["severity"],
                    title=f"{host}: 合规违规 {r['id']}",
                    detail=r["name"],
                    evidence=r.get("evidence", ""),
                    recommendation=r.get("advice", ""),
                )
            )
    if not findings:
        findings.append(
            Finding(
                module="compliance",
                severity=INFO,
                title=f"{host}: 合规检查全部通过",
                detail=f"合规得分 {compliance.get('score', 100)}/100,共 {compliance.get('total_rules', 0)} 条规则。",
            )
        )
    return findings
