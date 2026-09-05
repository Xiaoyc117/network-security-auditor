"""HTML 报告生成: 单文件,内嵌 CSS,可视化展示审计结果。"""

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
    SEVERITY_COLOR,
    SEVERITY_LABEL,
    SEVERITY_ORDER,
    html_escape,
    now_str,
    severity_rank,
    sort_findings,
)

CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
       background: #f5f6fa; color: #2c3e50; line-height: 1.6; padding: 20px; }
.container { max-width: 1200px; margin: 0 auto; }
header { background: linear-gradient(135deg, #2c3e50, #34495e); color: white;
         padding: 30px 40px; border-radius: 12px; margin-bottom: 24px;
         box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
header h1 { font-size: 28px; margin-bottom: 8px; }
header .subtitle { opacity: 0.85; font-size: 14px; }
.summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
           gap: 16px; margin-bottom: 24px; }
.stat-card { background: white; padding: 20px; border-radius: 10px;
             box-shadow: 0 2px 8px rgba(0,0,0,0.06); text-align: center;
             border-left: 4px solid #3498db; }
.stat-card .num { font-size: 32px; font-weight: 700; }
.stat-card .label { font-size: 13px; color: #7f8c8d; margin-top: 4px; }
.stat-card.critical { border-left-color: #c0392b; }
.stat-card.critical .num { color: #c0392b; }
.stat-card.high { border-left-color: #e74c3c; }
.stat-card.high .num { color: #e74c3c; }
.stat-card.medium { border-left-color: #f39c12; }
.stat-card.medium .num { color: #f39c12; }
.stat-card.low { border-left-color: #f1c40f; }
.stat-card.low .num { color: #f39c12; }
.host-card { background: white; border-radius: 10px; margin-bottom: 20px;
             overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.06); }
.host-header { padding: 16px 24px; background: #ecf0f1; border-bottom: 1px solid #e0e0e0;
               display: flex; align-items: center; justify-content: space-between; }
.host-header h2 { font-size: 18px; color: #2c3e50; }
.host-header .compliance { font-size: 13px; font-weight: 600; }
.host-body { padding: 20px 24px; }
.finding { padding: 12px 16px; margin-bottom: 10px; border-radius: 6px;
           border-left: 4px solid #ccc; background: #fafbfc; }
.finding.critical { border-left-color: #c0392b; background: #fdecea; }
.finding.high { border-left-color: #e74c3c; background: #fdecea; }
.finding.medium { border-left-color: #f39c12; background: #fef5e7; }
.finding.low { border-left-color: #f1c40f; background: #fefcf3; }
.finding.info { border-left-color: #95a5a6; background: #f4f6f7; }
.finding-title { font-weight: 600; margin-bottom: 4px; display: flex; align-items: center; gap: 8px; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 10px;
         font-size: 11px; font-weight: 600; color: white; }
.finding-detail { font-size: 13px; color: #5d6d7e; margin-top: 4px; }
.finding-evidence { font-size: 12px; color: #7f8c8d; margin-top: 4px;
                    font-family: Consolas, Monaco, monospace; background: #f0f0f0;
                    padding: 6px 10px; border-radius: 4px; word-break: break-all; }
.finding-rec { font-size: 13px; color: #1e8449; margin-top: 6px; }
.finding-rec::before { content: "▸ 修复建议: "; font-weight: 600; }
table { width: 100%; border-collapse: collapse; margin: 12px 0; font-size: 13px; }
th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid #ecf0f1; }
th { background: #f8f9fa; font-weight: 600; color: #2c3e50; }
tr:hover { background: #f8f9fa; }
.section-title { font-size: 15px; font-weight: 600; color: #2c3e50;
                 margin: 20px 0 10px; padding-bottom: 6px; border-bottom: 2px solid #ecf0f1; }
.compliance-table td.pass { color: #27ae60; font-weight: 600; }
.compliance-table td.fail { color: #c0392b; font-weight: 600; }
.compliance-score { font-size: 24px; font-weight: 700; }
.score-bar { background: #ecf0f1; border-radius: 10px; height: 10px; margin: 8px 0; overflow: hidden; }
.score-bar-fill { height: 100%; background: linear-gradient(90deg, #e74c3c, #f1c40f, #27ae60); }
footer { text-align: center; color: #95a5a6; font-size: 12px; margin-top: 30px; padding: 20px; }
.disclaimer { background: #fef9e7; border: 1px solid #f9e79f; padding: 12px 16px;
              border-radius: 6px; margin-bottom: 20px; font-size: 13px; color: #7d6608; }
"""


def generate_report(host_results: List[HostResult], output_path: str, target_info: str = "") -> str:
    """生成 HTML 报告到指定路径,返回输出路径。"""
    total_counts = {s: 0 for s in SEVERITY_ORDER}
    total_hosts = len(host_results)
    for hr in host_results:
        for sev, n in hr.severity_counts.items():
            total_counts[sev] = total_counts.get(sev, 0) + n

    html_parts: List[str] = []
    html_parts.append(f"<!DOCTYPE html><html lang='zh-CN'><head><meta charset='UTF-8'>")
    html_parts.append(f"<meta name='viewport' content='width=device-width, initial-scale=1.0'>")
    html_parts.append(f"<title>网络安全审计报告</title>")
    html_parts.append(f"<style>{CSS}</style></head><body>")
    html_parts.append(f"<div class='container'>")

    # 头部
    html_parts.append(
        f"<header><h1>网络安全审计报告</h1>"
        f"<div class='subtitle'>生成时间: {html_escape(now_str())} · 目标: {html_escape(target_info or '未指定')}</div>"
        f"</header>"
    )

    # 免责声明
    html_parts.append(
        f"<div class='disclaimer'>本报告由自动化工具生成,仅供授权安全审计参考。"
        f"所有发现需人工复核后再决定处置方式,使用本工具需遵守当地法律法规。</div>"
    )

    # 摘要卡片
    html_parts.append(f"<div class='summary'>")
    html_parts.append(
        f"<div class='stat-card'><div class='num'>{total_hosts}</div><div class='label'>审计主机数</div></div>"
    )
    for sev in (CRITICAL, HIGH, MEDIUM, LOW, INFO):
        css_class = sev
        html_parts.append(
            f"<div class='stat-card {css_class}'><div class='num'>{total_counts.get(sev, 0)}</div>"
            f"<div class='label'>{SEVERITY_LABEL[sev]}发现</div></div>"
        )
    html_parts.append(f"</div>")

    # 每主机详情
    for hr in host_results:
        html_parts.append(_render_host_card(hr))

    # 页脚
    html_parts.append(
        f"<footer>由自动化网络安全审计工具 v1.0 生成 · {html_escape(now_str())}<br>"
        f"仅限授权审计使用 · 数据来源于被动检测,未实施破坏性操作</footer>"
    )
    html_parts.append(f"</div></body></html>")

    html = "\n".join(html_parts)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    return output_path


def _render_host_card(hr: HostResult) -> str:
    """渲染单主机卡片。"""
    parts: List[str] = []
    parts.append(f"<div class='host-card'>")

    # 主机头部 + 合规得分
    score_text = ""
    if hr.compliance_info:
        score = hr.compliance_info.get("score", 100)
        color = "#27ae60" if score >= 80 else ("#f39c12" if score >= 60 else "#c0392b")
        score_text = f"<span class='compliance' style='color:{color}'>合规得分: {score}/100</span>"
    parts.append(
        f"<div class='host-header'><h2>主机: {html_escape(hr.host)} "
        f"<span style='font-size:13px;font-weight:400;color:#7f8c8d'>"
        f"{html_escape(hr.ip) if hr.ip and hr.ip != hr.host else ''}</span></h2>{score_text}</div>"
    )

    parts.append(f"<div class='host-body'>")

    # 端口表
    if hr.ports:
        parts.append(f"<div class='section-title'>开放端口 ({len(hr.ports)})</div>")
        parts.append(f"<table><thead><tr><th>端口</th><th>服务</th><th>Banner</th></tr></thead><tbody>")
        for p in hr.ports:
            parts.append(
                f"<tr><td>{p['port']}</td><td>{html_escape(p.get('service',''))}</td>"
                f"<td><code>{html_escape(p.get('banner','') or '-')}</code></td></tr>"
            )
        parts.append(f"</tbody></table>")

    # SSL 详情
    if hr.ssl_info:
        parts.append(f"<div class='section-title'>SSL/TLS 详情</div>")
        parts.append(_render_ssl_section(hr.ssl_info))

    # Web 详情
    if hr.web_info:
        parts.append(f"<div class='section-title'>Web 安全详情</div>")
        parts.append(_render_web_section(hr.web_info))

    # 合规详情
    if hr.compliance_info:
        parts.append(f"<div class='section-title'>合规检查</div>")
        parts.append(_render_compliance_section(hr.compliance_info))

    # 审计发现(按严重度排序)
    if hr.findings:
        parts.append(f"<div class='section-title'>审计发现 ({len(hr.findings)})</div>")
        for f in sort_findings(hr.findings):
            parts.append(_render_finding(f))

    parts.append(f"</div></div>")
    return "".join(parts)


def _render_ssl_section(ssl_info: dict) -> str:
    parts: List[str] = []
    if ssl_info.get("error"):
        parts.append(f"<p style='color:#7f8c8d'>{html_escape(ssl_info['error'])}</p>")
        return "".join(parts)
    cert = ssl_info.get("cert") or {}
    parts.append(f"<table><tbody>")
    parts.append(f"<tr><th>Subject</th><td>{html_escape(cert.get('subject',''))}</td></tr>")
    parts.append(f"<tr><th>Issuer</th><td>{html_escape(cert.get('issuer',''))}</td></tr>")
    parts.append(f"<tr><th>有效期</th><td>{html_escape(cert.get('not_before',''))} ~ {html_escape(cert.get('not_after',''))}</td></tr>")
    parts.append(f"<tr><th>自签名</th><td>{'是' if cert.get('self_signed') else '否'}</td></tr>")
    san = cert.get("san", [])
    parts.append(f"<tr><th>SAN</th><td>{html_escape(', '.join(san) if san else '-')}</td></tr>")
    parts.append(f"<tr><th>协商协议</th><td>{html_escape(cert.get('negotiated_version',''))}</td></tr>")
    parts.append(f"<tr><th>协商加密套件</th><td>{html_escape(cert.get('negotiated_cipher',''))}</td></tr>")
    parts.append(f"</tbody></table>")

    # 协议支持表
    protocols = ssl_info.get("protocols", {})
    if protocols:
        parts.append(f"<table><thead><tr><th>协议版本</th><th>是否支持</th></tr></thead><tbody>")
        for name, enabled in protocols.items():
            badge = "<span class='badge' style='background:#e74c3c'>支持</span>" if enabled else "<span style='color:#27ae60'>不支持</span>"
            if enabled and name in ("SSLv3", "TLSv1", "TLSv1.1"):
                badge = "<span class='badge' style='background:#e74c3c'>支持 (弱协议)</span>"
            parts.append(f"<tr><td>{html_escape(name)}</td><td>{badge}</td></tr>")
        parts.append(f"</tbody></table>")

    weak_ciphers = ssl_info.get("weak_ciphers", [])
    if weak_ciphers:
        parts.append(f"<p style='color:#c0392b;margin-top:8px'>弱加密套件: {html_escape(', '.join(weak_ciphers))}</p>")
    return "".join(parts)


def _render_web_section(web_info: dict) -> str:
    parts: List[str] = []
    if web_info.get("error"):
        parts.append(f"<p style='color:#7f8c8d'>Web 服务不可达: {html_escape(web_info['error'])}</p>")
        return "".join(parts)
    parts.append(f"<table><tbody>")
    parts.append(f"<tr><th>URL</th><td><code>{html_escape(web_info.get('url',''))}</code></td></tr>")
    parts.append(f"<tr><th>状态码</th><td>{web_info.get('status_code', 0)}</td></tr>")
    parts.append(f"<tr><th>Server</th><td>{html_escape(web_info.get('server','') or '-')}</td></tr>")
    parts.append(f"<tr><th>目录列出</th><td>{'开启' if web_info.get('directory_listing') else '关闭'}</td></tr>")
    parts.append(f"</tbody></table>")

    # 安全头检查表
    missing = web_info.get("missing_headers", [])
    if missing:
        parts.append(f"<table><thead><tr><th>缺失安全头</th><th>风险</th></tr></thead><tbody>")
        for m in missing:
            parts.append(
                f"<tr><td>{html_escape(m['label'])}</td>"
                f"<td><span class='badge' style='background:{SEVERITY_COLOR[m['severity']]}'>{SEVERITY_LABEL[m['severity']]}</span></td></tr>"
            )
        parts.append(f"</tbody></table>")

    # 敏感路径表
    sensitive = web_info.get("sensitive_paths", [])
    if sensitive:
        parts.append(f"<table><thead><tr><th>路径</th><th>状态码</th><th>说明</th></tr></thead><tbody>")
        for s in sensitive:
            parts.append(
                f"<tr><td><code>{html_escape(s['path'])}</code></td><td>{s['status']}</td>"
                f"<td>{html_escape(s.get('note',''))}</td></tr>"
            )
        parts.append(f"</tbody></table>")
    return "".join(parts)


def _render_compliance_section(compliance: dict) -> str:
    parts: List[str] = []
    score = compliance.get("score", 100)
    color = "#27ae60" if score >= 80 else ("#f39c12" if score >= 60 else "#c0392b")
    parts.append(
        f"<div class='compliance-score' style='color:{color}'>{score}/100</div>"
        f"<div class='score-bar'><div class='score-bar-fill' style='width:{score}%'></div></div>"
        f"<p style='font-size:13px;color:#7f8c8d'>通过 {compliance.get('passed_count',0)}/{compliance.get('total_rules',0)} 条规则</p>"
    )
    parts.append(f"<table class='compliance-table'><thead><tr><th>规则 ID</th><th>规则</th><th>状态</th><th>证据</th></tr></thead><tbody>")
    for r in compliance.get("rule_results", []):
        status_cls = "pass" if r["status"] == "pass" else "fail"
        status_text = "通过" if r["status"] == "pass" else "违规"
        parts.append(
            f"<tr><td>{html_escape(r['id'])}</td><td>{html_escape(r['name'])}</td>"
            f"<td class='{status_cls}'>{status_text}</td>"
            f"<td><code>{html_escape(r.get('evidence','') or '-')}</code></td></tr>"
        )
    parts.append(f"</tbody></table>")
    return "".join(parts)


def _render_finding(f: Finding) -> str:
    color = SEVERITY_COLOR.get(f.severity, "#7f8c8d")
    parts: List[str] = []
    parts.append(f"<div class='finding {f.severity}'>")
    parts.append(
        f"<div class='finding-title'><span class='badge' style='background:{color}'>"
        f"{SEVERITY_LABEL.get(f.severity, f.severity)}</span>"
        f"<span>{html_escape(f.title)}</span>"
        f"<span style='font-size:11px;color:#95a5a6;margin-left:auto'>[{html_escape(f.module)}]</span></div>"
    )
    if f.detail:
        parts.append(f"<div class='finding-detail'>{html_escape(f.detail)}</div>")
    if f.evidence:
        parts.append(f"<div class='finding-evidence'>{html_escape(f.evidence)}</div>")
    if f.recommendation:
        parts.append(f"<div class='finding-rec'>{html_escape(f.recommendation)}</div>")
    parts.append(f"</div>")
    return "".join(parts)
