"""Web 安全检测: 安全头、敏感路径、目录列出、版本泄露。"""

from __future__ import annotations

import socket
import urllib.error
import urllib.request
from typing import Dict, List, Optional, Tuple

from ..utils import Finding, HIGH, INFO, LOW, MEDIUM

# 必备安全响应头
SECURITY_HEADERS = {
    "strict-transport-security": {
        "label": "HSTS",
        "severity_missing": MEDIUM,
        "desc": "缺失 HSTS 头,站点可能遭受 SSL Strip 降级攻击。",
        "fix": "添加 'Strict-Transport-Security: max-age=31536000; includeSubDomains'。",
    },
    "content-security-policy": {
        "label": "CSP",
        "severity_missing": MEDIUM,
        "desc": "缺失 CSP 头,无法有效防御 XSS/数据注入攻击。",
        "fix": "配置严格的 Content-Security-Policy,限制脚本来源。",
    },
    "x-frame-options": {
        "label": "X-Frame-Options",
        "severity_missing": LOW,
        "desc": "缺失 X-Frame-Options,可能被点击劫持(clickjacking)。",
        "fix": "添加 'X-Frame-Options: SAMEORIGIN' 或使用 CSP frame-ancestors。",
    },
    "x-content-type-options": {
        "label": "X-Content-Type-Options",
        "severity_missing": LOW,
        "desc": "缺失 nosniff,浏览器可能进行 MIME 嗅探导致 XSS。",
        "fix": "添加 'X-Content-Type-Options: nosniff'。",
    },
    "x-xss-protection": {
        "label": "X-XSS-Protection",
        "severity_missing": LOW,
        "desc": "缺失 X-XSS-Protection(旧版浏览器需此头防护反射型 XSS)。",
        "fix": "添加 'X-XSS-Protection: 1; mode=block'。",
    },
    "referrer-policy": {
        "label": "Referrer-Policy",
        "severity_missing": INFO,
        "desc": "未配置 Referrer-Policy,可能泄露完整 URL 到第三方。",
        "fix": "添加 'Referrer-Policy: strict-origin-when-cross-origin'。",
    },
    "permissions-policy": {
        "label": "Permissions-Policy",
        "severity_missing": INFO,
        "desc": "未配置 Permissions-Policy,浏览器特性未受限。",
        "fix": "按需配置 Permissions-Policy 限制摄像头/麦克风/地理位置等。",
    },
}

# 敏感路径探测列表(仅 GET 判断状态码,不利用)
SENSITIVE_PATHS = [
    "/robots.txt",
    "/.git/HEAD",
    "/.git/config",
    "/.env",
    "/.svn/entries",
    "/.DS_Store",
    "/admin/",
    "/administrator/",
    "/phpmyadmin/",
    "/wp-admin/",
    "/wp-login.php",
    "/backup.sql",
    "/backup.zip",
    "/dump.sql",
    "/config.php.bak",
    "/.htaccess",
    "/server-status",
    "/phpinfo.php",
    "/.well-known/security.txt",
    "/swagger-ui/",
    "/api-docs",
    "/actuator/health",
    "/actuator/env",
    "/console/",
    "/.aws/credentials",
    "/.ssh/id_rsa",
]

USER_AGENT = "Mozilla/5.0 (compatible; NetworkSecurityAuditor/1.0)"
TIMEOUT = 6.0


def audit_web(host: str, port: int = 80, use_https: Optional[bool] = None) -> dict:
    """对目标主机的 Web 服务做安全检测。

    Args:
        host: 主机名/IP
        port: 端口
        use_https: 是否用 HTTPS,None 表示自动探测

    Returns:
        dict {scheme, url, status_code, headers, server, missing_headers,
             sensitive_paths, directory_listing, error}
    """
    result = {
        "host": host,
        "port": port,
        "scheme": "",
        "url": "",
        "status_code": 0,
        "headers": {},
        "server": "",
        "missing_headers": [],
        "sensitive_paths": [],
        "directory_listing": False,
        "error": "",
    }

    # 自动决定协议
    if use_https is None:
        use_https = port == 443
    scheme = "https" if use_https else "http"
    base_url = f"{scheme}://{host}:{port}" if port not in (80, 443) else f"{scheme}://{host}"
    result["scheme"] = scheme
    result["url"] = base_url

    # 1. 获取首页响应与响应头
    headers, status, err = _fetch(base_url, method="GET")
    if err:
        result["error"] = err
        # 尝试另一种协议
        if use_https or use_https is None:
            alt_scheme = "http" if scheme == "https" else "https"
            alt_url = f"{alt_scheme}://{host}" + (f":{port}" if port not in (80, 443) else "")
            headers, status, err2 = _fetch(alt_url, method="GET")
            if not err2:
                result["scheme"] = alt_scheme
                result["url"] = alt_url
                result["error"] = ""
        if result["error"]:
            return result

    result["status_code"] = status
    result["headers"] = headers
    result["server"] = headers.get("Server", "") or headers.get("server", "")

    # 2. 检查安全头缺失
    result["missing_headers"] = _check_security_headers(headers)

    # 3. 探测敏感路径
    result["sensitive_paths"] = _probe_sensitive_paths(base_url)

    # 4. 目录列出检测
    result["directory_listing"] = _detect_directory_listing(headers, base_url)

    return result


def _fetch(url: str, method: str = "GET", allow_redirects: bool = False) -> Tuple[dict, int, str]:
    """发起 HTTP 请求,返回 (响应头字典, 状态码, 错误信息)。"""
    req = urllib.request.Request(url, method=method, headers={"User-Agent": USER_AGENT})
    try:
        # urllib 默认跟随重定向;禁用需要自定义 opener
        opener = urllib.request.build_opener(_NoRedirectHandler) if not allow_redirects else urllib.request.build_opener()
        resp = opener.open(req, timeout=TIMEOUT)
        headers = {k.lower(): v for k, v in resp.headers.items()}
        body = b""
        try:
            body = resp.read(4096)
        except Exception:
            pass
        return headers, resp.status, ""
    except urllib.error.HTTPError as e:
        # HTTP 错误码(如 403/404)仍返回头和状态
        headers = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
        return headers, e.code, ""
    except (urllib.error.URLError, socket.timeout, OSError, ConnectionError) as e:
        return {}, 0, f"{type(e).__name__}: {e}"
    except Exception as e:
        return {}, 0, f"{type(e).__name__}: {e}"


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """禁用自动重定向以便识别 301/302。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _check_security_headers(headers: dict) -> List[dict]:
    """检查缺失的安全头,返回缺失项列表。"""
    missing = []
    for name, spec in SECURITY_HEADERS.items():
        if name not in headers:
            missing.append({
                "header": name,
                "label": spec["label"],
                "severity": spec["severity_missing"],
                "desc": spec["desc"],
                "fix": spec["fix"],
            })
    return missing


def _probe_sensitive_paths(base_url: str) -> List[dict]:
    """探测常见敏感路径,记录存在(200/403)或暴露内容的路径。"""
    found = []
    for path in SENSITIVE_PATHS:
        url = base_url.rstrip("/") + path
        headers, status, err = _fetch(url, method="GET")
        if err:
            continue
        # 200 表示资源存在; 403 表示存在但禁止访问; 401 需认证
        if status in (200, 403, 401):
            sensitive = _is_path_sensitive(path, status, headers)
            if sensitive:
                found.append({
                    "path": path,
                    "status": status,
                    "note": sensitive,
                })
    return found


def _is_path_sensitive(path: str, status: int, headers: dict) -> str:
    """判断该路径是否构成安全问题,返回说明字符串(空字符串表示忽略)。"""
    # .git/.svn 暴露 = 高危
    if path.startswith("/.git") or path.startswith("/.svn"):
        if status == 200:
            return "版本控制目录可访问,可能泄露源代码!"
    if path == "/.env" and status == 200:
        return ".env 文件可访问,可能泄露应用密钥和数据库凭据!"
    if path in ("/backup.sql", "/backup.zip", "/dump.sql") and status == 200:
        return "备份文件可下载,泄露数据库或源代码!"
    if path in ("/.ssh/id_rsa", "/.aws/credentials") and status == 200:
        return "凭据文件可访问,泄露私密密钥!"
    if path == "/server-status" and status == 200:
        return "Apache server-status 暴露,泄露运行状态和请求历史!"
    if path == "/phpinfo.php" and status == 200:
        return "phpinfo 暴露,泄露完整 PHP 配置和环境!"
    if path == "/actuator/env" and status == 200:
        return "Spring Boot actuator/env 暴露,泄露环境变量和密钥!"
    if path in ("/admin/", "/administrator/", "/wp-admin/", "/wp-login.php", "/phpmyadmin/", "/console/"):
        if status in (200, 401):
            return "管理后台路径可访问,应限制访问来源并强化认证。"
    if path == "/.htaccess" and status == 200:
        return ".htaccess 文件可访问,可能泄露重写规则和访问控制!"
    if path in ("/swagger-ui/", "/api-docs") and status == 200:
        return "API 文档暴露,攻击者可据此构造攻击请求。"
    return ""


def _detect_directory_listing(headers: dict, base_url: str) -> bool:
    """检测目录列出:通过响应体或 Server 头粗略判断。"""
    # 简化判断:请求一个不存在的目录,若返回 HTML 含 "Index of" 视为目录列出开启
    test_url = base_url.rstrip("/") + "/nonexistent_audit_dir_12345/"
    headers, status, err = _fetch(test_url, method="GET")
    if err or status not in (200, 403, 404):
        return False
    if status == 200:
        # 进一步获取响应体验证 "Index of"
        req = urllib.request.Request(test_url, headers={"User-Agent": USER_AGENT})
        try:
            opener = urllib.request.build_opener()
            resp = opener.open(req, timeout=TIMEOUT)
            body = resp.read(2048).decode("utf-8", errors="ignore").lower()
            if "index of" in body or "directory listing" in body:
                return True
        except Exception:
            pass
    return False


def to_findings(host: str, web_info: Optional[dict]) -> List[Finding]:
    """将 Web 检测结果转换为审计发现。"""
    if not web_info:
        return []

    findings: List[Finding] = []

    if web_info.get("error"):
        findings.append(
            Finding(
                module="web",
                severity=INFO,
                title=f"{host}: Web 服务不可达",
                detail=web_info["error"],
                recommendation="确认 Web 服务端口开放且协议正确。",
            )
        )
        return findings

    url = web_info.get("url", host)
    server = web_info.get("server", "")

    # 服务器版本泄露
    if server:
        # 包含版本号特征
        if any(ch.isdigit() for ch in server):
            findings.append(
                Finding(
                    module="web",
                    severity=LOW,
                    title=f"{host}: Server 头泄露版本信息",
                    detail=f"Server: {server}",
                    evidence=f"URL={url}",
                    recommendation="隐藏 Server 头或去除版本号(Apache: ServerTokens Prod;Nginx: server_tokens off)。",
                )
            )

    # 缺失安全头
    for item in web_info.get("missing_headers", []):
        findings.append(
            Finding(
                module="web",
                severity=item["severity"],
                title=f"{host}: 缺失安全头 {item['label']}",
                detail=item["desc"],
                evidence=f"URL={url}",
                recommendation=item["fix"],
            )
        )

    # 敏感路径暴露
    for item in web_info.get("sensitive_paths", []):
        sev = HIGH if any(kw in item["note"] for kw in ("源代码", "密钥", "凭据", "server-status", "phpinfo", "actuator/env", "备份")) else MEDIUM
        findings.append(
            Finding(
                module="web",
                severity=sev,
                title=f"{host}: 敏感路径 {item['path']} 可访问 (HTTP {item['status']})",
                detail=item["note"],
                evidence=f"URL={url}{item['path']}",
                recommendation="删除该文件/目录,或配置 Web 服务器禁止访问;敏感路径加访问控制。",
            )
        )

    # 目录列出
    if web_info.get("directory_listing"):
        findings.append(
            Finding(
                module="web",
                severity=MEDIUM,
                title=f"{host}: 目录列出开启",
                detail="Web 服务器对请求目录返回 Index of,可能泄露目录结构和文件列表。",
                evidence=f"URL={url}",
                recommendation="关闭目录列出(Apache: Options -Indexes;Nginx: autoindex off)。",
            )
        )

    if not findings:
        findings.append(
            Finding(
                module="web",
                severity=INFO,
                title=f"{host}: Web 安全头配置良好",
                detail="未发现缺失的关键安全头、敏感路径或目录列出。",
            )
        )

    return findings
