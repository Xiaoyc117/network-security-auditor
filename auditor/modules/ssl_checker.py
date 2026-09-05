"""SSL/TLS 证书检查: 证书有效性、协议版本、弱加密。"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import List, Optional

from ..utils import Finding, HIGH, INFO, LOW, MEDIUM

# 历史上不安全的协议(名称用于结果展示)
WEAK_PROTOCOL_NAMES = {
    "SSLv3": "SSLv3 已知存在 POODLE 攻击漏洞",
    "TLSv1": "TLS 1.0 已被废弃,存在 BEAST 等攻击风险",
    "TLSv1.1": "TLS 1.1 已被废弃,不满足现代合规要求",
}

# 弱加密套件关键词
WEAK_CIPHER_KEYWORDS = ("RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon", "CBC")


def check_ssl(host: str, port: int = 443, timeout: float = 5.0) -> dict:
    """检查目标的 SSL/TLS 配置,返回结果字典。

    返回结构:
      - cert: dict 或 None(notBefore/notAfter/subject/issuer/self_signed)
      - protocols: dict {协议名: 是否启用}
      - weak_ciphers: List[str]
      - error: str (失败时)
    """
    result = {
        "host": host,
        "port": port,
        "cert": None,
        "protocols": {},
        "weak_ciphers": [],
        "error": "",
    }

    # 1. 获取证书信息(不验证,以便拿到自签名证书)
    try:
        cert_info = _get_cert_info(host, port, timeout)
        result["cert"] = cert_info
    except Exception as e:
        result["error"] = f"无法获取证书: {e}"
        # 没有证书则协议探测意义不大,直接返回
        return result

    # 2. 探测各 TLS 协议版本支持
    result["protocols"] = _probe_protocols(host, port, timeout)

    # 3. 探测弱加密套件
    result["weak_ciphers"] = _probe_weak_ciphers(host, port, timeout)

    return result


def _get_cert_info(host: str, port: int, timeout: float) -> dict:
    """获取证书详情(不验证信任链,以便识别自签名证书)。"""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert_der = ssock.getpeercert(binary_form=True)
            cert_dict = ssock.getpeercert()
            negotiated_cipher = ssock.cipher()
            negotiated_version = ssock.version()

    # 用 ssl 模块解析 DER 证书获取结构化字段
    parsed = {}
    if cert_der:
        try:
            parsed = _parse_der_cert(cert_der)
        except Exception:
            parsed = {}

    not_before = parsed.get("notBefore", "")
    not_after = parsed.get("notAfter", "")
    subject = parsed.get("subject", cert_dict.get("subject", "") if cert_dict else "")
    issuer = parsed.get("issuer", cert_dict.get("issuer", "") if cert_dict else "")
    san = parsed.get("san", [])
    self_signed = bool(subject and issuer and _normalize_dn(subject) == _normalize_dn(issuer))

    return {
        "subject": _format_dn(subject) if subject else "",
        "issuer": _format_dn(issuer) if issuer else "",
        "not_before": not_before,
        "not_after": not_after,
        "san": san,
        "self_signed": self_signed,
        "negotiated_cipher": negotiated_cipher[0] if negotiated_cipher else "",
        "negotiated_version": negotiated_version or "",
    }


def _parse_der_cert(cert_der: bytes) -> dict:
    """解析 DER 证书为字段字典。

    为避免引入 cryptography 依赖,优先尝试用标准库的 ssl 模块间接解析;
    若失败则返回空结构,后续报告仍可展示 getpeercert 拿到的信息。
    """
    # 优先利用 openssl 命令? 不行(跨平台问题)。改为尝试 cryptography 可选导入。
    try:
        from cryptography import x509  # type: ignore
        from cryptography.hazmat.backends import default_backend
        cert = x509.load_der_x509_certificate(cert_der, default_backend())
        subject = cert.subject
        issuer = cert.issuer
        return {
            "subject": [(attr.oid._name, attr.value) for attr in subject] if hasattr(subject, "__iter__") else str(subject),
            "issuer": [(attr.oid._name, attr.value) for attr in issuer] if hasattr(issuer, "__iter__") else str(issuer),
            "not_before": cert.not_valid_before.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "not_after": cert.not_valid_after.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "san": _extract_san(cert),
        }
    except ImportError:
        # cryptography 不可用时退回基础解析
        return {}


def _extract_san(cert) -> List[str]:
    """提取证书 SAN(Subject Alternative Names)。"""
    try:
        from cryptography import x509  # type: ignore
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            return ext.value.get_values_for_type(x509.DNSName)
        except Exception:
            return []
    except ImportError:
        return []


def _normalize_dn(dn) -> str:
    """规范化 DN 字符串用于比较(判断自签名)。"""
    if isinstance(dn, list):
        return str(sorted([(t, v) for t, v in dn]))
    return str(dn)


def _format_dn(dn) -> str:
    """格式化 DN 为可读字符串。"""
    if isinstance(dn, list):
        return ", ".join(f"{t}={v}" for t, v in dn)
    return str(dn)


def _probe_protocols(host: str, port: int, timeout: float) -> dict:
    """探测支持的 TLS 协议版本。"""
    protocols_to_test = [
        ("SSLv3", _get_proto_constant("SSLv3")),
        ("TLSv1", _get_proto_constant("TLSv1")),
        ("TLSv1.1", _get_proto_constant("TLSv1.1")),
        ("TLSv1.2", _get_proto_constant("TLSv1.2")),
        ("TLSv1.3", _get_proto_constant("TLSv1.3")),
    ]
    result = {}
    for name, proto in protocols_to_test:
        if proto is None:
            # 该版本被本机 ssl 模块禁用(如 SSLv3),视为不支持
            result[name] = False
            continue
        result[name] = _try_protocol(host, port, proto, timeout)
    return result


def _get_proto_constant(name: str):
    """安全获取 TLSVersion 常量,不存在返回 None。"""
    if not hasattr(ssl, "TLSVersion"):
        return None
    mapping = {
        "SSLv3": getattr(ssl.TLSVersion, "MINIMUM_SUPPORTED", None),
        "TLSv1": ssl.TLSVersion.TLSv1,
        "TLSv1.1": ssl.TLSVersion.TLSv1_1,
        "TLSv1.2": ssl.TLSVersion.TLSv1_2,
        "TLSv1.3": getattr(ssl.TLSVersion, "TLSv1_3", None),
    }
    if name == "SSLv3":
        # 显式禁用测试 SSLv3
        return None
    return mapping.get(name)


def _try_protocol(host: str, port: int, proto, timeout: float) -> bool:
    """尝试用指定最低/最高协议版本握手。"""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = proto
        ctx.maximum_version = proto
    except (ValueError, AttributeError):
        return False
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except (ssl.SSLError, socket.error, OSError, ValueError):
        return False


def _probe_weak_ciphers(host: str, port: int, timeout: float) -> List[str]:
    """探测弱加密套件:通过协商出的 cipher 名粗略判断。"""
    weak_found = []
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")  # 允许弱算法以便探测
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cipher = ssock.cipher()
                if cipher:
                    cipher_name = cipher[0]
                    for kw in WEAK_CIPHER_KEYWORDS:
                        if kw.lower() in cipher_name.lower():
                            weak_found.append(cipher_name)
                            break
    except (ssl.SSLError, socket.error, OSError):
        pass
    return weak_found


def to_findings(host: str, ssl_info: Optional[dict]) -> List[Finding]:
    """将 SSL 检查结果转换为审计发现。"""
    if not ssl_info:
        return []

    findings: List[Finding] = []

    if ssl_info.get("error"):
        findings.append(
            Finding(
                module="ssl",
                severity=LOW,
                title=f"{host}: 无法获取 SSL 证书",
                detail=ssl_info["error"],
                recommendation="确认端口开放 HTTPS 服务;若为 HTTP 明文服务应迁移到 HTTPS。",
            )
        )
        return findings

    cert = ssl_info.get("cert") or {}
    protocols = ssl_info.get("protocols", {})
    weak_ciphers = ssl_info.get("weak_ciphers", [])

    # 弱协议启用
    for proto_name, enabled in protocols.items():
        if enabled and proto_name in WEAK_PROTOCOL_NAMES:
            findings.append(
                Finding(
                    module="ssl",
                    severity=HIGH,
                    title=f"{host}: 启用了弱协议 {proto_name}",
                    detail=WEAK_PROTOCOL_NAMES[proto_name],
                    recommendation=f"禁用 {proto_name},仅保留 TLS 1.2 / 1.3。",
                )
            )

    # 弱加密套件
    for cipher in weak_ciphers:
        findings.append(
            Finding(
                module="ssl",
                severity=MEDIUM,
                title=f"{host}: 协商到弱加密套件 {cipher}",
                detail="该套件包含 RC4/DES/CBC 等已不安全的算法。",
                recommendation="更新加密套件配置,优先使用 AEAD 算法(AES-GCM/ChaCha20-Poly1305)。",
            )
        )

    # 证书过期检查
    not_after = cert.get("not_after", "")
    if not_after:
        try:
            exp_dt = datetime.strptime(not_after, "%Y-%m-%d %H:%M:%S UTC").replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            days_left = (exp_dt - now).days
            if days_left < 0:
                findings.append(
                    Finding(
                        module="ssl",
                        severity=HIGH,
                        title=f"{host}: 证书已过期 {abs(days_left)} 天",
                        detail=f"证书有效期至 {not_after}。",
                        evidence=f"issuer={cert.get('issuer','')}",
                        recommendation="立即续期证书并部署。",
                    )
                )
            elif days_left < 30:
                findings.append(
                    Finding(
                        module="ssl",
                        severity=MEDIUM,
                        title=f"{host}: 证书将在 {days_left} 天后过期",
                        detail=f"证书有效期至 {not_after}。",
                        recommendation="提前续期证书,避免服务中断。",
                    )
                )
            else:
                findings.append(
                    Finding(
                        module="ssl",
                        severity=INFO,
                        title=f"{host}: 证书有效,剩余 {days_left} 天",
                        detail=f"颁发者: {cert.get('issuer','')}",
                    )
                )
        except ValueError:
            pass

    # 自签名证书
    if cert.get("self_signed"):
        findings.append(
            Finding(
                module="ssl",
                severity=MEDIUM,
                title=f"{host}: 使用自签名证书",
                detail="自签名证书无法被客户端自动信任,易被中间人攻击替代。",
                recommendation="使用受信任 CA 签发的证书(如 Let's Encrypt)。",
            )
        )

    # SAN 主机名匹配
    san = cert.get("san", [])
    if san and host not in san and not any(host.endswith(s.replace("*.", "")) for s in san):
        findings.append(
            Finding(
                module="ssl",
                severity=MEDIUM,
                title=f"{host}: 证书 SAN 不匹配目标主机",
                detail=f"证书 SAN: {', '.join(san)}",
                recommendation="签发包含正确主机名的证书。",
            )
        )

    if not findings:
        findings.append(
            Finding(
                module="ssl",
                severity=INFO,
                title=f"{host}: SSL/TLS 配置正常",
                detail="未发现弱协议、过期证书或自签名问题。",
            )
        )

    return findings
