"""命令行参数解析。"""

from __future__ import annotations

import argparse
from typing import List

from .modules.port_scanner import DEFAULT_PORTS, parse_ports

ALL_MODULES = ["port", "ssl", "web", "compliance", "subdomain"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="network-security-auditor",
        description="自动化网络安全审计工具: 端口扫描 + SSL/TLS 检查 + Web 安全 + 合规检查",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "使用示例:\n"
            "  python main.py --target 192.168.1.1\n"
            "  python main.py --target example.com --modules port,ssl,subdomain\n"
            "  python main.py --cidr 192.168.1.0/24 --ports 80,443,22,3389\n"
            "  python main.py --target 10.0.0.1 --ports 1-1000 --threads 50 --output my.html\n"
            "  python main.py --target example.com --format json --output report.json\n\n"
            "声明: 仅限对自有或已获书面授权的目标使用,禁止未授权扫描。"
        ),
    )
    parser.add_argument("--target", action="append", default=[], metavar="HOST",
                        help="单个目标(IP/域名),可多次指定")
    parser.add_argument("--cidr", action="append", default=[], metavar="CIDR",
                        help="CIDR 网段,如 192.168.1.0/24,可多次指定")
    parser.add_argument("--ports", default="", metavar="PORTS",
                        help=f"自定义端口,逗号分隔,支持范围(如 80,443,1000-2000);默认 Top {len(DEFAULT_PORTS)} 常见端口")
    parser.add_argument("--modules", default="port,ssl,web,compliance,subdomain", metavar="MODS",
                        help=f"选择模块,逗号分隔: {','.join(ALL_MODULES)};默认全部")
    parser.add_argument("--output", default="audit_report.html", metavar="PATH",
                        help="报告输出路径,默认 audit_report.html")
    parser.add_argument("--format", dest="fmt", default="html", choices=["html", "json", "csv"],
                        help="报告格式: html(默认)/json/csv")
    parser.add_argument("--threads", type=int, default=10, metavar="N",
                        help="并发线程数,默认 10")
    parser.add_argument("--timeout", type=float, default=3.0, metavar="SEC",
                        help="单次连接超时秒数,默认 3.0")
    parser.add_argument("--verbose", action="store_true",
                        help="打印详细进度信息")
    return parser


def parse_args(argv: List[str] = None):
    parser = build_parser()
    args = parser.parse_args(argv)

    # 校验
    targets = list(args.target) + list(args.cidr)
    if not targets:
        parser.error("至少指定一个 --target 或 --cidr")

    ports = parse_ports(args.ports) if args.ports else DEFAULT_PORTS
    if not ports:
        ports = DEFAULT_PORTS

    selected_modules = [m.strip() for m in args.modules.split(",") if m.strip()]
    for m in selected_modules:
        if m not in ALL_MODULES:
            parser.error(f"未知模块: {m},可选: {','.join(ALL_MODULES)}")

    if args.threads < 1:
        parser.error("--threads 必须 >= 1")
    if args.timeout <= 0:
        parser.error("--timeout 必须 > 0")

    return {
        "targets": targets,
        "ports": ports,
        "modules": selected_modules,
        "output": args.output,
        "fmt": args.fmt,
        "threads": args.threads,
        "timeout": args.timeout,
        "verbose": args.verbose,
    }
