#!/usr/bin/env python3
"""自动化网络安全审计工具 - 入口。

用法:
    python main.py --target 192.168.1.1
    python main.py --cidr 192.168.1.0/24 --ports 80,443,22
    python main.py --target example.com --modules port,ssl,web --verbose

声明: 本工具仅供授权安全审计使用。使用者需确保对扫描目标具有合法授权,
并遵守当地法律法规。工具采用非破坏性检测,但仍可能触发目标 IDS/防火墙告警。
"""

from __future__ import annotations

import sys

from auditor.cli import parse_args
from auditor.core import run_audit


def main(argv=None) -> int:
    try:
        opts = parse_args(argv)
    except SystemExit as e:
        return int(e.code or 0)

    print("=" * 60)
    print(" 自动化网络安全审计工具 v1.0")
    print("=" * 60)
    print(f" 目标: {', '.join(opts['targets'])}")
    print(f" 端口: {len(opts['ports'])} 个")
    print(f" 模块: {', '.join(opts['modules'])}")
    print(f" 并发: {opts['threads']} 线程, 超时: {opts['timeout']}s")
    print("-" * 60)
    print(" 注意: 仅限授权审计使用。")
    print("=" * 60)

    try:
        report_path = run_audit(
            targets=opts["targets"],
            ports=opts["ports"],
            timeout=opts["timeout"],
            threads=opts["threads"],
            modules=opts["modules"],
            output_path=opts["output"],
            target_info=", ".join(opts["targets"]),
            verbose=opts["verbose"],
            fmt=opts["fmt"],
        )
    except KeyboardInterrupt:
        print("\n[!] 用户中断,已退出。")
        return 130
    except Exception as e:
        print(f"\n[!] 审计失败: {type(e).__name__}: {e}")
        return 1

    print("\n" + "=" * 60)
    print(f" [+] 审计完成,HTML 报告已生成:")
    print(f"     {report_path}")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
