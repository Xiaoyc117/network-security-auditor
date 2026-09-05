# 自动化网络安全审计工具

一个纯 Python 标准库实现的自动化网络安全审计工具,无需任何外部 pip 依赖(可选 `cryptography` 用于增强证书解析)。

## 功能特性

- **端口与服务扫描**: TCP connect 扫描 + banner 抓取,识别常见服务(SSH/HTTP/MySQL/Redis 等)
- **SSL/TLS 证书检查**: 证书有效期/自签名/SAN 匹配 + 协议版本探测(标记 SSLv3/TLS1.0/1.1 等弱协议)+ 弱加密套件检测
- **Web 安全检测**: 安全响应头检查(HSTS/CSP/X-Frame-Options 等)+ 敏感路径探测(`.git`/`.env`/备份文件)+ 目录列出检测 + Server 版本泄露
- **合规与配置检查**: 基于 OWASP/CIS 基线规则集评估,输出合规得分(0-100)和修复建议
- **目标支持**: 单 IP / 域名 / CIDR 网段(`192.168.1.0/24`)/ IP 范围(`10.0.0.1-50`)
- **可视化报告**: 单文件 HTML,内嵌 CSS,离线可查看,含风险等级徽章和合规评分仪表盘
- **非破坏性**: 仅 TCP connect(无需 root),被动 Web 探测,合法合规使用

## 环境要求

- Python 3.8+(推荐 3.10+)
- 无强制依赖,纯标准库实现
- 可选: `pip install cryptography`(增强证书 SAN 解析)

## 快速开始

```bash
# 对本机运行(安全,不会触发外部告警)
python main.py --target 127.0.0.1 --output report.html --verbose

# 对域名运行
python main.py --target example.com

# 扫描 CIDR 网段
python main.py --cidr 192.168.1.0/24 --ports 80,443,22,3389

# 仅启用端口和 SSL 模块
python main.py --target 10.0.0.1 --modules port,ssl

# 自定义端口范围 + 高并发
python main.py --target 10.0.0.1 --ports 1-1000 --threads 50 --timeout 2
```

## 命令行参数

| 参数 | 说明 | 默认 |
|------|------|------|
| `--target HOST` | 单个目标(IP/域名),可多次指定 | - |
| `--cidr CIDR` | CIDR 网段,可多次指定 | - |
| `--ports PORTS` | 自定义端口,逗号分隔,支持范围 `80,443,1000-2000` | Top 100 常见端口 |
| `--modules MODS` | 选择模块:`port,ssl,web,compliance` | 全部 |
| `--output PATH` | HTML 报告输出路径 | `audit_report.html` |
| `--threads N` | 并发线程数 | 10 |
| `--timeout SEC` | 单次连接超时秒数 | 3.0 |
| `--verbose` | 打印详细进度 | 否 |

## 项目结构

```
network-security-auditor/
├── main.py                    # 入口
├── auditor/
│   ├── cli.py                 # 命令行解析
│   ├── core.py                # 审计流水线编排
│   ├── target.py              # 目标解析(IP/域名/CIDR/范围)
│   ├── utils.py               # 风险评级、并发、HTML 转义
│   ├── modules/
│   │   ├── port_scanner.py    # 端口与服务扫描
│   │   ├── ssl_checker.py     # SSL/TLS 检查
│   │   ├── web_auditor.py     # Web 安全检测
│   │   └── compliance.py      # 合规检查
│   └── reporters/
│       └── html_reporter.py   # HTML 报告生成
└── tests/                     # 单元测试
```

## 运行测试

```bash
cd network-security-auditor
python -m unittest discover tests -v
# 或使用 pytest
python -m pytest tests/ -v
```

## 风险等级说明

| 等级 | 中文 | 含义 |
|------|------|------|
| Critical | 严重 | 凭据/源代码/数据库直接暴露 |
| High | 高危 | 弱协议启用、高危端口开放、证书过期 |
| Medium | 中危 | 缺失关键安全头、自签名证书、明文服务 |
| Low | 低危 | 服务版本泄露、缺失次要安全头 |
| Info | 信息 | 正常配置、扫描摘要 |

## 合规规则集

合规模块基于以下基线规则(部分):

- `CIS-NET-001` 不应暴露 Telnet/rlogin 明文远程登录
- `CIS-NET-002` 数据库/缓存服务不应直接暴露公网
- `CIS-PORT-001` SMB/RDP 端口不应公网暴露
- `OWASP-CRYPTO-001` HTTPS 不应启用 TLS 1.0/1.1
- `OWASP-CRYPTO-002` 证书不应过期或自签名
- `OWASP-HEADER-001/002` 应配置 HSTS 和 CSP
- `OWASP-EXPOSE-001/002` 不应暴露源代码/凭据文件;管理后台不应公网可访问
- `OWASP-VERSION-001` 不应泄露服务/应用版本号

## 法律与使用声明

**本工具仅供授权安全审计使用。**

- 仅限对**自有或已获书面授权**的目标使用
- 禁止用于未授权扫描,违反可能触犯《网络安全法》《刑法》等法律法规
- 工具采用非破坏性检测(TCP connect、被动 Web 探测),但仍可能触发目标 IDS/防火墙告警
- 使用者自行承担一切法律责任

使用前请确认:
1. 你是目标资产的所有者,或
2. 你已获得资产所有者的书面授权
