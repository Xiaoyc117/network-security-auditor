"""端口扫描逻辑单元测试(不依赖网络)。"""

import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from auditor.modules.port_scanner import (  # noqa: E402
    BANNER_PROBES,
    COMMON_SERVICES,
    HIGH_RISK_PORTS,
    parse_ports,
    scan_one_port,
    to_findings,
)
from auditor.utils import HIGH, INFO, LOW, MEDIUM  # noqa: E402


class TestParsePorts(unittest.TestCase):
    def test_single(self):
        self.assertEqual(parse_ports("80"), [80])

    def test_csv(self):
        self.assertEqual(parse_ports("80,443,22"), [22, 80, 443])

    def test_range(self):
        self.assertEqual(parse_ports("100-102"), [100, 101, 102])

    def test_mixed(self):
        self.assertEqual(parse_ports("80,100-101,443"), [80, 100, 101, 443])

    def test_invalid_skipped(self):
        self.assertEqual(parse_ports("80,abc,443"), [80, 443])

    def test_empty(self):
        # 空字符串返回默认端口列表(非空)
        self.assertTrue(len(parse_ports("")) > 0)


class TestScanOnePort(unittest.TestCase):
    @patch("auditor.modules.port_scanner.socket.socket")
    def test_open_port(self, mock_sock_cls):
        sock = mock_sock_cls.return_value
        sock.connect_ex.return_value = 0  # 开放
        sock.recv.return_value = b"SSH-2.0-test\r\n"
        result = scan_one_port("127.0.0.1", 22, timeout=1.0)
        self.assertEqual(result["state"], "open")
        self.assertEqual(result["service"], "SSH")
        self.assertIn("SSH", result["banner"])

    @patch("auditor.modules.port_scanner.socket.socket")
    def test_closed_port(self, mock_sock_cls):
        sock = mock_sock_cls.return_value
        sock.connect_ex.return_value = 1  # 关闭
        result = scan_one_port("127.0.0.1", 9999, timeout=1.0)
        self.assertEqual(result["state"], "closed")
        self.assertEqual(result["banner"], "")


class TestToFindings(unittest.TestCase):
    def test_no_open_ports(self):
        findings = to_findings("host", [])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, INFO)

    def test_high_risk_port(self):
        # Telnet 23 是高危
        findings = to_findings("host", [{"port": 23, "state": "open", "service": "Telnet", "banner": ""}])
        self.assertTrue(any(f.severity == HIGH for f in findings))

    def test_db_port(self):
        findings = to_findings("host", [{"port": 3306, "state": "open", "service": "MySQL", "banner": ""}])
        self.assertTrue(any(f.severity == MEDIUM for f in findings))

    def test_banner_version_leak(self):
        findings = to_findings(
            "host",
            [{"port": 22, "state": "open", "service": "SSH", "banner": "OpenSSH_8.2 Ubuntu"}],
        )
        self.assertTrue(any("版本" in f.title for f in findings))


if __name__ == "__main__":
    unittest.main()
