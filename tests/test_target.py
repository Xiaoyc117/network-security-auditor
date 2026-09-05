"""目标解析单元测试。"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from auditor.target import parse_target, parse_targets  # noqa: E402


class TestSingleIP(unittest.TestCase):
    def test_single_ipv4(self):
        self.assertEqual(parse_target("192.168.1.1"), ["192.168.1.1"])

    def test_single_ipv4_strips_whitespace(self):
        self.assertEqual(parse_target("  10.0.0.1  "), ["10.0.0.1"])

    def test_empty_input(self):
        self.assertEqual(parse_target(""), [])


class TestCIDR(unittest.TestCase):
    def test_cidr_30(self):
        # /30 网络 4 个地址,2 个主机地址
        result = parse_target("192.168.1.0/30")
        self.assertEqual(result, ["192.168.1.1", "192.168.1.2"])

    def test_cidr_32(self):
        result = parse_target("192.168.1.5/32")
        self.assertEqual(result, ["192.168.1.5"])

    def test_invalid_cidr_returns_original(self):
        result = parse_target("not-a-cidr/24")
        # 不是合法 CIDR,但也不匹配其他规则,可能返回原值
        self.assertIn(result[0], ("not-a-cidr/24",))


class TestRange(unittest.TestCase):
    def test_range_short(self):
        # 192.168.1.1-3 → 1,2,3
        result = parse_target("192.168.1.1-3")
        self.assertEqual(result, ["192.168.1.1", "192.168.1.2", "192.168.1.3"])

    def test_range_full(self):
        result = parse_target("192.168.1.1-192.168.1.3")
        self.assertEqual(result, ["192.168.1.1", "192.168.1.2", "192.168.1.3"])

    def test_range_reversed(self):
        result = parse_target("192.168.1.3-1")
        self.assertEqual(result, ["192.168.1.1", "192.168.1.2", "192.168.1.3"])


class TestParseTargets(unittest.TestCase):
    def test_dedup(self):
        result = parse_targets(["192.168.1.1", "192.168.1.1", "10.0.0.1"])
        self.assertEqual(result, ["192.168.1.1", "10.0.0.1"])

    def test_mixed(self):
        result = parse_targets(["192.168.1.0/30", "192.168.1.1"])
        # 192.168.1.1 已在 /30 展开结果中,应去重
        self.assertEqual(result, ["192.168.1.1", "192.168.1.2"])


if __name__ == "__main__":
    unittest.main()
