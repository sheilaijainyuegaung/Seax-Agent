"""策略层纯函数单元测试（scope / targets / approval / dangerous / postex）。

全部使用示例域名 example.com、文档保留网段（10.0.0.0/24、192.0.2.x）与通用命令模式，
仅验证安全防护逻辑本身，不针对任何真实目标、不使用攻击 payload。
"""
import unittest

from pentest_agent.policy.scope import Scope
from pentest_agent.policy.targets import (
    extract_targets_from_text,
    scope_cfg_from_targets,
    looks_like_host,
)
from pentest_agent.policy.approval import decide, ALLOW, CONFIRM, BLOCK
from pentest_agent.policy.dangerous import scan_text
from pentest_agent.policy.postex import scan_postex


class TestScope(unittest.TestCase):
    def setUp(self):
        self.scope = Scope({"domains": ["example.com"], "cidrs": ["10.0.0.0/24"]})

    def test_domain_exact(self):
        ok, _ = self.scope.check_host("example.com")
        self.assertTrue(ok)

    def test_domain_subdomain(self):
        ok, _ = self.scope.check_host("www.example.com")
        self.assertTrue(ok)

    def test_domain_not_suffix_attack(self):
        # example.com.evil.com 不应命中（子域后缀检查）
        ok, _ = self.scope.check_host("example.com.evil.com")
        self.assertFalse(ok)

    def test_ip_in_cidr(self):
        ok, _ = self.scope.check_host("10.0.0.5")
        self.assertTrue(ok)

    def test_ip_out_of_cidr(self):
        ok, _ = self.scope.check_host("10.0.1.5")
        self.assertFalse(ok)

    def test_url_strips_scheme(self):
        ok, _ = self.scope.check_target("http://example.com/a/b")
        self.assertTrue(ok)

    def test_empty_scope_denies_all(self):
        ok, _ = Scope({}).check_host("example.com")
        self.assertFalse(ok)

    def test_allow_all(self):
        ok, _ = Scope({"allow_all": True}).check_host("anything.example")
        self.assertTrue(ok)


class TestTargets(unittest.TestCase):
    def test_extract_url_and_flag(self):
        hits = extract_targets_from_text("scan --url http://example.com -d example.org")
        self.assertIn("http://example.com", hits)
        self.assertIn("example.org", hits)

    def test_extract_plain_ip(self):
        hits = extract_targets_from_text("192.0.2.10")
        self.assertIn("192.0.2.10", hits)

    def test_looks_like_host(self):
        self.assertTrue(looks_like_host("example.com"))
        self.assertTrue(looks_like_host("192.0.2.1"))
        self.assertFalse(looks_like_host("user:pass"))
        self.assertFalse(looks_like_host("report.pdf"))

    def test_scope_cfg_from_targets(self):
        cfg = scope_cfg_from_targets(["example.com", "10.0.0.0/24"])
        self.assertIn("example.com", cfg["domains"])
        self.assertIn("10.0.0.0/24", cfg["cidrs"])
        self.assertFalse(cfg["allow_all"])


class TestApproval(unittest.TestCase):
    def test_pentest_read_allowed(self):
        self.assertEqual(decide("pentest", "default", "read")[0], ALLOW)

    def test_pentest_create_confirm(self):
        self.assertEqual(decide("pentest", "default", "create")[0], CONFIRM)

    def test_full_auth_delete_allowed(self):
        self.assertEqual(decide("pentest", "full", "delete")[0], ALLOW)

    def test_recon_write_blocked(self):
        self.assertEqual(decide("recon", "default", "create")[0], BLOCK)

    def test_destructive_full_blocked_by_default(self):
        d, _ = decide("pentest", "full", "command", "rm -rf 强删", {"allow_destructive_in_full": False})
        self.assertEqual(d, BLOCK)

    def test_destructive_full_allowed_when_configured(self):
        d, _ = decide("pentest", "full", "command", "rm -rf 强删", {"allow_destructive_in_full": True})
        self.assertEqual(d, ALLOW)


class TestDangerous(unittest.TestCase):
    def test_rm_rf_detected(self):
        self.assertIsNotNone(scan_text("rm -rf /tmp/x"))

    def test_del_force_detected(self):
        self.assertIsNotNone(scan_text("del /f /s somefile"))

    def test_benign_not_detected(self):
        self.assertIsNone(scan_text("echo hello world"))


class TestPostex(unittest.TestCase):
    def test_read_system_file_detected(self):
        self.assertIsNotNone(scan_postex("cat /etc/passwd"))

    def test_system_command_detected(self):
        self.assertIsNotNone(scan_postex("whoami"))

    def test_benign_not_detected(self):
        self.assertIsNone(scan_postex("send a normal request"))


if __name__ == "__main__":
    unittest.main()
