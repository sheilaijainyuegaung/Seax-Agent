"""LLM 层测试：LLMError 分类、冷却窗口生命周期、mock provider 路由。"""
import asyncio
import time
import unittest

from pentest_agent.llm.base import LLMError
from pentest_agent.llm.router import build_provider


class TestLLMError(unittest.TestCase):
    def test_is_runtime_error(self):
        self.assertIsInstance(LLMError("x", status_code=429), RuntimeError)

    def test_status_code(self):
        self.assertEqual(LLMError("x", status_code=429).status_code, 429)
        self.assertIsNone(LLMError("x").status_code)


class TestCooldown(unittest.TestCase):
    def _provider(self, seconds=0.05):
        return build_provider({"provider": "mock", "model": "m", "responses": ["x"], "cooldown_seconds": seconds})

    def test_lifecycle(self):
        p = self._provider()
        self.assertFalse(p._in_cooldown())
        p._note_failure()
        self.assertTrue(p._in_cooldown())
        p._note_success()
        self.assertFalse(p._in_cooldown())

    def test_expires(self):
        p = self._provider(seconds=0.03)
        p._note_failure()
        self.assertTrue(p._in_cooldown())
        time.sleep(0.05)
        self.assertFalse(p._in_cooldown())


class TestMockProvider(unittest.TestCase):
    def test_route_and_respond(self):
        p = build_provider({"provider": "mock", "model": "m", "responses": ["hi", "bye"]})
        self.assertEqual(asyncio.run(p.chat([], [])).text, "hi")
        self.assertEqual(asyncio.run(p.chat([], [])).text, "bye")
        self.assertEqual(asyncio.run(p.chat([], [])).text, "bye")  # 用完循环最后一个


if __name__ == "__main__":
    unittest.main()


class TestAnthropicDefaults(unittest.TestCase):
    def test_default_base_url(self):
        from pentest_agent.llm.anthropic import AnthropicProvider

        p = AnthropicProvider({"model": "claude-x", "api_key": "k"})
        self.assertEqual(p.base_url, "https://api.anthropic.com")
        # 显式配置仍然生效
        p2 = AnthropicProvider({"model": "claude-x", "api_key": "k", "base_url": "https://proxy.example.com"})
        self.assertEqual(p2.base_url, "https://proxy.example.com")
