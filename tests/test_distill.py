"""蒸馏链路单元测试 + mock provider 测试（中性数据，无攻击内容）。

端到端用 FakeRouter（不联网）验证 distill_session；mock provider 用预设文本验证 build_provider 路由。
fake chat 必须是 async 的：distill_session 面向真实 Router（async），同步假实现会掩盖
「同步调用 async 方法导致蒸馏静默失败」的回归。
"""
import asyncio
import json
import tempfile
import unittest
from pathlib import Path

from pentest_agent.distill import (
    collect_material,
    value_check,
    _extract_json,
    _validate_card,
    _find_task_detail_leak,
    distill_session,
)
from pentest_agent.llm.base import Message
from pentest_agent.llm.router import build_provider


class TestCollectMaterial(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())

    def _write(self, world, findings):
        (self.d / "world.json").write_text(json.dumps(world, ensure_ascii=False), encoding="utf-8")
        (self.d / "findings.json").write_text(json.dumps(findings, ensure_ascii=False), encoding="utf-8")

    def test_strips_task_details(self):
        self._write(
            {"fingerprint": "nginx", "signals": [], "hypotheses": [], "failures": []},
            [{"title": "通用问题", "severity": "info", "target": "192.0.2.10",
              "description": "描述", "remedy": "修复", "evidence": ["evidence/x.txt"]}],
        )
        mat = collect_material(self.d)
        f0 = mat["findings"][0]
        self.assertNotIn("target", f0)
        self.assertNotIn("evidence", f0)
        self.assertIn("description", f0)


class TestValueCheck(unittest.TestCase):
    def test_empty_no_value(self):
        m = {"fingerprint": "", "signals": [], "hypotheses": [], "failures": [], "findings": []}
        self.assertFalse(value_check(m))

    def test_hit_has_value(self):
        m = {"fingerprint": "", "signals": [], "hypotheses": [{"text": "x", "status": "hit"}], "failures": [], "findings": []}
        self.assertTrue(value_check(m))

    def test_finding_has_value(self):
        m = {"fingerprint": "", "signals": [], "hypotheses": [], "failures": [], "findings": [{"title": "t"}]}
        self.assertTrue(value_check(m))


class TestParsing(unittest.TestCase):
    def test_extract_bare_array(self):
        self.assertEqual(_extract_json('[{"name":"a","body":"b"}]'), [{"name": "a", "body": "b"}])

    def test_extract_with_prefix(self):
        self.assertEqual(_extract_json('前缀 [{"name":"x","body":"y"}]'), [{"name": "x", "body": "y"}])

    def test_extract_invalid(self):
        self.assertIsNone(_extract_json("完全不是 JSON"))

    def test_validate(self):
        self.assertIsNone(_validate_card({"name": "x", "body": "y"}))
        self.assertIsNotNone(_validate_card({"body": "y"}))
        self.assertIsNotNone(_validate_card({"name": "x"}))


class TestGuard(unittest.TestCase):
    def test_clean_card_passes(self):
        card = {"name": "recon-flow", "description": "通用流程", "body": "先识别指纹，再逐步验证"}
        self.assertIsNone(_find_task_detail_leak([card]))

    def test_leak_detected(self):
        card = {"name": "bad", "description": "针对某主机", "body": "对 192.0.2.10 先做探测"}
        leak = _find_task_detail_leak([card])
        self.assertIsNotNone(leak)
        self.assertEqual(leak[1], "192.0.2.10")


class TestDistillSession(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.skills = self.d / "skills"
        self.skills.mkdir(parents=True)

    def _write_session(self):
        s = self.d / "sess"
        s.mkdir(exist_ok=True)
        (s / "world.json").write_text(json.dumps({
            "fingerprint": "apache", "signals": [],
            "hypotheses": [{"id": "i001", "text": "目录结构", "status": "hit", "from": ["fingerprint"]}],
            "failures": [],
        }, ensure_ascii=False), encoding="utf-8")
        (s / "findings.json").write_text(json.dumps([
            {"title": "目录枚举方法", "severity": "info", "target": "198.51.100.1",
             "description": "字典枚举可发现隐藏路径", "evidence": ["evidence/x.txt"]},
        ], ensure_ascii=False), encoding="utf-8")
        return s

    def test_end_to_end(self):
        seen = []

        class _Resp:
            text = ""
        class _Fast:
            async def chat(self, messages, tools=()):
                # 必须收到 Message 对象：真实 provider 只认 Message，传 dict 会直接 AttributeError
                seen.append(list(messages))
                r = _Resp()
                r.text = '[{"name":"recon-method","description":"通用侦察方法","when":["侦察"],"body":"先指纹后验证"}]'
                return r
        class _Router:
            fast = _Fast()

        s = self._write_session()
        res = asyncio.run(distill_session(s, _Router(), {"skills": {"dir": str(self.skills)}}, session_id="sess"))
        self.assertEqual(res.get("created"), 1)
        self.assertTrue((self.skills / "recon-method" / "SKILL.md").exists())
        self.assertEqual(len(seen), 1)
        self.assertIsInstance(seen[0][0], Message)

    def _make_router(self, texts):
        class _Resp:
            text = ""
        class _Fast:
            def __init__(self, texts):
                self.texts = texts
                self.i = 0
            async def chat(self, messages, tools=()):
                r = _Resp()
                r.text = self.texts[min(self.i, len(self.texts) - 1)]
                self.i += 1
                return r
        class _Router:
            def __init__(self, texts):
                self.fast = _Fast(texts)
        return _Router(texts)

    def test_guard_filters_leaked_card(self):
        # 一张干净 + 一张夹带 IP 的卡，只写入干净的
        router = self._make_router([
            '[{"name":"good","description":"通用流程","when":["侦察"],"body":"先指纹后验证"},'
            '{"name":"bad","description":"针对某主机","body":"对 192.0.2.10 做探测"}]',
        ])
        s = self._write_session()
        res = asyncio.run(distill_session(s, router, {"skills": {"dir": str(self.skills)}}, session_id="s"))
        self.assertEqual(res.get("created"), 1)
        self.assertTrue((self.skills / "good" / "SKILL.md").exists())
        self.assertFalse((self.skills / "bad" / "SKILL.md").exists())

    def test_guard_rewrite_then_refilter(self):
        # 全部夹带 IP → 触发重写；重写结果仍夹带 IP → 被再次过滤，最终无卡写入
        router = self._make_router([
            '[{"name":"bad1","description":"x","body":"对 192.0.2.10 探测"}]',
            '[{"name":"bad2","description":"x","body":"对 198.51.100.1 探测"}]',
        ])
        s = self._write_session()
        res = asyncio.run(distill_session(s, router, {"skills": {"dir": str(self.skills)}}, session_id="s"))
        self.assertEqual(res.get("created"), 0)
        self.assertFalse((self.skills / "bad1" / "SKILL.md").exists())
        self.assertFalse((self.skills / "bad2" / "SKILL.md").exists())


class TestMockProvider(unittest.TestCase):
    def test_route_and_respond(self):
        p = build_provider({"provider": "mock", "model": "m", "responses": ["hi"]})
        import asyncio
        resp = asyncio.run(p.chat([], []))
        self.assertEqual(resp.text, "hi")


if __name__ == "__main__":
    unittest.main()
