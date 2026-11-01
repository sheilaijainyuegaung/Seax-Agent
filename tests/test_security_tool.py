"""工具货架(security_tool / registry)回归测试。

锁定的设计约束:
- C2 选配:清单不存在 = 空货架,agent 完整流水线照跑,security_tool 返回中性说明
- C3 AI 自主选型:系统提示注入的是货架卡片,不包含任何使用顺序/流程指令
- C5 结构化 scope:target 逐个校验;无 target / 带 extra_args → 无论授权档位都确认
"""
import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

from pentest_agent.core.agent import Agent
from pentest_agent.core.events import EventBus
from pentest_agent.llm.base import ToolCall
from pentest_agent.policy.scope import Scope
from pentest_agent.tools.base import ToolContext
from pentest_agent.tools.builtin import FindToolTool
from pentest_agent.tools.gen_registry import build_draft
from pentest_agent.tools.registry_decl import ToolEntry, load_registry, registry_path
from pentest_agent.tools.security_tool import SecurityToolAdapter
from pentest_agent.workspace.session import Workspace


class FakeBus:
    def __init__(self):
        self.events = []

    async def emit(self, etype, data, agent=""):
        self.events.append((etype, data, agent))


def _entry(**kw):
    base = dict(name="t", resolve="file", path="t.bat", description="测试工具",
                tool_class="read", target_flag="", multiple_targets=True, args="",
                allow_extra_args=True, timeout=600, danger_flags=[], output_hint="",
                resolved_path="C:/t.bat", error="")
    base.update(kw)
    return ToolEntry(**base)


def _cfg(tmp: Path, responses, tools_dir="", registry=""):
    return {
        "llm": {"main": {"provider": "mock", "model": "m", "responses": responses},
                "fast": {"provider": "mock", "model": "m", "responses": [""]}},
        "policy": {"max_rounds": 8, "distill_on_finish": False},
        "workspace_dir": str(tmp),
        "tools": {"dir": tools_dir, "registry": registry},
        "skills": {"dir": str(tmp / "skills")},
    }


class TestRegistryLoading(unittest.TestCase):
    def test_missing_file_is_empty_not_error(self):
        # C2:清单不存在 = 空货架,不是错误
        entries, problems = load_registry({"tools": {"registry": str(Path(tempfile.mkdtemp()) / "no.yaml")}})
        self.assertEqual(entries, {})
        self.assertEqual(problems, [])

    def test_load_entries_and_problems(self):
        tmp = Path(tempfile.mkdtemp())
        (tmp / "tools").mkdir()
        (tmp / "tools" / "a.exe").write_bytes(b"MZ")
        reg = tmp / "reg.yaml"
        reg.write_text(yaml.safe_dump({"tools": {
            "alpha": {"resolve": "file", "path": "tools/a.exe", "class": "read", "description": "测试"},
            "beta": {"resolve": "file", "path": "tools/missing.exe"},
            "gamma": {"resolve": "path", "path": "definitely-not-on-path-xyz-123"},
        }}, allow_unicode=True), encoding="utf-8")
        entries, problems = load_registry({"tools": {"dir": str(tmp), "registry": str(reg)}})
        self.assertIn("alpha", entries)
        self.assertEqual(entries["alpha"].tool_class, "read")
        self.assertTrue(entries["alpha"].resolved_path)
        self.assertEqual(len(problems), 2)
        self.assertTrue(any("beta" in p for p in problems))
        self.assertTrue(any("gamma" in p for p in problems))


class TestSecurityToolBehavior(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.tdir = self.tmp / "tools"
        self.tdir.mkdir()
        (self.tdir / "hello.py").write_text("import sys; print('ARGS', sys.argv[1:])", encoding="utf-8")
        self.ws = Workspace(self.tmp, "s_sec", {"mode": "pentest"})
        self.entry = _entry(name="hello", resolve="file", path="hello.py",
                            resolved_path=str(self.tdir / "hello.py"), tool_class="read")

    def _ctx(self, call_id="c1", registry=None):
        return ToolContext(ws=self.ws, scope=Scope({"allow_all": True}), mode="pentest", auth="full",
                           cfg={"tools": {"dir": str(self.tdir)}}, state={}, emit=None,
                           call_id=call_id, tool_registry={"hello": self.entry} if registry is None else registry)

    def test_unconfigured_returns_neutral_message(self):
        # C2:货架为空 = 中性说明,不引导不催促
        ad = SecurityToolAdapter()
        args = ad.validate_input({"tool": "nmap", "target": ["192.0.2.1"]})
        res = asyncio.run(ad.execute(args, self._ctx()))
        self.assertIn("不在可用货架", res.summary)

    def test_argv_build_and_execute(self):
        entry = _entry(name="hello", resolve="file", path="hello.py",
                       resolved_path=str(self.tdir / "hello.py"), tool_class="read",
                       args="-n", target_flag="-t")
        ad = SecurityToolAdapter(tool_registry={"hello": entry})
        args = ad.validate_input({"tool": "hello", "target": ["10.0.0.5"], "extra_args": "-v"})
        res = asyncio.run(ad.execute(args, self._ctx(registry={"hello": entry})))
        # 拼装顺序:清单固定参数 → target_flag → 目标 → extra_args
        self.assertIn("['-n', '-t', '10.0.0.5', '-v']", res.summary)
        self.assertTrue((self.ws.dir / res.evidence[0]).is_file())
        self.assertIn("hello", res.evidence[0])

    def test_needs_manual_confirm_rules(self):
        ad = SecurityToolAdapter(tool_registry={"hello": self.entry})
        ok = ad.validate_input({"tool": "hello", "target": ["10.0.0.5"]})
        self.assertIsNone(ad.needs_manual_confirm(ok))
        no_target = ad.validate_input({"tool": "hello"})
        self.assertIn("target", ad.needs_manual_confirm(no_target))
        with_extra = ad.validate_input({"tool": "hello", "target": ["10.0.0.5"], "extra_args": "-v"})
        self.assertIn("extra_args", ad.needs_manual_confirm(with_extra))
        unknown = ad.validate_input({"tool": "whatever", "target": ["10.0.0.5"]})
        self.assertIsNotNone(ad.needs_manual_confirm(unknown))

    def test_classify_uses_manifest(self):
        ad = SecurityToolAdapter(tool_registry={"hello": self.entry})
        ok = ad.validate_input({"tool": "hello", "target": ["10.0.0.5"]})
        self.assertEqual(ad.classify(ok), "read")
        no_target = ad.validate_input({"tool": "hello"})
        self.assertEqual(ad.classify(no_target), "command")

    def test_extra_args_disallowed(self):
        entry = _entry(name="strict", allow_extra_args=False, resolved_path=str(self.tdir / "hello.py"))
        ad = SecurityToolAdapter(tool_registry={"strict": entry})
        args = ad.validate_input({"tool": "strict", "target": ["10.0.0.5"], "extra_args": "-v"})
        res = asyncio.run(ad.execute(args, self._ctx(registry={"strict": entry})))
        self.assertIn("不允许 extra_args", res.summary)


class TestAgentIntegration(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.tdir = self.tmp / "tools"
        self.tdir.mkdir()
        (self.tdir / "hello.py").write_text("import sys; print('hello ok')", encoding="utf-8")
        self.reg = self.tmp / "reg.yaml"
        # path 相对 tools.dir 解析:hello.py 就在 tools.dir 下
        self.reg.write_text(yaml.safe_dump({"tools": {
            "t1": {"resolve": "file", "path": "hello.py", "class": "read"},
        }}, allow_unicode=True), encoding="utf-8")

    def test_out_of_scope_target_blocked(self):
        agent = Agent(_cfg(self.tmp, [], tools_dir=str(self.tdir), registry=str(self.reg)),
                      "pentest", "full", ["192.0.2.10"], {"domains": ["example.com"]},
                      "测试", FakeBus(), ws_root=self.tmp)
        tc = ToolCall(id="s1", name="security_tool",
                      arguments={"tool": "t1", "target": ["203.0.113.5"]})
        msg = asyncio.run(agent.handle_tool(tc))
        self.assertIn("scope 拦截", msg.content)

    def test_empty_target_confirms_even_in_full_auth(self):
        # C5:full 授权下,无结构化 target 也必须确认(旧自由文本通道这里是静默放行)
        agent = Agent(_cfg(self.tmp, [], tools_dir=str(self.tdir), registry=str(self.reg)),
                      "pentest", "full", ["192.0.2.10"], {"allow_all": True},
                      "测试", FakeBus(), ws_root=self.tmp)
        captured = {}

        async def fake_appr(rid, kind, payload):
            captured["reason"] = payload.get("reason", "")
            return {"decision": "deny"}
        agent.request_approval = fake_appr
        tc = ToolCall(id="s2", name="security_tool", arguments={"tool": "t1", "extra_args": "-x"})
        msg = asyncio.run(agent.handle_tool(tc))
        self.assertIn("target", captured.get("reason", ""))
        self.assertIn("拒绝", msg.content)

    def test_in_scope_read_tool_runs_free(self):
        agent = Agent(_cfg(self.tmp, [], tools_dir=str(self.tdir), registry=str(self.reg)),
                      "pentest", "full", ["192.0.2.10"], {"allow_all": True},
                      "测试", FakeBus(), ws_root=self.tmp)
        events = []
        agent.bus = FakeBus()
        tc = ToolCall(id="s3", name="security_tool", arguments={"tool": "t1", "target": ["192.0.2.10"]})
        msg = asyncio.run(agent.handle_tool(tc))
        self.assertIn("[t1]", msg.content)
        self.assertIn("exit=", msg.content)

    def test_no_tools_full_pipeline_still_works(self):
        # C2:不配置任何工具,agent 完整流水线照跑;security_tool 能力可见但为空货架
        responses = [
            '{"tool_calls": [{"id": "c1", "name": "save_assets", "arguments": {"assets": [{"target": "example.com", "type": "domain"}]}}]}',
            '{"text": "完成"}',
        ]
        agent = Agent(_cfg(self.tmp, responses), "pentest", "default", ["192.0.2.10"], {},
                      "测试任务", FakeBus(), ws_root=self.tmp)
        asyncio.run(agent.run())
        self.assertEqual(agent.tool_registry, {})
        self.assertIn("security_tool", agent.registry)
        self.assertEqual(len(agent.ws.assets), 2)  # seed + save_assets

    def test_system_prompt_shows_shelf(self):
        # C3:注入的是货架卡片(名字+安全属性+说明书),没有流程指令
        agent = Agent(_cfg(self.tmp, [], tools_dir=str(self.tdir), registry=str(self.reg)),
                      "pentest", "default", ["192.0.2.10"], {}, "测试", FakeBus(), ws_root=self.tmp)
        prompt = agent.system_prompt()
        self.assertIn("t1", prompt)
        self.assertIn("security_tool", prompt)
        self.assertIn("由你判断", prompt)


class TestFindToolShelfFirst(unittest.TestCase):
    def test_shelf_hits_before_dir_search(self):
        tmp = Path(tempfile.mkdtemp())
        ws = Workspace(tmp, "s_ft", {"mode": "pentest"})
        entry = _entry(name="nmap", description="端口扫描")
        ctx = ToolContext(ws=ws, scope=Scope({}), mode="pentest", auth="default",
                          cfg={}, state={}, emit=None, tool_registry={"nmap": entry})
        res = asyncio.run(FindToolTool().execute(FindToolTool().validate_input({"query": "nmap"}), ctx))
        self.assertIn("货架命中", res.summary)
        self.assertIn("nmap", res.summary)


class TestGenDraft(unittest.TestCase):
    def test_draft_and_description_preserved(self):
        tmp = Path(tempfile.mkdtemp())
        (tmp / "1.扫描").mkdir()
        (tmp / "1.扫描" / "nmap.exe").write_bytes(b"MZ")
        (tmp / "x.bat").write_bytes(b"@echo off\n")
        draft = build_draft(str(tmp))
        self.assertIn("nmap", draft["tools"])
        self.assertEqual(draft["tools"]["nmap"]["path"], "1.扫描/nmap.exe")
        self.assertEqual(draft["tools"]["nmap"]["class"], "command")  # 草稿保守
        self.assertIn("x", draft["tools"])
        # 重复生成不丢人工补的 description
        draft2 = build_draft(str(tmp), existing={"nmap": {"path": "1.扫描/nmap.exe",
                                                          "description": "老描述"}})
        self.assertEqual(draft2["tools"]["nmap"]["description"], "老描述")


if __name__ == "__main__":
    unittest.main()
