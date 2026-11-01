"""Agent 测试：push_input 的 建议(?) / 指令 分层 + reason/explore 规划闸门。"""
import asyncio
import tempfile
import unittest
from pathlib import Path

from pentest_agent.core.agent import Agent
from pentest_agent.llm.base import ToolCall
from pentest_agent.tools.builtin import SetPhaseArgs


class FakeBus:
    def __init__(self):
        self.events = []

    async def emit(self, etype, data, agent=""):
        self.events.append((etype, data, agent))


def _make_agent(tmp: Path, mode: str = "pentest", bus=None) -> Agent:
    cfg = {
        "llm": {
            "main": {"provider": "mock", "model": "m", "responses": [""]},
            "fast": {"provider": "mock", "model": "m", "responses": [""]},
        },
        "policy": {"max_rounds": 3},
        "workspace_dir": str(tmp),
        "tools": {"dir": ""},
        "skills": {"dir": str(tmp / "skills")},
    }
    return Agent(cfg, mode, "default", ["192.0.2.10"], {}, "测试任务", bus, ws_root=Path(tmp))


class TestPushInput(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def test_suggest_and_instruct(self):
        a = _make_agent(self.tmp)
        a.push_input("? 建议试试登录口")
        a.push_input("停手，只测 A")
        self.assertEqual(a.inbox, [("suggest", "建议试试登录口"), ("instruct", "停手，只测 A")])

    def test_suggest_strips_prefix(self):
        a = _make_agent(self.tmp)
        a.push_input("?带建议")
        self.assertEqual(a.inbox, [("suggest", "带建议")])

    def test_empty_ignored(self):
        a = _make_agent(self.tmp)
        a.push_input("   ")
        a.push_input("?   ")
        self.assertEqual(a.inbox, [])


class TestIntentGate(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def _go(self, a, phase):
        return asyncio.run(a.do_set_phase(SetPhaseArgs(phase=phase), ToolCall(id="c1", name="set_phase", arguments={"phase": phase})))

    def test_has_open_hypotheses(self):
        a = _make_agent(self.tmp)
        self.assertFalse(a._has_open_hypotheses())
        a.ws.memory.update_world(hypothesis="假设甲", status="open")
        self.assertTrue(a._has_open_hypotheses())
        a.ws.memory.update_world(hypothesis="假设甲", status="miss")
        self.assertFalse(a._has_open_hypotheses())

    def test_gate_blocks_discover_without_plan(self):
        a = _make_agent(self.tmp)
        a.state["phase"] = "surface"
        msg = self._go(a, "discover")
        self.assertIn("先规划", msg.content)
        self.assertNotEqual(a.state["phase"], "discover")

    def test_gate_passes_with_plan(self):
        a = _make_agent(self.tmp, bus=FakeBus())
        a.ws.memory.update_world(hypothesis="假设甲", status="open")
        a.state["phase"] = "surface"
        self._go(a, "discover")
        self.assertEqual(a.state["phase"], "discover")

    def test_gate_not_applied_to_other_phases(self):
        a = _make_agent(self.tmp, bus=FakeBus())
        a.state["phase"] = "probe"
        self._go(a, "surface")  # 进入战略阶段不受闸门约束
        self.assertEqual(a.state["phase"], "surface")


if __name__ == "__main__":
    unittest.main()

