"""断点续传机制测试：checkpoint 持久化、原子写、悬空 tool_call 补全、断点上下文、finish 标记。"""
import asyncio
import tempfile
import unittest
from pathlib import Path

from pentest_agent.workspace.session import Workspace
from pentest_agent.core.agent import Agent
from pentest_agent.llm.base import ToolCall
from pentest_agent.tools.builtin import FinishArgs


class FakeBus:
    def __init__(self):
        self.events = []

    async def emit(self, etype, data, agent=""):
        self.events.append((etype, data, agent))


def _make_agent(tmp: Path, bus=None) -> Agent:
    cfg = {
        "llm": {
            "main": {"provider": "mock", "model": "m", "responses": [""]},
            "fast": {"provider": "mock", "model": "m", "responses": [""]},
        },
        "policy": {"max_rounds": 3, "distill_on_finish": False},
        "workspace_dir": str(tmp),
        "tools": {"dir": ""},
        "skills": {"dir": str(tmp / "skills")},
    }
    return Agent(cfg, "pentest", "default", ["192.0.2.10"], {}, "测试任务", bus, ws_root=Path(tmp))


class TestCheckpoint(unittest.TestCase):
    def setUp(self):
        self.ws = Workspace(Path(tempfile.mkdtemp()), "sess1", {"mode": "pentest", "task": "t"})

    def test_save_load_roundtrip(self):
        self.ws.save_checkpoint(status="running", phase="discover", progress_summary="进展中")
        cp = self.ws.load_checkpoint()
        self.assertEqual(cp["status"], "running")
        self.assertEqual(cp["phase"], "discover")
        self.assertEqual(cp["progress_summary"], "进展中")
        self.assertIn("updated_at", cp)

    def test_clear_in_flight(self):
        self.ws.save_checkpoint(in_flight={"tool": "run_tool"}, status="running")
        self.assertIsNotNone(self.ws.load_checkpoint().get("in_flight"))
        self.ws.save_checkpoint(in_flight=None)
        self.assertIsNone(self.ws.load_checkpoint().get("in_flight"))

    def test_no_tmp_residue(self):
        self.ws.save_checkpoint(status="running")
        self.assertFalse((self.ws.dir / "checkpoint.json.tmp").exists())

    def test_load_empty_when_missing(self):
        ws = Workspace(Path(tempfile.mkdtemp()), "sess2", {"mode": "pentest"})
        self.assertEqual(ws.load_checkpoint(), {})


class TestLoadHistoryDangling(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def test_dangling_tool_call_patched(self):
        a = _make_agent(self.tmp)
        entries = [
            {"role": "user", "content": "任务"},
            {"role": "assistant", "content": "我来测试", "tool_calls": [{"id": "c1", "name": "run_tool", "arguments": {}}]},
        ]
        a.load_history(entries)
        self.assertEqual(a.messages[-1].role, "tool")
        self.assertIn("中断恢复", a.messages[-1].content)
        self.assertEqual(a.messages[-1].tool_call_id, "c1")

    def test_complete_history_untouched(self):
        a = _make_agent(self.tmp)
        entries = [
            {"role": "user", "content": "任务"},
            {"role": "assistant", "content": "我来", "tool_calls": [{"id": "c1", "name": "run_tool", "arguments": {}}]},
            {"role": "tool", "content": "结果", "tool_call_id": "c1", "name": "run_tool"},
        ]
        a.load_history(entries)
        self.assertEqual(a.messages[-1].content, "结果")

    def test_fifo_backfill_across_assistants(self):
        # 旧日志多个 assistant 各带无 id 的 tool 结果：按出现顺序 FIFO 配对，
        # 旧的"回看最近 assistant"实现会把第一条结果错配给最后一个调用
        a = _make_agent(self.tmp)
        entries = [
            {"role": "user", "content": "任务"},
            {"role": "assistant", "content": "", "tool_calls": [{"id": "a1", "name": "run_tool", "arguments": {}}]},
            {"role": "assistant", "content": "", "tool_calls": [{"id": "b1", "name": "run_tool", "arguments": {}}]},
            {"role": "tool", "content": "x"},
            {"role": "tool", "content": "y"},
        ]
        a.load_history(entries)
        tids = [m.tool_call_id for m in a.messages if m.role == "tool"]
        self.assertEqual(tids, ["a1", "b1"])

    def test_explicit_ids_removed_from_queue(self):
        # 显式 id 的结果先消费掉自己的调用，后面的无 id 结果才轮到下一个
        a = _make_agent(self.tmp)
        entries = [
            {"role": "user", "content": "任务"},
            {"role": "assistant", "content": "", "tool_calls": [
                {"id": "a1", "name": "t", "arguments": {}},
                {"id": "a2", "name": "t", "arguments": {}}]},
            {"role": "tool", "content": "第二个结果", "tool_call_id": "a2"},
            {"role": "tool", "content": "旧日志无 id"},
        ]
        a.load_history(entries)
        tids = [m.tool_call_id for m in a.messages if m.role == "tool"]
        self.assertEqual(tids, ["a2", "a1"])


class TestCheckpointBlock(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def test_interrupted_returns_context(self):
        a = _make_agent(self.tmp)
        a.checkpoint = {"status": "interrupted", "reason": "user_stop",
                        "progress_summary": "进展", "in_flight": {"tool": "run_tool"}}
        block = a._checkpoint_block()
        self.assertIn("断点续传", block)
        self.assertIn("run_tool", block)
        self.assertIn("进展", block)

    def test_running_returns_empty(self):
        a = _make_agent(self.tmp)
        a.checkpoint = {"status": "running"}
        self.assertEqual(a._checkpoint_block(), "")

    def test_empty_checkpoint_returns_empty(self):
        a = _make_agent(self.tmp)
        self.assertEqual(a._checkpoint_block(), "")


class TestFinishCheckpoint(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def test_finish_writes_completed(self):
        a = _make_agent(self.tmp, bus=FakeBus())
        args = FinishArgs(summary="任务完成")
        tc = ToolCall(id="c1", name="finish", arguments={"summary": "任务完成"})
        asyncio.run(a.do_finish(args, tc))
        self.assertEqual(a.ws.load_checkpoint().get("status"), "completed")


if __name__ == "__main__":
    unittest.main()
