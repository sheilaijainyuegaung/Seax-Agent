"""工具证据落盘测试：同一会话多次执行 run_tool / run_command，证据文件必须各自独立。

之前 run_tool/run_command 写死 run_tool_output.txt / run_command_output.txt，
第二次执行会覆盖第一次的证据，违反「全程可回放」的证据纪律。
"""
import asyncio
import tempfile
import unittest
from pathlib import Path

from pentest_agent.policy.scope import Scope
from pentest_agent.tools.base import ToolContext
from pentest_agent.tools.builtin import RunToolTool
from pentest_agent.workspace.session import Workspace


class TestRunToolEvidence(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.tdir = self.tmp / "tools"
        self.tdir.mkdir()
        (self.tdir / "echo.py").write_text("print('hello from tool')", encoding="utf-8")
        self.ws = Workspace(self.tmp, "s_evid", {"mode": "pentest", "task": "测试"})

    def _ctx(self, call_id: str) -> ToolContext:
        return ToolContext(
            ws=self.ws, scope=Scope({}), mode="pentest", auth="default",
            cfg={"tools": {"dir": str(self.tdir)}}, state={}, emit=None, call_id=call_id,
        )

    def test_two_runs_keep_both_evidences(self):
        adapter = RunToolTool()
        evidences = []
        for cid in ("call_aaa", "call_bbb"):
            args = adapter.validate_input({"tool": "echo.py", "args": ""})
            res = asyncio.run(adapter.execute(args, self._ctx(cid)))
            self.assertEqual(res.evidence and len(res.evidence), 1, res.summary)
            evidences.append(res.evidence[0])
        self.assertNotEqual(evidences[0], evidences[1])
        for ev in evidences:
            self.assertTrue((self.ws.dir / ev).is_file(), ev)
        # 文件名可读：含工具名与 call_id
        self.assertIn("echo", Path(evidences[0]).name)
        self.assertIn("call_aaa", Path(evidences[0]).name)

    def test_missing_call_id_still_unique(self):
        # call_id 缺失时用随机后缀兜底，依然不能互相覆盖
        adapter = RunToolTool()
        names = set()
        for _ in range(2):
            args = adapter.validate_input({"tool": "echo.py", "args": ""})
            res = asyncio.run(adapter.execute(args, self._ctx("")))
            names.add(res.evidence[0])
        self.assertEqual(len(names), 2)


if __name__ == "__main__":
    unittest.main()
