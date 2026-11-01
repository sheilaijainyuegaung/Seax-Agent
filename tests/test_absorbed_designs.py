"""Claude/Cairn 机制落地回归测试：工具契约、结果外置、事实/失败图和子 agent 恢复。"""
import asyncio
import tempfile
import unittest
from pathlib import Path

from pentest_agent.core.agent import Agent
from pentest_agent.llm.base import ToolCall
from pentest_agent.mcp_client import MCPServer
from pentest_agent.tools.base import StrictModel, ToolAdapter, ToolResult
from pentest_agent.workspace.graph import build_attack_graph
from pentest_agent.workspace.session import Workspace


class FakeBus:
    def __init__(self):
        self.events = []

    async def emit(self, etype, data, agent=""):
        self.events.append((etype, data, agent))


class EmptyArgs(StrictModel):
    pass


class HookTool(ToolAdapter):
    name = "hook_test"
    param_model = EmptyArgs
    result_limit = 500
    hooks = []

    async def before_execute(self, args, ctx):
        self.hooks.append("before")

    async def after_execute(self, args, ctx, result, status):
        self.hooks.append("after:" + status)

    async def execute(self, args, ctx):
        return ToolResult(summary="x" * 1200)


def _cfg(tmp: Path):
    return {
        "llm": {
            "main": {"provider": "mock", "model": "m", "responses": [""]},
            "fast": {"provider": "mock", "model": "m", "responses": [""]},
        },
        "policy": {"max_rounds": 2},
        "workspace_dir": str(tmp),
        "tools": {"dir": ""},
        "skills": {"dir": str(tmp / "skills")},
    }


class TestAbsorbedDesigns(unittest.TestCase):
    def test_fact_and_failure_graph(self):
        d = Path(tempfile.mkdtemp())
        ws = Workspace(d, "s1", {"mode": "pentest"})
        ws.memory.update_world(fingerprint="nginx 1.25", hypothesis="验证目录", status="open",
                               from_facts=["fingerprint"])
        ws.memory.update_world(hypothesis="验证目录", status="miss", result_fact="目录不存在")
        ws.memory.record_failure({"tool": "run_tool", "summary": "超时", "intent_id": "i001",
                                  "retryable": True, "alternatives": ["read_evidence"]})
        world = ws.memory.data
        self.assertEqual(world["facts"][0]["id"], "f001")
        self.assertEqual(world["hypotheses"][0]["result_fact"], "f002")
        graph = build_attack_graph(ws.dir)
        ids = {node["id"] for node in graph["nodes"]}
        self.assertIn("f001", ids)
        self.assertIn("f002", ids)
        self.assertIn("x001", ids)
        self.assertIn(("i001", "x001"), {(e["from"], e["to"]) for e in graph["edges"]})

    def test_tool_hooks_and_large_result_reference(self):
        tmp = Path(tempfile.mkdtemp())
        bus = FakeBus()
        agent = Agent(_cfg(tmp), "pentest", "default", ["192.0.2.10"], {}, "t", bus, ws_root=tmp)
        tool = HookTool()
        tool.hooks = []
        agent.registry[tool.name] = tool
        asyncio.run(agent.handle_tool(ToolCall(id="c1", name=tool.name, arguments={})))
        self.assertEqual(tool.hooks, ["before", "after:ok"])
        self.assertTrue((agent.ws.dir / "raw" / "hook_test_c1.txt").exists())
        ends = [data for typ, data, _ in bus.events if typ == "tool_end" and data.get("tool") == tool.name]
        self.assertEqual(ends[-1]["lifecycle"], "finished")
        self.assertTrue(ends[-1]["raw_output"])

    def test_restarted_parent_lists_and_resumes_child(self):
        tmp = Path(tempfile.mkdtemp())
        ws = Workspace(tmp, "s1", {"mode": "pentest", "targets": ["192.0.2.10"]})
        ws.save_agent_record("a1", name="recon", task="检查已知资产", status="interrupted", phase="probe")
        parent = Agent(_cfg(tmp), "pentest", "default", ["192.0.2.10"], {}, "t", FakeBus(), workspace=ws)
        self.assertIn("a1", parent.subagents)
        self.assertIn("interrupted", parent.describe_sub("a1"))
        async def resume_and_wait():
            self.assertTrue(await parent.resume_subagent("a1"))
            await parent.subagents["a1"]["task"]
        asyncio.run(resume_and_wait())
        self.assertEqual(ws.load_agent_record("a1").get("status"), "completed")

    def test_mcp_tool_search_is_local_and_statused(self):
        srv = MCPServer("demo", {"transport": "http", "url": "http://example.invalid"})
        srv.status = "connected"
        srv.tools = [{"name": "fetch_url", "description": "fetch a URL"},
                     {"name": "add_note", "description": "store a note"}]
        found = srv.search_tools("url")
        self.assertEqual([x["name"] for x in found], ["fetch_url"])
        self.assertEqual(found[0]["qualified_name"], "mcp_demo_fetch_url")


if __name__ == "__main__":
    unittest.main()
