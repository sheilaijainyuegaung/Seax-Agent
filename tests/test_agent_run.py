"""Agent 主循环端到端测试：run() 完整执行 + CancelledError 中断标记 + 恢复加载。

全部中性数据：目标用文档保留地址 192.0.2.10 / example.com，工具只用记账类 save_assets，
不发起任何真实网络请求、不执行命令、无攻击行为。
"""
import asyncio
import tempfile
import unittest
from pathlib import Path

from pentest_agent.core.agent import Agent
from pentest_agent.llm.base import LLMResponse, Message, ToolCall
from pentest_agent.workspace.session import Workspace


class FakeBus:
    def __init__(self):
        self.events = []

    async def emit(self, etype, data, agent=""):
        self.events.append((etype, data, agent))


class BlockingProvider:
    """测试专用：chat 阻塞，用于触发 CancelledError（模拟断网/长时间无响应）。"""

    name = "blocking"

    def __init__(self, cfg):
        self.cfg = cfg or {}

    async def chat(self, messages, tools, on_delta=None, on_reasoning=None):
        await asyncio.sleep(10)
        return LLMResponse(text="")


def _cfg(tmp: Path, responses) -> dict:
    return {
        "llm": {
            "main": {"provider": "mock", "model": "m", "responses": responses},
            "fast": {"provider": "mock", "model": "m", "responses": [""]},
        },
        "policy": {"max_rounds": 5, "distill_on_finish": False},
        "workspace_dir": str(tmp),
        "tools": {"dir": ""},
        "skills": {"dir": str(tmp / "skills")},
    }


class TestRunEndToEnd(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.bus = FakeBus()

    def test_run_with_tool_call(self):
        responses = [
            '{"tool_calls": [{"id": "c1", "name": "save_assets", "arguments": {"assets": [{"target": "example.com", "type": "domain", "source": "test"}]}}]}',
            '{"text": "本轮完成"}',
        ]
        agent = Agent(_cfg(self.tmp, responses), "pentest", "default", ["192.0.2.10"], {},
                      "测试任务", self.bus, ws_root=self.tmp)
        asyncio.run(agent.run())
        # 资产：开局 seed 192.0.2.10 + save_assets 写入 example.com = 2 条
        self.assertEqual(len(agent.ws.assets), 2)
        # 正常结束一轮 → checkpoint 写 running
        self.assertEqual(agent.ws.load_checkpoint().get("status"), "running")


class TestCancelledInterrupt(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def test_cancel_writes_interrupted(self):
        agent = Agent(_cfg(self.tmp, [""]), "pentest", "default", ["192.0.2.10"], {},
                      "测试任务", FakeBus(), ws_root=self.tmp)
        agent.router.main = BlockingProvider({})  # 替换为阻塞 provider，模拟断网卡住

        async def _run():
            task = asyncio.create_task(agent.run())
            await asyncio.sleep(0.1)
            task.cancel()  # 模拟用户主动中断
            try:
                await task
            except asyncio.CancelledError:
                pass

        asyncio.run(_run())
        cp = agent.ws.load_checkpoint()
        self.assertEqual(cp.get("status"), "interrupted")
        self.assertEqual(cp.get("reason"), "user_stop")

    def test_max_rounds_writes_interrupted(self):
        cfg = _cfg(self.tmp, [""])
        cfg["policy"]["max_rounds"] = 2
        cfg["llm"]["main"]["responses"] = [
            '{"tool_calls": [{"id": "c1", "name": "save_assets", "arguments": {"assets": [{"target": "example.com", "type": "domain"}]}}]}',
            '{"tool_calls": [{"id": "c2", "name": "save_assets", "arguments": {"assets": [{"target": "example.org", "type": "domain"}]}}]}',
        ]
        agent = Agent(cfg, "pentest", "default", ["192.0.2.10"], {}, "测试任务", FakeBus(), ws_root=self.tmp)
        asyncio.run(agent.run())
        cp = agent.ws.load_checkpoint()
        self.assertEqual(cp.get("status"), "interrupted")
        self.assertEqual(cp.get("reason"), "max_rounds")


class TestResumeAfterInterrupt(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def test_resume_loads_checkpoint(self):
        # 1) 模拟上次中断：workspace 已留下 interrupted 断点
        ws = Workspace(self.tmp, "sess1", {"mode": "pentest", "task": "测试", "targets": ["192.0.2.10"]})
        ws.save_checkpoint(status="interrupted", reason="user_stop",
                           progress_summary="已记录资产 example.com", in_flight=None)
        # 2) 恢复：用同一 ws 重建 agent（等价 server 的 _ensure_session）
        agent = Agent(_cfg(self.tmp, [""]), "pentest", "default", ["192.0.2.10"], {},
                      "测试", FakeBus(), workspace=ws)
        # 3) 验证 checkpoint 加载 + 断点上下文注入
        self.assertEqual(agent.checkpoint.get("status"), "interrupted")
        block = agent._checkpoint_block()
        self.assertIn("断点续传", block)
        self.assertIn("example.com", block)


class TestFinishCheckpoint(unittest.TestCase):
    """finish 后 checkpoint 必须保持 completed，不被 finally 的 running 覆盖。"""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.bus = FakeBus()

    def test_finish_keeps_completed(self):
        responses = [
            '{"tool_calls": [{"id": "f1", "name": "finish", "arguments": {"summary": "任务完成"}}]}',
        ]
        agent = Agent(_cfg(self.tmp, responses), "pentest", "default", ["192.0.2.10"], {},
                      "测试任务", self.bus, ws_root=self.tmp)
        asyncio.run(agent.run())
        cp = agent.ws.load_checkpoint()
        self.assertEqual(cp.get("status"), "completed")
        self.assertTrue(agent.state.get("finished"))


class TestAssetConfirmSelections(unittest.TestCase):
    """红队资产确认：selections=None=全部允许；空列表=一个都没勾=不授权任何目标。"""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def _agent(self):
        agent = Agent(_cfg(self.tmp, []), "redteam", "default", ["192.0.2.10"], {},
                      "红队测试", FakeBus(), ws_root=self.tmp)
        agent.ws.add_assets([{"target": "192.0.2.10", "type": "ip", "source": "user", "note": ""}])
        agent.state["phase"] = "recon"
        return agent

    def _confirm(self, agent, selections):
        async def fake_approval(rid, kind, payload):
            return {"decision": "allow", "selections": selections}
        agent.request_approval = fake_approval
        from pentest_agent.llm.base import ToolCall
        tc = ToolCall(id="t1", name="set_phase", arguments={"phase": "confirm_assets"})
        return asyncio.run(agent.handle_tool(tc))

    def test_empty_selections_authorize_nothing(self):
        agent = self._agent()
        msg = self._confirm(agent, [])
        self.assertIn("没有勾选任何资产", msg.content)
        # scope 未收紧、卡点未消费，agent 仍停在侦察阶段
        self.assertNotIn("assets_confirmed", agent.ws.meta)
        self.assertEqual(agent.state["phase"], "recon")

    def test_none_selections_confirms_all(self):
        agent = self._agent()
        msg = self._confirm(agent, None)
        self.assertTrue(agent.ws.meta.get("assets_confirmed"))
        self.assertEqual(agent.state["phase"], "confirm_assets")
        # 收紧后的 scope 覆盖全部已列资产
        ok, _ = agent.scope.check_target("192.0.2.10")
        self.assertTrue(ok)

    def test_resolve_approval_preserves_none(self):
        agent = self._agent()

        async def _flow():
            loop = asyncio.get_running_loop()
            fut = loop.create_future()
            agent.pending["r1"] = {"future": fut, "kind": "asset_confirm"}
            agent.resolve_approval("r1", "allow", None)
            return await fut
        answer = asyncio.run(_flow())
        self.assertIsNone(answer["selections"])


class TestHistoryReasoningBlocks(unittest.TestCase):
    """Claude extended thinking 块必须随 messages.jsonl 持久化并在恢复时回填。"""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def test_load_history_restores_blocks(self):
        ws = Workspace(self.tmp, "sess_rb", {"mode": "pentest", "task": "测试", "targets": ["192.0.2.10"]})
        agent = Agent(_cfg(self.tmp, [""]), "pentest", "default", ["192.0.2.10"], {},
                      "测试", FakeBus(), workspace=ws)
        history = [
            {"role": "user", "content": "任务"},
            {"role": "assistant", "content": "", "reasoning": "想想",
             "reasoning_blocks": [{"type": "thinking", "thinking": "想想", "signature": "sig=="}],
             "tool_calls": [{"id": "c9", "name": "save_assets", "arguments": {}}]},
            {"role": "tool", "content": "ok", "tool_call_id": "c9", "name": "save_assets"},
        ]
        agent.load_history(history)
        asst = [m for m in agent.messages if m.role == "assistant"][0]
        self.assertEqual(asst.reasoning_blocks[0].get("signature"), "sig==")
        # 恢复后的历史转 Anthropic 协议时，assistant 消息必须带上 thinking 块（协议硬要求）
        from pentest_agent.llm.anthropic import AnthropicProvider
        prov = AnthropicProvider({"model": "claude-x", "api_key": "k"})
        _system, conv = prov._convert(agent.messages)
        conv_asst = [c for c in conv if c["role"] == "assistant"][0]
        self.assertTrue(any(b.get("type") == "thinking" for b in conv_asst["content"]))

    def test_log_message_persists_blocks(self):
        agent = Agent(_cfg(self.tmp, [""]), "pentest", "default", ["192.0.2.10"], {},
                      "测试", FakeBus(), ws_root=self.tmp)
        agent._log_message({"role": "assistant", "content": "", "tool_calls": [],
                            "reasoning": "r", "reasoning_blocks": [{"type": "thinking", "thinking": "r"}],
                            "agent": agent.name})
        import json as _json
        line = (agent.ws.dir / "messages.jsonl").read_text(encoding="utf-8").strip().splitlines()[-1]
        self.assertEqual(_json.loads(line).get("reasoning_blocks"),
                         [{"type": "thinking", "thinking": "r"}])


class TestFinishResetsPerTurn(unittest.TestCase):
    """finish 标记只属于本轮：不重置会让后续每轮执行完第一个工具就被打断。"""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.bus = FakeBus()

    def test_finish_does_not_leak_into_next_turn(self):
        cfg = _cfg(self.tmp, [
            '{"tool_calls": [{"id": "f1", "name": "finish", "arguments": {"summary": "第一轮完成"}}]}',
        ])
        agent = Agent(cfg, "pentest", "default", ["192.0.2.10"], {}, "测试任务", self.bus, ws_root=self.tmp)
        asyncio.run(agent.run())
        self.assertTrue(agent.state.get("finished"))
        # 第 2 轮剧本：模型一次请求两个工具（mock provider 构造时已拷贝剧本，直接改实例）
        agent.router.main._responses = [
            '{"tool_calls": ['
            '{"id": "t1", "name": "save_assets", "arguments": {"assets": [{"target": "192.0.2.1", "type": "ip"}]}},'
            '{"id": "t2", "name": "save_assets", "arguments": {"assets": [{"target": "192.0.2.2", "type": "ip"}]}}]}',
        ]
        agent.router.main._idx = 0
        asyncio.run(agent.run(user_text="继续"))
        targets = {a["target"] for a in agent.ws.assets}
        self.assertIn("192.0.2.1", targets)
        self.assertIn("192.0.2.2", targets)


class TestRestoreKeepsConfirmedScope(unittest.TestCase):
    """红队确认资产后重启恢复：收紧的 scope 不能被 merge 结果覆盖放宽。"""

    def test_confirmed_scope_survives_restore(self):
        tmp = Path(tempfile.mkdtemp())
        targets = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
        agent = Agent(_cfg(tmp, []), "redteam", "default", targets, {}, "红队", FakeBus(), ws_root=tmp)
        for t in targets:
            agent.ws.add_assets([{"target": t, "type": "ip", "source": "user", "note": ""}])
        agent.state["phase"] = "recon"

        async def fake_approval(rid, kind, payload):
            return {"decision": "allow", "selections": ["10.0.0.2"]}
        agent.request_approval = fake_approval
        tc = ToolCall(id="t1", name="set_phase", arguments={"phase": "confirm_assets"})
        asyncio.run(agent.handle_tool(tc))
        self.assertFalse(agent.scope.check_target("10.0.0.1")[0])

        # 服务重启后的 _ensure_session 等价路径：同参数 + 同 workspace 重建
        meta = agent.ws.meta
        agent2 = Agent(_cfg(tmp, []), meta.get("mode"), meta.get("auth"),
                       meta.get("targets") or [], meta.get("scope") or {},
                       meta.get("task", ""), FakeBus(), workspace=agent.ws)
        self.assertTrue(agent2.ws.meta.get("assets_confirmed"))
        self.assertFalse(agent2.scope.check_target("10.0.0.1")[0], "被用户排除的资产恢复后不得变成可打")
        self.assertTrue(agent2.scope.check_target("10.0.0.2")[0])
        # 磁盘上的收紧 scope 也没有被覆盖放宽
        self.assertEqual((agent2.ws.meta.get("scope") or {}).get("cidrs"), ["10.0.0.2/32"])

    def test_unconfirmed_restore_still_migrates_scope(self):
        # 未确认资产的旧会话：merge 写回行为保持不变（旧会话 scope 为空的迁移路径）
        tmp = Path(tempfile.mkdtemp())
        ws = Workspace(tmp, "s_mig", {"mode": "pentest", "task": "测试", "targets": ["192.0.2.10"]})
        agent = Agent(_cfg(tmp, []), "pentest", "default", ["192.0.2.10"], {}, "测试", FakeBus(), workspace=ws)
        self.assertNotIn("assets_confirmed", agent.ws.meta)
        self.assertTrue(agent.scope.check_target("192.0.2.10")[0])


class TestCompressBoundary(unittest.TestCase):
    """压缩保留段不能以 tool 消息开头，否则序列非法、两个协议端点都 400。"""

    def test_recent_window_never_starts_with_tool(self):
        tmp = Path(tempfile.mkdtemp())
        cfg = _cfg(tmp, [])
        cfg["llm"]["main"]["context_window"] = 100  # 缩窗强制越过压缩阈值
        cfg["llm"]["fast"] = {"provider": "mock", "model": "m", "responses": ["工作笔记内容"]}
        agent = Agent(cfg, "pentest", "default", ["192.0.2.10"], {}, "测试", FakeBus(), ws_root=tmp)
        msgs = [Message(role="system", content="sys")]
        for i in range(9):
            msgs.append(Message(role="user", content=f"任务{i} " + "x" * 300))
            msgs.append(Message(role="assistant", content=None,
                                tool_calls=[{"id": f"c{i}", "name": "send_http_request", "arguments": {}}]))
            msgs.append(Message(role="tool", content="响应" + "y" * 300, tool_call_id=f"c{i}",
                                name="send_http_request"))
        msgs.append(Message(role="tool", content="尾部", tool_call_id="c8", name="send_http_request"))
        agent.messages = msgs
        self.assertEqual(msgs[-8].role, "tool")  # 旧实现会把 tool 留在保留段开头

        asyncio.run(agent.maybe_compress())
        self.assertNotEqual(agent.messages[2].role, "tool")
        # 用 OpenAI 协议实际转换验证合法性：第一条 tool 前必须存在带 tool_calls 的 assistant
        from pentest_agent.llm.openai_compat import OpenAICompatProvider
        oa = OpenAICompatProvider({"model": "m", "api_key": "k", "base_url": "http://x"})
        conv = [oa._convert(m) for m in agent.messages]
        first_tool = next(i for i, c in enumerate(conv) if c["role"] == "tool")
        self.assertTrue(any(c["role"] == "assistant" and c.get("tool_calls") for c in conv[:first_tool]))


class TestDanglingMultiToolRepair(unittest.TestCase):
    """一轮多个工具调用执行到一半被中断：恢复时必须就地补齐缺失的 tool 结果。"""

    def test_partial_tool_results_repaired_in_place(self):
        tmp = Path(tempfile.mkdtemp())
        ws = Workspace(tmp, "s_mt", {"mode": "pentest", "task": "测试", "targets": ["192.0.2.10"]})
        agent = Agent(_cfg(tmp, []), "pentest", "default", ["192.0.2.10"], {}, "测试", FakeBus(), workspace=ws)
        history = [
            {"role": "user", "content": "任务"},
            {"role": "assistant", "content": "", "tool_calls": [
                {"id": "c1", "name": "send_http_request", "arguments": {}},
                {"id": "c2", "name": "send_http_request", "arguments": {}}]},
            {"role": "tool", "content": "结果1", "tool_call_id": "c1", "name": "send_http_request"},
        ]
        agent.load_history(history)
        # assistant 之后依次是：合成 c2 结果（就地插入）、真实 c1 结果
        tools_after = [m for m in agent.messages if m.role == "tool"]
        self.assertEqual([m.tool_call_id for m in tools_after], ["c2", "c1"])
        self.assertIn("中断恢复", tools_after[0].content)
        self.assertEqual(tools_after[1].content, "结果1")
        # OpenAI 协议转换后 tool 消息仍紧跟 assistant（load_history 末尾会把 system 刷新到队首）
        from pentest_agent.llm.openai_compat import OpenAICompatProvider
        oa = OpenAICompatProvider({"model": "m", "api_key": "k", "base_url": "http://x"})
        conv = [oa._convert(m) for m in agent.messages]
        self.assertEqual([c["role"] for c in conv],
                         ["system", "user", "assistant", "tool", "tool"])

    def test_trailing_dangling_still_patched(self):
        # 原有场景（末条 assistant 带全部未答复调用）保持兼容
        tmp = Path(tempfile.mkdtemp())
        ws = Workspace(tmp, "s_td", {"mode": "pentest", "task": "测试", "targets": ["192.0.2.10"]})
        agent = Agent(_cfg(tmp, []), "pentest", "default", ["192.0.2.10"], {}, "测试", FakeBus(), workspace=ws)
        agent.load_history([
            {"role": "user", "content": "任务"},
            {"role": "assistant", "content": "我来测试", "tool_calls": [{"id": "c1", "name": "run_tool", "arguments": {}}]},
        ])
        self.assertEqual(agent.messages[-1].role, "tool")
        self.assertEqual(agent.messages[-1].tool_call_id, "c1")


class TestShutdownKeepsFinishedRecords(unittest.TestCase):
    """stop 不能把已完成子 agent 的记录覆盖成 cancelled。"""

    def test_shutdown_not_overwrite_completed_sub(self):
        tmp = Path(tempfile.mkdtemp())
        agent = Agent(_cfg(tmp, []), "pentest", "default", ["192.0.2.10"], {}, "测试", FakeBus(), ws_root=tmp)
        agent.ws.save_agent_record("a1", name="s1", task="子任务", status="completed", last_summary="完成")
        agent.subagents["a1"] = {"agent": None, "task": None, "name": "s1", "record": {}}
        agent.shutdown()
        self.assertEqual(agent.ws.load_agent_record("a1").get("status"), "completed")


if __name__ == "__main__":
    unittest.main()
