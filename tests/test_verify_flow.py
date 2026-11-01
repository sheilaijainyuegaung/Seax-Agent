"""验证流程回归测试:候选 → 独立验证者 → 报告。

锁定:
- record_finding 一律产生候选,进不了报告正文
- verify_finding 只能由子 agent(验证者)调用,主 agent 调用被拒
- verified 机械门槛:≥2 条入库之后新发送的 http 请求报文(payload+对照)
- rejected 至少 1 条新报文,且回流失败记忆
- 旧 findings 无 status 视为 verified(向后兼容)
"""
import asyncio
import tempfile
import unittest
from pathlib import Path

from pentest_agent.core.agent import Agent
from pentest_agent.llm.base import ToolCall
from pentest_agent.workspace.session import Workspace, finding_status


class FakeBus:
    def __init__(self):
        self.events = []

    async def emit(self, etype, data, agent=""):
        self.events.append((etype, data, agent))


def _cfg(tmp: Path, responses):
    return {
        "llm": {"main": {"provider": "mock", "model": "m", "responses": responses},
                "fast": {"provider": "mock", "model": "m", "responses": [""]}},
        "policy": {"max_rounds": 8, "distill_on_finish": False},
        "workspace_dir": str(tmp),
        "tools": {"dir": ""},
        "skills": {"dir": str(tmp / "skills")},
    }


def _write_http(ws: Workspace, n: int, tag: str = ""):
    prefix = f"{tag}_" if tag else ""
    (ws.evidence_dir / f"{prefix}http_{n}_request.txt").write_text(
        f"GET /?id={n} HTTP/1.1\nHost: 192.0.2.10\n\n", encoding="utf-8")
    (ws.evidence_dir / f"{prefix}http_{n}_response.txt").write_text(
        f"HTTP/1.1 200 OK\n\nresp-{n}", encoding="utf-8")


def _record(agent: Agent, title="疑似SQL注入"):
    tc = ToolCall(id="r1", name="record_finding", arguments={
        "title": title, "severity": "high", "target": "192.0.2.10",
        "description": "id 参数疑似注入", "evidence": ["evidence/http_1_request.txt"]})
    return asyncio.run(agent.handle_tool(tc))


def _verify(agent: Agent, fid=1, verdict="verified", evidence=None, note="1=1 与 1=2 响应可区分"):
    tc = ToolCall(id="v1", name="verify_finding", arguments={
        "id": fid, "verdict": verdict,
        "evidence": evidence if evidence is not None else
                    ["evidence/http_2_request.txt", "evidence/http_3_request.txt"],
        "note": note})
    return asyncio.run(agent.handle_tool(tc))


class TestVerifyFlow(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.bus = FakeBus()
        # 主 agent:发现者(默认档位,scope 放开)
        self.agent = Agent(_cfg(self.tmp, []), "pentest", "default", ["192.0.2.10"],
                           {"allow_all": True}, "测试", self.bus, ws_root=self.tmp)
        _write_http(self.agent.ws, 1)
        self.msg = _record(self.agent)

    def _verifier(self, name="verify-1", aid="a1") -> Agent:
        sub = Agent(_cfg(self.tmp, []), "pentest", "default", ["192.0.2.10"],
                    {"allow_all": True}, "验证任务", self.bus,
                    workspace=self.agent.ws, is_sub=True, name=name,
                    parent=self.agent, agent_id=aid)
        return sub

    # ---------- 入库即候选 ----------
    def test_record_creates_candidate(self):
        self.assertIn("候选漏洞已记录", self.msg.content)
        f = self.agent.ws.findings[0]
        self.assertEqual(finding_status(f), "candidate")
        self.assertEqual(f.get("req_seq_at_create"), 0)  # 会话实际发包数为 0(证据文件是预置的)
        self.assertEqual(f.get("recorded_by"), "main")   # 发现者身份落库,供自验隔离
        # findings.md:进候选区,不进已验证区
        md = (self.agent.ws.dir / "findings.md").read_text(encoding="utf-8")
        self.assertIn("待验证候选", md)
        self.assertNotIn("已独立验证", md.split("待验证候选")[0])

    def test_candidate_not_in_report_main_body(self):
        self.agent.ws.write_report(overview="ov")
        report = (self.agent.ws.dir / "report.md").read_text(encoding="utf-8")
        self.assertIn("附录 A：待验证候选", report)
        self.assertIn("仅计已独立验证", report)
        # 标题出现在附录之后,不在详情节
        self.assertGreater(report.index("疑似SQL注入"), report.index("附录 A"))

    # ---------- 身份隔离 ----------
    def test_main_agent_cannot_verify(self):
        _write_http(self.agent.ws, 2)
        _write_http(self.agent.ws, 3)
        msg = _verify(self.agent)
        self.assertIn("只能由独立验证者", msg.content)
        self.assertEqual(finding_status(self.agent.ws.findings[0]), "candidate")

    # ---------- 双新报文门槛 + 证据归属 ----------
    def test_verified_requires_two_new_requests(self):
        sub = self._verifier()
        vtag = "verify-1_a1"  # 验证者证据文件前缀
        # 模拟"入库前会话已发送 5 个请求":之后编号 >5 的才算新证据
        self.agent.state["req_seq"] = 5
        for n in range(1, 8):
            _write_http(self.agent.ws, n)                    # 无 tag:主 agent/他人的报文
            _write_http(self.agent.ws, n, tag="verify-1_a1")  # 验证者本人的报文
        tc = ToolCall(id="r2", name="record_finding", arguments={
            "title": "注入二号", "severity": "high", "target": "192.0.2.10",
            "description": "d", "evidence": ["evidence/http_5_request.txt"]})
        asyncio.run(self.agent.handle_tool(tc))
        f2 = self.agent.ws.findings[-1]
        self.assertEqual(f2.get("req_seq_at_create"), 5)

        # 只有 1 条新报文 → 拒绝
        msg = _verify(sub, fid=2, evidence=[f"evidence/{vtag}_http_6_request.txt"])
        self.assertIn("2 条", msg.content)
        # 旧报文(编号 ≤ 5)不算新证据 → 有效仅 1 条 → 拒绝
        msg = _verify(sub, fid=2, evidence=[f"evidence/{vtag}_http_2_request.txt",
                                            f"evidence/{vtag}_http_6_request.txt"])
        self.assertIn("2 条", msg.content)
        # 同一文件重复算一条 → 拒绝
        msg = _verify(sub, fid=2, evidence=[f"evidence/{vtag}_http_6_request.txt",
                                            f"evidence/{vtag}_http_6_request.txt"])
        self.assertIn("2 条", msg.content)
        # 借用他人/未署名报文 → 身份归属拒绝(必须验证者亲自发送)
        _write_http(self.agent.ws, 6)  # 无 tag 的 http_6(像是别人的)
        msg = _verify(sub, fid=2, evidence=["evidence/http_6_request.txt",
                                            f"evidence/{vtag}_http_7_request.txt"])
        self.assertIn("亲自发送", msg.content)
        # 合规:2 条不同新报文(payload+对照),均为验证者本人 → 通过
        msg = _verify(sub, fid=2, evidence=[f"evidence/{vtag}_http_6_request.txt",
                                            f"evidence/{vtag}_http_7_request.txt"])
        self.assertIn("已标记 verified", msg.content)
        f2 = self.agent.ws.findings[-1]
        self.assertEqual(finding_status(f2), "verified")
        self.assertEqual(f2.get("verified_by"), "a1")
        self.assertEqual(f2.get("verified_by_name"), "verify-1")
        self.assertIn(f"evidence/{vtag}_http_6_request.txt", f2.get("verify_evidence", []))
        # 进报告正文
        self.agent.ws.write_report(overview="ov")
        report = (self.agent.ws.dir / "report.md").read_text(encoding="utf-8")
        self.assertIn("已独立验证(验证者: verify-1)", report)
        # 全部已验证时无附录;标题在详情节、资产清单之前
        self.assertGreater(report.index("注入二号"), report.index("漏洞详情"))
        self.assertLess(report.index("注入二号"), report.index("四、资产清单"))

    def test_discoverer_sub_cannot_self_verify(self):
        # 发现者是子 agent 时同样不得自验(recorded_by == verified_by 即拒绝)
        sub = self._verifier()
        _write_http(self.agent.ws, 1)
        tc = ToolCall(id="r3", name="record_finding", arguments={
            "title": "subA的发现", "severity": "high", "target": "192.0.2.10",
            "description": "d", "evidence": ["evidence/http_1_request.txt"]})
        asyncio.run(sub.handle_tool(tc))
        _write_http(self.agent.ws, 2, tag="verify-1_a1")
        _write_http(self.agent.ws, 3, tag="verify-1_a1")
        msg = _verify(sub, fid=2, evidence=["evidence/verify-1_a1_http_2_request.txt",
                                            "evidence/verify-1_a1_http_3_request.txt"])
        self.assertIn("发现者不得自验", msg.content)
        self.assertEqual(finding_status(self.agent.ws.findings[-1]), "candidate")

    def test_rejected_records_failure_memory(self):
        sub = self._verifier()
        _write_http(self.agent.ws, 2, tag="verify-1_a1")
        msg = _verify(sub, verdict="rejected", evidence=["evidence/verify-1_a1_http_2_request.txt"],
                      note="对照请求无差异,注入不成立")
        self.assertIn("已标记 rejected", msg.content)
        self.assertEqual(finding_status(self.agent.ws.findings[0]), "rejected")
        fails = self.agent.ws.memory.data.get("failures") or []
        self.assertTrue(any("误报排除" in str(x.get("summary")) for x in fails))
        report = self.agent.ws.write_report(overview="ov")
        report = (self.agent.ws.dir / "report.md").read_text(encoding="utf-8")
        self.assertIn("附录 B：已排除误报", report)

    def test_missing_finding_and_bad_verdict(self):
        sub = self._verifier()
        msg = _verify(sub, fid=99)
        self.assertIn("不存在", msg.content)
        msg = _verify(sub, verdict="maybe")
        self.assertIn("verified / rejected", msg.content)

    # ---------- 向后兼容 ----------
    def test_legacy_finding_without_status_is_verified(self):
        ws = Workspace(self.tmp, "s_legacy", {"mode": "pentest"})
        _write_http(ws, 1)
        ws.add_finding({"title": "旧漏洞", "severity": "high", "evidence": ["evidence/http_1_request.txt"]})
        # 模拟旧数据:去掉 status
        import json
        fp = ws.dir / "findings.json"
        data = json.loads(fp.read_text(encoding="utf-8"))
        for f in data:
            f.pop("status", None)
        fp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        report = ws.write_report(overview="ov")
        report = (ws.dir / "report.md").read_text(encoding="utf-8")
        self.assertIn("旧漏洞", report.split("附录")[0])
        self.assertNotIn("待验证候选", report)

    def test_memory_render_shows_status(self):
        text = self.agent.ws.memory.render(self.agent.ws.assets, self.agent.ws.findings, [])
        self.assertIn("[候选]", text)


if __name__ == "__main__":
    unittest.main()
