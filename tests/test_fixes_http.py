"""HTTP 原子能力 / 事件总线 / scope / 配置占位符回归测试。

覆盖:重复请求头保真(证据与实发一致)、effective_timeout、审批事件不被队列丢弃、
IPv6 带端口目标、无效 CIDR 显式提示、${ENV} 占位符保留。
"""
import asyncio
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from pentest_agent.config import preserve_placeholder
from pentest_agent.core.events import EventBus
from pentest_agent.policy.scope import Scope
from pentest_agent.tools.base import ToolContext
from pentest_agent.tools.http_request import RawHttpAdapter
from pentest_agent.workspace.session import Workspace


class _EchoHeaders(BaseHTTPRequestHandler):
    seen = []

    def _route(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        _EchoHeaders.seen.append(list(self.headers.items()))
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")

    do_GET = _route

    def log_message(self, *a):
        pass


class TestDuplicateHeaders(unittest.TestCase):
    def test_duplicate_headers_reach_server_and_evidence(self):
        srv = HTTPServer(("127.0.0.1", 0), _EchoHeaders)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            tmp = Path(tempfile.mkdtemp())
            ws = Workspace(tmp, "s_http", {"mode": "pentest"})
            adapter = RawHttpAdapter()
            ctx = ToolContext(ws=ws, scope=Scope({"allow_all": True}), mode="pentest", auth="full",
                              cfg={}, state={}, emit=None, call_id="c1")
            raw = f"GET / HTTP/1.1\nHost: 127.0.0.1:{port}\nX-Test: a\nX-Test: b\n\n"
            args = adapter.validate_input({"raw_request": raw, "scheme": "http"})
            res = asyncio.run(adapter.execute(args, ctx))
            self.assertEqual(res.data["status"], 200)
            # 服务端真收到了两条 X-Test(之前被 dict 合并成一条)
            names = [k.lower() for k, _v in _EchoHeaders.seen[-1]]
            self.assertEqual(names.count("x-test"), 2)
            # 落盘证据与实际发送一致:两条都在
            ev = (ws.dir / res.evidence[0]).read_text(encoding="utf-8")
            self.assertEqual(ev.lower().count("x-test:"), 2)
        finally:
            srv.shutdown()


class TestEffectiveTimeout(unittest.TestCase):
    def test_http_uses_args_timeout(self):
        a = RawHttpAdapter()
        args = a.validate_input({"raw_request": "GET / HTTP/1.1\nHost: x\n\n", "timeout": 300})
        self.assertEqual(a.effective_timeout(args), 300)
        args2 = a.validate_input({"raw_request": "GET / HTTP/1.1\nHost: x\n\n"})
        self.assertEqual(a.effective_timeout(args2), 60)

    def test_base_adapter_defaults(self):
        from pentest_agent.tools.base import ToolAdapter

        self.assertEqual(ToolAdapter().effective_timeout(None), ToolAdapter.timeout)


class TestApprovalEventNotDropped(unittest.IsolatedAsyncioTestCase):
    async def test_approval_evicts_oldest_when_full(self):
        bus = EventBus(max_queue=2)
        q = bus.subscribe()
        await bus.emit("status", {"n": 1})
        await bus.emit("status", {"n": 2})
        await bus.emit("approval_request", {"request_id": "r1"})  # 队列满:挤掉最旧而不是丢审批
        got = []
        while not q.empty():
            got.append(q.get_nowait())
        self.assertEqual([e["type"] for e in got], ["status", "approval_request"])
        self.assertEqual(got[-1]["data"]["request_id"], "r1")


class TestScopeIPv6AndBadCidr(unittest.TestCase):
    def test_bracketed_ipv6_with_port(self):
        s = Scope({"cidrs": ["::1/128"]})
        ok, _ = s.check_target("[::1]:8080")
        self.assertTrue(ok)

    def test_bare_ipv6(self):
        s = Scope({"cidrs": ["2001:db8::/32"]})
        ok, _ = s.check_target("2001:db8::1")
        self.assertTrue(ok)

    def test_bad_cidr_surfaced_in_describe(self):
        s = Scope({"cidrs": ["10.0.0.0/24", "not-a-cidr"]})
        self.assertEqual(len(s.cidrs), 1)
        self.assertIn("not-a-cidr", s.describe())


class TestPreservePlaceholder(unittest.TestCase):
    def test_keeps_placeholder_when_unchanged(self):
        import os
        import unittest.mock

        with unittest.mock.patch.dict(os.environ, {"GLM_KEY": "abc123"}):
            # 表单回传的是展开值;用户没改就不该把 key 固化进 yaml
            self.assertEqual(preserve_placeholder("${GLM_KEY}", "abc123"), "${GLM_KEY}")

    def test_writes_new_value_when_edited(self):
        self.assertEqual(preserve_placeholder("${GLM_KEY}", "new-key"), "new-key")

    def test_plain_value_passthrough(self):
        self.assertEqual(preserve_placeholder("plain", "plain"), "plain")


if __name__ == "__main__":
    unittest.main()
