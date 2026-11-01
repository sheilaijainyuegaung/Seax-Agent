"""MCP 客户端 HTTP transport 测试：用 httpx MockTransport 模拟远端 MCP server 响应。"""
import asyncio
import json
import os
import unittest

import httpx

from pentest_agent.mcp_client import MCPServer


class TestHttpTransport(unittest.TestCase):
    def _http_srv(self, handler):
        srv = MCPServer("test", {"transport": "http", "url": "http://127.0.0.1:9876/sse"})
        srv._http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        return srv

    def test_request_http_json(self):
        def handler(request):
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": json.loads(request.content)["id"],
                                             "result": {"tools": [{"name": "t1"}]}},
                                  headers={"content-type": "application/json"})
        srv = self._http_srv(handler)
        result = asyncio.run(srv._request("tools/list", {}, 10))
        self.assertEqual(result, {"tools": [{"name": "t1"}]})

    def test_request_http_sse(self):
        def handler(request):
            body = 'event: message\ndata: {"jsonrpc":"2.0","id":1,"result":{"tools":[]}}\n\n'
            return httpx.Response(200, text=body, headers={"content-type": "text/event-stream"})
        srv = self._http_srv(handler)
        result = asyncio.run(srv._request("tools/list", {}, 10))
        self.assertEqual(result, {"tools": []})

    def test_request_http_non_200(self):
        def handler(request):
            return httpx.Response(500, text="boom")
        srv = self._http_srv(handler)
        with self.assertRaises(RuntimeError):
            asyncio.run(srv._request("tools/list", {}, 10))

    def test_request_http_error_field(self):
        def handler(request):
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "error": {"code": -1, "message": "bad"}},
                                  headers={"content-type": "application/json"})
        srv = self._http_srv(handler)
        with self.assertRaises(RuntimeError):
            asyncio.run(srv._request("tools/list", {}, 10))

    def test_stdio_transport_still_recognized(self):
        srv = MCPServer("test", {"transport": "stdio", "command": "npx", "args": ["x"]})
        self.assertEqual(srv.transport, "stdio")
        self.assertEqual(srv.command, "npx")

    def test_windows_cmd_shim_is_resolved(self):
        srv = MCPServer("test", {"transport": "stdio", "command": "npx", "args": ["--version"]})
        argv = srv._stdio_argv()
        if os.name == "nt":
            self.assertTrue(argv[0].lower().endswith(("node.exe", "cmd.exe")))
            self.assertTrue(any(part.lower().endswith(("npx-cli.js", "npx.cmd", "npx.bat")) for part in argv))
        else:
            self.assertEqual(argv[-1], "--version")

    def test_legacy_sse_endpoint_and_message(self):
        async def run():
            srv = MCPServer("test", {"transport": "sse", "url": "http://127.0.0.1:9876/"})
            loop = asyncio.get_running_loop()
            srv._sse_endpoint_ready = loop.create_future()
            srv._handle_sse_event("endpoint", "?sessionId=abc", "http://127.0.0.1:9876/")
            self.assertEqual(srv._post_url, "http://127.0.0.1:9876/?sessionId=abc")
            fut = loop.create_future()
            srv._pending[7] = fut
            srv._handle_sse_event(
                "message", '{"jsonrpc":"2.0","id":7,"result":{"tools":[]}}', srv.url
            )
            self.assertEqual(await fut, {"tools": []})

        asyncio.run(run())


if __name__ == "__main__":
    unittest.main()


class TestMCPNameDedup(unittest.IsolatedAsyncioTestCase):
    async def test_normalized_name_collision_deduped(self):
        """_safe() 归一化撞名(get-user/get_user)时加序号,不能互相覆盖注册表。"""
        import tempfile
        import unittest.mock
        from pathlib import Path

        from pentest_agent import mcp_client as mcp_mod
        from pentest_agent.core.agent import Agent
        from pentest_agent.core.events import EventBus

        class _Srv:
            trust = False
            tools = [{"name": "get-user", "description": "u1", "inputSchema": {}},
                     {"name": "get_user", "description": "u2", "inputSchema": {}}]

        async def fake_get_or_start(name, cfg):
            return _Srv()

        tmp = Path(tempfile.mkdtemp())
        cfg = {
            "llm": {"main": {"provider": "mock", "model": "m"}},
            "policy": {},
            "workspace_dir": str(tmp),
            "tools": {"dir": ""},
            "skills": {"dir": str(tmp / "skills")},
            "mcp": {"servers": {"fake": {"command": "whatever"}}},
        }
        agent = Agent(cfg, "pentest", "default", ["192.0.2.10"], {}, "测试", EventBus(), ws_root=tmp)
        with unittest.mock.patch.object(mcp_mod, "get_or_start", fake_get_or_start):
            await agent.setup_mcp()
        names = sorted(n for n in agent.registry if n.startswith("mcp_fake_"))
        self.assertEqual(len(names), 2)
        self.assertNotEqual(names[0], names[1])
