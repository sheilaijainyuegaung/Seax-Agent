"""PT-Agent 功能自检：用假 LLM 驱动完整 agent 循环，不依赖真实 API、不接触外网目标。

运行: python tests/functional_check.py
覆盖: 渗透模式全流程 / 红队资产卡点 / scope 拦截 / 破坏性拦截 / 用户拒绝 /
      上下文压缩 / 双协议消息转换 / 编码回退 / 原始报文解析
"""
import asyncio
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pentest_agent.core.agent import Agent
from pentest_agent.core.events import EventBus
from pentest_agent.llm.base import LLMProvider, LLMResponse, Message, ToolCall
from pentest_agent.tools.run_command import RunCommandAdapter
from pentest_agent.workspace.session import finding_status

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(("  ✅ " if cond else "  ❌ ") + name + (f"  ← {detail}" if (detail and not cond) else ""))


def call(_tool, **kwargs):
    return ToolCall(id=f"c_{_tool}_{abs(hash(json.dumps(kwargs, sort_keys=True, default=str))) % 99999}",
                    name=_tool, arguments=kwargs)


class FakeProvider(LLMProvider):
    """按剧本吐工具调用/文本。main 剧本给主 agent，sub 剧本给子 agent（按系统提示词区分）。"""

    def __init__(self, scripted=None, sub_scripted=None):
        super().__init__({"model": "fake", "base_url": "http://fake", "api_key": "k"})
        self.main_q = list(scripted or [])
        self.sub_q = list(sub_scripted or [])

    async def chat(self, messages, tools, on_delta=None, on_reasoning=None):
        await asyncio.sleep(0)  # 模拟真实网络 IO 的让出，避免事件收集器被饿死
        is_sub = any(m.role == "system" and "子 agent「" in (m.content or "") for m in messages)
        q = self.sub_q if is_sub else self.main_q
        if is_sub and not q:
            # 纯文本兜底：若子剧本里已有 finish，agent 会正常 break，不会覆盖总结
            return LLMResponse(text="(子任务剧本结束)")
        if not q:
            return LLMResponse(text="(剧本已结束，等待 agent 收尾)")
        item = q.pop(0)
        if isinstance(item, str):
            return LLMResponse(text=item)
        return LLMResponse(text="", tool_calls=item)


def make_agent(mode, auth, scope, scripted, tmp, cfg_extra=None, targets=None):
    cfg = {"llm": {"main": {"provider": "x", "model": "fake"}},
           "workspace_dir": str(tmp), "policy": {}}
    cfg.update(cfg_extra or {})
    agent = Agent(cfg, mode, auth, list(targets) if targets is not None else [], scope, "", EventBus())
    fake = FakeProvider(scripted)
    agent.router.main = fake
    agent.router.fast = fake
    return agent


async def run_collected(agent, decision="allow", selections=None, user_text=None):
    """收集全部事件并自动应答审批。user_text 非空时作为新一轮用户消息。"""
    q = agent.bus.subscribe()
    events = []

    async def _loop():
        while True:
            ev = await q.get()
            events.append(ev)
            if ev["type"] == "approval_request":
                agent.resolve_approval(ev["data"]["request_id"], decision, selections)

    t = asyncio.create_task(_loop())
    await agent.run(user_text=user_text)
    await asyncio.sleep(0.1)  # 给收集器留出排空尾部事件（done）的时间
    t.cancel()
    await asyncio.gather(t, return_exceptions=True)
    return events


def audit_events(agent):
    path = agent.ws.dir / "audit.jsonl"
    if not path.exists():
        return []
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


RAW_REQ = "POST /api/login HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nu=admin&p=1"
RAW_RESP = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>ok</html>"


async def scenario_pentest(tmp):
    print("\n▶ 场景 A：渗透模式全流程（含 POST 确认 + 本地靶机成功路径）")
    # 起一个本地 HTTP 服务当"靶机"，让 send_http_request 走真实成功路径
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import threading

    class Handler(BaseHTTPRequestHandler):
        def _resp(self):
            body = b"<html>ok-response</html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_GET = do_POST = _resp

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        raw_req = ("POST /api/login HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
                   "Content-Type: application/x-www-form-urlencoded\r\n\r\nu=admin&p=1" % port)
        agent = make_agent("pentest", "default", {"cidrs": ["127.0.0.0/8"]}, [
            [call("save_assets", assets=[{"target": "127.0.0.1", "type": "ip", "source": "manual"}]),
             call("send_http_request", raw_request=raw_req)],
            [call("record_finding", title="测试漏洞-登录点", severity="high", target="http://127.0.0.1/api/login",
                  description="测试描述", evidence=["evidence/http_1_request.txt"], remedy="修复它")],
            [],
        ], tmp)
        events = await run_collected(agent)

        check("A1 POST 触发了人工确认", any(e["type"] == "approval_request" and e["data"].get("kind") == "confirm"
                                              and e["data"].get("tool") == "send_http_request" for e in events))
        check("A2 原子HTTP 真实收到响应", any(e["type"] == "tool_end" and e["data"]["tool"] == "send_http_request"
                                                and e["data"]["status"] == "ok" for e in events))
        check("A3 漏洞自动入库", agent.ws.status()["findings"] == 1)
        check("A4 报告已生成", (agent.ws.dir / "report.md").exists())
        findings_md = (agent.ws.dir / "findings.md").read_text(encoding="utf-8")
        check("A5 findings.md 含原始请求包", "原始请求包" in findings_md and "POST /api/login" in findings_md)
        check("A6 findings.md 含原始响应包", "原始响应包" in findings_md and "200 OK" in findings_md)
        bound = next((f for f in agent.ws.findings if not f.get("duplicate")), {})
        ev_req = agent.ws.dir / (bound.get("request_evidence") or "")
        ev_content = open(ev_req, "r", encoding="utf-8", newline="").read() if ev_req.is_file() else ""
        check("A7 入库绑的是本会话 http 证据",
              bound.get("request_evidence") == "evidence/http_1_request.txt"
              and "POST /api/login" in ev_content)
        ev_http = agent.ws.dir / "evidence" / "http_1_response.txt"
        check("A8 原子HTTP 响应证据落盘", ev_http.exists() and "ok-response" in ev_http.read_text(encoding="utf-8"))
        check("A9 审计日志记录了工具调用", any(a.get("event") == "tool_call" for a in audit_events(agent)))
        check("A9b 本轮自然收尾", any(e["type"] == "turn_done" for e in events))
    finally:
        srv.shutdown()

    # A10/A11：任务结束后继续对话（对话 agent 的核心体验）
    n_before = len(agent.messages)
    agent.router.main.main_q.append("续聊完成：80 端口是 nginx")
    events2 = await run_collected(agent, user_text="再看看 80 端口的指纹")
    check("A10 结束后发消息可继续对话", len(agent.messages) > n_before
          and any(e["type"] == "status" and "收到新消息" in (e["data"].get("text") or "") for e in events2))
    check("A11 续聊结果正常收尾", "80 端口" in agent.state.get("last_text", "")
          and any(e["type"] == "turn_done" for e in events2))

    agent_rej = make_agent("pentest", "full", {"allow_all": True}, [
        [call("record_finding", title="未验证", severity="high", target="http://127.0.0.1/",
              description="编造")],
        [],
    ], tmp / "a12")
    ev_rej = await run_collected(agent_rej)
    check("A12 无证据 record_finding 不入库",
          agent_rej.ws.status()["findings"] == 0
          and any(e["type"] == "tool_end" and e["data"].get("tool") == "record_finding"
                  and "必须绑定" in (e["data"].get("summary") or "") for e in ev_rej))


async def scenario_redteam_checkpoint(tmp):
    print("\n▶ 场景 B：红队模式“确认资产”卡点")
    agent = make_agent("redteam", "default", {"cidrs": ["127.0.0.0/8"]}, [
        [call("save_assets", assets=[{"target": "127.0.0.1", "type": "ip"},
                                     {"target": "127.0.0.2", "type": "ip"}]),
         call("update_world", hypothesis="验证确认资产上的 HTTP 服务", priority="P0", status="open",
              from_facts=["f001"]),
         call("set_phase", phase="attack")],
        [call("send_http_request", raw_request="GET / HTTP/1.1\r\nHost: 127.0.0.2\r\n\r\n"),
         call("send_http_request", raw_request="GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")],
        [],
    ], tmp)
    events = await run_collected(agent, decision="allow", selections=["127.0.0.1"])

    reqs = [e for e in events if e["type"] == "approval_request" and e["data"].get("kind") == "asset_confirm"]
    check("B1 侦察结束弹出资产确认", len(reqs) == 1 and len(reqs[0]["data"]["assets"]) == 2)
    check("B2 确认后进入攻击阶段", agent.state["assets_confirmed"] is True
          and any(e["type"] == "phase" and e["data"]["phase"] == "attack" for e in events))
    check("B3 只保留勾选的资产为攻击范围", agent.ws.meta.get("assets_selected") == ["127.0.0.1"])
    check("B4 未勾选资产随后被 scope 拦截",
          any(a.get("event") == "scope_block" and "127.0.0.2" in str(a.get("target", ""))
              for a in audit_events(agent)))
    check("B5 确认后 live scope 已收紧",
          not agent.scope.allow_all
          and agent.scope.check_target("127.0.0.1")[0]
          and not agent.scope.check_target("127.0.0.2")[0])
    check("B6 确认后留档原始授权范围", agent.ws.meta.get("scope_original") is not None)

    from pentest_agent.workspace.session import Workspace as _WS
    ws2 = _WS(tmp, "empty_confirm_test", {"scope": {"allow_all": True}})
    cfg2 = ws2.apply_confirmed_scope([])
    check("B7 空资产确认不把 scope 锁成拒绝一切", bool(cfg2.get("allow_all")) is True)


async def scenario_scope_block(tmp):
    print("\n▶ 场景 C：scope 出界拦截")
    agent = make_agent("pentest", "full", {"domains": ["example.com"]}, [
        [call("send_http_request", raw_request="GET / HTTP/1.1\r\nHost: evil.com\r\n\r\n")],
        [],
    ], tmp)
    events = await run_collected(agent)
    check("C1 出界目标被拦截且未发请求", any(a.get("event") == "scope_block" for a in audit_events(agent))
          and any(e["type"] == "tool_end" and e["data"]["status"] == "blocked" for e in events))


async def scenario_dangerous(tmp):
    print("\n▶ 场景 D：破坏性命令拦截 / 用户拒绝")
    agent = make_agent("redteam", "full", {"allow_all": True}, [
        [call("run_command", command="rm -rf C:/temp")],
        [],
    ], tmp)
    agent.registry["run_command"] = RunCommandAdapter()
    await run_collected(agent)
    check("D1 完全授权下 rm -rf 仍被拦截", any(a.get("event") == "policy_block" for a in audit_events(agent)))

    agent2 = make_agent("pentest", "default", {"allow_all": True}, [
        [call("run_command", command="format C:")],
        [],
    ], tmp)
    agent2.registry["run_command"] = RunCommandAdapter()
    events = await run_collected(agent2, decision="deny")
    check("D2 默认档位弹确认且用户拒绝生效", any(e["type"] == "approval_request" for e in events)
          and any(a.get("event") == "user_denied" for a in audit_events(agent2)))


async def scenario_compress(tmp):
    print("\n▶ 场景 E：上下文压缩（可选策略，窗口阈值）")
    agent = make_agent("pentest", "full", {"allow_all": True}, ["1) 目标 local.test 2) 已试路径"], tmp,
                       cfg_extra={"policy": {"auto_compress": True},
                                  "llm": {"main": {"provider": "x", "model": "fake", "context_window": 100}}})
    agent.messages = [Message(role="system", content="sys")]
    agent.messages += [Message(role="user" if i % 2 else "assistant", content="历史消息内容" * 300)
                       for i in range(20)]
    await agent.maybe_compress()
    check("E1 旧消息被压缩为工作笔记", len(agent.messages) == 1 + 1 + 8
          and agent.messages[1].content.startswith("[工作笔记"))
    check("E2 系统提示词保留", agent.messages[0].role == "system")


async def scenario_units():
    print("\n▶ 场景 F：单元件（协议转换 / 编码 / 报文解析）")
    from pentest_agent.llm.openai_compat import OpenAICompatProvider
    from pentest_agent.llm.anthropic import AnthropicProvider
    from pentest_agent.tools.exec import _decode
    from pentest_agent.tools.http_request import parse_raw_request

    msgs = [Message(role="system", content="s"), Message(role="user", content="u"),
            Message(role="assistant", content=None, tool_calls=[ToolCall(id="1", name="nmap", arguments={"targets": ["x"]})]),
            Message(role="tool", content="result", tool_call_id="1")]
    p = OpenAICompatProvider({"model": "m", "max_tokens": 4096})
    conv = [p._convert(m) for m in msgs]
    check("F30 openai_compat 读取 max_tokens", p.max_tokens == 4096)
    check("F1 OpenAI 兼容转换", conv[2]["tool_calls"][0]["function"]["name"] == "nmap"
          and json.loads(conv[2]["tool_calls"][0]["function"]["arguments"])["targets"] == ["x"]
          and conv[3]["role"] == "tool")

    ap = AnthropicProvider({"model": "m"})
    system, aconv = ap._convert(msgs)
    check("F2 Claude 协议转换（tool_result 归并 user）", system == "s" and len(aconv) == 3
          and aconv[2]["content"][0]["type"] == "tool_result")

    from pentest_agent.tools.registry import build_registry, tool_specs
    from pentest_agent.llm.base import normalize_tools
    tools = normalize_tools(tool_specs(build_registry()))
    names = [t["name"] for t in tools]
    check("F5 工具清单 payload 构造（dict specs，回归 173233 会话的崩溃点）",
          len(tools) == 15 and tools[0]["name"] == "send_http_request"
          and "read_evidence" in names and "finish" in names and "update_world" in names
          and "security_tool" in names and "verify_finding" in names
          and "nuclei" not in names and "nmap" not in names
          and all(t["name"] and "parameters" in t for t in tools))

    text = "中文编码回退测试" * 10
    check("F3 GBK 输出解码回退", _decode(text.encode("gbk")) == text)

    m, path, headers, body = parse_raw_request("POST /a HTTP/1.1\nHost: x.com\nA: b\n\ndata1")
    check("F4 Burp 风格报文解析", m == "POST" and path == "/a"
          and headers == [("Host", "x.com"), ("A", "b")] and body == "data1")

    from pentest_agent.policy.approval import decide
    from pentest_agent.policy.postex import scan_postex
    from pentest_agent.policy.scope import Scope
    from pentest_agent.policy.targets import extract_targets_from_text, merge_scope_cfg, scope_cfg_from_targets
    from pentest_agent.tools.http_request import extract_forms
    from pentest_agent.workspace.cookies import domain_ok, merge_cookie_header, parse_set_cookie, path_matches

    extracted = extract_targets_from_text(
        "sqlmap -u http://evil.com/login.php --batch && nmap 10.1.2.3"
    )
    check("F6 从命令行抽取 URL/IP", "http://evil.com/login.php" in extracted and "10.1.2.3" in extracted)
    cfg = scope_cfg_from_targets(["http://127.0.0.1/DVWA/login.php", "a.example.com"])
    check("F7 确认资产生成收紧 scope",
          cfg.get("allow_all") is False
          and "127.0.0.1/32" in cfg.get("cidrs", [])
          and "a.example.com" in cfg.get("domains", []))
    forms = extract_forms(
        '<form action="login.php" method="post">'
        '<input type="text" name="username">'
        '<input type="hidden" name="user_token" value="tok-abc">'
        "</form>"
    )
    check("F8 HTML 表单抽出 hidden token",
          forms and "user_token(hidden=tok-abc)" in forms[0] and "username(text)" in forms[0])
    merged = merge_cookie_header("sid=from-req", "sid=from-jar; extra=1")
    check("F9 Cookie 合并时请求包显式值优先",
          "sid=from-req" in merged and "extra=1" in merged and "from-jar" not in merged)
    check("F26 Domain=com 过宽被拒绝",
          parse_set_cookie("sid=x; Domain=com", "evil.com") is None
          and not domain_ok("com", "evil.com")
          and domain_ok("evil.com", "a.evil.com"))
    check("F27 Cookie path 不误配前缀",
          path_matches("/DVWA", "/DVWA/login")
          and not path_matches("/DVWA", "/DVWA-admin")
          and path_matches("/", "/show"))

    safe = extract_targets_from_text('curl -u admin:password -d "user=a&pw=b" http://127.0.0.1/login')
    check("F10 curl 认证/POST 参数不被误抽为目标（回归 -u/-d 歧义）",
          safe == ["http://127.0.0.1/login"])
    dom = extract_targets_from_text("subfinder --domain example.com -o out.txt")
    check("F11 无歧义长选项 --domain 仍能抽取目标", "example.com" in dom)
    empty = scope_cfg_from_targets([])
    check("F12 空资产不产出 scope（交由上层保持原授权）",
          not empty.get("domains") and not empty.get("cidrs"))
    merged = merge_scope_cfg(["http://127.0.0.1/DVWA"], {"domains": [], "cidrs": [], "allow_all": False})
    check("F28 只填目标也写入 scope",
          "127.0.0.1/32" in (merged.get("cidrs") or [])
          and "http://127.0.0.1/DVWA" in (merged.get("given") or []))
    sc = Scope(merged)
    check("F29 只填目标不再显示未配置",
          "未配置" not in sc.describe() and sc.check_target("127.0.0.1")[0]
          and sc.check_target("http://127.0.0.1/DVWA/login.php")[0])
    check("F13 裸域名 nmap target.com 能抽出",
          "target.com" in extract_targets_from_text("nmap -sV --open target.com"))
    check("F14 subfinder -d 域名能抽出且不误伤 curl -d",
          "evil.com" in extract_targets_from_text("subfinder -d evil.com -o out.txt"))
    from pentest_agent.tools.mcp_adapter import MCPToolAdapter
    mcp_ad = MCPToolAdapter("s", {"name": "fetch", "description": "x", "inputSchema": {}}, True)
    mcp_hits = mcp_ad.scope_targets({"url": "http://evil.com/a", "q": 1})
    check("F16 MCP 从参数 JSON 抽 URL", any("evil.com" in t for t in mcp_hits))
    check("F16b 无网络目标的 MCP 不误抽", mcp_ad.scope_targets({"a": 2, "b": 3}) == [])

    from pentest_agent.gui.server import find_session_dir, safe_session_file
    import tempfile as _tf
    _p = Path(_tf.mkdtemp(prefix="ptagent_path_"))
    sess = _p / "sid"
    evil = _p / "sid_evil"
    sess.mkdir(parents=True, exist_ok=True)
    evil.mkdir(parents=True, exist_ok=True)
    (sess / "ok.txt").write_text("in", encoding="utf-8")
    (evil / "secret.txt").write_text("out", encoding="utf-8")
    check("F17 证据路径 relative_to 挡住兄弟会话",
          safe_session_file(sess, "ok.txt") is not None
          and safe_session_file(sess, "../sid_evil/secret.txt") is None)

    custom_root = _p / "custom_ws"
    csid = "20260830_custom"
    (custom_root / csid).mkdir(parents=True)
    (custom_root / csid / "session.json").write_text("{}", encoding="utf-8")
    idx = _p / "index.json"
    idx.write_text(json.dumps({csid: str(custom_root)}), encoding="utf-8")
    found = find_session_dir({"workspace_dir": str(_p / "default_ws")}, csid, idx)
    check("F21 自定义工作区能解析会话目录",
          found is not None and found.resolve() == (custom_root / csid).resolve())

    seed_dir = _p / "seed_ws"
    seed_dir.mkdir()
    agent_seed = Agent(
        {"llm": {"main": {"provider": "x", "model": "fake"}}, "workspace_dir": str(seed_dir)},
        "pentest", "full", ["http://127.0.0.1/DVWA"], {}, "", EventBus(),
    )
    prompt = agent_seed.system_prompt()
    check("F33 给定目标写入资产且提示不再说未配置",
          any(a.get("target") == "http://127.0.0.1/DVWA" for a in agent_seed.ws.assets)
          and agent_seed.scope.check_target("127.0.0.1")[0]
          and "未配置" not in agent_seed.scope.describe()
          and "渗透模式纪律" in prompt
          and "禁止子域" in prompt)
    check("F34 渗透模式从 probe 开始而不是扩资产 recon",
          agent_seed.state["phase"] == "probe"
          and "recon" not in agent_seed.profile["phases"])
    check("F35 渗透模式不加载 subdomain-recon",
          all(s.get("name") != "subdomain-recon" for s in agent_seed.skills))
    check("F39 渗透开局自动加载 web-pentest 流程",
          "已自动加载技能 web-pentest" in prompt
          and "S1 探测" in prompt
          and any(s.get("name") == "sql-injection" for s in agent_seed.skills))
    agent_seed.ws.memory.update_world(signals=["SQLe"], hypothesis="login id", priority="P0", status="open")
    prompt2 = agent_seed.system_prompt()
    check("F38 信号自动加载 sql-injection 且假设写入世界模型",
          "按信号自动加载技能 sql-injection" in prompt2
          and "[P0][open] login id" in prompt2)

    from pentest_agent.workspace.session import Workspace as _WSbind
    bdir = Path(_tf.mkdtemp(prefix="ptagent_bind_"))
    wsb = _WSbind(bdir, "bind1", {"mode": "pentest"})
    (wsb.evidence_dir / "http_2_request.txt").write_text("GET / HTTP/1.1\nHost: x\n", encoding="utf-8")
    (wsb.evidence_dir / "http_2_response.txt").write_text("HTTP/1.1 200 OK\n\nok", encoding="utf-8")
    ok, err = wsb.bind_http_evidence(["evidence/http_2_request.txt"])
    check("F22 绑定本会话 http 证据并带上响应",
          err == "" and ok and ok["request_evidence"] == "evidence/http_2_request.txt"
          and ok["response_evidence"] == "evidence/http_2_response.txt")
    bad, berr = wsb.bind_http_evidence(["evidence/../session.json"])
    check("F23 入库证据不能逃出 evidence", bad is None and "不在本会话" in berr)
    none, nerr = wsb.bind_http_evidence([])
    check("F24 无证据拒绝绑定", none is None and "必须绑定" in nerr)
    rej = wsb.add_finding({"title": "假", "target": "x"})
    check("F25 add_finding 无证据拒绝", bool(rej.get("rejected")) and wsb.status()["findings"] == 0)

    check("F18 后渗透能识别读系统文件/命令/抽哈希",
          scan_postex("GET /fi/?page=../../windows/win.ini") == "读取系统敏感文件"
          and scan_postex("ip=1; ipconfig") == "系统命令执行"
          and scan_postex("secretsdump -just-dc") == "凭据/哈希转储")
    check("F19 登录口令与 id= 不误伤后渗透",
          scan_postex("username=admin&password=password") is None
          and scan_postex("GET /index.php?id=1 HTTP/1.1") is None)
    d1, _ = decide("pentest", "full", "read", postex_hit="读取系统敏感文件")
    d1b, _ = decide("pentest", "full", "read", postex_hit="读取系统敏感文件",
                    policy_cfg={"allow_postex_in_full": False})
    d2, _ = decide("redteam", "full", "read", postex_hit="读取系统敏感文件")
    d3, _ = decide("recon", "default", "read", postex_hit="读取系统敏感文件")
    check("F20 渗透后渗透:full 放行(可关)、默认档确认、红队放行、侦察拦截",
          d1 == "allow" and d1b == "confirm" and d2 == "allow" and d3 == "block")


async def scenario_subagent(tmp):
    print("\n▶ 场景 G：子 agent 并发派生与结果收取")
    cfg = {"llm": {"main": {"provider": "x", "model": "fake"}},
           "workspace_dir": str(tmp), "policy": {}}
    main = Agent(cfg, "pentest", "default", ["local.test"], {"allow_all": True}, "", EventBus())
    fake = FakeProvider(
        scripted=[
            [call("spawn_agent", name="recon1", task="扫描 127.0.0.1 并汇报结果")],
            [call("agent_result", agent_id="a1", wait_seconds=15)],
            [],
        ],
        sub_scripted=[
            "子任务完成：发现80端口HTTP服务",
        ],
    )
    main.router.main = fake
    main.router.fast = fake
    events = await run_collected(main)

    check("G1 spawn_agent 派出子agent", any(e["type"] == "sub_spawned" and e["data"]["name"] == "recon1" for e in events))
    check("G2 子agent不能再派生", len(main.subagents) == 1
          and "spawn_agent" not in list(main.subagents.values())[0]["agent"].registry)
    check("G3 agent_result 收到子agent总结", any(
        e["type"] == "tool_end" and e["data"].get("tool") == "agent_result"
        and "80端口" in (e["data"].get("summary") or "") for e in events))
    check("G4 sub_done 完成事件", any(e["type"] == "sub_done" and "80端口" in e["data"].get("summary", "") for e in events))
    check("G5 主agent正常收尾", any(e["type"] == "turn_done" for e in events))

    class SlowFake(FakeProvider):
        async def chat(self, messages, tools, on_delta=None, on_reasoning=None):
            is_sub = any(m.role == "system" and "子 agent「" in (m.content or "") for m in messages)
            if is_sub:
                await asyncio.sleep(0.5)
            return await super().chat(messages, tools, on_delta=on_delta, on_reasoning=on_reasoning)

    main2 = Agent(cfg, "pentest", "default", ["local.test"], {"allow_all": True}, "", EventBus())
    fake2 = SlowFake(
        scripted=[
            [call("spawn_agent", name="slow1", task="慢慢扫完再回报")],
            "主任务先说到这里，子 agent 继续跑",
        ],
        sub_scripted=["子任务完成：仍在跑时主轮已结束"],
    )
    main2.router.main = fake2
    main2.router.fast = fake2
    await run_collected(main2)
    entry = list(main2.subagents.values())[0]
    check("G6 本轮结束不取消还在跑的子 agent", not entry["task"].cancelled())
    await asyncio.wait_for(entry["task"], timeout=5)


async def scenario_tooldir(tmp):
    print("\n▶ 场景 H：工具目录发现与执行")
    tdir = tmp / "tools"
    (tdir / "sub").mkdir(parents=True)
    (tdir / "sub" / "hellobat.bat").write_text("@echo off\r\necho PT-TOOL-OK %1\r\n", encoding="gbk")
    (tdir / "nmap.exe").write_bytes(b"MZ\x00\x00")  # 占位，仅验证解析
    agent = make_agent("pentest", "default", {"allow_all": True}, [
        [call("find_tool", query="hello")],
        [call("run_tool", tool="hellobat", args="world")],
        [],
    ], tmp, cfg_extra={"tools": {"dir": str(tdir)}})
    events = await run_collected(agent)

    check("H1 find_tool 递归搜到子目录工具", any(
        e["type"] == "tool_end" and e["data"].get("tool") == "find_tool"
        and "hellobat.bat" in (e["data"].get("summary") or "") for e in events))
    check("H2 run_tool 执行库内工具", any(
        e["type"] == "tool_end" and e["data"].get("tool") == "run_tool"
        and "PT-TOOL-OK" in (e["data"].get("summary") or "") for e in events))
    from pentest_agent.tools.discovery import folder_catalog, resolve
    check("H3 run_tool 按名解析工具目录", (resolve("nmap", str(tdir)) or "").endswith("nmap.exe"))
    cat = folder_catalog(str(tdir))
    check("H3b 目录树列出子文件夹而不点名扫描器",
          "sub/" in cat and str(tdir) in cat and "已索引" in cat)
    check("H3c 系统提示注入目录树",
          "武器库" in agent.system_prompt() and "sub/" in agent.system_prompt()
          and "find_tool" in agent.system_prompt())
    agent_empty = make_agent("pentest", "default", {"allow_all": True}, [
        [call("find_tool", query="")],
        [],
    ], tmp, cfg_extra={"tools": {"dir": str(tdir)}})
    ev_empty = await run_collected(agent_empty)
    check("H3d find_tool 留空返回目录树", any(
        e["type"] == "tool_end" and e["data"].get("tool") == "find_tool"
        and "sub/" in (e["data"].get("summary") or "") for e in ev_empty))
    agent2 = make_agent("pentest", "default", {"allow_all": True}, [
        [call("run_tool", tool="no_such_tool", args="")],
        [],
    ], tmp, cfg_extra={"tools": {"dir": str(tdir)}})
    await run_collected(agent2)
    check("H4 不存在工具给出相近建议", any(a.get("event") == "tool_call" and a.get("tool") == "run_tool"
                                             for a in audit_events(agent2)))
    check("H2b run_tool 视为命令需确认", any(
        e["type"] == "approval_request" and e["data"].get("tool") == "run_tool" for e in events))

    agent3 = make_agent("pentest", "full", {"allow_all": True}, [
        [call("run_tool", tool="ping", args="127.0.0.1")],
        [],
    ], tmp, cfg_extra={"tools": {"dir": str(tdir)}})
    events3 = await run_collected(agent3)
    check("H5 系统 PATH 回退已关闭", any(
        e["type"] == "tool_end" and e["data"].get("tool") == "run_tool"
        and "PATH 回退已关闭" in (e["data"].get("summary") or "") for e in events3))

    agent4 = make_agent("pentest", "full", {"domains": ["example.com"]}, [
        [call("run_tool", tool="hellobat", args="-u http://evil.com/login")],
        [],
    ], tmp, cfg_extra={"tools": {"dir": str(tdir)}})
    await run_collected(agent4)
    check("H6 run_tool 参数出界被拦截", any(
        a.get("event") == "scope_block" and "evil.com" in str(a.get("target", ""))
        for a in audit_events(agent4)))


async def scenario_shelf(tmp):
    print("\n▶ 场景 S：工具货架（security_tool / 声明式注册表）")
    tdir = tmp / "shelf_tools"
    tdir.mkdir(parents=True, exist_ok=True)
    (tdir / "hello.py").write_text("import sys; print('SHELF-OK', sys.argv[1:])", encoding="utf-8")
    reg = tmp / "shelf.yaml"
    reg.write_text(
        "tools:\n"
        "  hello:\n"
        "    resolve: file\n"
        "    path: hello.py\n"
        "    class: read\n"
        "    args: \"-n\"\n"
        "    target_flag: \"-t\"\n"
        "    description: 测试货架工具\n",
        encoding="utf-8")

    agent = make_agent("pentest", "full", {"allow_all": True}, [
        [call("find_tool", query="hello")],
        [call("security_tool", tool="hello", target=["192.0.2.10"])],
        [],
    ], tmp, cfg_extra={"tools": {"dir": str(tdir), "registry": str(reg)}})
    events = await run_collected(agent)
    check("S1 find_tool 货架命中优先", any(
        e["type"] == "tool_end" and e["data"].get("tool") == "find_tool"
        and "货架命中" in (e["data"].get("summary") or "") for e in events))
    check("S2 security_tool 执行登记工具", any(
        e["type"] == "tool_end" and e["data"].get("tool") == "security_tool"
        and "SHELF-OK" in (e["data"].get("summary") or "") for e in events))
    check("S2b 参数拼装 args→flag→target", any(
        "['-n', '-t', '192.0.2.10']" in (e["data"].get("summary") or "")
        for e in events if e["type"] == "tool_end" and e["data"].get("tool") == "security_tool"))
    check("S3 货架内只读免确认（不弹审批）", not any(
        e["type"] == "approval_request" for e in events))

    agent2 = make_agent("pentest", "full", {"allow_all": True}, [
        [call("security_tool", tool="hello")],
        [],
    ], tmp, cfg_extra={"tools": {"dir": str(tdir), "registry": str(reg)}})
    events2 = await run_collected(agent2)
    check("S4 无 target 完全授权下也确认", any(
        e["type"] == "approval_request" and e["data"].get("tool") == "security_tool"
        and "target" in (e["data"].get("reason") or "") for e in events2))

    agent3 = make_agent("pentest", "full", {"domains": ["example.com"]}, [
        [call("security_tool", tool="hello", target=["203.0.113.5"])],
        [],
    ], tmp, cfg_extra={"tools": {"dir": str(tdir), "registry": str(reg)}})
    events3 = await run_collected(agent3)
    check("S5 出界 target 被 scope 拦截", any(
        e["type"] == "tool_end" and e["data"].get("tool") == "security_tool"
        and e["data"].get("status") == "blocked" for e in events3))

    agent4 = make_agent("pentest", "full", {"allow_all": True}, [[]], tmp)
    prompt = agent4.system_prompt()
    check("S6 空货架选配语义（提示无货架卡片，能力可见）",
          "货架已登记" not in prompt and "security_tool" in agent4.registry)

    agent5 = make_agent("pentest", "full", {"allow_all": True}, [
        [call("security_tool", tool="hello", target=["-iL", "/etc/passwd", "192.0.2.10"])],
        [],
    ], tmp, cfg_extra={"tools": {"dir": str(tdir), "registry": str(reg)}})
    events5 = await run_collected(agent5)
    check("S7 target 以'-'开头被机械拒绝(flag 注入)", any(
        e["type"] == "tool_end" and e["data"].get("tool") == "security_tool"
        and "不能以 '-' 开头" in (e["data"].get("summary") or "") for e in events5))


MCP_TEST_SERVER = r'''
import sys, json
def reply(rid, result):
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": rid, "result": result}) + "\n")
    sys.stdout.flush()
TOOLS = [{"name": "add", "description": "两数相加",
          "inputSchema": {"type": "object",
                          "properties": {"a": {"type": "number"}, "b": {"type": "number"}},
                          "required": ["a", "b"]}},
         {"name": "fetch", "description": "拉一个 URL",
          "inputSchema": {"type": "object",
                          "properties": {"url": {"type": "string"}},
                          "required": ["url"]}}]
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        obj = json.loads(line)
    except Exception:
        continue
    m, rid = obj.get("method"), obj.get("id")
    if m == "initialize":
        reply(rid, {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}},
                    "serverInfo": {"name": "test", "version": "0"}})
    elif m == "tools/list":
        reply(rid, {"tools": TOOLS})
    elif m == "tools/call":
        params = obj.get("params") or {}
        a = params.get("arguments") or {}
        name = params.get("name") or ""
        if name == "fetch":
            reply(rid, {"content": [{"type": "text", "text": "FETCHED=%s" % a.get("url", "")}]})
        else:
            reply(rid, {"content": [{"type": "text", "text": "SUM=%s" % (a.get("a", 0) + a.get("b", 0))}]})
    elif rid is not None:
        reply(rid, {})
'''


async def scenario_http_session(tmp):
    print("\n▶ 场景 K：HTTP 会话 Cookie 罐 + 工作记忆")
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import threading

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path.startswith("/set"):
                body = (
                    b'<html><form action="login.php" method="post">'
                    b'<input type="text" name="username">'
                    b'<input type="hidden" name="user_token" value="tok-xyz">'
                    b"</form></html>"
                )
                self.send_response(200)
                self.send_header("Set-Cookie", "sid=abc123; Path=/")
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                cookie = self.headers.get("Cookie") or ""
                body = b"OK-AUTH" if "sid=abc123" in cookie else b"NO-AUTH"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        raw_set = "GET /set HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n" % port
        raw_show = "GET /show HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n" % port
        agent = make_agent("pentest", "full", {"cidrs": ["127.0.0.0/8"]}, [
            [call("send_http_request", raw_request=raw_set)],
            [call("send_http_request", raw_request=raw_show)],
            [],
        ], tmp)
        events = await run_collected(agent)
        first = next((e for e in events if e["type"] == "tool_end" and e["data"].get("tool") == "send_http_request"
                      and "/set" in (e["data"].get("summary") or "")), None)
        second = next((e for e in reversed(events) if e["type"] == "tool_end"
                       and e["data"].get("tool") == "send_http_request"
                       and "/show" in (e["data"].get("summary") or "")), None)
        check("K1 响应摘要含表单 hidden token",
              first is not None and "user_token(hidden=tok-xyz)" in (first["data"].get("summary") or ""))
        check("K2 第二次请求自动带上 Cookie",
              second is not None and "OK-AUTH" in (second["data"].get("summary") or "")
              and "自动附加 sid" in (second["data"].get("summary") or ""))
        prompt = agent.system_prompt()
        check("K3 工作记忆注入提示词",
              "# 工作记忆" in prompt and "sid=abc123" in prompt
              and "GET" in prompt and str(port) in prompt)
        agent.router.main.main_q.append([call("read_evidence", path="evidence/http_1_request.txt")])
        agent.router.main.main_q.append([])
        ev_read = await run_collected(agent, user_text="读一下刚才的请求包")
        check("K4 read_evidence 读到本会话报文",
              any(e["type"] == "tool_end" and e["data"].get("tool") == "read_evidence"
                  and "GET /set" in (e["data"].get("summary") or "") for e in ev_read))
    finally:
        srv.shutdown()


async def scenario_mcp_skill(tmp):
    print("\n▶ 场景 I/J：MCP 接入 + 技能加载")
    # J: MCP — 本地起一个测试 server（stdlib 实现 stdio JSON-RPC）
    server_py = tmp / "mcp_test_server.py"
    server_py.write_text(MCP_TEST_SERVER, encoding="utf-8")
    # I: 技能
    skdir = tmp / "skills" / "my-recon"
    skdir.mkdir(parents=True)
    (skdir / "SKILL.md").write_text(
        "---\nname: my-recon\ndescription: 测试技能\n---\n先 subfinder 再 httpx，最后把资产写入 save_assets。",
        encoding="utf-8")

    agent = make_agent("pentest", "default", {"allow_all": True}, [
        [call("mcp_test_add", a=2, b=3)],
        [call("use_skill", name="my-recon")],
        [],
    ], tmp, cfg_extra={
        "mcp": {"servers": {"test": {"command": sys.executable, "args": [str(server_py)], "trust": True}}},
        "skills": {"dir": str(tmp / "skills")},
    })
    events = await run_collected(agent)

    check("I1 use_skill 加载技能正文", any(
        e["type"] == "tool_end" and e["data"].get("tool") == "use_skill"
        and "先 subfinder 再 httpx" in (e["data"].get("summary") or "") for e in events))
    check("J1 MCP 工具动态注册", "mcp_test_add" in agent.registry)
    check("J2 MCP 工具调用返回结果", any(
        e["type"] == "tool_end" and e["data"].get("tool") == "mcp_test_add"
        and "SUM=5" in (e["data"].get("summary") or "") for e in events))
    check("J3 MCP 接入状态提示", any(e["type"] == "status" and "MCP[test]" in (e["data"].get("text") or "")
                                      for e in events))

    agent_mcp_scope = make_agent("pentest", "full", {"domains": ["example.com"]}, [
        [call("mcp_test_fetch", url="http://evil.com/x")],
        [],
    ], tmp, cfg_extra={
        "mcp": {"servers": {"test": {"command": sys.executable, "args": [str(server_py)], "trust": True}}},
        "skills": {"dir": str(tmp / "skills")},
    })
    await run_collected(agent_mcp_scope)
    check("J4 trust MCP 出界 URL 仍被 scope 拦截", any(
        a.get("event") == "scope_block" and "evil.com" in str(a.get("target", ""))
        for a in audit_events(agent_mcp_scope)))

    mcp_hi = [e for e in events if e["type"] == "status" and "MCP[test]" in (e["data"].get("text") or "")]
    agent.router.main.main_q.append("第二轮只汇报，不重连")
    ev2 = await run_collected(agent, user_text="继续")
    mcp_hi2 = [e for e in ev2 if e["type"] == "status" and "MCP[test]" in (e["data"].get("text") or "")]
    check("J5 续聊不再重复接入 MCP", len(mcp_hi) == 1 and len(mcp_hi2) == 0)


async def scenario_resume(tmp):
    print("\n▶ 场景 L：会话恢复不丢任务 / tool_call_id")
    agent = make_agent("pentest", "full", {"allow_all": True}, [], tmp)
    agent.load_history([
        {"role": "user", "content": "测 http://example.com"},
        {"role": "assistant", "content": "", "tool_calls": [
            {"id": "c_save", "name": "save_assets",
             "arguments": {"assets": [{"target": "example.com"}]}},
            {"id": "c_phase", "name": "set_phase", "arguments": {"phase": "surface"}},
        ]},
        {"role": "tool", "name": "save_assets", "content": "ok", "tool_call_id": "c_save"},
        {"role": "tool", "name": "set_phase", "content": "ok", "tool_call_id": "c_phase"},
    ])
    check("L1 恢复后 system 在队首且任务还在",
          agent.messages[0].role == "system"
          and agent.messages[1].role == "user"
          and agent.messages[1].content == "测 http://example.com")
    check("L2 tool_call_id 按落盘恢复",
          agent.messages[3].tool_call_id == "c_save"
          and agent.messages[4].tool_call_id == "c_phase")
    first_user = agent.messages[1].content
    agent._refresh_system()
    check("L3 刷新 system 不覆盖用户任务", agent.messages[1].content == first_user)

    from pentest_agent.workspace.session import Workspace as _WS
    rdir = tmp / "restore_ws"
    ws = _WS(rdir, "20260830_pentest", {
        "mode": "pentest", "auth": "default", "targets": ["x"],
        "scope": {"allow_all": True}, "task": "t",
    })
    created = ws.meta["created"]
    ws.update_runtime(phase="discover", req_seq=5)
    (ws.evidence_dir / "http_5_request.txt").write_text("x", encoding="utf-8")
    ws2 = _WS(rdir, "20260830_pentest", {"mode": "pentest", "auth": "default"})
    check("L4 恢复不改写 created", ws2.meta["created"] == created)
    agent_r = Agent(
        {"llm": {"main": {"provider": "x", "model": "fake"}}},
        "pentest", "default", ["x"], {"allow_all": True}, "t", EventBus(), workspace=ws2,
    )
    check("L5 恢复阶段", agent_r.state["phase"] == "discover")
    check("L6 恢复 req_seq", agent_r.state["req_seq"] == 5)

    agent_ph = make_agent("pentest", "full", {"allow_all": True}, [
        [call("set_phase", phase="surface")],
        [],
    ], tmp)
    await run_collected(agent_ph)
    check("L7 set_phase 落盘阶段", agent_ph.ws.meta.get("phase") == "surface")

    # 旧会话只有证据、没有 req_seq 字段
    old = _WS(rdir, "old_seq", {"mode": "pentest"})
    (old.evidence_dir / "http_3_request.txt").write_text("x", encoding="utf-8")
    meta = json.loads(old.meta_path.read_text(encoding="utf-8"))
    meta.pop("req_seq", None)
    meta.pop("phase", None)
    old.meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    ws_old = _WS(rdir, "old_seq", {"mode": "pentest"})
    agent_old = Agent(
        {"llm": {"main": {"provider": "x", "model": "fake"}}},
        "pentest", "default", ["x"], {"allow_all": True}, "t", EventBus(), workspace=ws_old,
    )
    check("L8 无 req_seq 时从 evidence 推断", agent_old.state["req_seq"] == 3)


async def scenario_postex(tmp):
    print("\n▶ 场景 M：渗透模式后渗透需用户点头")
    raw_fi = "GET /vulnerabilities/fi/?page=../../windows/win.ini HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
    agent = make_agent("pentest", "full", {"allow_all": True}, [
        [call("send_http_request", raw_request=raw_fi)],
        [],
    ], tmp)
    events = await run_collected(agent, decision="deny")
    check("M1 完全授权下后渗透默认放行(不弹确认)",
          not any(e["type"] == "approval_request" for e in events)
          and any(e["type"] == "tool_end" and e["data"]["tool"] == "send_http_request"
                  and e["data"]["status"] == "ok" for e in events))

    agent_cfg = make_agent("pentest", "full", {"allow_all": True}, [
        [call("send_http_request", raw_request=raw_fi)],
        [],
    ], tmp, cfg_extra={"policy": {"allow_postex_in_full": False}})
    events_cfg = await run_collected(agent_cfg, decision="deny")
    check("M1b allow_postex_in_full=false 恢复逐次确认",
          any(e["type"] == "approval_request" and e["data"].get("tool") == "send_http_request"
              and "后渗透" in (e["data"].get("reason") or "") for e in events_cfg)
          and any(a.get("event") == "user_denied" for a in audit_events(agent_cfg)))

    agent_def = make_agent("pentest", "default", {"allow_all": True}, [
        [call("send_http_request", raw_request=raw_fi)],
        [],
    ], tmp)
    events_def = await run_collected(agent_def, decision="deny")
    check("M1c 默认档位后渗透仍需确认",
          any(e["type"] == "approval_request" and "后渗透" in (e["data"].get("reason") or "")
              for e in events_def))

    raw_ok = "GET /login.php HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
    agent2 = make_agent("pentest", "full", {"allow_all": True}, [
        [call("send_http_request", raw_request=raw_ok)],
        [],
    ], tmp)
    events2 = await run_collected(agent2)
    check("M2 普通 GET 不弹后渗透确认",
          not any(e["type"] == "approval_request" for e in events2))

    agent3 = make_agent("recon", "default", {"allow_all": True}, [
        [call("send_http_request", raw_request=raw_fi)],
        [],
    ], tmp)
    await run_collected(agent3)
    check("M3 侦察模式后渗透被拦截",
          any(a.get("event") == "policy_block" for a in audit_events(agent3)))

    agent4 = make_agent("redteam", "full", {"allow_all": True}, [
        [call("send_http_request", raw_request=raw_fi)],
        [],
    ], tmp)
    events4 = await run_collected(agent4)
    check("M4 红队模式后渗透不额外确认",
          not any(e["type"] == "approval_request" for e in events4))


async def scenario_verify_flow(tmp):
    print("\n▶ 场景 V：候选 → 独立验证者 → 报告")
    agent = make_agent("pentest", "default", {"allow_all": True}, [[]], tmp)
    vtag = "verify-1_a1"  # 验证者证据文件前缀
    for n in (1, 2, 3, 4):
        for prefix in ("", f"{vtag}_"):
            (agent.ws.evidence_dir / f"{prefix}http_{n}_request.txt").write_text(
                f"GET /?id={n} HTTP/1.1\nHost: 192.0.2.10\n\n", encoding="utf-8")
            (agent.ws.evidence_dir / f"{prefix}http_{n}_response.txt").write_text(
                f"HTTP/1.1 200 OK\n\nresp-{n}", encoding="utf-8")
    # 模拟入库前会话已发送 2 个请求:之后编号 >2 的才算新证据
    agent.state["req_seq"] = 2
    msg = await agent.handle_tool(call("record_finding", title="疑似SQLi", severity="high",
                                       target="192.0.2.10", description="id 参数注入",
                                       evidence=["evidence/http_2_request.txt"]))
    check("V1 record_finding 产生候选而非定案", "候选漏洞已记录" in msg.content
          and finding_status(next(f for f in agent.ws.findings if not f.get("duplicate"))) == "candidate")

    # 发现者(主 agent)自验被拒
    msg = await agent.handle_tool(call("verify_finding", id=1, verdict="verified",
                                       evidence=[f"evidence/{vtag}_http_3_request.txt",
                                                 f"evidence/{vtag}_http_4_request.txt"]))
    check("V2 主 agent 不得自验(身份隔离)", "只能由独立验证者" in msg.content)

    # 验证者子 agent:门槛校验
    sub = Agent(_vcfg(tmp), "pentest", "default", ["192.0.2.10"], {"allow_all": True}, "验证任务",
                agent.bus, workspace=agent.ws, is_sub=True, name="verify-1", parent=agent, agent_id="a1")
    msg = await sub.handle_tool(call("verify_finding", id=1, verdict="verified",
                                     evidence=[f"evidence/{vtag}_http_3_request.txt"]))
    check("V3 verified 双新报文门槛(1 条被拒)", "2 条" in msg.content)
    msg = await sub.handle_tool(call("verify_finding", id=1, verdict="verified",
                                     evidence=[f"evidence/{vtag}_http_1_request.txt",
                                               f"evidence/{vtag}_http_3_request.txt"]))
    check("V4 旧报文(入库前,编号≤2)不算新证据", "2 条" in msg.content)
    msg = await sub.handle_tool(call("verify_finding", id=1, verdict="verified",
                                     evidence=["evidence/http_2_request.txt",
                                               f"evidence/{vtag}_http_4_request.txt"]))
    check("V4b 借用他人报文被拒(必须验证者亲自发送)", "亲自发送" in msg.content)
    msg = await sub.handle_tool(call("verify_finding", id=1, verdict="verified",
                                     evidence=[f"evidence/{vtag}_http_3_request.txt",
                                               f"evidence/{vtag}_http_4_request.txt"],
                                     note="1=1 与 1=2 响应可区分"))
    f1 = next(f for f in agent.ws.findings if not f.get("duplicate"))
    check("V5 合规验证通过并记录验证者",
          "已标记 verified" in msg.content and f1.get("status") == "verified"
          and f1.get("verified_by") == "a1" and f1.get("verified_by_name") == "verify-1")
    agent.ws.write_report(overview="ov")
    report = (agent.ws.dir / "report.md").read_text(encoding="utf-8")
    check("V6 verified 进报告正文并标注验证者",
          "已独立验证(验证者: verify-1)" in report
          and report.index("疑似SQLi") < report.index("四、资产清单"))

    # 误报回流
    await agent.handle_tool(call("record_finding", title="疑似XSS", severity="medium",
                                 target="192.0.2.10", description="反射",
                                 evidence=["evidence/http_3_request.txt"]))
    msg = await sub.handle_tool(call("verify_finding", id=2, verdict="rejected",
                                     evidence=[f"evidence/{vtag}_http_4_request.txt"],
                                     note="输出经编码,不执行"))
    fails = agent.ws.memory.data.get("failures") or []
    report = agent.ws.write_report(overview="")
    check("V7 rejected 回流失败记忆并进附录",
          "已标记 rejected" in msg.content
          and any("误报排除" in str(x.get("summary")) for x in fails)
          and "附录 B：已排除误报" in report.read_text(encoding="utf-8"))


def _vcfg(tmp):
    return {"llm": {"main": {"provider": "mock", "model": "m"},
                    "fast": {"provider": "mock", "model": "m"}},
            "policy": {"distill_on_finish": False},
            "workspace_dir": str(tmp), "tools": {"dir": ""},
            "skills": {"dir": str(tmp / "skills")}}


async def scenario_finish_timeout(tmp):
    print("\n▶ 场景 N：finish 收尾 + 审批超时")
    agent = make_agent("pentest", "full", {"allow_all": True}, [
        [call("finish", summary="本轮验证结束，无新洞")],
        [call("save_assets", assets=[{"target": "should-not-run"}])],
    ], tmp / "n1")
    events = await run_collected(agent)
    check("N1 finish 写报告并结束本轮",
          agent.state.get("finished") is True
          and "验证结束" in (agent.state.get("last_text") or "")
          and (agent.ws.dir / "report.md").exists()
          and any(e["type"] == "tool_end" and e["data"].get("tool") == "finish" for e in events)
          and not any(e["type"] == "tool_end" and e["data"].get("tool") == "save_assets" for e in events))

    tdir = tmp / "tools_to"
    tdir.mkdir(exist_ok=True)
    (tdir / "hellobat.bat").write_text("@echo off\r\necho x\r\n", encoding="gbk")
    agent2 = make_agent("pentest", "default", {"allow_all": True}, [
        [call("run_tool", tool="hellobat", args="")],
        [],
    ], tmp / "n2", cfg_extra={"tools": {"dir": str(tdir)}, "policy": {"approval_timeout": 1}})
    q = agent2.bus.subscribe()
    ev2 = []

    async def _loop():
        while True:
            ev2.append(await q.get())

    t = asyncio.create_task(_loop())
    await agent2.run()
    await asyncio.sleep(0.1)
    t.cancel()
    await asyncio.gather(t, return_exceptions=True)
    check("N2 审批超时视为拒绝",
          any(a.get("event") == "approval_timeout" for a in audit_events(agent2))
          and any(e["type"] == "tool_end" and "审批超时" in (e["data"].get("summary") or "")
                  for e in ev2))


async def main():
    print("=" * 60)
    print("PT-Agent 功能自检")
    print("=" * 60)
    await scenario_units()
    tmp = Path(tempfile.mkdtemp(prefix="ptagent_test_"))
    await scenario_pentest(tmp)
    await scenario_redteam_checkpoint(tmp)
    await scenario_scope_block(tmp)
    await scenario_dangerous(tmp)
    await scenario_compress(tmp)
    await scenario_subagent(tmp)
    await scenario_tooldir(tmp)
    await scenario_shelf(tmp)
    await scenario_verify_flow(tmp)
    await scenario_http_session(tmp)
    await scenario_mcp_skill(tmp)
    await scenario_resume(tmp)
    await scenario_postex(tmp)
    await scenario_finish_timeout(tmp)
    print("\n" + "=" * 60)
    print(f"结果: {len(PASS)} 通过 / {len(FAIL)} 失败")
    if FAIL:
        print("失败项:", FAIL)
        sys.exit(1)
    print("全部通过 ✅")


if __name__ == "__main__":
    asyncio.run(main())
