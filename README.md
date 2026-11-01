# Seax-Agent —— 自主作业的渗透测试 Agent


Windows 原生运行的渗透测试 Agent。核心设计:**一条工作流流水线 + 模式作为配置**,而不是每套模式各写一套流程。

```
信息收集 → 攻击面识别 → 漏洞发现 → 验证(PoC) → [利用 → 后渗透] → 报告
```

- **侦察模式** recon：资产测绘，产出资产清单
- **渗透模式** pentest：漏洞验证，产出带 **Burp 原始请求包**  漏洞报告
- **红队模式** redteam：同一条流水线继续走利用和后渗透，目标是立足点（shell）；

## 模式 × 授权档位

| 动作类型 | 逐步确认 | 默认策略 | 完全授权 |
|---|---|---|---|
| 只读（扫描/PoC/GET） | 放行 | 放行 | 放行 |
| 增（POST 等） | 确认 | 渗透模式：确认 / 红队：放行 | 放行 |
| 删/改（DELETE/PUT 等） | 确认 | 确认 | 放行 |
| 不可逆破坏（rm -rf、格式化、清日志…） | 确认 | 确认 | **拦截**（除非 `allow_destructive_in_full: true`） |
| 后渗透特征（读系统文件/命令执行 payload…） | 确认 | 确认 | 放行（`allow_postex_in_full: false` 恢复逐次确认） |
| 任意命令 run_command | 确认 | 确认 | 放行 |

永远生效、任何档位不绕过的两条底线：

1. **scope 校验**：每次目标型工具调用都校验目标是否在授权范围内，出界直接拦截
2. **审计日志**：每次工具调用、每次策略决策都写入 `sessions/<sid>/audit.jsonl`，全程可回放

## 安装与启动

```bash
cd seax-agent
pip install -r requirements.txt

# 配置：复制模板并填写 API key（支持 ${ENV_VAR} 写法）
copy config\settings.example.yaml config\settings.yaml
notepad config\settings.yaml

# 启动 GUI
python -m pentest_agent gui            # http://127.0.0.1:8765(包名暂为 pentest_agent,品牌名 Seax)

# 或命令行跑
python -m pentest_agent run --mode pentest --auth default ^
    --target 10.0.0.5 --cidr 10.0.0.0/24 --task "重点测登录和注入"
```

## 模型配置

`llm.main`：规划与漏洞验证决策，建议用 function calling 最稳的模型。
`llm.fast`：上下文压缩等脏活，便宜模型即可（不配则用 main）。

两种协议都支持，`provider` 二选一：

- `openai_compat`：GLM / DeepSeek / Qwen / Kimi / OpenAI（配 `base_url` + `api_key` + `model`）
- `anthropic`：Claude（`base_url` 默认 https://api.anthropic.com，可配代理）

## 工具(选配件)

**不配置任何工具,agent 也能完整作业**——`send_http_request` 手工发包验证是原子能力,证据/审批/报告全流程不受影响。配置工具只是给模型一个"货架":清单只声明有哪些工具、怎么安全地调用,**用什么、什么时候用由模型自主判断**,系统不写死任何流程。

三层用法,按需选择:

1. **零配置**:什么都不填,agent 用 send_http_request 手工验证。
2. **公开工具(推荐开源用户)**:`copy config\tools.example.yaml config\tools.local.yaml`,nmap/nuclei/httpx 等装好后从系统 PATH 自动解析。该文件已被 `.gitignore`,你的本地清单不会进仓库。
3. **本地武器库**:工具再多也不怕(几千个文件也不用扫全盘)——一键生成货架草稿,人工删减:

```bash
python scripts/gen_tool_registry.py --dir E:/path/to/your/tools
# 产出 config/tools.local.yaml:description 补一句、确认安全的工具 class 改 read,其余保持需确认
```

| 工具 | 说明 |
|---|---|
| **security_tool** | 货架统一入口:`security_tool(tool=名字, target=[目标], extra_args="...")`。target 是结构化参数、**逐个过 scope 校验**;不传 target 或带 extra_args 会触发人工确认 |
| **find_tool** | 搜索货架(优先)与工具目录;找到后用 security_tool / run_tool 调用 |
| **run_tool** | 执行货架外的本地工具(逃生舱):视为任意命令需确认;参数抽不到目标时强制确认 |
| **send_http_request** | **原子能力:直接发 Burp 风格原始请求包**,POST/PUT/DELETE 自动触发确认 | 原始请求/响应 .txt |
| save_assets / record_finding / set_phase / finish | 资产清单 / 漏洞入库 / 阶段推进 / 结束 | — |

清单字段(`resolve: path/file/abs`、`class: read/command`、`target_flag`、`danger_flags`、`output_hint` 等)见 `config/tools.example.yaml` 内注释。

## 验证流程(防误报)

**发现 ≠ 结论。** 所有来源的发现(扫描器、模型假设、手工验证)一律先入「候选」,候选不进报告正文——验证由**独立子 agent** 执行,发现者不得自验:

```
record_finding(绑本会话报文) → 【候选】
    → spawn_agent(验证任务书:仅含 编号/类型/目标/参数位置,不带发现者结论)
    → 验证者独立设计 payload+对照 双请求,亲自发送
    → verify_finding(id, verdict, evidence, note)   ← 仅子 agent 可调用
        verified → 报告正文(标注验证者)
        rejected → 报告附录留档 + 写入失败记忆(防重复追同一误报)
```

机械门槛(后端强制,不靠模型自觉):

1. `verified` 必须绑定 **≥2 条入库之后新发送** 的 `http_*_request.txt`(payload+对照,按请求序号校验)——单响应/旧报文盖章直接被拒;
2. `verify_finding` 身份隔离:主 agent 调用会被工具本身拒绝;
3. 报告三段式:正文仅已验证漏洞;附录 A 待验证候选(明示可能误报);附录 B 已排除误报(留档审计)。

验证方法论(payload+对照范式)写入 verify 阶段 checklist 与技能卡;无法对照验证的候选保持候选并标 info,宁可少报不误报。

## 会话工作区与并行子 agent

- **工作目录（项目）**：对话里点 📁 胶囊，用目录浏览器选一个项目目录，agent 产出的全部东西（证据/报告/审计/命令输出）都存在该项目下；自定义目录的会话自动登记索引，侧栏可见
- **并行子 agent**：agent 可用 `spawn_agent(name, task)` 派出子 agent 同时作业（上限 `policy.max_subagents`，默认 5），`agent_status` 查询、`agent_result(wait_seconds)` 收结果；子 agent 共享 scope/审批/工作区（证据文件自动加名字前缀），需要确认的操作同样会在对话里弹出，且不能再派生子 agent
- **子 agent 恢复**：每个子 agent 另存 `agents/<agent_id>/metadata.json`、`checkpoint.json`、`messages.jsonl`；主进程重启后可由 `agent_status` 查看，并用 `agent_result` 继续未完成任务
- **结果外置与压缩**：超大工具输出完整保存在 `raw/`，上下文只保留摘要和路径；接近模型窗口 75% 时自动生成带事实/假设/漏洞/失败 ID 的工作笔记（`policy.auto_compress: false` 可关闭）
- **事实图与失败路径**：`world.json` 同时保存 `facts`、带来源的假设、验证结果事实和结构化 `failures`；GUI 攻击链可据此显示事实 → 意图 → 失败/漏洞路径

```
<工作目录>/
  <时间>_<模式>/
  session.json       模式/授权/scope/任务
  assets.json/.md    资产清单（红队确认卡点的数据源）
  findings.json/.md  漏洞库（每条含原始请求/响应包）
  report.md          最终报告
  audit.jsonl        全程审计
  messages.jsonl     对话流（可回放）
    evidence/          扫描输出、原始报文等全部证据
    raw/               超大工具输出原文（上下文压缩后仍可 read_evidence 读取）
    agents/            子 agent 元数据、独立 checkpoint 与 transcript
```

MCP server 会记录连接状态，发生连接类错误时只有限重连一次，并在成功后重新执行 `initialize` / `tools/list`。可用 `find_mcp_tool` 按名称或用途搜索当前工具目录。

## 架构

```
pentest_agent/
  core/agent.py    主循环：校验→scope→审批→执行→记录，上下文压缩（工作笔记）
  llm/             统一消息模型 + openai_compat / anthropic 双协议适配
  tools/           适配器：pydantic schema → 执行 → 结构化解析 → 证据落盘
  policy/          scope 校验 / 审批矩阵 / 破坏性命令黑名单
  workspace/       会话工作区与 Markdown 报告
  modes/           模式 profile（阶段 + checklist）
  gui/             FastAPI + WebSocket + Codex 风格前端
```

加新工具：在 `tools/` 写一个 `ToolAdapter` 子类（参数模型 + execute + 解析），在 `registry.py` 注册即可。协议为 Linux-only 的工具可在适配器里走 `shell="wsl"`。

## 已知设计决策（可改配置）

- 红队模式的"确认资产"卡点在完全授权下默认跳过（`skip_checkpoint_in_full_auth`）
- 红队模式按你的规则"增"不确认、"删/改"确认；渗透模式"增删改"都确认 —— 如需调整改 `policy/approval.py`
- 命令行模式下审批事件只提示不交互，确认类操作请用 GUI 或 `--auth full`

## 开源说明

- 授权:MIT(见 LICENSE)。
- **仅供已授权的安全测试与教学研究使用。** 对未授权目标使用本项目造成的任何后果由使用者自行承担;请始终在你的授权范围(scope)内作业。
- `config/settings.yaml`(含 API Key)与 `sessions/`(全部测试数据)已被 `.gitignore` 排除,不会进入仓库。
