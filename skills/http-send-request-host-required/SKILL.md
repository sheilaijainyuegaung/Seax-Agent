---
name: http-send-request-host-required
description: 负知识：send_http_request工具发送原始HTTP请求时必须包含Host头
when: Host, 请求包, send_http, 工具报错
modes: pentest, redteam
x-source-session: 20261101_161427_f5102d_pentest
---

使用 send_http_request 工具发送原始 HTTP 请求时，请求包中必须包含 Host 头。
- 如果请求包缺少 Host 头且未提供 host_override 参数，工具将报错：'ValueError: 请求包缺少 Host 头，且未提供 host_override，无法确定目标'
- 解决方案：在原始请求包第一行（请求行）之后立即添加 Host: <目标域名>。
- 如果是基于 IP 的测试，Host 头仍需填写（可填写 IP 或虚拟主机名）。
- 已知此错误出现 2 次，遇到时直接补全 Host 头即可，无需重新构造请求。