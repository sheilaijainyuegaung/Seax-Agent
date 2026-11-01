---
name: client-cookie-security-level
description: 检测并利用客户端Cookie控制安全/过滤等级的设计缺陷
when: cookie, 安全等级, 降级, 绕过防护
modes: pentest, redteam
x-source-session: 20261101_161427_f5102d_pentest
---

1. 检查响应头中 Set-Cookie 是否包含应用自定义的安全等级/防护等级字段。
2. 修改该 cookie 值为最低等级（如 low、0、off），重放原始请求，观察防护行为是否发生变化。
3. 对比不同等级下的响应差异来验证服务端确实在读取该 cookie：
   - low：输入原样回显（无过滤）
   - medium：部分过滤（如仅删除 script 标签）
   - impossible/high：请求被拒绝或输入被完全编码
4. 确认攻击者可自选安全等级后，记录为可利用的设计缺陷，强调生产环境安全等级应由服务端控制。
5. 同时测试中间等级的过滤绕过（如 medium 仅 strip 标签未做编码，可尝试闭合标签残留、事件属性等绕过）。