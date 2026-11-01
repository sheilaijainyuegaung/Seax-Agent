---
name: xss-reflect-store-detect
description: 检测反射型与存储型XSS，关注输出编码缺失与响应头CSP缺失
when: XSS, 反射, 存储, 脚本注入, 跨站
modes: pentest, redteam
x-source-session: 20261101_161427_f5102d_pentest
---

1. 反射型XSS检测：
   - 向各输入点注入 <script>alert(1)</script> 或带唯一标记的payload。
   - 检查响应中输入是否原样回显（未做 HTML 编码）。
   - 检查响应头是否缺失 CSP（Content-Security-Policy）。
   - 注意：反射 XSS 主要通过响应内容分析，不必强求浏览器实弹执行。
2. 存储型XSS检测：
   - 找到留言板/评论/用户资料等持久化存储功能点。
   - 注入带唯一标记的 XSS payload 提交。
   - 重新加载页面或等待他人访问，验证 payload 是否持久存在且未编码回显。
   - 检查前端 maxlength 限制（仅客户端限制可直接用 Burp 绕过）。
3. 输出编码验证：
   - 注入特殊字符 < > " ' & 测试编码处理情况。
   - 未做 htmlspecialchars(ENT_QUOTES) 编码即为存在 XSS。
4. 修复建议：输出编码按上下文处理（HTML body/attribute/JS/CSS 各不同）；部署 CSP 限制内联脚本；存储前也做输入校验与编码。