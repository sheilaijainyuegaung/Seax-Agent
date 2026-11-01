---
name: login-default-creds-test
description: 对登录表单进行默认弱口令与常见凭据字典测试
when: 登录, 弱口令, 默认凭据, 认证
modes: pentest, redteam
x-source-session: 20261101_161427_f5102d_pentest
---

1. 识别登录表单的 username/password 参数名，使用浏览器开发者工具或抓包确认请求格式（POST/GET、Content-Type）。
2. 测试常见默认凭据组合：admin/admin, admin/password, admin/123456, test/test, root/root 等。
3. 对于已知脆弱靶场/开源项目，先查阅其默认凭据文档。
4. 验证登录成功标志：关注响应状态码（302跳转到首页）、Set-Cookie 中出现会话token、页面内容变化。
5. 登录成功后检查是否可访问管理功能（如安全等级切换、用户管理、数据库操作等），评估影响范围。
6. 将成功凭据记录为 high/critical 级别发现。