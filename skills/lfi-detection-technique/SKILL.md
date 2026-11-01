---
name: lfi-detection-technique
description: 通过文件包含参数测试本地文件包含（LFI），利用PHP错误泄露绝对路径
when: 文件包含, LFI, include, 路径穿越, 任意文件读取
modes: pentest, redteam
x-source-session: 20261101_161427_f5102d_pentest
---

1. 找到通过 include/require/receive 等函数加载文件的参数（常见参数名：page、file、template、path）。
2. 用合法已知文件名建立对照基线（如 include.php、index.php），确认正常加载行为。
3. 测试包含系统文件：
   - Linux: page=/etc/passwd, page=../../../../etc/passwd
   - Windows: page=C:/Windows/win.ini（验证标志：[fonts][extensions] 等特征内容）
   - PHP内置：page=php://filter/convert.base64-encode/resource=index.php（读取源码）
4. 如果路径不正确触发 PHP Warning，响应中可能泄露绝对路径（如 PHP Warning: include(): Failed opening... in /path/to/file.php），收集此信息辅助后续利用。
5. 评估利用链：
   - 读取配置文件（数据库密码、API密钥）
   - 结合日志文件包含实现 RCE
   - 结合文件上传 + LFI 实现 RCE
6. 修复建议：文件包含使用白名单机制，仅允许预定义文件名；关闭 PHP 错误回显；open_basedir 限制。