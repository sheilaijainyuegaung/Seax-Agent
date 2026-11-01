---
name: vuln-app-fingerprint
description: 通过登录页标题、页脚信息、Cookie特征快速识别已知脆弱Web应用
when: 指纹, 识别, 标题, 页脚, cookie
modes: pentest, redteam
x-source-session: 20261101_161427_f5102d_pentest
---

1. 访问登录页（如 login.php），提取页面 <title> 标签内容，搜索其在公开仓库（GitHub/Google）中的归属项目。
2. 查看页面页脚（footer），已知脆弱靶场通常会标注项目名称或源码仓库地址。
3. 检查响应头 Set-Cookie，如出现应用自定义的安全等级cookie（如 security=low），结合标题与页脚即可确认目标应用类型。
4. 确认应用类型后，查阅其已知漏洞模块清单，制定针对性测试计划，避免盲目扫描。
5. 判断运行环境（PHP/Java等）：通过扩展名 .php、PHP Warning 泄露、Server 响应头等辅助确认。