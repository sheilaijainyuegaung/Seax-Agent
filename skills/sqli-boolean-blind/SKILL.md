---
name: sqli-boolean-blind
description: 通过布尔对照验证SQL注入的可区分性，确认注入点真实可利用
when: sql注入, 布尔, 盲注, 注入
modes: pentest, redteam
x-source-session: 20261101_161427_f5102d_pentest
---

1. 在输入点尝试注入单引号触发SQL错误，初步判断注入点存在。
2. 构造布尔对照 payload 验证可区分性：
   - True条件：1' AND '1'='1 或 1 AND 1=1 → 正常返回数据
   - False条件：1' AND '1'='2 或 1 AND 1=2 → 返回空/不同内容
3. 多次重复发送，确认响应差异稳定可复现，排除随机干扰。
4. 确认可区分后，进一步尝试：
   - 联合查询（UNION SELECT）拖库
   - 报错注入提取信息
   - 布尔盲注逐字符爆破
5. 注意 payload 中的引号需要与后端 SQL 语法匹配（单引号/双引号/无引号）。
6. 发现后记录完整 SQL 语句上下文（从报错信息或页面行为推断），便于修复建议具体化。