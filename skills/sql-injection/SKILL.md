---
name: sql-injection
description: SQL 注入：报错/布尔/时间对照验证，证明存在即止
modes: pentest, redteam
when: SQLe, SQLb, search, query, sort, order, 报错, 注入
---

# SQL 注入（决策，不是利用手册）

## 前置
给定资产上的参数化入口：搜索、排序、ID、筛选。先有正常对照响应，再做差异。

## 决策
1. 响应里出现数据库/SQL 报错特征 → 记 SQLe，做「真条件 / 假条件」对照
2. 无报错但状态、长度或耗时稳定分化 → 记 SQLb，同样成对对照
3. 两次对照无稳定差异 → 30 秒内 skip，换入口

## 验证纪律
- 必须成对请求，单次响应不算命中
- 证明「后端把输入拼进查询」即可，不要导出库表、不要写库
- record_finding 绑成对请求的 http_* 证据
- 返回：命中? / 新发现 / 衍生（例如是否还有第二参数）
