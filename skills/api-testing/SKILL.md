---
name: api-testing
description: API：文档、方法、鉴权边界、多余字段观察
modes: pentest, redteam
when: APIe, swagger, openapi, json, graphql, api
---

# API 测试（决策）

## 前置
给定资产上的 /swagger、/api-docs、/graphql、XHR 接口名。只测这些主机上的路径。

## 决策
1. 先拉文档或 JS 里的路径，列入假设，不要对整站目录爆破
2. 同一路径对照：不同 HTTP 方法、带/不带鉴权
3. JSON 多收未知字段时：只观察是否被接受（回显或生效），不要构造提权利用链
4. 401 只说明这一条通道，其他通道仍要测

## 验证纪律
- 每个接口记入 update_world.tested
- 未授权数据只要能证明存在就停，不要翻页拖库
- 返回：命中? / 哪个边界 / 衍生
