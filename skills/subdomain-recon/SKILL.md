---
name: subdomain-recon
description: 子域测绘与资产收敛打法：被动优先、主动补充、存活收敛（仅侦察/红队）
modes: recon, redteam
---

# 子域测绘方法论

## 1. 被动收集（不接触目标）
- 用 find_tool 找子域收集类工具打底；多源聚合结果常含失效域名
- 交叉验证：证书透明（crt.sh 查询）、DNS 解析存活

## 2. 主动验证
- 解析筛选：只保留可解析的记录（A/CNAME）
- 从工具目录选探活/指纹工具收敛 web 资产；对无 web 的 IP 段再补端口
- 没有指定必须用哪个工具，按目录和目标情况自选

## 3. 收敛输出
- 资产全部写入 save_assets（type: domain / web）
- 命名规律发现（如 api-*.target.com、*-dev.target.com）→ 用关键字再发散一轮
- 重点标记：管理后台、API 网关、老系统（exp 命中率高）

## 4. 红队卡点
- 全部资产收集完毕 → save_assets → set_phase，等用户确认后再攻击
