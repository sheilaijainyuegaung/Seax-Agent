---
name: file-upload
description: 上传：观察过滤，证明接受非预期类型即止
modes: pentest, redteam
when: upload, file, 上传, multipart
---

# 文件上传（决策）

## 前置
给定资产上的 multipart 上传口。先走正常文件拿到对照响应。

## 决策
1. 看服务端按扩展名、Content-Type 还是内容过滤
2. 非预期类型被接受（响应路径或成功提示）→ hit「过滤不严」
3. 一律拒绝且无差异 → skip

## 验证纪律
- 证明「过滤可被绕过或过宽」即可
- 不要上传 webshell、不要追求 getshell
- 删除/覆盖已有文件必须先问用户
- 返回：命中? / 过滤方式 / 衍生
