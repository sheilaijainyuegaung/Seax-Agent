---
name: php-error-path-leak
description: 利用PHP错误信息泄露绝对路径，辅助后续文件包含与目录遍历
when: 路径泄露, PHP Warning, 错误信息, 绝对路径
modes: pentest, redteam
x-source-session: 20261101_161427_f5102d_pentest
---

1. 在文件包含、文件读取等功能点构造不存在的文件路径，触发 PHP Warning。
2. PHP Warning/Notice/Deprecated 信息中通常包含绝对路径：
   - include(): Failed opening 'xxx' for inclusion (include_path='...') in /absolute/path/to/file.php on line N
3. 收集泄露的绝对路径信息，可推断：
   - Web 根目录位置
   - 操作系统类型（Windows 用 \ 和盘符，Linux 用 /）
   - 应用安装结构与框架信息
4. 利用泄露的路径信息：
   - 构造更精准的 LFI payload（省去路径猜测）
   - 确定日志文件位置用于日志包含 RCE
   - 判断是否可写目录
5. 如果生产环境暴露 PHP 错误信息，本身就是一个信息泄露漏洞，应记录并修复（display_errors=Off）。