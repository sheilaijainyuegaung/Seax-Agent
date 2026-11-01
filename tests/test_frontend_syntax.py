"""前端脚本语法校验:index.html 的 <script> 必须能通过 node --check。

背景:一处 `a ?? b || c`(JS 禁止 ?? 与 || 不加括号混用)导致整个脚本解析失败、
页面所有按钮失效——Python 侧的字符串替换测试发现不了 JS 语法错误,必须在测试里校验。
本机没有 node 时跳过。
"""
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

STATIC = Path(__file__).resolve().parent.parent / "pentest_agent" / "gui" / "static" / "index.html"


@unittest.skipIf(shutil.which("node") is None, "node 不可用,跳过前端语法校验")
class TestFrontendSyntax(unittest.TestCase):
    def test_index_html_script_parses(self):
        src = STATIC.read_text(encoding="utf-8")
        m = re.search(r"<script>([\s\S]*?)</script>", src)
        self.assertIsNotNone(m, "index.html 中找不到 <script> 块")
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as f:
            f.write(m.group(1))
            tmp = Path(f.name)
        try:
            r = subprocess.run(["node", "--check", str(tmp)], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, f"前端脚本语法错误:\n{r.stderr[:1000]}")
        finally:
            tmp.unlink()


if __name__ == "__main__":
    unittest.main()
