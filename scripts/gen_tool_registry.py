"""CLI 包装:扫描本地工具库,生成 tools.local.yaml 货架草稿。

用法:
  python scripts/gen_tool_registry.py --dir E:/安全/tools
  python scripts/gen_tool_registry.py --dir D:/tools --out config/tools.local.yaml --include-py
详见 pentest_agent/tools/gen_registry.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pentest_agent.tools.gen_registry import main

if __name__ == "__main__":
    raise SystemExit(main())
