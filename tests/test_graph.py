"""攻击链图构建测试：world.json 假设 + from 依赖 → nodes/edges。"""
import json
import tempfile
import unittest
from pathlib import Path

from pentest_agent.workspace.graph import build_attack_graph


class TestAttackGraph(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())

    def _write(self, world, findings):
        (self.d / "world.json").write_text(json.dumps(world, ensure_ascii=False), encoding="utf-8")
        (self.d / "findings.json").write_text(json.dumps(findings, ensure_ascii=False), encoding="utf-8")

    def test_empty(self):
        self._write({}, [])
        self.assertEqual(build_attack_graph(self.d), {"nodes": [], "edges": []})

    def test_full_chain(self):
        self._write(
            {
                "fingerprint": "nginx",
                "hypotheses": [
                    {"id": "i001", "text": "目录探测", "status": "hit", "from": ["fingerprint"]},
                    {"id": "i002", "text": "衍生验证", "status": "open", "from": ["i001"]},
                ],
            },
            [{"id": 1, "title": "目录枚举", "duplicate": False}],
        )
        g = build_attack_graph(self.d)
        node_ids = {n["id"]: n for n in g["nodes"]}
        self.assertIn("fingerprint", node_ids)
        self.assertIn("i001", node_ids)
        self.assertIn("i002", node_ids)
        self.assertIn("#1", node_ids)
        self.assertEqual(node_ids["fingerprint"]["type"], "root")
        self.assertEqual(node_ids["#1"]["type"], "finding")
        edges = {(e["from"], e["to"]) for e in g["edges"]}
        self.assertIn(("fingerprint", "i001"), edges)
        self.assertIn(("i001", "i002"), edges)

    def test_duplicate_finding_skipped(self):
        self._write({}, [{"id": 1, "title": "a", "duplicate": True}, {"id": 2, "title": "b", "duplicate": False}])
        g = build_attack_graph(self.d)
        finding_nodes = [n for n in g["nodes"] if n["type"] == "finding"]
        self.assertEqual([n["id"] for n in finding_nodes], ["#2"])


if __name__ == "__main__":
    unittest.main()
