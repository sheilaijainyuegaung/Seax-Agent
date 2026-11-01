"""工作记忆与漏洞库单元测试：假设自动分配 id、from 依赖链、render 渲染、原子落盘、重复漏洞 id。"""
import tempfile
import unittest
from pathlib import Path

from pentest_agent.workspace.memory import WorkingMemory
from pentest_agent.workspace.session import Workspace


class TestWorkingMemoryFactGraph(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.mkdtemp()
        self.wm = WorkingMemory(Path(tmp) / "world.json")

    def test_assigns_incrementing_ids(self):
        self.wm.update_world(hypothesis="假设甲")
        self.wm.update_world(hypothesis="假设乙")
        ids = [h["id"] for h in self.wm.data["hypotheses"]]
        self.assertEqual(ids, ["i001", "i002"])

    def test_records_from_facts(self):
        self.wm.update_world(hypothesis="根假设")
        self.wm.update_world(hypothesis="衍生假设", from_facts=["i001", "fingerprint", "#1"])
        derived = self.wm.data["hypotheses"][-1]
        self.assertEqual(derived["from"], ["i001", "fingerprint", "#1"])

    def test_same_text_updates_not_duplicates(self):
        self.wm.update_world(hypothesis="同一假设", status="open")
        self.wm.update_world(hypothesis="同一假设", status="hit")
        self.assertEqual(len(self.wm.data["hypotheses"]), 1)
        self.assertEqual(self.wm.data["hypotheses"][0]["status"], "hit")

    def test_render_contains_id_and_source(self):
        self.wm.update_world(hypothesis="假设甲", from_facts=["fingerprint"])
        text = self.wm.render([], [], [])
        self.assertIn("i001", text)
        self.assertIn("fingerprint", text)


class TestMemoryAtomicSave(unittest.TestCase):
    """world.json 必须原子写：写坏后 _load 会静默清空整个世界模型，断点续传就废了。"""

    def test_no_tmp_residue_after_save(self):
        tmp = Path(tempfile.mkdtemp())
        wm = WorkingMemory(tmp / "world.json")
        wm.update_world(hypothesis="假设甲", status="hit")
        self.assertFalse((tmp / "world.json.tmp").exists())
        # 落盘内容可读回
        again = WorkingMemory(tmp / "world.json")
        self.assertEqual(again.data["hypotheses"][0]["status"], "hit")


class TestFindingDuplicateId(unittest.TestCase):
    def test_duplicate_returns_matched_id(self):
        tmp = Path(tempfile.mkdtemp())
        ws = Workspace(tmp, "s_dup", {"mode": "pentest"})
        (ws.evidence_dir / "http_1_request.txt").write_text("GET / HTTP/1.1\nHost: x\n\n", encoding="utf-8")
        (ws.evidence_dir / "http_1_response.txt").write_text("HTTP/1.1 200 OK\n\nok", encoding="utf-8")
        f1 = ws.add_finding({"title": "漏洞A", "severity": "high", "evidence": ["evidence/http_1_request.txt"]})
        f2 = ws.add_finding({"title": "漏洞B", "severity": "low", "evidence": ["evidence/http_1_request.txt"]})
        dup = ws.add_finding({"title": "漏洞A", "severity": "high", "evidence": ["evidence/http_1_request.txt"]})
        self.assertTrue(dup["duplicate"])
        # 必须指向实际重复的那条，而不是清单最后一条
        self.assertEqual(dup["id"], f1["id"])
        self.assertNotEqual(dup["id"], f2["id"])


if __name__ == "__main__":
    unittest.main()
