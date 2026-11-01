"""技能卡写入/合并/可见性单元测试（中性技能名，无攻击内容）。"""
import tempfile
import unittest
from pathlib import Path

from pentest_agent.skills import save_skill_card, list_skills


class TestSaveSkillCard(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp()) / "skills"

    def test_create(self):
        out = save_skill_card("web-recon-flow", "信息收集流程", ["信息收集"], "1. 先看指纹", self.base, source_session="s1")
        self.assertEqual(out, "created")
        self.assertTrue((self.base / "web-recon-flow" / "SKILL.md").exists())

    def test_merge_case_insensitive(self):
        save_skill_card("web-recon-flow", "信息收集流程", ["信息收集"], "1. 先看指纹", self.base, source_session="s1")
        out = save_skill_card("WEB-RECON-FLOW", "忽略描述", ["端口"], "2. 再看端口", self.base, source_session="s2")
        self.assertEqual(out, "updated")
        txt = (self.base / "web-recon-flow" / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("补充（自动沉淀）", txt)   # body 追加
        self.assertIn("信息收集", txt)            # when 并集保留
        self.assertIn("端口", txt)                # 新 when 并入

    def test_merge_preserves_name(self):
        save_skill_card("web-recon-flow", "信息收集流程", [], "正文", self.base, source_session="s1")
        save_skill_card("WEB-RECON-FLOW", "x", [], "补充", self.base, source_session="s2")
        names = [c["name"] for c in list_skills({"skills": {"dir": str(self.base)}})]
        self.assertIn("web-recon-flow", names)
        self.assertNotIn("WEB-RECON-FLOW", names)

    def test_skip_hidden_dir(self):
        save_skill_card("visible-skill", "d", [], "正文", self.base, source_session="s1")
        (self.base / ".pending").mkdir(exist_ok=True)
        (self.base / ".pending" / "SKILL.md").write_text("---\nname: hidden\n---\n正文", encoding="utf-8")
        names = [c["name"] for c in list_skills({"skills": {"dir": str(self.base)}})]
        self.assertIn("visible-skill", names)
        self.assertNotIn("hidden", names)


if __name__ == "__main__":
    unittest.main()
