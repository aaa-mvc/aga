"""Unit tests for the Skill Parser."""

import pytest

from aga.sdk.parser import Parser, SkillIR, SkillMeta


class TestParser:
    """Test SKILL.md parsing and validation."""

    def test_parse_minimal_skill_md(self, tmp_path):
        """Parse a minimal SKILL.md with frontmatter."""
        skill_dir = tmp_path / "test-skill"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text(
            "---\nname: test-skill\ndescription: A test skill\n---\n\n# Instructions\nDo something."
        )

        parser = Parser()
        ir = parser.parse(skill_dir)

        assert isinstance(ir, SkillIR)
        assert ir.meta.name == "test-skill"
        assert "Do something" in ir.instructions_raw
        assert ir.code_artifacts == []

    def test_parse_with_scripts(self, tmp_path):
        """Parse a skill with a scripts/ directory."""
        skill_dir = tmp_path / "test-skill"
        skill_dir.mkdir()
        scripts_dir = skill_dir / "scripts"
        scripts_dir.mkdir()
        (skill_dir / "SKILL.md").write_text("---\nname: test-skill\n---\n\n# Instructions")
        (scripts_dir / "helper.py").write_text("print('hello')")

        parser = Parser()
        ir = parser.parse(skill_dir)

        assert len(ir.code_artifacts) == 1
        assert ir.code_artifacts[0].language == "python"
        assert ir.code_artifacts[0].path.replace("\\", "/") == "scripts/helper.py"

    def test_parse_rejects_missing_skill_md(self, tmp_path):
        """Parser should raise FileNotFoundError if SKILL.md is missing."""
        skill_dir = tmp_path / "empty-skill"
        skill_dir.mkdir()

        parser = Parser()
        with pytest.raises(FileNotFoundError, match="SKILL.md"):
            parser.parse(skill_dir)

    def test_parse_rejects_not_a_directory(self, tmp_path):
        """Parser should raise ValueError if path is not a directory."""
        not_a_dir = tmp_path / "just-a-file.txt"
        not_a_dir.write_text("hello")

        parser = Parser()
        with pytest.raises(ValueError, match="Not a directory"):
            parser.parse(not_a_dir)

    def test_parse_empty_frontmatter(self, tmp_path):
        """Skills without frontmatter should get default name."""
        skill_dir = tmp_path / "test-skill"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text("# Just a heading\n\nSome content.")

        parser = Parser()
        ir = parser.parse(skill_dir)

        assert ir.meta.name == "unknown"


class TestSkillIR:
    """Test SkillIR validation."""

    def test_empty_ir_rejected(self):
        """SkillIR with no instructions and no code should be invalid."""
        with pytest.raises(ValueError, match="either instructions or code"):
            SkillIR(
                meta=SkillMeta(name="test"),
                instructions_raw="",
                code_artifacts=[],
            )
