"""Skill Parser — parse SKILL.md + scripts/ into a standardized SkillIR.

This is the first line of defense: input validation happens at the Pydantic model level.
Malformed or oversized inputs are rejected before they reach the Rule Engine.
"""

from __future__ import annotations

import re
from pathlib import Path

from pydantic import BaseModel, Field, model_validator

# ── Constants ──────────────────────────────────────────────────

MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB
MAX_FRONTMATTER_SIZE = 64 * 1024  # 64 KB
MAX_CODE_ARTIFACTS = 50
SUPPORTED_LANGUAGES = {
    ".py": "python",
    ".sh": "bash",
    ".bash": "bash",
    ".js": "javascript",
    ".ts": "typescript",
    ".ps1": "powershell",
    ".rb": "ruby",
    ".go": "go",
    ".rs": "rust",
}


# ── Pydantic IR Models ─────────────────────────────────────────


class SkillMeta(BaseModel):
    """Metadata extracted from SKILL.md frontmatter."""

    name: str = Field(..., max_length=256)
    description: str = Field(default="", max_length=2048)
    version: str | None = Field(default=None, max_length=64)
    author: str | None = Field(default=None, max_length=256)
    homepage: str | None = Field(default=None, max_length=2048)
    declared_permissions: list[str] = Field(default_factory=list, max_length=100)
    declared_intent: str = Field(default="", max_length=4096)
    allowed_tools: list[str] = Field(default_factory=list, max_length=100)


class CodeArtifact(BaseModel):
    """A single code file within a skill."""

    path: str = Field(..., max_length=1024)
    language: str = Field(default="unknown", max_length=64)
    content: str = Field(default="", max_length=MAX_FILE_SIZE)
    size_bytes: int = Field(default=0, ge=0)


class SkillIR(BaseModel):
    """Intermediate representation of a skill for security analysis.

    This is the universal currency passed from Parser → Rule Engine → Reporter.
    """

    meta: SkillMeta
    instructions_raw: str = Field(default="", max_length=MAX_FILE_SIZE)
    code_artifacts: list[CodeArtifact] = Field(default_factory=list, max_length=MAX_CODE_ARTIFACTS)
    dependencies: dict[str, list[str]] = Field(default_factory=dict)

    @model_validator(mode="after")
    def check_not_empty(self) -> SkillIR:
        if not self.instructions_raw.strip() and not self.code_artifacts:
            raise ValueError("Skill must have either instructions or code artifacts")
        return self


# ── Parser ─────────────────────────────────────────────────────


class Parser:
    """Parse a skill directory into a SkillIR.

    Usage:
        parser = Parser()
        ir = parser.parse("./my-skill")
        # Or from raw content (for streaming / git-based analysis):
        ir = parser.parse_raw(skill_md_content, scripts={"main.py": "..."})
    """

    def parse_raw(
        self,
        skill_md_content: str,
        scripts: dict[str, str] | None = None,
        skill_name: str = "unknown",
    ) -> SkillIR:
        """Parse skill from raw strings (no filesystem access).

        Args:
            skill_md_content: Full text of SKILL.md
            scripts: Dict of {path: content} for each script file
            skill_name: Human-readable name for logging

        Returns:
            SkillIR ready for analysis
        """
        if len(skill_md_content) > self.max_file_size:
            raise ValueError(f"SKILL.md exceeds max size ({self.max_file_size} bytes)")

        frontmatter, body = self._split_frontmatter(skill_md_content)
        meta = self._parse_frontmatter(frontmatter)

        code_artifacts: list[CodeArtifact] = []
        for path, content in (scripts or {}).items():
            if len(code_artifacts) >= self.max_code_artifacts:
                break
            if len(content) > self.max_file_size:
                continue
            suffix = Path(path).suffix.lower()
            language = SUPPORTED_LANGUAGES.get(suffix, "unknown")
            code_artifacts.append(
                CodeArtifact(
                    path=path,
                    language=language,
                    content=content,
                    size_bytes=len(content.encode("utf-8")),
                )
            )

        # Extract code blocks from SKILL.md body (handles skills with code in fences, not scripts/)
        md_artifacts = self._extract_md_code_blocks(body)
        for ma in md_artifacts:
            if len(code_artifacts) >= self.max_code_artifacts:
                break
            code_artifacts.append(ma)

        return SkillIR(
            meta=meta,
            instructions_raw=body,
            code_artifacts=code_artifacts,
            dependencies={},  # Not parsed in raw mode
        )

    def __init__(
        self,
        max_file_size: int = MAX_FILE_SIZE,
        max_code_artifacts: int = MAX_CODE_ARTIFACTS,
    ) -> None:
        self.max_file_size = max_file_size
        self.max_code_artifacts = max_code_artifacts

    def parse(self, path: str | Path) -> SkillIR:
        """Parse a skill directory and return a SkillIR."""
        root = Path(path).resolve()
        if not root.is_dir():
            raise ValueError(f"Not a directory: {root}")

        # 1. Parse SKILL.md
        skill_md = root / "SKILL.md"
        if not skill_md.exists():
            raise FileNotFoundError(f"SKILL.md not found in {root}")

        raw_content = skill_md.read_text(encoding="utf-8-sig", errors="replace")
        if len(raw_content) > self.max_file_size:
            raise ValueError(f"SKILL.md exceeds max size ({self.max_file_size} bytes)")

        frontmatter, body = self._split_frontmatter(raw_content)
        meta = self._parse_frontmatter(frontmatter)

        # 2. Parse scripts/ directory
        scripts_dir = root / "scripts"
        code_artifacts = []
        if scripts_dir.is_dir():
            code_artifacts = self._parse_scripts(scripts_dir)

        # 2b. Extract code blocks from SKILL.md body (skills with code in fences)
        md_artifacts = self._extract_md_code_blocks(body)
        for ma in md_artifacts:
            if len(code_artifacts) >= self.max_code_artifacts:
                break
            # Avoid duplicating files that are already in scripts/
            if not any(a.path == ma.path for a in code_artifacts):
                code_artifacts.append(ma)

        # 3. Parse dependencies
        dependencies = self._parse_dependencies(root)

        return SkillIR(
            meta=meta,
            instructions_raw=body,
            code_artifacts=code_artifacts,
            dependencies=dependencies,
        )

    # ── Markdown code block extraction ──────────────────────────

    @staticmethod
    def _extract_md_code_blocks(body: str) -> list[CodeArtifact]:
        """Extract fenced code blocks from SKILL.md body text.

        Handles ```language ... ``` and ``` ... ``` blocks.
        Returns CodeArtifact objects that can be analyzed by the Rule Engine.
        """
        artifacts: list[CodeArtifact] = []
        # Match fenced code blocks with optional language tag
        pattern = r"```(\S*)\n(.*?)```"
        for i, match in enumerate(re.finditer(pattern, body, re.DOTALL)):
            lang = match.group(1).strip().lower() if match.group(1) else ""
            code = match.group(2)
            if not code.strip():
                continue
            # Map common language tags to our supported languages
            lang_map = {
                "python": "python",
                "py": "python",
                "bash": "bash",
                "sh": "bash",
                "shell": "bash",
                "javascript": "javascript",
                "js": "javascript",
                "typescript": "typescript",
                "ts": "typescript",
                "powershell": "powershell",
                "ps1": "powershell",
                "ruby": "ruby",
                "rb": "ruby",
                "go": "go",
                "golang": "go",
                "rust": "rust",
                "rs": "rust",
            }
            resolved_lang = lang_map.get(lang, lang if lang else "unknown")
            artifacts.append(
                CodeArtifact(
                    path=f"SKILL.md:block{i + 1}",
                    language=resolved_lang,
                    content=code,
                    size_bytes=len(code.encode("utf-8")),
                )
            )
        return artifacts

    # ── Private helpers ─────────────────────────────────────────

    @staticmethod
    def _split_frontmatter(content: str) -> tuple[str, str]:
        """Split YAML frontmatter from markdown body."""
        pattern = r"^---\s*\n(.*?)\n---\s*\n"
        match = re.match(pattern, content, re.DOTALL)
        if match:
            return match.group(1), content[match.end() :]
        return "", content

    @staticmethod
    def _parse_frontmatter(raw: str) -> SkillMeta:
        """Parse YAML frontmatter into SkillMeta."""
        if not raw.strip():
            return SkillMeta(name="unknown")

        import yaml

        try:
            data = yaml.safe_load(raw)
        except yaml.YAMLError:
            return SkillMeta(name="unknown")

        if not isinstance(data, dict):
            return SkillMeta(name="unknown")

        # Normalize: some SKILL.md files use comma-separated strings for lists
        allowed_tools_raw = data.get("allowed-tools", [])
        if isinstance(allowed_tools_raw, str):
            allowed_tools_raw = [t.strip() for t in allowed_tools_raw.split(",") if t.strip()]

        permissions_raw = data.get("permissions", [])
        if isinstance(permissions_raw, str):
            permissions_raw = [p.strip() for p in permissions_raw.split(",") if p.strip()]

        # Normalize version: YAML may parse "1.0" as float
        version_raw = data.get("version")
        if version_raw is not None and not isinstance(version_raw, str):
            version_raw = str(version_raw)

        return SkillMeta(
            name=str(data.get("name", "unknown")),
            description=str(data.get("description", "")),
            version=version_raw,
            author=data.get("author"),
            homepage=data.get("homepage"),
            declared_permissions=permissions_raw if isinstance(permissions_raw, list) else [],
            declared_intent=str(data.get("description", "")),
            allowed_tools=allowed_tools_raw if isinstance(allowed_tools_raw, list) else [],
        )

    def _parse_scripts(self, scripts_dir: Path) -> list[CodeArtifact]:
        """Recursively discover and parse script files."""
        artifacts: list[CodeArtifact] = []
        for file_path in scripts_dir.rglob("*"):
            if not file_path.is_file():
                continue
            if len(artifacts) >= self.max_code_artifacts:
                break
            if file_path.stat().st_size > self.max_file_size:
                continue

            suffix = file_path.suffix.lower()
            if suffix not in SUPPORTED_LANGUAGES:
                continue

            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            artifacts.append(
                CodeArtifact(
                    path=str(file_path.relative_to(scripts_dir.parent)),
                    language=SUPPORTED_LANGUAGES[suffix],
                    content=content,
                    size_bytes=len(content.encode("utf-8")),
                )
            )
        return artifacts

    @staticmethod
    def _parse_dependencies(root: Path) -> dict[str, list[str]]:
        """Extract declared dependencies from standard files."""
        deps: dict[str, list[str]] = {}

        # Python
        req_file = root / "requirements.txt"
        if req_file.exists():
            lines = req_file.read_text(errors="replace").strip().split("\n")
            deps["python"] = [
                line.strip() for line in lines if line.strip() and not line.startswith("#")
            ]

        # Node.js
        pkg_file = root / "package.json"
        if pkg_file.exists():
            import json

            try:
                pkg = json.loads(pkg_file.read_text())
                all_deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
                deps["node"] = list(all_deps.keys())
            except (json.JSONDecodeError, KeyError):
                pass

        return deps
