"""Rule Registry — remote download + local installed.json management.

A RuleRegistry knows how to:
  - Fetch a remote index.yaml listing available community rules
  - Download individual rule YAML files to a target directory
  - Read / write the local installed.json manifest
  - Detect conflicts between installed and remote rules
"""

from __future__ import annotations

import json
import logging
import re
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import yaml as _yaml
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# ── Rule validation result ─────────────────────────────────────


@dataclass
class RuleValidationResult:
    """Result of scanning downloaded rule files for safety."""

    passed: bool
    risk_score: int  # 0-100
    risk_level: str  # low | medium | high | critical
    issues: list[str] = field(default_factory=list)
    file_count: int = 0

# ── Suspicious patterns for rule YAML files ────────────────────

# Patterns that should NEVER appear in a legitimate rule YAML
_SUSPICIOUS_PATTERNS: list[tuple[str, str, str]] = [
    # (regex, severity, description)
    (r'(?:os\.system|subprocess\.(?:call|run|Popen)|exec\s*\(|eval\s*\()',
     "critical", "Code execution pattern in rule file"),
    (r'(?:rm\s+-rf\s+/|del\s+/[fs]|format\s+[cdefgh]:)',
     "critical", "Destructive filesystem pattern in rule file"),
    (r'(?:(?:curl|wget)\s+(?!https://github\.com/aaa-mvc)[^|&;]*\|?\s*(?:sh|bash|python))',
     "critical", "Remote shell piping in rule file"),
    (r'(?:-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH)\s+PRIVATE\s+KEY-----)',
     "critical", "Embedded private key in rule file"),
    (r'__import__\s*\(', "high", "Dynamic import in rule file"),
    (r'base64\.(?:b64decode|decodestring)\s*\(', "high", "Obfuscated payload pattern in rule file"),
]

# Required top-level keys in a valid rule YAML
_REQUIRED_RULE_KEYS = {"id", "name", "severity", "category"}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}

# ── Models ───────────────────────────────────────────────────────


class RemoteRuleInfo(BaseModel):
    """Information about a rule available from the remote index."""

    name: str = ""
    version: str = ""
    description: str = ""
    behavior_id: str = ""
    files: list[str] = Field(default_factory=list)


class InstalledRule(BaseModel):
    """A record in installed.json for a locally installed rule."""

    name: str
    version: str
    behavior_id: str = ""
    description: str = ""
    installed_at: str = ""  # ISO 8601
    files: list[str] = Field(default_factory=list)


class InstalledManifest(BaseModel):
    """The installed.json file format."""

    rules: list[InstalledRule] = Field(default_factory=list)


# ── RuleRegistry ─────────────────────────────────────────────────


class RuleRegistry:
    """Manage remote rule discovery and local installation tracking.

    Usage:
        registry = RuleRegistry()

        # List remote rules
        for info in registry.list_remote():
            print(f"{info.name} v{info.version}")

        # Download a rule
        paths = registry.download_rule("B1-data-exfil", temp_dir)

        # Check local installation
        installed = registry.read_installed(Path(".aga/rules"))
    """

    INDEX_FILENAME = "index.yaml"
    INSTALLED_FILENAME = "installed.json"
    REQUEST_TIMEOUT = 30.0  # seconds

    # ── Remote operations ───────────────────────────────────────

    def fetch_index(self, source_url: str) -> dict[str, Any]:
        """Fetch the remote index.yaml and return its parsed contents.

        Expected format:
            rules:
              rule-name:
                version: "1.0.0"
                description: "..."
                behavior_id: "B1"
                files:
                  - rule-name/file-a.yaml
                  - rule-name/file-b.yaml

        Args:
            source_url: Base URL of the rule repository.

        Returns:
            Parsed YAML dict, or empty dict on failure.
        """
        url = f"{source_url.rstrip('/')}/{self.INDEX_FILENAME}"
        try:
            resp = httpx.get(url, timeout=self.REQUEST_TIMEOUT, follow_redirects=True)
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            logger.warning(f"Failed to fetch index from {url}: {exc}")
            return {}

        # Parse YAML from response
        import yaml

        try:
            data = yaml.safe_load(resp.text)
        except yaml.YAMLError as exc:
            logger.warning(f"Invalid YAML in remote index {url}: {exc}")
            return {}

        if not isinstance(data, dict):
            logger.warning(f"Remote index {url} is not a mapping")
            return {}

        return data

    def list_remote(self, source_url: str) -> list[RemoteRuleInfo]:
        """Fetch and flatten the remote index into a list of RemoteRuleInfo.

        Args:
            source_url: Base URL of the rule repository.

        Returns:
            List of RemoteRuleInfo, sorted by name.
        """
        data = self.fetch_index(source_url)
        rules_dict = data.get("rules", {})
        if not isinstance(rules_dict, dict):
            return []

        result: list[RemoteRuleInfo] = []
        for name, info in rules_dict.items():
            if not isinstance(info, dict):
                continue
            result.append(
                RemoteRuleInfo(
                    name=name,
                    version=str(info.get("version", "0.0.0")),
                    description=str(info.get("description", "")),
                    behavior_id=str(info.get("behavior_id", "")),
                    files=[str(f) for f in info.get("files", [])],
                )
            )

        result.sort(key=lambda r: r.name)
        return result

    def download_rule(
        self,
        name: str,
        dest: Path,
        source_url: str,
        version: str | None = None,
    ) -> list[Path]:
        """Download all YAML files for a rule to *dest*.

        Resolves the rule's file list from the remote index, then downloads
        each YAML file individually.

        Args:
            name: Rule name (must match the key in index.yaml).
            dest: Destination directory (will be created if needed).
            source_url: Base URL of the rule repository.
            version: Ignored in MVP (always fetches whatever index points to).

        Returns:
            List of Path objects pointing to downloaded files.
        """
        dest.mkdir(parents=True, exist_ok=True)

        # Resolve file list from remote index
        index = self.fetch_index(source_url)
        rules_dict = index.get("rules", {})
        rule_info = rules_dict.get(name)
        if not isinstance(rule_info, dict):
            raise ValueError(
                f"Rule '{name}' not found in remote index. "
                f"Run 'aga rule list --remote' to see available rules."
            )

        files = rule_info.get("files", [])
        if not files:
            raise ValueError(f"Rule '{name}' has no files listed in remote index.")

        base_url = source_url.rstrip("/")
        downloaded: list[Path] = []

        for file_rel in files:
            file_rel = str(file_rel).lstrip("/")
            url = f"{base_url}/{file_rel}"
            file_name = Path(file_rel).name  # e.g. "network-exfil.yaml"

            try:
                resp = httpx.get(
                    url,
                    timeout=self.REQUEST_TIMEOUT,
                    follow_redirects=True,
                )
                resp.raise_for_status()
            except httpx.HTTPError as exc:
                logger.warning(f"Failed to download {url}: {exc}")
                continue

            target = dest / file_name
            target.write_bytes(resp.content)
            downloaded.append(target)
            logger.info(f"Downloaded {url} → {target}")

        if not downloaded:
            raise RuntimeError(
                f"Failed to download any files for rule '{name}'. Check network."
            )

        return downloaded

    # ── Local operations ─────────────────────────────────────────

    def get_install_dir(
        self,
        local: bool = False,
        global_: bool = False,
        project_dir: Path | None = None,
    ) -> Path:
        """Resolve the rule installation directory.

        See aga.sdk.config.resolve_install_path for full logic.
        """
        from aga.sdk.config import resolve_install_path

        return resolve_install_path(local=local, global_=global_, project_dir=project_dir)

    def read_installed(self, install_dir: Path) -> list[InstalledRule]:
        """Read installed.json from *install_dir*.

        Returns an empty list if the file doesn't exist or is invalid.
        """
        manifest_path = install_dir / self.INSTALLED_FILENAME
        if not manifest_path.is_file():
            return []

        try:
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest = InstalledManifest.model_validate(data)
            return manifest.rules
        except Exception as exc:
            logger.warning(f"Failed to read {manifest_path}: {exc}")
            return []

    def write_installed(
        self,
        install_dir: Path,
        rules: list[InstalledRule],
    ) -> None:
        """Write installed.json to *install_dir*."""
        install_dir.mkdir(parents=True, exist_ok=True)
        manifest = InstalledManifest(rules=rules)
        manifest_path = install_dir / self.INSTALLED_FILENAME
        manifest_path.write_text(
            json.dumps(
                manifest.model_dump(mode="json"),
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )

    def is_installed(self, name: str, install_dir: Path) -> InstalledRule | None:
        """Check if a rule with *name* is already installed.

        Returns the InstalledRule if found, None otherwise.
        """
        for rule in self.read_installed(install_dir):
            if rule.name == name:
                return rule
        return None

    def add_installed(self, install_dir: Path, record: InstalledRule) -> None:
        """Append or replace a rule record in installed.json.

        If a rule with the same name already exists, its record is replaced.
        """
        rules = self.read_installed(install_dir)
        # Remove existing entry with same name
        rules = [r for r in rules if r.name != record.name]
        rules.append(record)
        rules.sort(key=lambda r: r.name)
        self.write_installed(install_dir, rules)

    def remove_installed(self, install_dir: Path, name: str) -> bool:
        """Remove a rule record and delete its files.

        Returns True if the rule was found and removed, False otherwise.
        """
        rules = self.read_installed(install_dir)
        target = next((r for r in rules if r.name == name), None)
        if target is None:
            return False

        # Delete rule files
        for file_name in target.files:
            file_path = install_dir / file_name
            if file_path.is_file():
                file_path.unlink()
                logger.info(f"Deleted {file_path}")

        # Remove from manifest
        rules = [r for r in rules if r.name != name]
        if rules:
            self.write_installed(install_dir, rules)
        else:
            # Remove empty manifest
            manifest_path = install_dir / self.INSTALLED_FILENAME
            if manifest_path.exists():
                manifest_path.unlink()

        return True

    def install_files(
        self,
        rule_name: str,
        version: str,
        downloaded_files: list[Path],
        install_dir: Path,
        remote_info: dict[str, Any] | None = None,
    ) -> InstalledRule:
        """Copy downloaded files to *install_dir* and record in installed.json.

        Args:
            rule_name: Rule name.
            version: Rule version string.
            downloaded_files: Paths to downloaded YAML files.
            install_dir: Target installation directory.
            remote_info: Optional remote rule metadata (description, behavior_id).

        Returns:
            The InstalledRule record that was written.
        """
        install_dir.mkdir(parents=True, exist_ok=True)
        installed_files: list[str] = []

        for src in downloaded_files:
            dst = install_dir / src.name
            shutil.copy2(src, dst)
            installed_files.append(src.name)
            logger.info(f"Installed {src.name} → {dst}")

        description = ""
        behavior_id = ""
        if isinstance(remote_info, dict):
            description = str(remote_info.get("description", ""))
            behavior_id = str(remote_info.get("behavior_id", ""))

        record = InstalledRule(
            name=rule_name,
            version=version,
            behavior_id=behavior_id,
            description=description,
            installed_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            files=installed_files,
        )

        self.add_installed(install_dir, record)
        return record

    # ── Rule file validation ────────────────────────────────────

    @classmethod
    def validate_rule_files(cls, files: list[Path]) -> RuleValidationResult:
        """Validate downloaded rule YAML files for safety and correctness.

        Checks:
          1. YAML is well-formed and safe-parseable
          2. Required rule keys are present (id, name, severity, category)
          3. No suspicious code injection patterns embedded in the YAML

        This is a lightweight static check — NOT the full Analyzer pipeline.
        Rule YAML files loaded by ``yaml.safe_load`` cannot execute code,
        but we still verify they contain no embedded payloads.

        Args:
            files: Paths to downloaded rule YAML files.

        Returns:
            RuleValidationResult with passed/failed, risk_score, and issues.
        """
        issues: list[str] = []
        file_count = 0
        max_risk = 0
        max_level = "low"

        for file_path in files:
            if file_path.suffix.lower() not in (".yaml", ".yml"):
                continue
            file_count += 1

            # 1. Parse YAML safely
            try:
                raw = file_path.read_text(encoding="utf-8", errors="replace")
                data = _yaml.safe_load(raw)
            except _yaml.YAMLError as exc:
                issues.append(f"{file_path.name}: invalid YAML — {exc}")
                max_risk = max(max_risk, 80)
                max_level = "high"
                continue
            except Exception as exc:
                issues.append(f"{file_path.name}: cannot read file — {exc}")
                max_risk = max(max_risk, 80)
                max_level = "high"
                continue

            if not isinstance(data, dict):
                issues.append(f"{file_path.name}: not a rule mapping")
                max_risk = max(max_risk, 50)
                max_level = "medium"
                continue

            # 2. Check required keys
            missing = _REQUIRED_RULE_KEYS - set(data.keys())
            if missing:
                issues.append(f"{file_path.name}: missing keys: {', '.join(sorted(missing))}")
                max_risk = max(max_risk, 40)
                max_level = "medium"

            # 3. Validate severity value
            severity = str(data.get("severity", "")).lower()
            if severity and severity not in _VALID_SEVERITIES:
                issues.append(f"{file_path.name}: invalid severity '{severity}'")
                max_risk = max(max_risk, 30)
                if max_level == "low":
                    max_level = "medium"

            # 4. Scan for suspicious patterns
            for pattern, sev, desc in _SUSPICIOUS_PATTERNS:
                if re.search(pattern, raw, re.IGNORECASE):
                    issues.append(f"{file_path.name}: {desc}")
                    if sev == "critical":
                        max_risk = max(max_risk, 90)
                        max_level = "critical"
                    elif sev == "high":
                        max_risk = max(max_risk, 70)
                        if max_level not in ("critical",):
                            max_level = "high"

        # Determine final level from score
        if max_risk > 0:
            if max_risk >= 80:
                max_level = "critical"
            elif max_risk >= 55:
                max_level = "high"
            elif max_risk >= 30:
                max_level = "medium"

        passed = max_level not in ("high", "critical")

        return RuleValidationResult(
            passed=passed,
            risk_score=max_risk,
            risk_level=max_level,
            issues=issues,
            file_count=file_count,
        )
