"""Test configuration and shared fixtures for AGA tests."""

from pathlib import Path

import pytest

TESTS_DIR = Path(__file__).parent
FIXTURES_DIR = TESTS_DIR / "fixtures" / "skills"
BENIGN_FIXTURES_DIR = FIXTURES_DIR / "benign"
MALWARE_FIXTURES_DIR = FIXTURES_DIR / "malware"
BUILTIN_RULES_DIR = TESTS_DIR.parent / "aga" / "sdk" / "rules" / "builtin"


@pytest.fixture
def fixtures_dir() -> Path:
    """Path to test fixtures directory."""
    return FIXTURES_DIR


@pytest.fixture
def builtin_rules_dir() -> Path:
    """Path to built-in rules directory."""
    return BUILTIN_RULES_DIR
