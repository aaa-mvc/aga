"""Behavior taxonomy definitions for malicious agent skills.

Derived from MalSkillBench (MIT License):
  - B1-B9:  Code Injection behaviors (code-level attacks)
  - B10-B15: Prompt Injection behaviors (instruction-level attacks)

These definitions are embedded directly in AGA as runtime constants,
following the "core taxonomy embedded" strategy from design decision D.4.1.3.
"""

from __future__ import annotations

from enum import Enum


class AttackVector(str, Enum):
    """Attack vector classification."""

    CI = "CI"  # Code Injection — malicious code in scripts/ or code blocks
    PI = "PI"  # Prompt Injection — manipulative text in SKILL.md
    MIXED = "MIXED"  # Coordinated CI + PI multi-stage attack


# ── Behavior definitions ───────────────────────────────────────

CI_BEHAVIORS: dict[str, tuple[str, str]] = {
    "B1": ("Data Exfiltration", "Scan and send files/data to external endpoint"),
    "B2": ("Credential Theft", "Steal API keys, SSH keys, passwords, env vars"),
    "B3": ("Remote Code Execution", "Download and execute remote code (one-shot)"),
    "B4": ("Malware Delivery", "Download, install, and run a malware binary"),
    "B5": ("Persistence", "Write to cron, bashrc, systemd for survival"),
    "B6": ("Reverse Shell", "Establish reverse shell to attacker"),
    "B7": ("Ransomware", "Encrypt user files and demand payment"),
    "B8": ("Resource Abuse", "Cryptomining, DDoS, fork bomb"),
    "B9": ("Privilege Escalation", "chmod 4755, sudo abuse, container escape"),
}

PI_ONLY_BEHAVIORS: dict[str, tuple[str, str]] = {
    "B10": ("Role Hijack", "Replace agent identity via persona injection"),
    "B11": ("Safety Bypass", "Instruct agent to ignore safety rules"),
    "B12": ("Instruction Override", "Ignore previous instructions payloads"),
    "B13": ("System Prompt Leak", "Induce agent to reveal its system prompt"),
    "B14": ("Goal Hijacking", "Covertly redirect agent task"),
    "B15": ("Content Manipulation", "Inject biased or false content into outputs"),
}

ALL_BEHAVIORS = {**CI_BEHAVIORS, **PI_ONLY_BEHAVIORS}

CI_BEHAVIOR_IDS: set[str] = set(CI_BEHAVIORS.keys())
PI_BEHAVIOR_IDS: set[str] = set(CI_BEHAVIORS.keys()) | set(PI_ONLY_BEHAVIORS.keys())

# ── Keyword signatures for rule matching ───────────────────────

CI_BEHAVIOR_KEYWORDS: dict[str, list[str]] = {
    "B1": ["exfiltrat", "steal.*data", "send.*data", "upload.*file", "transmit", "leak.*data"],
    "B2": [
        "credential",
        "password",
        "api.key",
        "token",
        "secret",
        "aws.key",
        "auth",
        "ssh.key",
        "env.var",
    ],
    "B3": [
        "remote.code",
        "urlopen.*exec",
        "download.*exec",
        "fetch.*run",
        "eval.*url",
        "download.*script",
    ],
    "B4": [
        "malware",
        "trojan",
        "dropper",
        "install.*backdoor",
        "download.*binary",
        "download.*execut",
    ],
    "B5": ["persist", "startup", "cron", "bashrc", "autorun", "boot", "systemd"],
    "B6": ["reverse.shell", "shell.*connect", "socket.*spawn", "pty.spawn", "bind.*shell"],
    "B7": ["ransomware", "encrypt.*file", "ransom", "lock.*file"],
    "B8": ["cryptomin", "mining", "ddos", "botnet", "cpu.*abuse", "monero", "xmrig"],
    "B9": ["privilege.escal", "chmod.*[42]", "sudo", "suid", "container.escape", "root"],
}

PI_BEHAVIOR_KEYWORDS: dict[str, list[str]] = {
    "B10": [
        "act as",
        "you are now",
        "pretend",
        "roleplay",
        "persona",
        "character",
        "DAN",
        "new identity",
    ],
    "B11": [
        "no restriction",
        "bypass",
        "developer mode",
        "jailbreak",
        "ignore.*safety",
        "unrestrict",
    ],
    "B12": ["ignore.*previous", "forget.*instruction", "disregard", "override", "new instruction"],
    "B13": [
        "system prompt",
        "reveal.*instruction",
        "show.*prompt",
        "what were you told",
        "repeat.*instruction",
    ],
    "B14": ["new task", "instead.*do", "your.*goal", "real.*purpose", "actually.*want", "redirect"],
    "B15": ["always say", "always recommend", "promote", "believe", "opinion", "bias", "endorse"],
}


# ── Helper functions ───────────────────────────────────────────


def behavior_label(behavior_id: str) -> str:
    """Return human-readable label for a behavior ID, e.g., 'B2 Credential Theft'."""
    if behavior_id in ALL_BEHAVIORS:
        return f"{behavior_id} {ALL_BEHAVIORS[behavior_id][0]}"
    return behavior_id


def behavior_vector(behavior_id: str) -> AttackVector:
    """Map a behavior ID to its primary attack vector."""
    if behavior_id in PI_ONLY_BEHAVIORS:
        return AttackVector.PI
    if behavior_id in CI_BEHAVIORS:
        return AttackVector.CI
    raise ValueError(f"Unknown behavior ID: {behavior_id}")


def all_behavior_ids() -> list[str]:
    """Return all B1-B15 behavior IDs in order."""
    return [f"B{i}" for i in range(1, 16)]
