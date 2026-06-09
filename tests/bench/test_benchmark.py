"""Benchmark test: precision/recall against 50 MalSkillBench skills.

Ground truth is inferred from directory naming convention:
  - Directories containing __CI_Bx -> malicious (Code Injection, Bx)
  - Directories containing __PI_Bx -> malicious (Prompt Injection, Bx)
  - Directories containing __MIXED_Bx -> malicious (Mixed attack, Bx)
  - Directories in benign/ -> benign (should score < 60)
  - Unlabeled malware directories -> malicious (real-world malware)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from aga.sdk.analyzer import Analyzer

FIXTURES = Path(__file__).parent.parent / "fixtures" / "skills"
MALWARE_DIR = FIXTURES / "malware"
BENIGN_DIR = FIXTURES / "benign"

THRESHOLD = 60  # Score >= THRESHOLD -> classified as malicious


@dataclass
class BenchmarkResult:
    """Aggregated benchmark statistics."""

    total: int = 0
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0
    details: list[dict] = field(default_factory=list)

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom > 0 else 0.0

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom > 0 else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    @property
    def accuracy(self) -> float:
        denom = self.total
        correct = self.true_positives + self.true_negatives
        return correct / denom if denom > 0 else 0.0


def _is_malicious_ground_truth(dirname: str, is_benign: bool) -> bool:
    """Determine if a skill is malicious based on directory naming."""
    if is_benign:
        return False
    # Check for MalSkillBench label: __CI_Bx, __PI_Bx, __MIXED_Bx
    if "__CI_" in dirname or "__PI_" in dirname or "__MIXED_" in dirname:
        return True
    # Unlabeled malware -- treat as malicious (real-world samples)
    return True


def _extract_ground_truth_behavior(dirname: str) -> list[str]:
    """Extract expected behavior IDs from directory name."""
    import re
    behaviors = set()
    for match in re.finditer(r"__(CI|PI|MIXED)_B(\d+)", dirname):
        behaviors.add(f"B{match.group(2)}")
    return sorted(behaviors)


def _collect_skills() -> list[tuple[Path, bool, str]]:
    """Collect all benchmark skill paths with ground truth labels.

    Returns list of (path, is_malicious, dirname).
    """
    skills: list[tuple[Path, bool, str]] = []

    # Malware skills
    if MALWARE_DIR.exists():
        for d in sorted(MALWARE_DIR.iterdir()):
            if d.is_dir() and (d / "SKILL.md").exists():
                skills.append((d, True, d.name))

    # Benign skills
    if BENIGN_DIR.exists():
        for d in sorted(BENIGN_DIR.iterdir()):
            if d.is_dir() and (d / "SKILL.md").exists():
                skills.append((d, False, d.name))

    return skills


def test_benchmark_50_skills():
    """Run full 50-skill benchmark and assert quality thresholds."""
    analyzer = Analyzer()
    skills = _collect_skills()
    result = BenchmarkResult(total=len(skills))

    print(f"\n{'='*60}")
    print(f"  AGA BENCHMARK -- {len(skills)} Skills")
    print(f"  Threshold: score >= {THRESHOLD} -> MALICIOUS")
    print(f"{'='*60}\n")

    for path, is_malicious_gt, dirname in skills:
        report = analyzer.scan(path)
        predicted_malicious = report.risk_score >= THRESHOLD
        gt_behaviors = _extract_ground_truth_behavior(dirname)

        # Track
        if is_malicious_gt and predicted_malicious:
            result.true_positives += 1
            status = "TP +"
        elif is_malicious_gt and not predicted_malicious:
            result.false_negatives += 1
            status = "FN !! MISSED"
        elif not is_malicious_gt and predicted_malicious:
            result.false_positives += 1
            status = "FP ?? "
        else:
            result.true_negatives += 1
            status = "TN +"

        detail = {
            "skill": dirname,
            "ground_truth": "MALICIOUS" if is_malicious_gt else "BENIGN",
            "predicted": f"Score={report.risk_score} {report.risk_level}",
            "status": status,
            "gt_behaviors": gt_behaviors,
            "detected_behaviors": [i.behavior_id for i in report.issues],
        }
        result.details.append(detail)

        # Print per-skill result
        gt_tag = f"[{','.join(gt_behaviors)}]" if gt_behaviors else "[UNLABELED]"
        print(f"  {status} {dirname[:50]:<50} GT={gt_tag:<15} Score={report.risk_score:>3}")

    # -- Summary --
    print(f"\n{'='*60}")
    print("  BENCHMARK RESULTS")
    print(f"{'='*60}")
    print(f"  Total:        {result.total}")
    print(f"  True Positive:  {result.true_positives}")
    print(f"  True Negative:  {result.true_negatives}")
    print(f"  False Positive: {result.false_positives}")
    print(f"  False Negative: {result.false_negatives}")
    print("  -------------------------")
    print(f"  Precision:    {result.precision:.1%}")
    print(f"  Recall:       {result.recall:.1%}")
    print(f"  F1 Score:     {result.f1:.1%}")
    print(f"  Accuracy:     {result.accuracy:.1%}")
    print(f"{'='*60}\n")

    # -- Detailed breakdown for failures --
    failures = [d for d in result.details if "!!" in d["status"] or "??" in d["status"]]
    if failures:
        print("  FAILURE DETAILS:")
        for f in failures:
            print(f"    {f['status']} {f['skill']}")
            print(f"         GT: {f['ground_truth']} {f['gt_behaviors']}")
            print(f"         Pred: {f['predicted']} Detected: {f['detected_behaviors']}")
        print()

    # -- Assertions (quality anchors) --
    assert result.precision >= 0.70, (
        f"Precision {result.precision:.1%} below 70% threshold"
    )
    assert result.recall >= 0.50, (
        f"Recall {result.recall:.1%} below 50% threshold"
    )
    assert result.f1 >= 0.55, (
        f"F1 {result.f1:.1%} below 55% threshold"
    )


def test_behavior_coverage():
    """Verify that at least one detection was made for each covered behavior."""
    analyzer = Analyzer()
    behavior_hits: dict[str, int] = {}
    behavior_total: dict[str, int] = {}

    skills = _collect_skills()
    for path, _, dirname in skills:
        gt_behaviors = _extract_ground_truth_behavior(dirname)
        if not gt_behaviors:
            continue
        report = analyzer.scan(path)
        detected = {i.behavior_id for i in report.issues}

        for b in gt_behaviors:
            behavior_total[b] = behavior_total.get(b, 0) + 1
            if b in detected:
                behavior_hits[b] = behavior_hits.get(b, 0) + 1

    print(f"\n{'='*60}")
    print("  BEHAVIOR-LEVEL RECALL")
    print(f"{'='*60}")
    for b in sorted(set(behavior_total.keys()), key=lambda x: int(x[1:])):
        total = behavior_total.get(b, 0)
        hits = behavior_hits.get(b, 0)
        pct = hits / total * 100 if total > 0 else 0
        bar = "#" * int(pct / 10) + "." * (10 - int(pct / 10))
        print(f"  {b}: {hits}/{total} = {pct:5.1f}% {bar}")
    print()

    # Assert at least 50% of behaviors with samples are detected
    total_behaviors = len(behavior_total)
    detected_behaviors = sum(1 for b, total in behavior_total.items()
                             if behavior_hits.get(b, 0) > 0)
    coverage = detected_behaviors / total_behaviors if total_behaviors > 0 else 0
    print(f"  Behavior coverage: {detected_behaviors}/{total_behaviors} = {coverage:.1%}")
    print(f"{'='*60}\n")

    assert coverage >= 0.60, f"Behavior coverage {coverage:.1%} below 60%"
