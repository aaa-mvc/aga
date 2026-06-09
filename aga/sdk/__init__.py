"""SDK public API for AGA.

Core classes for programmatic skill security analysis:

    from aga import Analyzer

    analyzer = Analyzer()
    report = analyzer.scan("./my-skill")
    print(f"Risk: {report.risk_score}/100 ({report.risk_level})")
"""

from aga.sdk.analyzer import Analyzer
from aga.sdk.parser import CodeArtifact, Parser, SkillIR, SkillMeta
from aga.sdk.reporter import RiskLevel, RiskReport

__all__ = [
    "Analyzer",
    "Parser",
    "SkillIR",
    "SkillMeta",
    "CodeArtifact",
    "RiskReport",
    "RiskLevel",
]
