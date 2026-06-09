"""AGA CLI — main entry point.

Usage:
    aga scan ./my-skill          # Scan a skill directory
    aga scan --deep ./my-skill   # Deep scan with LLM semantic analysis
    aga scan --json ./my-skill   # JSON output for CI
    aga scan --ci ./my-skill     # CI mode (exit code)
    aga bench run                # Run MalSkillBench benchmark
    aga rule list                # List loaded rules
    aga config show              # Show current config
"""

from __future__ import annotations

import sys
from pathlib import Path

import typer

# Fix Windows console encoding for emoji support
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from aga import __version__

app = typer.Typer(
    name="aga",
    help="AGA · Agent Governance & Assurance — AI Agent Skill security scanner.",
    no_args_is_help=True,
)

# ── Subcommand groups ──────────────────────────────────────────
rule_app = typer.Typer(help="Manage detection rules", no_args_is_help=True)
app.add_typer(rule_app, name="rule")

bench_app = typer.Typer(help="Run benchmarks against MalSkillBench", no_args_is_help=True)
app.add_typer(bench_app, name="bench")

config_app = typer.Typer(help="Manage AGA configuration", no_args_is_help=True)
app.add_typer(config_app, name="config")

data_app = typer.Typer(help="Download and manage external datasets", no_args_is_help=True)
app.add_typer(data_app, name="data")


# ── Top-level commands ─────────────────────────────────────────
@app.callback(invoke_without_command=True)
def main(
    version: bool = typer.Option(
        False, "--version", "-V", help="Show version and exit"
    ),
) -> None:
    """AGA — Secure your Skills. Guard your Agents."""
    if version:
        typer.echo(f"aga v{__version__}")
        raise typer.Exit()

    # If no subcommand is given and no flags, show help
    import sys as _sys
    if len(_sys.argv) == 1:
        typer.echo(app.get_help())
        raise typer.Exit()


# ── Scan command (direct on app, not a sub-group) ──────────────
@app.command("scan")
def scan(
    path: Path = typer.Argument(..., help="Path to skill directory", exists=True),
    deep: bool = typer.Option(False, "--deep", help="Enable LLM semantic analysis"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
    ci: bool = typer.Option(False, "--ci", help="CI mode (exit code 0=pass, 1=fail)"),
    fix: bool = typer.Option(False, "--fix", help="Auto-fix low-risk issues"),
) -> None:
    """Scan a skill directory for code injection, prompt injection, and mixed attacks."""
    from aga.sdk.analyzer import Analyzer
    from aga.sdk.reporter import Reporter

    analyzer = Analyzer()
    report = analyzer.scan(path, deep=deep)

    if json_output:
        typer.echo(Reporter.json(report))
    else:
        typer.echo(Reporter.terminal(report))

    if ci:
        Reporter.ci_exit(report)


# ── Rule commands ──────────────────────────────────────────────
@rule_app.command("list", help="List all loaded rules")
def rule_list(
    search: str | None = typer.Option(None, "--search", "-s", help="Filter by keyword"),
) -> None:
    """Display loaded rules, optionally filtered by keyword."""
    typer.echo("📋 Rules (placeholder)")
    typer.echo("   No rules loaded yet — scaffolding phase.")


@rule_app.command("pull", help="Pull latest community rules")
def rule_pull() -> None:
    """Download community-contributed rules."""
    typer.echo("⬇️  Pulling community rules (placeholder)")


@rule_app.command("add", help="Add a local custom rule file or directory")
def rule_add(
    path: Path = typer.Argument(..., help="Path to rule YAML file or directory", exists=True),
) -> None:
    """Register a custom rule from a local path."""
    typer.echo(f"➕ Adding rule(s) from: {path} (placeholder)")


# ── Bench commands ─────────────────────────────────────────────
@bench_app.command("run", help="Run MalSkillBench benchmark")
def bench_run() -> None:
    """Evaluate detection performance against MalSkillBench ground truth."""
    typer.echo("🏃 Running benchmark (placeholder)")


@bench_app.command("report", help="Show latest benchmark report")
def bench_report() -> None:
    """Display the most recent benchmark results."""
    typer.echo("📊 Benchmark report (placeholder)")


# ── Config commands ────────────────────────────────────────────
@config_app.command("show", help="Display current configuration")
def config_show() -> None:
    """Print the active AGA configuration."""
    typer.echo("⚙️  Config (placeholder)")
    typer.echo("   No config file found — using defaults.")


@config_app.command("set", help="Set a configuration value")
def config_set(
    key: str = typer.Argument(..., help="Config key (e.g., llm.provider)"),
    value: str = typer.Argument(..., help="Config value"),
) -> None:
    """Update a configuration key."""
    typer.echo(f"⚙️  Setting {key} = {value} (placeholder)")


# ── Data commands ──────────────────────────────────────────────
@data_app.command("pull", help="Download external dataset (e.g., MalSkillBench)")
def data_pull(
    target: str = typer.Option("malskillbench", help="Dataset to pull"),
) -> None:
    """Pull down the MalSkillBench benchmark dataset."""
    typer.echo(f"⬇️  Pulling dataset: {target} (placeholder)")


@app.command("init", help="Initialize .aga.yaml in current directory")
def init_config() -> None:
    """Create a default .aga.yaml configuration file."""
    typer.echo("📄 Creating .aga.yaml (placeholder)")


# ── Entry point ────────────────────────────────────────────────
if __name__ == "__main__":
    app()
