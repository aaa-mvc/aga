"""AGA CLI — main entry point.

Usage:
    aga scan ./my-skill          # Scan a skill directory
    aga scan --deep ./my-skill   # Deep scan with LLM semantic analysis
    aga scan --json ./my-skill   # JSON output for CI
    aga scan --ci ./my-skill     # CI mode (exit code)

    aga init                     # Create .aga.yaml config skeleton

    aga rule list                # List installed rules
    aga rule list --remote       # List remote available rules
    aga rule pull <name>         # Download rule(s) to temp dir (preview)
    aga rule install <name>      # Download → scan → gate → install
    aga rule install --force <n> # Install bypassing security gate
    aga rule uninstall <name>    # Remove installed rule
    aga rule update --all        # Update all installed rules

    aga config show              # Display current configuration
"""

from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

import typer

# Fix Windows console encoding for emoji support
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
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
    version: bool = typer.Option(False, "--version", "-V", help="Show version and exit"),
) -> None:
    """AGA — Secure your Skills. Guard your Agents."""
    if version:
        typer.echo(f"aga v{__version__}")
        raise typer.Exit()

    import sys as _sys
    if len(_sys.argv) == 1:
        typer.echo("Usage: aga [OPTIONS] COMMAND [ARGS]...\n\n  Try 'aga --help' for help.")
        raise typer.Exit()


# ── Scan command ───────────────────────────────────────────────
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


# ── Init command ───────────────────────────────────────────────
@app.command("init", help="Initialize .aga.yaml in current directory")
def init_config(
    force: bool = typer.Option(False, "--force", "-f", help="Overwrite existing config"),
) -> None:
    """Create a default .aga.yaml configuration file."""
    from aga.sdk.config import Config, ConfigLoader

    target = Path.cwd() / ConfigLoader.CONFIG_FILENAME

    if target.exists() and not force:
        typer.echo(f"⚙️  {target} already exists. Use --force to overwrite.")
        raise typer.Exit(0)

    ConfigLoader.save(Config(), target)
    typer.echo(f"📄 Created {target}")
    typer.echo("")
    typer.echo("💡 Recommended community rules to install:")
    typer.echo("   aga rule install B1-data-exfil")
    typer.echo("   aga rule install B2-credential-theft")
    typer.echo("   aga rule install B3-remote-code-exec")
    typer.echo("")
    typer.echo("   Run 'aga rule list --remote' to see all available rules.")


# ── Config commands ────────────────────────────────────────────
@config_app.command("show", help="Display current configuration")
def config_show() -> None:
    """Print the active AGA configuration."""
    from aga.sdk.config import ConfigLoader

    config = ConfigLoader.load()

    typer.echo("⚙️  AGA Configuration")
    typer.echo(f"   rules_source    = {config.rules_source}")
    typer.echo(f"   gate_threshold  = {config.gate_threshold}")
    typer.echo("")

    # Show which file was loaded
    project_root = ConfigLoader.find_project_root(Path.cwd())
    project_config = project_root / ConfigLoader.CONFIG_FILENAME if project_root else None
    user_config = Path.home() / ConfigLoader.CONFIG_FILENAME

    if project_config and project_config.exists():
        typer.echo(f"   📁 Source: {project_config}")
    elif user_config.exists():
        typer.echo(f"   📁 Source: {user_config}")
    else:
        typer.echo("   📁 Source: built-in defaults (no config file found)")


@config_app.command("set", help="Set a configuration value")
def config_set(
    key: str = typer.Argument(..., help="Config key (rules_source | gate_threshold)"),
    value: str = typer.Argument(..., help="Config value"),
    global_: bool = typer.Option(
        False, "--global", help="Write to user-level ~/.aga.yaml"
    ),
) -> None:
    """Update a configuration key."""
    from aga.sdk.config import ConfigLoader

    valid_keys = {"rules_source", "gate_threshold"}
    if key not in valid_keys:
        typer.echo(f"❌ Unknown config key: {key}. Valid keys: {', '.join(sorted(valid_keys))}")
        raise typer.Exit(1)

    # Load existing config
    target_path: Path
    if global_:
        target_path = Path.home() / ConfigLoader.CONFIG_FILENAME
        existing = ConfigLoader.load()
    else:
        project_root = ConfigLoader.find_project_root(Path.cwd())
        if project_root:
            target_path = project_root / ConfigLoader.CONFIG_FILENAME
            existing = ConfigLoader.load(project_dir=project_root)
        else:
            target_path = Path.cwd() / ConfigLoader.CONFIG_FILENAME
            existing = ConfigLoader.load()

    # Update
    setattr(existing, key, value)
    ConfigLoader.save(existing, target_path)
    typer.echo(f"⚙️  Set {key} = {value}")
    typer.echo(f"   📁 Written to: {target_path}")


# ── Rule: list ─────────────────────────────────────────────────
@rule_app.command("list", help="List installed rules (or --remote for available)")
def rule_list(
    remote: bool = typer.Option(False, "--remote", "-r", help="Show remote available rules"),
    local: bool = typer.Option(False, "--local", help="Use project-level rules"),
    global_: bool = typer.Option(False, "--global", help="Use user-level rules"),
) -> None:
    """Display installed or available rules."""
    from rich.console import Console
    from rich.table import Table

    from aga.sdk.config import resolve_install_path
    from aga.sdk.registry import RuleRegistry

    console = Console()
    registry = RuleRegistry()

    if remote:
        # Show remote catalog
        from aga.sdk.config import ConfigLoader

        config = ConfigLoader.load()
        remote_rules = registry.list_remote(config.rules_source)

        if not remote_rules:
            typer.echo("🌐 No remote rules found. Check network or rules_source config.")
            return

        install_dir = resolve_install_path(local=local, global_=global_)
        installed_map = {r.name: r for r in registry.read_installed(install_dir)}

        table = Table(title="🌐 Remote Rule Catalog")
        table.add_column("Status", style="bold")
        table.add_column("Name", style="cyan")
        table.add_column("Version")
        table.add_column("Behavior")
        table.add_column("Description")

        for rule in remote_rules:
            if rule.name in installed_map:
                local_ver = installed_map[rule.name].version
                if local_ver == rule.version:
                    status = "[green]✓ 已最新[/]"
                else:
                    status = f"[yellow]↑ {local_ver}→{rule.version}[/]"
            else:
                status = "[dim]可安装[/]"

            table.add_row(
                status,
                rule.name,
                rule.version,
                rule.behavior_id,
                rule.description[:60] + ("..." if len(rule.description) > 60 else ""),
            )

        console.print(table)
        typer.echo(f"\n📦 {len(remote_rules)} rules available. Install with: aga rule install <name>")

    else:
        # Show local installed rules
        install_dir = resolve_install_path(local=local, global_=global_)
        installed = registry.read_installed(install_dir)

        if not installed:
            typer.echo("📋 No rules installed.")
            typer.echo(f"   Install directory: {install_dir}")
            typer.echo("   Run 'aga rule list --remote' to browse available rules.")
            return

        table = Table(title="📋 Installed Rules")
        table.add_column("Name", style="cyan")
        table.add_column("Version")
        table.add_column("Behavior")
        table.add_column("Installed")
        table.add_column("Files")

        for rule in installed:
            table.add_row(
                rule.name,
                rule.version,
                rule.behavior_id,
                rule.installed_at[:10] if rule.installed_at else "-",
                ", ".join(rule.files),
            )

        console.print(table)
        typer.echo(f"\n📦 {len(installed)} rules installed in {install_dir}")


# ── Rule: pull ─────────────────────────────────────────────────
@rule_app.command("pull", help="Download rule(s) to a temp directory for preview")
def rule_pull(
    name: str = typer.Argument(..., help="Rule name or --all to pull all"),
    all_: bool = typer.Option(False, "--all", help="Pull all available rules"),
    version: str | None = typer.Option(None, "--version", help="Specific version to pull"),
) -> None:
    """Download community rules to a temporary directory for review."""
    from aga.sdk.config import ConfigLoader
    from aga.sdk.registry import RuleRegistry

    config = ConfigLoader.load()
    registry = RuleRegistry()

    if all_:
        typer.echo("⬇️  Pulling all remote rules (--all) ...")
        remote_rules = registry.list_remote(config.rules_source)
        if not remote_rules:
            typer.echo("❌ No remote rules found.")
            raise typer.Exit(1)

        temp_dir = Path(tempfile.mkdtemp(prefix="aga-pull-"))
        count = 0
        for rule in remote_rules:
            try:
                files = registry.download_rule(
                    rule.name, temp_dir / rule.name, config.rules_source, version
                )
                typer.echo(f"   ✅ {rule.name} v{rule.version} ({len(files)} files)")
                count += 1
            except Exception as exc:
                typer.echo(f"   ⚠️  {rule.name}: {exc}")

        typer.echo(f"\n📦 Pulled {count} rules → {temp_dir}")
        typer.echo("   Next: aga rule install <name> to install after automatic scan.")
        return

    # Single rule
    temp_dir = Path(tempfile.mkdtemp(prefix="aga-pull-"))
    try:
        files = registry.download_rule(name, temp_dir, config.rules_source, version)
        typer.echo(f"⬇️  Pulled {name} ({len(files)} files)")
        typer.echo(f"   📁 {temp_dir}")
        typer.echo("   Next: aga rule install <name>")
    except Exception as exc:
        typer.echo(f"❌ Pull failed: {exc}", err=True)
        raise typer.Exit(1) from exc


# ── Rule: install ──────────────────────────────────────────────
@rule_app.command("install", help="Install a rule → auto-scan → gate → install")
def rule_install(
    name: str = typer.Argument(..., help="Rule name to install"),
    version: str | None = typer.Option(None, "--version", help="Specific version"),
    local: bool = typer.Option(False, "--local", help="Install to project-level .aga/rules/"),
    global_: bool = typer.Option(False, "--global", help="Install to user-level ~/.aga/rules/"),
    force: bool = typer.Option(False, "--force", "-f", help="Bypass security gate"),
) -> None:
    """Install a community rule with automatic security scanning.

    The pipeline: download → scan → gate (HIGH/CRITICAL blocked) → install.

    Use --force to install even if the security gate blocks it.
    """
    from aga.sdk.config import ConfigLoader, resolve_install_path
    from aga.sdk.registry import RuleRegistry

    config = ConfigLoader.load()
    registry = RuleRegistry()
    install_dir = resolve_install_path(local=local, global_=global_)
    temp_dir = Path(tempfile.mkdtemp(prefix="aga-install-"))

    try:
        # ── 1. Conflict detection ────────────────────────────
        existing = registry.is_installed(name, install_dir)
        if existing:
            typer.echo(
                f"⚠️  {name} v{existing.version} is already installed. "
                f"Use 'aga rule update {name}' to upgrade, "
                f"or 'aga rule uninstall {name}' to remove first."
            )
            raise typer.Exit(0)

        # ── 2. Download ──────────────────────────────────────
        typer.echo(f"⬇️  Downloading {name} ...")
        try:
            downloaded = registry.download_rule(name, temp_dir, config.rules_source, version)
        except Exception as exc:
            typer.echo(f"❌ Download failed: {exc}", err=True)
            raise typer.Exit(1) from exc

        # ── 3. Validate rule files ───────────────────────────
        typer.echo(f"🔍 Validating {len(downloaded)} rule file(s) ...")
        result = RuleRegistry.validate_rule_files(downloaded)

        # Show validation results
        if result.issues:
            typer.echo(f"   Score: {result.risk_score}/100 ({result.risk_level.upper()})")
            for issue in result.issues:
                typer.echo(f"   ⚠️  {issue}")
        else:
            typer.echo(f"   ✅ All {result.file_count} file(s) valid ({result.risk_score}/100)")

        # ── 4. Gate ──────────────────────────────────────────
        if not result.passed and not force:
            typer.echo("")
            typer.echo("❌ Installation blocked — security risk detected.", err=True)
            typer.echo(f"   Risk: {result.risk_score}/100 ({result.risk_level.upper()})")
            typer.echo("   Use --force to bypass the security gate.")
            raise typer.Exit(1)

        if force and not result.passed:
            typer.echo("⚠️  Security check BYPASSED (--force). Installing anyway.")

        # ── 5. Resolve version from remote index ────────────────
        remote_meta: dict = {}
        try:
            index = registry.fetch_index(config.rules_source)
            remote_meta = index.get("rules", {}).get(name, {})
            if not isinstance(remote_meta, dict):
                remote_meta = {}
        except Exception:
            pass
        resolved_version = version or str(remote_meta.get("version", "0.0.0"))

        # ── 6. Install ───────────────────────────────────────
        record = registry.install_files(
            rule_name=name,
            version=resolved_version,
            downloaded_files=downloaded,
            install_dir=install_dir,
            remote_info=remote_meta,
        )
        typer.echo("")
        typer.echo(
            f"✅ {record.name} v{record.version} installed to {install_dir} "
            f"(validation: {result.risk_score}/100 {result.risk_level.upper()})"
        )

    finally:
        # ── 7. Cleanup ──────────────────────────────────────
        if temp_dir.exists():
            shutil.rmtree(temp_dir, ignore_errors=True)


# ── Rule: uninstall ────────────────────────────────────────────
@rule_app.command("uninstall", help="Remove an installed rule")
def rule_uninstall(
    name: str = typer.Argument(..., help="Rule name to uninstall"),
    local: bool = typer.Option(False, "--local", help="Remove from project-level"),
    global_: bool = typer.Option(False, "--global", help="Remove from user-level"),
) -> None:
    """Uninstall a previously installed community rule."""
    from aga.sdk.config import resolve_install_path
    from aga.sdk.registry import RuleRegistry

    registry = RuleRegistry()
    install_dir = resolve_install_path(local=local, global_=global_)

    existing = registry.is_installed(name, install_dir)
    if not existing:
        typer.echo(f"⚠️  {name} is not installed in {install_dir}")
        typer.echo("   Run 'aga rule list' to see installed rules.")
        raise typer.Exit(0)

    registry.remove_installed(install_dir, name)
    typer.echo(f"🗑️  {name} v{existing.version} uninstalled from {install_dir}")


# ── Rule: update ───────────────────────────────────────────────
@rule_app.command("update", help="Update installed rules to latest version")
def rule_update(
    name: str | None = typer.Argument(None, help="Rule name to update (omit for --all)"),
    all_: bool = typer.Option(False, "--all", help="Update all installed rules"),
    local: bool = typer.Option(False, "--local", help="Update project-level rules"),
    global_: bool = typer.Option(False, "--global", help="Update user-level rules"),
    force: bool = typer.Option(False, "--force", "-f", help="Bypass security gate on update"),
) -> None:
    """Update installed rules, reusing the scan→gate pipeline for each."""
    from aga.sdk.config import ConfigLoader, resolve_install_path
    from aga.sdk.registry import RuleRegistry

    if not name and not all_:
        typer.echo("❌ Specify a rule name or use --all.", err=True)
        raise typer.Exit(1)

    config = ConfigLoader.load()
    registry = RuleRegistry()
    install_dir = resolve_install_path(local=local, global_=global_)

    # Determine which rules to update
    installed = registry.read_installed(install_dir)
    if not installed:
        typer.echo("📋 No rules installed. Nothing to update.")
        return

    remote_rules = {
        r.name: r for r in registry.list_remote(config.rules_source)
    }

    to_update: list = []
    for rule in installed:
        if name and name != "*" and rule.name != name:
            continue
        remote = remote_rules.get(rule.name)
        if remote and remote.version != rule.version:
            to_update.append((rule, remote))
        elif not remote:
            typer.echo(f"⚠️  {rule.name}: no longer in remote catalog — skipping")

    if not to_update:
        typer.echo("✅ All installed rules are up to date.")
        return

    typer.echo(f"🔄 Updating {len(to_update)} rule(s) ...\n")

    updated = 0
    for old_rule, remote_info in to_update:
        temp_dir = Path(tempfile.mkdtemp(prefix="aga-update-"))
        try:
            typer.echo(f"⬇️  {old_rule.name}: {old_rule.version} → {remote_info.version}")

            # Download new version
            downloaded = registry.download_rule(
                old_rule.name, temp_dir, config.rules_source, remote_info.version
            )

            # Validate rule files
            result = RuleRegistry.validate_rule_files(downloaded)
            typer.echo(f"   🔍 Validation: {result.risk_score}/100 ({result.risk_level.upper()})")

            # Gate
            if not result.passed and not force:
                typer.echo("   ❌ Blocked by security gate. Use --force to skip.")
                continue

            if force and not result.passed:
                typer.echo("   ⚠️  Security gate bypassed (--force).")

            # Remove old, install new
            registry.remove_installed(install_dir, old_rule.name)
            registry.install_files(
                rule_name=old_rule.name,
                version=remote_info.version,
                downloaded_files=downloaded,
                install_dir=install_dir,
                remote_info={
                    "description": remote_info.description,
                    "behavior_id": remote_info.behavior_id,
                },
            )
            typer.echo(f"   ✅ Updated to v{remote_info.version}")
            updated += 1

        except Exception as exc:
            typer.echo(f"   ❌ Failed: {exc}")
        finally:
            if temp_dir.exists():
                shutil.rmtree(temp_dir, ignore_errors=True)

    typer.echo(f"\n✅ {updated}/{len(to_update)} rule(s) updated successfully.")


# ── Rule: add (local import) ───────────────────────────────────
@rule_app.command("add", help="Add a local custom rule file or directory")
def rule_add(
    path: Path = typer.Argument(..., help="Path to rule YAML file or directory", exists=True),
    local: bool = typer.Option(False, "--local", help="Add to project-level rules"),
    global_: bool = typer.Option(False, "--global", help="Add to user-level rules"),
) -> None:
    """Import a local custom rule YAML file or directory."""
    from aga.sdk.config import resolve_install_path

    install_dir = resolve_install_path(local=local, global_=global_)
    install_dir.mkdir(parents=True, exist_ok=True)

    if path.is_file():
        dst = install_dir / path.name
        shutil.copy2(path, dst)
        typer.echo(f"➕ Added rule: {path.name} → {install_dir}")
    else:
        # Directory: copy all YAML files
        yaml_files = list(path.rglob("*.yaml")) + list(path.rglob("*.yml"))
        for yf in yaml_files:
            dst = install_dir / yf.name
            shutil.copy2(yf, dst)
        typer.echo(f"➕ Added {len(yaml_files)} rule(s) from {path} → {install_dir}")

    typer.echo("   The rule will be loaded on the next scan.")


# ── Bench commands ─────────────────────────────────────────────
@bench_app.command("run", help="Run MalSkillBench benchmark")
def bench_run() -> None:
    """Evaluate detection performance against MalSkillBench ground truth."""
    typer.echo("🏃 Running benchmark (placeholder)")


@bench_app.command("report", help="Show latest benchmark report")
def bench_report() -> None:
    """Display the most recent benchmark results."""
    typer.echo("📊 Benchmark report (placeholder)")


# ── Data commands ──────────────────────────────────────────────
@data_app.command("pull", help="Download external dataset (e.g., MalSkillBench)")
def data_pull(
    target: str = typer.Option("malskillbench", help="Dataset to pull"),
) -> None:
    """Pull down the MalSkillBench benchmark dataset."""
    typer.echo(f"⬇️  Pulling dataset: {target} (placeholder)")


# ── Entry point ────────────────────────────────────────────────
if __name__ == "__main__":
    app()
