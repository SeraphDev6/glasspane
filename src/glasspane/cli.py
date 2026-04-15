"""Glasspane CLI — AI-powered security scanning scaffold.

Usage:
    glasspane scan /path/to/repo
    glasspane scan /path/to/repo --profile drupal
    glasspane scan /path/to/repo --output ./results --parallel 5
    glasspane init  # create default config at ~/.glasspane/config.yml
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel

from glasspane import __version__
from glasspane.config import load_config, write_default_config
from glasspane.models import ScanConfig, ScanResult
from glasspane.phases.analyze import run_analyze_phase
from glasspane.phases.rank import run_rank_phase
from glasspane.phases.report import run_report_phase
from glasspane.phases.validate import run_validate_phase
from glasspane.profiles import detect_profile, get_profile, list_profiles
from glasspane.sandbox import GlasspaneSandbox

app = typer.Typer(
    name="glasspane",
    help="AI-powered security scanning scaffold",
    no_args_is_help=True,
)
console = Console()

# Sentinel value so we can detect "user didn't pass this flag"
_UNSET = "__UNSET__"


@app.command()
def scan(
    target: Path = typer.Argument(..., help="Path to the repository to scan"),
    output: str | None = typer.Option(None, "--output", "-o", help="Output directory (default: from config)"),
    profile: str | None = typer.Option(None, "--profile", "-p", help="Scan profile (default: auto-detect)"),
    rank_model: str | None = typer.Option(None, "--rank-model", help="Model for ranking phase"),
    analyze_model: str | None = typer.Option(None, "--analyze-model", help="Model for analysis phase"),
    validate_model: str | None = typer.Option(None, "--validate-model", help="Model for validation phase"),
    parallel: int | None = typer.Option(None, "--parallel", "-j", help="Number of parallel analysis agents"),
    min_rank: int | None = typer.Option(None, "--min-rank", help="Minimum file rank to deep-scan (1-5)"),
    max_files: int | None = typer.Option(None, "--max-files", help="Maximum files to deep-scan"),
    skip_validate: bool = typer.Option(False, "--skip-validate", help="Skip the validation phase"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show all tool calls instead of a single status line"),
) -> None:
    """Scan a repository for security vulnerabilities."""
    asyncio.run(_scan_async(
        target, output, profile, rank_model, analyze_model, validate_model,
        parallel, min_rank, max_files, skip_validate, verbose,
    ))


async def _scan_async(
    target: Path,
    output: str | None,
    profile: str | None,
    rank_model: str | None,
    analyze_model: str | None,
    validate_model: str | None,
    parallel: int | None,
    min_rank: int | None,
    max_files: int | None,
    skip_validate: bool,
    verbose: bool,
) -> None:
    """Async implementation of the scan command."""
    # Load config file defaults
    cfg = load_config()

    # Resolve: CLI flag > config file > hardcoded default
    raw_output = Path(output or cfg.output_dir)
    # Reject symlinks to prevent a malicious repo from redirecting output
    if raw_output.exists() and raw_output.is_symlink():
        console.print(
            f"[red]Error: output path {raw_output} is a symlink — refusing to follow. "
            f"Use --output to specify a direct path.[/red]"
        )
        raise typer.Exit(1)
    output_path = raw_output.resolve()
    profile_name = profile or cfg.default_profile
    r_model = rank_model or cfg.rank_model
    a_model = analyze_model or cfg.analyze_model
    v_model = validate_model or cfg.validate_model
    n_parallel = parallel or cfg.parallel
    n_min_rank = min_rank or cfg.min_rank
    n_max_files = max_files or cfg.max_files

    # Validate target
    target = target.resolve()
    if not target.is_dir():
        console.print(f"[red]Error: {target} is not a directory[/red]")
        raise typer.Exit(1)

    # Banner
    console.print(Panel(
        f"[bold]Glasspane v{__version__}[/bold] — AI-powered security scanning\n"
        f"Target: {target}\n"
        f"Output: {output_path}",
        title="Security Scan",
        border_style="blue",
    ))

    start_time = time.time()

    # Detect or use specified profile
    if profile_name == "auto":
        profile_name = detect_profile(target)
        console.print(f"Auto-detected profile: [bold]{profile_name}[/bold]")

    scan_profile = get_profile(profile_name)
    console.print(f"Profile: [bold]{scan_profile.name}[/bold] — {scan_profile.description}")
    console.print(f"Models: rank=[cyan]{r_model}[/cyan] analyze=[cyan]{a_model}[/cyan] validate=[cyan]{v_model}[/cyan]")

    config = ScanConfig(
        target_path=target,
        output_path=output_path,
        profile=profile_name,
        rank_model=r_model,
        analyze_model=a_model,
        validate_model=v_model,
        max_files_to_analyze=n_max_files,
        min_rank_to_analyze=n_min_rank,
        parallel_agents=n_parallel,
    )

    # Start sandbox eagerly — avoids race condition when parallel agents
    # trigger _ensure_container() from multiple threads simultaneously
    sandbox = GlasspaneSandbox(config.target_path, config.output_path)
    sandbox.start()
    try:
        # Phase 1: RANK
        rankings = await run_rank_phase(config, scan_profile, sandbox, verbose=verbose)

        # Phase 2: ANALYZE
        findings = await run_analyze_phase(config, scan_profile, rankings, sandbox, verbose=verbose)

        # Phase 3: VALIDATE
        validations = []
        if not skip_validate and findings:
            validations = await run_validate_phase(config, scan_profile, findings, sandbox, verbose=verbose)
    finally:
        sandbox.stop()

    # Build result
    elapsed = time.time() - start_time
    result = ScanResult(
        target=str(target),
        profile=profile_name,
        rankings=rankings,
        findings=findings,
        validations=validations,
        total_files_discovered=len(rankings),
        total_files_ranked=len(rankings),
        total_files_analyzed=sum(1 for r in rankings if r.rank >= config.min_rank_to_analyze),
        scan_duration_seconds=elapsed,
    )

    # Phase 5: REPORT
    run_report_phase(config, scan_profile, result)

    # Final summary
    confirmed = len([v for v in validations if v.verdict.value in ("confirmed", "likely")])
    console.print(Panel(
        f"[bold green]Scan complete[/bold green] in {elapsed:.0f}s\n"
        f"Findings: {len(findings)} raw, {confirmed} confirmed/likely\n"
        f"Reports: {config.output_path}",
        title="Done",
        border_style="green",
    ))


@app.command()
def init() -> None:
    """Create default config at ~/.glasspane/config.yml."""
    path = write_default_config()
    console.print(f"Config written to [bold]{path}[/bold]")
    console.print()
    console.print("Next steps:")
    console.print(f"  1. Set your provider's API key:")
    console.print(f"     [cyan]export ANTHROPIC_API_KEY=...[/cyan]          (Anthropic)")
    console.print(f"     [cyan]export OPENAI_API_KEY=...[/cyan]             (OpenAI)")
    console.print(f"     [cyan]export AZURE_OPENAI_ENDPOINT=... + KEY[/cyan] (Azure OpenAI)")
    console.print(f"     [dim]AWS credentials for Bedrock, GOOGLE_API_KEY for Google, etc.[/dim]")
    console.print(f"  2. Edit config:      [cyan]{path}[/cyan]")
    console.print(f"  3. Run a scan:       [cyan]glasspane scan /path/to/repo[/cyan]")


@app.command()
def profiles() -> None:
    """List available scan profiles."""
    from glasspane.profiles import list_profiles, _profiles_dir

    all_profiles = list_profiles()
    console.print(f"\nProfiles directory: [dim]{_profiles_dir()}[/dim]\n")

    for name, p in all_profiles.items():
        badge = "[green]built-in[/green]" if name == "generic" else "[cyan]external[/cyan]"
        console.print(f"[bold]{name}[/bold] {badge} — {p.description}")
        console.print(f"  Language: {p.language}")
        console.print(f"  File patterns: {', '.join(p.file_patterns)}")
        console.print(f"  Vulnerability classes: {len(p.vuln_classes)}")
        console.print()


@app.command()
def version() -> None:
    """Show version."""
    console.print(f"glasspane v{__version__}")


if __name__ == "__main__":
    app()
