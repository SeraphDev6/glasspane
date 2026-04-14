"""Phase 5: REPORT — Generate structured output.

Produces markdown findings reports, executive summary, and scan metadata.
Replicates the manual step where we wrote SUMMARY.md and disclosure drafts.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console

from glasspane.models import (
    Finding,
    ScanConfig,
    ScanProfile,
    ScanResult,
    Severity,
    ValidationResult,
    Verdict,
)

console = Console()


def run_report_phase(
    config: ScanConfig,
    profile: ScanProfile,
    result: ScanResult,
) -> None:
    """Generate all output reports."""
    console.print("\n[bold blue]Phase 5: REPORT[/bold blue] — Generating output...")

    output = config.output_path
    output.mkdir(parents=True, exist_ok=True)

    # Build a verdict lookup
    verdicts: dict[str, ValidationResult] = {}
    for v in result.validations:
        verdicts[v.finding_id] = v

    # Filter to confirmed/likely findings
    confirmed_findings = [
        f for f in result.findings
        if verdicts.get(f.id, ValidationResult(finding_id=f.id, verdict=Verdict.LIKELY, reasoning="")).verdict
        in (Verdict.CONFIRMED, Verdict.LIKELY, Verdict.NEEDS_POC)
    ]

    # 1. Individual finding reports
    findings_dir = output / "findings"
    findings_dir.mkdir(exist_ok=True)
    for finding in confirmed_findings:
        _write_finding_report(finding, verdicts.get(finding.id), findings_dir)

    # 2. Executive summary
    _write_summary(config, profile, result, confirmed_findings, verdicts, output)

    # 3. Raw data (JSON)
    _write_raw_data(result, output)

    console.print(f"  Reports written to [bold]{output}[/bold]")
    console.print(f"  Findings: {len(confirmed_findings)} confirmed/likely")
    console.print(f"  False positives filtered: {len(result.findings) - len(confirmed_findings)}")


def _write_finding_report(
    finding: Finding,
    validation: ValidationResult | None,
    output_dir: Path,
) -> None:
    """Write a single finding report."""
    verdict_str = validation.verdict.value if validation else "unvalidated"
    severity = finding.severity.value.upper()

    content = f"""# {finding.title}

**ID:** {finding.id}
**Severity:** {severity}
**CWE:** {finding.cwe}
**Validation:** {verdict_str}
**Confidence:** {finding.confidence}

## Location

**File:** `{finding.file_path}`
**Line:** {finding.line_number or 'N/A'}

## Description

{finding.description}

## Vulnerable Code

```
{finding.code_snippet}
```

## Attack Vector

{finding.attack_vector}

## Impact

{finding.impact}

## Recommendation

{finding.recommendation}
"""

    if validation and validation.reasoning:
        content += f"""
## Validation Notes

{validation.reasoning}
"""

    if validation and validation.poc_suggestion:
        content += f"""
## PoC Suggestion

{validation.poc_suggestion}
"""

    if finding.chain_with:
        content += f"""
## Chain Potential

Chains with: {', '.join(finding.chain_with)}
"""

    # Sanitize finding ID — model-controlled, could contain path separators
    safe_id = "".join(c for c in finding.id if c.isalnum() or c in "-_.")
    if not safe_id:
        safe_id = "unknown"
    filename = f"{safe_id}.md"
    dest = (output_dir / filename).resolve()
    if not dest.is_relative_to(output_dir.resolve()):
        raise ValueError(f"Finding ID {finding.id!r} resolved outside output directory")
    dest.write_text(content)


def _write_summary(
    config: ScanConfig,
    profile: ScanProfile,
    result: ScanResult,
    confirmed: list[Finding],
    verdicts: dict[str, ValidationResult],
    output_dir: Path,
) -> None:
    """Write the executive summary."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    by_severity: dict[str, int] = {}
    for f in confirmed:
        sev = f.severity.value
        by_severity[sev] = by_severity.get(sev, 0) + 1

    severity_table = "\n".join(
        f"| {sev.value.capitalize()} | {by_severity.get(sev.value, 0)} |"
        for sev in Severity
    )

    findings_list = "\n".join(
        f"| {f.severity.value.upper()} | {f.title} | `{f.file_path}` | {f.cwe} |"
        for f in sorted(confirmed, key=lambda x: list(Severity).index(x.severity))
    )

    content = f"""# Glasspane Security Scan — Summary Report

**Date:** {now}
**Target:** {result.target}
**Profile:** {result.profile}

## Scan Statistics

| Metric | Value |
|--------|-------|
| Files discovered | {result.total_files_discovered} |
| Files ranked | {result.total_files_ranked} |
| Files deep-scanned | {result.total_files_analyzed} |
| Raw findings | {len(result.findings)} |
| Confirmed/Likely findings | {len(confirmed)} |
| False positives filtered | {len(result.findings) - len(confirmed)} |
| Scan duration | {result.scan_duration_seconds:.0f}s |
| API calls | {result.api_calls} |

## Findings by Severity

| Severity | Count |
|----------|-------|
{severity_table}

## All Findings

| Severity | Title | File | CWE |
|----------|-------|------|-----|
{findings_list}

## Methodology

- **Rank phase:** {config.rank_model} — file discovery and risk ranking
- **Analyze phase:** {config.analyze_model} — deep scan with {config.parallel_agents} parallel agents
- **Validate phase:** {config.validate_model} — adversarial verification
- **Profile:** {profile.name} ({profile.language})
- **Minimum rank to analyze:** {config.min_rank_to_analyze}

## Scan Engine

Glasspane v0.1.0 — AI-powered security scanning scaffold
"""

    (output_dir / "SUMMARY.md").write_text(content)


def _write_raw_data(result: ScanResult, output_dir: Path) -> None:
    """Write raw scan data as JSON for programmatic access."""
    raw = result.model_dump(mode="json")
    (output_dir / "scan_data.json").write_text(json.dumps(raw, indent=2))
