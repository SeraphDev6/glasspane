"""Phase 3: VALIDATE — Adversarial second opinion on findings.

Uses Opus. Replicates the manual step where Wesley verified each finding
against actual source code to separate real vulnerabilities from hallucinations.
"""

from __future__ import annotations

import json

from rich.console import Console

from glasspane.client import create_deps, create_phase_agent
from glasspane.models import (
    Finding,
    ScanConfig,
    ScanProfile,
    ValidateOutput,
    ValidationResult,
    Verdict,
)
from glasspane.sandbox import GlasspaneSandbox

console = Console()

VALIDATE_SYSTEM_PROMPT = """You are a senior security researcher performing adversarial review of vulnerability findings.

Another researcher has identified potential vulnerabilities in a codebase. Your job is to VERIFY each finding by:

1. Reading the actual source code at the reported file and line number
2. Checking if the vulnerability is real or a false positive
3. Checking if framework-level mitigations make it unexploitable
4. Checking if the attack vector described is actually reachable
5. Checking if the impact assessment is accurate

For each finding, provide a verdict:
- confirmed: The vulnerability is real and exploitable as described
- likely: The vulnerability appears real but some conditions may vary
- possible: The vulnerability could exist but requires specific conditions
- false_positive: The finding is incorrect — the code is safe
- needs_poc: The finding looks real but requires a proof-of-concept to confirm

IMPORTANT: Be skeptical. The previous researcher may have hallucinated code that doesn't exist, misread the control flow, or missed framework protections. Verify everything against the actual source.

{framework_mitigations}

Use the available tools to verify each finding. Read the actual code, not just the snippet provided.

Return your validation results as structured output."""


async def run_validate_phase(
    config: ScanConfig,
    profile: ScanProfile,
    findings: list[Finding],
    sandbox: GlasspaneSandbox,
    verbose: bool = False,
) -> list[ValidationResult]:
    """Validate findings with an adversarial second opinion."""
    console.print("\n[bold blue]Phase 3: VALIDATE[/bold blue] — Adversarial verification of findings...")

    if not findings:
        console.print("  [yellow]No findings to validate.[/yellow]")
        return []

    console.print(f"  Validating [bold]{len(findings)}[/bold] findings")
    console.print(f"  Using model: [cyan]{config.validate_model}[/cyan]")

    # Sanitize finding file paths — reject traversal outside the repo root
    repo_root = config.target_path.resolve()
    for f in findings:
        try:
            resolved = (repo_root / f.file_path).resolve()
            if not resolved.is_relative_to(repo_root):
                f.file_path = f"[rejected: {f.file_path}]"
        except (ValueError, OSError):
            f.file_path = f"[rejected: {f.file_path}]"

    # Build findings summary for the validator
    findings_json = json.dumps(
        [f.model_dump() for f in findings],
        indent=2,
    )

    mitigations = f"Framework mitigations to consider:\n{profile.framework_mitigations}" if profile.framework_mitigations else ""

    system = VALIDATE_SYSTEM_PROMPT.format(framework_mitigations=mitigations)

    user_msg = f"""Verify each of these security findings against the actual source code.

Findings to validate:
{findings_json}

For each finding:
1. Read the actual file at the reported path and line number
2. Verify the code snippet matches what's actually there
3. Trace the attack vector — is it really reachable?
4. Check framework mitigations — does the framework protect against this?
5. Provide your verdict and reasoning"""

    agent, activity = create_phase_agent(
        model=config.validate_model,
        instructions=system,
        output_type=ValidateOutput,
        sandbox=sandbox,
        verbose=verbose,
    )
    deps = create_deps(sandbox)

    result = await agent.run(user_msg, deps=deps)
    activity.clear_line()
    validations = result.output.validations

    confirmed = sum(1 for v in validations if v.verdict == Verdict.CONFIRMED)
    likely = sum(1 for v in validations if v.verdict == Verdict.LIKELY)
    fp = sum(1 for v in validations if v.verdict == Verdict.FALSE_POSITIVE)

    console.print(f"  [green]Confirmed: {confirmed}[/green]")
    console.print(f"  [yellow]Likely: {likely}[/yellow]")
    console.print(f"  [red]False positives: {fp}[/red]")

    return validations
