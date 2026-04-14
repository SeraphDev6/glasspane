"""Phase 3: VALIDATE — Adversarial second opinion on findings.

Uses Opus. Replicates the manual step where Wesley verified each finding
against actual source code to separate real vulnerabilities from hallucinations.
"""

from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console

from glasspane.client import get_client, run_agent_loop
from glasspane.models import Finding, ScanConfig, ScanProfile, ValidationResult, Verdict
from glasspane.sandbox import Sandbox

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

Use the read_file and grep tools to verify each finding. Read the actual code, not just the snippet provided.

Respond with a JSON array of validation results. Output ONLY the JSON array.

Example:
[
  {{
    "finding_id": "FIND-001",
    "verdict": "confirmed",
    "reasoning": "Verified Html::escape() at line 409. The function definitively does not escape LDAP metacharacters. The call chain from exposed filter to translateCondition is traceable.",
    "adjusted_severity": null,
    "poc_suggestion": "Submit ?cn=* to an exposed LDAP Views filter and observe all entries returned"
  }},
  {{
    "finding_id": "FIND-002",
    "verdict": "false_positive",
    "reasoning": "The code uses parameterized queries via the framework DB abstraction. The reported SQL injection is not possible.",
    "adjusted_severity": null,
    "poc_suggestion": ""
  }}
]"""


def run_validate_phase(
    config: ScanConfig,
    profile: ScanProfile,
    findings: list[Finding],
    sandbox: Sandbox,
) -> list[ValidationResult]:
    """Validate findings with an adversarial second opinion."""
    console.print("\n[bold blue]Phase 3: VALIDATE[/bold blue] — Adversarial verification of findings...")

    if not findings:
        console.print("  [yellow]No findings to validate.[/yellow]")
        return []

    console.print(f"  Validating [bold]{len(findings)}[/bold] findings")
    console.print(f"  Using model: [cyan]{config.validate_model}[/cyan]")

    client = get_client()

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

    raw = run_agent_loop(
        client=client,
        model=config.validate_model,
        system_prompt=system,
        user_message=user_msg,
        sandbox=sandbox,
    )

    validations = _parse_validations(raw)

    confirmed = sum(1 for v in validations if v.verdict == Verdict.CONFIRMED)
    likely = sum(1 for v in validations if v.verdict == Verdict.LIKELY)
    fp = sum(1 for v in validations if v.verdict == Verdict.FALSE_POSITIVE)

    console.print(f"  [green]Confirmed: {confirmed}[/green]")
    console.print(f"  [yellow]Likely: {likely}[/yellow]")
    console.print(f"  [red]False positives: {fp}[/red]")

    return validations


def _parse_validations(raw: str) -> list[ValidationResult]:
    """Parse the model's JSON response into ValidationResult objects."""
    start = raw.find("[")
    end = raw.rfind("]") + 1
    if start == -1 or end == 0:
        return []

    try:
        data = json.loads(raw[start:end])
        return [ValidationResult(**item) for item in data]
    except (json.JSONDecodeError, ValueError):
        return []
