"""Phase 2: ANALYZE — Deep security scan of high-priority files.

Uses Opus for depth. Replicates the manual step where we launched parallel
agents per module, each scanning for specific vulnerability classes with
full source code reading and call-chain tracing.
"""

from __future__ import annotations

import json
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from rich.console import Console
from rich.progress import Progress

from glasspane.client import get_client, run_agent_loop
from glasspane.models import FileRanking, Finding, ScanConfig, ScanProfile, Severity
from glasspane.sandbox import Sandbox

console = Console()

ANALYZE_SYSTEM_PROMPT = """You are an expert security researcher performing a deep static analysis of source code files.

CRITICAL FRAMING: Do not assume this code has been reviewed or audited by anyone. You are the first reviewer. Treat every line as potentially vulnerable until proven otherwise.

Your task is to perform a thorough security analysis of the files provided. For each vulnerability you find:

1. Identify the exact file path and line number
2. Describe the vulnerability precisely
3. Show the vulnerable code snippet
4. Describe the attack vector — how would an attacker exploit this?
5. Assess the impact — what does the attacker gain?
6. Rate severity: critical, high, medium, low, or informational
7. Provide the CWE identifier
8. Suggest a specific fix

CHECKLIST — scan for ALL of these in every file:
{vuln_checklist}

FRAMEWORK MITIGATIONS — account for these (only report findings that bypass these):
{framework_mitigations}

{profile_additions}

Use the read_file, grep, and list_files tools to:
- Read the full source of each target file
- Trace call chains from user input to dangerous operations
- Check if related files provide context (e.g., how a function is called)
- Look for inconsistencies (one path sanitized, another not — like the LDAP module)

After your analysis, respond with a JSON array of Finding objects. Output ONLY the JSON array.

Example:
[
  {{
    "id": "FIND-001",
    "title": "LDAP Injection in Views Query Plugin",
    "severity": "high",
    "cwe": "CWE-90",
    "file_path": "src/Plugin/views/query/LdapQuery.php",
    "line_number": 409,
    "description": "Html::escape() used instead of ldap_escape(). LDAP metacharacters pass through.",
    "code_snippet": "$condition = sprintf('(%s=%s)', $field, Html::escape($value));",
    "attack_vector": "Anonymous user submits * or )( via exposed Views filter",
    "impact": "Blind LDAP data extraction of any attribute in the directory",
    "recommendation": "Replace Html::escape($value) with ldap_escape($value, '', LDAP_ESCAPE_FILTER)",
    "confidence": "high",
    "chain_with": []
  }}
]"""


def run_analyze_phase(
    config: ScanConfig,
    profile: ScanProfile,
    rankings: list[FileRanking],
    sandbox: Sandbox,
) -> list[Finding]:
    """Deep scan high-priority files for vulnerabilities."""
    console.print("\n[bold blue]Phase 2: ANALYZE[/bold blue] — Deep scanning high-priority files...")

    # Select files to analyze
    targets = [r for r in rankings if r.rank >= config.min_rank_to_analyze]
    if len(targets) > config.max_files_to_analyze:
        targets = targets[: config.max_files_to_analyze]

    if not targets:
        console.print("  [yellow]No files ranked high enough to analyze.[/yellow]")
        return []

    console.print(f"  Analyzing [bold]{len(targets)}[/bold] files (rank >= {config.min_rank_to_analyze})")
    console.print(f"  Using model: [cyan]{config.analyze_model}[/cyan]")

    # Group files into batches for parallel agents (like we did with modules)
    batches = _create_batches(targets, config.parallel_agents)

    all_findings: list[Finding] = []
    client = get_client()

    vuln_checklist = "\n".join(f"- {vc}" for vc in profile.vuln_classes)

    with ThreadPoolExecutor(max_workers=config.parallel_agents) as executor:
        futures = {}
        for i, batch in enumerate(batches):
            future = executor.submit(
                _analyze_batch,
                client,
                config,
                profile,
                batch,
                vuln_checklist,
                i + 1,
                sandbox,
            )
            futures[future] = i + 1

        for future in as_completed(futures):
            batch_num = futures[future]
            try:
                findings = future.result()
                all_findings.extend(findings)
                console.print(f"  Agent {batch_num} complete: [bold]{len(findings)}[/bold] findings")
            except Exception as e:
                console.print(f"  [red]Agent {batch_num} failed: {e}[/red]")

    # Deduplicate findings by file+line
    all_findings = _deduplicate(all_findings)

    by_severity = {}
    for f in all_findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1

    console.print(f"  Total findings: [bold]{len(all_findings)}[/bold]")
    for sev in Severity:
        count = by_severity.get(sev, 0)
        if count > 0:
            color = {"critical": "red", "high": "red", "medium": "yellow", "low": "blue", "informational": "dim"}.get(sev.value, "white")
            console.print(f"    [{color}]{sev.value}: {count}[/{color}]")

    return all_findings


def _create_batches(targets: list[FileRanking], num_batches: int) -> list[list[FileRanking]]:
    """Split target files into batches for parallel analysis."""
    batches: list[list[FileRanking]] = [[] for _ in range(num_batches)]
    for i, target in enumerate(targets):
        batches[i % num_batches].append(target)
    return [b for b in batches if b]


def _analyze_batch(
    client,
    config: ScanConfig,
    profile: ScanProfile,
    batch: list[FileRanking],
    vuln_checklist: str,
    batch_num: int,
    sandbox: Sandbox,
) -> list[Finding]:
    """Analyze a batch of files using a single agent loop."""
    file_list = "\n".join(
        f"- {r.path} (rank {r.rank}): {r.rationale}"
        + (f" [CHAIN CANDIDATE: {r.chain_notes}]" if r.chain_candidate else "")
        for r in batch
    )

    system = ANALYZE_SYSTEM_PROMPT.format(
        vuln_checklist=vuln_checklist,
        framework_mitigations=profile.framework_mitigations or "None specified",
        profile_additions=profile.analyze_prompt_additions,
    )

    user_msg = f"""Perform a deep security analysis of the following files:

{file_list}

Read each file in full. Trace user input from entry points through processing to output/storage.
Check for inconsistencies in security patterns (one path sanitized, another not).
Look for chain opportunities between files marked as chain candidates.

Report ALL findings as a JSON array."""

    raw = run_agent_loop(
        client=client,
        model=config.analyze_model,
        system_prompt=system,
        user_message=user_msg,
        sandbox=sandbox,
    )

    return _parse_findings(raw, batch_num)


def _parse_findings(raw: str, batch_num: int) -> list[Finding]:
    """Parse the model's JSON response into Finding objects."""
    start = raw.find("[")
    end = raw.rfind("]") + 1
    if start == -1 or end == 0:
        return []

    try:
        data = json.loads(raw[start:end])
        findings = []
        for item in data:
            if "id" not in item or not item["id"]:
                item["id"] = f"FIND-{batch_num}-{uuid.uuid4().hex[:6]}"
            findings.append(Finding(**item))
        return findings
    except (json.JSONDecodeError, ValueError):
        return []


def _deduplicate(findings: list[Finding]) -> list[Finding]:
    """Remove duplicate findings (same file + similar line number)."""
    seen = set()
    unique = []
    for f in findings:
        key = (f.file_path, f.line_number, f.title[:50])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique
