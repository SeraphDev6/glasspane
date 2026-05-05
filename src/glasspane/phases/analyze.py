"""Phase 2: ANALYZE — Deep security scan of high-priority files.

Uses Opus for depth. Replicates the manual step where we launched parallel
agents per module, each scanning for specific vulnerability classes with
full source code reading and call-chain tracing.
"""

from __future__ import annotations

import asyncio
import uuid

from rich.console import Console

from glasspane.client import create_deps, create_phase_agent
from glasspane.models import (
    AnalyzeOutput,
    FileRanking,
    Finding,
    ScanConfig,
    ScanProfile,
    Severity,
)
from glasspane.sandbox import GlasspaneSandbox

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

Use the available tools to:
- Read the full source of each target file
- Trace call chains from user input to dangerous operations
- Check if related files provide context (e.g., how a function is called)
- Look for inconsistencies (one path sanitized, another not — like the LDAP module)

After your analysis, return your findings as structured output."""


async def run_analyze_phase(
    config: ScanConfig,
    profile: ScanProfile,
    rankings: list[FileRanking],
    sandbox: GlasspaneSandbox,
    verbose: bool = False,
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

    # Group files into batches for parallel agents
    batches = _create_batches(targets, config.parallel_agents)

    vuln_checklist = "\n".join(f"- {vc}" for vc in profile.vuln_classes)

    # Run batches in parallel using asyncio
    tasks = [
        _analyze_batch(config, profile, batch, vuln_checklist, i + 1, sandbox, verbose)
        for i, batch in enumerate(batches)
    ]
    batch_results = await asyncio.gather(*tasks, return_exceptions=True)

    all_findings: list[Finding] = []
    for i, result in enumerate(batch_results):
        batch_num = i + 1
        if isinstance(result, Exception):
            console.print(f"  [red]Agent {batch_num} failed: {result}[/red]")
        else:
            all_findings.extend(result)
            console.print(f"  Agent {batch_num} complete: [bold]{len(result)}[/bold] findings")

    # Deduplicate findings by file+line
    all_findings = _deduplicate(all_findings)

    by_severity: dict[Severity, int] = {}
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


async def _analyze_batch(
    config: ScanConfig,
    profile: ScanProfile,
    batch: list[FileRanking],
    vuln_checklist: str,
    batch_num: int,
    sandbox: GlasspaneSandbox,
    verbose: bool = False,
) -> list[Finding]:
    """Analyze a batch of files using a pydantic-deep agent."""
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

Report ALL findings as structured output."""

    agent, activity = create_phase_agent(
        model=config.analyze_model,
        instructions=system,
        output_type=AnalyzeOutput,
        sandbox=sandbox,
        verbose=verbose,
    )
    deps = create_deps(sandbox)

    result = await agent.run(user_msg, deps=deps)
    activity.clear_line()
    findings = result.output.findings

    # Ensure all findings have IDs
    for f in findings:
        if not f.id:
            f.id = f"FIND-{batch_num}-{uuid.uuid4().hex[:6]}"

    return findings


def _deduplicate(findings: list[Finding]) -> list[Finding]:
    """Remove duplicate findings (same file + similar line number)."""
    seen: set[tuple[str, int | None, str]] = set()
    unique = []
    for f in findings:
        key = (f.file_path, f.line_number, f.title[:50])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique
