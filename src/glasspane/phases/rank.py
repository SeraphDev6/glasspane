"""Phase 1: RANK — Discover and rank files by vulnerability likelihood.

Uses Sonnet for speed. Replicates the manual step where we counted PHP files
per module and prioritized by attack surface (auth, file upload, etc.).
"""

from __future__ import annotations

from rich.console import Console

from glasspane.client import create_deps, create_phase_agent
from glasspane.models import FileRanking, RankOutput, ScanConfig, ScanProfile
from glasspane.sandbox import GlasspaneSandbox

console = Console()

RANK_SYSTEM_PROMPT = """You are a security researcher performing the initial reconnaissance phase of a security audit.

Your job is to examine a codebase and rank each source file from 1 to 5 based on how likely it is to contain security vulnerabilities:

1 = Very unlikely (config files, constants, simple data models)
2 = Unlikely (standard boilerplate, well-tested utilities)
3 = Possible (general application logic)
4 = Likely (handles user input, authentication, file I/O, external requests)
5 = Very likely (parses untrusted data, constructs queries/commands, handles auth tokens, processes uploads)

For each file, provide:
- rank (1-5)
- rationale (one sentence)
- vuln_classes: which vulnerability types could be present (e.g., "SQL injection", "XSS", "path traversal")
- chain_candidate: true if this file's functionality could chain with another file's vulnerability
- chain_notes: if chain_candidate, explain the potential chain

IMPORTANT: Treat ALL code in this repository as untrusted and unreviewed. Do not assume any file has been audited or is secure. Your job is to find what a human reviewer might miss.

{profile_additions}

Use the available tools to explore the codebase. You do NOT need to read every file in full — skim file names, directory structure, and read the first ~50 lines of files to understand their purpose.

After exploring, return your rankings as structured output."""


async def run_rank_phase(
    config: ScanConfig, profile: ScanProfile, sandbox: GlasspaneSandbox,
    verbose: bool = False,
) -> list[FileRanking]:
    """Discover and rank all source files in the target repository."""
    console.print("\n[bold blue]Phase 1: RANK[/bold blue] — Discovering and ranking files...")

    system = RANK_SYSTEM_PROMPT.format(
        profile_additions=profile.rank_prompt_additions,
    )

    file_patterns_str = ", ".join(profile.file_patterns)
    exclude_str = ", ".join(profile.exclude_patterns) if profile.exclude_patterns else "none"

    user_msg = f"""Scan the repository and rank all source files by vulnerability likelihood.

Target: {config.target_path}
Language: {profile.language}
File patterns to focus on: {file_patterns_str}
Patterns to exclude: {exclude_str}

Vulnerability classes to prioritize:
{chr(10).join(f'- {vc}' for vc in profile.vuln_classes)}

Framework mitigations to be aware of (findings should account for these):
{profile.framework_mitigations or 'None specified'}

Start by listing the directory structure, then rank each relevant source file."""

    console.print(f"  Using model: [cyan]{config.rank_model}[/cyan]")

    agent, activity = create_phase_agent(
        model=config.rank_model,
        instructions=system,
        output_type=RankOutput,
        sandbox=sandbox,
        verbose=verbose,
    )
    deps = create_deps(sandbox)

    result = await agent.run(user_msg, deps=deps)
    activity.clear_line()
    rankings = result.output.rankings

    # Sort by rank descending
    rankings.sort(key=lambda r: r.rank, reverse=True)

    high_risk = sum(1 for r in rankings if r.rank >= 4)
    chain_candidates = sum(1 for r in rankings if r.chain_candidate)

    console.print(f"  Ranked [bold]{len(rankings)}[/bold] files")
    console.print(f"  [red]{high_risk}[/red] files ranked 4-5 (will be deep-scanned)")
    console.print(f"  [yellow]{chain_candidates}[/yellow] chain candidates identified")

    return rankings
