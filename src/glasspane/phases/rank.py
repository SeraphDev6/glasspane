"""Phase 1: RANK — Discover and rank files by vulnerability likelihood.

Uses Sonnet for speed. Replicates the manual step where we counted PHP files
per module and prioritized by attack surface (auth, file upload, etc.).
"""

from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console
from rich.progress import Progress

from glasspane.client import SONNET, get_client, run_agent_loop
from glasspane.models import FileRanking, ScanConfig, ScanProfile
from glasspane.sandbox import Sandbox

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

Use the list_files and read_file tools to explore the codebase. You do NOT need to read every file in full — skim file names, directory structure, and read the first ~50 lines of files to understand their purpose.

After exploring, respond with a JSON array of FileRanking objects. Output ONLY the JSON array, no other text.

Example:
[
  {{"path": "src/auth/login.py", "rank": 5, "rationale": "Handles user authentication with password validation", "vuln_classes": ["authentication bypass", "timing attack"], "chain_candidate": true, "chain_notes": "Auth bypass here could chain with admin-only endpoints"}},
  {{"path": "src/utils/constants.py", "rank": 1, "rationale": "Static constants, no user input", "vuln_classes": [], "chain_candidate": false, "chain_notes": ""}}
]"""


def run_rank_phase(config: ScanConfig, profile: ScanProfile, sandbox: Sandbox) -> list[FileRanking]:
    """Discover and rank all source files in the target repository."""
    console.print("\n[bold blue]Phase 1: RANK[/bold blue] — Discovering and ranking files...")

    client = get_client()

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

    raw_response = run_agent_loop(
        client=client,
        model=config.rank_model,
        system_prompt=system,
        user_message=user_msg,
        sandbox=sandbox,
    )

    # Parse the JSON response
    rankings = _parse_rankings(raw_response)

    # Sort by rank descending
    rankings.sort(key=lambda r: r.rank, reverse=True)

    high_risk = sum(1 for r in rankings if r.rank >= 4)
    chain_candidates = sum(1 for r in rankings if r.chain_candidate)

    console.print(f"  Ranked [bold]{len(rankings)}[/bold] files")
    console.print(f"  [red]{high_risk}[/red] files ranked 4-5 (will be deep-scanned)")
    console.print(f"  [yellow]{chain_candidates}[/yellow] chain candidates identified")

    return rankings


def _parse_rankings(raw: str) -> list[FileRanking]:
    """Parse the model's JSON response into FileRanking objects."""
    # Find JSON array in the response (model might include extra text)
    start = raw.find("[")
    end = raw.rfind("]") + 1
    if start == -1 or end == 0:
        console.print("[red]  Warning: Could not parse rankings from model response[/red]")
        return []

    try:
        data = json.loads(raw[start:end])
        return [FileRanking(**item) for item in data]
    except (json.JSONDecodeError, ValueError) as e:
        console.print(f"[red]  Warning: Failed to parse rankings: {e}[/red]")
        return []
