"""Agent factories for Glasspane phases using pydantic-deep.

Each phase gets a configured pydantic-deep agent with:
- Docker sandbox backend for isolated tool execution
- Built-in filesystem and execute tools (read_file, grep, ls, shell)
- Structured output via output_type (automatic JSON parsing + validation)
"""

from __future__ import annotations

import shutil
import sys
from typing import Any, TypeVar

from pydantic import BaseModel
from pydantic_ai.capabilities.abstract import AbstractCapability
from pydantic_deep import DeepAgentDeps, create_deep_agent

from glasspane.sandbox import GlasspaneSandbox

T = TypeVar("T", bound=BaseModel)


class ToolActivityLog(AbstractCapability[Any]):
    """Prints a single overwriting status line showing the current tool call."""

    def __init__(self, verbose: bool = False) -> None:
        self._verbose = verbose
        self._call_count = 0
        self._cols = shutil.get_terminal_size().columns

    async def before_tool_execute(self, ctx, *, call, tool_def, args):
        self._call_count += 1
        items = args.items() if isinstance(args, dict) else args.model_dump().items() if isinstance(args, BaseModel) else {}
        preview = ", ".join(f"{k}={v!r}" for k, v in items)
        if len(preview) > self._cols - 40:
            preview = preview[: self._cols - 43] + "..."
        line = f"    [{self._call_count}] {call.tool_name}({preview})"
        if self._verbose:
            print(line, file=sys.stderr)
        else:
            print(f"\r\033[K{line}", end="", file=sys.stderr, flush=True)
        return args

    async def after_tool_execute(self, ctx, *, call, tool_def, args, result):
        return result

    def clear_line(self) -> None:
        if not self._verbose:
            print("\r\033[K", end="", file=sys.stderr, flush=True)


def create_phase_agent(
    model: str,
    instructions: str,
    output_type: type[T],
    sandbox: GlasspaneSandbox,
    verbose: bool = False,
) -> tuple[Any, ToolActivityLog]:
    """Create a pydantic-deep agent configured for a glasspane scan phase.

    The model parameter uses pydantic-ai's provider:model format
    (e.g. "anthropic:claude-sonnet-4-6", "openai:gpt-4o", "google-gla:gemini-2.5-pro").

    Enables only filesystem + execute tools. Disables planning, subagents,
    skills, memory, web access, and other features not needed for scanning.

    Returns (agent, activity_log) — call activity_log.clear_line() after the
    run completes to clean up the status line.
    """
    activity = ToolActivityLog(verbose=verbose)
    agent = create_deep_agent(
        model=model,
        instructions=instructions,
        output_type=output_type,
        backend=sandbox,
        capabilities=[activity],
        interrupt_on={"execute": False, "write_file": False, "edit_file": False},  # sandbox enforces read-only; no approval needed
        include_filesystem=True,
        include_execute=True,
        include_todo=False,
        include_subagents=False,
        include_skills=False,
        include_builtin_subagents=False,
        include_plan=False,
        include_memory=False,
        include_teams=False,
        include_improve=False,
        include_history_archive=False,
        include_checkpoints=False,
        web_search=False,
        web_fetch=False,
        context_manager=True,
        context_discovery=False,
        cost_tracking=True,
        stuck_loop_detection=True,
        patch_tool_calls=False,
        thinking="medium",
        retries=3,
    )
    return agent, activity


def create_deps(sandbox: GlasspaneSandbox) -> DeepAgentDeps:
    """Create dependencies for a glasspane agent run."""
    return DeepAgentDeps(backend=sandbox)
