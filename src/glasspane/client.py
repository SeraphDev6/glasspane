"""Anthropic API client and agent loop for Glasspane.

The API client runs on the host (needs network to reach Anthropic).
Tool execution runs inside a Docker sandbox (no network, read-only repo).
"""

from __future__ import annotations

import os
from pathlib import Path

import anthropic
from rich.console import Console

from glasspane.sandbox import Sandbox, sandbox_tools, handle_sandbox_tool

console = Console()

SONNET = "claude-sonnet-4-6-20250514"
OPUS = "claude-opus-4-6-20250514"


def get_client(api_key: str | None = None) -> anthropic.Anthropic:
    """Get an Anthropic client.

    Uses the provided key, or falls back to ANTHROPIC_API_KEY env var.
    """
    key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
    if not key:
        console.print("[red]Error: No API key provided.[/red]")
        raise SystemExit(1)
    return anthropic.Anthropic(api_key=key)


def run_agent_loop(
    client: anthropic.Anthropic,
    model: str,
    system_prompt: str,
    user_message: str,
    sandbox: Sandbox,
    tools: list[dict] | None = None,
    max_turns: int = 30,
) -> str:
    """Run an agentic loop with tool use.

    API calls happen on the host. Tool execution happens in the Docker sandbox.
    The model gets: read_file, list_files, grep (ripgrep), shell (read-only bash).
    """
    if tools is None:
        tools = sandbox_tools()

    messages = [{"role": "user", "content": user_message}]

    for turn in range(max_turns):
        response = client.messages.create(
            model=model,
            max_tokens=16384,
            system=system_prompt,
            tools=tools,
            messages=messages,
        )

        if response.stop_reason == "end_turn":
            text_parts = [b.text for b in response.content if b.type == "text"]
            return "\n".join(text_parts)

        if response.stop_reason == "tool_use":
            messages.append({"role": "assistant", "content": response.content})

            tool_results = []
            for block in response.content:
                if block.type == "tool_use":
                    result = handle_sandbox_tool(block.name, block.input, sandbox)
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": result,
                    })

            messages.append({"role": "user", "content": tool_results})
        else:
            text_parts = [b.text for b in response.content if b.type == "text"]
            return "\n".join(text_parts) if text_parts else ""

    return "[Agent reached maximum turns without completing]"
