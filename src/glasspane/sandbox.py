"""Docker-based sandbox for tool execution.

All tool calls from the LLM execute inside an isolated container:
- Target repo mounted read-only at /repo
- Output dir mounted read-write at /output
- No network access (--network none)
- No host filesystem access beyond the mounts
- Real CLI tools available: grep, find, cat, wc, file, head, tail, etc.
- Runs as non-root user

The host process sends tool calls to the sandbox via docker exec.
"""

from __future__ import annotations

import json
import subprocess
import shlex
import hashlib
from pathlib import Path

from rich.console import Console

console = Console()

SANDBOX_IMAGE = "glasspane-sandbox"
SANDBOX_DOCKERFILE = """FROM python:3.12-slim

# Install useful CLI tools for security analysis
RUN apt-get update && apt-get install -y --no-install-recommends \\
    ripgrep \\
    tree \\
    file \\
    jq \\
    && rm -rf /var/lib/apt/lists/*

# Non-root user
RUN useradd -m -s /bin/bash scanner
USER scanner
WORKDIR /repo
"""


class Sandbox:
    """Manages a Docker container for isolated tool execution."""

    def __init__(self, repo_path: Path, output_path: Path):
        self.repo_path = repo_path.resolve()
        self.output_path = output_path.resolve()
        self.container_name = f"glasspane-{hashlib.md5(str(self.repo_path).encode()).hexdigest()[:12]}"
        self._running = False

    def start(self) -> None:
        """Build image if needed and start the sandbox container."""
        self._ensure_image()
        self.output_path.mkdir(parents=True, exist_ok=True)

        # Stop any existing container with same name
        subprocess.run(
            ["docker", "rm", "-f", self.container_name],
            capture_output=True,
        )

        # Start container: repo read-only, output read-write, no network
        result = subprocess.run(
            [
                "docker", "run", "-d",
                "--name", self.container_name,
                "--network", "none",
                "--read-only",
                "--tmpfs", "/tmp:size=100m",
                "-v", f"{self.repo_path}:/repo:ro",
                "-v", f"{self.output_path}:/output:rw",
                SANDBOX_IMAGE,
                "sleep", "infinity",
            ],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            raise RuntimeError(f"Failed to start sandbox: {result.stderr}")

        self._running = True
        console.print(f"  Sandbox started: [dim]{self.container_name}[/dim]")

    def stop(self) -> None:
        """Stop and remove the sandbox container."""
        if self._running:
            subprocess.run(
                ["docker", "rm", "-f", self.container_name],
                capture_output=True,
            )
            self._running = False

    def exec(self, command: list[str], timeout: int = 30) -> str:
        """Execute a command inside the sandbox and return stdout."""
        result = subprocess.run(
            ["docker", "exec", self.container_name] + command,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode != 0 and result.stderr:
            return json.dumps({"error": result.stderr.strip()[:500]})
        return result.stdout

    def _ensure_image(self) -> None:
        """Build the sandbox image if it doesn't exist."""
        check = subprocess.run(
            ["docker", "image", "inspect", SANDBOX_IMAGE],
            capture_output=True,
        )
        if check.returncode == 0:
            return

        console.print("  Building sandbox image...")
        result = subprocess.run(
            ["docker", "build", "-t", SANDBOX_IMAGE, "-"],
            input=SANDBOX_DOCKERFILE,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Failed to build sandbox image: {result.stderr}")

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        self.stop()


# --- Tool definitions (what the LLM sees) ---

def sandbox_tools() -> list[dict]:
    """Tool definitions for sandbox-executed tools."""
    return [
        {
            "name": "read_file",
            "description": "Read the contents of a file from the target repository.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "File path relative to the repository root.",
                    },
                    "start_line": {
                        "type": "integer",
                        "description": "Optional: start reading from this line number (1-based).",
                    },
                    "end_line": {
                        "type": "integer",
                        "description": "Optional: stop reading at this line number.",
                    },
                },
                "required": ["path"],
            },
        },
        {
            "name": "list_files",
            "description": "List files in the target repository. Uses 'find' under the hood — supports full find syntax.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Directory path relative to repo root. Use '.' for root.",
                    },
                    "pattern": {
                        "type": "string",
                        "description": "Glob pattern for file names (e.g., '*.py', '*.php'). Default: all files.",
                        "default": "*",
                    },
                },
                "required": ["path"],
            },
        },
        {
            "name": "grep",
            "description": "Search file contents using ripgrep (rg). Fast regex search across the codebase. Returns matching lines with file paths and line numbers.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Regex pattern to search for.",
                    },
                    "path": {
                        "type": "string",
                        "description": "Directory to search in, relative to repo root. Use '.' for entire repo.",
                        "default": ".",
                    },
                    "file_pattern": {
                        "type": "string",
                        "description": "Glob to filter files (e.g., '*.py'). Maps to rg --glob.",
                        "default": "",
                    },
                    "context_lines": {
                        "type": "integer",
                        "description": "Number of context lines before and after each match.",
                        "default": 0,
                    },
                },
                "required": ["pattern"],
            },
        },
        {
            "name": "shell",
            "description": "Run a read-only shell command inside the sandbox. The repository is mounted at /repo (read-only). Use for advanced analysis: wc, file, head, tail, sort, uniq, diff, tree, jq, etc. No write access, no network.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "Shell command to execute. Working directory is /repo.",
                    },
                },
                "required": ["command"],
            },
        },
    ]


def handle_sandbox_tool(tool_name: str, tool_input: dict, sandbox: Sandbox) -> str:
    """Execute a tool call inside the Docker sandbox."""
    if tool_name == "read_file":
        return _sandbox_read_file(tool_input, sandbox)
    elif tool_name == "list_files":
        return _sandbox_list_files(tool_input, sandbox)
    elif tool_name == "grep":
        return _sandbox_grep(tool_input, sandbox)
    elif tool_name == "shell":
        return _sandbox_shell(tool_input, sandbox)
    else:
        return json.dumps({"error": f"Unknown tool: {tool_name}"})


def _sandbox_read_file(inp: dict, sandbox: Sandbox) -> str:
    path = inp["path"]
    start = inp.get("start_line")
    end = inp.get("end_line")

    if start and end:
        cmd = ["sed", "-n", f"{start},{end}p", f"/repo/{path}"]
    elif start:
        cmd = ["tail", "-n", f"+{start}", f"/repo/{path}"]
    else:
        cmd = ["cat", "-n", f"/repo/{path}"]

    result = sandbox.exec(cmd, timeout=10)

    # Truncate very large output
    if len(result) > 200_000:
        result = result[:200_000] + "\n\n... [TRUNCATED — exceeds 200KB]"

    return result


def _sandbox_list_files(inp: dict, sandbox: Sandbox) -> str:
    path = inp.get("path", ".")
    pattern = inp.get("pattern", "*")

    cmd = [
        "find", f"/repo/{path}",
        "-name", pattern,
        "-type", "f",
        "-printf", "%p\t%s\n",
    ]

    result = sandbox.exec(cmd, timeout=15)

    # Rewrite paths to be relative to /repo
    lines = []
    for line in result.strip().splitlines()[:500]:
        if "\t" in line:
            fpath, size = line.rsplit("\t", 1)
            fpath = fpath.replace("/repo/", "", 1)
            lines.append(f"{fpath}\t{size}")
    return "\n".join(lines) if lines else "(no files found)"


def _sandbox_grep(inp: dict, sandbox: Sandbox) -> str:
    pattern = inp["pattern"]
    path = inp.get("path", ".")
    file_pattern = inp.get("file_pattern", "")
    context = inp.get("context_lines", 0)

    cmd = ["rg", "--no-heading", "-n"]
    if context > 0:
        cmd += ["-C", str(context)]
    if file_pattern:
        cmd += ["--glob", file_pattern]
    cmd += ["--", pattern, f"/repo/{path}"]

    result = sandbox.exec(cmd, timeout=20)

    # Rewrite paths
    result = result.replace("/repo/", "")

    # Truncate
    lines = result.splitlines()
    if len(lines) > 500:
        result = "\n".join(lines[:500]) + f"\n\n... [{len(lines) - 500} more matches truncated]"

    return result if result.strip() else "(no matches)"


def _sandbox_shell(inp: dict, sandbox: Sandbox) -> str:
    command = inp["command"]

    # Execute via bash inside the container — working dir is /repo
    result = sandbox.exec(
        ["bash", "-c", f"cd /repo && {command}"],
        timeout=30,
    )

    # Truncate
    if len(result) > 100_000:
        result = result[:100_000] + "\n\n... [TRUNCATED]"

    return result if result.strip() else "(no output)"
