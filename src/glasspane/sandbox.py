"""Docker-based sandbox for tool execution via pydantic-deep.

All tool calls from the LLM execute inside an isolated container:
- Target repo mounted read-only at /repo
- Output dir mounted read-write at /output
- No network access (--network none)
- Real CLI tools available: ripgrep, tree, file, jq, etc.
- Runs as non-root user

Uses pydantic-deep's DockerSandbox with a custom image and read-only mount override.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import uuid
from pathlib import Path
from typing import Any

from rich.console import Console

from pydantic_deep import DockerSandbox

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


def _dockerfile_digest() -> str:
    """Return a stable hash of the embedded Dockerfile content."""
    return hashlib.sha256(SANDBOX_DOCKERFILE.encode()).hexdigest()[:16]


def _ensure_image() -> None:
    """Build the sandbox image if it doesn't exist or wasn't built by us."""
    expected_digest = _dockerfile_digest()

    # Check if image exists and was built by Glasspane with the current Dockerfile
    check = subprocess.run(
        ["docker", "image", "inspect", SANDBOX_IMAGE],
        capture_output=True,
        text=True,
    )
    if check.returncode == 0:
        try:
            info = json.loads(check.stdout)
            labels = info[0].get("Config", {}).get("Labels") or {}
            if labels.get("glasspane.dockerfile-digest") == expected_digest:
                return
        except (json.JSONDecodeError, IndexError, KeyError):
            pass
        # Image exists but isn't ours or is stale — remove it
        subprocess.run(
            ["docker", "rmi", "-f", SANDBOX_IMAGE],
            capture_output=True,
        )

    console.print("  Building sandbox image...")
    labeled_dockerfile = SANDBOX_DOCKERFILE + (
        f'\nLABEL glasspane.dockerfile-digest="{expected_digest}"\n'
    )
    result = subprocess.run(
        ["docker", "build", "-t", SANDBOX_IMAGE, "-"],
        input=labeled_dockerfile,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Failed to build sandbox image: {result.stderr}")


class GlasspaneSandbox(DockerSandbox):
    """DockerSandbox with read-only repo mount and glasspane-specific config."""

    def __init__(self, repo_path: Path, output_path: Path):
        self._repo_path = repo_path.resolve()
        self._output_path = output_path.resolve()
        self._output_path.mkdir(parents=True, exist_ok=True)

        _ensure_image()

        container_id = uuid.uuid4().hex[:12]

        super().__init__(
            image=SANDBOX_IMAGE,
            work_dir="/repo",
            network_mode="none",
            volumes={
                str(self._repo_path): "/repo",
                str(self._output_path): "/output",
            },
            container_name=f"glasspane-{container_id}",
        )

    def _ensure_container(self) -> None:
        """Override to set repo volume as read-only and output as read-write."""
        if self._container is not None:
            return

        try:
            import docker
        except ImportError as e:
            raise ImportError(
                "Docker package not installed. Install with: pip install docker"
            ) from e

        client = docker.from_env()

        # Build volume mounts with correct modes: repo=ro, output=rw
        docker_volumes: dict[str, dict[str, str]] = {
            str(self._repo_path): {"bind": "/repo", "mode": "ro"},
            str(self._output_path): {"bind": "/output", "mode": "rw"},
        }

        run_kwargs: dict[str, Any] = dict(
            command="sleep infinity",
            detach=True,
            working_dir=self._work_dir,
            auto_remove=self._auto_remove,
            read_only=True,
            tmpfs={"/tmp": "size=100m"},
            volumes=docker_volumes,
            mem_limit="512m",
            cpu_period=100000,
            cpu_quota=100000,  # 1 CPU
            pids_limit=256,
        )
        if self._container_name is not None:
            run_kwargs["name"] = self._container_name
        if self._network_mode is not None:
            run_kwargs["network_mode"] = self._network_mode

        self._container = client.containers.run(self._image, **run_kwargs)
        console.print(f"  Sandbox started: [dim]{self._container_name}[/dim]")
