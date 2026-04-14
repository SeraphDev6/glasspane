"""User configuration — loads defaults from ~/.glasspane/config.yml.

Config file is optional. CLI flags override config file values.
API key is NEVER stored in the config — only the name of the env var to read.
"""

from __future__ import annotations

import os
from pathlib import Path

import yaml
from pydantic import BaseModel, Field

DEFAULT_CONFIG_PATH = Path.home() / ".glasspane" / "config.yml"


class UserConfig(BaseModel):
    """User defaults loaded from config file."""

    api_key_env: str = Field(default="ANTHROPIC_API_KEY", description="Environment variable containing the API key")
    rank_model: str = "claude-sonnet-4-6-20250514"
    analyze_model: str = "claude-opus-4-6-20250514"
    validate_model: str = "claude-opus-4-6-20250514"
    parallel: int = 3
    min_rank: int = 4
    max_files: int = 30
    default_profile: str = "auto"
    output_dir: str = "./glasspane-output"


def load_config(path: Path | None = None) -> UserConfig:
    """Load config from YAML file, falling back to defaults."""
    config_path = path or DEFAULT_CONFIG_PATH

    if not config_path.is_file():
        return UserConfig()

    try:
        data = yaml.safe_load(config_path.read_text())
        if not isinstance(data, dict):
            return UserConfig()
        return UserConfig(**data)
    except Exception:
        return UserConfig()


def resolve_api_key(config: UserConfig) -> str:
    """Read the API key from the configured environment variable."""
    return os.environ.get(config.api_key_env, "")


def write_default_config(path: Path | None = None) -> Path:
    """Write a default config file with comments."""
    config_path = path or DEFAULT_CONFIG_PATH
    config_path.parent.mkdir(parents=True, exist_ok=True)

    content = """# Glasspane configuration
# Docs: https://github.com/seraphdev-llc/glasspane

# Environment variable containing your Anthropic API key.
# The key itself is NEVER stored here — only the env var name.
api_key_env: ANTHROPIC_API_KEY

# Models — override per-phase if needed
rank_model: claude-sonnet-4-6-20250514
analyze_model: claude-opus-4-6-20250514
validate_model: claude-opus-4-6-20250514

# Scan defaults
parallel: 3          # Number of parallel analysis agents
min_rank: 4          # Minimum file rank to deep-scan (1-5)
max_files: 30        # Maximum files to deep-scan
default_profile: auto  # auto, generic, or any profile name

# Output
output_dir: ./glasspane-output
"""

    config_path.write_text(content)
    return config_path
