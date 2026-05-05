"""User configuration — loads defaults from ~/.glasspane/config.yml.

Config file is optional. CLI flags override config file values.
API keys are managed via standard environment variables for each provider
(e.g. ANTHROPIC_API_KEY, OPENAI_API_KEY, GOOGLE_API_KEY).
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field

DEFAULT_CONFIG_PATH = Path.home() / ".glasspane" / "config.yml"


class UserConfig(BaseModel):
    """User defaults loaded from config file."""

    rank_model: str = "anthropic:claude-sonnet-4-6"
    analyze_model: str = "anthropic:claude-opus-4-6"
    validate_model: str = "anthropic:claude-opus-4-6"
    parallel: int = Field(3, ge=1, le=32)
    min_rank: int = Field(4, ge=1, le=5)
    max_files: int = Field(30, ge=1, le=1000)
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


def write_default_config(path: Path | None = None) -> Path:
    """Write a default config file with comments."""
    config_path = path or DEFAULT_CONFIG_PATH
    config_path.parent.mkdir(parents=True, exist_ok=True)

    content = """# Glasspane configuration
# Docs: https://github.com/seraphdev-llc/glasspane

# Models use the provider:model format supported by pydantic-ai.
# Set the appropriate API key env var for your provider:
#
#   Anthropic:     export ANTHROPIC_API_KEY=...
#   OpenAI:        export OPENAI_API_KEY=...
#   Azure OpenAI:  export AZURE_OPENAI_ENDPOINT=https://<resource>.openai.azure.com
#                  export AZURE_OPENAI_API_KEY=...
#                  export OPENAI_API_VERSION=2024-12-01-preview
#   AWS Bedrock:   export AWS_DEFAULT_REGION=us-east-1  (+ AWS credentials)
#   Google:        export GOOGLE_API_KEY=...
#   Groq:          export GROQ_API_KEY=...
#
# Install provider extras as needed:
#   pip install glasspane[azure]     # Azure OpenAI
#   pip install glasspane[bedrock]   # AWS Bedrock
#   pip install glasspane[all]       # All providers
#
# Examples:
#   anthropic:claude-sonnet-4-6          openai:gpt-4o
#   anthropic:claude-opus-4-6            openai:o3
#   azure:gpt-5.4                        google-gla:gemini-2.5-pro
#   bedrock:anthropic.claude-sonnet-4-6  groq:llama-3.3-70b-versatile
rank_model: anthropic:claude-sonnet-4-6
analyze_model: anthropic:claude-opus-4-6
validate_model: anthropic:claude-opus-4-6

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
