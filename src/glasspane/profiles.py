"""Scan profiles — generic built-in + external profile loading.

The generic profile ships with the open-source scaffold. Ecosystem-specific
profiles (drupal, python-ai-agent, etc.) are loaded from external YAML files
at ~/.glasspane/profiles/ or a path specified by GLASSPANE_PROFILES_DIR.

This separation is intentional: the scaffold is open source, the profiles
are the IP — the vuln checklists, framework mitigations, and prompt
engineering that make scans actually find bugs.
"""

from __future__ import annotations

import os
from pathlib import Path

import yaml

from glasspane.models import ScanProfile

# The only profile that ships with the open-source scaffold
GENERIC_PROFILE = ScanProfile(
    name="Generic",
    description="Language-agnostic security scan — works on any codebase",
    language="auto",
    file_patterns=["*"],
    exclude_patterns=[
        "*/tests/*",
        "*/test/*",
        "*/__pycache__/*",
        "*/node_modules/*",
        "*/vendor/*",
        "*/.git/*",
        "*/venv/*",
        "*/.venv/*",
    ],
    vuln_classes=[
        "Injection (SQL, command, LDAP, XPath, template — any untrusted input in a query or command)",
        "Authentication and session management flaws",
        "Access control bypass (missing or inconsistent permission checks)",
        "Cross-site scripting / XSS (unescaped output)",
        "Insecure deserialization",
        "Server-side request forgery / SSRF (user-controlled URLs in server requests)",
        "Path traversal (user-controlled file paths)",
        "Sensitive data exposure (credentials in logs, hardcoded secrets)",
        "Security misconfiguration (insecure defaults, verbose errors)",
        "Cryptographic failures (weak algorithms, improper key management)",
    ],
    framework_mitigations="",
    rank_prompt_additions="",
    analyze_prompt_additions="Check for INCONSISTENT security patterns — the same codebase using the correct sanitization in one path but missing it in another. This asymmetry is the strongest signal for real vulnerabilities.",
)

# Default directory for external profiles
DEFAULT_PROFILES_DIR = Path.home() / ".glasspane" / "profiles"


def _profiles_dir() -> Path:
    """Get the profiles directory, respecting GLASSPANE_PROFILES_DIR env var."""
    env_dir = os.environ.get("GLASSPANE_PROFILES_DIR")
    if env_dir:
        return Path(env_dir)
    return DEFAULT_PROFILES_DIR


def _load_external_profiles() -> dict[str, ScanProfile]:
    """Load all YAML profiles from the profiles directory."""
    profiles_dir = _profiles_dir()
    if not profiles_dir.is_dir():
        return {}

    external = {}
    for path in sorted(profiles_dir.glob("*.yml")):
        try:
            data = yaml.safe_load(path.read_text())
            profile = ScanProfile(**data)
            name = path.stem
            external[name] = profile
        except Exception:
            # Skip malformed profiles silently
            continue

    for path in sorted(profiles_dir.glob("*.yaml")):
        try:
            data = yaml.safe_load(path.read_text())
            profile = ScanProfile(**data)
            name = path.stem
            external[name] = profile
        except Exception:
            continue

    return external


def list_profiles() -> dict[str, ScanProfile]:
    """List all available profiles (built-in + external)."""
    profiles = {"generic": GENERIC_PROFILE}
    profiles.update(_load_external_profiles())
    return profiles


def get_profile(name: str) -> ScanProfile:
    """Get a scan profile by name.

    Looks up in order: external profiles dir, then built-in generic.
    """
    if name == "generic":
        return GENERIC_PROFILE

    # Try external profiles
    external = _load_external_profiles()
    if name in external:
        return external[name]

    available = ["generic"] + list(external.keys())
    raise ValueError(f"Unknown profile: {name}. Available: {', '.join(available)}")


def detect_profile(target_path) -> str:
    """Auto-detect the best profile based on the target codebase.

    Checks external profiles first (they have specific file_patterns),
    falls back to generic.
    """
    target = Path(target_path)
    external = _load_external_profiles()

    # Score each external profile by how many matching files exist
    best_name = "generic"
    best_score = 0

    resolved_target = target.resolve()

    for name, profile in external.items():
        score = 0
        for pattern in profile.file_patterns:
            # Reject patterns that could escape the target directory
            if ".." in pattern or Path(pattern).is_absolute():
                continue
            for match in list(target.rglob(pattern))[:100]:
                if match.resolve().is_relative_to(resolved_target):
                    score += 1
        if score > best_score:
            best_score = score
            best_name = name

    # Only use external profile if it found a meaningful number of files
    if best_score >= 5:
        return best_name

    return "generic"
