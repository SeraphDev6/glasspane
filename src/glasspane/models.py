"""Core data models for Glasspane scan pipeline."""

from __future__ import annotations

from enum import Enum
from pathlib import Path

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class FileRanking(BaseModel):
    """A ranked file from the RANK phase."""

    path: str
    rank: int = Field(ge=1, le=5, description="1=lowest risk, 5=highest risk")
    rationale: str
    vuln_classes: list[str] = Field(default_factory=list)
    chain_candidate: bool = False
    chain_notes: str = ""


class Finding(BaseModel):
    """A security finding from the ANALYZE phase."""

    id: str
    title: str
    severity: Severity
    cwe: str = ""
    file_path: str
    line_number: int | None = None
    description: str
    code_snippet: str = ""
    attack_vector: str = ""
    impact: str = ""
    recommendation: str = ""
    confidence: str = Field(default="medium", description="high/medium/low")
    chain_with: list[str] = Field(default_factory=list, description="IDs of related findings for chaining")


class Verdict(str, Enum):
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    POSSIBLE = "possible"
    FALSE_POSITIVE = "false_positive"
    NEEDS_POC = "needs_poc"


class ValidationResult(BaseModel):
    """Result from the VALIDATE phase."""

    finding_id: str
    verdict: Verdict
    reasoning: str
    adjusted_severity: Severity | None = None
    poc_suggestion: str = ""


class RankOutput(BaseModel):
    """Structured output from the RANK phase."""

    rankings: list[FileRanking]


class AnalyzeOutput(BaseModel):
    """Structured output from the ANALYZE phase."""

    findings: list[Finding]


class ValidateOutput(BaseModel):
    """Structured output from the VALIDATE phase."""

    validations: list[ValidationResult]


class ScanProfile(BaseModel):
    """Configuration profile for a specific ecosystem/language."""

    name: str
    description: str
    language: str
    file_patterns: list[str] = Field(description="Glob patterns for files to scan")
    exclude_patterns: list[str] = Field(default_factory=list)
    vuln_classes: list[str] = Field(description="Vulnerability classes to scan for")
    rank_prompt_additions: str = ""
    analyze_prompt_additions: str = ""
    framework_mitigations: str = Field(default="", description="Known framework-level protections to account for")
    max_file_size_kb: int = 500


class ScanConfig(BaseModel):
    """Top-level scan configuration."""

    target_path: Path
    output_path: Path = Path("./glasspane-output")
    profile: str = "auto"
    rank_model: str = "anthropic:claude-sonnet-4-6"
    analyze_model: str = "anthropic:claude-opus-4-6"
    validate_model: str = "anthropic:claude-opus-4-6"
    max_files_to_analyze: int = 30
    min_rank_to_analyze: int = 4
    generate_poc: bool = True
    parallel_agents: int = 3


class ScanResult(BaseModel):
    """Complete scan result."""

    target: str
    profile: str
    rankings: list[FileRanking] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    validations: list[ValidationResult] = Field(default_factory=list)
    total_files_discovered: int = 0
    total_files_ranked: int = 0
    total_files_analyzed: int = 0
    scan_duration_seconds: float = 0
    api_calls: int = 0
    estimated_cost_usd: float = 0
