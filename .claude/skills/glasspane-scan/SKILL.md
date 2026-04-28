---
name: glasspane-scan
description: "Run a 7-phase AI security scan (RECON, RANK, ANALYZE, CHAIN, VALIDATE, REPORT, POC) on a target codebase. Maps codebase structure, ranks files by vulnerability likelihood, deep-scans high-risk files with parallel agents, synthesizes cross-file exploit chains, validates findings adversarially, produces structured reports, and optionally generates proof-of-concept exploits."
---

# Glasspane Security Scan

You are executing the Glasspane security scanning workflow — a 7-phase AI-powered security audit pipeline. Follow each phase precisely in order. Do not skip phases. Do not improvise the workflow.

## Invocation

The user invokes this skill as `/glasspane-scan [target-path]`.

- If `target-path` is provided, use it as the absolute path to the repository to scan.
- If no argument is provided, use the current working directory as the target.
- Set `OUTPUT_DIR` to `<target-path>/glasspane-output`.

Announce the scan with a banner:

```
## Glasspane Security Scan
- **Target:** <target-path>
- **Output:** <OUTPUT_DIR>
- **Profile:** Generic (language-agnostic)
- **Phases:** RECON → RANK → ANALYZE → CHAIN → VALIDATE → REPORT → POC (optional)
- **Min rank to analyze:** 4
- **Max files to analyze:** 50
- **Parallel agents:** 3
```

## Constants

```
MIN_RANK = 4
MAX_FILES = 50
PARALLEL_AGENTS = 3
GENERATE_POC = true

EXCLUDE_PATTERNS:
  */tests/*
  */test/*
  */__pycache__/*
  */node_modules/*
  */vendor/*
  */.git/*
  */venv/*
  */.venv/*
  */.tox/*
  */dist/*
  */build/*
  */.mypy_cache/*
  */.pytest_cache/*
  */.ruff_cache/*

BINARY_EXTENSIONS (skip these):
  .png .jpg .jpeg .gif .ico .bmp .webp .svg
  .woff .woff2 .ttf .eot .otf
  .pdf .zip .gz .tar .bz2 .xz .7z .rar
  .lock .map .min.js .min.css
  .pyc .pyo .class .o .so .dll .exe .wasm .dylib
  .db .sqlite .sqlite3
  .DS_Store
```

## Vulnerability Classes Checklist

Use this checklist in both RANK and ANALYZE phases. Scan for ALL of these:

1. **Injection** — SQL, command, LDAP, XPath, template — any untrusted input in a query or command
2. **Authentication and session management flaws**
3. **Access control bypass** — missing or inconsistent permission checks
4. **Cross-site scripting / XSS** — unescaped output
5. **Insecure deserialization**
6. **Server-side request forgery / SSRF** — user-controlled URLs in server requests
7. **Path traversal** — user-controlled file paths
8. **Sensitive data exposure** — credentials in logs, hardcoded secrets
9. **Security misconfiguration** — insecure defaults, verbose errors
10. **Cryptographic failures** — weak algorithms, improper key management

---

## Phase 0.5: RECON — Build Codebase Context Map

Announce: `## Phase 0.5: RECON — Mapping codebase structure...`

### Step 0.5.1: Launch Recon Agent

Launch the **`glasspane-recon`** agent (defined in `.claude/agents/glasspane-recon.md`) with this user message:

```
Scan the repository at: {target_path}

Build a structural map of the codebase for a security audit.
```

### Step 0.5.2: Process Recon Results

1. Extract the JSON object from the agent's response (find content between ` ```json ` and ` ``` ` markers)
2. Store the entire JSON object as `codebase_context_json` — you will inject this into every subsequent agent prompt
3. Display a brief summary:

```
### Recon Results
- Entry points found: <count>
- Trust boundaries mapped: <count>
- Auth mechanism: <description>
- Frameworks: <comma-separated list>
```

### Step 0.5.3: Handle Recon Failure

If the recon agent fails or returns unparseable output:
- Log: "RECON phase failed — continuing without codebase context"
- Set `codebase_context_json` to `"No codebase context available — the recon phase did not complete. Proceed with your own analysis of the codebase structure."`
- Continue to Phase 1. All subsequent phases degrade gracefully without context.

---

## Phase 1: RANK — Discover and Rank Files

Announce: `## Phase 1: RANK — Discovering and ranking files...`

### Step 1.1: File Discovery

Use the **Glob** tool with pattern `**/*` on the target directory to discover all files. Then filter:

1. Remove files matching any EXCLUDE_PATTERNS
2. Remove files with any BINARY_EXTENSIONS
3. Remove files larger than 500KB (skip reading them; estimate from context or just include them and note the size)

Record the count as `total_files_discovered`.

### Step 1.2: Rank Each File

**Before ranking**, review the codebase context from RECON to inform your ranking decisions. Files near entry points, trust boundaries, and auth mechanisms should generally rank higher.

You are a security researcher performing initial reconnaissance. For each discovered source file, assign a rank from 1 to 5:

| Rank | Meaning | Examples |
|------|---------|----------|
| **1** | Very unlikely to contain vulnerabilities | Config files, constants, simple data models, package manifests |
| **2** | Unlikely | Standard boilerplate, well-tested utilities, type definitions |
| **3** | Possible | General application logic, internal helpers |
| **4** | Likely | Handles user input, authentication, file I/O, external requests, database queries |
| **5** | Very likely | Parses untrusted data, constructs queries/commands, handles auth tokens, processes uploads, deserializes data |

For efficiency:
- Use **Read** on each file (first ~80 lines, or full file if small) to understand its purpose
- Use **Grep** to search for high-signal patterns across the codebase: `exec`, `eval`, `subprocess`, `system`, `sql`, `query`, `password`, `token`, `secret`, `upload`, `request\.get`, `open(`, `deserializ`, `pickle`, `yaml\.load`, `innerHTML`, `dangerouslySetInnerHTML`, `shell=True`, `os\.system`, `render_template`, `raw_input`, `input(`, `getattr`, `__import__`
- You do NOT need to read every file in full — skim file names, directory structure, and key lines

For EACH file, record:
- **path**: relative path from target root
- **rank**: 1-5
- **rationale**: one sentence explaining the rank
- **vuln_classes**: which vulnerability types from the checklist could be present
- **chain_candidate**: true if this file's functionality could chain with another file's vulnerability
- **chain_notes**: if chain_candidate is true, explain the potential chain

**IMPORTANT:** Treat ALL code in this repository as untrusted and unreviewed. Do not assume any file has been audited or is secure. Your job is to find what a human reviewer might miss.

**Check for INCONSISTENT security patterns** — the same codebase using correct sanitization in one path but missing it in another. This asymmetry is the strongest signal for real vulnerabilities.

### Step 1.3: Display Rankings

Display a summary table of all files ranked >= 3, sorted by rank descending:

```
| Rank | File | Rationale | Vuln Classes |
|------|------|-----------|--------------|
| 5    | ... | ...       | ...          |
| 4    | ... | ...       | ...          |
| 3    | ... | ...       | ...          |
```

Report:
- Total files discovered
- Files ranked 4-5 (will be deep-scanned)
- Chain candidates identified

### Step 1.4: Select Targets for Phase 2

Filter to files with rank >= `MIN_RANK` (4). Cap at `MAX_FILES` (50). Sort by rank descending. If NO files rank >= 4, announce "No high-risk files found — skipping ANALYZE and VALIDATE phases" and jump directly to Phase 4: REPORT with empty findings.

Store the full rankings list (all files, all ranks) — you will need it for the final report.

---

## Phase 2: ANALYZE — Deep Security Scan

Announce: `## Phase 2: ANALYZE — Deep scanning <N> high-priority files...`

### Step 2.1: Create Batches

Distribute the target files (rank >= 4, capped at 50) across up to `PARALLEL_AGENTS` (3) batches using round-robin assignment:
- File 0 → Batch 1
- File 1 → Batch 2
- File 2 → Batch 3
- File 3 → Batch 1
- File 4 → Batch 2
- ... and so on

If there are fewer files than PARALLEL_AGENTS, use only as many batches as there are files.

### Step 2.2: Launch Parallel Agents

Launch ALL batch agents simultaneously using the **Agent** tool. Send a single message with multiple Agent tool calls — one per batch. Each agent MUST use the **`glasspane-analyze`** agent (defined in `.claude/agents/glasspane-analyze.md`).

Each Agent call must include the complete user message below (agents do not share context with each other or with you). Fill in the `{variables}` for each batch:

```
Target repository: {target_path}
Batch: {batch_number}

## Codebase Context

{codebase_context_json}

## Target Files

{file_list}

(Each file formatted as: "- {path} (rank {rank}): {rationale} [CHAIN CANDIDATE: {chain_notes}]")

Number your findings as FIND-{batch_number}-001, FIND-{batch_number}-002, etc.
```

### Step 2.3: Collect and Deduplicate

After ALL agents complete:

1. Extract the JSON array from each agent's response (find content between ` ```json ` and ` ``` ` markers)
2. Combine all findings into a single list
3. **Deduplicate**: For each finding, compute a key of `(file_path, line_number, first 50 chars of title)`. If two findings share the same key, keep only the first occurrence.
4. **Renumber**: Assign new sequential IDs: `GP-001`, `GP-002`, `GP-003`, etc.

### Step 2.4: Display Analysis Summary

Show a summary:

```
### Analysis Results
- Agent 1: <N> findings
- Agent 2: <N> findings
- Agent 3: <N> findings
- **Total (after dedup): <N> findings**

| Severity | Count |
|----------|-------|
| Critical | ...   |
| High     | ...   |
| Medium   | ...   |
| Low      | ...   |
| Info     | ...   |
```

If zero findings after all agents, announce this and skip to Phase 4: REPORT.

---

## Phase 2.5: CHAIN — Cross-File Exploit Chain Synthesis

Announce: `## Phase 2.5: CHAIN — Synthesizing cross-file exploit chains...`

If there are no findings from Phase 2 OR no chain candidates from Phase 1, skip this phase and announce: "No chain candidates — skipping chain synthesis."

### Step 2.5.1: Prepare Chain Input

Collect:
1. All deduplicated findings from Phase 2 (the full GP-XXX list with JSON)
2. All files flagged as `chain_candidate: true` from Phase 1 rankings (with their chain_notes)
3. The `codebase_context_json` from RECON

### Step 2.5.2: Launch Chain Synthesis Agent

Launch the **`glasspane-chain`** agent (defined in `.claude/agents/glasspane-chain.md`) with this user message:

```
Target repository: {target_path}

## Codebase Context

{codebase_context_json}

## Individual Findings

{findings_json}

(The full JSON array of all deduplicated GP-XXX findings)

## Chain Candidates

{chain_candidates_list}

(Each formatted as: "- {path} (rank {rank}): {chain_notes}")
```

### Step 2.5.3: Process Chain Results

1. Extract the JSON array from the agent's response
2. Store chain findings separately — they use CHAIN-XXX IDs, not GP-XXX IDs
3. Display a summary:

```
### Chain Analysis Results
- Chains identified: <count>
- Findings involved in chains: <count of unique GP-XXX IDs across all chains>

| ID | Severity | Title | Constituent Findings |
|----|----------|-------|---------------------|
| CHAIN-001 | ... | ... | GP-001, GP-003 |
```

If zero chains found, announce: "No cross-file exploit chains identified."

---

## Phase 3: VALIDATE — Adversarial Verification

Announce: `## Phase 3: VALIDATE — Adversarial verification of <N> findings...`

### Step 3.1: Launch Validation Agent

Launch the **`glasspane-validate`** agent (defined in `.claude/agents/glasspane-validate.md`) with this user message:

```
Target repository: {target_path}

## Codebase Context

{codebase_context_json}

## Individual Findings

{findings_json}

(The full JSON array of all deduplicated GP-XXX findings)

## Chain Findings

{chain_findings_json}

(The chain findings JSON array. If no chains were found: "No chain findings to validate.")
```

---

### Step 3.2: Process Validation Results

1. Extract the JSON array from the agent's response
2. Match each validation result to its finding by `finding_id` (both GP-XXX and CHAIN-XXX IDs)
3. If the validator missed any finding (no matching `finding_id`), assign a default verdict of `likely` with reasoning "Not reviewed by validator — defaulting to likely"
4. Separate validation results into two lists: individual finding validations and chain finding validations

### Step 3.3: Display Validation Summary

```
### Validation Results
| Verdict | Count |
|---------|-------|
| Confirmed | ... |
| Likely | ... |
| Possible | ... |
| False Positive | ... |
| Needs PoC | ... |
```

---

## Phase 4: REPORT — Generate Output

Announce: `## Phase 4: REPORT — Generating output...`

### Step 4.1: Filter Findings

Only findings with a verdict of **confirmed**, **likely**, or **needs_poc** survive to the report. Findings with verdicts of `possible` or `false_positive` are excluded from individual reports and the summary findings list (but are preserved in scan_data.json).

If a finding's validation has an `adjusted_severity` that is not null, use the adjusted severity instead of the original.

### Step 4.2: Write Individual Finding Reports

For each surviving finding, use the **Write** tool to create `<OUTPUT_DIR>/findings/<safe_id>.md`.

The `safe_id` is computed from the finding ID by keeping only alphanumeric characters, hyphens, underscores, and dots. If the result is empty, use "unknown".

Use EXACTLY this template:

```markdown
# {title}

**ID:** {id}
**Severity:** {severity in UPPERCASE}
**CWE:** {cwe}
**Validation:** {verdict}
**Confidence:** {confidence}

## Location

**File:** `{file_path}`
**Line:** {line_number or 'N/A'}

## Description

{description}

## Vulnerable Code

```
{code_snippet}
```

## Attack Vector

{attack_vector}

## Impact

{impact}

## Recommendation

{recommendation}
```

Conditionally append these sections ONLY if the data exists:

If validation reasoning is non-empty:
```markdown
## Validation Notes

{validation reasoning}
```

If poc_suggestion is non-empty:
```markdown
## PoC Suggestion

{poc_suggestion}
```

If chain_with is non-empty:
```markdown
## Chain Potential

Chains with: {comma-separated list of finding IDs}
```

If this finding has a PoC from Phase 3.5:
```markdown
## Proof of Concept

**Type:** {poc_type}

```
{poc code}
```

**Setup:** {setup_instructions}
**Expected Result:** {expected_result}
**Notes:** {notes}
```

### Step 4.2.1: Write Chain Finding Reports

For each surviving chain finding (CHAIN-XXX with verdict confirmed, likely, or needs_poc), use the **Write** tool to create `<OUTPUT_DIR>/findings/<safe_id>.md`.

Use this template (different from individual findings):

```markdown
# {title}

**ID:** {id}
**Severity:** {severity in UPPERCASE}
**Type:** Exploit Chain
**Validation:** {verdict}

## Constituent Findings

{comma-separated list of finding_ids with links: GP-001, GP-003}

## Attack Path

{attack_path — rendered with each step on its own line}

## Description

{description}

## Impact

{impact}

## Recommendation

{recommendation}
```

Conditionally append Validation Notes and Proof of Concept sections as with individual findings.

### Step 4.3: Write SUMMARY.md

Use the **Write** tool to create `<OUTPUT_DIR>/SUMMARY.md` with EXACTLY this format:

```markdown
# Glasspane Security Scan — Summary Report

**Date:** {current date/time in YYYY-MM-DD HH:MM UTC format}
**Target:** {target path}
**Profile:** Generic

## Scan Statistics

| Metric | Value |
|--------|-------|
| Files discovered | {total_files_discovered} |
| Files ranked | {count of all ranked files} |
| Files deep-scanned | {count of files with rank >= MIN_RANK that were analyzed} |
| Raw findings | {total findings before filtering} |
| Confirmed/Likely findings | {count of surviving individual findings} |
| Exploit chains | {count of surviving chain findings} |
| PoCs generated | {count of PoC results, or 0 if phase was skipped} |
| False positives filtered | {raw findings minus surviving findings} |

## Findings by Severity

| Severity | Count |
|----------|-------|
| Critical | {count} |
| High | {count} |
| Medium | {count} |
| Low | {count} |
| Informational | {count} |

## All Findings

| Severity | Title | File | CWE |
|----------|-------|------|-----|
| {SEVERITY} | {title} | `{file_path}` | {cwe} |
{... one row per surviving finding, sorted by severity: critical first, then high, medium, low, informational}

## Exploit Chains

{If chain findings exist with surviving verdicts, render this table. If none, write "No exploit chains identified."}

| Severity | Chain | Constituent Findings | Attack Path Summary |
|----------|-------|---------------------|---------------------|
| {SEVERITY} | {title} | {finding_ids joined} | {first line of attack_path} |

## Methodology

- **Recon phase:** Codebase structure mapping (entry points, trust boundaries, auth mechanisms)
- **Rank phase:** File discovery and risk ranking (1-5 scale)
- **Analyze phase:** Deep scan with up to 3 parallel agents, informed by recon context
- **Chain phase:** Cross-file exploit chain synthesis
- **Validate phase:** Adversarial verification of all findings and chains
- **PoC phase:** Proof-of-concept generation for ambiguous findings (conditional)
- **Profile:** Generic (language-agnostic)
- **Minimum rank to analyze:** 4

## Scan Engine

Glasspane — AI-powered security scanning (Claude Code skill)
```

### Step 4.4: Write scan_data.json

Use the **Write** tool to create `<OUTPUT_DIR>/scan_data.json` containing the complete scan data. This file includes ALL data — including false positives and unconfirmed findings — for programmatic analysis.

```json
{
  "target": "{target path}",
  "profile": "generic",
  "codebase_context": {codebase_context_json or null if recon failed},
  "rankings": [
    {
      "path": "...",
      "rank": 1-5,
      "rationale": "...",
      "vuln_classes": ["..."],
      "chain_candidate": true/false,
      "chain_notes": "..."
    }
  ],
  "findings": [
    {
      "id": "GP-001",
      "title": "...",
      "severity": "critical|high|medium|low|informational",
      "cwe": "...",
      "file_path": "...",
      "line_number": null or integer,
      "description": "...",
      "code_snippet": "...",
      "attack_vector": "...",
      "impact": "...",
      "recommendation": "...",
      "confidence": "high|medium|low",
      "chain_with": []
    }
  ],
  "chain_findings": [
    {
      "id": "CHAIN-001",
      "title": "...",
      "severity": "critical|high|medium|low",
      "finding_ids": ["GP-001", "GP-003"],
      "attack_path": "...",
      "description": "...",
      "impact": "...",
      "recommendation": "..."
    }
  ],
  "validations": [
    {
      "finding_id": "GP-001 or CHAIN-001",
      "verdict": "confirmed|likely|possible|false_positive|needs_poc",
      "reasoning": "...",
      "adjusted_severity": null or "...",
      "poc_suggestion": "..."
    }
  ],
  "pocs": [
    {
      "finding_id": "GP-001",
      "poc_type": "curl|python_script|browser_payload|manual_steps",
      "code": "...",
      "setup_instructions": "...",
      "expected_result": "...",
      "verdict_update": "confirmed|false_positive|needs_poc",
      "notes": "..."
    }
  ],
  "total_files_discovered": 0,
  "total_files_ranked": 0,
  "total_files_analyzed": 0,
  "total_chains_identified": 0,
  "total_pocs_generated": 0,
  "scan_duration_seconds": 0,
  "api_calls": 0,
  "estimated_cost_usd": 0
}
```

### Step 4.5: Final Summary

Display the final report to the user:

```
## Scan Complete

- **Reports written to:** <OUTPUT_DIR>
- **Confirmed/Likely findings:** <count>
- **Exploit chains:** <count>
- **PoCs generated:** <count>
- **False positives filtered:** <count>
- **Files:** SUMMARY.md, scan_data.json, findings/<N> individual + chain reports
```

---

## Phase 5: POC — Proof-of-Concept Generation (Post-Report)

Check if any findings (GP-XXX or CHAIN-XXX) received a `needs_poc` verdict from Phase 3. If none did, skip this phase entirely — do not mention it.

If `GENERATE_POC` is `false`, also skip this phase.

**IMPORTANT: Ask the user for confirmation before running this phase.** The user has now seen the full report. Display the list of findings that need PoC and ask:

```
<N> findings were flagged as needing proof-of-concept verification:
- <finding_id>: <title> (<severity>)
- ...

Would you like to generate proof-of-concept exploits for these findings?
```

If the user declines, the scan is complete. No further action needed.

If the user confirms:

Announce: `## Phase 5: POC — Generating proof-of-concept exploits for <N> findings...`

### Step 5.1: Launch PoC Agent

Launch the **`glasspane-poc`** agent (defined in `.claude/agents/glasspane-poc.md`) with this user message:

```
Target repository: {target_path}

## Codebase Context

{codebase_context_json}

## Findings Requiring Proof-of-Concept

{needs_poc_findings_json}

(Only findings with needs_poc verdict, including their validation reasoning and poc_suggestion)
```

### Step 5.2: Process PoC Results and Update Reports

1. Extract the JSON array from the agent's response
2. For each PoC result:
   - If `verdict_update` is `confirmed` or `false_positive`, update the finding's validation verdict in `scan_data.json`
   - **Append** a `## Proof of Concept` section to the corresponding finding's report file at `<OUTPUT_DIR>/findings/<safe_id>.md`:
     ```markdown
     ## Proof of Concept

     **Type:** {poc_type}
     **Verdict Update:** {verdict_update}

     ```
     {poc code}
     ```

     **Setup:** {setup_instructions}
     **Expected Result:** {expected_result}
     **Notes:** {notes}
     ```
   - If `verdict_update` is `false_positive`, remove the finding report from `findings/` (it should no longer be in the report) and update SUMMARY.md accordingly
   - Add PoC data to `scan_data.json` under the `"pocs"` key
3. Display a summary:

```
### PoC Results
- PoCs generated: <count>
- Verdicts updated to confirmed: <count>
- Verdicts updated to false_positive: <count>
- Still needs_poc: <count>
- Reports updated in: <OUTPUT_DIR>/findings/
```

### Step 5.3: Handle PoC Failure

If the PoC agent fails or returns unparseable output:
- Log: "POC phase failed — reports remain unchanged"
- The scan is complete with all `needs_poc` verdicts as-is

---

## Error Handling

Follow these rules precisely:

1. **RECON agent fails or returns unparseable output**: Log warning, set `codebase_context_json` to a fallback string (see Step 0.5.3), and continue. All subsequent phases degrade gracefully.

2. **No files found after filtering**: Report "No source files found in target directory" and produce an empty SUMMARY.md with all zero counts. Do not proceed to ANALYZE.

3. **No files ranked >= 4**: Report "No high-risk files found — all files ranked below threshold." Skip ANALYZE, CHAIN, VALIDATE, and POC. Produce SUMMARY.md with zero findings. Still write scan_data.json with the rankings.

4. **An ANALYZE agent returns no findings or unparseable output**: Log a warning (e.g., "Agent 2 returned no findings") and continue with findings from other agents. Do not fail the entire scan.

5. **CHAIN agent fails or returns unparseable output**: Log warning ("Chain synthesis failed — continuing without chain findings") and continue with an empty chain findings list.

6. **VALIDATE agent misses a finding**: For any finding (GP-XXX or CHAIN-XXX) without a matching validation result, assign: `verdict: "likely"`, `reasoning: "Not reviewed by validator — defaulting to likely"`, `adjusted_severity: null`, `poc_suggestion: ""`.

7. **POC agent fails or returns unparseable output**: Log warning ("POC generation failed — reports remain unchanged"). The scan is already complete; no further action needed.

8. **All findings are false positives**: Produce SUMMARY.md and scan_data.json with zero confirmed findings. The findings/ directory will be empty. Report "All findings were classified as false positives."

---

## Critical Rules

- **Do NOT modify any files in the target repository.** This is a read-only scan. Only write to the OUTPUT_DIR.
- **Do NOT skip the VALIDATE phase** unless there are zero findings from ANALYZE.
- **Do NOT run Phase 5 (POC) without asking the user first.** After the full report is displayed, if any findings have `needs_poc` verdicts, ask the user whether they want PoCs generated. Only proceed if the user confirms.
- **Do NOT report findings that were classified as false_positive or possible** in the individual finding files or SUMMARY.md findings table. They appear ONLY in scan_data.json.
- **Follow the output templates EXACTLY.** The format matters for downstream tooling.
- **The RECON phase output (codebase context) must be included in EVERY subsequent agent prompt.** Agents do not share context — you must inject the full `codebase_context_json` into each agent's prompt.
- **Every Agent sub-call must be fully self-contained.** Include the complete system prompt, file list, vuln checklist, target path, codebase context, and output schema in every Agent call. Agents do not share your context.
- **Launch ANALYZE batch agents in parallel** (multiple Agent tool calls in a single message). Do NOT run them sequentially.
- **Deduplicate findings** using the key `(file_path, line_number, first 50 characters of title)`.
- **Renumber findings** sequentially as GP-001, GP-002, etc. after deduplication.
- **Chain findings use CHAIN-XXX IDs** (e.g., CHAIN-001) to distinguish from regular findings (GP-001). Do not mix ID schemes.
