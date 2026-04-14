# Glasspane

AI-powered security scanning scaffold. Glasspane drives Claude through a
four-phase pipeline — **rank → analyze → validate → report** — to surface
vulnerabilities in a target codebase. Profiles describe *what* to look for;
the scaffold handles orchestration, sandboxing, parallelism, and reporting.

## Features

- **Profile-driven** — YAML profiles define file patterns, vulnerability
  classes, and prompts. A built-in `generic` profile ships out of the box;
  drop your own into `~/.glasspane/profiles/`.
- **Four-phase pipeline** — rank files by risk, deep-analyze the top hits in
  parallel, validate findings with a stronger model, then render a report.
- **Sandboxed** — the target repo is mounted read-only and the analysis
  process runs without network access.
- **Model-flexible** — pick a different Anthropic model per phase (fast and
  cheap for ranking, stronger for validation).
- **Rich CLI** — auto-detect profiles, configurable parallelism, per-phase
  model overrides.

## Install

Requires Python 3.12+.

```bash
git clone https://github.com/yourname/glasspane.git
cd glasspane
pip install -e .
```

## Quick start

```bash
# One-time setup
glasspane init
export ANTHROPIC_API_KEY=sk-ant-...

# Scan a repo
glasspane scan /path/to/repo

# Pick a profile, tune parallelism and model choice
glasspane scan /path/to/repo \
    --profile drupal \
    --parallel 5 \
    --analyze-model claude-sonnet-4-6 \
    --validate-model claude-opus-4-6
```

## Commands

| Command | Description |
| --- | --- |
| `glasspane scan <path>` | Run the full pipeline against a repo |
| `glasspane init` | Write a default config to `~/.glasspane/config.yml` |
| `glasspane profiles` | List available scan profiles |
| `glasspane version` | Print the installed version |

## Configuration

Defaults live in `~/.glasspane/config.yml` (created by `glasspane init`).
Every value can be overridden at the CLI. Key options:

- `default_profile` — `auto` (detect from repo contents) or a profile name
- `rank_model` / `analyze_model` / `validate_model` — per-phase model IDs
- `parallel` — number of concurrent analyze workers
- `min_rank` — minimum rank (1–5) a file must score to be deep-analyzed
- `max_files` — hard cap on files sent to the analyze phase
- `api_key_env` — environment variable Glasspane reads for the API key

## Writing profiles

Profiles are YAML files in `~/.glasspane/profiles/`. Each one declares the
language, file globs, vulnerability classes, and phase-specific prompt
fragments. Run `glasspane profiles` to see where Glasspane is looking and
which profiles it found. The built-in `generic` profile is a good starting
template.

## How it works

1. **Rank** — Glasspane enumerates files matching the profile's globs and
   asks the rank model to score each from 1 (low risk) to 5 (high risk).
2. **Analyze** — files scoring at or above `min_rank` are deep-scanned in
   parallel. Each worker reads the file inside the sandbox and produces
   structured findings.
3. **Validate** — a stronger model re-examines each finding and labels it
   `confirmed`, `likely`, `unlikely`, or `false_positive`.
4. **Report** — results render to the output directory as JSON plus a
   human-readable summary.

## Security

Glasspane is a static-analysis aid, not a guarantee. Always review findings
manually before acting on them, and never run it against code you don't have
permission to audit. Report security issues in Glasspane itself by opening a
private advisory on the repo.

## Contributing

Issues and pull requests are welcome. For larger changes, please open an
issue first to discuss the direction.

## License

[MIT](LICENSE)
