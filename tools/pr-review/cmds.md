# PR Review Tool — Command Reference

A rule-based, deterministic PR review CLI for `connector-service`.
No AI/LLM — purely static analysis with 63 rules across 11 categories.

---

## Prerequisites

| Requirement | Why |
|---|---|
| **Python >= 3.10** | Uses `match`, `X \| Y` union types, `tomllib` |
| **click >= 8.0** | CLI framework |
| **rich >= 13.0** | Pretty terminal output (tables, colors, panels) |
| **gh CLI** (optional) | Only needed for `pr` subcommand (posting comments to GitHub PRs) |

---

## Setup

```bash
# From the repo root
cd tools/pr-review

# Option A: Install in editable mode (recommended for development)
pip install -e ".[dev]"

# Option B: Just set PYTHONPATH (no install needed)
export PYTHONPATH=tools/pr-review
```

After setup you can run the tool in two ways:
```bash
# If installed via pip
pr-review --help

# If using PYTHONPATH
python -m pr_review --help
```

---

## Three Subcommands

The tool has three subcommands: **`review`** (default), **`pr`**, and **`learn`**.

```
python -m pr_review <subcommand> [options]
```

If you omit the subcommand, `review` is assumed:
```bash
# These two are identical:
python -m pr_review --base main
python -m pr_review review --base main
```

---

## 1. `review` — Review Local Branch Changes

Diffs your current branch against a base branch (default: `main`), runs all 63 rules, and prints a scored report.

### Usage

```bash
python -m pr_review review [OPTIONS]
```

### All Options

| Option | Type | Default | Description |
|---|---|---|---|
| `--base` | string | `main` | Base branch to diff against. |
| `--format` | `terminal` / `markdown` / `json` | `terminal` | Output format. |
| `--fail-under` | integer | `60` (or from config) | Exit code 1 if quality score is below this. |
| `--min-severity` | `critical` / `warning` / `suggestion` | `suggestion` | Only show findings at or above this severity. |
| `--config` | file path | `tools/pr-review/pr-review.toml` | Path to TOML config file. |
| `--repo-root` | directory path | auto-detected via git | Path to repository root. |
| `--pr-title` | string | last commit message | PR title to check (for PQ-001 conventional commit rule). |
| `--diff-file` | file path | _(none)_ | Read diff from a file instead of running `git diff`. |
| `--no-learn` | flag | `false` | Skip loading `learned_data.json` (use hardcoded defaults). |

### Examples

```bash
# Basic: review current branch vs main, terminal output
python -m pr_review review --base main

# CI mode: markdown output, fail if score < 80
python -m pr_review review --base main --format markdown --fail-under 80

# JSON for automation
python -m pr_review review --format json

# Only show critical and warning issues (skip suggestions)
python -m pr_review review --min-severity warning

# Review a saved diff file
git diff main...HEAD > /tmp/my.diff
python -m pr_review review --diff-file /tmp/my.diff

# Diff against a different branch
python -m pr_review review --base develop

# Supply a custom PR title for convention checking
python -m pr_review review --pr-title "feat(stripe): add refund support"

# Skip self-learned data, use only hardcoded rules
python -m pr_review review --no-learn
```

### Output Formats Explained

**`--format terminal`** (default)
Rich-formatted output with colored tables, severity icons, score panel. Best for local development.

**`--format markdown`**
GitHub-flavored markdown. Designed to be pasted as a PR comment or piped into CI:
```bash
python -m pr_review review --format markdown > review-comment.md
```

**`--format json`**
Machine-readable JSON with all findings, scores, and metadata. Useful for integrations:
```bash
python -m pr_review review --format json | jq '.quality_score'
```

### Exit Codes

| Code | Meaning |
|---|---|
| `0` | Quality score >= `--fail-under` threshold |
| `1` | Quality score < threshold (review failed) |

---

## 2. `pr` — Review a GitHub PR and Post Comments

Fetches a PR's diff from GitHub, reviews it locally, shows findings in the terminal, then lets you interactively select which findings to post as **line-level review comments** on the PR.

### Prerequisites

```bash
# Install GitHub CLI
brew install gh          # macOS
# or: https://cli.github.com

# Authenticate
gh auth login
```

### Usage

```bash
python -m pr_review pr <URL> [OPTIONS]
```

### URL Formats Supported

```bash
# Full GitHub URL
python -m pr_review pr https://github.com/owner/repo/pull/123

# Without https://
python -m pr_review pr github.com/owner/repo/pull/123

# Shorthand
python -m pr_review pr owner/repo#123
```

### All Options

| Option | Type | Default | Description |
|---|---|---|---|
| `--no-learn` | flag | `false` | Skip loading learned data. |
| `--min-severity` | `critical` / `warning` / `suggestion` | `suggestion` | Minimum severity to show. |
| `--dry-run` | flag | `false` | Show findings locally but do NOT post anything to GitHub. |
| `--config` | file path | `tools/pr-review/pr-review.toml` | Path to TOML config file. |

### Examples

```bash
# Review a PR, see findings, then interactively choose what to post
python -m pr_review pr https://github.com/juspay/connector-service/pull/456

# Preview only — don't post anything
python -m pr_review pr owner/repo#456 --dry-run

# Only show critical issues
python -m pr_review pr owner/repo#456 --min-severity critical
```

### Interactive Flow

1. Tool fetches PR diff and metadata via `gh`
2. Runs all 63 rules against the diff
3. Displays the scored report in terminal
4. Shows a numbered list of **postable findings** (those that map to a specific line in the diff)
5. Prompts you to select which findings to post:

```
Select findings to post (numbers e.g. '1,3,5', range '1-3', 'all', or 'none'): 1,3,5-8
```

6. Posts a GitHub review with:
   - A **review body** (summary with score, counts)
   - **Line-level comments** on the selected findings
   - **PR-level findings** (those without a specific diff line) go into the review body

### Selection Syntax

| Input | Meaning |
|---|---|
| `1,3,5` | Post findings #1, #3, #5 |
| `1-5` | Post findings #1 through #5 |
| `1,3-5,8` | Combine individual and range |
| `all` | Post all postable findings |
| `none` | Cancel, post nothing |

---

## 3. `learn` — Scan Codebase and Update Rule Data

Scans the repository and writes `learned_data.json` — a snapshot of patterns, conventions, and config that the rules use at review time. This is the **self-upgrading system**: when the codebase changes (new connectors added, new enums, new sensitive fields), run `learn` to keep the rules up-to-date.

### Usage

```bash
python -m pr_review learn [OPTIONS]
```

### All Options

| Option | Type | Default | Description |
|---|---|---|---|
| `--repo-root` | directory path | auto-detected via git | Path to repository root. |
| `--output` | file path | `tools/pr-review/learned_data.json` | Where to save the learned data. |
| `--quiet` | flag | `false` | Only print the output path (no summary). |

### Examples

```bash
# Standard: scan repo and update learned_data.json
python -m pr_review learn

# Custom output path
python -m pr_review learn --output /tmp/learned.json

# Quiet mode (for scripts)
python -m pr_review learn --quiet
```

### What It Scans (10 Scanners)

| Scanner | What It Extracts | Consumed By |
|---|---|---|
| Clippy lints | Lint levels from `[workspace.lints.clippy]` | TS-001..009 |
| Rust lints | Lint levels from `[workspace.lints.rust]` | TS-001..009 |
| Flow structs | Flow types and trait mappings from `connector_flow.rs` | CP-008 |
| ConnectorCommon methods | Required methods (`id`, `base_url`, etc.) from `api.rs` | CP-003 |
| Known connectors | All connector names from the connectors directory | CP-007 |
| AttemptStatus variants | Enum variants from `common_enums` | DR-003 |
| Sensitive fields | Field names using `Secret<T>` across the codebase | SE-001 |
| Error response patterns | Connector error response struct patterns | CP-005 |
| Commit config | Conventional commit types from `cog.toml` / git history | PQ-001, PQ-003 |
| Proto conventions | Package name, go_package, service names, SecretString fields from `.proto` files | PT-001, PT-003, PT-004 |
| Composite service | Request types, AccessToken trait impls, process methods from `composite-service` | CS-002 |

### Sample Output

```
Scanning repository: /path/to/connector-service

Learned data summary:
  Clippy lints:         45
  Rust lints:           3
  Flow structs:         12
  Flow-trait mappings:  12
  ConnectorCommon methods: 6
  Known connectors:     76
  AttemptStatus variants: 31
  Sensitive field names: 408
  Error response structs: 127
  Commit types:         11
  Proto package:        types
  Proto services:       11
  Proto SecretString fields: 154
  Composite requests:   2
  Composite methods:    2

Saved to: tools/pr-review/learned_data.json
Generated at: 2026-03-15T10:30:00Z
```

---

## Makefile Targets

These are convenience shortcuts defined in the repo-root `Makefile`:

```bash
# Review current branch (terminal output, fail-under 60)
make pr-review

# Review current branch (markdown output for CI)
make pr-review-md

# Review current branch (JSON output for automation)
make pr-review-json

# Run the 400 unit tests
make pr-review-test
```

Under the hood these run:
```bash
PYTHONPATH=tools/pr-review python3 -m pr_review --base main --format terminal --fail-under 60
PYTHONPATH=tools/pr-review python3 -m pr_review --base main --format markdown
PYTHONPATH=tools/pr-review python3 -m pr_review --base main --format json
PYTHONPATH=tools/pr-review python3 -m pytest tools/pr-review/tests/ -v
```

---

## Configuration (TOML)

The tool loads config from `tools/pr-review/pr-review.toml` by default. Override with `--config`.

### Example Config

```toml
# Minimum quality score to pass (exit 0)
fail_under = 80

# Warn when PR touches more than this many files
max_file_count = 25

# File patterns to ignore (glob-style)
[ignore]
patterns = [
    "backend/connector-integration/src/connectors/*/test.rs",
    "sdk/**",
    "*.md",
]

# Override individual rules
[rules.TS-006]
severity = "suggestion"    # Downgrade from warning to suggestion

[rules.TS-009]
enabled = false            # Disable this rule entirely

[rules.SE-002]
severity = "critical"      # Upgrade to critical
```

### Config Fields

| Field | Type | Default | Description |
|---|---|---|---|
| `fail_under` | integer | `60` | Score threshold for pass/fail |
| `max_file_count` | integer | `25` | Files beyond this trigger PQ-002 |
| `ignore.patterns` | list of strings | `[]` | Glob patterns for files to skip |
| `rules.<ID>.severity` | `critical` / `warning` / `suggestion` | _(rule default)_ | Override a rule's severity |
| `rules.<ID>.enabled` | boolean | `true` | Disable a rule |

---

## Quality Scoring

```
Score = 100 - (Critical × 20) - (Warning × 5) - (Suggestion × 1)
```

| Score Range | Status | Exit Code (with default fail-under=60) |
|---|---|---|
| 95–100 | PASS (Excellent) | 0 |
| 80–94 | PASS (Good) | 0 |
| 60–79 | PASS WITH WARNINGS | 0 |
| 40–59 | BLOCKED (Poor) | 1 |
| 0–39 | BLOCKED (Critical) | 1 |

---

## All 63 Rules

### Type Safety (TS) — 9 rules

| ID | Name | Severity | What It Checks |
|---|---|---|---|
| TS-001 | No unwrap() calls | critical | `unwrap()` can panic at runtime |
| TS-002 | No expect() calls | warning | `expect()` can panic at runtime |
| TS-003 | No panic!() macro | critical | `panic!()` crashes the program |
| TS-004 | No todo!/unimplemented! | critical | Placeholder macros that panic |
| TS-005 | No unsafe blocks | critical | `unsafe` is forbidden in this workspace |
| TS-006 | No as type casts | suggestion | `as` casts can silently truncate data |
| TS-007 | No println!/eprintln!/dbg! | warning | Use structured tracing logger instead |
| TS-008 | No unreachable!() macro | warning | Panics at runtime |
| TS-009 | No direct [] indexing | suggestion | Can panic on out-of-bounds |

### Architecture (AR) — 6 rules

| ID | Name | Severity | What It Checks |
|---|---|---|---|
| AR-001 | Use ConnectorIntegrationV2 | critical | Legacy `ConnectorIntegration` must not be used |
| AR-002 | Use RouterDataV2 | critical | Legacy `RouterData` must not be used |
| AR-003 | Import from domain_types | critical | Not `hyperswitch_domain_models` |
| AR-004 | Import from common_enums | warning | Not `hyperswitch_enums` |
| AR-005 | Use ForeignTryFrom/ForeignFrom | suggestion | For cross-crate conversions |
| AR-006 | No direct reqwest usage | warning | Use external-services layer |

### Security (SE) — 6 rules

| ID | Name | Severity | What It Checks |
|---|---|---|---|
| SE-001 | Sensitive fields use Secret\<T\> | critical | API keys, tokens must be wrapped |
| SE-002 | No hardcoded URLs | warning | Base URLs should come from config |
| SE-003 | No hardcoded credentials | critical | Keys/tokens never in source |
| SE-004 | Auth headers use Maskable | warning | Prevent logging auth values |
| SE-005 | Use masked_serialize | suggestion | For logging sensitive data |
| SE-006 | No .expose() in logging | warning | Don't expose secrets in logs |

### Error Handling (EH) — 5 rules

| ID | Name | Severity | What It Checks |
|---|---|---|---|
| EH-001 | No hardcoded unwrap_or | warning | Hardcoded fallbacks mask errors |
| EH-002 | No unwrap_or_else hardcoded | warning | Same issue with closure variant |
| EH-003 | Use change_context | suggestion | For `error_stack` error conversion |
| EH-004 | Use attach_printable | suggestion | Descriptive error context |
| EH-005 | Use get_required_value | warning | Not get_optional for required fields |

### Connector Patterns (CP) — 9 rules

| ID | Name | Severity | What It Checks |
|---|---|---|---|
| CP-001 | Use create_all_prerequisites! | warning | Every connector must invoke this macro |
| CP-002 | Use macro_connector_implementation! | warning | Each flow needs this macro call |
| CP-003 | Implement ConnectorCommon | critical | Required trait with 5 methods |
| CP-004 | TryFrom in transformers | critical | Request/response type conversions |
| CP-005 | Define error response struct | warning | For connector error mapping |
| CP-006 | Two-file pattern | critical | connector.rs + transformers.rs |
| CP-007 | Register new connectors | warning | Add to connectors.rs and connector_types.rs |
| CP-008 | Flow marker traits | warning | e.g. `PaymentAuthorizeV2` |
| CP-009 | Typed error deserialization | warning | In build_error_response |

### Domain Rules (DR) — 5 rules

| ID | Name | Severity | What It Checks |
|---|---|---|---|
| DR-001 | Amounts use MinorUnit | warning | Not primitive numeric types |
| DR-002 | Use enums for limited values | suggestion | Not String for status fields |
| DR-003 | Default status is Pending | warning | Catch-all should be Pending |
| DR-004 | Store connector_transaction_id | warning | For reconciliation |
| DR-005 | Use get_currency_unit() | suggestion | For amount conversion |

### Testing (TE) — 4 rules

| ID | Name | Severity | What It Checks |
|---|---|---|---|
| TE-001 | New connectors have tests | warning | Test file in grpc-server/tests/ |
| TE-002 | Use grpc_test! macro | suggestion | Consistent test setup |
| TE-003 | Relax Clippy in tests | suggestion | Allow unwrap/expect in test files |
| TE-004 | No hardcoded test credentials | critical | Load from credential utility |

### PR Quality (PQ) — 4 rules

| ID | Name | Severity | What It Checks |
|---|---|---|---|
| PQ-001 | Conventional commit title | warning | `type(scope): description` format |
| PQ-002 | Reasonable PR scope | suggestion | Too many files = hard to review |
| PQ-003 | Descriptive branch name | suggestion | e.g. `feat/add-stripe-connector` |
| PQ-004 | No WIP markers | suggestion | Non-draft PRs shouldn't have WIP |

### gRPC Server (GR) — 6 rules

| ID | Name | Severity | What It Checks |
|---|---|---|---|
| GR-001 | Handlers use http_handler! macro | warning | Handler files must use `http_handler!`, not hand-rolled handlers |
| GR-002 | Service methods have tracing::instrument | warning | Every `async fn` in service trait impls needs `#[tracing::instrument]` |
| GR-003 | Service methods use grpc_logging_wrapper | warning | Method body must be wrapped in `grpc_logging_wrapper` for structured logging |
| GR-004 | Service methods call get_config_from_request | warning | Must extract config via `get_config_from_request(&request)?` |
| GR-005 | Routes use post() method | warning | All gRPC-bridged HTTP routes must use POST (except `/health`) |
| GR-006 | No tonic::Status::unknown() | suggestion | Use specific status codes like `internal`, `invalid_argument` |

### Proto (PT) — 5 rules

| ID | Name | Severity | What It Checks |
|---|---|---|---|
| PT-001 | Package is types | warning | Proto files must use `package types;` (auto-learned from repo) |
| PT-002 | Enum zero value is _UNSPECIFIED | warning | First enum variant must end with `_UNSPECIFIED = 0` |
| PT-003 | Sensitive fields use SecretString | warning | Fields like `email`, `api_key`, `password` must use `SecretString` |
| PT-004 | Has go_package option | suggestion | Proto files should declare `option go_package` |
| PT-005 | No large field number gaps | suggestion | New proto files shouldn't skip field numbers (gaps > 10) |

### Composite Service (CS) — 4 rules

| ID | Name | Severity | What It Checks |
|---|---|---|---|
| CS-001 | Use request.into_parts() | warning | Composite methods must decompose request via `into_parts()` |
| CS-002 | Implement CompositeAccessTokenRequest | warning | Request types must implement the access token trait |
| CS-003 | Propagate metadata in sub-service calls | warning | `tonic::Request::new()` must be followed by `metadata_mut()` propagation |
| CS-004 | Use ForeignFrom in transformers | suggestion | Use `ForeignFrom` trait, not raw `From` for cross-crate conversions |

---

## Common Workflows

### Before Opening a PR

```bash
# 1. Update learned data (if codebase changed significantly)
python -m pr_review learn

# 2. Review your branch
python -m pr_review review --base main

# 3. Fix issues, re-run until score >= 80
python -m pr_review review --base main --fail-under 80
```

### In CI Pipeline

```bash
# Generate markdown report and fail if score < 80
PYTHONPATH=tools/pr-review python3 -m pr_review \
  --base main \
  --format markdown \
  --fail-under 80 \
  > review.md

# Post review.md as a PR comment (using gh)
gh pr comment $PR_NUMBER --body-file review.md
```

### Reviewing a Teammate's PR

```bash
# Review and post selected findings as line comments
python -m pr_review pr https://github.com/juspay/connector-service/pull/456

# Or preview without posting
python -m pr_review pr owner/repo#456 --dry-run
```

### Running Tests

```bash
# Via Makefile
make pr-review-test

# Directly
PYTHONPATH=tools/pr-review python3 -m pytest tools/pr-review/tests/ -v
```

---

## Project Structure

```
tools/pr-review/
├── pyproject.toml              # Package config, deps, entry point
├── pr-review.toml              # Default TOML configuration
├── learned_data.json           # Auto-generated by `learn` command
├── bulk_test.py                # Bulk test script for all merged PRs
├── pr_review/
│   ├── __init__.py             # Package init
│   ├── __main__.py             # python -m pr_review entry point
│   ├── cli.py                  # Click CLI (3 subcommands)
│   ├── analyzer.py             # Orchestrator, scoring, AnalysisResult
│   ├── reporter.py             # Terminal / Markdown / JSON formatters
│   ├── config.py               # TOML config loading
│   ├── diff_parser.py          # Git diff → ChangedFile objects
│   ├── file_classifier.py      # 23 FileType categories
│   ├── learner.py              # 10 scanners for self-upgrading
│   ├── github.py               # GitHub interaction via gh CLI
│   ├── utils.py                # Comment detection, string helpers
│   └── rules/
│       ├── __init__.py         # get_all_rules() aggregator (11 modules)
│       ├── base.py             # Rule, Finding, Severity, Category
│       ├── type_safety.py      # TS-001 to TS-009
│       ├── architecture.py     # AR-001 to AR-006
│       ├── security.py         # SE-001 to SE-006
│       ├── error_handling.py   # EH-001 to EH-005
│       ├── connector_patterns.py # CP-001 to CP-009
│       ├── domain_rules.py     # DR-001 to DR-005
│       ├── testing.py          # TE-001 to TE-004
│       ├── pr_quality.py       # PQ-001 to PQ-004
│       ├── grpc_server.py      # GR-001 to GR-006
│       ├── proto.py            # PT-001 to PT-005
│       └── composite.py        # CS-001 to CS-004
└── tests/                      # 400 unit tests
    ├── test_diff_parser.py
    ├── test_file_classifier.py
    ├── test_utils.py
    ├── test_rules_type_safety.py
    ├── test_rules_other.py
    ├── test_connector_and_pr_rules.py
    ├── test_analyzer_reporter_config.py
    ├── test_learner.py
    ├── test_github.py
    └── test_new_rules.py       # gRPC, Proto, Composite rule tests
```
