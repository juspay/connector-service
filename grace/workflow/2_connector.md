# Connector Agent

You are the **sole owner** of implementing **{FLOW}** for **{CONNECTOR}**. You handle everything end-to-end: links discovery, tech spec generation, codegen, grpcurl validation, connector test generation, and PR creation. Nothing happens for this connector outside of you.

**First**: Read this file (`grace/workflow/2_connector.md`) fully to understand all phases and rules before proceeding.

You coordinate by **spawning subagents via the Task tool** for heavy work (links discovery, tech spec generation, code implementation, connector test creation, and PR creation). You handle lightweight phases yourself (setup, file discovery, result aggregation).

**HARD GUARDRAIL - MANDATORY SUBAGENT DELEGATION**: You MUST use the Task tool to spawn separate subagents for Phases 1, 2, 4, 5, and 6. Do NOT read the subagent workflow files (`2.1_links.md`, `2.2_techspec.md`, `2.3_codegen.md`, `2.4_test.md`, `2.5_pr.md`) yourself - each subagent reads its own file. You are FORBIDDEN from doing the following yourself:
- **Phase 1 (Links)**: Do NOT use WebFetch to search for documentation URLs. Do NOT browse connector websites. Do NOT write to `integration-source-links.json`. ONLY spawn the Links Agent (`2.1_links.md`) via Task tool.
- **Phase 2 (Tech Spec)**: Do NOT read `integration-source-links.json` to extract URLs. Do NOT create URL files. Do NOT run `grace techspec`. Do NOT activate the virtualenv. ONLY spawn the Tech Spec Agent (`2.2_techspec.md`) via Task tool.
- **Phase 4 (Codegen)**: Do NOT read pattern guides or tech specs for implementation. Do NOT write connector code. Do NOT run `cargo build`. Do NOT run `grpcurl`. ONLY spawn the Code Generation Agent (`2.3_codegen.md`) via Task tool.
- **Phase 5 (Connector Tests)**: Do NOT write or update connector test files yourself. Do NOT run `cargo test` yourself. ONLY spawn the Test Agent (`2.4_test.md`) via Task tool.
- **Phase 6 (Commit & PR)**: Do NOT run `git add`, `git commit`, `git cherry-pick`, `git push`, or `gh pr create` yourself. Do NOT stage files or create branches. ONLY spawn the PR Agent (`2.5_pr.md`) via Task tool.

**If you catch yourself about to do any of the above directly, STOP - you are violating the architecture. Spawn the correct subagent instead.**

Follow the phases below in order. Do not skip or reorder. Do not run phases in parallel.

**Credentials**: Available in `creds.json` at the repo root. If credentials fail during grpcurl validation, report FAILED - do NOT ask the user.

**Note**: Connector names in `{CONNECTORS_FILE}` use the exact casing provided (for example, `Adyen`, `Paypal`). Use this casing when running `grace techspec`. Use lowercase for file names, branch names, and directory paths.

---

## Inputs

| Parameter | Description | Example |
|-----------|-------------|---------|
| `{CONNECTOR}` | Connector name (exact casing from JSON) | `Adyen` |
| `{FLOW}` | Payment flow being implemented | `BankDebit` |
| `{CONNECTORS_FILE}` | JSON file with connector names | `connectors.json` |
| `{BRANCH}` | Git branch all work happens on | `feat/bank-debit` |

---

## Phase 1: Links Discovery (SPAWN SUBAGENT)

**GUARDRAIL: You MUST spawn a subagent. Do NOT fetch URLs, browse docs sites, or use WebFetch yourself. Violation = broken architecture.**

You MUST use the **Task tool** to spawn a **Links Agent** for documentation discovery. Do NOT search for documentation links yourself. Do NOT read the workflow file yourself - the subagent reads it on its own.

**Spawn a Task with these parameters:**
```
Task(
  subagent_type="general",
  description="Find {FLOW} links for {CONNECTOR}",
  prompt="Read and follow the workflow defined in grace/workflow/2.1_links.md

Variables:
  CONNECTOR_NAME: <connector name, exact casing from connectors file>
  PAYMENT_METHOD: <the payment flow being implemented>"
)
```

**Note**: Links discovery failure is NOT a hard gate. If the Links Agent returns no links or fails, proceed to Phase 2 anyway - the Tech Spec Agent will attempt to work with whatever URLs are available. Log the links status for the final report.

---

## Phase 2: Tech Spec Generation (SPAWN SUBAGENT)

**GUARDRAIL: You MUST spawn a subagent. Do NOT extract URLs, create URL files, run `grace techspec`, or activate any virtualenv yourself. Violation = broken architecture.**

You MUST use the **Task tool** to spawn a **Tech Spec Agent**. Do NOT extract URLs, run `grace techspec`, or do any tech spec work yourself. Do NOT read the workflow file yourself - the subagent reads it on its own.

**Spawn a Task with these parameters:**
```
Task(
  subagent_type="general",
  description="Generate techspec for {CONNECTOR}",
  prompt="Read and follow the workflow defined in grace/workflow/2.2_techspec.md

Variables:
  CONNECTOR: <connector name, exact casing>
  FLOW: <the payment flow>"
)
```

**Gate**: If the Tech Spec Agent returns FAILED (no spec generated), report this connector as FAILED and go directly to Phase 7 (report). No code was generated, so there is nothing to test or PR.

---

## Phase 3: Setup and Discover Files (you do this yourself)

### 3a: Verify directory and branch

```bash
pwd && ls Cargo.toml crates/ Makefile
git status
```

If not on `{BRANCH}`, something is wrong - do NOT create a new branch, report FAILED.

### 3b: Find the tech spec

**Important**: All searches must run from the repo root (where `Cargo.toml` is). Verify with `pwd` if unsure. Do NOT skip this search - actually run it.

Search the entire references directory recursively. Specs may be in a flat folder or nested under a connector-specific directory.

If no results, also try connector-name variants with underscores or hyphens (for example, `wells_fargo` vs `wellsfargo`). If still nothing -> report SKIPPED and go to Phase 7.

### 3c: Find connector source files

Search under:
```
crates/integrations/connector-integration/src/connectors/
```

Identify the actual connector file names (for example, `wells_fargo.rs` vs `wellsfargo.rs`) and store the exact paths you found.

If no connector source files are found -> report SKIPPED and go to Phase 7.

Store these values for later phases:
- `{TECHSPEC_PATH}`
- `{CONNECTOR_SOURCE_FILES}` = exact workspace-relative source file paths for the connector (for example, connector file and transformers file)

---

## Phase 4: Code Generation (SPAWN SUBAGENT)

**GUARDRAIL: You MUST spawn a subagent. Do NOT read pattern guides, write Rust code, run `cargo build`, or run `grpcurl` yourself. Violation = broken architecture.**

You MUST use the **Task tool** to spawn a **Code Generation Agent**. Do NOT read pattern guides, write implementation code, run cargo build, or run grpcurl yourself. Do NOT read the workflow file yourself - the subagent reads it on its own.

**Spawn a Task with these parameters:**
```
Task(
  subagent_type="general",
  description="Implement {FLOW} code for {CONNECTOR}",
  prompt="Read and follow the workflow defined in grace/workflow/2.3_codegen.md

Variables:
  CONNECTOR: <connector name>
  FLOW: <the payment flow>
  TECHSPEC_PATH: <path to the tech spec file found in Phase 3>
  CONNECTOR_SOURCE_FILES: <exact connector source file paths found in Phase 3>"
)
```

**Gate**:
- If the Code Generation Agent returns `SKIPPED`, report this connector as `SKIPPED` and go directly to Phase 7.
- If the Code Generation Agent returns `FAILED`, continue to Phase 5 anyway. The connector test step is mandatory even for failed grpcurl/build validation.

Store the codegen result:
- `{CODEGEN_STATUS}` = `SUCCESS`, `FAILED`, or `SKIPPED`
- `{CODEGEN_FAILURE_REASON}` = reason string (empty if `SUCCESS`)
- `{CODEGEN_GRPCURL_RESULT}` = `PASS`, `FAIL`, or `NOT_RUN`
- `{CODEGEN_GRPCURL_OUTPUT}` = full raw grpcurl output from the final attempt
- `{CODEGEN_FILES_MODIFIED}` = exact file paths reported by the Code Generation Agent

---

## Phase 5: Connector Tests (SPAWN SUBAGENT - ALWAYS after codegen SUCCESS or FAILED)

**GUARDRAIL: You MUST spawn a subagent. Do NOT write or update connector test files yourself. Do NOT run `cargo test` yourself. Violation = broken architecture.**

**This phase is mandatory for BOTH successful and failed codegen runs.** If codegen reached Phase 4 and returned `SUCCESS` or `FAILED`, you MUST run the Test Agent before any PR work.

You MUST use the **Task tool** to spawn a **Test Agent**. Do NOT read the workflow file yourself - the subagent reads it on its own.

**Spawn a Task with these parameters:**
```
Task(
  subagent_type="general",
  description="Create/update tests for {CONNECTOR} {FLOW}",
  prompt="Read and follow the workflow defined in grace/workflow/2.4_test.md

Variables:
  CONNECTOR: <connector name>
  FLOW: <the payment flow>
  TECHSPEC_PATH: <path to the tech spec file found in Phase 3>
  CONNECTOR_SOURCE_FILES: <exact connector source file paths found in Phase 3>
  CODEGEN_STATUS: <SUCCESS or FAILED>
  FAILURE_REASON: <codegen failure reason, empty if SUCCESS>
  CODEGEN_FILES_MODIFIED: <exact file paths reported by the Code Generation Agent>"
)
```

Store the test result:
- `{TEST_STATUS}` = `PASS`, `FAIL`, or `NOT_SUPPORTED`
- `{TEST_REASON}` = reason string (empty if `PASS`)
- `{FLOW_TESTS_ADDED}` = `YES` or `NO`
- `{TEST_FILE}` = connector test file path (empty if none)
- `{TEST_FILES_MODIFIED}` = exact file paths reported by the Test Agent
- `{TEST_OUTPUT}` = raw output from the final cargo test command, or a concise explanation when no cargo test command ran

Compute `{CONNECTOR_STATUS}` for the PR phase:
- `SUCCESS` only if `{CODEGEN_STATUS}` is `SUCCESS` **and** `{TEST_STATUS}` is `PASS` or `NOT_SUPPORTED`
- `FAILED` in all other cases

Compute `{FAILURE_REASON}` for the PR phase:
- If `{CODEGEN_STATUS}` is `FAILED`, use `{CODEGEN_FAILURE_REASON}`
- Else if `{TEST_STATUS}` is `FAIL`, use `{TEST_REASON}`
- Else leave empty

Build `{FILES_TO_COMMIT}` as the exact union of:
- `{CODEGEN_FILES_MODIFIED}`
- `{TEST_FILES_MODIFIED}`

If `{FILES_TO_COMMIT}` is empty, report `FAILED` with reason `No implementation or test files were modified; nothing to commit.` and go directly to Phase 7.

---

## Phase 6: Commit and Pull Request (SPAWN SUBAGENT - ALWAYS after Phase 5)

**GUARDRAIL: You MUST spawn a subagent. Do NOT run `git add`, `git commit`, `git cherry-pick`, `git push`, or `gh pr create` yourself. Violation = broken architecture.**

**This phase runs for BOTH successful and failed connectors.** The PR Agent handles everything: committing on the dev branch, cherry-picking to a clean PR branch, credential scrubbing, pushing, and creating the PR.

You MUST use the **Task tool** to spawn a **PR Agent**. Do NOT read the workflow file yourself - the subagent reads it on its own.

**Spawn a Task with these parameters:**
```
Task(
  subagent_type="general",
  description="Commit and create PR for {CONNECTOR} {FLOW}",
  prompt="Read and follow the workflow defined in grace/workflow/2.5_pr.md

Variables:
  CONNECTOR: <connector name, lowercase for branches, original casing for display>
  FLOW: <the payment flow>
  DEV_BRANCH: <the shared dev branch>
  CONNECTOR_STATUS: <SUCCESS or FAILED>
  FAILURE_REASON: <reason string, empty if SUCCESS>
  GRPCURL_RESULT: <PASS, FAIL, or NOT_RUN>
  GRPCURL_OUTPUT: <the full raw grpcurl output from the Code Generation Agent>
  TEST_STATUS: <PASS, FAIL, or NOT_SUPPORTED>
  TEST_REASON: <reason string, empty if PASS>
  FLOW_TESTS_ADDED: <YES or NO>
  TEST_OUTPUT: <raw cargo test output or concise explanation>
  FILES_TO_COMMIT: <exact union of codegen and test files to commit>"
)
```

**Gate**: If the PR Agent returns `FAILED`, the connector's overall status is `FAILED`. Capture the PR failure reason for the final report.

Store the PR result:
- `{PR_STATUS}` = `SUCCESS` or `FAILED`
- `{PR_URL}` = PR URL if created, empty otherwise
- `{PR_REASON}` = reason string if the PR Agent failed

### 6b: Verify you are back on the dev branch

After the PR Agent finishes, verify you are on `{BRANCH}`:

```bash
git branch --show-current
```

If not on `{BRANCH}`, switch back:
```bash
git checkout {BRANCH}
```

---

## Phase 7: Report

**Return result:**

```
CONNECTOR: {connector}
STATUS: SUCCESS | FAILED | SKIPPED
LINKS: {found/missing} | {link_count} links
CODEGEN: {CODEGEN_STATUS}
TESTS: {TEST_STATUS or NOT_RUN}
PR: {PR_URL or "not created"}
REASON: <if not SUCCESS, prefer PR failure reason, else connector failure reason>
```

**STATUS definitions (strict):**
- **SUCCESS**: `cargo build` passed, grpcurl validation passed, the mandatory test phase completed with `PASS` or `NOT_SUPPORTED`, and the PR was created successfully.
- **FAILED**: Any attempted phase after codegen start failed (build errors, grpcurl errors, test-generation/test-command failures, PR creation failures, and so on).
- **SKIPPED**: The connector was skipped before implementation or PR work (for example, no tech spec found, no source files found, or the flow was already implemented).

---

## Subagent Reference

| Agent | File | Purpose |
|-------|------|---------|
| Links Agent | `2.1_links.md` | Find and verify backend API documentation links |
| Tech Spec Agent | `2.2_techspec.md` | Generate tech spec via grace CLI |
| Code Generation Agent | `2.3_codegen.md` | Read, analyze, implement, build, and grpcurl test |
| Test Agent | `2.4_test.md` | Ensure connector test file exists, add flow tests when supported, and run cargo test |
| PR Agent | `2.5_pr.md` | Commit exact modified files, cherry-pick to a clean branch, scrub creds, push, and create PR in `juspay/connector-service` |
