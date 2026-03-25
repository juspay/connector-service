# Connector Agent

You are the **sole owner** of implementing **all payment flows** for **{CONNECTOR}**. You handle everything end-to-end: flow planning, sequential flow implementation, and committing/PR creation. Nothing happens for this connector outside of you.

**First**: Read this file (`grace/workflow/v2/2_connector.md`) fully to understand all phases and rules before proceeding.

You coordinate by **spawning subagents via the Task tool** for all heavy work. You handle lightweight phases yourself (setup, file discovery, ID accumulation, dependency enforcement).

**HARD GUARDRAIL — MANDATORY SUBAGENT DELEGATION**: You MUST use the Task tool to spawn separate subagents for Phases 2, 3, and 4. Do NOT read the subagent workflow files (`2.1_flow_decider.md`, `2.2_flow.md`, `2.2.1_testing.md`, `2.3_pr.md`) yourself — each subagent reads its own file.

**HARD GUARDRAIL — SEQUENTIAL FLOW IMPLEMENTATION**: You MUST spawn Flow Agents ONE AT A TIME. One Task call per message. Wait for the result. ONLY THEN spawn the next. NEVER send a single message with multiple Task calls for different flows. This is a hard architectural constraint — parallel execution will cause build conflicts and test interference.

---

## Inputs

| Parameter | Description | Example |
|-----------|-------------|---------|
| `{CONNECTOR}` | Connector name (exact casing from JSON) | `Adyen` |
| `{CONNECTORS_FILE}` | JSON file with connector names | `connectors.json` |
| `{BRANCH}` | Git branch all work happens on | `feat/all-flows` |

---

## RULES (read once, apply everywhere)

1. **Working directory**: ALL commands use the `connector-service` repo root. Never `cd`.
2. **STRICTLY SEQUENTIAL FLOWS**: Process ONE flow at a time. One Task call per message. Wait for result. Only then spawn the next.
3. **No `cargo test`**: Testing is done via grpcurl through the Testing Agent (inside the Flow Agent). Never run `cargo test`.
4. **MANDATORY: Do NOT move to the next flow until the current flow's Testing Agent completes.** The grpcurl test must either PASS or be reported as FAILED.
5. **Scoped git**: Only stage connector-specific files. Never `git add -A`. Never force push.
6. **Credentials**: Read from `creds.json` at the repo root. If connector is missing, report SKIPPED.
7. **Only do what's listed**: Do not invent steps. Do not add features. Do not write tests.
8. **FULLY AUTONOMOUS**: Never stop, ask questions, or present options. Make decisions using these rules.
9. **HARD GUARDRAIL — CONNECTOR AGENT DOES NOT DO SUBAGENT WORK**:
   - Do NOT read or write connector code yourself
   - Do NOT run `cargo build` or `grpcurl` yourself
   - Do NOT read `2.1_flow_decider.md`, `2.2_flow.md`, `2.2.1_testing.md`, or `2.3_pr.md` to execute them yourself
   - Your ONLY subagents are: Flow Decider, Flow Agent, and PR Agent

---

## Phase 1: Setup & Discover Files (you do this yourself)

### 1a: Verify directory and branch

```bash
pwd && ls Cargo.toml crates/ Makefile     # verify directory
git branch --show-current                  # verify on {BRANCH}
```

If not on `{BRANCH}`, something is wrong — report FAILED.

### 1b: Find the techspec

```bash
ls techspec/{connector}.md
```

Where `{connector}` is the lowercase version of `{CONNECTOR}`. If not found, also try variations:
```bash
ls techspec/ | grep -i {connector}
```

If no techspec found → report FAILED with reason "No techspec found at techspec/{connector}.md".

Store `{TECHSPEC_PATH}` (e.g., `techspec/adyen.md`).

### 1c: Find connector source files

```bash
find crates/integrations/connector-integration/src/connectors/ -iname "*{connector}*" | head -20
```

Note the actual directory/file name (e.g., `adyen.rs` and `adyen/transformers.rs`). If not found → report FAILED with reason "No connector source files found".

Store `{CONNECTOR_SOURCE_FILES}`.

---

## Phase 2: Flow Planning (SPAWN SUBAGENT)

**GUARDRAIL: You MUST spawn a subagent. Do NOT analyze the techspec yourself.**

Spawn a **Flow Decider Agent** via the Task tool:

```
Task(
  subagent_type="general",
  description="Determine flow plan for {CONNECTOR}",
  prompt="Read and follow the workflow defined in grace/workflow/v2/2.1_flow_decider.md

Variables:
  CONNECTOR: <connector name, exact casing>
  TECHSPEC_PATH: <path to techspec>
  CONNECTOR_SOURCE_FILES: <paths to connector .rs files>"
)
```

**Gate**: If the Flow Decider returns FAILED (no implementable flows), report this connector as FAILED and go directly to Phase 5.

Parse the returned flow plan to extract:
- `ORDERED_FLOWS` — the ordered list of flow names with status PLAN
- For each flow: its `TECHSPEC_SECTION`, `GRPCURL_SERVICE`, and `PATTERN_GUIDE`

---

## Phase 3: Flow Implementation (SPAWN SUBAGENTS — SEQUENTIAL, ONE AT A TIME)

**HARD GUARDRAIL — ONE TASK CALL PER MESSAGE**: Spawn exactly ONE Flow Agent per message. Wait for the result. Only after receiving the result, spawn the next flow in a NEW message.

Initialize tracking state:
```
ACCUMULATED_IDS = {}           # grows as flows complete
PREVIOUS_FLOW_GRPCURL = ""     # raw grpcurl+output from the last completed flow
FLOW_RESULTS = []              # array of per-flow results
```

For each flow in `ORDERED_FLOWS`, in order:

### 3a: Check dependency gates

Before spawning the Flow Agent, check if this flow's dependencies are met:

| Flow | Dependency | Gate |
|------|-----------|------|
| Authorize | None | Always proceed |
| PSync | Authorize must have succeeded | If Authorize FAILED → SKIP PSync |
| Capture | Authorize must exist (EXISTING or SUCCESS) | If Authorize FAILED → SKIP Capture |
| Refund | Authorize must have succeeded (need `connector_transaction_id`) | If Authorize FAILED → SKIP Refund |
| RSync | Refund must have succeeded (need `connector_refund_id`) | If Refund FAILED/SKIPPED → SKIP RSync |
| Void | Authorize must exist (EXISTING or SUCCESS) | If Authorize FAILED → SKIP Void |

If a dependency is not met, mark the flow as SKIPPED with reason "Prerequisite {dependency} not met" and continue to the next flow.

### 3b: Spawn Flow Agent

```
Task(
  subagent_type="general",
  description="Implement {FLOW_NAME} for {CONNECTOR}",
  prompt="Read and follow the workflow defined in grace/workflow/v2/2.2_flow.md

Variables:
  CONNECTOR: <connector name, lowercase>
  FLOW_NAME: <flow name from the ordered list>
  TECHSPEC_PATH: <path to techspec>
  TECHSPEC_SECTION: <section identifier from flow plan>
  CONNECTOR_SOURCE_FILES: <paths to connector .rs files>
  PREVIOUS_FLOW_GRPCURL: <raw grpcurl+output from the previous flow, or empty for first flow>
  ACCUMULATED_IDS: <JSON with all extracted IDs so far>"
)
```

### 3c: Collect result and update state

After the Flow Agent returns:

1. **Record the flow result** in `FLOW_RESULTS`:
   ```
   {
     flow_name: <name>,
     status: SUCCESS | FAILED | SKIPPED,
     grpcurl_command: <raw command>,
     grpcurl_output: <raw output>,
     extracted_ids: {connector_transaction_id: ..., connector_refund_id: ...},
     files_modified: [...],
     reason: <if failed>
   }
   ```

2. **Merge extracted IDs** into `ACCUMULATED_IDS`:
   - If the flow returned `connector_transaction_id`, add/update it in `ACCUMULATED_IDS`
   - If the flow returned `connector_refund_id`, add/update it in `ACCUMULATED_IDS`

3. **Update `PREVIOUS_FLOW_GRPCURL`** with this flow's raw grpcurl command + output (for the next flow to use as reference)

4. **Apply dependency enforcement** for subsequent flows (see gate table in 3a)

**WAIT** for this result before spawning the next flow. The next flow MUST be in a SEPARATE, SUBSEQUENT message.

---

## Phase 4: Commit & PR (SPAWN SUBAGENT)

**GUARDRAIL: You MUST spawn a subagent. Do NOT run git commands yourself.**

First, check if there are any file changes to commit:
```bash
git status -- crates/integrations/connector-integration/src/connectors/{connector}*
```

If no changes (all flows were SKIPPED or EXISTING), skip to Phase 5.

Determine overall connector status:
- **SUCCESS**: ALL planned flows have status SUCCESS
- **PARTIAL**: At least one flow succeeded but others failed/skipped
- **FAILED**: No flows succeeded (all FAILED or SKIPPED after Authorize failure)

Collect test report paths:
```bash
ls grace/workflow/v2/test_reports/{connector}/*.md 2>/dev/null
```

Spawn the **PR Agent**:

```
Task(
  subagent_type="general",
  description="Commit and create PR for {CONNECTOR}",
  prompt="Read and follow the workflow defined in grace/workflow/v2/2.3_pr.md

Variables:
  CONNECTOR: <connector name, lowercase for branches, original casing for display>
  DEV_BRANCH: <the shared dev branch>
  CONNECTOR_STATUS: <SUCCESS | PARTIAL | FAILED>
  FLOW_RESULTS: <JSON array of all per-flow results from Phase 3>
  CONNECTOR_SOURCE_FILES: <paths to modified files>
  TEST_REPORT_PATHS: <paths to test report MDs>"
)
```

After the PR Agent finishes, verify you are on `{BRANCH}`:
```bash
git branch --show-current
```

If not on `{BRANCH}`:
```bash
git checkout {BRANCH}
```

---

## Phase 5: Report

Return the final result:

```
CONNECTOR: {CONNECTOR}
STATUS: SUCCESS | PARTIAL | FAILED | SKIPPED
FLOWS:
  - Authorize: SUCCESS | FAILED | SKIPPED | EXISTING
  - PSync: SUCCESS | FAILED | SKIPPED | EXISTING
  - Capture: SUCCESS | FAILED | SKIPPED | EXISTING
  - Refund: SUCCESS | FAILED | SKIPPED | EXISTING
  - RSync: SUCCESS | FAILED | SKIPPED | EXISTING
  - Void: SUCCESS | FAILED | SKIPPED | EXISTING
FLOWS_SUCCEEDED: <count>
FLOWS_FAILED: <count>
FLOWS_SKIPPED: <count>
PR: <PR_URL or "not created">
REASON: <if not SUCCESS, primary reason>
```

**STATUS definitions:**
- **SUCCESS**: ALL planned flows passed (build + grpcurl) AND PR created. No exceptions.
- **PARTIAL**: At least one planned flow succeeded, but others failed or were skipped.
- **FAILED**: No planned flows succeeded, OR Authorize failed (which cascades to all).
- **SKIPPED**: Connector was skipped before any implementation (no techspec, no source files, no credentials).

---

## Subagent Reference

| Agent | File | Purpose |
|-------|------|---------|
| Flow Decider Agent | `2.1_flow_decider.md` | Analyze techspec, determine flows to implement and their order |
| Flow Agent | `2.2_flow.md` | Implement, build, and test ONE flow (spawns Testing Agent internally) |
| PR Agent | `2.3_pr.md` | Commit, cherry-pick, push, and create cross-fork PR |
