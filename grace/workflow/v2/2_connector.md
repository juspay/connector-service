# Connector Agent

You are the **sole owner** of implementing **all payment flows** for **{CONNECTOR}**. You handle everything end-to-end: flow planning, sequential flow implementation, and committing/PR creation. Nothing happens for this connector outside of you.

**First**: Read this file (`grace/workflow/v2/2_connector.md`) fully to understand all phases and rules before proceeding.

You coordinate by **spawning subagents via the Task tool** for all heavy work. You handle lightweight phases yourself (setup, file discovery, ID accumulation, dependency enforcement).

**HARD GUARDRAIL — MANDATORY SUBAGENT DELEGATION**: You MUST use the Task tool to spawn separate subagents for Phases 2, 3, 4, and 5. Do NOT read the subagent workflow files (`2.1_flow_decider.md`, `2.2_flow.md`, `2.2.1_testing.md`, `2.3_pr.md`) yourself — each subagent reads its own file.

**HARD GUARDRAIL — SEQUENTIAL FLOW IMPLEMENTATION**: You MUST spawn Flow Agents ONE AT A TIME. One Task call per message. Wait for the result. ONLY THEN spawn the next. NEVER send a single message with multiple Task calls for different flows. This is a hard architectural constraint — parallel execution will cause build conflicts and test interference.

---

## Inputs

| Parameter | Description | Example |
|-----------|-------------|---------|
| `{CONNECTOR}` | Connector name (exact casing from JSON) | `Adyen` |
| `{CONNECTORS_FILE}` | JSON file with connector names | `connectors.json` |
| `{BRANCH}` | Git branch all work happens on | `feat/all-flows` |
| `{MANDATORY_PAYMENT_METHODS}` | JSON object of mandatory payment methods → PMTs from `connectors.json`. These MUST be implemented. | `{"UPI": ["UPI_PAY", "UPI_QR"], "WALLET": ["REDIRECT_WALLET_DEBIT"]}` |

---

## RULES (read once, apply everywhere)

1. **Working directory**: ALL commands use the `connector-service` repo root. Never `cd`.
2. **STRICTLY SEQUENTIAL FLOWS**: Process ONE flow at a time. One Task call per message. Wait for result. Only then spawn the next.
3. **No `cargo test`**: Testing is done via grpcurl through the Testing Agent (Phase 4). Never run `cargo test`.
4. **MANDATORY: Do NOT move to the next flow until the current Flow Agent completes its build.** Do NOT move to the next test until the current Testing Agent completes.
5. **Scoped git**: Only stage connector-specific files. Never `git add -A`. Never force push.
6. **Credentials**: Read from `creds.json` at the repo root. If connector is missing, report SKIPPED.
7. **Only do what's listed**: Do not invent steps. Do not add features. Do not write tests.
8. **FULLY AUTONOMOUS**: Never stop, ask questions, or present options. Make decisions using these rules.
9. **HARD GUARDRAIL — CONNECTOR AGENT DOES NOT DO SUBAGENT WORK**:
   - Do NOT read or write connector code yourself
   - Do NOT run `cargo build` or `grpcurl` yourself
   - Do NOT read `2.1_flow_decider.md`, `2.2_flow.md`, `2.2.1_testing.md`, or `2.3_pr.md` to execute them yourself
   - Your ONLY subagents are: Flow Decider, Flow Agent, Testing Agent, and PR Agent
10. **MANDATORY PAYMENT METHODS ARE NON-NEGOTIABLE**: The payment methods and PMTs listed in `{MANDATORY_PAYMENT_METHODS}` MUST be implemented. If the Flow Decider or Flow Agent cannot implement a mandatory payment method, the connector status is PARTIAL at best (never SUCCESS). The Flow Decider may discover additional (optional) payment methods from the techspec — those are best-effort.

---

## Phase 1: Setup & Discover Files (you do this yourself)

### 1a: Verify directory and branch

```bash
pwd && ls Cargo.toml crates/ Makefile     # verify directory
git branch --show-current                  # verify on {BRANCH}
```

If not on `{BRANCH}`, something is wrong — report FAILED.

### 1b: Find the techspec

Techspecs are located at `/home/kanikachaudhary/workflow/hyperswitch-prism/euler-techspec-output/` with naming pattern `{CONNECTOR_UPPER}_spec.md`.

```bash
# Try uppercase connector name (primary pattern)
CONNECTOR_UPPER=$(echo "{CONNECTOR}" | tr '[:lower:]' '[:upper:]')
ls /home/kanikachaudhary/workflow/hyperswitch-prism/euler-techspec-output/${CONNECTOR_UPPER}_spec.md
```

If not found, try variations (spaces/hyphens may become underscores):
```bash
ls /home/kanikachaudhary/workflow/hyperswitch-prism/euler-techspec-output/ | grep -i {connector}
```

If no techspec found → report FAILED with reason "No techspec found at /home/kanikachaudhary/workflow/hyperswitch-prism/euler-techspec-output/{CONNECTOR_UPPER}_spec.md".

Store `{TECHSPEC_PATH}` (e.g., `/home/kanikachaudhary/workflow/hyperswitch-prism/euler-techspec-output/RAZORPAY_spec.md`).

### 1c: Find connector source files

```bash
find crates/integrations/connector-integration/src/connectors/ -iname "*{connector}*" | head -20
```

Note the actual directory/file name (e.g., `adyen.rs` and `adyen/transformers.rs`).

**If connector source files are NOT found**: This means the connector is **brand new** and does not exist in the codebase yet. This is valid — the Flow Decider and Flow Agents will create the connector from scratch during implementation. In this case:
- Set `{CONNECTOR_SOURCE_FILES}` to `"NEW_CONNECTOR"` (a sentinel value)
- The Flow Decider will know there are no existing flows to skip
- The first Flow Agent (typically the foundational flow like Authorize or CreateOrder) will create the connector module, struct, `ConnectorCommon`, `create_all_prerequisites!`, and transformers module from scratch
- Do NOT report FAILED — proceed to Phase 2

Store `{CONNECTOR_SOURCE_FILES}` (either actual paths or `"NEW_CONNECTOR"`).

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
  CONNECTOR_SOURCE_FILES: <paths to connector .rs files, or NEW_CONNECTOR>
  MANDATORY_PAYMENT_METHODS: <JSON object of mandatory payment methods from connectors.json>"
)
```

**Gate**: If the Flow Decider returns FAILED (no implementable flows), report this connector as FAILED and go directly to Phase 6.

Parse the returned flow plan to extract:
- `ORDERED_FLOWS` — the ordered list of flow names with status PLAN or EXISTING_PM_PENDING
- `EXISTING_PM_PENDING_FLOWS` — flows that exist but need PM additions (status EXISTING_PM_PENDING). These ARE included in `ORDERED_FLOWS` for implementation.
- For each flow: its `TECHSPEC_SECTION` and `GRPCURL_SERVICE`

---

## Phase 3: Flow Implementation (SPAWN SUBAGENTS — SEQUENTIAL, ONE AT A TIME)

**HARD GUARDRAIL — ONE TASK CALL PER MESSAGE**: Spawn exactly ONE Flow Agent per message. Wait for the result. Only after receiving the result, spawn the next flow in a NEW message.

**NOTE**: Flow Agents only implement and build. Testing is deferred to Phase 4 after ALL flows are built.

Initialize tracking state:
```
BUILD_RESULTS = []             # array of per-flow build results
```

For each flow in `ORDERED_FLOWS`, in order:

### 3a: Check build dependency gates

Before spawning the Flow Agent, check if this flow's build dependencies are met. Since flows share code (e.g., post-Authorize flows reference structs from Authorize), a flow cannot be built if its code dependency failed to build.

**Pre-Authorize flows (no Authorize dependency):**

| Flow | Dependency | Gate |
|------|-----------|------|
| CreateOrder | None | Always proceed |
| CreateAccessToken | None | Always proceed |
| CreateConnectorCustomer | None | Always proceed |
| SessionToken | None | Always proceed |
| SdkSessionToken | None | Always proceed |
| PaymentMethodToken | None | Always proceed |
| PreAuthenticate | None | Always proceed |

**Authorize and post-Authorize flows:**

| Flow | Dependency | Gate |
|------|-----------|------|
| Authorize | Pre-Authorize flows if any (as ordered by decider) | Proceed after pre-flows complete |
| Authenticate | PreAuthenticate must have built | If PreAuthenticate BUILD_FAILED → SKIP |
| PostAuthenticate | Authenticate must have built | If Authenticate BUILD_FAILED → SKIP |
| PSync | Authorize must have built | If Authorize BUILD_FAILED → SKIP |
| Capture | Authorize must exist (EXISTING or BUILD_SUCCESS) | If Authorize BUILD_FAILED → SKIP |
| IncrementalAuthorization | Authorize must have built | If Authorize BUILD_FAILED → SKIP |
| Refund | Authorize must have built | If Authorize BUILD_FAILED → SKIP |
| RSync | Refund must have built | If Refund BUILD_FAILED/SKIPPED → SKIP |
| Void | Authorize must exist (EXISTING or BUILD_SUCCESS) | If Authorize BUILD_FAILED → SKIP |
| VoidPC | Capture must have built | If Capture BUILD_FAILED → SKIP |
| SetupMandate | Authorize must have built | If Authorize BUILD_FAILED → SKIP |
| RepeatPayment | SetupMandate must have built | If SetupMandate BUILD_FAILED → SKIP |
| MandateRevoke | SetupMandate must have built | If SetupMandate BUILD_FAILED → SKIP |

**Dispute flows (independent of payment lifecycle):**

| Flow | Dependency | Gate |
|------|-----------|------|
| DSync | Authorize must have built | If Authorize BUILD_FAILED → SKIP |
| AcceptDispute | Authorize must have built | If Authorize BUILD_FAILED → SKIP |
| SubmitEvidence | Authorize must have built | If Authorize BUILD_FAILED → SKIP |
| DefendDispute | Authorize must have built | If Authorize BUILD_FAILED → SKIP |

**Webhook flow:**

| Flow | Dependency | Gate |
|------|-----------|------|
| IncomingWebhook | None, but typically implemented last | Always proceed |

**EXISTING_PM_PENDING flows**: When a flow (e.g., Authorize) has status EXISTING_PM_PENDING, it IS included in `ORDERED_FLOWS` and IS spawned as a Flow Agent task. The Flow Agent receives the flow name with the additional context that it is adding PMs to an existing flow, not building from scratch. The `MANDATORY_PAYMENT_METHODS` parameter tells the Flow Agent which PMs to add. The flow plan's EXISTING_PM_PENDING entry lists which PMs are already implemented and which are pending.

**General rule**: The Flow Decider determines the order. If you encounter a flow not listed above, check if it shares code with Authorize or Refund. If unclear, proceed — build errors will surface naturally.

If a dependency is not met, mark the flow as SKIPPED with reason "Prerequisite {dependency} build not met" and continue to the next flow.

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
  CONNECTOR_SOURCE_FILES: <paths to connector .rs files, or NEW_CONNECTOR>
  MANDATORY_PAYMENT_METHODS: <JSON object of mandatory payment methods — pass ONLY for Authorize/SetupMandate/RepeatPayment flows that handle payment method data, otherwise empty {}>"
)
```

### 3c: Collect build result and update state

After the Flow Agent returns:

1. **Record the build result** in `BUILD_RESULTS`:
   ```
   {
     flow_name: <name>,
     build_status: BUILD_SUCCESS | BUILD_FAILED | SKIPPED,
     files_modified: [...],
     reason: <if failed>
   }
   ```

2. **Update `CONNECTOR_SOURCE_FILES`**: If this was the first flow for a NEW_CONNECTOR, the Flow Agent will have created the connector files. Update `CONNECTOR_SOURCE_FILES` from `"NEW_CONNECTOR"` to the actual paths reported in `files_modified` so subsequent Flow Agents get the real paths.

3. **Apply dependency enforcement** for subsequent flows (see gate table in 3a)

**WAIT** for this result before spawning the next flow. The next flow MUST be in a SEPARATE, SUBSEQUENT message.

---

## Phase 4: Testing (SPAWN SUBAGENTS — SEQUENTIAL, ONE AT A TIME)

After ALL flows have been built in Phase 3, test each successfully-built flow via the Testing SubAgent.

**HARD GUARDRAIL — ONE TASK CALL PER MESSAGE**: Spawn exactly ONE Testing Agent per message. Wait for the result. Only after receiving the result, spawn the next test in a NEW message.

Initialize testing state:
```
ACCUMULATED_IDS = {}           # grows as tests complete
PREVIOUS_FLOW_GRPCURL = ""     # raw grpcurl+output from the last completed test
TEST_RESULTS = []              # array of per-flow test results
```

For each flow in `ORDERED_FLOWS` that has `build_status: BUILD_SUCCESS` in `BUILD_RESULTS` (skip BUILD_FAILED and SKIPPED flows):

### 4a: Check testing dependency gates

Before spawning the Testing Agent, check if this flow's **testing dependencies** are met. Testing dependencies are about runtime data (IDs extracted from prior test responses), not build artifacts.

**Pre-Authorize flows (no testing dependency):**

| Flow | Dependency | Gate |
|------|-----------|------|
| CreateOrder | None | Always proceed |
| CreateAccessToken | None | Always proceed |
| CreateConnectorCustomer | None | Always proceed |
| SessionToken | None | Always proceed |
| SdkSessionToken | None | Always proceed |
| PaymentMethodToken | None | Always proceed |
| PreAuthenticate | None | Always proceed |

**Authorize and post-Authorize flows:**

| Flow | Dependency | Gate |
|------|-----------|------|
| Authorize | Pre-Authorize flows if any | Proceed after pre-flow tests complete |
| Authenticate | PreAuthenticate test must have PASSED | If PreAuthenticate test FAILED → SKIP |
| PostAuthenticate | Authenticate test must have PASSED | If Authenticate test FAILED → SKIP |
| PSync | Authorize test must have PASSED (need `connector_transaction_id`) | If Authorize test FAILED → SKIP |
| Capture | Authorize build exists (runs its OWN prerequisite Authorize) | Always proceed if Authorize was built |
| IncrementalAuthorization | Authorize test must have PASSED | If Authorize test FAILED → SKIP |
| Refund | Authorize test must have PASSED (need `connector_transaction_id` from a CHARGED payment) | If Authorize test FAILED → SKIP |
| RSync | Refund test must have PASSED (need `connector_refund_id`) | If Refund test FAILED/SKIPPED → SKIP |
| Void | Authorize build exists (runs its OWN prerequisite Authorize) | Always proceed if Authorize was built |
| VoidPC | Capture test must have PASSED | If Capture test FAILED → SKIP |
| SetupMandate | Authorize test must have PASSED | If Authorize test FAILED → SKIP |
| RepeatPayment | SetupMandate test must have PASSED | If SetupMandate test FAILED → SKIP |
| MandateRevoke | SetupMandate test must have PASSED | If SetupMandate test FAILED → SKIP |

**Dispute flows:**

| Flow | Dependency | Gate |
|------|-----------|------|
| DSync | Authorize test must have PASSED | If Authorize test FAILED → SKIP |
| AcceptDispute | Authorize test must have PASSED | If Authorize test FAILED → SKIP |
| SubmitEvidence | Authorize test must have PASSED | If Authorize test FAILED → SKIP |
| DefendDispute | Authorize test must have PASSED | If Authorize test FAILED → SKIP |

**Webhook flow:**

| Flow | Dependency | Gate |
|------|-----------|------|
| IncomingWebhook | None | Always proceed |

If a testing dependency is not met, mark the flow's test as SKIPPED with reason "Prerequisite {dependency} test not passed" and continue to the next flow.

### 4b: Spawn Testing Agent

```
Task(
  subagent_type="general",
  description="Test {FLOW_NAME} grpcurl for {CONNECTOR}",
  prompt="Read and follow the workflow defined in grace/workflow/v2/2.2.1_testing.md

Variables:
  CONNECTOR: {connector}
  FLOW_NAME: {FLOW_NAME}
  GRPCURL_SERVICE: <gRPC service method for this flow>
  ACCUMULATED_IDS: <JSON with all IDs from prior tests>
  PREVIOUS_FLOW_GRPCURL: <raw grpcurl+output from previous test, or empty>
  MANDATORY_PAYMENT_METHODS: <JSON object of mandatory payment methods — pass for Authorize/SetupMandate/RepeatPayment flows, otherwise empty {}>"
)
```

**Do NOT read `grace/workflow/v2/2.2.1_testing.md` yourself.** The Testing Agent reads its own workflow file.

### 4c: Collect test result and update state

After the Testing Agent returns:

1. **Record the test result** in `TEST_RESULTS`:
   ```
   {
     flow_name: <name>,
     test_status: PASS | FAIL | SKIPPED,
     grpcurl_command: <raw command>,
     grpcurl_output: <raw output>,
     extracted_ids: {connector_transaction_id: ..., connector_refund_id: ...},
     reason: <if failed>
   }
   ```

2. **Merge extracted IDs** into `ACCUMULATED_IDS`:
   - If the test returned `connector_transaction_id`, add/update it in `ACCUMULATED_IDS`
   - If the test returned `connector_refund_id`, add/update it in `ACCUMULATED_IDS`

3. **Update `PREVIOUS_FLOW_GRPCURL`** with this test's raw grpcurl command + output (for the next test to use as reference)

4. **Apply testing dependency enforcement** for subsequent tests (see gate table in 4a)

**WAIT** for this result before spawning the next test. The next test MUST be in a SEPARATE, SUBSEQUENT message.

### 4d: Merge build and test results

After all tests complete, produce the final `FLOW_RESULTS` by merging `BUILD_RESULTS` and `TEST_RESULTS`:

```
FLOW_RESULTS = []
for each flow in ORDERED_FLOWS:
  {
    flow_name: <name>,
    status: SUCCESS | FAILED | SKIPPED,
    build_status: BUILD_SUCCESS | BUILD_FAILED | SKIPPED,
    test_status: PASS | FAIL | SKIPPED | NOT_RUN,
    grpcurl_command: <from TEST_RESULTS or empty>,
    grpcurl_output: <from TEST_RESULTS or empty>,
    extracted_ids: <from TEST_RESULTS or empty>,
    files_modified: <from BUILD_RESULTS>,
    reason: <if not SUCCESS>
  }
```

**Final status per flow:**
- **SUCCESS**: build_status is BUILD_SUCCESS AND test_status is PASS
- **FAILED**: build_status is BUILD_FAILED, OR test_status is FAIL
- **SKIPPED**: build_status is SKIPPED, OR test was SKIPPED due to unmet dependency

### 4e: Validate mandatory payment method coverage

After merging results, check that ALL mandatory payment methods from `{MANDATORY_PAYMENT_METHODS}` were covered:

1. The Flow Decider's plan marks each payment method as `MANDATORY` or `OPTIONAL`
2. For each mandatory payment method + PMT pair:
   - Check if the Authorize flow (or relevant flow handling that PM) has status SUCCESS
   - If the flow that covers a mandatory PM has FAILED or SKIPPED → record it as `MANDATORY_UNCOVERED`

```
MANDATORY_COVERAGE = {
  covered: [list of mandatory PM:PMT pairs with SUCCESS],
  uncovered: [list of mandatory PM:PMT pairs that FAILED or were SKIPPED]
}
```

**If any mandatory payment methods are uncovered**, the connector status CANNOT be SUCCESS — it is PARTIAL at best.

---

## Phase 5: Commit & PR (SPAWN SUBAGENT)

**GUARDRAIL: You MUST spawn a subagent. Do NOT run git commands yourself.**

First, check if there are any file changes to commit:
```bash
git status -- crates/integrations/connector-integration/src/connectors/{connector}*
```

If no changes (all flows were SKIPPED or EXISTING), skip to Phase 6.

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
  FLOW_RESULTS: <JSON array of all per-flow results from Phase 4d>
  CONNECTOR_SOURCE_FILES: <paths to modified files>
  TEST_REPORT_PATHS: <paths to test report MDs>
  MANDATORY_PAYMENT_METHODS: <JSON object of mandatory payment methods from connectors.json>
  MANDATORY_COVERAGE: <JSON with covered/uncovered mandatory PM:PMT lists from Phase 4e>"
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

## Phase 6: Report

Return the final result:

```
CONNECTOR: {CONNECTOR}
STATUS: SUCCESS | PARTIAL | FAILED | SKIPPED
FLOWS:
  <For each flow from the Flow Decider's plan (not a fixed list — may include any combination of flows):>
  - {FlowName}: SUCCESS | FAILED | SKIPPED | EXISTING
FLOWS_SUCCEEDED: <count>
FLOWS_FAILED: <count>
FLOWS_SKIPPED: <count>
MANDATORY_PAYMENT_METHODS:
  COVERED: [list of mandatory PM:PMT pairs implemented successfully]
  UNCOVERED: [list of mandatory PM:PMT pairs that failed or were skipped]
PR: <PR_URL or "not created">
REASON: <if not SUCCESS, primary reason>
```

**STATUS definitions:**
- **SUCCESS**: ALL planned flows passed (build + grpcurl) AND ALL mandatory payment methods are covered AND PR created. No exceptions.
- **PARTIAL**: At least one planned flow succeeded, but others failed or were skipped, OR some mandatory payment methods are uncovered.
- **FAILED**: No planned flows succeeded, OR Authorize failed (which cascades to all).
- **SKIPPED**: Connector was skipped before any implementation (no techspec, no source files, no credentials).

---

## Subagent Reference

| Agent | File | Purpose |
|-------|------|---------|
| Flow Decider Agent | `2.1_flow_decider.md` | Analyze techspec, determine flows to implement and their order |
| Flow Agent | `2.2_flow.md` | Implement and build ONE flow (code + cargo build only) |
| Testing Agent | `2.2.1_testing.md` | Test ONE flow via grpcurl (spawned by Connector Agent after all flows are built) |
| PR Agent | `2.3_pr.md` | Commit, cherry-pick, push, and create cross-fork PR |
