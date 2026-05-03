# Connector Session (v2)

You are the **sole owner** of implementing every unimplemented item for **{CONNECTOR}** that survives confidence-score gating. You handle the session end-to-end: link discovery + scoring, techspec generation, per-item codegen, grpcurl validation, and committing.

You are invoked **once per connector** by the Orchestrator (`1_orchestrator.md`) via `openswarm exec --local --pipeline`. The OpenSwarm Worker runs you; the OpenSwarm Reviewer (post-Worker) reads your final diff.

**First**: Read this file (`grace/workflow/v2/2_connector.md`) fully to understand all phases and rules before proceeding.

You coordinate by **spawning subagents via the Task tool** for the heavy phases (link scoring, techspec, codegen, grpcurl, PR). Lightweight orchestration (manifest reading, result aggregation) you do yourself.

**HARD GUARDRAIL — MANDATORY SUBAGENT DELEGATION**: For Phases 1, 2, 3, 4, 5 you MUST spawn separate subagents via the Task tool. Do NOT do their work yourself. Each subagent reads its own workflow file — do NOT paste their contents into prompts.

---

## Inputs

| Parameter | Description | Example |
|-----------|-------------|---------|
| `{CONNECTOR}` | Connector slug (lowercase) | `stripe` |
| `{MANIFEST}` | Path to per-connector manifest from Phase 0 | `grace/workflow/v2/work/stripe_manifest.json` |
| `{BRANCH}` | Shared dev branch | `feat/grace-v2-2026-05-03` |
| `{LINK_THRESHOLD}` | Min confidence (0.0-1.0) to keep an item | `0.70` |

---

## RULES

1. **Working directory**: All commands from `connector-service` repo root. Exception: `grace techspec` runs from `grace/` with venv activated (delegated to Tech Spec Agent — you don't activate the venv yourself).
2. **No retry loops without diagnosis**: NEVER retry the same `cargo build` or `grpcurl` call without a code change. If a stage fails, read logs, identify root cause, fix, then retest. Item-codegen agents handle their own internal retries; you do not loop them externally.
3. **Scoped git**: Per-item commits stage only the touched files. The PR Agent (Phase 5) handles all `git add` / `git commit` / `git cherry-pick` / `git push` / `gh pr create`. You do NOT run those.
4. **Credentials**: `creds.json` at repo root. If creds for `{CONNECTOR}` are absent, return `STATUS: SKIPPED` with reason `"no credentials"` immediately and skip all phases.
5. **Phases run in order**: 1 → 2 → 3 → 4 → 5 → 6. Do not skip or reorder.
6. **One results file**: All phases append to `grace/workflow/v2/work/{CONNECTOR}_results.json`. The orchestrator reads this file.

---

## Phase 0: Pre-flight (you do this yourself)

Verify branch and creds.

```bash
pwd && ls Cargo.toml crates/ Makefile
git branch --show-current
# expect: {BRANCH}. If not on {BRANCH}, switch:
git checkout {BRANCH}

jq -e --arg c "{CONNECTOR}" '.[$c] // .[($c | ascii_upcase)] // .[($c | ascii_downcase)]' creds.json >/dev/null \
  || { echo "no credentials for {CONNECTOR} — exiting SKIPPED"; exit 0; }

jq '.counts' {MANIFEST}
```

If `{MANIFEST}` does not exist or has zero counts, exit with `STATUS: SKIPPED`, reason `"no unimplemented items"`.

---

## Phase 1: Link Discovery + Confidence Scoring (SPAWN SUBAGENT)

**GUARDRAIL: Spawn a subagent. Do NOT use WebFetch / WebSearch yourself to discover or score links.**

Spawn the Link-Scoring Agent via Task tool with a minimal prompt:

```
Task(
  subagent_type="general",
  description="Score links for {CONNECTOR}",
  prompt="Read and follow the workflow defined in grace/workflow/v2/2.1_link_scoring.md

Variables:
  CONNECTOR: {CONNECTOR}
  MANIFEST: {MANIFEST}
  THRESHOLD: {LINK_THRESHOLD}
  OUTPUT: grace/workflow/v2/work/{CONNECTOR}_links.json"
)
```

Wait for the agent to finish. It writes `{CONNECTOR}_links.json` whose `items[]` array contains one entry per manifest item with either `decision: "implement"` (a link scored ≥ threshold) or `decision: "skip"` (with `reason`).

**Gate**: If the JSON has zero `decision: "implement"` items, report `STATUS: SKIPPED`, reason `"all items below confidence threshold"`, and go to Phase 6.

Capture from the JSON:
- `KEPT_ITEMS` = array of items with `decision: "implement"`
- `SKIPPED_ITEMS` = array of items with `decision: "skip"` (for the final report)

---

## Phase 2: TechSpec Generation (SPAWN ONE SUBAGENT PER KEPT ITEM)

**GUARDRAIL: Spawn a subagent per item. Do NOT run `grace techspec` yourself.**

For each item in `KEPT_ITEMS`, spawn the Tech Spec Agent in a SEPARATE message (sequential, one at a time):

```
Task(
  subagent_type="general",
  description="Techspec {CONNECTOR}/{ITEM_NAME}",
  prompt="Read and follow the workflow defined in grace/workflow/v2/2.2_techspec.md

Variables:
  CONNECTOR: {CONNECTOR}
  ITEM_ID: <item.id>
  ITEM_NAME: <item.name>
  ITEM_KIND: <item.kind: 'flow' or 'payment_method'>
  SOURCE_FLOW: <item.source_flow>
  LINK_URL: <item.best_link.url>
  OUTPUT_DIR: grace/rulesbook/codegen/references/{CONNECTOR}/v2"
)
```

Each agent returns either `STATUS: SUCCESS` with a `TECHSPEC_PATH` or `STATUS: FAILED` with a reason. **Drop FAILED items from the work list** — do NOT attempt codegen for them. Record them in the results JSON as `SKIPPED (techspec_failed)`.

After this phase, you have `READY_ITEMS` = items with both a high-confidence link AND a successful techspec.

---

## Phase 3: Per-Item Code Generation (SPAWN ONE SUBAGENT PER READY ITEM, SEQUENTIAL)

**GUARDRAIL: Spawn a subagent per item. Do NOT write Rust code or run `cargo build` yourself.**

**HARD GUARDRAIL — SEQUENTIAL ONLY**: Codegen must be sequential per item within a connector — `cargo target/` is single, parallel `cargo build` against the same tree corrupts artifacts.

For each item in `READY_ITEMS`, in a separate message, spawn the Item Codegen Agent:

```
Task(
  subagent_type="general",
  description="Codegen {CONNECTOR}/{ITEM_NAME}",
  prompt="Read and follow the workflow defined in grace/workflow/v2/2.3_item_codegen.md

Variables:
  CONNECTOR: {CONNECTOR}
  ITEM_ID: <item.id>
  ITEM_NAME: <item.name>
  ITEM_KIND: <flow or payment_method>
  SOURCE_FLOW: <item.source_flow>
  TECHSPEC_PATH: <from Phase 2>
  GRPCURL_PAYLOAD_OUT: grace/workflow/v2/work/{CONNECTOR}_payloads/<item.id>.json"
)
```

Each agent returns one of:
- `STATUS: SUCCESS` — code written, `cargo build` passed, grpcurl payload template emitted.
- `STATUS: FAILED` — with reason (build error, conflict with existing flow, etc.).
- `STATUS: SKIPPED` — already implemented (codegen detected the item is already in the source).

Record each item's status to the in-memory results structure. **Do not abort the phase on a single FAILED**; continue with the next item.

After all items: `IMPLEMENTED_ITEMS` = items with `STATUS: SUCCESS`.

---

## Phase 4: grpcurl Validation (SPAWN SUBAGENT)

**GUARDRAIL: Spawn a subagent. Do NOT run `make run` or `grpcurl` yourself. The runner manages service lifecycle.**

Spawn the Grpcurl Runner ONCE for the connector (it iterates internally):

```
Task(
  subagent_type="general",
  description="grpcurl runner for {CONNECTOR}",
  prompt="Read and follow the workflow defined in grace/workflow/v2/2.5_grpcurl_runner.md

Variables:
  CONNECTOR: {CONNECTOR}
  ITEMS: <JSON array of IMPLEMENTED_ITEMS with their grpcurl payload paths>
  PAYLOADS_DIR: grace/workflow/v2/work/{CONNECTOR}_payloads
  OUTPUT: grace/workflow/v2/work/{CONNECTOR}_results.json"
)
```

The runner returns per-item validation status. Update the results JSON with `grpcurl_status` per item.

**Gate**: An item with `cargo build` SUCCESS but `grpcurl` FAILED is still considered FAILED for the final report (the implementation didn't actually work end-to-end).

---

## Phase 5: Commit & PR (SPAWN SUBAGENT)

**GUARDRAIL: Spawn a subagent. Do NOT run `git add` / `git commit` / `git push` / `gh pr create` yourself.**

Spawn the PR Agent ONCE:

```
Task(
  subagent_type="general",
  description="PR for {CONNECTOR} v2 batch",
  prompt="Read and follow the workflow defined in grace/workflow/v2/2.4_pr.md

Variables:
  CONNECTOR: {CONNECTOR}
  DEV_BRANCH: {BRANCH}
  RESULTS: grace/workflow/v2/work/{CONNECTOR}_results.json
  ITEMS_FOR_PR: <JSON array of items with grpcurl_status SUCCESS or FAILED>"
)
```

The PR Agent commits per-item changes on `{BRANCH}`, cherry-picks them onto a clean per-connector PR branch (e.g. `feat/grace-v2-{CONNECTOR}-{date}`), scrubs creds, pushes, opens a PR on `juspay/connector-service`. For batches with any FAILED items, the PR is labelled `do-not-merge`.

Capture `PR_URL` from the agent's output.

---

## Phase 6: Verify Branch + Report

After Phase 5, verify you are back on `{BRANCH}`:

```bash
git branch --show-current
# if not {BRANCH}:
git checkout {BRANCH}
```

Write the final results JSON. The schema must be:

```json
{
  "connector": "{CONNECTOR}",
  "status": "SUCCESS|PARTIAL|FAILED|SKIPPED",
  "branch": "{BRANCH}",
  "pr_url": "<url or empty>",
  "items": [
    {
      "id": "f5z",
      "name": "Wallet - Paypal",
      "kind": "payment_method",
      "source_flow": "PaymentService.Authorize",
      "decision": "implement",
      "techspec_status": "SUCCESS|FAILED|SKIPPED",
      "codegen_status": "SUCCESS|FAILED|SKIPPED",
      "grpcurl_status": "SUCCESS|FAILED|SKIPPED",
      "status": "SUCCESS|FAILED|SKIPPED",
      "reason": "<empty if SUCCESS>"
    }
  ]
}
```

**status definitions** (per item):
- `SUCCESS` — codegen + cargo build + grpcurl all SUCCESS.
- `FAILED` — any phase failed after attempting it.
- `SKIPPED` — pre-empted (low confidence, already implemented, techspec missing, no creds).

**connector status**:
- `SUCCESS` — all kept items SUCCESS.
- `PARTIAL` — some SUCCESS, some FAILED/SKIPPED.
- `FAILED` — every kept item FAILED.
- `SKIPPED` — Phase 0 or 1 short-circuited.

Print the summary to stdout (the OpenSwarm Worker captures this for the Reviewer):

```
=== {CONNECTOR} ===
Status: {status}
Items: implement={N_kept}, success={N_success}, failed={N_failed}, skipped={N_skipped}
PR: {PR_URL or "none"}
```

---

## Subagent Reference

| Agent | File | Purpose |
|-------|------|---------|
| Link-Scoring Agent | `2.1_link_scoring.md` | Discover candidate URLs per item, score, drop below-threshold |
| Tech Spec Agent | `2.2_techspec.md` | Run `grace techspec` for one item with its high-confidence link |
| Item Codegen Agent | `2.3_item_codegen.md` | Implement one item (flow or payment method), cargo build |
| Grpcurl Runner | `2.5_grpcurl_runner.md` | Start service, grpcurl per implemented item, write results JSON |
| PR Agent | `2.4_pr.md` | Commit + cherry-pick + push + open PR for the batch |
