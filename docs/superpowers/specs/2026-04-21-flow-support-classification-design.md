# Flow Support Classification — Design Spec

**Date:** 2026-04-21
**Status:** Draft — awaiting user review
**Template PR:** [#1154 — feat(connector): complete CryptoPay integration](https://github.com/juspay/hyperswitch-prism/pull/1154)

## Problem

Every connector in `crates/integrations/connector-integration/src/connectors/` has empty `ConnectorIntegrationV2<Flow, ...>` impl blocks for flows the integration doesn't handle. When the gRPC layer calls into one of those blocks, the default stub produces `"This feature is not implemented: ..."`. The dashboard reads this through `data/field_probe/<connector>.json`, where the flow shows up as `"status": "not_implemented"`.

The failure mode: the dashboard cannot distinguish between **not_supported** (the processor's own API doesn't offer the feature — e.g., CryptoPay has no Refund endpoint because crypto refunds don't work that way) and **not_implemented** (the processor supports the feature but we haven't wired our client to it). Today both surface as `not_implemented`, which misinforms merchants about processor capability.

PR #1154 established the fix pattern for CryptoPay: for each truly-unsupported flow, override `get_url()` in the impl block to return `IntegrationError::FlowNotSupported { flow, connector, context }`, and flip the field_probe JSON to `"status": "not_supported"` with a descriptive `error` message. This spec scales that pattern to the other 82 connectors.

## Non-goals

- Not wiring any currently-missing integration. `supported_but_not_wired` verdicts are recorded but produce no code change in this pass.
- Not changing flows already marked `supported`. No regression surface.
- Not touching framework-level flows without Rust flow structs: `eligibility`, `verify_redirect`, `handle_event`, `proxy_*`, `token_*`. These have no impl block to override.
- Not re-classifying `VerifyWebhookSource` — internal, no probe entry.
- Not refactoring connector.rs files beyond the minimum two-method injection per approved row.

## Ground rules

- **Verdict bar = GOLD + BRONZE.**
  - **GOLD:** Direct quote from an official processor doc page stating the flow is not offered.
  - **BRONZE:** Business-model impossibility argument tied to the processor's product (e.g., atomic settlement precludes separate Capture).
  - Anything else → `uncertain`. Leave as `not_implemented`.
- **Flow naming convention:** PascalCase in `FlowNotSupported.flow` strings and field_probe `error` messages, matching PR #1154 exactly (e.g., `"IncrementalAuthorization"`, `"AcceptDispute"`). This is the only merged precedent and diverging would fragment the grep pattern.
- **Scope constraint:** A row is in scope iff (a) the connector currently has `"status": "not_implemented"` for that flow in its field_probe JSON, AND (b) the flow has a corresponding Rust flow struct in `crates/types-traits/domain_types/src/connector_flow.rs`, AND (c) the connector's `.rs` file has an empty `ConnectorIntegrationV2<Flow, ...>` impl block for that flow. Any of these missing → skip + log.
- **PR cadence:** Single mega-PR across all 83 connectors, but with **one commit per connector** to preserve per-connector revertability inside the single diff.

## Pilot connectors

| Connector | Role | What it tests |
|---|---|---|
| `cryptopay` | Calibration baseline | PR #1154 already classified 14 flows. Agent must reproduce those verdicts exactly or we fix the prompt. |
| `stripe` | Over-classification risk | Rich feature matrix across multiple product pages (Radar, Connect, Billing). False `not_supported` here would be catastrophic. |
| `mifinity` | Under-classification risk | Narrow wallet — most flows genuinely don't apply. Tests BRONZE impossibility-by-design reasoning on non-crypto. |

If any pilot fails to produce defensible verdicts, halt and revise the agent prompt before fan-out.

## Architecture

Three phases with one shared ground-truth file.

### Phase 0 — Baseline snapshot

One deterministic script, no subagents:

1. Enumerate all `data/field_probe/*.json` files.
2. For each connector, extract every `(flow_key, status)` tuple where `status == "not_implemented"`.
3. Cross-reference with `crates/integrations/connector-integration/src/connectors/<connector>.rs`: confirm the corresponding `ConnectorIntegrationV2<Flow, ...>` impl block exists and is empty (bodyless `{}` or only whitespace).
4. Emit `/tmp/flow-support/baseline.jsonl` — one row per in-scope `(connector, rust_flow_struct, probe_key)` tuple.

### Phase 1 — Research subagents (parallel)

One subagent per in-scope connector.

**Tools allowed:** `WebFetch`, `WebSearch`, `firecrawl:firecrawl`, `Read`, `Grep`, `Bash` (restricted to `curl`/`gh api` for doc fetching). **No write tools.** **No code generation.**

**Prompt skeleton:**

```
You are classifying payment flows for connector <NAME>. Your job is to determine,
for each flow in the in-scope list, whether the processor's own API supports it.

Evidence bar (GOLD + BRONZE):
  GOLD   — A direct quote from an official processor doc stating the flow/feature
           is not offered.
  BRONZE — A business-model impossibility argument tied to the processor's product
           (e.g., "Crypto charges settle atomically, so separate Capture is
            meaningless").
  Anything else — return "uncertain". DO NOT guess. DO NOT use "not_supported" as
  a default when docs are thin or hard to find.

Anti-hallucination rules:
  - If you cannot find the processor's official API reference, return "uncertain"
    for every flow.
  - Before returning "not_supported" for a flow, you MUST search for at least 3
    synonyms of the flow name (Void ≈ reversal ≈ cancel; Dispute ≈ chargeback
    ≈ claim; SetupMandate ≈ stored credentials ≈ recurring profile; etc.).
  - If the processor has a separate product page for a feature (Stripe Radar,
    Adyen RevenueProtect, Cybersource Payer Auth, etc.), that counts as supported.
  - Fabricating a quote is a terminal failure of this task.

In-scope flows for this connector:
  <LIST from baseline.jsonl>

Output: write /tmp/flow-support/evidence/<NAME>.json in this exact schema:
<SCHEMA>
```

**Output schema:**

```json
{
  "connector": "<name>",
  "docs_root_url": "<official docs root>",
  "docs_accessed_at": "YYYY-MM-DD",
  "docs_access": "ok" | "unavailable",
  "flows": {
    "<RustFlowStruct>": {
      "verdict": "not_supported" | "supported_but_not_wired" | "uncertain",
      "evidence_type": "gold" | "bronze" | null,
      "evidence_url": "<direct doc url>" | null,
      "evidence_quote": "<verbatim text>" | null,
      "rationale": "<one-paragraph>"
    }
  }
}
```

**Fan-out strategy:** Pilot first (3 connectors). Inspect evidence packs. Calibrate prompt if needed. Then fan out remaining 80 in batches of 20 to avoid runtime caps and produce intermediate checkpoints.

### Phase 2 — Human review gate

**Surface:** `/tmp/flow-support/review.md` — grouped by connector, showing only `not_supported` rows (each with evidence_url, quote, rationale, and an `[ ]` checkbox). `supported_but_not_wired` and `uncertain` verdicts are summarized in footer counts, not shown inline.

**Mechanic:** In-place markdown edit. The user ticks the `[ ]` box on each row they approve. A small parser reads the markdown, emits `/tmp/flow-support/approved.jsonl` with only the checked rows.

**Spot-check audit (automated, before Phase 3 starts):** Pick 5 random approved rows across 5 different connectors. Re-fetch each `evidence_url` and confirm the `evidence_quote` appears verbatim on the page. Any miss → halt, surface the failing connector's full evidence pack for re-review.

### Phase 3 — Deterministic code-write

One subagent, no research tools. Reads `approved.jsonl` and emits commits.

**Per approved row `(connector, flow_struct, probe_key)`:**

**Edit 1 — `crates/integrations/connector-integration/src/connectors/<connector>.rs`:**

Locate the impl block:

```rust
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    ConnectorIntegrationV2<<FlowStruct>, <FlowData>, <Req>, <Resp>>
    for <Connector><T>
{
    // body
}
```

If the body is empty, inject:

```rust
    fn get_url(
        &self,
        _req: &RouterDataV2<<FlowStruct>, <FlowData>, <Req>, <Resp>>,
    ) -> CustomResult<String, IntegrationError> {
        Err(report!(IntegrationError::FlowNotSupported {
            flow: "<PascalCaseFlowName>".to_string(),
            connector: "<ConnectorBrandName>".to_string(),
            context: Default::default(),
        }))
    }
```

If the body is non-empty, halt that row and flag for human review — non-empty body contradicts the `not_supported` verdict.

**Edit 2 — `data/field_probe/<connector>.json`:**

Flip

```json
"<probe_key>": { "default": { "status": "not_implemented" } }
```

to

```json
"<probe_key>": {
  "default": {
    "status": "not_supported",
    "error": "<PascalCaseFlowName> flow not supported by <ConnectorBrandName> connector"
  }
}
```

**Connector-brand-name lookup:** Derived from the connector's `ConnectorCommon::id()` or `to_string()`. Falls back to a small hand-curated map (`cryptopay` → `"CryptoPay"`, etc.) where automatic capitalization is wrong.

**Commit message template:**

```
fix(connector): reclassify unsupported flows for <connector>

Marks <N> flows as FlowNotSupported based on official documentation.

Flows reclassified:
- Capture: gold — <one-line rationale>
- Void:    bronze — <one-line rationale>
- ...

Evidence: docs/superpowers/evidence/<connector>.json (committed in this PR)
```

**Safety rails between commits:**

1. `cargo check -p connector-integration` — halt on failure.
2. `cargo fmt --check` on the modified `.rs` file.
3. `jq empty data/field_probe/<connector>.json` — halt on malformed JSON.
4. After the last commit, re-run the doc generator (`scripts/generators/docs/generate.py`) and verify `docs-generated/all_connector.md` regenerates cleanly.

## Flow-key mapping table

**Illustrative only.** The authoritative mapping is derived at Phase 0 runtime by intersecting the actual probe-key set in each `data/field_probe/<connector>.json` with the Rust flow structs in `crates/types-traits/domain_types/src/connector_flow.rs`. This table reflects the common case but the per-connector probe JSON is ground truth. Where the table and observed data diverge, observed data wins.

The table below is derived from `scripts/generators/docs/generate.py:_FLOW_KEY_OVERRIDES` (`:218-245`) plus direct inspection of `cryptopay.json` and `stripe.json`.

| Rust flow struct | gRPC service.RPC | Probe key |
|---|---|---|
| `Authorize` | `PaymentService.Authorize` | `authorize` |
| `PSync` | `PaymentService.Get` | `get` |
| `Capture` | `PaymentService.Capture` | `capture` |
| `Void` | `PaymentService.Void` | `void` |
| `VoidPC` | `PaymentService.Reverse` | `reverse` |
| `Refund` | `RefundService.Refund` | `refund` |
| `RSync` | `RefundService.Get` | `refund_get` |
| `CreateOrder` | `PaymentService.CreateOrder` | `create_order` |
| `SetupMandate` | `RecurringPaymentService.SetupRecurring` | `setup_recurring` |
| `RepeatPayment` | `RecurringPaymentService.Charge` | `recurring_charge` |
| `MandateRevoke` | `RecurringPaymentService.Revoke` | `recurring_revoke` |
| `IncrementalAuthorization` | `PaymentService.IncrementalAuthorization` | `incremental_authorization` |
| `Accept` | `DisputeService.Accept` | `dispute_accept` |
| `SubmitEvidence` | `DisputeService.SubmitEvidence` | `dispute_submit_evidence` |
| `DefendDispute` | `DisputeService.Defend` | `dispute_defend` |
| `PreAuthenticate` | `PaymentMethodAuthenticationService.PreAuthenticate` | `pre_authenticate` |
| `Authenticate` | `PaymentMethodAuthenticationService.Authenticate` | `authenticate` |
| `PostAuthenticate` | `PaymentMethodAuthenticationService.PostAuthenticate` | `post_authenticate` |
| `ClientAuthenticationToken` | `MerchantAuthenticationService.CreateClientAuthenticationToken` | `create_client_authentication_token` |
| `ServerAuthenticationToken` | `MerchantAuthenticationService.CreateServerAuthenticationToken` | `create_server_authentication_token` |
| `ServerSessionAuthenticationToken` | `MerchantAuthenticationService.CreateServerSessionAuthenticationToken` | `create_server_session_authentication_token` |
| `CreateConnectorCustomer` | `CustomerService.Create` | `create_customer` |
| `PaymentMethodToken` | `PaymentMethodService.Tokenize` | `tokenize` |
| `PayoutCreate` / `PayoutTransfer` / `PayoutGet` / `PayoutVoid` / `PayoutStage` / `PayoutCreateLink` / `PayoutCreateRecipient` / `PayoutEnrollDisburseAccount` | `PayoutService.*` | `payout_*` (confirm per-connector; skip rows where probe key is absent) |
| `VerifyWebhookSource` | (internal) | — (out of scope) |

## Evidence pack retention

Research evidence packs are committed to the repository under `docs/superpowers/evidence/<connector>.json` as part of the mega-PR. This gives reviewers and future re-classifiers a persistent audit trail. The `review.md` approval artifact and `baseline.jsonl` / `approved.jsonl` stay ephemeral in `/tmp/flow-support/`.

## Failure modes & mitigations

| Risk | Mitigation |
|---|---|
| Agent hallucinates an `evidence_quote` | Automated spot-check audit re-fetches 5 random URLs and greps for the quote before Phase 3 starts. |
| Agent returns `not_supported` for a flow that actually exists under a different name | Prompt mandates 3-synonym search before `not_supported`. Pilot on `stripe` catches this class because Stripe has many multi-named features. |
| Agent marks all flows `uncertain` because it couldn't reach docs | Schema includes `docs_access: "unavailable"` flag. These connectors get zero verdicts landed and are listed in the PR description as "docs inaccessible, follow-up required". |
| Probe key is absent for a connector (e.g., `payout_*` for card-only processors) | Phase 0 baseline drops that row. Phase 3 code-writer also defensively skips if the key is missing at write time. |
| Non-empty impl block in `connector.rs` (partial code contradicts `not_supported`) | Phase 3 halts that row and surfaces for human review. Does not overwrite. |
| Mega-PR review gets stuck on one bad connector | Per-connector commits allow reviewers to request revert of a single commit via `git revert <sha>` without touching the rest. |
| Doc generator (`scripts/generators/docs/generate.py`) breaks after changes | Mandatory regeneration step before PR push; any failure halts. |

## What's explicitly accepted as residual risk

- Review fatigue: ~500–1500 checked rows across 83 connectors is a lot to skim. Mitigation: the pilot calibrates the agent's precision; if pilot rejection rate is low (<10%), fan-out can be bulk-approved with only flagged rows getting attention.
- Payout flows: classification quality is expected to be lowest here (terminology varies most widely across processors). If pilot reveals systematic bad verdicts on payouts, we drop payouts from scope and do a separate pass with a payouts-specific prompt.
- PR size: 15–25k lines of mostly-mechanical diff. Per-connector commits mitigate revert cost but not review time.

## Approval gates before execution

1. **This spec** — user reviews this file. Approved → write implementation plan.
2. **After Phase 0 baseline** — user sees the `baseline.jsonl` row count and per-connector scope. Approved → launch pilot.
3. **After pilot evidence packs** — user reviews 3 pilot packs. Approved → fan out the remaining 80.
4. **After Phase 2 review** — user ticks the approved rows. `approved.jsonl` becomes the ground truth.
5. **After Phase 3 first commit** — user inspects the first connector's commit. Approved → proceed through the batch.
6. **Before PR push** — user reviews the final branch state. Approved → `gh pr create`.
