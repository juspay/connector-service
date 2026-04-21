# Flow Support Classification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reclassify every currently-`not_implemented` flow across 83 connectors into `not_supported` (documented + justified) or leave as `not_implemented`, mirroring the PR #1154 template, and ship as a single mega-PR with per-connector commits.

**Architecture:** Three-phase pipeline — (0) extract baseline of in-scope `(connector, flow)` tuples from probe JSON + connector.rs emptiness check, (1) parallel research subagents produce GOLD+BRONZE evidence packs, (2) human ticks approval markdown, (3) deterministic code-write subagent emits per-connector commits.

**Tech Stack:** Rust (connector-integration crate), Python (probe-key derivation, review surface generation), `jq`, `cargo`, `gh`, Claude subagents via Agent tool.

**Spec:** `docs/superpowers/specs/2026-04-21-flow-support-classification-design.md` (commit `17c90d57f`)

---

## Phase 0 — Baseline extraction (no subagents, no web)

### Task 0.1: Create workspace directory

**Files:**
- Create: `scripts/flow_support/` (new dir)
- Create: `/tmp/flow-support/` (ephemeral, outside repo)
- Create: `docs/superpowers/evidence/` (for committed evidence packs at end of Phase 1)

- [ ] **Step 1: Create directories**

```bash
mkdir -p /Users/tushar.shukla/Downloads/Work/euler-ucs/hyperswitch-prism/scripts/flow_support
mkdir -p /Users/tushar.shukla/Downloads/Work/euler-ucs/hyperswitch-prism/docs/superpowers/evidence
mkdir -p /tmp/flow-support/{evidence,review,logs}
```

- [ ] **Step 2: Verify**

```bash
ls -d /Users/tushar.shukla/Downloads/Work/euler-ucs/hyperswitch-prism/scripts/flow_support \
      /Users/tushar.shukla/Downloads/Work/euler-ucs/hyperswitch-prism/docs/superpowers/evidence \
      /tmp/flow-support/evidence /tmp/flow-support/review /tmp/flow-support/logs
```

Expected: five paths echoed, no "No such file" errors.

### Task 0.2: Write the baseline extractor

**Files:**
- Create: `scripts/flow_support/extract_baseline.py`

**What it does.** For every `data/field_probe/<connector>.json`:
  1. Load JSON; iterate `flows` dict.
  2. For each flow key, if `flows[key].default.status == "not_implemented"`, record `(connector, probe_key)`.
  3. Cross-reference with `crates/integrations/connector-integration/src/connectors/<connector>.rs`: find the `ConnectorIntegrationV2<<FlowStruct>, ...>` impl block matching the probe key via a hand-maintained mapping table, and confirm the block body is empty (regex: `impl<.*> ConnectorIntegrationV2<FlowStruct, .+> for \w+<T> \{\s*\}`).
  4. Emit `/tmp/flow-support/baseline.jsonl` — one JSON row per in-scope tuple `{connector, rust_flow_struct, probe_key, impl_block_line_range}`.
  5. Emit `/tmp/flow-support/out_of_scope.jsonl` — tuples that were `not_implemented` in probe but had a non-empty impl block (possible bug, needs human look).

- [ ] **Step 1: Write the script**

```python
#!/usr/bin/env python3
"""Extract baseline of in-scope (connector, flow) tuples for reclassification."""
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PROBE_DIR = REPO / "data" / "field_probe"
CONN_DIR = REPO / "crates" / "integrations" / "connector-integration" / "src" / "connectors"

# Authoritative mapping: Rust flow struct -> probe key.
# Verified against scripts/generators/docs/generate.py:_FLOW_KEY_OVERRIDES
# and cryptopay.json / stripe.json.
FLOW_STRUCT_TO_PROBE_KEY = {
    "Authorize": "authorize",
    "PSync": "get",
    "Capture": "capture",
    "Void": "void",
    "VoidPC": "reverse",
    "Refund": "refund",
    "RSync": "refund_get",
    "CreateOrder": "create_order",
    "SetupMandate": "setup_recurring",
    "RepeatPayment": "recurring_charge",
    "MandateRevoke": "recurring_revoke",
    "IncrementalAuthorization": "incremental_authorization",
    "Accept": "dispute_accept",
    "SubmitEvidence": "dispute_submit_evidence",
    "DefendDispute": "dispute_defend",
    "PreAuthenticate": "pre_authenticate",
    "Authenticate": "authenticate",
    "PostAuthenticate": "post_authenticate",
    "ClientAuthenticationToken": "create_client_authentication_token",
    "ServerAuthenticationToken": "create_server_authentication_token",
    "ServerSessionAuthenticationToken": "create_server_session_authentication_token",
    "CreateConnectorCustomer": "create_customer",
    "PaymentMethodToken": "tokenize",
}
PROBE_KEY_TO_FLOW_STRUCT = {v: k for k, v in FLOW_STRUCT_TO_PROBE_KEY.items()}

EMPTY_IMPL_RE = re.compile(
    r"impl<T:[^>]+>\s+ConnectorIntegrationV2<\s*(?P<flow>\w+)\s*,[^{]+?for\s+\w+<T>\s*\{\s*\}",
    re.MULTILINE | re.DOTALL,
)
NONEMPTY_IMPL_RE = re.compile(
    r"impl<T:[^>]+>\s+ConnectorIntegrationV2<\s*(?P<flow>\w+)\s*,[^{]+?for\s+\w+<T>\s*\{(?P<body>[^}]*\S[^}]*)\}",
    re.MULTILINE | re.DOTALL,
)

def load_probe(path):
    with open(path) as f:
        return json.load(f)

def connector_file(connector_name):
    candidate = CONN_DIR / f"{connector_name}.rs"
    return candidate if candidate.exists() else None

def main():
    baseline = []
    out_of_scope = []
    missing_rust = []
    for probe_path in sorted(PROBE_DIR.glob("*.json")):
        connector = probe_path.stem
        probe = load_probe(probe_path)
        flows = probe.get("flows", {})
        rust_path = connector_file(connector)
        if rust_path is None:
            missing_rust.append(connector)
            continue
        rust_src = rust_path.read_text()
        empty_flows = {m.group("flow") for m in EMPTY_IMPL_RE.finditer(rust_src)}
        nonempty_flows = {m.group("flow") for m in NONEMPTY_IMPL_RE.finditer(rust_src)}
        for probe_key, entry in flows.items():
            default = entry.get("default", {})
            if default.get("status") != "not_implemented":
                continue
            flow_struct = PROBE_KEY_TO_FLOW_STRUCT.get(probe_key)
            if flow_struct is None:
                continue  # framework-level probe key, out of scope
            row = {"connector": connector, "rust_flow_struct": flow_struct, "probe_key": probe_key}
            if flow_struct in empty_flows:
                baseline.append(row)
            elif flow_struct in nonempty_flows:
                row["note"] = "non_empty_impl_block_contradicts_not_implemented"
                out_of_scope.append(row)
            else:
                row["note"] = "no_impl_block_found"
                out_of_scope.append(row)

    out_dir = Path("/tmp/flow-support")
    (out_dir / "baseline.jsonl").write_text(
        "\n".join(json.dumps(r) for r in baseline) + "\n"
    )
    (out_dir / "out_of_scope.jsonl").write_text(
        "\n".join(json.dumps(r) for r in out_of_scope) + "\n"
    )
    (out_dir / "missing_rust.jsonl").write_text(
        "\n".join(json.dumps({"connector": c}) for c in missing_rust) + "\n"
    )
    print(f"baseline: {len(baseline)} rows")
    print(f"out_of_scope: {len(out_of_scope)} rows")
    print(f"missing_rust: {len(missing_rust)} connectors")

if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Make executable and dry-run**

```bash
chmod +x /Users/tushar.shukla/Downloads/Work/euler-ucs/hyperswitch-prism/scripts/flow_support/extract_baseline.py
python3 /Users/tushar.shukla/Downloads/Work/euler-ucs/hyperswitch-prism/scripts/flow_support/extract_baseline.py
```

Expected output: three line counts printed, three files at `/tmp/flow-support/baseline.jsonl`, `/tmp/flow-support/out_of_scope.jsonl`, `/tmp/flow-support/missing_rust.jsonl`.

- [ ] **Step 3: Sanity-check baseline**

```bash
wc -l /tmp/flow-support/baseline.jsonl /tmp/flow-support/out_of_scope.jsonl /tmp/flow-support/missing_rust.jsonl
head -3 /tmp/flow-support/baseline.jsonl
# Expect rows like:
# {"connector": "aci", "rust_flow_struct": "DefendDispute", "probe_key": "dispute_defend"}
```

Expected: baseline line count between ~200 and ~1500 (depends on actual state). If 0 or >2000, the extractor has a bug — stop and fix.

- [ ] **Step 4: Verify against cryptopay (PR #1154 ground truth)**

PR #1154 marked exactly these 14 flows for cryptopay. Confirm the extractor did NOT include them (they should now be `not_supported`, not `not_implemented` — unless the PR hasn't merged/wasn't pulled locally yet).

```bash
grep '"connector": "cryptopay"' /tmp/flow-support/baseline.jsonl | jq -r .rust_flow_struct | sort -u
```

Expected: empty output if PR #1154's changes are on `main`. If `cryptopay` shows up with flows, it means the local working tree doesn't have PR #1154's changes — check `git log --oneline -- crates/integrations/connector-integration/src/connectors/cryptopay.rs` and confirm.

- [ ] **Step 5: Commit extractor script**

```bash
cd /Users/tushar.shukla/Downloads/Work/euler-ucs/hyperswitch-prism
git add scripts/flow_support/extract_baseline.py
git commit -m "chore: add flow-support baseline extractor

Enumerates (connector, flow) tuples where the probe JSON shows
not_implemented and the corresponding Rust impl block is empty.
Input to the Phase 1 research agents."
```

- [ ] **Step 6: Human checkpoint — approve baseline**

Show the user:
- Total baseline row count
- Per-connector row-count top 10 and bottom 10 (sanity: stripe should be low; a barely-wired connector should be high)
- Per-flow row-count histogram (sanity: Capture, Refund, Void should dominate; VoidPC and IncrementalAuthorization should be moderate)
- `out_of_scope.jsonl` inspection (any `non_empty_impl_block_contradicts_not_implemented` entries require human look — they indicate a bug in either the probe JSON or the connector.rs)

Blocked gate: user must approve before Phase 1 launches.

---

## Phase 1a — Pilot (3 connectors)

### Task 1.1: Write the research agent prompt file

**Files:**
- Create: `scripts/flow_support/research_agent_prompt.md`

- [ ] **Step 1: Write the prompt file**

```markdown
# Flow Support Research Agent

You are classifying payment flows for connector `{CONNECTOR_NAME}`. Your only job is to produce a JSON evidence pack for the flows listed below. You will write no code.

## Evidence bar (strict)

You may assign one of three verdicts to each flow:

1. **not_supported** — Use ONLY when you have:
   - (GOLD) A direct quote from an official processor doc stating the flow/feature is not offered, OR
   - (BRONZE) A business-model impossibility argument tied to the processor's product (e.g., "Crypto charges settle atomically, so separate Capture is meaningless"; "this is a prepaid e-wallet with no card-rails, so 3DS does not apply"). The argument must be specific to the connector's business model, not generic.

2. **supported_but_not_wired** — The processor DOES offer this flow in their API. Our integration has a stub but hasn't wired it. Must cite the processor's doc page for the feature.

3. **uncertain** — Evidence is thin, terminology is ambiguous, or you couldn't reach the processor's docs. Default for anything below the bar. DO NOT use "not_supported" as a fallback when you're unsure.

## Anti-hallucination rules (violating these is a terminal failure)

- **Fabricating a quote is grounds for rejection.** Every `evidence_quote` you return must appear verbatim on the cited `evidence_url`. A random spot-check will be run; a single fabricated quote invalidates the entire evidence pack.
- If you cannot find `{CONNECTOR_NAME}`'s official API reference, return `uncertain` for every flow and set `docs_access: "unavailable"`.
- Before returning `not_supported` for a flow, you MUST search for at least 3 synonyms of the flow name:
  - Void ≈ reversal ≈ cancel ≈ pre-capture void
  - Refund ≈ credit ≈ reversal (when post-capture) ≈ return
  - Capture ≈ settle ≈ confirm ≈ complete
  - Dispute ≈ chargeback ≈ claim ≈ retrieval ≈ RDR
  - SetupMandate ≈ stored credentials ≈ recurring profile ≈ COF (Credential-on-File) ≈ subscription setup ≈ tokenize-for-MIT
  - MandateRevoke ≈ deactivate mandate ≈ cancel stored credential ≈ cancel subscription
  - RepeatPayment ≈ MIT (Merchant-Initiated Transaction) ≈ recurring charge ≈ subscription bill
  - 3DS (PreAuthenticate/Authenticate/PostAuthenticate) ≈ payer authentication ≈ 3-D Secure ≈ authentication lookup ≈ ACS/enrolment check
  - IncrementalAuthorization ≈ additional auth ≈ auth top-up ≈ partial auth increment
- If the processor has a separate product page for a feature (Stripe Radar, Adyen RevenueProtect, Cybersource Payer Authentication, etc.), that counts as **supported**. Don't return `not_supported` because the core payments doc doesn't mention it.
- If the feature is gated behind merchant tier / enterprise plan / manual activation but exists in the API: that's `supported_but_not_wired` (not `not_supported`).

## In-scope flows for `{CONNECTOR_NAME}`

{FLOW_LIST_JSON}

Return verdicts for exactly these flows. Do not return verdicts for flows not in the list.

## Output format

Write your output to `/tmp/flow-support/evidence/{CONNECTOR_NAME}.json` with this exact schema:

```json
{
  "connector": "{CONNECTOR_NAME}",
  "docs_root_url": "<official docs root>",
  "docs_accessed_at": "2026-04-21",
  "docs_access": "ok",
  "flows": {
    "Capture": {
      "verdict": "not_supported",
      "evidence_type": "gold",
      "evidence_url": "https://<processor-docs>/some-page",
      "evidence_quote": "<verbatim text from that page>",
      "rationale": "One paragraph explaining why this is not_supported."
    },
    "Refund": {
      "verdict": "supported_but_not_wired",
      "evidence_type": null,
      "evidence_url": "https://<processor-docs>/refunds",
      "evidence_quote": "<verbatim text showing the Refund endpoint exists>",
      "rationale": "Processor has a Refund API; our integration has a stub."
    }
  }
}
```

## Tools available

- `WebFetch`, `WebSearch`, `firecrawl:firecrawl` — for crawling processor docs.
- `Read`, `Grep` — for reading our own connector's source if the code comments have hints about which flows were intentionally skipped.

Do not write any code. Do not edit any file outside `/tmp/flow-support/evidence/`. Do not attempt to verify your verdicts against the Rust code (the point of this research is independent of the code).
```

- [ ] **Step 2: Commit the prompt file**

```bash
cd /Users/tushar.shukla/Downloads/Work/euler-ucs/hyperswitch-prism
git add scripts/flow_support/research_agent_prompt.md
git commit -m "chore: add flow-support research agent prompt"
```

### Task 1.2: Write the dispatcher script

**Files:**
- Create: `scripts/flow_support/dispatch_research.py`

- [ ] **Step 1: Write the script**

This script reads `baseline.jsonl`, groups rows by connector, and for each connector produces a ready-to-paste subagent invocation string (description + prompt body). The actual Agent tool calls will be made by the orchestrator (Claude) — the script just generates the payloads.

```python
#!/usr/bin/env python3
"""Generate subagent invocation payloads from baseline.jsonl."""
import json
import sys
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
BASELINE = Path("/tmp/flow-support/baseline.jsonl")
PROMPT = REPO / "scripts" / "flow_support" / "research_agent_prompt.md"
OUT_DIR = Path("/tmp/flow-support/agent_payloads")

def main():
    connectors_to_flows = defaultdict(list)
    with open(BASELINE) as f:
        for line in f:
            if not line.strip():
                continue
            row = json.loads(line)
            connectors_to_flows[row["connector"]].append(row["rust_flow_struct"])

    prompt_template = PROMPT.read_text()
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    filter_connectors = set(sys.argv[1:]) if len(sys.argv) > 1 else None

    for connector, flows in sorted(connectors_to_flows.items()):
        if filter_connectors and connector not in filter_connectors:
            continue
        flow_list_json = json.dumps(sorted(flows), indent=2)
        rendered = (
            prompt_template
            .replace("{CONNECTOR_NAME}", connector)
            .replace("{FLOW_LIST_JSON}", flow_list_json)
        )
        (OUT_DIR / f"{connector}.md").write_text(rendered)

    print(f"Generated {len(list(OUT_DIR.glob('*.md')))} agent payloads in {OUT_DIR}")

if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Generate pilot payloads only**

```bash
python3 /Users/tushar.shukla/Downloads/Work/euler-ucs/hyperswitch-prism/scripts/flow_support/dispatch_research.py cryptopay stripe mifinity
ls /tmp/flow-support/agent_payloads/
```

Expected: three files `cryptopay.md`, `stripe.md`, `mifinity.md`. If `cryptopay.md` is missing, that confirms PR #1154 is already on main and cryptopay has zero in-scope rows — swap it for another calibration connector (e.g., `bambora` or any connector with 6+ in-scope flows and a well-known public doc site).

- [ ] **Step 3: Commit dispatcher**

```bash
cd /Users/tushar.shukla/Downloads/Work/euler-ucs/hyperswitch-prism
git add scripts/flow_support/dispatch_research.py
git commit -m "chore: add flow-support research dispatcher"
```

### Task 1.3: Launch 3 pilot research agents in parallel

- [ ] **Step 1: Launch 3 subagents in a single message (parallel)**

Using the Agent tool with `subagent_type: "general-purpose"`, dispatch all three in one message:

```
description: "Research flows: cryptopay"
prompt: <contents of /tmp/flow-support/agent_payloads/cryptopay.md>

description: "Research flows: stripe"
prompt: <contents of /tmp/flow-support/agent_payloads/stripe.md>

description: "Research flows: mifinity"
prompt: <contents of /tmp/flow-support/agent_payloads/mifinity.md>
```

Each agent runs in foreground so we wait for all three before proceeding.

- [ ] **Step 2: Verify all three evidence packs exist and parse**

```bash
for c in cryptopay stripe mifinity; do
  f=/tmp/flow-support/evidence/$c.json
  if [ -f "$f" ]; then
    python3 -c "import json; d=json.load(open('$f')); print('$c:', len(d['flows']), 'flows,', sum(1 for v in d['flows'].values() if v['verdict']=='not_supported'), 'not_supported,', sum(1 for v in d['flows'].values() if v['verdict']=='supported_but_not_wired'), 'supported_but_not_wired,', sum(1 for v in d['flows'].values() if v['verdict']=='uncertain'), 'uncertain')"
  else
    echo "$c: MISSING"
  fi
done
```

Expected: all three present, each with flow counts matching their `baseline.jsonl` row counts.

### Task 1.4: Calibration audit on pilot

- [ ] **Step 1: Automated quote-verification on 5 random not_supported rows**

```python
#!/usr/bin/env python3
# scripts/flow_support/verify_quotes.py
import json, random, sys
from pathlib import Path
import urllib.request

EVIDENCE_DIR = Path("/tmp/flow-support/evidence")

def fetch(url):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.read().decode("utf-8", errors="ignore")
    except Exception as e:
        return f"__FETCH_ERROR__: {e}"

def main():
    rows = []
    for f in EVIDENCE_DIR.glob("*.json"):
        d = json.load(open(f))
        for flow_name, flow in d["flows"].items():
            if flow["verdict"] == "not_supported" and flow.get("evidence_quote"):
                rows.append((d["connector"], flow_name, flow["evidence_url"], flow["evidence_quote"]))

    sample_n = min(5, len(rows))
    sample = random.sample(rows, sample_n) if rows else []
    fails = 0
    for connector, flow, url, quote in sample:
        page = fetch(url)
        ok = quote[:80] in page  # prefix match to tolerate minor whitespace
        print(f"[{'OK' if ok else 'FAIL'}] {connector}/{flow} — {url}")
        if not ok:
            fails += 1
            print(f"   quote starts: {quote[:80]!r}")
    print(f"\n{sample_n - fails}/{sample_n} quotes verified")
    sys.exit(1 if fails else 0)

if __name__ == "__main__":
    main()
```

Commit it too:

```bash
cd /Users/tushar.shukla/Downloads/Work/euler-ucs/hyperswitch-prism
git add scripts/flow_support/verify_quotes.py
git commit -m "chore: add evidence quote verifier"
```

Then run:

```bash
python3 /Users/tushar.shukla/Downloads/Work/euler-ucs/hyperswitch-prism/scripts/flow_support/verify_quotes.py
```

Expected: `5/5 quotes verified` (or `N/N` if fewer than 5 not_supported rows). Any `FAIL` halts.

- [ ] **Step 2: Manual calibration against cryptopay**

If `cryptopay` is in the pilot (PR #1154 hadn't merged locally when baseline ran), verify:

```bash
jq '.flows | to_entries[] | select(.value.verdict == "not_supported") | .key' /tmp/flow-support/evidence/cryptopay.json | sort
```

Expected: exactly the 14 flows from PR #1154 — `Capture, Void, Refund, RSync, SetupMandate, Accept, SubmitEvidence, DefendDispute, PreAuthenticate, Authenticate, PostAuthenticate, IncrementalAuthorization, MandateRevoke, RepeatPayment`. Any divergence → fix the prompt, re-run cryptopay only, repeat until aligned.

- [ ] **Step 3: Stripe sanity check**

```bash
jq '.flows | to_entries[] | select(.value.verdict == "not_supported") | .key' /tmp/flow-support/evidence/stripe.json
```

Expected: almost empty. Stripe supports virtually every flow. If the agent marked any of Refund/Capture/Void/Dispute/3DS/Mandate as `not_supported`, that's a catastrophic false-negative — revise the prompt to emphasize multi-product search, re-run stripe, repeat.

- [ ] **Step 4: User review gate**

Show the user all three pilot evidence packs (counts + the actual `not_supported` verdicts with quotes). User decides:
- **PASS** → proceed to fan-out.
- **RETRY** → prompt revisions applied, re-run specific pilot connectors.
- **ABORT** → halt the pipeline; re-open the spec.

---

## Phase 1b — Fan-out (remaining 80)

### Task 1.5: Generate all fan-out payloads

- [ ] **Step 1: Generate all remaining agent payloads**

```bash
python3 /Users/tushar.shukla/Downloads/Work/euler-ucs/hyperswitch-prism/scripts/flow_support/dispatch_research.py
ls /tmp/flow-support/agent_payloads/ | wc -l
```

Expected: up to 83 files (one per connector with at least one in-scope row).

### Task 1.6: Fan-out in batches of 20

- [ ] **Step 1: Compute remaining connectors (exclude pilot)**

```bash
ls /tmp/flow-support/agent_payloads/ | grep -v -E '^(cryptopay|stripe|mifinity)\.md$' > /tmp/flow-support/remaining.txt
wc -l /tmp/flow-support/remaining.txt
```

- [ ] **Step 2: Launch batch 1 (first 20)**

In a single message to Claude's Agent tool, dispatch 20 subagents in parallel. Each agent gets its own `subagent_type: "general-purpose"` invocation with `description: "Research flows: <connector>"` and the corresponding payload. **All 20 in one message to run concurrently.**

Wait for all 20 to complete.

- [ ] **Step 3: Verify batch 1**

```bash
for c in $(sed -n '1,20p' /tmp/flow-support/remaining.txt | sed 's/\.md$//'); do
  if [ ! -f /tmp/flow-support/evidence/$c.json ]; then
    echo "MISSING: $c"
  fi
done
python3 /Users/tushar.shukla/Downloads/Work/euler-ucs/hyperswitch-prism/scripts/flow_support/verify_quotes.py
```

Expected: no MISSING lines; quote verifier passes.

- [ ] **Step 4: Launch batches 2, 3, 4**

Repeat Steps 2-3 for rows 21-40, 41-60, 61-80.

- [ ] **Step 5: Final quote-verification sweep**

```bash
python3 /Users/tushar.shukla/Downloads/Work/euler-ucs/hyperswitch-prism/scripts/flow_support/verify_quotes.py
```

Expected: clean pass (or `N/5` where all N sampled verify).

---

## Phase 2 — Human review gate

### Task 2.1: Generate review markdown

**Files:**
- Create: `scripts/flow_support/generate_review.py`

- [ ] **Step 1: Write the script**

```python
#!/usr/bin/env python3
"""Generate review.md with checkbox-per-not_supported row."""
import json
from pathlib import Path

EVIDENCE_DIR = Path("/tmp/flow-support/evidence")
OUT = Path("/tmp/flow-support/review.md")

def main():
    not_supported = []
    summary = {"supported_but_not_wired": 0, "uncertain": 0, "docs_unavailable": 0}

    for f in sorted(EVIDENCE_DIR.glob("*.json")):
        d = json.load(open(f))
        if d.get("docs_access") == "unavailable":
            summary["docs_unavailable"] += 1
            continue
        for flow_name, flow in d["flows"].items():
            if flow["verdict"] == "not_supported":
                not_supported.append((d["connector"], flow_name, flow))
            else:
                summary[flow["verdict"]] = summary.get(flow["verdict"], 0) + 1

    lines = [
        "# Flow-Support Classification Review",
        "",
        f"Total not_supported rows to review: **{len(not_supported)}**",
        "",
        "Instructions: tick `[x]` on rows you approve. Leave `[ ]` on anything suspicious — those rows stay `not_implemented`.",
        "",
        "---",
        "",
    ]
    current_connector = None
    for connector, flow_name, flow in not_supported:
        if connector != current_connector:
            lines.append(f"\n## {connector}\n")
            current_connector = connector
        lines.append(f"### {connector} → {flow_name}")
        lines.append(f"- **verdict:** not_supported ({flow['evidence_type']})")
        lines.append(f"- **url:** {flow['evidence_url']}")
        if flow.get("evidence_quote"):
            lines.append(f"- **quote:** > {flow['evidence_quote']}")
        lines.append(f"- **rationale:** {flow['rationale']}")
        lines.append(f"- [ ] APPROVE")
        lines.append("")

    lines.append("---")
    lines.append("## Summary (not shown inline)")
    lines.append(f"- supported_but_not_wired: {summary['supported_but_not_wired']}")
    lines.append(f"- uncertain: {summary['uncertain']}")
    lines.append(f"- docs_unavailable connectors: {summary['docs_unavailable']}")

    OUT.write_text("\n".join(lines))
    print(f"Wrote {OUT} — {len(not_supported)} not_supported rows")

if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Run it**

```bash
python3 /Users/tushar.shukla/Downloads/Work/euler-ucs/hyperswitch-prism/scripts/flow_support/generate_review.py
wc -l /tmp/flow-support/review.md
```

- [ ] **Step 3: Commit the generator**

```bash
cd /Users/tushar.shukla/Downloads/Work/euler-ucs/hyperswitch-prism
git add scripts/flow_support/generate_review.py
git commit -m "chore: add review markdown generator"
```

### Task 2.2: User reviews

- [ ] **Step 1: Tell user where to find the file**

Output the path `/tmp/flow-support/review.md` to the user. Tell them to tick `[x]` on approved rows, save, then say "done".

### Task 2.3: Parse approvals

**Files:**
- Create: `scripts/flow_support/parse_approvals.py`

- [ ] **Step 1: Write the script**

```python
#!/usr/bin/env python3
"""Parse review.md and emit approved.jsonl."""
import json
import re
from pathlib import Path

REVIEW = Path("/tmp/flow-support/review.md")
OUT = Path("/tmp/flow-support/approved.jsonl")

HEADING = re.compile(r"^### (?P<connector>\S+) → (?P<flow>\S+)$")
APPROVE_LINE = re.compile(r"^- \[([ xX])\] APPROVE")

def main():
    approved = []
    current = None
    lines = REVIEW.read_text().splitlines()
    for line in lines:
        m = HEADING.match(line)
        if m:
            current = (m.group("connector"), m.group("flow"))
            continue
        m = APPROVE_LINE.match(line)
        if m and current and m.group(1).lower() == "x":
            connector, flow = current
            approved.append({"connector": connector, "rust_flow_struct": flow})
            current = None

    OUT.write_text("\n".join(json.dumps(r) for r in approved) + "\n")
    print(f"Approved: {len(approved)} rows → {OUT}")

if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Run and verify**

```bash
python3 /Users/tushar.shukla/Downloads/Work/euler-ucs/hyperswitch-prism/scripts/flow_support/parse_approvals.py
head -5 /tmp/flow-support/approved.jsonl
```

- [ ] **Step 3: Commit parser**

```bash
cd /Users/tushar.shukla/Downloads/Work/euler-ucs/hyperswitch-prism
git add scripts/flow_support/parse_approvals.py
git commit -m "chore: add review approval parser"
```

### Task 2.4: Pre-Phase-3 audit

- [ ] **Step 1: Confirm approved count vs expected**

```bash
wc -l /tmp/flow-support/approved.jsonl
```

If `approved.jsonl` is significantly smaller than the `not_supported` count in `review.md`, ask the user whether the low approval rate is intentional (it's their prerogative) or whether they intended to approve more.

- [ ] **Step 2: Show user approved-row summary and ask for final go-ahead**

```bash
jq -r '.connector' /tmp/flow-support/approved.jsonl | sort | uniq -c | sort -rn
```

Show the user the per-connector counts. User says "go" → Phase 3 starts.

---

## Phase 3 — Deterministic code-write

### Task 3.1: Create feature branch

- [ ] **Step 1: Branch from current main**

```bash
cd /Users/tushar.shukla/Downloads/Work/euler-ucs/hyperswitch-prism
git fetch origin
git checkout -b feat/flow-support-classification origin/main
git status
```

Expected: clean working tree, on new branch.

### Task 3.2: Connector-brand-name lookup

**Files:**
- Create: `scripts/flow_support/connector_brand.py`

The `FlowNotSupported { connector: "CryptoPay" }` uses the brand casing, not the file name. We need a reliable way to go from `cryptopay` → `"CryptoPay"`.

- [ ] **Step 1: Extract brand map from source**

```python
#!/usr/bin/env python3
"""Extract brand name for each connector from its ConnectorCommon::id()."""
import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CONN_DIR = REPO / "crates" / "integrations" / "connector-integration" / "src" / "connectors"

ID_RE = re.compile(
    r'fn id\(&self\) -> &\'static str \{\s*"([^"]+)"\s*\}',
    re.MULTILINE | re.DOTALL,
)

def main():
    brand_map = {}
    for p in sorted(CONN_DIR.glob("*.rs")):
        connector = p.stem
        src = p.read_text()
        m = ID_RE.search(src)
        if m:
            brand_map[connector] = m.group(1)
        else:
            brand_map[connector] = connector  # fallback — may need hand-fix
    out = Path("/tmp/flow-support/brand_map.json")
    out.write_text(json.dumps(brand_map, indent=2, sort_keys=True))
    missing = [k for k, v in brand_map.items() if v == k]
    print(f"Extracted {len(brand_map)} brands; {len(missing)} fell back to file name: {missing[:10]}")

if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Run and inspect fallbacks**

```bash
python3 /Users/tushar.shukla/Downloads/Work/euler-ucs/hyperswitch-prism/scripts/flow_support/connector_brand.py
jq '.cryptopay, .stripe, .aci' /tmp/flow-support/brand_map.json
```

Expected: `"CryptoPay"`, `"Stripe"`, `"Aci"`. If any common brand has wrong casing (e.g., `"aci"` instead of `"Aci"`), add a hand-curated override file at `scripts/flow_support/brand_overrides.json` and have the script merge it.

- [ ] **Step 3: Commit brand extractor**

```bash
cd /Users/tushar.shukla/Downloads/Work/euler-ucs/hyperswitch-prism
git add scripts/flow_support/connector_brand.py
git commit -m "chore: add connector brand-name extractor"
```

### Task 3.3: Write the code-write transformer

**Files:**
- Create: `scripts/flow_support/apply_classifications.py`

This is the single biggest script. It reads `approved.jsonl` and `brand_map.json`, then for each row does both edits: `.rs` injection and `.json` flip.

- [ ] **Step 1: Write the transformer**

```python
#!/usr/bin/env python3
"""Apply approved flow-support classifications to connector.rs and field_probe JSON."""
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CONN_DIR = REPO / "crates" / "integrations" / "connector-integration" / "src" / "connectors"
PROBE_DIR = REPO / "data" / "field_probe"
APPROVED = Path("/tmp/flow-support/approved.jsonl")
BRAND_MAP = json.loads(Path("/tmp/flow-support/brand_map.json").read_text())
EVIDENCE_DIR = Path("/tmp/flow-support/evidence")

FLOW_STRUCT_TO_PROBE_KEY = {
    "Authorize": "authorize", "PSync": "get", "Capture": "capture", "Void": "void",
    "VoidPC": "reverse", "Refund": "refund", "RSync": "refund_get",
    "CreateOrder": "create_order", "SetupMandate": "setup_recurring",
    "RepeatPayment": "recurring_charge", "MandateRevoke": "recurring_revoke",
    "IncrementalAuthorization": "incremental_authorization",
    "Accept": "dispute_accept", "SubmitEvidence": "dispute_submit_evidence",
    "DefendDispute": "dispute_defend", "PreAuthenticate": "pre_authenticate",
    "Authenticate": "authenticate", "PostAuthenticate": "post_authenticate",
    "ClientAuthenticationToken": "create_client_authentication_token",
    "ServerAuthenticationToken": "create_server_authentication_token",
    "ServerSessionAuthenticationToken": "create_server_session_authentication_token",
    "CreateConnectorCustomer": "create_customer",
    "PaymentMethodToken": "tokenize",
}

IMPL_BLOCK_RE = re.compile(
    r"(?P<header>impl<T:[^>]+>\s+ConnectorIntegrationV2<\s*(?P<flow>\w+)\s*,(?P<rest_types>[^{]+?)for\s+(?P<conn>\w+)<T>\s*\{)"
    r"(?P<body>\s*)\}",
    re.MULTILINE | re.DOTALL,
)

GET_URL_TEMPLATE = """
    fn get_url(
        &self,
        _req: &RouterDataV2<{flow},{rest_types}>,
    ) -> CustomResult<String, IntegrationError> {{
        Err(report!(IntegrationError::FlowNotSupported {{
            flow: "{flow}".to_string(),
            connector: "{brand}".to_string(),
            context: Default::default(),
        }}))
    }}
"""

def patch_rs(connector, flow_struct_set, brand):
    path = CONN_DIR / f"{connector}.rs"
    src = path.read_text()
    new_src = src
    patched = []
    skipped = []

    def replace(m):
        flow = m.group("flow")
        if flow not in flow_struct_set:
            return m.group(0)
        rest_types = m.group("rest_types").rstrip()
        body = m.group("body")
        if body.strip():
            skipped.append((flow, "non_empty_body"))
            return m.group(0)
        injection = GET_URL_TEMPLATE.format(flow=flow, rest_types=rest_types, brand=brand)
        patched.append(flow)
        return m.group("header") + injection + "}"

    new_src = IMPL_BLOCK_RE.sub(replace, src)

    missing = flow_struct_set - set(patched) - {s[0] for s in skipped}
    if new_src != src:
        path.write_text(new_src)
    return patched, skipped, missing

def patch_probe(connector, flow_struct_set, brand):
    path = PROBE_DIR / f"{connector}.json"
    data = json.loads(path.read_text())
    flows = data.get("flows", {})
    patched = []
    for flow_struct in flow_struct_set:
        probe_key = FLOW_STRUCT_TO_PROBE_KEY.get(flow_struct)
        if probe_key is None:
            continue
        entry = flows.get(probe_key)
        if not entry:
            continue
        default = entry.get("default", {})
        if default.get("status") != "not_implemented":
            continue
        default["status"] = "not_supported"
        default["error"] = f"{flow_struct} flow not supported by {brand} connector"
        patched.append(flow_struct)
    if patched:
        # Preserve key order & indentation as much as possible.
        path.write_text(json.dumps(data, indent=2) + "\n")
    return patched

def main():
    by_connector = defaultdict(set)
    with open(APPROVED) as f:
        for line in f:
            if not line.strip():
                continue
            row = json.loads(line)
            by_connector[row["connector"]].add(row["rust_flow_struct"])

    summary = {}
    for connector, flows in sorted(by_connector.items()):
        brand = BRAND_MAP.get(connector, connector.capitalize())
        rs_patched, rs_skipped, rs_missing = patch_rs(connector, flows, brand)
        probe_patched = patch_probe(connector, flows, brand)
        summary[connector] = {
            "rs_patched": rs_patched,
            "rs_skipped": rs_skipped,
            "rs_missing": list(rs_missing),
            "probe_patched": probe_patched,
        }

    out = Path("/tmp/flow-support/apply_summary.json")
    out.write_text(json.dumps(summary, indent=2, sort_keys=True))
    print(f"Applied classifications for {len(summary)} connectors. Summary: {out}")

if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Dry-run on pilot first**

```bash
# Filter approved.jsonl to pilot connectors only, back up, overlay.
jq -c 'select(.connector == "cryptopay" or .connector == "stripe" or .connector == "mifinity")' \
  /tmp/flow-support/approved.jsonl > /tmp/flow-support/approved_pilot.jsonl
cp /tmp/flow-support/approved.jsonl /tmp/flow-support/approved_full.jsonl.bak
cp /tmp/flow-support/approved_pilot.jsonl /tmp/flow-support/approved.jsonl

python3 /Users/tushar.shukla/Downloads/Work/euler-ucs/hyperswitch-prism/scripts/flow_support/apply_classifications.py
cat /tmp/flow-support/apply_summary.json
```

- [ ] **Step 3: Verify pilot edits locally**

```bash
cd /Users/tushar.shukla/Downloads/Work/euler-ucs/hyperswitch-prism
git diff --stat
cargo check -p connector-integration 2>&1 | tail -20
cargo fmt --check -p connector-integration 2>&1 | tail -5
for c in cryptopay stripe mifinity; do
  jq empty data/field_probe/$c.json && echo "$c.json OK"
done
```

Expected: `cargo check` passes, `cargo fmt --check` clean, all three JSON files valid.

- [ ] **Step 4: Revert pilot dry-run**

```bash
cd /Users/tushar.shukla/Downloads/Work/euler-ucs/hyperswitch-prism
git checkout -- crates/integrations/connector-integration/src/connectors data/field_probe
cp /tmp/flow-support/approved_full.jsonl.bak /tmp/flow-support/approved.jsonl
```

- [ ] **Step 5: Commit transformer**

```bash
cd /Users/tushar.shukla/Downloads/Work/euler-ucs/hyperswitch-prism
git add scripts/flow_support/apply_classifications.py
git commit -m "chore: add classification transformer script"
```

### Task 3.4: Per-connector commit loop

- [ ] **Step 1: Write the commit loop**

Create `scripts/flow_support/commit_loop.sh`:

```bash
#!/usr/bin/env bash
# Apply approved classifications one connector at a time, committing after each
# and running safety gates. Halts on any gate failure.
set -euo pipefail

REPO="/Users/tushar.shukla/Downloads/Work/euler-ucs/hyperswitch-prism"
APPROVED="/tmp/flow-support/approved.jsonl"
EVIDENCE_DIR="/tmp/flow-support/evidence"
cd "$REPO"

connectors=$(jq -r '.connector' "$APPROVED" | sort -u)
echo "Connectors to commit: $(echo "$connectors" | wc -l)"

for connector in $connectors; do
    echo "=== $connector ==="
    # Isolate approved rows for just this connector
    jq -c "select(.connector == \"$connector\")" "$APPROVED" > /tmp/flow-support/approved_one.jsonl
    cp "$APPROVED" /tmp/flow-support/approved_all.backup
    cp /tmp/flow-support/approved_one.jsonl "$APPROVED"

    python3 "$REPO/scripts/flow_support/apply_classifications.py"

    # Restore full approved file for next iteration
    cp /tmp/flow-support/approved_all.backup "$APPROVED"

    # Gate 1: cargo check
    if ! cargo check -p connector-integration 2>/tmp/flow-support/logs/check-$connector.log; then
        echo "FAIL: cargo check failed for $connector"
        cat /tmp/flow-support/logs/check-$connector.log
        git checkout -- crates data
        exit 1
    fi

    # Gate 2: cargo fmt --check
    if ! cargo fmt -p connector-integration -- --check >/dev/null 2>&1; then
        cargo fmt -p connector-integration
    fi

    # Gate 3: jq empty on probe
    jq empty "data/field_probe/$connector.json"

    # Copy evidence pack into repo
    cp "$EVIDENCE_DIR/$connector.json" "docs/superpowers/evidence/$connector.json"

    # Build commit message with evidence summary
    num_flows=$(jq "length" /tmp/flow-support/approved_one.jsonl)
    flows_list=$(jq -r '.rust_flow_struct' /tmp/flow-support/approved_one.jsonl | paste -sd, -)

    git add "crates/integrations/connector-integration/src/connectors/$connector.rs" \
            "data/field_probe/$connector.json" \
            "docs/superpowers/evidence/$connector.json"

    git commit -m "fix(connector): reclassify unsupported flows for $connector

Marks $num_flows flows as FlowNotSupported based on official documentation.

Flows reclassified: $flows_list

Evidence pack: docs/superpowers/evidence/$connector.json"
done

echo "All connector commits complete."
```

- [ ] **Step 2: Commit the loop script**

```bash
cd /Users/tushar.shukla/Downloads/Work/euler-ucs/hyperswitch-prism
chmod +x scripts/flow_support/commit_loop.sh
git add scripts/flow_support/commit_loop.sh
git commit -m "chore: add per-connector commit loop"
```

- [ ] **Step 3: Human checkpoint — first three commits only**

Modify the loop to exit after processing the first three connectors (or run it manually). Show the user:

```bash
cd /Users/tushar.shukla/Downloads/Work/euler-ucs/hyperswitch-prism
git log --oneline -5
git show --stat HEAD
git show --stat HEAD~1
git show --stat HEAD~2
```

User inspects the first three connector commits. Approves → continue the loop for the remaining connectors. Rejects → revert with `git reset --hard` and investigate.

- [ ] **Step 4: Run to completion**

```bash
cd /Users/tushar.shukla/Downloads/Work/euler-ucs/hyperswitch-prism
./scripts/flow_support/commit_loop.sh 2>&1 | tee /tmp/flow-support/logs/commit_loop.log
```

Expected: one commit per approved-connector, no halts.

### Task 3.5: Regenerate docs and final verification

- [ ] **Step 1: Regenerate dashboard docs**

```bash
cd /Users/tushar.shukla/Downloads/Work/euler-ucs/hyperswitch-prism
python3 scripts/generators/docs/generate.py
git status
git diff --stat docs-generated/
```

Expected: diffs only in `docs-generated/` (per-connector .md + all_connector.md), no other files touched.

- [ ] **Step 2: Commit regenerated docs**

```bash
git add docs-generated/
git commit -m "docs: regenerate dashboard after flow-support reclassification"
```

- [ ] **Step 3: Final full-workspace check**

```bash
cargo check -p connector-integration 2>&1 | tail -5
cargo fmt --check -p connector-integration 2>&1 | tail -5
for f in data/field_probe/*.json; do jq empty "$f" || echo "BAD: $f"; done
```

Expected: all three clean.

### Task 3.6: Open the mega-PR

- [ ] **Step 1: Push branch**

```bash
cd /Users/tushar.shukla/Downloads/Work/euler-ucs/hyperswitch-prism
git push -u origin feat/flow-support-classification
```

- [ ] **Step 2: Build PR description**

Create PR body text:

```markdown
## Summary

Reclassifies flows across <N> connectors from `not_implemented` to `not_supported` where the processor's official API does not offer the feature. Follows the pattern established by PR #1154 (CryptoPay).

## Methodology

- Design: `docs/superpowers/specs/2026-04-21-flow-support-classification-design.md`
- Evidence packs: `docs/superpowers/evidence/<connector>.json` (one per reclassified connector, committed in this PR)
- Verdict bar: GOLD (direct quote from processor docs) or BRONZE (business-model impossibility argument tied to the processor's product).
- Every `not_supported` verdict in the committed diffs has a traceable evidence pack. Flows where evidence was thin remain `not_implemented`.

## What reviewers should check

- Walk the per-connector commits. Each commit has the reclassified flows in the message body and the full evidence pack in `docs/superpowers/evidence/<connector>.json`.
- To reject a single connector's classifications, `git revert <sha>` on that connector's commit — the remaining commits are independent.

## Test plan

- [x] `cargo check -p connector-integration` passes.
- [x] `cargo fmt --check -p connector-integration` clean.
- [x] All `data/field_probe/*.json` parse with `jq empty`.
- [x] `scripts/generators/docs/generate.py` regenerated dashboard markdown without errors.
- [ ] Sample run: verify a previously-`not_implemented` flow (e.g., `<connector>/Refund`) now returns `FlowNotSupported` error on gRPC call.
```

- [ ] **Step 3: Open PR**

```bash
cd /Users/tushar.shukla/Downloads/Work/euler-ucs/hyperswitch-prism
gh pr create --title "fix(connector): reclassify unsupported flows across connectors" \
             --body-file /tmp/flow-support/pr_body.md \
             --base main
```

- [ ] **Step 4: Surface PR URL to user and close out**

Return the PR URL. Completion criteria: PR is open, CI is running, evidence packs are in the tree.

---

## Rollback plan

If the mega-PR has systematic problems:

1. **Drop individual connector commits** — `git rebase -i` and drop the bad commits, force-push.
2. **Scrap the PR, keep scripts** — the scripts under `scripts/flow_support/` + `docs/superpowers/evidence/` have independent value. Close the PR, land the scripts + evidence as a separate smaller PR, re-run classifications with a revised prompt against the same baseline.
3. **Full abort** — `git push --delete origin feat/flow-support-classification` + local branch delete. Evidence packs remain in `/tmp/flow-support/` for the next attempt.

## Residual risk accepted

- Review fatigue on 500–1500 rows. Mitigation: pilot's `supported_but_not_wired` count hints at the agent's quality; if pilot is clean, fan-out can be largely bulk-approved.
- Payout classification quality. If pilot/early fan-out shows systematic bad payout verdicts, drop payouts from `approved.jsonl` before Phase 3 and handle in a follow-up.
- Mega-PR size is unreviewable as a single diff. Per-connector commits mitigate via walk-commit-by-commit, but it's still ~20k lines in total.
