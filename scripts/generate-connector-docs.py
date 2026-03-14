#!/usr/bin/env python3
"""
Connector Documentation Generator

Generates connector documentation from field-probe JSON output.

Usage:
    python3 scripts/generate-connector-docs.py stripe adyen
    python3 scripts/generate-connector-docs.py --all
    python3 scripts/generate-connector-docs.py --list
    python3 scripts/generate-connector-docs.py --all-connectors-doc

How it works:
  1. Loads probe data from data/{connector}.json
  2. Flow metadata (service names, RPC names, descriptions) comes from probe.json
  3. Merges with connector-annotations/{name}.yaml for sample payloads and human notes
  4. Outputs docs/connectors/{name}.md

To add docs for a new connector:
  - Run field-probe to generate probe data: cd backend/field-probe && cargo r
  - Create scripts/connector-annotations/{name}.yaml with sample payloads
  - Run: python3 scripts/generate-connector-docs.py {name}
"""

import sys
import json
from pathlib import Path
from typing import Optional

import sdk_snippets

# ─── Probe Data ───────────────────────────────────────────────────────────────

# Flows that have PM-specific probe results (vs flows that only have a 'default' key)
_PM_AWARE_FLOWS = frozenset(["authorize"])

# Global flow metadata loaded from probe.json (populated by load_probe_data)
_FLOW_METADATA: list[dict] = []

# Global message schemas from manifest (populated by load_probe_data)
_MESSAGE_SCHEMAS: dict = {}

# Global probe data indexed by connector name (populated by load_probe_data)
_PROBE_DATA: dict[str, dict] = {}


def get_flow_metadata() -> dict[str, dict]:
    """
    Get flow metadata as a dict keyed by flow_key.
    Returns {flow_key: {service_rpc, description, service_name, rpc_name}}
    """
    return {m["flow_key"]: m for m in _FLOW_METADATA}


def get_proto_flow_definitions() -> dict[str, tuple[str, str, str]]:
    """
    Get flow definitions in legacy format for compatibility.
    Returns {flow_key: (service_name, rpc_name, description)}
    """
    return {
        m["flow_key"]: (m["service_name"], m["rpc_name"], m["description"])
        for m in _FLOW_METADATA
    }


# Build reverse mapping from flow metadata (populated after load_probe_data)
def _build_flow_name_to_key_mapping() -> dict[str, str]:
    """
    Build mapping from RPC name to flow_key using loaded flow_metadata.
    E.g., "Authorize" -> "authorize", "Get" -> "get"
    """
    mapping = {}
    for m in _FLOW_METADATA:
        rpc_name = m.get("rpc_name", "")
        flow_key = m.get("flow_key", "")
        if rpc_name and flow_key:
            mapping[rpc_name] = flow_key
    return mapping


def get_flow_name_to_key() -> dict[str, str]:
    """Get the flow name to probe key mapping from loaded metadata."""
    if not hasattr(get_flow_name_to_key, '_cache'):
        get_flow_name_to_key._cache = _build_flow_name_to_key_mapping()
    return get_flow_name_to_key._cache

# Mapping from probe PM key to display name (order matters for table columns)
_PROBE_PM_DISPLAY: dict[str, str] = {
    "Card":           "Card",
    "GooglePay":      "Google Pay",
    "ApplePay":       "Apple Pay",
    "Sepa":           "SEPA",
    "Bacs":           "BACS",
    "Ach":            "ACH",
    "Becs":           "BECS",
    "Ideal":          "iDEAL",
    "PaypalRedirect": "PayPal",
    "Blik":           "BLIK",
    "Klarna":         "Klarna",
    "Afterpay":       "Afterpay",
    "UpiCollect":     "UPI",
    "Affirm":         "Affirm",
    "SamsungPay":     "Samsung Pay",
}

# Mapping from sample title keywords → probe PM key (for filtering samples)
_SAMPLE_TITLE_TO_PM: list[tuple[str, str]] = [
    ("google pay",  "GooglePay"),
    ("apple pay",   "ApplePay"),
    ("sepa",        "Sepa"),
    ("bacs",        "Bacs"),
    ("ach",         "Ach"),
    ("becs",        "Becs"),
    ("card",        "Card"),
]


def load_probe_data(probe_path: Optional[Path]) -> dict[str, dict]:
    """
    Load probe JSON and index by connector name.

    Expects the split format: data/field_probe/ directory with manifest.json
    and per-connector {connector}.json files.

    Returns {connector_name: connector_data} dict.
    """
    global _FLOW_METADATA, _MESSAGE_SCHEMAS, _PROBE_DATA

    if probe_path is None:
        return {}

    probe_dir = probe_path if probe_path.is_dir() else probe_path
    manifest_path = probe_dir / "manifest.json"

    if not manifest_path.exists():
        print(f"Warning: manifest.json not found in {probe_dir}. Run field-probe first.", file=sys.stderr)
        return {}

    try:
        with open(manifest_path, encoding="utf-8") as f:
            manifest = json.load(f)
        _FLOW_METADATA = manifest.get("flow_metadata", [])
        _MESSAGE_SCHEMAS = manifest.get("message_schemas", {})
        connector_names = manifest.get("connectors", [])

        _PROBE_DATA = {}
        for conn_name in connector_names:
            conn_file = probe_dir / f"{conn_name}.json"
            if conn_file.exists():
                try:
                    with open(conn_file, encoding="utf-8") as f:
                        conn_data = json.load(f)
                    _PROBE_DATA[conn_name] = conn_data
                except Exception as exc:
                    print(f"Warning: failed to load {conn_file}: {exc}", file=sys.stderr)

        return _PROBE_DATA
    except Exception as exc:
        print(f"Warning: failed to load manifest: {exc}", file=sys.stderr)
        return {}


def _probe_pm_support(probe_connector: dict, flow_key: str) -> Optional[dict[str, bool]]:
    """
    Return {pm_key: supported} for a flow that has PM-specific probe results.
    Returns None for flows that only have a 'default' key (no PM breakdown).
    """
    if not flow_key:
        return None
    pms = probe_connector.get("flows", {}).get(flow_key, {})
    if not pms or set(pms.keys()) == {"default"}:
        return None
    return {pm: pms[pm]["status"] == "supported" for pm in _PROBE_PM_DISPLAY if pm in pms}


# Human-readable label per PM key used as the sample heading
_PROBE_PM_LABELS: dict[str, str] = {
    "Card":          "Card (Raw PAN)",
    "GooglePay":     "Google Pay",
    "ApplePay":      "Apple Pay",
    "Sepa":          "SEPA Direct Debit",
    "Bacs":          "BACS Direct Debit",
    "Ach":           "ACH Direct Debit",
    "Becs":          "BECS Direct Debit",
    "Ideal":         "iDEAL",
    "PaypalRedirect":"PayPal Redirect",
    "Blik":          "BLIK",
    "Klarna":        "Klarna",
    "Afterpay":      "Afterpay / Clearpay",
}


def _probe_samples_for_flow(probe_connector: dict, flow_key: str) -> list[tuple[str, dict]]:
    """
    Return [(label, proto_request)] from probe data for a flow.

    - Authorize: one sample per supported PM type (in _PROBE_PM_LABELS order).
    - Other flows: single sample from the "default" entry if supported.
    Returns empty list when no probe data is available.
    """
    if not flow_key:
        return []
    pms = probe_connector.get("flows", {}).get(flow_key, {})
    if not pms:
        return []

    if set(pms.keys()) == {"default"}:
        # Non-authorize flow — single payload, no PM breakdown
        entry = pms["default"]
        if entry.get("status") == "supported" and "proto_request" in entry:
            # Include even if proto_request is empty (no required fields)
            return [("Example Request", entry["proto_request"])]
        return []

    # Authorize flow — one sample per supported PM type
    result = []
    for pm_key, label in _PROBE_PM_LABELS.items():
        entry = pms.get(pm_key, {})
        if entry.get("status") == "supported" and entry.get("proto_request"):
            result.append((label, entry["proto_request"]))
    return result


def _sample_pm_key(title: str) -> Optional[str]:
    """Map a sample title to a probe PM key."""
    lower = title.lower()
    for keyword, pm_key in _SAMPLE_TITLE_TO_PM:
        if keyword in lower:
            return pm_key
    return None

try:
    import yaml
except ImportError:
    yaml = None  # Handled gracefully below

# ─── Paths ────────────────────────────────────────────────────────────────────

REPO_ROOT = Path(__file__).parent.parent
DOCS_DIR = REPO_ROOT / "docs/connectors"
ANNOTATIONS_DIR = Path(__file__).parent / "connector-annotations"
PROTO_DIR = REPO_ROOT / "backend/grpc-api-types/proto"

# Category order for grouping flows in documentation
CATEGORY_ORDER = ["Payments", "Refunds", "Mandates", "Customers", "Disputes", "Authentication", "Session", "Other"]

# ─── Annotation Loading ───────────────────────────────────────────────────────

def _load_yaml(path: Path) -> dict:
    """Load a YAML file, returning {} on missing or parse error."""
    if yaml is None or not path.exists():
        return {}
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        print(f"  Warning: failed to parse {path}: {exc}", file=sys.stderr)
        return {}


def load_annotations(connector_name: str) -> dict:
    """
    Load connector-specific annotations (display_name, overview, credentials,
    test_credentials, and per-flow notes/required_fields).

    Sample payloads are sourced exclusively from probe data (data/field_probe/),
    not from annotation files.
    """
    for ext in ("yaml", "yml"):
        data = _load_yaml(ANNOTATIONS_DIR / f"{connector_name}.{ext}")
        if data:
            return data
    return {}


# ─── Display Name ─────────────────────────────────────────────────────────────

_DISPLAY_NAMES = {
    "stripe": "Stripe",
    "adyen": "Adyen",
    "razorpay": "Razorpay",
    "razorpayv2": "Razorpay V2",
    "authorizedotnet": "Authorize.net",
    "braintree": "Braintree",
    "cybersource": "CyberSource",
    "checkout": "Checkout.com",
    "payu": "PayU",
    "novalnet": "Novalnet",
    "nexinets": "Nexinets",
    "noon": "Noon",
    "fiserv": "Fiserv",
    "elavon": "Elavon",
    "xendit": "Xendit",
    "mifinity": "MiFinity",
    "phonepe": "PhonePe",
    "cashfree": "Cashfree",
    "paytm": "Paytm",
    "cashtocode": "CashtoCode",
    "volt": "Volt",
    "dlocal": "dLocal",
    "helcim": "Helcim",
    "placetopay": "PlacetoPay",
    "rapyd": "Rapyd",
    "aci": "ACI",
    "trustpay": "TrustPay",
    "fiuu": "Fiuu",
    "calida": "Calida",
    "cryptopay": "CryptoPay",
}


def display_name(connector_name: str, annotations: dict) -> str:
    if annotations.get("display_name"):
        return annotations["display_name"]
    return _DISPLAY_NAMES.get(connector_name, connector_name.replace("_", " ").title())


# ─── Markdown Generation ──────────────────────────────────────────────────────

def _json_block(data) -> str:
    return "```json\n" + json.dumps(data, indent=2) + "\n```"


def get_flows_from_probe(probe_connector: dict) -> list[str]:
    """Extract list of supported flow keys from probe data."""
    return list(probe_connector.get("flows", {}).keys())


def get_flow_meta(flow_key: str) -> dict:
    """Get flow metadata by flow_key from loaded probe.json data."""
    flow_metadata = get_flow_metadata()
    return flow_metadata.get(flow_key, {})


def generate_connector_doc(connector_name: str, probe_data: Optional[dict] = None) -> Optional[str]:
    """Generate complete markdown documentation for a connector."""
    probe_connector = (probe_data or {}).get(connector_name, {})
    
    # Get flows from probe data
    flows = get_flows_from_probe(probe_connector)
    if not flows:
        print(f"  No flows found for '{connector_name}' – skipping.", file=sys.stderr)
        return None

    ann = load_annotations(connector_name)
    name = display_name(connector_name, ann)

    out: list[str] = []
    a = out.append  # shorthand

    # ── Front-matter comment ────────────────────────────────────────────────
    a(f"# {name}")
    a("")
    a("<!--")
    a("This file is auto-generated. Do not edit by hand.")
    a(f"Source: data/field_probe/{connector_name}.json")
    a(f"Regenerate: python3 scripts/generate-connector-docs.py {connector_name}")
    a("-->")
    a("")

    # ── Overview ────────────────────────────────────────────────────────────
    if ann.get("overview"):
        a("## Overview")
        a("")
        a(ann["overview"].strip())
        a("")

    # ── Credentials ─────────────────────────────────────────────────────────
    if ann.get("credentials"):
        a("## Required Credentials")
        a("")
        a("| Field | Description |")
        a("|-------|-------------|")
        for c in ann["credentials"]:
            a(f"| `{c['name']}` | {c['description']} |")
        a("")

    # ── SDK Configuration (once per connector) ──────────────────────────────
    for line in sdk_snippets.render_config_section(connector_name):
        a(line)

    # ── Flow summary table ───────────────────────────────────────────────────
    a("## Implemented Flows")
    a("")
    a("| Flow (Service.RPC) | Category | gRPC Request Message |")
    a("|--------------------|----------|----------------------|")
    for f in flows:
        meta = get_flow_meta(f)
        cat = meta.get("category", "Other")
        req_msg = meta.get("grpc_request", "—")
        service = meta.get("service_name", "")
        rpc = meta.get("rpc_name", f)
        if service:
            flow_display = f"{service}.{rpc}"
        else:
            flow_display = f
        # VS Code/GitHub auto-generate anchors from heading text: lowercase, remove dots/special chars
        anchor = flow_display.lower().replace(".", "").replace(" ", "-")
        a(f"| [{flow_display}](#{anchor}) | {cat} | `{req_msg}` |")
    a("")

    # ── Per-flow detail ──────────────────────────────────────────────────────
    a("## Flow Details")
    a("")

    # Group by category
    by_cat: dict[str, list[str]] = {}
    for f in flows:
        meta = get_flow_meta(f)
        cat = meta.get("category", "Other")
        by_cat.setdefault(cat, []).append(f)

    for cat in CATEGORY_ORDER:
        if cat not in by_cat:
            continue
        a(f"### {cat}")
        a("")

        for f in by_cat[cat]:
            meta = get_flow_meta(f)
            flow_ann = ann.get("flows", {}).get(f, {})

            # Flow heading with anchor and full Service.RPC name
            service = meta.get("service_name", "")
            rpc = meta.get("rpc_name", f)
            if service:
                flow_heading = f"{service}.{rpc}"
            else:
                flow_heading = f
            a(f"#### {flow_heading}")
            a("")

            if meta.get("description"):
                a(meta["description"])
                a("")

            # gRPC messages
            if meta.get("grpc_request"):
                a(f"| | Message |")
                a(f"|---|---------|")
                a(f"| **Request** | `{meta['grpc_request']}` |")
                a(f"| **Response** | `{meta.get('grpc_response', '—')}` |")
                a("")

            # Payment method type support (from field-probe)
            pm_support = _probe_pm_support(probe_connector, f)
            if pm_support:
                a("**Supported payment method types:**")
                a("")
                a("| Payment Method | Supported |")
                a("|----------------|:---------:|")
                for pm_key, pm_label in _PROBE_PM_DISPLAY.items():
                    if pm_key in pm_support:
                        mark = "✓" if pm_support[pm_key] else "—"
                        a(f"| {pm_label} | {mark} |")
                a("")

            # Flow-level notes from annotations
            if flow_ann.get("notes"):
                notes = flow_ann["notes"]
                if isinstance(notes, str):
                    notes = [notes]
                for note in notes:
                    a(f"> {note}")
                a("")

            # Connector-specific required fields for this flow
            if flow_ann.get("required_fields"):
                a("**Connector-specific required fields:**")
                a("")
                for rf in flow_ann["required_fields"]:
                    if isinstance(rf, dict):
                        a(f"- `{rf['field']}` — {rf.get('note', '')}")
                    else:
                        a(f"- `{rf}`")
                a("")

            # Sample payloads: prefer probe-verified proto_requests (actual payloads
            # that succeeded in the req_transformer), fall back to YAML annotations.
            probe_samples = _probe_samples_for_flow(probe_connector, f)
            yaml_samples = flow_ann.get("samples", [])

            if probe_samples:
                # Probe-verified samples — these are the exact payloads the SDK
                # accepts and that produced a successful transformer call.
                for title, proto_req in probe_samples:
                    a(f"**{title}**")
                    for line in sdk_snippets.render_payload_block(
                        f,
                        meta.get("service_name", ""),
                        meta.get("grpc_request", ""),
                        proto_req,
                        _MESSAGE_SCHEMAS,
                    ):
                        a(line)
            elif yaml_samples:
                # Fall back to YAML annotation samples
                for sample in yaml_samples:
                    title = sample.get("title", "Minimum Request Payload")
                    # Skip samples for PM types that the probe confirmed unsupported
                    if pm_support is not None:
                        sample_pm = _sample_pm_key(title)
                        if sample_pm is not None and not pm_support.get(sample_pm, True):
                            continue
                    a(f"**{title}**")
                    a("")

                    if sample.get("required_fields_table"):
                        a("*Required fields for this variant:*")
                        a("")
                        a("| Field | Type | Description |")
                        a("|-------|------|-------------|")
                        for rf in sample["required_fields_table"]:
                            a(f"| `{rf['field']}` | `{rf.get('type', 'varies')}` | {rf.get('desc', '')} |")
                        a("")

                    if sample.get("request"):
                        a(_json_block(sample["request"]))
                        a("")

                    if sample.get("notes"):
                        note_lines = sample["notes"]
                        if isinstance(note_lines, str):
                            note_lines = [note_lines]
                        for n in note_lines:
                            a(f"> {n}")
                        a("")
            else:
                a(
                    f"<!-- TODO: Add sample payload for `{f}` in "
                    f"`scripts/connector-annotations/{connector_name}.yaml` -->"
                )
                a("")

    # ── Test credentials / cards from annotations ────────────────────────────
    tc = ann.get("test_credentials", {})
    if tc:
        a("## Testing")
        a("")
        if tc.get("note"):
            a(tc["note"].strip())
            a("")
        if tc.get("api_key"):
            a(f"**Test API Key:** `{tc['api_key']}`")
            a("")
        if tc.get("webhook_secret"):
            a(f"**Test Webhook Secret:** `{tc['webhook_secret']}`")
            a("")
        if tc.get("cards"):
            a("### Test Cards")
            a("")
            a("| Card Number | Brand | CVV | Expiry | Scenario |")
            a("|------------|-------|-----|--------|----------|")
            for card in tc["cards"]:
                a(
                    f"| `{card['number']}` | {card.get('brand', '—')} "
                    f"| `{card.get('cvc', 'any')}` | `{card.get('expiry', 'any future')}` "
                    f"| {card.get('scenario', '')} |"
                )
            a("")
        if tc.get("payment_methods"):
            a("### Test Payment Methods")
            a("")
            for pm in tc["payment_methods"]:
                a(f"- **{pm['type']}**: {pm.get('note', '')}")
            a("")

    return "\n".join(out)


# ─── Connector Discovery ──────────────────────────────────────────────────────

def list_connectors() -> list[str]:
    """Return sorted list of all connector names from probe data."""
    return sorted(_PROBE_DATA.keys())


# ─── CLI ─────────────────────────────────────────────────────────────────────

def cmd_list():
    connectors = list_connectors()
    print(f"Available connectors ({len(connectors)}):\n")
    for name in connectors:
        has_ann = any((ANNOTATIONS_DIR / f"{name}.{ext}").exists() for ext in ("yaml", "yml"))
        marker = "✓" if has_ann else "○"
        print(f"  {marker}  {name}")
    print("\n  ✓ = annotation file present   ○ = auto-generated only")


def cmd_generate(connectors: list[str], output_dir: Path, probe_path: Optional[Path] = None):
    if yaml is None:
        print("Warning: PyYAML not installed – annotation files will be ignored.")
        print("Install with: pip install pyyaml\n")

    probe_data = load_probe_data(probe_path)
    if not probe_data:
        print("Error: No probe data available. Run field-probe first.", file=sys.stderr)
        sys.exit(1)
    
    print(f"Loaded probe data for {len(probe_data)} connectors from {probe_path}\n")

    output_dir.mkdir(parents=True, exist_ok=True)

    ok = 0
    skip = 0
    for name in connectors:
        print(f"  {name} ... ", end="", flush=True)
        doc = generate_connector_doc(name, probe_data=probe_data)
        if doc:
            out = output_dir / f"{name}.md"
            out.write_text(doc, encoding="utf-8")
            n_flows = len(get_flows_from_probe(probe_data.get(name, {})))
            print(f"✓  ({n_flows} flows → {out.relative_to(REPO_ROOT)})")
            ok += 1
        else:
            print("skipped")
            skip += 1

    print(f"\nDone: {ok} generated, {skip} skipped.")


# ─── All Connectors Coverage Document ─────────────────────────────────────────

def _get_flow_status(flows: dict, flow_key: str) -> tuple[str, str]:
    """
    Get the status of a flow from probe data.
    Returns (status_mark, notes) tuple.
    """
    flow_data = flows.get(flow_key, {})
    
    # For PM-aware flows, check if there's any supported PM
    if flow_key in _PM_AWARE_FLOWS:
        supported_pms = [
            pm for pm, data in flow_data.items()
            if pm != "default" and data.get("status") == "supported"
        ]
        if supported_pms:
            return ("✓", f"{len(supported_pms)} PMs")
        # Check if there are any PM entries at all
        pm_entries = [pm for pm in flow_data.keys() if pm != "default"]
        if pm_entries:
            return ("—", "")
    
    # For flows with only 'default' entry
    default_entry = flow_data.get("default", {})
    status = default_entry.get("status", "unknown")
    
    if status == "supported":
        return ("✓", "")
    elif status == "error":
        error_msg = default_entry.get("error", "")
        if len(error_msg) > 60:
            error_msg = error_msg[:57] + "..."
        return ("⚠", error_msg if error_msg else "Error")
    elif status == "not_supported":
        return ("—", "")
    else:
        return ("?", "")


def generate_all_connector_doc(probe_data: dict[str, dict], output_dir: Path) -> None:
    """
    Generate all_connector.md - a comprehensive connector-wise flow coverage document.
    
    This creates a unified view showing:
    - For each flow, which connectors support which payment methods
    - Summary statistics for each connector and flow
    - Flow names follow proto service definitions from services.proto
    """
    out: list[str] = []
    a = out.append
    
    # ── Header ────────────────────────────────────────────────────────────────
    a("# Connector Flow Coverage")
    a("")
    a("<!--")
    a("This file is auto-generated. Do not edit by hand.")
    a("Source: data/field_probe/")
    a("Regenerate: python3 scripts/generate-connector-docs.py --all-connectors-doc")
    a("-->")
    a("")
    a("This document provides a comprehensive overview of payment method support")
    a("across all connectors for each payment flow. Flow names follow the gRPC")
    a("service definitions from `backend/grpc-api-types/proto/services.proto`.")
    a("")
    
    # Get all connectors that have probe data
    connectors_with_probe = sorted(probe_data.keys())
    
    if not connectors_with_probe:
        a("No probe data available.")
        output_dir.mkdir(parents=True, exist_ok=True)
        out_path = output_dir / "all_connector.md"
        out_path.write_text("\n".join(out), encoding="utf-8")
        return
    
    # ── Summary Table ──────────────────────────────────────────────────────────
    # Use proto-based flow names for summary
    summary_flows = [
        ("authorize", "PaymentService.Authorize"),
        ("capture", "PaymentService.Capture"),
        ("get", "PaymentService.Get"),
        ("refund", "PaymentService.Refund"),
        ("void", "PaymentService.Void"),
    ]
    
    a("## Summary")
    a("")
    # Header with service-prefixed flow names
    header_parts = ["Connector"]
    for _, flow_display in summary_flows:
        # Extract just the RPC name for brevity in header
        rpc_name = flow_display.split(".")[-1]
        header_parts.append(rpc_name)
    a("| " + " | ".join(header_parts) + " |")
    a("|" + "|".join(["-----------"] + [":---:" for _ in summary_flows]) + "|")
    
    for conn_name in connectors_with_probe:
        conn_data = probe_data[conn_name]
        flows = conn_data.get("flows", {})
        
        display = _DISPLAY_NAMES.get(conn_name, conn_name.replace("_", " ").title())
        row = [f"[{display}](connectors/{conn_name}.md)"]
        
        for flow_key, _ in summary_flows:
            status_mark, _ = _get_flow_status(flows, flow_key)
            row.append(status_mark)
        
        a("| " + " | ".join(row) + " |")
    a("")
    
    # ── Per-Service Flow Coverage Tables ───────────────────────────────────────
    a("## Flow Details")
    a("")
    a("Flow names follow the gRPC service definitions. Each flow is prefixed with")
    a("its service name (e.g., `PaymentService.Authorize`, `RefundService.Get`).")
    a("")
    
    # Group flows by service
    services_order = [
        "PaymentService",
        "RecurringPaymentService", 
        "RefundService",
        "CustomerService",
        "PaymentMethodService",
        "MerchantAuthenticationService",
        "PaymentMethodAuthenticationService",
        "DisputeService",
    ]
    
    # Build service -> flows mapping from flow_metadata loaded from probe.json
    proto_flow_defs = get_proto_flow_definitions()
    if not proto_flow_defs:
        print("Warning: No flow metadata loaded from probe.json", file=sys.stderr)
    service_flows: dict[str, list[tuple[str, str, str]]] = {}
    for flow_key, (service_name, rpc_name, description) in proto_flow_defs.items():
        service_flows.setdefault(service_name, []).append((flow_key, rpc_name, description))
    
    for service_name in services_order:
        if service_name not in service_flows:
            continue
        
        flows_in_service = service_flows[service_name]
        
        # Check if any flow in this service has probe data
        service_has_data = any(
            any(
                probe_data[c].get("flows", {}).get(flow_key)
                for c in connectors_with_probe
            )
            for flow_key, _, _ in flows_in_service
        )
        if not service_has_data:
            continue
        
        a(f"### {service_name}")
        a("")
        
        for flow_key, rpc_name, description in flows_in_service:
            # Check if any connector has data for this flow
            has_data = any(
                probe_data[c].get("flows", {}).get(flow_key)
                for c in connectors_with_probe
            )
            if not has_data:
                continue
            
            # Flow heading with full service.rpc name
            a(f"#### {service_name}.{rpc_name}")
            a("")
            a(description)
            a("")
            
            if flow_key in _PM_AWARE_FLOWS:
                # For PM-aware flows, show full PM breakdown
                a("| Connector | " + " | ".join(_PROBE_PM_DISPLAY.values()) + " |")
                a("|-----------|" + "|".join([":---:" for _ in _PROBE_PM_DISPLAY]) + "|")
                
                for conn_name in connectors_with_probe:
                    conn_data = probe_data[conn_name]
                    flow_data = conn_data.get("flows", {}).get(flow_key, {})
                    
                    display = _DISPLAY_NAMES.get(conn_name, conn_name.replace("_", " ").title())
                    row = [f"[{display}](connectors/{conn_name}.md)"]
                    
                    for pm_key in _PROBE_PM_DISPLAY:
                        pm_data = flow_data.get(pm_key, {})
                        status = pm_data.get("status", "unknown")
                        if status == "supported":
                            row.append("✓")
                        elif status == "not_supported":
                            row.append("—")
                        elif status == "error":
                            row.append("⚠")
                        else:
                            row.append("?")
                    
                    a("| " + " | ".join(row) + " |")
                a("")
                
                # Legend
                a("**Legend:** ✓ Supported | — Not Supported | ⚠ Error | ? Unknown")
                a("")
            else:
                # For other flows, show simple supported/not supported
                a("| Connector | Supported | Notes |")
                a("|-----------|:---------:|-------|")
                
                for conn_name in connectors_with_probe:
                    conn_data = probe_data[conn_name]
                    flows = conn_data.get("flows", {})
                    status_mark, notes = _get_flow_status(flows, flow_key)
                    
                    display = _DISPLAY_NAMES.get(conn_name, conn_name.replace("_", " ").title())
                    a(f"| [{display}](connectors/{conn_name}.md) | {status_mark} | {notes} |")
                a("")
    
    # ── Payment Method Legend ─────────────────────────────────────────────────
    a("## Payment Methods")
    a("")
    a("Payment methods probed for authorize flow (configured in `backend/field-probe/probe-config.toml`):")
    a("")
    a("| Key | Display Name | Description |")
    a("|-----|--------------|-------------|")
    a("| Card | Card | Credit/Debit card payments |")
    a("| GooglePay | Google Pay | Google Pay digital wallet |")
    a("| ApplePay | Apple Pay | Apple Pay digital wallet |")
    a("| Sepa | SEPA | SEPA Direct Debit (EU bank transfers) |")
    a("| Bacs | BACS | BACS Direct Debit (UK bank transfers) |")
    a("| Ach | ACH | ACH Direct Debit (US bank transfers) |")
    a("| Becs | BECS | BECS Direct Debit (AU bank transfers) |")
    a("| Ideal | iDEAL | iDEAL (Netherlands bank redirect) |")
    a("| PaypalRedirect | PayPal | PayPal redirect payments |")
    a("| Blik | BLIK | BLIK (Polish mobile payment) |")
    a("| Klarna | Klarna | Klarna Buy Now Pay Later |")
    a("| Afterpay | Afterpay | Afterpay/Clearpay BNPL |")
    a("| UpiCollect | UPI | UPI Collect (India) |")
    a("| Affirm | Affirm | Affirm BNPL |")
    a("| SamsungPay | Samsung Pay | Samsung Pay digital wallet |")
    a("")
    
    # ── Services Reference ─────────────────────────────────────────────────────
    a("## Services Reference")
    a("")
    a("Flow definitions are derived from `backend/grpc-api-types/proto/services.proto`:")
    a("")
    a("| Service | Description |")
    a("|---------|-------------|")
    a("| PaymentService | Process payments from authorization to settlement |")
    a("| RecurringPaymentService | Charge and revoke recurring payments |")
    a("| RefundService | Retrieve and synchronize refund statuses |")
    a("| CustomerService | Create and manage customer profiles |")
    a("| PaymentMethodService | Tokenize and retrieve payment methods |")
    a("| MerchantAuthenticationService | Generate access tokens and session credentials |")
    a("| PaymentMethodAuthenticationService | Execute 3D Secure authentication flows |")
    a("| DisputeService | Manage chargeback disputes |")
    a("")
    
    # Write output
    output_dir.mkdir(parents=True, exist_ok=True)
    out_path = output_dir / "all_connector.md"
    out_path.write_text("\n".join(out), encoding="utf-8")
    print(f"  ✓ Generated {out_path.relative_to(REPO_ROOT)}")


def cmd_all_connectors_doc(output_dir: Path, probe_path: Optional[Path] = None):
    """Generate the all_connector.md coverage document."""
    probe_data = load_probe_data(probe_path)
    if not probe_data:
        print("Error: No probe data available. Run field-probe first.", file=sys.stderr)
        sys.exit(1)
    
    print(f"Generating all_connector.md from {len(probe_data)} connectors\n")
    generate_all_connector_doc(probe_data, output_dir)
    print("\nDone.")


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Generate connector docs from field-probe JSON output",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("connectors", nargs="*", help="Connector names (e.g. stripe adyen)")
    parser.add_argument("--all", action="store_true", help="Generate docs for all connectors")
    parser.add_argument("--list", action="store_true", help="List connectors and annotation status")
    parser.add_argument(
        "--all-connectors-doc",
        action="store_true",
        help="Generate all_connector.md with flow coverage matrix",
    )
    parser.add_argument(
        "--output-dir",
        default=str(DOCS_DIR),
        metavar="DIR",
        help=f"Output directory (default: {DOCS_DIR})",
    )
    parser.add_argument(
        "--probe",
        default=str(REPO_ROOT / "data" / "field_probe"),
        metavar="DIR",
        help="Path to field-probe directory (default: data/field_probe/)",
    )
    args = parser.parse_args()

    # Load probe data first (needed for list and generate)
    probe_path = Path(args.probe) if args.probe else None
    probe_data = load_probe_data(probe_path)

    if args.list:
        if not probe_data:
            print("Error: No probe data available. Run field-probe first.", file=sys.stderr)
            sys.exit(1)
        cmd_list()
        return

    if args.all_connectors_doc:
        cmd_all_connectors_doc(Path(args.output_dir).parent, probe_path=probe_path)
        return

    if args.all:
        targets = list_connectors()
    elif args.connectors:
        targets = args.connectors
    else:
        parser.print_help()
        return

    cmd_generate(targets, Path(args.output_dir), probe_path=probe_path)


if __name__ == "__main__":
    main()