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
  1. Loads probe data from data/field_probe/{connector}.json
  2. All content is derived exclusively from probe data — no manual annotation files
  3. Outputs docs/connectors/{name}.md

To add docs for a new connector:
  - Run field-probe to generate probe data: cd backend/field-probe && cargo r
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

        # Load proto type map for wrapper-type detection (SecretString, CardNumberType, etc.)
        proto_dir = probe_dir.parent.parent / "backend" / "grpc-api-types" / "proto"
        if proto_dir.exists():
            sdk_snippets.load_proto_type_map(proto_dir)

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


# ─── Paths ────────────────────────────────────────────────────────────────────

REPO_ROOT       = Path(__file__).parent.parent
DOCS_DIR     = REPO_ROOT / "docs/connectors"
EXAMPLES_DIR = REPO_ROOT / "examples"
PROTO_DIR    = REPO_ROOT / "backend/grpc-api-types/proto"

# Category order for grouping flows in documentation
CATEGORY_ORDER = ["Payments", "Refunds", "Mandates", "Customers", "Disputes", "Authentication", "Session", "Other"]

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


def display_name(connector_name: str) -> str:
    return _DISPLAY_NAMES.get(connector_name, connector_name.replace("_", " ").title())


# ─── Markdown Generation ──────────────────────────────────────────────────────

def get_flows_from_probe(probe_connector: dict) -> list[str]:
    """Extract list of supported flow keys from probe data."""
    return list(probe_connector.get("flows", {}).keys())


def get_flow_meta(flow_key: str) -> dict:
    """Get flow metadata by flow_key from loaded probe.json data."""
    flow_metadata = get_flow_metadata()
    return flow_metadata.get(flow_key, {})


def _get_flow_proto_requests(
    probe_connector: dict,
    scenario: "sdk_snippets.ScenarioSpec",
) -> dict[str, dict]:
    """
    Build flow_key → proto_request dict for the flows in a scenario.

    For authorize: uses the PM-specific entry keyed by scenario.pm_key.
    For all other flows: uses the "default" entry.
    Returns {} for any flow whose payload is missing or status != supported.
    """
    flows = probe_connector.get("flows", {})
    result: dict[str, dict] = {}
    for flow_key in scenario.flows:
        pm_key = scenario.pm_key if flow_key == "authorize" else "default"
        entry  = flows.get(flow_key, {}).get(pm_key or "default", {})
        if entry.get("status") == "supported":
            result[flow_key] = entry.get("proto_request") or {}
    return result


def generate_scenario_files(
    connector_name: str,
    probe_connector: dict,
    examples_dir: Path,
) -> list[Path]:
    """
    Write examples/{connector}/python/{scenario_key}.py and
    examples/{connector}/javascript/{scenario_key}.js for each detected scenario.

    Returns list of written paths. Creates directories as needed.
    """
    flow_metadata = get_flow_metadata()
    scenarios     = sdk_snippets.detect_scenarios(probe_connector)
    written: list[Path] = []

    for scenario in scenarios:
        flow_payloads = _get_flow_proto_requests(probe_connector, scenario)
        if not flow_payloads:
            continue

        for sdk, ext, render_fn in [
            ("python",     "py", sdk_snippets.render_scenario_python),
            ("javascript", "js", sdk_snippets.render_scenario_javascript),
        ]:
            out_dir  = examples_dir / connector_name / sdk
            out_dir.mkdir(parents=True, exist_ok=True)
            out_path = out_dir / f"{scenario.key}.{ext}"
            content  = render_fn(scenario, connector_name, flow_payloads, flow_metadata, _MESSAGE_SCHEMAS)
            out_path.write_text(content, encoding="utf-8")
            written.append(out_path)

    return written


# PM priority for selecting the representative authorize payload
_AUTHORIZE_PM_PRIORITY = [
    "Card", "GooglePay", "ApplePay", "SamsungPay",
    "Sepa", "Ach", "Bacs", "Becs",
    "Ideal", "PaypalRedirect", "Blik", "Klarna", "Afterpay", "UpiCollect", "Affirm",
]


def generate_flow_files(
    connector_name: str,
    probe_connector: dict,
    examples_dir: Path,
) -> dict[str, list[Path]]:
    """
    Write examples/{connector}/{lang}/{flow_key}.{ext} for each supported flow.

    For authorize: uses the primary PM (Card preferred, else first available).
    For all other flows: uses the "default" entry.
    Returns {flow_key: [py_path, js_path]} dict.
    """
    flow_metadata   = get_flow_metadata()
    flows           = probe_connector.get("flows", {})
    scenario_keys   = {s.key for s in sdk_snippets.detect_scenarios(probe_connector)}
    result: dict[str, list[Path]] = {}

    for flow_key, flow_data in flows.items():
        # Skip flow keys that collide with a scenario key (scenario file takes precedence)
        if flow_key in scenario_keys:
            continue
        if flow_key == "authorize":
            proto_req = None
            pm_label  = ""
            for pm in _AUTHORIZE_PM_PRIORITY:
                entry = flow_data.get(pm, {})
                if entry.get("status") == "supported" and entry.get("proto_request"):
                    proto_req = entry["proto_request"]
                    pm_label  = pm
                    break
            if proto_req is None:
                continue
        else:
            entry = flow_data.get("default", {})
            if entry.get("status") != "supported":
                continue
            proto_req = entry.get("proto_request") or {}
            pm_label  = ""

        written: list[Path] = []
        for sdk, ext, render_fn in [
            ("python",     "py", sdk_snippets.render_flow_python),
            ("javascript", "js", sdk_snippets.render_flow_javascript),
            ("kotlin",     "kt", sdk_snippets.render_flow_kotlin),
            ("rust",       "rs", sdk_snippets.render_flow_rust),
        ]:
            out_dir  = examples_dir / connector_name / sdk
            out_dir.mkdir(parents=True, exist_ok=True)
            out_path = out_dir / f"{flow_key}.{ext}"
            content  = render_fn(flow_key, connector_name, proto_req, flow_metadata, _MESSAGE_SCHEMAS, pm_label)
            out_path.write_text(content, encoding="utf-8")
            written.append(out_path)

        result[flow_key] = written

    return result


def generate_llms_txt(probe_data: dict[str, dict], docs_dir: Path) -> None:
    """
    Write docs/llms.txt — a machine-readable navigation index for AI assistants.
    """
    lines: list[str] = [
        "# Connector Service — LLM Navigation Index",
        f"# Connectors: {len(probe_data)}",
        "#",
        "# This file helps AI coding assistants navigate connector-service documentation.",
        "# Each connector block lists: doc path, scenarios, supported payment methods,",
        "# supported flows, and paths to runnable Python/JavaScript examples.",
        "#",
        "# Usage: fetch this file first, then fetch the specific connector doc or example.",
        "",
        "overview:",
        f"  total_connectors: {len(probe_data)}",
        "  docs_root: docs/connectors/",
        "  examples_root: examples/",
        "  all_connectors_matrix: docs/all_connector.md",
        "",
        "integration_pattern:",
        "  1. Configure ConnectorConfig with connector name and credentials",
        "  2. Call flows in sequence per scenario (see Integration Scenarios in connector doc)",
        "  3. Branch on response.status: AUTHORIZED / PENDING / FAILED",
        "  4. PENDING means await webhook or poll Get before capturing",
        "  5. Pass connector_transaction_id from Authorize response to Capture/Refund",
        "",
        "---",
        "",
    ]

    for connector_name in sorted(probe_data.keys()):
        probe_connector = probe_data[connector_name]
        name            = display_name(connector_name)
        scenarios       = sdk_snippets.detect_scenarios(probe_connector)
        entry           = sdk_snippets.render_llms_txt_entry(
            connector_name, name, probe_connector, scenarios
        )
        lines.append(entry)

    out_path = docs_dir.parent / "llms.txt"
    out_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"  llms.txt → {out_path.relative_to(REPO_ROOT)}")


def generate_connector_doc(connector_name: str, probe_data: Optional[dict] = None) -> Optional[str]:
    """Generate complete markdown documentation for a connector."""
    probe_connector = (probe_data or {}).get(connector_name, {})
    
    # Get flows from probe data
    flows = get_flows_from_probe(probe_connector)
    if not flows:
        print(f"  No flows found for '{connector_name}' – skipping.", file=sys.stderr)
        return None

    name = display_name(connector_name)

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

    # ── SDK Configuration (once per connector) ──────────────────────────────
    for line in sdk_snippets.render_config_section(connector_name):
        a(line)

    # ── Integration Scenarios ────────────────────────────────────────────────
    scenarios     = sdk_snippets.detect_scenarios(probe_connector)
    flow_metadata = get_flow_metadata()
    if scenarios:
        a("## Integration Scenarios")
        a("")
        a(
            "Complete, runnable examples for common integration patterns. "
            "Each example shows the full flow with status handling. "
            "Copy-paste into your app and replace placeholder values."
        )
        a("")
        for scenario in scenarios:
            flow_payloads = _get_flow_proto_requests(probe_connector, scenario)
            for line in sdk_snippets.render_scenario_section(
                scenario, connector_name, flow_payloads,
                flow_metadata, _MESSAGE_SCHEMAS, {},
            ):
                a(line)

    # ── Payment Method Reference ──────────────────────────────────────────────
    for line in sdk_snippets.render_pm_reference_section(
        probe_connector, flow_metadata, _MESSAGE_SCHEMAS
    ):
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
    a("## Flow Reference")
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

            # Link to per-flow example files instead of embedding code
            flow_data = probe_connector.get("flows", {}).get(f, {})
            has_payload = (
                flow_data.get("default", {}).get("status") == "supported"
                or any(
                    v.get("status") == "supported"
                    for k, v in flow_data.items()
                    if k != "default"
                )
            )
            if has_payload:
                py_path = f"../../examples/{connector_name}/python/{f}.py"
                js_path = f"../../examples/{connector_name}/javascript/{f}.js"
                kt_path = f"../../examples/{connector_name}/kotlin/{f}.kt"
                rs_path = f"../../examples/{connector_name}/rust/{f}.rs"
                a(f"**Examples:** [Python]({py_path}) · [JavaScript]({js_path}) · [Kotlin]({kt_path}) · [Rust]({rs_path})")
                a("")

    return "\n".join(out)


# ─── Connector Discovery ──────────────────────────────────────────────────────

def list_connectors() -> list[str]:
    """Return sorted list of all connector names from probe data."""
    return sorted(_PROBE_DATA.keys())


# ─── CLI ─────────────────────────────────────────────────────────────────────

def check_example_syntax(examples_dir: Path) -> None:
    """Run syntax checks on all generated example files."""
    import subprocess

    py_files = sorted(examples_dir.rglob("*.py"))
    js_files = sorted(examples_dir.rglob("*.js"))
    kt_files = sorted(examples_dir.rglob("*.kt"))
    rs_files = sorted(examples_dir.rglob("*.rs"))

    errors: list[str] = []

    # Python — full AST parse
    for f in py_files:
        result = subprocess.run(
            [sys.executable, "-m", "py_compile", str(f)],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            errors.append(f"Python: {f.relative_to(examples_dir.parent)}: {result.stderr.strip()}")

    # JavaScript — syntax check
    node_ok = False
    try:
        subprocess.run(["node", "--version"], capture_output=True, check=True)
        node_ok = True
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    if node_ok:
        for f in js_files:
            result = subprocess.run(["node", "--check", str(f)], capture_output=True, text=True)
            if result.returncode != 0:
                errors.append(f"JS: {f.relative_to(examples_dir.parent)}: {result.stderr.strip()}")

    # Kotlin — syntax check via kotlinc -script (if available)
    # Full compilation requires SDK JARs: ./gradlew compileKotlin (from sdk/java/)
    kt_ok = False
    try:
        subprocess.run(["kotlinc", "-version"], capture_output=True, check=True)
        kt_ok = True
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    if kt_ok:
        for f in kt_files:
            result = subprocess.run(
                ["kotlinc", "-nowarn", str(f), "-d", "/dev/null"],
                capture_output=True, text=True,
            )
            if result.returncode != 0:
                errors.append(f"Kotlin: {f.relative_to(examples_dir.parent)}: {result.stderr.strip()}")

    # Rust — format check via rustfmt (syntax-level); full compile needs cargo check
    # Full compilation: cargo check -p hyperswitch-payments-client (from repo root)
    rustfmt_ok = False
    try:
        subprocess.run(["rustfmt", "--version"], capture_output=True, check=True)
        rustfmt_ok = True
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    if rustfmt_ok:
        for f in rs_files:
            result = subprocess.run(
                ["rustfmt", "--check", "--edition", "2021", str(f)],
                capture_output=True, text=True,
            )
            # rustfmt --check exits 1 only on formatting diffs, not syntax errors.
            # Run rustfmt without --check to detect parse errors.
            result2 = subprocess.run(
                ["rustfmt", "--edition", "2021", "--check", str(f)],
                capture_output=True, text=True,
            )
            if "error" in result2.stderr.lower():
                errors.append(f"Rust: {f.relative_to(examples_dir.parent)}: {result2.stderr.strip()}")

    if errors:
        print(f"\n  Syntax errors in {len(errors)} example file(s):")
        for e in errors:
            print(f"    {e}")
    else:
        checks = f"{len(py_files)} Python, {len(js_files)} JavaScript, {len(kt_files)} Kotlin, {len(rs_files)} Rust"
        js_note = "" if node_ok else " (node unavailable — JS skipped)"
        kt_note = "" if kt_ok else " (kotlinc unavailable — Kotlin skipped)"
        rs_note = "" if rustfmt_ok else " (rustfmt unavailable — Rust skipped)"
        print(f"  ✓ Syntax check passed ({checks}){js_note}{kt_note}{rs_note}")


def cmd_list():
    connectors = list_connectors()
    print(f"Available connectors ({len(connectors)}):\n")
    for name in connectors:
        print(f"  {name}")


def cmd_generate(connectors: list[str], output_dir: Path, probe_path: Optional[Path] = None):
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
            probe_connector = probe_data.get(name, {})
            n_flows         = len(get_flows_from_probe(probe_connector))
            scenario_files  = generate_scenario_files(name, probe_connector, EXAMPLES_DIR)
            flow_files      = generate_flow_files(name, probe_connector, EXAMPLES_DIR)
            n_scenarios     = len(scenario_files) // 2  # python + js per scenario
            n_flow_files    = len(flow_files)
            print(f"✓  ({n_flows} flows, {n_scenarios} scenarios, {n_flow_files} flow examples → {out.relative_to(REPO_ROOT)})")
            ok += 1
        else:
            print("skipped")
            skip += 1

    generate_llms_txt(probe_data, output_dir)
    print(f"\nDone: {ok} generated, {skip} skipped.")
    check_example_syntax(EXAMPLES_DIR)


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