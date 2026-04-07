#!/usr/bin/env python3
"""
Map FFI flow names to integration test suite names and vice versa.

The integration test harness uses "suite names" (e.g. `create_customer`,
`recurring_charge`, `tokenize_payment_method`) that differ from the FFI flow
names (e.g. `create`, `charge`, `tokenize`).  This script produces a mapping
table so that tooling and documentation can bridge the two naming conventions.

Data sources:
  - crates/ffi/ffi/src/bindings/_generated_ffi_flows.rs       (FFI flow names)
  - crates/internal/integration-tests/src/harness/scenario_api.rs (suite names)
  - sdk/python/src/payments/_generated_flows.py                (Python SDK flows)

Usage:
    python3 scripts/map_flows_to_suites.py [--json]
"""

import argparse
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

FFI_FLOWS_PATH = REPO_ROOT / "crates/ffi/ffi/src/bindings/_generated_ffi_flows.rs"
SCENARIO_API_PATH = REPO_ROOT / "crates/internal/integration-tests/src/harness/scenario_api.rs"
SDK_FLOWS_PATH = REPO_ROOT / "sdk/python/src/payments/_generated_flows.py"

# ── Hardcoded suite↔FFI mapping ────────────────────────────────────────────────
# Where suite name != FFI flow name. The rest are identity mappings.
SUITE_TO_FFI_OVERRIDES = {
    "create_customer": "create",
    "recurring_charge": "charge",
    "tokenize_payment_method": "tokenize",
    "server_authentication_token": "create_server_authentication_token",
    "server_session_authentication_token": "create_server_session_authentication_token",
    "client_authentication_token": "create_client_authentication_token",
}

# Suites that have NO corresponding FFI flow (gRPC-only or composite suites)
SUITES_WITHOUT_FFI = {
    "complete_authorize",
    "refund_sync",
    "revoke_mandate",
    "verify_redirect_response",
    "incremental_authorization",
    "payment_method_eligibility",
    "handle_event",
}


def parse_ffi_flows() -> set:
    """Extract all flow names from the Rust FFI generated file."""
    content = FFI_FLOWS_PATH.read_text()
    return set(re.findall(r"define_ffi_flow!\(\s*(\w+)\s*,", content))


def parse_suite_names() -> list:
    """Extract all suite names from all_known_suites() in scenario_api.rs."""
    content = SCENARIO_API_PATH.read_text()
    # Look for the array inside all_known_suites()
    match = re.search(
        r"pub fn all_known_suites\(\).*?&\[(.*?)\]",
        content,
        re.DOTALL,
    )
    if not match:
        print("ERROR: Could not find all_known_suites() in scenario_api.rs", file=sys.stderr)
        sys.exit(1)

    body = match.group(1)
    return re.findall(r'"(\w+)"', body)


def parse_sdk_flow_names() -> set:
    """Extract all flow names from the Python SDK."""
    content = SDK_FLOWS_PATH.read_text()
    # Match "flow_name": "ResponseType" entries
    return set(re.findall(r'^\s*"(\w+)"\s*:\s*"\w+"', content, re.MULTILINE))


def build_mapping(suites: list, ffi_flows: set) -> list:
    """Build the mapping table.

    Returns list of dicts with keys:
        suite, ffi_flow, has_ffi, has_suite, in_python_sdk
    """
    sdk_flows = parse_sdk_flow_names()
    rows = []

    # Start with all suites
    for suite in suites:
        if suite in SUITES_WITHOUT_FFI:
            rows.append({
                "suite": suite,
                "ffi_flow": None,
                "has_ffi": False,
                "has_suite": True,
                "in_python_sdk": suite in sdk_flows,
                "note": "gRPC/composite only (no FFI flow)",
            })
            continue

        ffi_name = SUITE_TO_FFI_OVERRIDES.get(suite, suite)
        has_ffi = ffi_name in ffi_flows
        rows.append({
            "suite": suite,
            "ffi_flow": ffi_name if has_ffi else f"{ffi_name}?",
            "has_ffi": has_ffi,
            "has_suite": True,
            "in_python_sdk": ffi_name in sdk_flows,
            "note": "" if has_ffi else "FFI flow not found",
        })

    # FFI flows without a suite
    mapped_ffi = set()
    for row in rows:
        if row["ffi_flow"] and row["has_ffi"]:
            mapped_ffi.add(row["ffi_flow"])

    for ffi_flow in sorted(ffi_flows - mapped_ffi):
        rows.append({
            "suite": None,
            "ffi_flow": ffi_flow,
            "has_ffi": True,
            "has_suite": False,
            "in_python_sdk": ffi_flow in sdk_flows,
            "note": "FFI flow without integration test suite",
        })

    return rows


def main():
    parser = argparse.ArgumentParser(description="Map FFI flows to integration test suites")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    ffi_flows = parse_ffi_flows()
    suites = parse_suite_names()
    mapping = build_mapping(suites, ffi_flows)

    if args.json:
        print(json.dumps(mapping, indent=2))
        return

    # Pretty-print table
    print("=" * 90)
    print("  Suite Name → FFI Flow Mapping")
    print("=" * 90)
    print()
    print(f"  {'Suite':<42} {'FFI Flow':<35} {'SDK':<5} {'Note'}")
    print(f"  {'-'*42} {'-'*35} {'-'*5} {'-'*20}")

    for row in mapping:
        suite = row["suite"] or "(none)"
        ffi = row["ffi_flow"] or "(none)"
        sdk = "yes" if row["in_python_sdk"] else "no"
        note = row.get("note", "")
        print(f"  {suite:<42} {ffi:<35} {sdk:<5} {note}")

    print()

    # Summary
    with_ffi = sum(1 for r in mapping if r["has_ffi"])
    with_suite = sum(1 for r in mapping if r["has_suite"])
    with_sdk = sum(1 for r in mapping if r["in_python_sdk"])
    ffi_no_suite = sum(1 for r in mapping if r["has_ffi"] and not r["has_suite"])
    suite_no_ffi = sum(1 for r in mapping if r["has_suite"] and not r["has_ffi"])

    print(f"  Total suites:                {with_suite}")
    print(f"  Total FFI flows:             {with_ffi}")
    print(f"  FFI flows with a suite:      {with_ffi - ffi_no_suite}")
    print(f"  FFI flows without a suite:   {ffi_no_suite}")
    print(f"  Suites without an FFI flow:  {suite_no_ffi}")
    print(f"  Flows in Python SDK:         {with_sdk}")
    print()


if __name__ == "__main__":
    main()
