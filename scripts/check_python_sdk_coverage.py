#!/usr/bin/env python3
"""
Check Python SDK coverage against FFI flow definitions.

Compares flows declared in:
  - crates/ffi/ffi/src/bindings/_generated_ffi_flows.rs  (Rust FFI)
  - sdk/python/src/payments/_generated_flows.py           (Python SDK)

Reports:
  - Flows present in both FFI and Python SDK
  - Flows in FFI but missing from Python SDK
  - Flows in Python SDK but missing from FFI
  - Overall coverage percentage

Usage:
    python3 scripts/check_python_sdk_coverage.py [--json] [--strict]
"""

import argparse
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

FFI_FLOWS_PATH = REPO_ROOT / "crates/ffi/ffi/src/bindings/_generated_ffi_flows.rs"
SDK_FLOWS_PATH = REPO_ROOT / "sdk/python/src/payments/_generated_flows.py"

# Regex to extract flow names from define_ffi_flow!(name, ...) lines
FFI_FLOW_RE = re.compile(r"define_ffi_flow!\(\s*(\w+)\s*,")

# Regex to extract flow names from Python SERVICE_FLOWS dict entries:
#   "flow_name": "ResponseType",
SDK_FLOW_RE = re.compile(r'^\s*"(\w+)"\s*:\s*"(\w+)"', re.MULTILINE)

# Regex to extract client names from the Python SERVICE_FLOWS dict
SDK_CLIENT_RE = re.compile(r'^\s*"(\w+Client)"\s*:', re.MULTILINE)

# Regex for SINGLE_SERVICE_FLOWS entries
SDK_SINGLE_FLOW_RE = re.compile(
    r'^\s*"(\w+Client)"\s*:\s*\{[^}]*"(\w+)"\s*:', re.MULTILINE | re.DOTALL
)


def parse_ffi_flows() -> set:
    """Extract all flow names from the Rust FFI generated file."""
    if not FFI_FLOWS_PATH.exists():
        print(f"ERROR: FFI flows file not found: {FFI_FLOWS_PATH}", file=sys.stderr)
        sys.exit(1)

    content = FFI_FLOWS_PATH.read_text()
    return set(FFI_FLOW_RE.findall(content))


def parse_sdk_flows() -> dict:
    """Extract all flow names from the Python SDK generated file.

    Returns dict[client_name] -> set of flow names.
    """
    if not SDK_FLOWS_PATH.exists():
        print(f"ERROR: SDK flows file not found: {SDK_FLOWS_PATH}", file=sys.stderr)
        sys.exit(1)

    content = SDK_FLOWS_PATH.read_text()
    clients: dict = {}

    # Parse SERVICE_FLOWS block
    in_service_flows = False
    current_client = None
    brace_depth = 0

    for line in content.splitlines():
        stripped = line.strip()

        if "SERVICE_FLOWS" in stripped and "=" in stripped and "SINGLE" not in stripped:
            in_service_flows = True
            brace_depth = 0
            continue

        if "SINGLE_SERVICE_FLOWS" in stripped and "=" in stripped:
            in_service_flows = True
            brace_depth = 0
            continue

        if not in_service_flows:
            continue

        # Track brace depth to know when we exit the dict
        brace_depth += stripped.count("{") - stripped.count("}")

        # Check for client key
        client_match = re.match(r'"(\w+Client)"\s*:', stripped)
        if client_match:
            current_client = client_match.group(1)
            if current_client not in clients:
                clients[current_client] = set()
            continue

        # Check for flow entry
        flow_match = re.match(r'"(\w+)"\s*:\s*"(\w+)"', stripped)
        if flow_match and current_client:
            clients[current_client].add(flow_match.group(1))
            continue

        if brace_depth <= 0 and in_service_flows and stripped == "}":
            in_service_flows = False
            current_client = None

    return clients


def flatten_sdk_flows(sdk_clients: dict) -> set:
    """Flatten all SDK client flows into a single set."""
    result = set()
    for flows in sdk_clients.values():
        result.update(flows)
    return result


def main():
    parser = argparse.ArgumentParser(description="Check Python SDK coverage against FFI flows")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit with code 1 if any FFI flow is missing from Python SDK",
    )
    args = parser.parse_args()

    ffi_flows = parse_ffi_flows()
    sdk_clients = parse_sdk_flows()
    sdk_flows = flatten_sdk_flows(sdk_clients)

    # Coverage analysis
    in_both = ffi_flows & sdk_flows
    ffi_only = ffi_flows - sdk_flows
    sdk_only = sdk_flows - ffi_flows

    coverage_pct = (len(in_both) / len(ffi_flows) * 100) if ffi_flows else 0.0

    if args.json:
        report = {
            "ffi_flows": sorted(ffi_flows),
            "sdk_flows": sorted(sdk_flows),
            "sdk_clients": {k: sorted(v) for k, v in sorted(sdk_clients.items())},
            "covered": sorted(in_both),
            "ffi_only_missing_from_sdk": sorted(ffi_only),
            "sdk_only_not_in_ffi": sorted(sdk_only),
            "coverage_percent": round(coverage_pct, 1),
            "total_ffi_flows": len(ffi_flows),
            "total_sdk_flows": len(sdk_flows),
            "total_covered": len(in_both),
        }
        print(json.dumps(report, indent=2))
    else:
        print("=" * 60)
        print("  Python SDK Coverage vs FFI Flows")
        print("=" * 60)
        print()
        print(f"  FFI flows (Rust):     {len(ffi_flows)}")
        print(f"  SDK flows (Python):   {len(sdk_flows)}")
        print(f"  Covered (in both):    {len(in_both)}")
        print(f"  Coverage:             {coverage_pct:.1f}%")
        print()

        if in_both:
            print(f"  Covered flows ({len(in_both)}):")
            for flow in sorted(in_both):
                print(f"    + {flow}")
            print()

        if ffi_only:
            print(f"  FFI-only (missing from Python SDK) ({len(ffi_only)}):")
            for flow in sorted(ffi_only):
                print(f"    - {flow}")
            print()

        if sdk_only:
            print(f"  SDK-only (not in FFI) ({len(sdk_only)}):")
            for flow in sorted(sdk_only):
                print(f"    ? {flow}")
            print()

        print("  SDK Client Breakdown:")
        for client, flows in sorted(sdk_clients.items()):
            print(f"    {client}: {', '.join(sorted(flows))}")
        print()

    if args.strict and ffi_only:
        print(
            f"STRICT: {len(ffi_only)} FFI flow(s) missing from Python SDK",
            file=sys.stderr,
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
