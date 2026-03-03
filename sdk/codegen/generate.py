
#!/usr/bin/env python3
"""
SDK codegen — auto-discovers flows by cross-referencing:
  1. services.proto     → RPC name, request type, response type, service name,
                          and the leading doc-comment from the proto file.
  2. bindings/uniffi.rs → which flows have #[uniffi::export] {flow}_req_transformer

Generates _generated_flows.* files for all SDK connector clients.

Usage (from repo root):
    python3 sdk/codegen/generate.py
    make generate
"""

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent.parent
SDK_ROOT = REPO_ROOT / "sdk"
SERVICES_PROTO = REPO_ROOT / "backend/grpc-api-types/proto/services.proto"
FFI_BINDINGS = REPO_ROOT / "backend/ffi/src/bindings/uniffi.rs"


# ── Source parsing ───────────────────────────────────────────────────────────

def to_snake_case(name: str) -> str:
    """'CreateAccessToken' -> 'create_access_token'"""
    s = re.sub("(.)([A-Z][a-z]+)", r"\1_\2", name)
    return re.sub("([a-z0-9])([A-Z])", r"\1_\2", s).lower()


def parse_proto_rpcs(proto_file: Path) -> dict[str, dict]:
    """
    Parse all rpc definitions, capturing:
      - request / response type names
      - the parent service name
      - the rpc's original PascalCase name
      - the first line of the leading // doc-comment (if any)

    Returns {snake_case_rpc_name: {...}}.
    First-occurrence wins on name collision (e.g. PaymentService.Get beats
    RefundService.Get for the key 'get'), which matches the FFI implementation.
    """
    lines = proto_file.read_text().splitlines()
    rpcs: dict[str, dict] = {}
    current_service: str | None = None
    pending_comments: list[str] = []

    for line in lines:
        stripped = line.strip()

        # Track current service block
        sm = re.match(r"service\s+(\w+)\s*\{", stripped)
        if sm:
            current_service = sm.group(1)
            pending_comments = []
            continue

        # Accumulate consecutive leading // comment lines
        if stripped.startswith("//"):
            pending_comments.append(stripped[2:].strip())
            continue

        # Parse rpc definition
        rm = re.match(
            r"rpc\s+(\w+)\s*\(\s*(\w+)\s*\)\s+returns\s*\(\s*(\w+)\s*\)", stripped
        )
        if rm and current_service:
            rpc_name, req_type, res_type = rm.groups()
            snake = to_snake_case(rpc_name)
            if snake not in rpcs:
                # Join all comment lines; fall back to ServiceName.RpcName if none
                desc = (
                    " ".join(pending_comments)
                    if pending_comments
                    else f"{current_service}.{rpc_name}"
                )
                rpcs[snake] = {
                    "request": req_type,
                    "response": res_type,
                    "service": current_service,
                    "rpc": rpc_name,
                    "description": desc,
                }

        # Any non-comment line (including blank lines and rpc lines) resets the buffer
        pending_comments = []

    return rpcs


def parse_ffi_flows(ffi_file: Path) -> set[str]:
    """
    Scan bindings/uniffi.rs for every function marked with #[uniffi::export]
    whose name matches {flow}_req_transformer.
    """
    text = ffi_file.read_text()
    return {
        m.group(1)
        for m in re.finditer(
            r"#\[uniffi::export\]\s+pub fn (\w+)_req_transformer\b", text
        )
    }


def discover_flows() -> list[dict]:
    """
    Cross-reference proto RPCs with implemented FFI transformers.
    Only flows present in BOTH sources are returned, sorted by name.
    """
    proto_rpcs = parse_proto_rpcs(SERVICES_PROTO)
    ffi_flows = parse_ffi_flows(FFI_BINDINGS)

    flows = []
    for flow in sorted(ffi_flows):
        if flow not in proto_rpcs:
            print(
                f"  WARNING: '{flow}_req_transformer' exists in FFI but has no matching RPC in services.proto",
                file=sys.stderr,
            )
            continue
        flows.append({"name": flow, **proto_rpcs[flow]})

    unimplemented = sorted(set(proto_rpcs) - ffi_flows)
    if unimplemented:
        print(f"  Proto RPCs not yet in FFI (skipped): {unimplemented}")

    return flows


# ── Generators ───────────────────────────────────────────────────────────────

def write(path: Path, content: str) -> None:
    path.write_text(content)
    print(f"  wrote {path.relative_to(REPO_ROOT)}")


def flow_comment(f: dict, prefix: str) -> str:
    """
    Single-line comment for a flow, e.g.:
      // authorize: PaymentService.Authorize — Authorizes a payment amount...
    """
    return f"{prefix} {f['name']}: {f['service']}.{f['rpc']} — {f['description']}"


def gen_python(flows: list[dict]) -> None:
    lines = [
        "# AUTO-GENERATED — do not edit by hand.",
        "# Source: services.proto ∩ bindings/uniffi.rs  |  Regenerate: make generate",
        "FLOW_RESPONSES = {",
    ]
    for f in flows:
        lines.append(flow_comment(f, "    #"))
        lines.append(f'    "{f["name"]}": "{f["response"]}",')
    lines.append("}")
    write(
        SDK_ROOT / "python/src/payments/_generated_flows.py",
        "\n".join(lines) + "\n",
    )


def gen_python_stub(flows: list[dict]) -> None:
    """Generate connector_client.pyi so IDEs can resolve flow methods and offer completions."""
    # Collect all proto types that need importing
    types: set[str] = set()
    for f in flows:
        types.add(f["request"])
        types.add(f["response"])

    imports = sorted(types)

    lines = [
        "# AUTO-GENERATED — do not edit by hand.",
        "# Source: services.proto ∩ bindings/uniffi.rs  |  Regenerate: make generate",
        "#",
        "# This stub exposes dynamically-attached flow methods to static analysers",
        "# (Pylance, pyright, mypy) so IDEs offer completions and type checking.",
        "from payments.generated.sdk_options_pb2 import FfiOptions",
        "from payments.generated.payment_pb2 import (",
    ]
    for t in imports:
        lines.append(f"    {t},")
    lines += [
        ")",
        "",
        "class ConnectorClient:",
        "    def __init__(self, lib_path: str | None = ...) -> None: ...",
        "",
    ]

    for f in flows:
        n, req, res = f["name"], f["request"], f["response"]
        lines.append(
            f"    def {n}(self, request: {req}, metadata: dict, options: FfiOptions | None = ...) -> {res}:"
        )
        lines.append(f'        """{f["service"]}.{f["rpc"]} — {f["description"]}"""')
        lines.append(f"        ...")
        lines.append("")

    write(
        SDK_ROOT / "python/src/payments/connector_client.pyi",
        "\n".join(lines) + "\n",
    )


def to_camel(snake: str) -> str:
    """'create_access_token' -> 'createAccessToken'"""
    return re.sub(r"_([a-z])", lambda m: m.group(1).upper(), snake)

def gen_javascript(flows: list[dict]) -> None:
    # Generate flow methods into connector_client.ts between markers
    gen_connector_client_ts_flows(flows)
    gen_uniffi_client_ts_flows(flows)


def gen_connector_client_ts_flows(flows: list[dict]) -> None:
    """Insert generated flow methods between markers in connector_client.ts."""
    ts_file = SDK_ROOT / "javascript/src/payments/connector_client.ts"
    content = ts_file.read_text()

    start_marker = "  // <GENERATED_FLOWS_START>"
    end_marker = "  // <GENERATED_FLOWS_END>"

    if start_marker not in content or end_marker not in content:
        print(f"  WARNING: Markers not found in {ts_file}, skipping flow generation")
        return

    # Generate flow methods
    flow_lines = [
        "  // <GENERATED_FLOWS_START> - This section is auto-generated by sdk/codegen/generate.py",
        "  // Do not edit manually. Run `make generate` to update.",
        "",
    ]

    for f in flows:
        n, req, res = f["name"], f["request"], f["response"]
        camel = to_camel(n)
        flow_lines.append(f"  /** {f['service']}.{f['rpc']} — {f['description']} */")
        flow_lines.append(f"  async {camel}(")
        flow_lines.append(f"    requestMsg: ucs.v2.I{req},")
        flow_lines.append(f"    metadata: Record<string, string>,")
        flow_lines.append(f"    ffiOptions?: ucs.v2.IFfiOptions | null")
        flow_lines.append(f"  ): Promise<ucs.v2.{res}> {{")
        flow_lines.append(f"    return this._executeFlow('{n}', requestMsg, metadata, ffiOptions, '{req}', '{res}') as Promise<ucs.v2.{res}>;")
        flow_lines.append(f"  }}")
        flow_lines.append("")

    flow_lines.append("  // <GENERATED_FLOWS_END>")

    # Replace content between markers
    start_idx = content.find(start_marker)
    end_idx = content.find(end_marker) + len(end_marker)
    new_content = content[:start_idx] + "\n".join(flow_lines) + content[end_idx:]

    ts_file.write_text(new_content)
    print(f"  wrote flows to {ts_file.relative_to(REPO_ROOT)}")


def gen_uniffi_client_ts_flows(flows: list[dict]) -> None:
    """Insert generated concrete flow methods between markers in uniffi_client.ts."""
    ts_file = SDK_ROOT / "javascript/src/payments/uniffi_client.ts"
    content = ts_file.read_text()

    start_marker = "  // <GENERATED_FLOWS_START>"
    end_marker = "  // <GENERATED_FLOWS_END>"

    if start_marker not in content or end_marker not in content:
        print(f"  WARNING: Markers not found in {ts_file}, skipping flow generation")
        return

    # Generate flow methods
    flow_lines = [
        "  // <GENERATED_FLOWS_START> - This section is auto-generated by sdk/codegen/generate.py",
        "  // Do not edit manually. Run `make generate` to update.",
        "",
    ]

    for f in flows:
        n = f["name"]
        camel = to_camel(n)
        # Generate Req method that delegates to callReq
        flow_lines.append(f"  /** Build connector HTTP request for {n} flow. */")
        flow_lines.append(f"  {camel}Req(")
        flow_lines.append(f"    requestBytes: Buffer | Uint8Array,")
        flow_lines.append(f"    metadata: Record<string, string>,")
        flow_lines.append(f"    optionsBytes: Buffer | Uint8Array")
        flow_lines.append(f"  ): Buffer {{")
        flow_lines.append(f"    return this.callReq('{n}', requestBytes, metadata, optionsBytes);")
        flow_lines.append(f"  }}")
        flow_lines.append(f"")
        # Generate Res method that delegates to callRes
        flow_lines.append(f"  /** Parse connector HTTP response for {n} flow. */")
        flow_lines.append(f"  {camel}Res(")
        flow_lines.append(f"    responseBytes: Buffer | Uint8Array,")
        flow_lines.append(f"    requestBytes: Buffer | Uint8Array,")
        flow_lines.append(f"    metadata: Record<string, string>,")
        flow_lines.append(f"    optionsBytes: Buffer | Uint8Array")
        flow_lines.append(f"  ): Buffer {{")
        flow_lines.append(f"    return this.callRes('{n}', responseBytes, requestBytes, metadata, optionsBytes);")
        flow_lines.append(f"  }}")
        flow_lines.append(f"")

    flow_lines.append("  // <GENERATED_FLOWS_END>")

    # Replace content between markers
    start_idx = content.find(start_marker)
    end_idx = content.find(end_marker) + len(end_marker)
    new_content = content[:start_idx] + "\n".join(flow_lines) + content[end_idx:]

    ts_file.write_text(new_content)
    print(f"  wrote flows to {ts_file.relative_to(REPO_ROOT)}")


def gen_kotlin(flows: list[dict]) -> None:
    lines = [
        "// AUTO-GENERATED — do not edit by hand.",
        "// Source: services.proto ∩ bindings/uniffi.rs  |  Regenerate: make generate",
        "",
    ]

    # FFI transformer imports — use full camelCase matching UniFFI Kotlin codegen
    for f in flows:
        camel = to_camel(f["name"])
        lines += [
            f"import uniffi.connector_service_ffi.{camel}ReqTransformer",
            f"import uniffi.connector_service_ffi.{camel}ResTransformer",
        ]
    lines.append("")

    # Proto imports — deduplicated (request + response per flow)
    seen: set[str] = set()
    for f in flows:
        for cls in (f["request"], f["response"]):
            if cls not in seen:
                lines.append(f"import ucs.v2.Payment.{cls}")
                seen.add(cls)
    lines.append("import ucs.v2.SdkOptions.FfiOptions")
    lines.append("")

    # FlowRegistry object
    # reqTransformers: returns ByteArray (protobuf FfiConnectorHttpRequest bytes)
    # resTransformers: 4-param (responseBytes, requestBytes, metadata, optionsBytes)
    lines += [
        "object FlowRegistry {",
        "    val reqTransformers: Map<String, (ByteArray, Map<String, String>, ByteArray) -> ByteArray> = mapOf(",
    ]
    for f in flows:
        camel = to_camel(f["name"])
        lines.append(f'        "{f["name"]}" to ::{camel}ReqTransformer,')
    lines += [
        "    )",
        "",
        "    val resTransformers: Map<String, (ByteArray, ByteArray, Map<String, String>, ByteArray) -> ByteArray> = mapOf(",
    ]
    for f in flows:
        camel = to_camel(f["name"])
        lines.append(f'        "{f["name"]}" to ::{camel}ResTransformer,')
    lines += ["    )", "}", ""]

    # Extension functions with doc-comments
    lines.append("// Extension functions — typed with concrete proto request/response types.")
    lines.append("")
    for f in flows:
        n, req, res = f["name"], f["request"], f["response"]
        lines.append(flow_comment(f, "//"))
        lines.append(
            f"fun ConnectorClient.{n}(request: {req}, metadata: Map<String, String>, options: FfiOptions? = null): {res} ="
        )
        lines.append(f'    executeFlow("{n}", request.toByteArray(), {res}.parser(), metadata, options?.toByteArray())')
        lines.append("")

    write(
        SDK_ROOT / "java/src/main/kotlin/GeneratedFlows.kt",
        "\n".join(lines),
    )


def print_rust_note(flows: list[dict]) -> None:
    print()
    print("  Rust SDK — sdk/rust/src/connector_client.rs needs these methods:")
    for f in flows:
        n, req, res = f["name"], f["request"], f["response"]
        print(f"    // {f['service']}.{f['rpc']} — {f['description']}")
        print(f"    pub async fn {n}(&self, request: {req}, metadata: &HashMap<String, String>)")
        print(f"        -> Result<{res}, Box<dyn Error>>")
        print(f"        {{ /* {n}_req_handler / {n}_res_handler */ }}")


# ── Entry point ──────────────────────────────────────────────────────────────

def main() -> None:
    print(f"Parsing: {SERVICES_PROTO.relative_to(REPO_ROOT)}")
    print(f"Parsing: {FFI_BINDINGS.relative_to(REPO_ROOT)}")
    print()

    flows = discover_flows()

    print(f"Discovered {len(flows)} flows: {[f['name'] for f in flows]}")
    print()

    print("Generating Python SDK...")
    gen_python(flows)
    gen_python_stub(flows)

    print("Generating JavaScript SDK...")
    gen_javascript(flows)

    print("Generating Kotlin SDK...")
    gen_kotlin(flows)

    print("Rust SDK (manual — Rust requires explicit types):")
    print_rust_note(flows)

    print("\nDone.")


if __name__ == "__main__":
    main()
