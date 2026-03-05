
#!/usr/bin/env python3
"""
SDK codegen — auto-discovers payment flows and generates type-safe client methods.

Cross-references:
  1. services.proto (via protoc descriptor) → RPC definitions with types and docs
  2. services/payments.rs → which flows have req_transformer implementations

Generates flow methods (authorize, capture, refund, etc.) for each SDK,
and the Rust FFI flow registration files.

Usage:
    # Generate all SDKs + Rust FFI registrations
    python3 sdk/codegen/generate.py
    make generate

    # Generate specific language only
    python3 sdk/codegen/generate.py --lang python
    python3 sdk/codegen/generate.py --lang javascript
    python3 sdk/codegen/generate.py --lang kotlin
    python3 sdk/codegen/generate.py --lang rust

    # Via individual SDK Makefiles
    make -C sdk/python generate
    make -C sdk/javascript generate
    make -C sdk/java generate
"""

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent.parent
SDK_ROOT = REPO_ROOT / "sdk"
SERVICES_PROTO = REPO_ROOT / "backend/grpc-api-types/proto/services.proto"
FFI_SERVICES = REPO_ROOT / "backend/ffi/src/services/payments.rs"
PROTO_DESCRIPTOR = REPO_ROOT / "sdk/codegen/services.desc"

RUST_HANDLERS_OUT = REPO_ROOT / "backend/ffi/src/handlers/_generated_flow_registrations.rs"
RUST_FFI_FLOWS_OUT = REPO_ROOT / "backend/ffi/src/bindings/_generated_ffi_flows.rs"


def ensure_descriptor_exists() -> None:
    """Verify proto descriptor file exists and is readable."""
    if not PROTO_DESCRIPTOR.exists():
        print(
            f"ERROR: Proto descriptor not found: {PROTO_DESCRIPTOR}",
            file=sys.stderr,
        )
        print(
            "Run 'make generate' from the sdk directory to generate the descriptor.",
            file=sys.stderr,
        )
        sys.exit(1)


# ── Source parsing ───────────────────────────────────────────────────────────

def to_snake_case(name: str) -> str:
    """'CreateAccessToken' -> 'create_access_token'"""
    s = re.sub("(.)([A-Z][a-z]+)", r"\1_\2", name)
    return re.sub("([a-z0-9])([A-Z])", r"\1_\2", s).lower()


def parse_proto_rpcs(desc_file: Path) -> dict[str, dict]:
    """
    Parse RPC definitions from a protobuf descriptor file.
    
    Uses protoc-generated descriptor to properly handle:
      - All proto syntax (imports, nested types, options)
      - Request/response type names
      - Parent service name
      - Original PascalCase RPC name
      - Doc comments from SourceCodeInfo
    
    Returns {snake_case_rpc_name: {...}}.
    First-occurrence wins on name collision.
    """
    from google.protobuf.descriptor_pb2 import FileDescriptorSet
    
    with open(desc_file, 'rb') as f:
        desc_set = FileDescriptorSet.FromString(f.read())
    
    rpcs: dict[str, dict] = {}
    
    for file_desc in desc_set.file:
        # Build source info lookup for doc comments
        # Location path: [service_index, method_index]
        source_info = {}
        if file_desc.source_code_info:
            for location in file_desc.source_code_info.location:
                path = tuple(location.path)
                if location.leading_comments:
                    source_info[path] = location.leading_comments.strip()
        
        for svc_idx, service in enumerate(file_desc.service):
            for method_idx, method in enumerate(service.method):
                rpc_name = method.name
                snake = to_snake_case(rpc_name)
                
                if snake not in rpcs:
                    # Extract type names (remove package prefix)
                    req_type = method.input_type.split('.')[-1]
                    res_type = method.output_type.split('.')[-1]
                    
                    # Get doc comment if available
                    # Path for method: [6 (service), svc_idx, 2 (method), method_idx]
                    path = (6, svc_idx, 2, method_idx)
                    comment = source_info.get(path, f"{service.name}.{rpc_name}")
                    # Normalize whitespace to single-line
                    comment = ' '.join(comment.split())
                    
                    rpcs[snake] = {
                        "request": req_type,
                        "response": res_type,
                        "service": service.name,
                        "rpc": rpc_name,
                        "description": comment,
                    }
    
    return rpcs


def parse_service_flows(service_file: Path) -> set[str]:
    """
    Scan services/payments.rs for every req_transformer! invocation.
    Captures the flow name from `fn_name: {flow}_req_transformer`.
    """
    text = service_file.read_text()
    return {
        m.group(1)
        for m in re.finditer(
            r"fn_name:\s*(\w+)_req_transformer\b", text
        )
    }


def discover_flows() -> list[dict]:
    """
    Cross-reference proto RPCs with implemented service transformers.
    Only flows present in BOTH sources are returned, sorted by name.
    """
    proto_rpcs = parse_proto_rpcs(PROTO_DESCRIPTOR)
    service_flows = parse_service_flows(FFI_SERVICES)

    flows = []
    for flow in sorted(service_flows):
        if flow not in proto_rpcs:
            print(
                f"  WARNING: '{flow}_req_transformer' exists in services/payments.rs but has no matching RPC in services.proto",
                file=sys.stderr,
            )
            continue
        flows.append({"name": flow, **proto_rpcs[flow]})

    unimplemented = sorted(set(proto_rpcs) - service_flows)
    if unimplemented:
        print(f"  Proto RPCs not yet implemented (skipped): {unimplemented}")

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
    # Normalize all whitespace to single spaces for single-line comment
    desc = ' '.join(f['description'].split())
    return f"{prefix} {f['name']}: {f['service']}.{f['rpc']} — {desc}"


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
    gen_flows_js(flows)
    gen_connector_client_ts(flows)
    gen_uniffi_client_ts(flows)


def gen_flows_js(flows: list[dict]) -> None:
    """Generate _generated_flows.js — flow metadata used by UniffiClient for FFI symbol dispatch."""
    max_len = max((len(f["name"]) for f in flows), default=0)
    lines = [
        "// AUTO-GENERATED — do not edit by hand.",
        "// Source: services.proto ∩ bindings/uniffi.rs  |  Regenerate: make generate",
        '"use strict";',
        "",
        "const FLOWS = {",
    ]
    for f in flows:
        lines.append(f"  {flow_comment(f, '//')}")
        padding = " " * (max_len - len(f["name"]) + 1)
        lines.append(f'  {f["name"]}{padding}: {{ request: "{f["request"]}", response: "{f["response"]}" }},')
        lines.append("")
    lines += ["};", "", "module.exports = { FLOWS };", ""]
    write(SDK_ROOT / "javascript/src/payments/_generated_flows.js", "\n".join(lines))


def gen_connector_client_ts(flows: list[dict]) -> None:
    """Generate _generated_connector_client_flows.ts — ConnectorClient subclass with typed flow methods."""
    lines = [
        "// AUTO-GENERATED — do not edit by hand.",
        "// Source: services.proto ∩ bindings/uniffi.rs  |  Regenerate: make generate",
        "",
        'import { ConnectorClient as _ConnectorClientBase } from "./connector_client";',
        '// @ts-ignore - protobuf generated files might not have types yet',
        'import { ucs } from "./generated/proto";',
        "",
        "export class ConnectorClient extends _ConnectorClientBase {",
    ]
    for f in flows:
        n, req, res = f["name"], f["request"], f["response"]
        camel = to_camel(n)
        lines.append(f"  /** {f['service']}.{f['rpc']} — {f['description']} */")
        lines.append(f"  async {camel}(")
        lines.append(f"    requestMsg: ucs.v2.I{req},")
        lines.append(f"    metadata: Record<string, string>,")
        lines.append(f"    requestOptions?: ucs.v2.IRequestOptions | null")
        lines.append(f"  ): Promise<ucs.v2.{res}> {{")
        lines.append(f"    return this._executeFlow('{n}', requestMsg, metadata, requestOptions, '{req}', '{res}') as Promise<ucs.v2.{res}>;")
        lines.append(f"  }}")
        lines.append("")
    lines += ["}", ""]
    write(
        SDK_ROOT / "javascript/src/payments/_generated_connector_client_flows.ts",
        "\n".join(lines),
    )


def gen_uniffi_client_ts(flows: list[dict]) -> None:
    """Generate _generated_uniffi_client_flows.ts — UniffiClient subclass with typed flow methods."""
    lines = [
        "// AUTO-GENERATED — do not edit by hand.",
        "// Source: services.proto ∩ bindings/uniffi.rs  |  Regenerate: make generate",
        "",
        'import { UniffiClient as _UniffiClientBase } from "./uniffi_client";',
        "",
        "export class UniffiClient extends _UniffiClientBase {",
    ]
    for f in flows:
        n = f["name"]
        camel = to_camel(n)
        lines.append(f"  /** Build connector HTTP request for {n} flow. */")
        lines.append(f"  {camel}Req(")
        lines.append(f"    requestBytes: Buffer | Uint8Array,")
        lines.append(f"    metadata: Record<string, string>,")
        lines.append(f"    optionsBytes: Buffer | Uint8Array")
        lines.append(f"  ): Buffer {{")
        lines.append(f"    return this.callReq('{n}', requestBytes, metadata, optionsBytes);")
        lines.append(f"  }}")
        lines.append("")
        lines.append(f"  /** Parse connector HTTP response for {n} flow. */")
        lines.append(f"  {camel}Res(")
        lines.append(f"    responseBytes: Buffer | Uint8Array,")
        lines.append(f"    requestBytes: Buffer | Uint8Array,")
        lines.append(f"    metadata: Record<string, string>,")
        lines.append(f"    optionsBytes: Buffer | Uint8Array")
        lines.append(f"  ): Buffer {{")
        lines.append(f"    return this.callRes('{n}', responseBytes, requestBytes, metadata, optionsBytes);")
        lines.append(f"  }}")
        lines.append("")
    lines += ["}", ""]
    write(
        SDK_ROOT / "javascript/src/payments/_generated_uniffi_client_flows.ts",
        "\n".join(lines),
    )


def gen_kotlin(flows: list[dict]) -> None:
    lines = [
        "// AUTO-GENERATED — do not edit by hand.",
        "// Source: services.proto ∩ services/payments.rs  |  Regenerate: make generate",
        "",
        "package payments",
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
    # Proto types and FfiOptions are available via type aliases in package payments
    # (Payments.kt / Configs.kt) — no ucs.v2.* imports needed.

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


def gen_rust_handlers(flows: list[dict]) -> None:
    """Generate _generated_flow_registrations.rs — included by handlers/payments.rs."""
    all_types = sorted({t for f in flows for t in (f["request"], f["response"])})

    lines = [
        "// AUTO-GENERATED — do not edit by hand.",
        "// Source: services.proto ∩ services/payments.rs  |  Regenerate: make generate",
        "",
        "use grpc_api_types::payments::{",
    ]
    for t in all_types:
        lines.append(f"    {t},")
    lines.append("};")
    lines.append("use crate::services::payments::{")
    for f in flows:
        lines.append(f"    {f['name']}_req_transformer, {f['name']}_res_transformer,")
    lines.append("};")
    lines.append("")
    for f in flows:
        n, req, res = f["name"], f["request"], f["response"]
        lines.append(flow_comment(f, "//"))
        lines.append(f"impl_flow_handlers!({n}, {req}, {res}, {n}_req_transformer, {n}_res_transformer);")
    lines.append("")
    write(RUST_HANDLERS_OUT, "\n".join(lines))


def gen_rust_ffi_flows(flows: list[dict]) -> None:
    """Generate _generated_ffi_flows.rs — included by bindings/uniffi.rs."""
    req_types = sorted({f["request"] for f in flows})

    lines = [
        "// AUTO-GENERATED — do not edit by hand.",
        "// Source: services.proto ∩ services/payments.rs  |  Regenerate: make generate",
        "",
        "use grpc_api_types::payments::{",
    ]
    for t in req_types:
        lines.append(f"    {t},")
    lines.append("};")
    lines.append("use crate::handlers::payments::{")
    for f in flows:
        lines.append(f"    {f['name']}_req_handler, {f['name']}_res_handler,")
    lines.append("};")
    lines.append("")
    for f in flows:
        n, req = f["name"], f["request"]
        lines.append(flow_comment(f, "//"))
        lines.append(f"define_ffi_flow!({n}, {req}, {n}_req_handler, {n}_res_handler);")
    lines.append("")
    write(RUST_FFI_FLOWS_OUT, "\n".join(lines))


# ── Entry point ──────────────────────────────────────────────────────────────

def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(
        description="SDK codegen — regenerate SDK clients from services.proto ∩ services/payments.rs"
    )

    parser.add_argument(
        "--lang",
        choices=["python", "javascript", "kotlin", "rust", "all"],
        default="all",
        help="Which language/SDK to generate (default: all)"
    )
    args = parser.parse_args()

    ensure_descriptor_exists()

    print(f"Parsing: {SERVICES_PROTO.relative_to(REPO_ROOT)}")
    print(f"Parsing: {FFI_SERVICES.relative_to(REPO_ROOT)}")
    print()

    flows = discover_flows()

    print(f"Discovered {len(flows)} flows: {[f['name'] for f in flows]}")
    print()

    if args.lang in ("rust", "all"):
        print("Generating Rust FFI flow registrations...")
        gen_rust_handlers(flows)
        gen_rust_ffi_flows(flows)

    if args.lang in ("python", "all"):
        print("Generating Python SDK...")
        gen_python(flows)
        gen_python_stub(flows)

    if args.lang in ("javascript", "all"):
        print("Generating JavaScript SDK...")
        gen_javascript(flows)

    if args.lang in ("kotlin", "all"):
        print("Generating Kotlin SDK...")
        gen_kotlin(flows)

    print("\nDone.")


if __name__ == "__main__":
    main()
