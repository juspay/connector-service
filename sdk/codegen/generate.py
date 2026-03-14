
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


def parse_single_flows(service_file: Path) -> set[str]:
    """
    Scan services/payments.rs for hand-written single-step transformers.
    These are `pub fn {flow}_transformer` functions that are NOT req/res macros —
    they take the request directly and return the response without an HTTP round-trip
    (e.g. webhook processing via `handle_transformer`).
    """
    text = service_file.read_text()
    return {
        m.group(1)
        for m in re.finditer(r"^pub fn (\w+)_transformer\b", text, re.MULTILINE)
    }


def discover_flows() -> tuple[list[dict], list[dict]]:
    """
    Cross-reference proto RPCs with implemented service transformers.
    Returns (standard_flows, single_flows) — both sorted by name.
    Standard flows use req+HTTP+res; single flows call the transformer directly.
    """
    proto_rpcs = parse_proto_rpcs(PROTO_DESCRIPTOR)
    service_flows = parse_service_flows(FFI_SERVICES)
    single_flow_names = parse_single_flows(FFI_SERVICES)

    flows = []
    for flow in sorted(service_flows):
        if flow not in proto_rpcs:
            print(
                f"  WARNING: '{flow}_req_transformer' exists in services/payments.rs but has no matching RPC in services.proto",
                file=sys.stderr,
            )
            continue
        flows.append({"name": flow, **proto_rpcs[flow]})

    single_flows = []
    for flow in sorted(single_flow_names):
        if flow not in proto_rpcs:
            print(
                f"  WARNING: '{flow}_transformer' exists in services/payments.rs but has no matching RPC in services.proto",
                file=sys.stderr,
            )
            continue
        single_flows.append({"name": flow, **proto_rpcs[flow]})

    implemented = service_flows | single_flow_names
    unimplemented = sorted(set(proto_rpcs) - implemented)
    if unimplemented:
        print(f"  Proto RPCs not yet implemented (skipped): {unimplemented}")

    return flows, single_flows


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


def gen_python(flows: list[dict], single_flows: list[dict]) -> None:
    groups = group_by_service(flows)
    lines = [
        "# AUTO-GENERATED — do not edit by hand.",
        "# Source: services.proto ∩ bindings/uniffi.rs  |  Regenerate: make generate",
        "SERVICE_FLOWS = {",
    ]
    for service, sflows in groups.items():
        client_name = service_to_client_name(service)
        lines.append(f'    "{client_name}": {{')
        for f in sflows:
            lines.append(flow_comment(f, "        #"))
            lines.append(f'        "{f["name"]}": "{f["response"]}",')
        lines.append("    },")
    lines.append("}")
    if single_flows:
        lines.append("")
        lines.append("# Single-step flows: no HTTP round-trip (e.g. webhook processing).")
        lines.append("SINGLE_SERVICE_FLOWS = {")
        for service, sflows in group_by_service(single_flows).items():
            client_name = service_to_client_name(service)
            lines.append(f'    "{client_name}": {{')
            for f in sflows:
                lines.append(flow_comment(f, "        #"))
                lines.append(f'        "{f["name"]}": "{f["response"]}",')
            lines.append("    },")
        lines.append("}")
    write(
        SDK_ROOT / "python/src/payments/_generated_flows.py",
        "\n".join(lines) + "\n",
    )


def gen_python_clients(flows: list[dict], single_flows: list[dict]) -> None:
    """Generate _generated_service_clients.py — per-service client classes."""
    groups = group_by_service(flows)
    single_groups = group_by_service(single_flows)
    all_groups = {**groups}
    for service, sflows in single_groups.items():
        all_groups.setdefault(service, [])

    lines = [
        "# AUTO-GENERATED — do not edit by hand.",
        "# Source: services.proto ∩ bindings/uniffi.rs  |  Regenerate: make generate",
        "",
        "from payments.connector_client import _ConnectorClientBase",
        "import payments.generated.payment_pb2 as _pb2",
        "",
    ]

    for service in sorted(all_groups):
        client_name = service_to_client_name(service)
        lines.append(f"class {client_name}(_ConnectorClientBase):")
        lines.append(f'    """{service} flows"""')
        for f in groups.get(service, []):
            n, res = f["name"], f["response"]
            lines.append("")
            lines.append(f"    def {n}(self, request, options=None):")
            lines.append(f'        """{f["service"]}.{f["rpc"]} — {f["description"]}"""')
            lines.append(f'        return self._execute_flow("{n}", request, _pb2.{res}, options)')
        for f in single_groups.get(service, []):
            n, res = f["name"], f["response"]
            lines.append("")
            lines.append(f"    def {n}(self, request, options=None):")
            lines.append(f'        """{f["service"]}.{f["rpc"]} — {f["description"]}"""')
            lines.append(f'        return self._execute_direct("{n}", request, _pb2.{res}, options)')
        lines.append("")

    write(
        SDK_ROOT / "python/src/payments/_generated_service_clients.py",
        "\n".join(lines) + "\n",
    )


def gen_python_stub(flows: list[dict], single_flows: list[dict] = []) -> None:
    """Generate connector_client.pyi — per-service client stubs for IDE completions."""
    groups = group_by_service(flows)
    single_groups = group_by_service(single_flows)

    # Collect all proto types that need importing
    types: set[str] = set()
    for f in flows + single_flows:
        types.add(f["request"])
        types.add(f["response"])

    imports = sorted(types)

    lines = [
        "# AUTO-GENERATED — do not edit by hand.",
        "# Source: services.proto ∩ bindings/uniffi.rs  |  Regenerate: make generate",
        "#",
        "# This stub exposes per-service client classes to static analysers",
        "# (Pylance, pyright, mypy) so IDEs offer completions and type checking.",
        "from payments.generated.sdk_config_pb2 import ConnectorConfig, RequestConfig",
        "from payments.generated.payment_pb2 import (",
    ]
    for t in imports:
        lines.append(f"    {t},")
    lines += [
        ")",
        "",
        "class _ConnectorClientBase:",
        "    def __init__(self, config: ConnectorConfig, defaults: RequestConfig | None = ..., lib_path: str | None = ...) -> None: ...",
        "",
    ]

    all_services = sorted(set(groups) | set(single_groups))
    for service in all_services:
        client_name = service_to_client_name(service)
        lines.append(f"class {client_name}(_ConnectorClientBase):")
        for f in groups.get(service, []):
            n, req, res = f["name"], f["request"], f["response"]
            lines.append(
                f"    def {n}(self, request: {req}, options: RequestConfig | None = ...) -> {res}:"
            )
            lines.append(f'        """{f["service"]}.{f["rpc"]} — {f["description"]}"""')
            lines.append(f"        ...")
            lines.append("")
        for f in single_groups.get(service, []):
            n, req, res = f["name"], f["request"], f["response"]
            lines.append(
                f"    def {n}(self, request: {req}, options: RequestConfig | None = ...) -> {res}:"
            )
            lines.append(f'        """{f["service"]}.{f["rpc"]} — {f["description"]}"""')
            lines.append(f"        ...")
            lines.append("")
        lines.append("")

    write(
        SDK_ROOT / "python/src/payments/connector_client.pyi",
        "\n".join(lines) + "\n",
    )


def service_to_client_name(service: str) -> str:
    """'PaymentService' -> 'PaymentClient', 'MerchantAuthenticationService' -> 'MerchantAuthenticationClient'"""
    return service[:-7] + "Client" if service.endswith("Service") else service + "Client"


def group_by_service(flows: list[dict]) -> dict[str, list[dict]]:
    """Group flows by their proto service name. Returns {service_name: [flow, ...]}."""
    groups: dict[str, list[dict]] = {}
    for f in flows:
        groups.setdefault(f["service"], []).append(f)
    return groups


def to_camel(snake: str) -> str:
    """'create_access_token' -> 'createAccessToken'"""
    return re.sub(r"_([a-z])", lambda m: m.group(1).upper(), snake)


def gen_javascript(flows: list[dict], single_flows: list[dict]) -> None:
    gen_flows_js(flows, single_flows)
    gen_connector_client_ts(flows, single_flows)
    gen_uniffi_client_ts(flows, single_flows)


def gen_flows_js(flows: list[dict], single_flows: list[dict]) -> None:
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
    lines += ["};", ""]
    if single_flows:
        max_len_s = max((len(f["name"]) for f in single_flows), default=0)
        lines += ["// Single-step flows: no HTTP round-trip.", "const SINGLE_FLOWS = {"]
        for f in single_flows:
            lines.append(f"  {flow_comment(f, '//')}")
            padding = " " * (max_len_s - len(f["name"]) + 1)
            lines.append(f'  {f["name"]}{padding}: {{ request: "{f["request"]}", response: "{f["response"]}" }},')
            lines.append("")
        lines += ["};", ""]
        lines += ["module.exports = { FLOWS, SINGLE_FLOWS };", ""]
    else:
        lines += ["module.exports = { FLOWS };", ""]
    write(SDK_ROOT / "javascript/src/payments/_generated_flows.js", "\n".join(lines))


def gen_connector_client_ts(flows: list[dict], single_flows: list[dict]) -> None:
    """Generate _generated_connector_client_flows.ts — per-service client classes."""
    groups = group_by_service(flows)
    single_groups = group_by_service(single_flows)
    all_services = sorted(set(groups) | set(single_groups))

    lines = [
        "// AUTO-GENERATED — do not edit by hand.",
        "// Source: services.proto ∩ bindings/uniffi.rs  |  Regenerate: make generate",
        "",
        'import { ConnectorClient as _ConnectorClientBase } from "./connector_client";',
        '// @ts-ignore - protobuf generated files might not have types yet',
        'import { types } from "./generated/proto";',
        "",
    ]
    for service in all_services:
        client_name = service_to_client_name(service)
        lines.append(f"export class {client_name} extends _ConnectorClientBase {{")
        for f in groups.get(service, []):
            n, req, res = f["name"], f["request"], f["response"]
            camel = to_camel(n)
            lines.append(f"  /** {f['service']}.{f['rpc']} — {f['description']} */")
            lines.append(f"  async {camel}(")
            lines.append(f"    requestMsg: types.I{req},")
            lines.append(f"    options?: types.IRequestConfig | null")
            lines.append(f"  ): Promise<types.{res}> {{")
            lines.append(f"    return this._executeFlow('{n}', requestMsg, options, '{req}', '{res}') as Promise<types.{res}>;")
            lines.append(f"  }}")
            lines.append("")
        for f in single_groups.get(service, []):
            n, req, res = f["name"], f["request"], f["response"]
            camel = to_camel(n)
            lines.append(f"  /** {f['service']}.{f['rpc']} — {f['description']} */")
            lines.append(f"  async {camel}(")
            lines.append(f"    requestMsg: types.I{req},")
            lines.append(f"    options?: types.IRequestConfig | null")
            lines.append(f"  ): Promise<types.{res}> {{")
            lines.append(f"    return this._executeDirect('{n}', requestMsg, options, '{req}', '{res}') as Promise<types.{res}>;")
            lines.append(f"  }}")
            lines.append("")
        lines += ["}", ""]

    write(
        SDK_ROOT / "javascript/src/payments/_generated_connector_client_flows.ts",
        "\n".join(lines),
    )


def gen_uniffi_client_ts(flows: list[dict], single_flows: list[dict]) -> None:
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
        lines.append(f"    optionsBytes: Buffer | Uint8Array")
        lines.append(f"  ): Buffer {{")
        lines.append(f"    return this.callReq('{n}', requestBytes, optionsBytes);")
        lines.append(f"  }}")
        lines.append("")
        lines.append(f"  /** Parse connector HTTP response for {n} flow. */")
        lines.append(f"  {camel}Res(")
        lines.append(f"    responseBytes: Buffer | Uint8Array,")
        lines.append(f"    requestBytes: Buffer | Uint8Array,")
        lines.append(f"    optionsBytes: Buffer | Uint8Array")
        lines.append(f"  ): Buffer {{")
        lines.append(f"    return this.callRes('{n}', responseBytes, requestBytes, optionsBytes);")
        lines.append(f"  }}")
        lines.append("")
    for f in single_flows:
        n = f["name"]
        camel = to_camel(n)
        lines.append(f"  /** Direct single-step transform for {n} (no HTTP round-trip). */")
        lines.append(f"  {camel}Direct(")
        lines.append(f"    requestBytes: Buffer | Uint8Array,")
        lines.append(f"    optionsBytes: Buffer | Uint8Array")
        lines.append(f"  ): Buffer {{")
        lines.append(f"    return this.callDirect('{n}', requestBytes, optionsBytes);")
        lines.append(f"  }}")
        lines.append("")
    lines += ["}", ""]
    write(
        SDK_ROOT / "javascript/src/payments/_generated_uniffi_client_flows.ts",
        "\n".join(lines),
    )


def gen_kotlin(flows: list[dict], single_flows: list[dict] = []) -> None:
    lines = [
        "// AUTO-GENERATED — do not edit by hand.",
        "// Source: services.proto ∩ services/payments.rs  |  Regenerate: make generate",
        "",
        "package payments",
        "",
        # All flow request/response types are generated from payment.proto into this class.
        # This wildcard import makes GeneratedFlows.kt self-contained: no manual typealias
        # additions needed in Payments.kt when new flows are added.
        "import types.Payment.*",
        "",
    ]

    # FFI transformer imports — use full camelCase matching UniFFI Kotlin codegen
    for f in flows:
        camel = to_camel(f["name"])
        lines += [
            f"import uniffi.connector_service_ffi.{camel}ReqTransformer",
            f"import uniffi.connector_service_ffi.{camel}ResTransformer",
        ]
    for f in single_flows:
        camel = to_camel(f["name"])
        lines.append(f"import uniffi.connector_service_ffi.{camel}Transformer")
    lines.append("")

    # FlowRegistry object — FFI req/res transformers take (requestBytes, optionsBytes) or
    # (responseBytes, requestBytes, optionsBytes); metadata is carried inside options/context.
    lines += [
        "object FlowRegistry {",
        "    val reqTransformers: Map<String, (ByteArray, ByteArray) -> ByteArray> = mapOf(",
    ]
    for f in flows:
        camel = to_camel(f["name"])
        lines.append(
            f'        "{f["name"]}" to {{ requestBytes, optionsBytes -> {camel}ReqTransformer(requestBytes, optionsBytes) }},'
        )
    lines += [
        "    )",
        "",
        "    val resTransformers: Map<String, (ByteArray, ByteArray, ByteArray) -> ByteArray> = mapOf(",
    ]
    for f in flows:
        camel = to_camel(f["name"])
        lines.append(
            f'        "{f["name"]}" to {{ responseBytes, requestBytes, optionsBytes -> {camel}ResTransformer(responseBytes, requestBytes, optionsBytes) }},'
        )
    lines += ["    )", ""]
    if single_flows:
        lines += [
            "    // Single-step flows: direct transformer, no HTTP round-trip.",
            "    val directTransformers: Map<String, (ByteArray, ByteArray) -> ByteArray> = mapOf(",
        ]
        for f in single_flows:
            camel = to_camel(f["name"])
            lines.append(
                f'        "{f["name"]}" to {{ requestBytes, optionsBytes -> {camel}Transformer(requestBytes, optionsBytes) }},'
            )
        lines += ["    )", ""]
    lines += ["}", ""]

    # Per-service classes extending ConnectorClient
    groups = group_by_service(flows)
    single_groups = group_by_service(single_flows)
    all_services = sorted(set(groups) | set(single_groups))
    lines.append("// Per-service client classes — typed with concrete proto request/response types.")
    lines.append("")
    for service in all_services:
        client_name = service_to_client_name(service)
        lines.append(f"class {client_name}(")
        lines.append(f"    config: ConnectorConfig,")
        lines.append(f"    defaults: RequestConfig = RequestConfig.getDefaultInstance(),")
        lines.append(f"    libPath: String? = null")
        lines.append(f") : ConnectorClient(config, defaults, libPath) {{")
        for f in groups.get(service, []):
            n, req, res = f["name"], f["request"], f["response"]
            lines.append(flow_comment(f, "    //"))
            lines.append(
                f"    fun {n}(request: {req}, options: RequestConfig? = null): {res} ="
            )
            lines.append(f'        executeFlow("{n}", request.toByteArray(), {res}.parser(), options)')
            lines.append("")
        for f in single_groups.get(service, []):
            n, req, res = f["name"], f["request"], f["response"]
            lines.append(flow_comment(f, "    //"))
            lines.append(
                f"    fun {n}(request: {req}, options: RequestConfig? = null): {res} ="
            )
            lines.append(f'        executeDirect("{n}", request.toByteArray(), {res}.parser(), options)')
            lines.append("")
        lines += ["}", ""]

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

    flows, single_flows = discover_flows()

    print(f"Discovered {len(flows)} flows: {[f['name'] for f in flows]}")
    if single_flows:
        print(f"Discovered {len(single_flows)} single-step flows: {[f['name'] for f in single_flows]}")
    print()

    if args.lang in ("rust", "all"):
        print("Generating Rust FFI flow registrations...")
        gen_rust_handlers(flows)
        gen_rust_ffi_flows(flows)

    if args.lang in ("python", "all"):
        print("Generating Python SDK...")
        gen_python(flows, single_flows)
        gen_python_stub(flows, single_flows)
        gen_python_clients(flows, single_flows)

    if args.lang in ("javascript", "all"):
        print("Generating JavaScript SDK...")
        gen_javascript(flows, single_flows)

    if args.lang in ("kotlin", "all"):
        print("Generating Kotlin SDK...")
        gen_kotlin(flows, single_flows)

    print("\nDone.")


if __name__ == "__main__":
    main()
