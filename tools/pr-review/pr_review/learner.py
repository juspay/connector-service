"""Learner module: scans the codebase to extract patterns and conventions.

This module provides the self-upgrading capability for the PR review tool.
Running `python -m pr_review learn` scans the repository and writes a
`learned_data.json` file that the rules consume at review time.

Data extracted (10 scanners):
    - Clippy lint levels (from [workspace.lints.clippy] + [workspace.lints.rust])
    - Flow structs and their marker trait mappings (from connector_flow.rs + connector_types.rs)
    - ConnectorCommon required methods (from api.rs)
    - Known connector names (from connectors directory)
    - AttemptStatus enum variants (from common_enums)
    - Sensitive field patterns learned from existing Secret<T> usage
    - Error response struct naming patterns
    - Conventional commit configuration (from cog.toml)
    - Proto conventions (package, go_package, services, SecretString fields)
    - Composite service patterns (request types, AccessToken impls, process methods)
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path


# ── Schema version ──────────────────────────────────────────────────
SCHEMA_VERSION = 1
LEARNED_DATA_FILENAME = "learned_data.json"


def default_learned_data_path(repo_root: str) -> str:
    """Return the default path for learned_data.json."""
    return os.path.join(repo_root, "tools", "pr-review", LEARNED_DATA_FILENAME)


# ── Individual scanner functions ────────────────────────────────────


def scan_clippy_lints(repo_root: str) -> dict:
    """Parse Cargo.toml [workspace.lints.clippy] and [workspace.lints.rust]."""
    cargo_path = Path(repo_root) / "Cargo.toml"
    if not cargo_path.exists():
        return {"clippy": {}, "rust": {}}

    content = cargo_path.read_text(encoding="utf-8", errors="replace")

    clippy_lints: dict[str, str] = {}
    rust_lints: dict[str, str] = {}

    current_section = None
    for line in content.splitlines():
        stripped = line.strip()

        # Detect section headers
        if stripped == "[workspace.lints.clippy]":
            current_section = "clippy"
            continue
        elif stripped == "[workspace.lints.rust]":
            current_section = "rust"
            continue
        elif stripped.startswith("["):
            current_section = None
            continue

        if current_section and "=" in stripped and not stripped.startswith("#"):
            # Parse: lint_name = "level" or lint_name = { level = "warn", ... }
            key, _, value = stripped.partition("=")
            key = key.strip()
            value = value.strip()

            # Simple: lint_name = "warn"
            simple = re.match(r'^"(\w+)"$', value)
            if simple:
                level = simple.group(1)
            else:
                # Complex: { level = "warn", priority = -1 }
                level_match = re.search(r'level\s*=\s*"(\w+)"', value)
                level = level_match.group(1) if level_match else None

            if level and key:
                target = clippy_lints if current_section == "clippy" else rust_lints
                target[key] = level

    return {"clippy": clippy_lints, "rust": rust_lints}


def scan_connector_flows(repo_root: str) -> dict:
    """Parse connector_flow.rs for flow structs and connector_types.rs for trait mappings."""
    flows: list[str] = []
    flow_trait_map: dict[str, str] = {}

    # 1. Parse connector_flow.rs for flow structs
    flow_path = (
        Path(repo_root) / "backend" / "domain_types" / "src" / "connector_flow.rs"
    )
    if flow_path.exists():
        content = flow_path.read_text(encoding="utf-8", errors="replace")
        # Match: pub struct FlowName;
        for m in re.finditer(r"pub\s+struct\s+(\w+)\s*;", content):
            flows.append(m.group(1))

    # 2. Parse connector_types.rs for trait-to-flow mappings
    types_path = (
        Path(repo_root) / "backend" / "interfaces" / "src" / "connector_types.rs"
    )
    if types_path.exists():
        content = types_path.read_text(encoding="utf-8", errors="replace")
        # Match: pub trait TraitName<...>: ConnectorIntegrationV2<connector_flow::FlowName, ...>
        # Handle multiline by joining with spaces
        single_line = " ".join(content.splitlines())
        for m in re.finditer(
            r"pub\s+trait\s+(\w+)(?:<[^>]*>)?\s*:\s*ConnectorIntegrationV2\s*<\s*connector_flow::(\w+)",
            single_line,
        ):
            trait_name = m.group(1)
            flow_name = m.group(2)
            flow_trait_map[flow_name] = trait_name

    return {
        "flow_structs": flows,
        "flow_trait_map": flow_trait_map,
    }


def scan_connector_common_methods(repo_root: str) -> list[str]:
    """Parse api.rs to extract ConnectorCommon trait method names."""
    api_path = Path(repo_root) / "backend" / "interfaces" / "src" / "api.rs"
    if not api_path.exists():
        return []

    content = api_path.read_text(encoding="utf-8", errors="replace")

    # Find the ConnectorCommon trait block
    trait_start = content.find("pub trait ConnectorCommon")
    if trait_start == -1:
        return []

    # Find the closing brace by counting depth
    brace_start = content.find("{", trait_start)
    if brace_start == -1:
        return []

    depth = 0
    trait_end = brace_start
    for i in range(brace_start, len(content)):
        if content[i] == "{":
            depth += 1
        elif content[i] == "}":
            depth -= 1
            if depth == 0:
                trait_end = i + 1
                break

    trait_body = content[trait_start:trait_end]

    # Extract method names: fn method_name(
    methods = re.findall(r"fn\s+(\w+)\s*\(", trait_body)
    return methods


def scan_known_connectors(repo_root: str) -> list[str]:
    """Scan the connectors directory for known connector names."""
    connectors_dir = (
        Path(repo_root) / "backend" / "connector-integration" / "src" / "connectors"
    )
    if not connectors_dir.exists():
        return []

    connectors: list[str] = []
    excluded = {"macros", "mod"}

    for entry in connectors_dir.iterdir():
        if entry.suffix == ".rs" and entry.stem not in excluded:
            connectors.append(entry.stem)

    return sorted(connectors)


def scan_attempt_status_variants(repo_root: str) -> dict:
    """Parse AttemptStatus enum from common_enums."""
    enums_path = Path(repo_root) / "backend" / "common_enums" / "src" / "enums.rs"
    if not enums_path.exists():
        return {"variants": [], "default_variant": None, "terminal_success": []}

    content = enums_path.read_text(encoding="utf-8", errors="replace")

    # Find AttemptStatus enum
    enum_start = content.find("pub enum AttemptStatus")
    if enum_start == -1:
        return {"variants": [], "default_variant": None, "terminal_success": []}

    # Find the block
    brace_start = content.find("{", enum_start)
    if brace_start == -1:
        return {"variants": [], "default_variant": None, "terminal_success": []}

    depth = 0
    enum_end = brace_start
    for i in range(brace_start, len(content)):
        if content[i] == "{":
            depth += 1
        elif content[i] == "}":
            depth -= 1
            if depth == 0:
                enum_end = i + 1
                break

    enum_body = content[brace_start:enum_end]

    # Extract variants
    variants: list[str] = []
    default_variant = None
    for line in enum_body.splitlines():
        stripped = line.strip()
        # Check for #[default]
        if stripped == "#[default]":
            # Next variant is the default
            default_variant = "__next__"
            continue

        variant_match = re.match(r"^(\w+)\s*(?:=\s*\d+)?\s*,?\s*$", stripped)
        if variant_match:
            name = variant_match.group(1)
            # Skip serde/strum attribute keywords
            if name in ("serde", "strum", "default", "derive"):
                continue
            variants.append(name)
            if default_variant == "__next__":
                default_variant = name

    # Identify terminal success statuses (heuristic: Charged, Authorized, AutoRefunded)
    success_keywords = {
        "Charged",
        "Authorized",
        "CaptureInitiated",
        "PartialCharged",
        "PartiallyAuthorized",
    }
    terminal_success = [v for v in variants if v in success_keywords]

    return {
        "variants": variants,
        "default_variant": default_variant,
        "terminal_success": terminal_success,
    }


def scan_sensitive_field_patterns(repo_root: str) -> list[str]:
    """Scan existing connector code for fields wrapped in Secret<T> to learn sensitive patterns."""
    connectors_dir = (
        Path(repo_root) / "backend" / "connector-integration" / "src" / "connectors"
    )
    if not connectors_dir.exists():
        return []

    # Generic field names that are too noisy to treat as sensitive
    _GENERIC_BLOCKLIST = frozenset(
        {
            "id",
            "name",
            "value",
            "data",
            "code",
            "country",
            "state",
            "year",
            "version",
            "rank",
            "display",
            "source",
            "project",
            "request",
            "content",
            "url",
            "email",
            "phone",
            "address",
            "city",
            "message",
            "result",
            "response",
            "description",
            "title",
            "type",
            "format",
            "method",
            "action",
            "body",
            "header",
            "path",
            "query",
            "hash",
            "number",
            "amount",
            "currency",
            "date",
            "time",
            "status",
            "reason",
            "error",
            "text",
            "label",
            "note",
            "comment",
            "tag",
            "reference",
            "merchant",
            "customer",
            "payment",
            "transaction",
            "order",
            "item",
            "product",
            "plan",
            "subscription",
            "invoice",
            "charge",
            "refund",
            "payout",
            "transfer",
            "balance",
            "account",
            "bank",
            "card",
            "network",
            "bin",
            "expiry",
            "month",
            "day",
            "first",
            "last",
            "middle",
            "prefix",
            "suffix",
            "company",
            "org",
            "redirect",
            "return",
            "callback",
            "webhook",
            "event",
            "session",
            "flow",
            "mode",
            "option",
            "setting",
            "config",
            "param",
            "field",
            "key",
        }
    )

    # Regex: field_name: Secret<T> or field_name: Option<Secret<T>>
    secret_field_pattern = re.compile(
        r"(?:pub\s+)?(\w+)\s*:\s*(?:Option\s*<\s*)?Secret\b"
    )

    field_names: set[str] = set()

    # Scan transformer files
    for transformer in connectors_dir.rglob("transformers.rs"):
        try:
            content = transformer.read_text(encoding="utf-8", errors="replace")
            for m in secret_field_pattern.finditer(content):
                field_names.add(m.group(1))
        except (OSError, UnicodeDecodeError):
            continue

    # Also scan connector main files
    for rs_file in connectors_dir.glob("*.rs"):
        if rs_file.stem in ("macros", "mod"):
            continue
        try:
            content = rs_file.read_text(encoding="utf-8", errors="replace")
            for m in secret_field_pattern.finditer(content):
                field_names.add(m.group(1))
        except (OSError, UnicodeDecodeError):
            continue

    # Filter out generic names and very short names
    filtered = {
        f for f in field_names if f.lower() not in _GENERIC_BLOCKLIST and len(f) > 2
    }

    return sorted(filtered)


def scan_error_response_patterns(repo_root: str) -> list[str]:
    """Scan transformers for error response struct naming patterns."""
    connectors_dir = (
        Path(repo_root) / "backend" / "connector-integration" / "src" / "connectors"
    )
    if not connectors_dir.exists():
        return []

    # Match struct definitions with Error in the name
    error_struct_pattern = re.compile(r"pub\s+struct\s+(\w*[Ee]rror\w*)\s*[{<]")

    struct_names: set[str] = set()

    for transformer in connectors_dir.rglob("transformers.rs"):
        try:
            content = transformer.read_text(encoding="utf-8", errors="replace")
            for m in error_struct_pattern.finditer(content):
                struct_names.add(m.group(1))
        except (OSError, UnicodeDecodeError):
            continue

    return sorted(struct_names)


def scan_proto_conventions(repo_root: str) -> dict:
    """Scan proto files for package name, go_package, service names, and SecretString fields."""
    proto_dir = Path(repo_root) / "backend" / "grpc-api-types" / "proto"
    if not proto_dir.exists():
        return {
            "package_name": None,
            "go_package": None,
            "service_names": [],
            "secret_string_fields": [],
            "proto_files": [],
        }

    package_names: dict[str, int] = {}
    go_packages: dict[str, int] = {}
    service_names: list[str] = []
    secret_fields: set[str] = set()
    proto_files: list[str] = []

    service_pattern = re.compile(r"^service\s+(\w+)\s*\{", re.MULTILINE)
    package_pattern = re.compile(r"^package\s+([^;]+);", re.MULTILINE)
    go_package_pattern = re.compile(r'option\s+go_package\s*=\s*"([^"]+)"\s*;')
    secret_field_pattern = re.compile(
        r"(?:optional\s+)?SecretString\s+(\w+)\s*=\s*\d+\s*;"
    )

    for proto_file in sorted(proto_dir.glob("*.proto")):
        proto_files.append(proto_file.name)
        try:
            content = proto_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        # Package name (skip health_check which uses a different convention)
        if "health_check" not in proto_file.name:
            for m in package_pattern.finditer(content):
                pkg = m.group(1).strip()
                package_names[pkg] = package_names.get(pkg, 0) + 1

        # go_package
        for m in go_package_pattern.finditer(content):
            gp = m.group(1)
            go_packages[gp] = go_packages.get(gp, 0) + 1

        # Services
        for m in service_pattern.finditer(content):
            service_names.append(m.group(1))

        # SecretString fields
        for m in secret_field_pattern.finditer(content):
            secret_fields.add(m.group(1))

    # Most common package name is the convention
    dominant_package = (
        max(package_names, key=package_names.get) if package_names else None
    )
    dominant_go_package = max(go_packages, key=go_packages.get) if go_packages else None

    return {
        "package_name": dominant_package,
        "go_package": dominant_go_package,
        "service_names": sorted(service_names),
        "secret_string_fields": sorted(secret_fields),
        "proto_files": proto_files,
    }


def scan_composite_service(repo_root: str) -> dict:
    """Scan composite-service crate for request types, trait impls, and process methods."""
    composite_dir = Path(repo_root) / "backend" / "composite-service" / "src"
    if not composite_dir.exists():
        return {
            "request_types": [],
            "access_token_impls": [],
            "process_methods": [],
        }

    request_type_pattern = re.compile(r"\bComposite(\w+)Request\b")
    access_token_impl_pattern = re.compile(
        r"impl\s+CompositeAccessTokenRequest\s+for\s+Composite(\w+)Request"
    )
    process_method_pattern = re.compile(r"async\s+fn\s+(process_composite_\w+)\s*\(")

    request_types: set[str] = set()
    access_token_impls: set[str] = set()
    process_methods: list[str] = []

    for rs_file in composite_dir.rglob("*.rs"):
        try:
            content = rs_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        for m in request_type_pattern.finditer(content):
            request_types.add(m.group(1))

        for m in access_token_impl_pattern.finditer(content):
            access_token_impls.add(m.group(1))

        for m in process_method_pattern.finditer(content):
            process_methods.append(m.group(1))

    # Filter out "AccessToken" from request_types since it's the trait itself
    request_types.discard("AccessToken")

    return {
        "request_types": sorted(request_types),
        "access_token_impls": sorted(access_token_impls),
        "process_methods": sorted(set(process_methods)),
    }


def scan_conventional_commit_config(repo_root: str) -> dict:
    """Check for cog.toml or similar conventional commit config."""
    cog_path = Path(repo_root) / "cog.toml"
    if not cog_path.exists():
        # Return default conventional commit types
        return {
            "source": "default",
            "commit_types": [
                "feat",
                "fix",
                "refactor",
                "docs",
                "test",
                "chore",
                "ci",
                "perf",
                "build",
                "style",
                "revert",
            ],
            "branch_prefixes": [
                "feat",
                "fix",
                "refactor",
                "docs",
                "test",
                "chore",
                "ci",
                "perf",
                "hotfix",
                "release",
                "connector",
            ],
        }

    content = cog_path.read_text(encoding="utf-8", errors="replace")
    # Parse commit types from cog.toml if present
    types: list[str] = []
    for m in re.finditer(r"\[commit_types\.(\w+)\]", content):
        types.append(m.group(1))

    if not types:
        types = [
            "feat",
            "fix",
            "refactor",
            "docs",
            "test",
            "chore",
            "ci",
            "perf",
            "build",
            "style",
            "revert",
        ]

    return {
        "source": "cog.toml",
        "commit_types": types,
        "branch_prefixes": types + ["hotfix", "release", "connector"],
    }


# ── Main learn function ─────────────────────────────────────────────


def learn(repo_root: str) -> dict:
    """Run all scanners and return the complete learned data."""
    lints = scan_clippy_lints(repo_root)
    flows = scan_connector_flows(repo_root)
    connector_common_methods = scan_connector_common_methods(repo_root)
    known_connectors = scan_known_connectors(repo_root)
    attempt_status = scan_attempt_status_variants(repo_root)
    sensitive_fields = scan_sensitive_field_patterns(repo_root)
    error_response_patterns = scan_error_response_patterns(repo_root)
    commit_config = scan_conventional_commit_config(repo_root)
    proto_conventions = scan_proto_conventions(repo_root)
    composite_service = scan_composite_service(repo_root)

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "repo_root": repo_root,
        "lints": lints,
        "flows": flows,
        "connector_common_methods": connector_common_methods,
        "known_connectors": known_connectors,
        "attempt_status": attempt_status,
        "sensitive_fields_from_code": sensitive_fields,
        "error_response_patterns": error_response_patterns,
        "commit_config": commit_config,
        "proto_conventions": proto_conventions,
        "composite_service": composite_service,
    }


def save_learned_data(data: dict, output_path: str) -> None:
    """Write learned data to a JSON file."""
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=False)
        f.write("\n")


def load_learned_data(path: str) -> dict | None:
    """Load learned data from a JSON file. Returns None if not found."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if data.get("schema_version") != SCHEMA_VERSION:
            return None
        return data
    except (FileNotFoundError, json.JSONDecodeError, KeyError):
        return None
