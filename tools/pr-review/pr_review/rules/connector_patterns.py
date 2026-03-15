"""Connector pattern rules.

Validates that connector implementations follow the macro-driven framework,
implement required traits, have proper file structure, and are registered correctly.
"""

from __future__ import annotations

import re
from pathlib import Path

from pr_review.rules.base import (
    Rule,
    FileContentRule,
    CrossFileRule,
    Finding,
    Severity,
    Category,
)
from pr_review.file_classifier import ClassifiedFile, FileType


class ConnectorHasCreateAllPrerequisitesRule(FileContentRule):
    """Check that connector files use the create_all_prerequisites! macro."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="CP-001",
            name="Connector must use create_all_prerequisites! macro",
            severity=Severity.WARNING,
            category=Category.CONNECTOR_PATTERN,
            description="Every connector must invoke create_all_prerequisites! to define its struct and supported flows.",
        )

    def check_file_content(
        self,
        classified_file: ClassifiedFile,
        content: str,
        repo_root: str,
        all_classified_files: list[ClassifiedFile] | None = None,
    ) -> list[Finding]:
        if classified_file.file_type != FileType.CONNECTOR:
            return []

        if "create_all_prerequisites!" not in content:
            return [
                self._make_finding(
                    file_path=classified_file.path,
                    line_number=1,
                    message="Connector file missing `create_all_prerequisites!` macro invocation.",
                    suggestion="Add `macros::create_all_prerequisites!(connector_name: ..., api: [...], ...)` to define the connector.",
                    context="This macro generates the connector struct, flow bridges, amount converters, and member functions.",
                )
            ]
        return []


class ConnectorHasMacroImplementationRule(FileContentRule):
    """Check that connector files use macro_connector_implementation! for declared flows."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="CP-002",
            name="Each flow must have macro_connector_implementation!",
            severity=Severity.WARNING,
            category=Category.CONNECTOR_PATTERN,
            description="Each flow declared in create_all_prerequisites! needs a corresponding macro_connector_implementation! call.",
        )
        self._flow_pattern = re.compile(r"flow:\s*(\w+)")
        self._impl_pattern = re.compile(r"macro_connector_implementation!\s*\(")
        self._impl_flow_pattern = re.compile(r"flow_name:\s*(\w+)")

    def check_file_content(
        self,
        classified_file: ClassifiedFile,
        content: str,
        repo_root: str,
        all_classified_files: list[ClassifiedFile] | None = None,
    ) -> list[Finding]:
        if classified_file.file_type != FileType.CONNECTOR:
            return []

        # Extract flows declared in create_all_prerequisites!
        prereq_start = content.find("create_all_prerequisites!")
        if prereq_start == -1:
            return []  # CP-001 will catch this

        # Find the matching closing paren/bracket by counting nesting depth
        # Start from the opening paren after the macro name
        macro_text = ""
        paren_start = content.find("(", prereq_start)
        if paren_start != -1:
            depth = 0
            for j in range(paren_start, min(len(content), paren_start + 10000)):
                ch = content[j]
                if ch in "([{":
                    depth += 1
                elif ch in ")]}":
                    depth -= 1
                    if depth == 0:
                        macro_text = content[prereq_start : j + 1]
                        break

        if not macro_text:
            # Fallback: use a generous window
            macro_text = content[prereq_start : prereq_start + 5000]

        # Find all flow declarations within the macro
        declared_flows = set(self._flow_pattern.findall(macro_text))

        # Find all implemented flows in the entire file
        implemented_flows = set(self._impl_flow_pattern.findall(content))

        # Check for missing implementations
        missing = declared_flows - implemented_flows
        findings = []
        if missing:
            for flow in sorted(missing):
                findings.append(
                    self._make_finding(
                        file_path=classified_file.path,
                        line_number=1,
                        message=f"Flow `{flow}` is declared in `create_all_prerequisites!` but has no `macro_connector_implementation!`.",
                        suggestion=f"Add `macros::macro_connector_implementation!(connector: ..., flow_name: {flow}, ...)` for this flow.",
                        context="Each declared flow needs an implementation macro that defines its HTTP method, URL, headers, etc.",
                    )
                )
        return findings


class ConnectorCommonTraitRule(FileContentRule):
    """Check that ConnectorCommon trait is implemented with required methods."""

    # Default required methods (used when learned data is not available)
    _DEFAULT_REQUIRED_METHODS = [
        "id",
        "base_url",
        "get_currency_unit",
        "get_auth_header",
        "build_error_response",
    ]

    def __init__(self, required_methods: list[str] | None = None) -> None:
        super().__init__(
            rule_id="CP-003",
            name="ConnectorCommon trait must be implemented",
            severity=Severity.CRITICAL,
            category=Category.CONNECTOR_PATTERN,
            description="Every connector must implement the ConnectorCommon trait with id(), base_url(), get_currency_unit(), get_auth_header(), and build_error_response().",
        )
        # Match both `impl ConnectorCommon for X` and `impl<T: ...> ConnectorCommon\n    for X<T>`
        self._pattern = re.compile(r"impl\b.*\bConnectorCommon\b", re.DOTALL)
        self._required_methods = (
            required_methods
            if required_methods is not None
            else self._DEFAULT_REQUIRED_METHODS
        )

    def check_file_content(
        self,
        classified_file: ClassifiedFile,
        content: str,
        repo_root: str,
        all_classified_files: list[ClassifiedFile] | None = None,
    ) -> list[Finding]:
        if classified_file.file_type != FileType.CONNECTOR:
            return []

        if not self._pattern.search(content):
            return [
                self._make_finding(
                    file_path=classified_file.path,
                    line_number=1,
                    message="Connector is missing `impl ConnectorCommon for ...` implementation.",
                    suggestion="Implement `ConnectorCommon` with id(), base_url(), get_currency_unit(), get_auth_header(), and build_error_response().",
                    context="ConnectorCommon provides the basic connector identity and configuration methods.",
                )
            ]

        # Check that required methods are present in the impl block
        findings = []
        if self._required_methods:
            # Extract the ConnectorCommon impl block
            impl_start = self._pattern.search(content)
            if impl_start:
                brace_pos = content.find("{", impl_start.start())
                if brace_pos != -1:
                    depth = 0
                    impl_end = brace_pos
                    for i in range(brace_pos, min(len(content), brace_pos + 10000)):
                        if content[i] == "{":
                            depth += 1
                        elif content[i] == "}":
                            depth -= 1
                            if depth == 0:
                                impl_end = i + 1
                                break
                    impl_body = content[impl_start.start() : impl_end]
                    # Check each required method
                    for method in self._required_methods:
                        # Look for fn method_name( in the impl body
                        if (
                            f"fn {method}(" not in impl_body
                            and f"fn {method} (" not in impl_body
                        ):
                            findings.append(
                                self._make_finding(
                                    file_path=classified_file.path,
                                    line_number=content[: impl_start.start()].count(
                                        "\n"
                                    )
                                    + 1,
                                    message=f"ConnectorCommon implementation is missing required method `{method}()`.",
                                    suggestion=f"Add `fn {method}(...)` to the `impl ConnectorCommon` block.",
                                    context="ConnectorCommon requires all its methods to be implemented for proper connector operation.",
                                )
                            )

        return findings


class TransformerHasTryFromRule(FileContentRule):
    """Check that transformer files have TryFrom implementations."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="CP-004",
            name="Transformers must have TryFrom implementations",
            severity=Severity.CRITICAL,
            category=Category.CONNECTOR_PATTERN,
            description="Transformer files must implement TryFrom for request and response type conversions.",
        )

    def check_file_content(
        self,
        classified_file: ClassifiedFile,
        content: str,
        repo_root: str,
        all_classified_files: list[ClassifiedFile] | None = None,
    ) -> list[Finding]:
        if classified_file.file_type != FileType.TRANSFORMER:
            return []

        findings = []
        has_try_from = (
            "impl TryFrom<" in content or "impl<" in content and "TryFrom<" in content
        )

        if not has_try_from:
            findings.append(
                self._make_finding(
                    file_path=classified_file.path,
                    line_number=1,
                    message="Transformer file has no `TryFrom` implementations.",
                    suggestion="Add `impl TryFrom<RouterDataV2<...>> for ConnectorRequest` and `impl TryFrom<ResponseRouterData<...>> for RouterDataV2<...>` implementations.",
                    context="Transformers must convert between RouterDataV2 (domain types) and connector-specific request/response structs.",
                )
            )
        return findings


class TransformerHasErrorResponseRule(FileContentRule):
    """Check that transformer files define an error response struct."""

    def __init__(self, error_response_patterns: list[str] | None = None) -> None:
        super().__init__(
            rule_id="CP-005",
            name="Transformers should define an error response struct",
            severity=Severity.WARNING,
            category=Category.CONNECTOR_PATTERN,
            description="Transformer files should define a connector-specific error response struct for mapping connector errors.",
        )
        self._known_error_structs = (
            set(error_response_patterns) if error_response_patterns else set()
        )

    def check_file_content(
        self,
        classified_file: ClassifiedFile,
        content: str,
        repo_root: str,
        all_classified_files: list[ClassifiedFile] | None = None,
    ) -> list[Finding]:
        if classified_file.file_type != FileType.TRANSFORMER:
            return []

        # Look for an error response struct using hardcoded patterns
        error_patterns = [
            r"ErrorResponse",
            r"Error\w+Response",
            r"\w+ErrorBody",
            r"\w+ApiError",
        ]
        has_error_struct = any(re.search(pat, content) for pat in error_patterns)

        # Also check against learned error struct names if available
        if not has_error_struct and self._known_error_structs:
            # Extract all struct names defined in this file
            defined_structs = set(re.findall(r"pub\s+struct\s+(\w+)", content))
            # Check if any defined struct matches a known error struct pattern
            has_error_struct = bool(defined_structs & self._known_error_structs)

        if not has_error_struct:
            return [
                self._make_finding(
                    file_path=classified_file.path,
                    line_number=1,
                    message="No error response struct found in transformer file.",
                    suggestion="Define a struct like `pub struct ConnectorErrorResponse { ... }` to deserialize connector error responses.",
                    context="Each connector should have a typed error response struct for proper error handling in build_error_response().",
                )
            ]
        return []


class ConnectorFileStructureRule(CrossFileRule):
    """Check that new connectors have both the main file and transformers file."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="CP-006",
            name="Connector must have both connector.rs and transformers.rs",
            severity=Severity.CRITICAL,
            category=Category.CONNECTOR_PATTERN,
            description="Each connector must follow the two-file pattern: connector.rs + connector/transformers.rs.",
        )

    def check_all(
        self,
        classified_files: list[ClassifiedFile],
        repo_root: str,
    ) -> list[Finding]:
        # Group files by connector name
        connector_files: dict[str, set[FileType]] = {}
        for cf in classified_files:
            if cf.connector_name and cf.file_type in (
                FileType.CONNECTOR,
                FileType.TRANSFORMER,
            ):
                connector_files.setdefault(cf.connector_name, set()).add(cf.file_type)

        findings = []
        for name, file_types in connector_files.items():
            # Only flag if we see a new connector file without its pair
            # Check if the missing file exists on disk (it might not be in the diff)
            if (
                FileType.CONNECTOR in file_types
                and FileType.TRANSFORMER not in file_types
            ):
                transformer_path = (
                    Path(repo_root)
                    / f"backend/connector-integration/src/connectors/{name}/transformers.rs"
                )
                if not transformer_path.exists():
                    findings.append(
                        self._make_finding(
                            file_path=f"backend/connector-integration/src/connectors/{name}.rs",
                            line_number=0,
                            message=f"Connector `{name}` is missing its `transformers.rs` file.",
                            suggestion=f"Create `backend/connector-integration/src/connectors/{name}/transformers.rs` with request/response structs and TryFrom implementations.",
                            context="Every connector follows the two-file pattern: connector.rs for trait impls, transformers.rs for type conversions.",
                        )
                    )

            if (
                FileType.TRANSFORMER in file_types
                and FileType.CONNECTOR not in file_types
            ):
                connector_path = (
                    Path(repo_root)
                    / f"backend/connector-integration/src/connectors/{name}.rs"
                )
                if not connector_path.exists():
                    findings.append(
                        self._make_finding(
                            file_path=f"backend/connector-integration/src/connectors/{name}/transformers.rs",
                            line_number=0,
                            message=f"Transformer for `{name}` exists but the main connector file is missing.",
                            suggestion=f"Create `backend/connector-integration/src/connectors/{name}.rs` with create_all_prerequisites!, ConnectorCommon impl, and flow implementations.",
                        )
                    )
        return findings


class ConnectorRegistrationRule(CrossFileRule):
    """Check that new connectors are registered in the module and type registry."""

    def __init__(self, known_connectors: list[str] | None = None) -> None:
        super().__init__(
            rule_id="CP-007",
            name="New connectors must be registered",
            severity=Severity.WARNING,
            category=Category.CONNECTOR_PATTERN,
            description="New connectors must be added to connectors.rs (mod declaration) and connector_types.rs (ConnectorEnum variant).",
        )
        self._known_connectors = set(known_connectors) if known_connectors else set()

    def check_all(
        self,
        classified_files: list[ClassifiedFile],
        repo_root: str,
    ) -> list[Finding]:
        # Find new connector files (is_new flag)
        new_connectors = set()
        for cf in classified_files:
            if (
                cf.file_type == FileType.CONNECTOR
                and cf.changed_file.is_new
                and cf.connector_name
            ):
                new_connectors.add(cf.connector_name)

        if not new_connectors:
            return []

        findings = []

        # Check if connectors.rs has the mod declaration
        connectors_rs = (
            Path(repo_root) / "backend/connector-integration/src/connectors.rs"
        )
        if connectors_rs.exists():
            connectors_content = connectors_rs.read_text(
                encoding="utf-8", errors="replace"
            )
            for name in new_connectors:
                if (
                    f"pub mod {name}" not in connectors_content
                    and f"mod {name}" not in connectors_content
                ):
                    findings.append(
                        self._make_finding(
                            file_path="backend/connector-integration/src/connectors.rs",
                            line_number=0,
                            message=f"New connector `{name}` is not registered in `connectors.rs`.",
                            suggestion=f"Add `pub mod {name};` to `backend/connector-integration/src/connectors.rs`.",
                            context="The module must be declared for the connector code to be compiled.",
                        )
                    )

        # Check if connector_types.rs has the enum variant
        connector_types_rs = (
            Path(repo_root) / "backend/domain_types/src/connector_types.rs"
        )
        if connector_types_rs.exists():
            types_content = connector_types_rs.read_text(
                encoding="utf-8", errors="replace"
            )
            for name in new_connectors:
                # Convert snake_case to PascalCase for enum variant
                pascal_name = "".join(word.capitalize() for word in name.split("_"))
                if pascal_name not in types_content:
                    findings.append(
                        self._make_finding(
                            file_path="backend/domain_types/src/connector_types.rs",
                            line_number=0,
                            message=f"New connector `{name}` is not added to `ConnectorEnum` in `connector_types.rs`.",
                            suggestion=f"Add `{pascal_name}` variant to the `ConnectorEnum` enum.",
                            context="The connector must be registered in ConnectorEnum for dispatch to work.",
                        )
                    )

        # Check for suspiciously similar names to existing connectors
        if self._known_connectors:
            for name in new_connectors:
                for existing in self._known_connectors:
                    if name == existing:
                        continue
                    # Check if new name is a prefix/suffix variant of existing
                    # e.g., "stripev2" vs "stripe", "adyenv3" vs "adyen"
                    shorter, longer = sorted([name, existing], key=len)
                    if longer.startswith(shorter) and longer[len(shorter) :].isdigit():
                        continue  # Versioned connectors are legitimate (e.g., razorpayv2)
                    # Levenshtein-like: flag if only 1-2 chars different and same length
                    if len(name) == len(existing) and len(name) > 4:
                        diffs = sum(1 for a, b in zip(name, existing) if a != b)
                        if diffs == 1:
                            findings.append(
                                self._make_finding(
                                    file_path=f"backend/connector-integration/src/connectors/{name}.rs",
                                    line_number=0,
                                    message=f"New connector `{name}` has a very similar name to existing connector `{existing}`. Verify this is intentional.",
                                    suggestion=f"If this is a variant of `{existing}`, consider using a versioned name like `{existing}v2`.",
                                    context="Similar connector names can cause confusion in routing and configuration.",
                                )
                            )

        return findings


class FlowMarkerTraitsRule(FileContentRule):
    """Check that flow marker traits are implemented for declared flows."""

    # Default mapping (used when learned data is not available)
    _DEFAULT_FLOW_TRAIT_MAP = {
        "Authorize": "PaymentAuthorizeV2",
        "PSync": "PaymentSyncV2",
        "Capture": "PaymentCapture",
        "Void": "PaymentVoidV2",
        "Refund": "RefundV2",
        "RSync": "RefundSyncV2",
        "SetupMandate": "SetupMandateV2",
    }

    def __init__(self, flow_trait_map: dict[str, str] | None = None) -> None:
        super().__init__(
            rule_id="CP-008",
            name="Flow marker traits must be implemented",
            severity=Severity.WARNING,
            category=Category.CONNECTOR_PATTERN,
            description="Each supported flow needs its marker trait implemented (e.g., PaymentAuthorizeV2).",
        )
        self._flow_to_trait = (
            flow_trait_map
            if flow_trait_map is not None
            else self._DEFAULT_FLOW_TRAIT_MAP
        )
        self._flow_pattern = re.compile(r"flow_name:\s*(\w+)")

    def check_file_content(
        self,
        classified_file: ClassifiedFile,
        content: str,
        repo_root: str,
        all_classified_files: list[ClassifiedFile] | None = None,
    ) -> list[Finding]:
        if classified_file.file_type != FileType.CONNECTOR:
            return []

        # Find flows used in macro_connector_implementation!
        implemented_flows = set(self._flow_pattern.findall(content))
        if not implemented_flows:
            return []

        findings = []
        for flow in implemented_flows:
            trait_name = self._flow_to_trait.get(flow)
            if trait_name and trait_name not in content:
                findings.append(
                    self._make_finding(
                        file_path=classified_file.path,
                        line_number=1,
                        message=f"Flow `{flow}` is implemented but marker trait `{trait_name}` is not found.",
                        suggestion=f"Add `impl connector_types::{trait_name} for ConnectorName {{}}` to the connector file.",
                        context="Marker traits signal that the connector supports a particular flow.",
                    )
                )
        return findings


class BuildErrorResponseRule(FileContentRule):
    """Check that ConnectorCommon::build_error_response is properly implemented."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="CP-009",
            name="build_error_response should use typed error deserialization",
            severity=Severity.WARNING,
            category=Category.CONNECTOR_PATTERN,
            description="build_error_response should deserialize the raw response into a typed error struct.",
        )

    def check_file_content(
        self,
        classified_file: ClassifiedFile,
        content: str,
        repo_root: str,
        all_classified_files: list[ClassifiedFile] | None = None,
    ) -> list[Finding]:
        if classified_file.file_type != FileType.CONNECTOR:
            return []

        if "build_error_response" not in content:
            return []

        # Check if build_error_response uses parse_struct for typed deserialization
        # Find the build_error_response function
        ber_start = content.find("fn build_error_response")
        if ber_start == -1:
            return []

        # Look at the next ~30 lines for parse_struct usage
        remaining = content[ber_start : ber_start + 1500]
        if "parse_struct" not in remaining and "serde_json::from_" not in remaining:
            return [
                self._make_finding(
                    file_path=classified_file.path,
                    line_number=content[:ber_start].count("\n") + 1,
                    message="`build_error_response` does not appear to deserialize the error response into a typed struct.",
                    suggestion='Use `res.response.parse_struct("ConnectorErrorResponse")` to deserialize into your typed error struct.',
                    context="Typed error deserialization ensures proper mapping of connector-specific error codes and messages.",
                )
            ]
        return []


def get_rules(learned_data: dict | None = None) -> list[Rule]:
    """Return all connector pattern rules.

    Args:
        learned_data: Optional dict from learner.py with flow-trait mappings.
    """
    # Extract flow-trait map from learned data if available
    flow_trait_map = None
    known_connectors = None
    error_response_patterns = None
    connector_common_methods = None
    if learned_data:
        flows = learned_data.get("flows", {})
        ftm = flows.get("flow_trait_map")
        if ftm and isinstance(ftm, dict) and len(ftm) > 0:
            flow_trait_map = ftm
        kc = learned_data.get("known_connectors")
        if kc and isinstance(kc, list) and len(kc) > 0:
            known_connectors = kc
        erp = learned_data.get("error_response_patterns")
        if erp and isinstance(erp, list) and len(erp) > 0:
            error_response_patterns = erp
        ccm = learned_data.get("connector_common_methods")
        if ccm and isinstance(ccm, list) and len(ccm) > 0:
            connector_common_methods = ccm

    return [
        ConnectorHasCreateAllPrerequisitesRule(),
        ConnectorHasMacroImplementationRule(),
        ConnectorCommonTraitRule(required_methods=connector_common_methods),
        TransformerHasTryFromRule(),
        TransformerHasErrorResponseRule(
            error_response_patterns=error_response_patterns
        ),
        ConnectorFileStructureRule(),
        ConnectorRegistrationRule(known_connectors=known_connectors),
        FlowMarkerTraitsRule(flow_trait_map=flow_trait_map),
        BuildErrorResponseRule(),
    ]
