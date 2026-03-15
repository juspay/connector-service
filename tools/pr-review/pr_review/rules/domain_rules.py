"""Domain-specific rules.

Enforces MinorUnit usage for amounts, enum types for limited value sets,
proper status mapping, and connector auth type handling.
"""

from __future__ import annotations

import re

from pr_review.rules.base import (
    Rule,
    RegexLineRule,
    FileContentRule,
    Finding,
    Severity,
    Category,
)
from pr_review.file_classifier import ClassifiedFile, FileType


class AmountFieldTypeRule(FileContentRule):
    """Check that amount fields use MinorUnit, not primitive types."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="DR-001",
            name="Amount fields must use MinorUnit",
            severity=Severity.WARNING,
            category=Category.DOMAIN_RULES,
            description="Amount fields in connector request structs must use MinorUnit or StringMinorUnit, not primitive numeric types.",
        )
        self._amount_field = re.compile(
            r"^\s*(?:pub\s+)?(\w*amount\w*)\s*:\s*((?:Option\s*<\s*)?)(\w+)",
            re.IGNORECASE,
        )
        self._bad_types = {
            "i64",
            "u64",
            "i32",
            "u32",
            "f64",
            "f32",
            "i128",
            "u128",
        }
        # Fields that are NOT monetary amounts (counts, limits, metadata)
        self._non_amount_fields = re.compile(
            r"(?:max_amount|min_amount|authorized_amount.*days|per_item|"
            r"_count|_limit|_threshold|_percentage|_rate|installment)",
            re.IGNORECASE,
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

        # Only check structs that look like requests (contain "Request" in name)
        # Response structs legitimately use primitive types from the connector API
        in_request_struct = False
        findings = []

        for i, line in enumerate(content.split("\n"), 1):
            stripped = line.strip()

            # Track whether we're inside a request struct
            if "struct " in stripped and "Request" in stripped:
                in_request_struct = True
            elif "struct " in stripped:
                in_request_struct = False
            elif stripped == "}" and in_request_struct:
                in_request_struct = False

            if not in_request_struct:
                continue

            m = self._amount_field.match(line)
            if m:
                field_name = m.group(1)
                field_type = m.group(3)

                # Skip non-monetary "amount" fields
                if self._non_amount_fields.search(field_name):
                    continue

                # Only flag String amounts (not numeric) — numeric types
                # from connector APIs are common and often acceptable
                if field_type == "String":
                    findings.append(
                        self._make_finding(
                            file_path=classified_file.path,
                            line_number=i,
                            message=f"Amount field `{field_name}` uses `{field_type}` instead of `StringMinorUnit`.",
                            line_content=stripped,
                            suggestion="Change the type to `StringMinorUnit` (or `MinorUnit` for numeric amounts).",
                            context="StringMinorUnit/MinorUnit ensures correct currency handling and prevents unit confusion.",
                        )
                    )
                elif field_type in self._bad_types:
                    findings.append(
                        self._make_finding(
                            file_path=classified_file.path,
                            line_number=i,
                            message=f"Amount field `{field_name}` uses `{field_type}` instead of `MinorUnit`.",
                            line_content=stripped,
                            suggestion="Change the type to `MinorUnit` (or `StringMinorUnit` if the connector uses string amounts).",
                            context="The MinorUnit type ensures correct currency handling and prevents unit confusion.",
                        )
                    )
        return findings


class EnumVsStringRule(FileContentRule):
    """Check that fields with limited value sets use enums, not String."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="DR-002",
            name="Limited-value fields should use enums",
            severity=Severity.SUGGESTION,
            category=Category.DOMAIN_RULES,
            description="Fields like status or payment_status that represent a fixed set of states should use enums, not String.",
        )
        # Only flag fields whose name is EXACTLY one of these high-confidence enum candidates
        self._enum_candidate_fields = {
            "status",
            "payment_status",
            "refund_status",
            "transaction_status",
            "order_status",
            "capture_status",
            "auth_status",
        }
        self._field_pattern = re.compile(
            r"^\s*(?:pub\s+)?(\w+)\s*:\s*(?:Option\s*<\s*)?String",
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
        for i, line in enumerate(content.split("\n"), 1):
            m = self._field_pattern.match(line)
            if m:
                field_name = m.group(1)
                if field_name.lower() in self._enum_candidate_fields:
                    findings.append(
                        self._make_finding(
                            file_path=classified_file.path,
                            line_number=i,
                            message=f"Field `{field_name}` uses `String` but likely represents a fixed set of states.",
                            line_content=line.strip(),
                            suggestion=f"Define an enum type (e.g., `Connector{field_name.title().replace('_', '')}`) with proper serde attributes.",
                            context='Enums provide type safety and exhaustive matching. Use #[serde(rename = "...")] for wire format.',
                        )
                    )
        return findings


class StatusMappingDefaultRule(FileContentRule):
    """Check that default status in match arms is Pending, not a success state."""

    # Default terminal success statuses (used when learned data unavailable)
    _DEFAULT_TERMINAL_SUCCESS = ["Charged", "Authorized", "CaptureInitiated"]

    def __init__(self, terminal_success: list[str] | None = None) -> None:
        super().__init__(
            rule_id="DR-003",
            name="Default status should be Pending",
            severity=Severity.WARNING,
            category=Category.DOMAIN_RULES,
            description="When mapping connector statuses to AttemptStatus, the default/catch-all should be Pending.",
        )
        success_variants = (
            terminal_success
            if terminal_success is not None
            else self._DEFAULT_TERMINAL_SUCCESS
        )
        # Build regex from the list of terminal success variants
        variants_pattern = "|".join(re.escape(v) for v in success_variants)
        self._bad_default = re.compile(
            rf"_\s*=>\s*(?:enums::)?AttemptStatus::({variants_pattern})"
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
        for i, line in enumerate(content.split("\n"), 1):
            if self._bad_default.search(line):
                findings.append(
                    self._make_finding(
                        file_path=classified_file.path,
                        line_number=i,
                        message="Default match arm maps to a success status. Default should be `Pending`.",
                        line_content=line.strip(),
                        suggestion="Use `_ => enums::AttemptStatus::Pending` as the default case.",
                        context="Unknown connector statuses should default to Pending, not a terminal success state. This prevents false positives.",
                    )
                )
        return findings


class ConnectorTransactionIdStorageRule(FileContentRule):
    """Check that response transformers store connector_transaction_id."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="DR-004",
            name="Response transformers should store connector_transaction_id",
            severity=Severity.WARNING,
            category=Category.DOMAIN_RULES,
            description="Payment response transformers should store the connector's transaction ID for reconciliation.",
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

        # Only check if there are response TryFrom implementations
        has_response_tryfrom = "ResponseRouterData" in content
        if not has_response_tryfrom:
            return []

        # Check if connector_transaction_id is set somewhere
        if "connector_transaction_id" not in content:
            return [
                self._make_finding(
                    file_path=classified_file.path,
                    line_number=1,
                    message="No `connector_transaction_id` mapping found in response transformer.",
                    suggestion="Store the connector's transaction/payment ID: `connector_transaction_id: Some(response.id)`.",
                    context="connector_transaction_id is critical for payment reconciliation, refunds, and status syncs.",
                )
            ]
        return []


def get_rules(learned_data: dict | None = None) -> list[Rule]:
    """Return all domain-specific rules.

    Args:
        learned_data: Optional dict from learner.py with AttemptStatus variants.
    """
    # Extract terminal success variants from learned data
    terminal_success = None
    if learned_data:
        attempt_status = learned_data.get("attempt_status", {})
        ts = attempt_status.get("terminal_success")
        if ts and isinstance(ts, list) and len(ts) > 0:
            terminal_success = ts

    return [
        AmountFieldTypeRule(),
        EnumVsStringRule(),
        StatusMappingDefaultRule(terminal_success=terminal_success),
        ConnectorTransactionIdStorageRule(),
        RegexLineRule(
            rule_id="DR-005",
            name="Use get_currency_unit() for amount conversion",
            severity=Severity.SUGGESTION,
            category=Category.DOMAIN_RULES,
            description="Amount conversion should use the connector's get_currency_unit() method.",
            pattern=r"amount\s*\.\s*0\b|amount\s+as\s+",
            message_template="Direct amount access or cast detected. Use the amount framework.",
            suggestion="Use `utils::get_amount_as_string()` or the connector's `get_currency_unit()` for proper conversion.",
            context="Different connectors use different currency units (minor/major). The framework handles conversion.",
            exclude_test_files=True,
            exclude_patterns=[r"^\s*//", r"^\s*\*", r"MinorUnit"],
            file_filter=r"backend/connector-integration/",
        ),
    ]
