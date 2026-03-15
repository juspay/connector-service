"""Security rules.

Detects missing Secret<T> wrappers, hardcoded credentials, hardcoded URLs,
missing masked serialization, and other security-sensitive patterns.
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


class SensitiveFieldNotWrappedRule(FileContentRule):
    """Detect struct fields with sensitive names that are not wrapped in Secret<T>."""

    # Generic field names to exclude from learned data (too noisy)
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
            "key",  # too generic on its own
        }
    )

    def __init__(self, learned_sensitive_fields: list[str] | None = None) -> None:
        super().__init__(
            rule_id="SE-001",
            name="Sensitive fields must use Secret<T>",
            severity=Severity.CRITICAL,
            category=Category.SECURITY,
            description="Fields containing secrets (API keys, tokens, passwords) must be wrapped in Secret<T> from hyperswitch_masking.",
        )
        self._sensitive_patterns = re.compile(
            r"\b(api_key|api_secret|secret_key|password|token|access_token|"
            r"private_key|client_secret|auth_key|signing_key|encryption_key|"
            r"secret|passphrase|credential)\b",
            re.IGNORECASE,
        )
        self._field_pattern = re.compile(r"^\s*(?:pub\s+)?(\w+)\s*:\s*(.+?)\s*,?\s*$")

        # Build supplementary set from learned data (filtered)
        self._learned_fields: frozenset[str] = frozenset()
        if learned_sensitive_fields:
            filtered = {
                f
                for f in learned_sensitive_fields
                if f.lower() not in self._GENERIC_BLOCKLIST and len(f) > 2
            }
            self._learned_fields = frozenset(filtered)

    def check_file_content(
        self,
        classified_file: ClassifiedFile,
        content: str,
        repo_root: str,
        all_classified_files: list[ClassifiedFile] | None = None,
    ) -> list[Finding]:
        if not classified_file.is_rust:
            return []

        # Only check connector-related files
        if classified_file.file_type not in (
            FileType.CONNECTOR,
            FileType.TRANSFORMER,
        ):
            return []

        findings = []
        in_struct = False

        for i, line in enumerate(content.split("\n"), 1):
            stripped = line.strip()

            # Track if we're inside a struct definition
            if stripped.startswith("pub struct ") or stripped.startswith("struct "):
                in_struct = True
                continue
            if in_struct and stripped == "}":
                in_struct = False
                continue

            if not in_struct:
                continue

            # Check if this is a field definition
            m = self._field_pattern.match(line)
            if not m:
                continue

            field_name = m.group(1)
            field_type = m.group(2)

            # Check if field name matches sensitive patterns
            is_sensitive = bool(self._sensitive_patterns.search(field_name))
            is_learned = field_name in self._learned_fields

            if is_sensitive or is_learned:
                # Check if it's already wrapped in Secret<> or Maskable<>
                if "Secret<" not in field_type and "Maskable<" not in field_type:
                    # Only flag String/&str fields — typed structs (e.g., CardNumber,
                    # TokenizationData) handle their own security via their type
                    base_type = field_type.strip().rstrip(",")
                    # Unwrap Option<T>
                    if base_type.startswith("Option<"):
                        base_type = base_type[7:].rstrip(">").strip()
                    if base_type in ("String", "&str", "&'a str"):
                        findings.append(
                            self._make_finding(
                                file_path=classified_file.path,
                                line_number=i,
                                message=f"Sensitive field `{field_name}` is not wrapped in `Secret<T>`.",
                                line_content=stripped,
                                suggestion=f"Change type to `Secret<{field_type.strip().rstrip(',')}>` and use `.expose()` to access the value.",
                                context="All sensitive data must be wrapped in Secret<T> from hyperswitch_masking to prevent accidental logging.",
                            )
                        )

        return findings


def get_rules(learned_data: dict | None = None) -> list[Rule]:
    """Return all security rules."""
    learned_sensitive_fields = None
    if learned_data:
        sf = learned_data.get("sensitive_fields_from_code")
        if sf and isinstance(sf, list) and len(sf) > 0:
            learned_sensitive_fields = sf

    return [
        SensitiveFieldNotWrappedRule(learned_sensitive_fields=learned_sensitive_fields),
        RegexLineRule(
            rule_id="SE-002",
            name="No hardcoded URLs in connector code",
            severity=Severity.WARNING,
            category=Category.SECURITY,
            description="Connector base URLs should come from config, not hardcoded.",
            pattern=r"""(?:"|')https?://[a-zA-Z0-9]""",
            message_template="Hardcoded URL detected. Use config-based URLs.",
            suggestion="Use `self.base_url(connectors)` from ConnectorCommon trait. Base URLs are defined in config/*.toml.",
            context="Hardcoded URLs prevent environment-specific configuration and make it harder to switch between sandbox/production.",
            exclude_test_files=True,
            exclude_patterns=[
                r"^\s*//",
                r"^\s*\*",
                r"^\s*///",
                r"base_url",  # Already referencing base_url config
                r"doc\s*=",  # Documentation attributes
            ],
            file_filter=r"backend/connector-integration/src/connectors/",
        ),
        RegexLineRule(
            rule_id="SE-003",
            name="No hardcoded API keys or credentials",
            severity=Severity.CRITICAL,
            category=Category.SECURITY,
            description="API keys, tokens, and secrets must never be hardcoded in source.",
            pattern=r"""(?:"|')(sk_live_|pk_live_|sk_test_|pk_test_|bearer\s+[a-zA-Z0-9]{20,}|Basic\s+[a-zA-Z0-9+/=]{20,})""",
            message_template="Possible hardcoded credential detected.",
            suggestion="Use ConnectorAuthType from request metadata. Credentials should come from the caller.",
            context="Hardcoded credentials are a critical security vulnerability.",
            exclude_test_files=False,
            exclude_patterns=[r"^\s*//", r"^\s*\*"],
        ),
        RegexLineRule(
            rule_id="SE-004",
            name="Auth headers must use Maskable<String>",
            severity=Severity.WARNING,
            category=Category.SECURITY,
            description="Authentication header values must use Maskable<String> to prevent logging.",
            # Match header tuples that use plain String instead of Maskable
            pattern=r"""headers::\w+\.to_string\(\)\s*,\s*[^.]*\.to_string\(\)\s*\)""",
            message_template="Auth header value may not be using `Maskable<String>`.",
            suggestion="Use `.into_masked()` on sensitive header values: `value.into_masked()`.",
            context="All auth-related header values should use Maskable<String> to prevent sensitive data in logs.",
            exclude_test_files=True,
            exclude_patterns=[r"^\s*//", r"^\s*\*", r"into_masked", r"Maskable"],
            file_filter=r"backend/connector-integration/",
        ),
        RegexLineRule(
            rule_id="SE-005",
            name="Use masked_serialize for logging sensitive data",
            severity=Severity.SUGGESTION,
            category=Category.SECURITY,
            description="When logging data that may contain PII or secrets, use masked_serialize.",
            # Detect serde_json::to_string on types that might contain sensitive data
            pattern=r"serde_json::to_string\(",
            message_template="Consider using `masked_serialize` instead of `serde_json::to_string` for potentially sensitive data.",
            suggestion="Use `hyperswitch_masking::masked_serialize` for safe logging of structs containing Secret<T> fields.",
            context="masked_serialize respects Secret<T> wrappers and redacts sensitive fields in output.",
            exclude_test_files=True,
            exclude_patterns=[r"^\s*//", r"^\s*\*"],
            file_filter=r"backend/connector-integration/",
        ),
        RegexLineRule(
            rule_id="SE-006",
            name="No .expose() in logging/debug contexts",
            severity=Severity.WARNING,
            category=Category.SECURITY,
            description="Do not expose Secret<T> values in logging or debug output.",
            pattern=r"""(?:logger::|log::|tracing::)(?:info|debug|warn|error|trace).*\.expose\(\)""",
            message_template="Secret value exposed in a logging context.",
            suggestion="Remove `.expose()` from logging calls. The Secret<T> type will display as `***` automatically.",
            context="Calling .expose() in logging defeats the purpose of Secret<T> wrapping.",
            exclude_test_files=True,
            exclude_patterns=[r"^\s*//", r"^\s*\*"],
        ),
    ]
