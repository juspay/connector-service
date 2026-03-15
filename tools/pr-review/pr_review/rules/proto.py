"""Proto file rules.

Validates protobuf conventions: package declaration, enum zero values,
SecretString usage for sensitive fields, and message naming.
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


class ProtoPackageDeclarationRule(FileContentRule):
    """Proto files must use the standard package declaration."""

    def __init__(self, expected_package: str = "types") -> None:
        self._expected_package = expected_package
        super().__init__(
            rule_id="PT-001",
            name=f"Proto must use package {expected_package}",
            severity=Severity.WARNING,
            category=Category.ARCHITECTURE,
            description=f"Proto files must declare `package {expected_package};`.",
        )

    def check_file_content(
        self,
        classified_file: ClassifiedFile,
        content: str,
        repo_root: str,
        all_classified_files: list[ClassifiedFile] | None = None,
    ) -> list[Finding]:
        if classified_file.file_type != FileType.PROTO:
            return []

        # Skip health_check.proto which uses grpc.health.v1
        if "health_check" in classified_file.path:
            return []

        expected = f"package {self._expected_package};"
        if expected not in content:
            return [
                self._make_finding(
                    file_path=classified_file.path,
                    line_number=1,
                    message=f"Proto file does not use the standard package `{self._expected_package}`.",
                    suggestion=f"Add `{expected}` at the top of the file.",
                    context=f"All proto files in this project use the `{self._expected_package}` package namespace.",
                )
            ]
        return []


class ProtoEnumZeroValueRule(FileContentRule):
    """Proto enums must have UNSPECIFIED = 0 as the first value."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="PT-002",
            name="Proto enums must have UNSPECIFIED = 0",
            severity=Severity.WARNING,
            category=Category.ARCHITECTURE,
            description="Every proto enum must start with an UNSPECIFIED = 0 variant.",
        )
        self._enum_block = re.compile(r"enum\s+(\w+)\s*\{")
        self._unspecified_pattern = re.compile(r"\w+_UNSPECIFIED\s*=\s*0\s*;")

    def check_file_content(
        self,
        classified_file: ClassifiedFile,
        content: str,
        repo_root: str,
        all_classified_files: list[ClassifiedFile] | None = None,
    ) -> list[Finding]:
        if classified_file.file_type != FileType.PROTO:
            return []

        findings = []
        lines = content.split("\n")

        for i, line in enumerate(lines):
            m = self._enum_block.search(line)
            if not m:
                continue

            enum_name = m.group(1)

            # Look forward for the first field assignment (within 10 lines)
            has_unspecified = False
            for j in range(i + 1, min(len(lines), i + 10)):
                if self._unspecified_pattern.search(lines[j]):
                    has_unspecified = True
                    break
                # If we find a non-unspecified field first, it's wrong
                if re.search(
                    r"=\s*0\s*;", lines[j]
                ) and not self._unspecified_pattern.search(lines[j]):
                    break
                if "}" in lines[j]:
                    break

            if not has_unspecified:
                findings.append(
                    self._make_finding(
                        file_path=classified_file.path,
                        line_number=i + 1,
                        message=f"Proto enum `{enum_name}` does not start with `{enum_name.upper()}_UNSPECIFIED = 0`.",
                        line_content=line.strip(),
                        suggestion=f"Add `{self._to_unspecified_name(enum_name)} = 0;` as the first enum value.",
                        context="Proto3 requires a zero value and the convention is to name it UNSPECIFIED for safe default handling.",
                    )
                )

        return findings

    @staticmethod
    def _to_unspecified_name(enum_name: str) -> str:
        """Convert CamelCase enum name to UPPER_SNAKE_UNSPECIFIED."""
        # Insert _ before each uppercase letter, then upper the whole thing
        result = re.sub(r"(?<=[a-z0-9])([A-Z])", r"_\1", enum_name)
        return result.upper() + "_UNSPECIFIED"


class ProtoSensitiveFieldsMustUseSecretStringRule(FileContentRule):
    """Sensitive proto fields must use SecretString instead of string."""

    # Known sensitive field name patterns (hardcoded defaults)
    _DEFAULT_SENSITIVE_NAMES = {
        "api_key",
        "api_secret",
        "secret",
        "token",
        "password",
        "credential",
        "card_number",
        "cvv",
        "cvc",
        "expiry",
        "email",
        "phone",
        "phone_number",
        "first_name",
        "last_name",
        "line1",
        "line2",
        "line3",
        "zip_code",
        "raw_connector_response",
        "raw_connector_request",
        "public_key",
        "private_key",
        "access_token",
        "auth_token",
        "session_token",
    }

    def __init__(self, learned_secret_fields: list[str] | None = None) -> None:
        super().__init__(
            rule_id="PT-003",
            name="Sensitive proto fields must use SecretString",
            severity=Severity.WARNING,
            category=Category.SECURITY,
            description="Fields containing PII or secrets must use SecretString instead of string.",
        )
        # Merge learned fields with defaults
        all_names = set(self._DEFAULT_SENSITIVE_NAMES)
        if learned_secret_fields:
            all_names.update(learned_secret_fields)

        # Build regex dynamically from all known sensitive field names
        escaped = "|".join(re.escape(n) for n in sorted(all_names))
        self._sensitive_pattern = re.compile(
            rf"\b(?:string)\s+(?:{escaped})\s*=",
            re.IGNORECASE,
        )

    def check_file_content(
        self,
        classified_file: ClassifiedFile,
        content: str,
        repo_root: str,
        all_classified_files: list[ClassifiedFile] | None = None,
    ) -> list[Finding]:
        if classified_file.file_type != FileType.PROTO:
            return []

        findings = []
        lines = content.split("\n")

        for i, line in enumerate(lines):
            stripped = line.strip()
            # Skip comments
            if stripped.startswith("//"):
                continue

            if self._sensitive_pattern.search(stripped):
                # Extract field name for the message
                field_match = re.search(r"string\s+(\w+)\s*=", stripped)
                if field_match:
                    field_name = field_match.group(1)
                    findings.append(
                        self._make_finding(
                            file_path=classified_file.path,
                            line_number=i + 1,
                            message=f"Sensitive field `{field_name}` uses `string` instead of `SecretString`.",
                            line_content=stripped,
                            suggestion=f"Change `string {field_name}` to `SecretString {field_name}`.",
                            context="SecretString ensures sensitive data is masked in logs and serialization.",
                        )
                    )

        return findings


class ProtoGoPackageOptionRule(FileContentRule):
    """Proto files must include go_package option."""

    def __init__(self, expected_go_package: str | None = None) -> None:
        self._expected_go_package = expected_go_package
        super().__init__(
            rule_id="PT-004",
            name="Proto must have go_package option",
            severity=Severity.SUGGESTION,
            category=Category.ARCHITECTURE,
            description="Proto files should include an option go_package for Go code generation.",
        )

    def check_file_content(
        self,
        classified_file: ClassifiedFile,
        content: str,
        repo_root: str,
        all_classified_files: list[ClassifiedFile] | None = None,
    ) -> list[Finding]:
        if classified_file.file_type != FileType.PROTO:
            return []

        if "option go_package" not in content:
            suggestion_value = (
                self._expected_go_package
                or "github.com/juspay/connector-service/backend/grpc-api-types/proto;proto"
            )
            return [
                self._make_finding(
                    file_path=classified_file.path,
                    line_number=1,
                    message="Proto file is missing `option go_package`.",
                    suggestion=f'Add `option go_package = "{suggestion_value}";`.',
                    context="go_package is required for Go code generation from proto definitions.",
                )
            ]
        return []


class ProtoFieldNumberGapRule(FileContentRule):
    """Warn on large gaps in proto field numbers (potential deleted fields)."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="PT-005",
            name="No large field number gaps in proto messages",
            severity=Severity.SUGGESTION,
            category=Category.ARCHITECTURE,
            description="Large gaps in field numbers may indicate deleted fields that should use `reserved`.",
        )
        self._message_block = re.compile(r"message\s+(\w+)\s*\{")
        self._field_number = re.compile(r"=\s*(\d+)\s*;")

    def check_file_content(
        self,
        classified_file: ClassifiedFile,
        content: str,
        repo_root: str,
        all_classified_files: list[ClassifiedFile] | None = None,
    ) -> list[Finding]:
        if classified_file.file_type != FileType.PROTO:
            return []

        # Only check added lines in the diff for new messages
        cf = classified_file.changed_file
        if not cf.is_new:
            return []

        findings = []
        lines = content.split("\n")
        in_message = False
        message_name = ""
        last_number = 0

        for i, line in enumerate(lines):
            stripped = line.strip()

            msg_match = self._message_block.search(stripped)
            if msg_match:
                in_message = True
                message_name = msg_match.group(1)
                last_number = 0
                continue

            if in_message and stripped == "}":
                in_message = False
                continue

            if in_message:
                num_match = self._field_number.search(stripped)
                if num_match:
                    current = int(num_match.group(1))
                    if last_number > 0 and current > last_number + 10:
                        findings.append(
                            self._make_finding(
                                file_path=classified_file.path,
                                line_number=i + 1,
                                message=f"Large field number gap in `{message_name}`: {last_number} -> {current}.",
                                line_content=stripped,
                                suggestion="Use `reserved` for deleted field numbers to prevent accidental reuse.",
                                context="Proto field numbers should be sequential. Gaps may indicate deleted fields.",
                            )
                        )
                    last_number = current

        return findings


def get_rules(learned_data: dict | None = None) -> list[Rule]:
    """Return all proto rules."""
    proto_conv = (learned_data or {}).get("proto_conventions", {})

    expected_package = proto_conv.get("package_name") or "types"
    expected_go_package = proto_conv.get("go_package")
    learned_secret_fields = proto_conv.get("secret_string_fields")

    return [
        ProtoPackageDeclarationRule(expected_package=expected_package),
        ProtoEnumZeroValueRule(),
        ProtoSensitiveFieldsMustUseSecretStringRule(
            learned_secret_fields=learned_secret_fields,
        ),
        ProtoGoPackageOptionRule(expected_go_package=expected_go_package),
        ProtoFieldNumberGapRule(),
    ]
