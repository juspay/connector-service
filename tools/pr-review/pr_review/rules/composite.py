"""Composite service rules.

Validates patterns specific to the composite-service layer:
trait implementations, request decomposition, and access token handling.
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


class CompositeRequestDecompositionRule(FileContentRule):
    """Composite service methods must decompose requests via into_parts()."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="CS-001",
            name="Composite methods must use request.into_parts()",
            severity=Severity.SUGGESTION,
            category=Category.ARCHITECTURE,
            description="Composite service methods should decompose requests into (metadata, extensions, payload).",
        )
        self._method_def = re.compile(r"async\s+fn\s+(process_composite_\w+)\s*\(")

    def check_file_content(
        self,
        classified_file: ClassifiedFile,
        content: str,
        repo_root: str,
        all_classified_files: list[ClassifiedFile] | None = None,
    ) -> list[Finding]:
        if classified_file.file_type != FileType.COMPOSITE_SERVICE:
            return []

        findings = []
        lines = content.split("\n")

        for i, line in enumerate(lines):
            m = self._method_def.search(line)
            if not m:
                continue

            method_name = m.group(1)

            # Look forward for into_parts()
            has_into_parts = False
            for j in range(i, min(len(lines), i + 10)):
                if "into_parts()" in lines[j]:
                    has_into_parts = True
                    break

            if not has_into_parts:
                findings.append(
                    self._make_finding(
                        file_path=classified_file.path,
                        line_number=i + 1,
                        message=f"Composite method `{method_name}` does not use `request.into_parts()`.",
                        line_content=line.strip(),
                        suggestion="Decompose the request via `let (metadata, extensions, payload) = request.into_parts();`.",
                        context="into_parts() extracts metadata and extensions needed for sub-service calls.",
                    )
                )

        return findings


class CompositeAccessTokenTraitRule(FileContentRule):
    """New composite request types must implement CompositeAccessTokenRequest."""

    def __init__(self, known_request_types: list[str] | None = None) -> None:
        super().__init__(
            rule_id="CS-002",
            name="Composite requests must implement CompositeAccessTokenRequest",
            severity=Severity.WARNING,
            category=Category.ARCHITECTURE,
            description="New composite request types need CompositeAccessTokenRequest for access token flow.",
        )
        self._known_request_types = (
            set(known_request_types) if known_request_types else None
        )
        self._composite_request = re.compile(r"Composite(\w+)Request")
        self._trait_impl = re.compile(
            r"impl\s+CompositeAccessTokenRequest\s+for\s+Composite(\w+)Request"
        )

    def check_file_content(
        self,
        classified_file: ClassifiedFile,
        content: str,
        repo_root: str,
        all_classified_files: list[ClassifiedFile] | None = None,
    ) -> list[Finding]:
        if classified_file.file_type != FileType.COMPOSITE_SERVICE:
            return []

        # Only check payments.rs where composite flows are defined
        if "payments.rs" not in classified_file.path:
            return []

        # Find all composite request types used in process_ methods
        process_pattern = re.compile(
            r"request:\s*tonic::Request<Composite(\w+)Request>"
        )
        used_types = set(process_pattern.findall(content))

        # Find all types that have the trait impl
        impl_types = set(self._trait_impl.findall(content))

        findings = []
        for request_type in used_types:
            if request_type not in impl_types:
                findings.append(
                    self._make_finding(
                        file_path=classified_file.path,
                        line_number=1,
                        message=f"`Composite{request_type}Request` is missing `CompositeAccessTokenRequest` trait implementation.",
                        suggestion=f"Add `impl CompositeAccessTokenRequest for Composite{request_type}Request {{ ... }}`.",
                        context="CompositeAccessTokenRequest is required for the access token flow in composite services.",
                    )
                )

        return findings


class CompositeMetadataPropagationRule(FileContentRule):
    """Composite sub-service calls must propagate metadata."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="CS-003",
            name="Sub-service calls must propagate metadata",
            severity=Severity.WARNING,
            category=Category.ARCHITECTURE,
            description="Composite sub-service calls must clone and propagate request metadata.",
        )
        self._new_request = re.compile(r"tonic::Request::new\(\w+\)")

    def check_file_content(
        self,
        classified_file: ClassifiedFile,
        content: str,
        repo_root: str,
        all_classified_files: list[ClassifiedFile] | None = None,
    ) -> list[Finding]:
        if classified_file.file_type != FileType.COMPOSITE_SERVICE:
            return []

        findings = []
        lines = content.split("\n")

        for i, line in enumerate(lines):
            if not self._new_request.search(line):
                continue

            # Look forward for metadata_mut() within 5 lines
            has_metadata = False
            for j in range(i, min(len(lines), i + 5)):
                if "metadata_mut()" in lines[j]:
                    has_metadata = True
                    break

            if not has_metadata:
                findings.append(
                    self._make_finding(
                        file_path=classified_file.path,
                        line_number=i + 1,
                        message="Sub-request created via `tonic::Request::new()` without metadata propagation.",
                        line_content=line.strip(),
                        suggestion="Add `*request.metadata_mut() = metadata.clone();` after creating the request.",
                        context="Metadata carries authentication, routing, and tracing context that sub-services need.",
                    )
                )

        return findings


class CompositeForeignFromRule(FileContentRule):
    """Composite transformers should implement ForeignFrom, not raw From/Into."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="CS-004",
            name="Use ForeignFrom in composite transformers",
            severity=Severity.SUGGESTION,
            category=Category.ARCHITECTURE,
            description="Composite transformer files should use ForeignFrom for type conversions.",
        )

    def check_file_content(
        self,
        classified_file: ClassifiedFile,
        content: str,
        repo_root: str,
        all_classified_files: list[ClassifiedFile] | None = None,
    ) -> list[Finding]:
        if classified_file.file_type != FileType.COMPOSITE_SERVICE:
            return []

        if "transformers" not in classified_file.path:
            return []

        # Check if file uses raw From instead of ForeignFrom
        has_raw_from = bool(re.search(r"impl\s+From<", content))
        has_foreign_from = bool(re.search(r"impl\s+ForeignFrom<", content))

        if has_raw_from and not has_foreign_from:
            findings = []
            for i, line in enumerate(content.split("\n")):
                if re.search(r"impl\s+From<", line):
                    findings.append(
                        self._make_finding(
                            file_path=classified_file.path,
                            line_number=i + 1,
                            message="Using `impl From<>` instead of `ForeignFrom<>` for type conversion.",
                            line_content=line.strip(),
                            suggestion="Use `impl ForeignFrom<SourceType> for TargetType` to be consistent with the rest of the codebase.",
                            context="ForeignFrom works around the orphan rule and is the project convention.",
                        )
                    )
            return findings

        return []


def get_rules(learned_data: dict | None = None) -> list[Rule]:
    """Return all composite service rules."""
    composite_data = (learned_data or {}).get("composite_service", {})

    known_request_types = composite_data.get("request_types") or None

    return [
        CompositeRequestDecompositionRule(),
        CompositeAccessTokenTraitRule(known_request_types=known_request_types),
        CompositeMetadataPropagationRule(),
        CompositeForeignFromRule(),
    ]
