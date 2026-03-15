"""gRPC server rules.

Validates handler patterns, service implementations, router conventions,
and tracing instrumentation for the gRPC server layer.
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


class HandlerMustUseHttpHandlerMacroRule(FileContentRule):
    """HTTP handler files must use the http_handler! macro, not hand-rolled handlers."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="GR-001",
            name="Handlers must use http_handler! macro",
            severity=Severity.WARNING,
            category=Category.ARCHITECTURE,
            description="HTTP handler files must use the http_handler! macro for consistency.",
        )

    def check_file_content(
        self,
        classified_file: ClassifiedFile,
        content: str,
        repo_root: str,
        all_classified_files: list[ClassifiedFile] | None = None,
    ) -> list[Finding]:
        if classified_file.file_type != FileType.GRPC_HANDLER:
            return []

        # Skip macro definition file, mod file, and health endpoint
        fname = (
            classified_file.path.rsplit("/", 1)[-1]
            if "/" in classified_file.path
            else classified_file.path
        )
        if fname in ("macros.rs", "mod.rs", "health.rs"):
            return []

        if "http_handler!" not in content:
            # Check if there are pub async fn handlers defined manually
            if re.search(r"pub\s+async\s+fn\s+\w+\s*\(", content):
                return [
                    self._make_finding(
                        file_path=classified_file.path,
                        line_number=1,
                        message="HTTP handler file defines hand-rolled handlers instead of using `http_handler!` macro.",
                        suggestion="Use `http_handler!(fn_name, RequestType, ResponseType, service_method, service_field);` for consistency.",
                        context="The http_handler! macro standardizes request/response handling, config transfer, and metadata propagation.",
                    )
                ]
        return []


def _find_service_methods(content: str) -> list[tuple[str, int]]:
    """Find all async trait impl methods (multi-line safe) and their line numbers.

    Matches methods like:
        async fn authorize(
            &self,
            request: tonic::Request<...>,
        ) -> ...

    Returns list of (method_name, line_number) tuples.
    """
    # Use re.DOTALL so \s+ matches across newlines
    pattern = re.compile(
        r"async\s+fn\s+(\w+)\s*\(\s*&self\s*,\s*request\s*:", re.DOTALL
    )
    methods = []
    for m in pattern.finditer(content):
        # Calculate line number from character offset
        line_number = content[: m.start()].count("\n") + 1
        methods.append((m.group(1), line_number))
    return methods


class ServiceMustHaveTracingInstrumentRule(FileContentRule):
    """gRPC service trait implementations must use #[tracing::instrument]."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="GR-002",
            name="Service methods must have tracing::instrument",
            severity=Severity.WARNING,
            category=Category.ARCHITECTURE,
            description="Every gRPC service method must have #[tracing::instrument] for observability.",
        )

    def check_file_content(
        self,
        classified_file: ClassifiedFile,
        content: str,
        repo_root: str,
        all_classified_files: list[ClassifiedFile] | None = None,
    ) -> list[Finding]:
        if classified_file.file_type != FileType.GRPC_SERVICE:
            return []

        # Only check files with tonic::async_trait (service impls)
        if "#[tonic::async_trait]" not in content:
            return []

        findings = []
        lines = content.split("\n")
        methods = _find_service_methods(content)

        for idx, (method_name, line_number) in enumerate(methods):
            # Look back up to 25 lines for #[tracing::instrument],
            # but stop at the previous method's line to avoid false positives
            prev_method_line = methods[idx - 1][1] if idx > 0 else 0
            lookback_start = max(prev_method_line, line_number - 26)
            has_instrument = False
            for j in range(lookback_start, line_number - 1):
                if "tracing::instrument" in lines[j]:
                    has_instrument = True
                    break

            if not has_instrument:
                line_content = (
                    lines[line_number - 1].strip() if line_number <= len(lines) else ""
                )
                findings.append(
                    self._make_finding(
                        file_path=classified_file.path,
                        line_number=line_number,
                        message=f"gRPC service method `{method_name}` is missing `#[tracing::instrument]`.",
                        line_content=line_content,
                        suggestion='Add `#[tracing::instrument(name = "...", fields(...), skip(self, request))]` above the method.',
                        context="All gRPC service methods must have tracing instrumentation for observability and logging.",
                    )
                )

        return findings


class ServiceMustUseGrpcLoggingWrapperRule(FileContentRule):
    """gRPC service methods must use grpc_logging_wrapper."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="GR-003",
            name="Service methods must use grpc_logging_wrapper",
            severity=Severity.WARNING,
            category=Category.ARCHITECTURE,
            description="gRPC service methods must wrap their logic in grpc_logging_wrapper for structured logging.",
        )

    def check_file_content(
        self,
        classified_file: ClassifiedFile,
        content: str,
        repo_root: str,
        all_classified_files: list[ClassifiedFile] | None = None,
    ) -> list[Finding]:
        if classified_file.file_type != FileType.GRPC_SERVICE:
            return []

        if "#[tonic::async_trait]" not in content:
            return []

        findings = []
        lines = content.split("\n")
        methods = _find_service_methods(content)

        for idx, (method_name, line_number) in enumerate(methods):
            # Determine the end boundary: either the next method or +50 lines
            if idx + 1 < len(methods):
                end_line = methods[idx + 1][1]
            else:
                end_line = min(len(lines), line_number + 50)

            has_wrapper = False
            for j in range(line_number - 1, end_line):
                if j >= len(lines):
                    break
                if "grpc_logging_wrapper" in lines[j]:
                    has_wrapper = True
                    break

            if not has_wrapper:
                line_content = (
                    lines[line_number - 1].strip() if line_number <= len(lines) else ""
                )
                findings.append(
                    self._make_finding(
                        file_path=classified_file.path,
                        line_number=line_number,
                        message=f"gRPC service method `{method_name}` does not use `grpc_logging_wrapper`.",
                        line_content=line_content,
                        suggestion="Wrap the method body in `grpc_logging_wrapper(request, &service_name, config, FlowName, |data| { ... }).await`.",
                        context="grpc_logging_wrapper provides structured logging, metrics, and request/response tracing.",
                    )
                )

        return findings


class ServiceMustCallGetConfigRule(FileContentRule):
    """gRPC service methods must call get_config_from_request."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="GR-004",
            name="Service methods must call get_config_from_request",
            severity=Severity.WARNING,
            category=Category.ARCHITECTURE,
            description="Every gRPC service method must extract config via get_config_from_request.",
        )

    def check_file_content(
        self,
        classified_file: ClassifiedFile,
        content: str,
        repo_root: str,
        all_classified_files: list[ClassifiedFile] | None = None,
    ) -> list[Finding]:
        if classified_file.file_type != FileType.GRPC_SERVICE:
            return []

        if "#[tonic::async_trait]" not in content:
            return []

        findings = []
        lines = content.split("\n")
        methods = _find_service_methods(content)

        for idx, (method_name, line_number) in enumerate(methods):
            # Determine the end boundary: either the next method or +30 lines
            if idx + 1 < len(methods):
                end_line = methods[idx + 1][1]
            else:
                end_line = min(len(lines), line_number + 30)

            has_config = False
            for j in range(line_number - 1, end_line):
                if j >= len(lines):
                    break
                if "get_config_from_request" in lines[j]:
                    has_config = True
                    break

            if not has_config:
                line_content = (
                    lines[line_number - 1].strip() if line_number <= len(lines) else ""
                )
                findings.append(
                    self._make_finding(
                        file_path=classified_file.path,
                        line_number=line_number,
                        message=f"gRPC service method `{method_name}` does not call `get_config_from_request`.",
                        line_content=line_content,
                        suggestion="Add `let config = get_config_from_request(&request)?;` at the start of the method.",
                        context="Config is needed for connector routing, feature flags, and environment settings.",
                    )
                )

        return findings


class RouterMustUsePostRule(RegexLineRule):
    """All routes (except /health) must use post()."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="GR-005",
            name="Routes must use post() method",
            severity=Severity.WARNING,
            category=Category.ARCHITECTURE,
            description="All gRPC-bridged HTTP routes must use POST, except /health.",
            pattern=r'\.route\s*\(\s*"(?!/health)[^"]+"\s*,\s*get\s*\(',
            message_template="HTTP route uses `get()` instead of `post()`. All gRPC-bridged routes must use POST.",
            suggestion="Change `get(handler)` to `post(handler)`.",
            context="gRPC operations are non-idempotent and carry request bodies; GET is only for health checks.",
            file_filter=r"router\.rs$",
        )


class NoDirectTonicStatusConstructionRule(RegexLineRule):
    """Avoid constructing tonic::Status directly with generic messages."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="GR-006",
            name="Avoid tonic::Status::unknown()",
            severity=Severity.SUGGESTION,
            category=Category.ERROR_HANDLING,
            description="Use specific tonic status codes, not generic unknown().",
            pattern=r"tonic::Status::unknown\s*\(",
            message_template="Using `tonic::Status::unknown()`. Prefer specific status codes like `internal`, `invalid_argument`, `not_found`.",
            suggestion="Use `tonic::Status::internal(...)`, `tonic::Status::invalid_argument(...)`, etc.",
            context="Specific status codes help clients handle errors appropriately.",
            file_filter=r"\.rs$",
        )


def get_rules() -> list[Rule]:
    """Return all gRPC server rules."""
    return [
        HandlerMustUseHttpHandlerMacroRule(),
        ServiceMustHaveTracingInstrumentRule(),
        ServiceMustUseGrpcLoggingWrapperRule(),
        ServiceMustCallGetConfigRule(),
        RouterMustUsePostRule(),
        NoDirectTonicStatusConstructionRule(),
    ]
