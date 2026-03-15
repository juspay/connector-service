"""Testing rules.

Validates test file existence, proper test patterns, credential handling,
and flow coverage for connector implementations.
"""

from __future__ import annotations

import re
from pathlib import Path

from pr_review.rules.base import (
    Rule,
    RegexLineRule,
    FileContentRule,
    CrossFileRule,
    Finding,
    Severity,
    Category,
)
from pr_review.file_classifier import ClassifiedFile, FileType


class TestFileExistsRule(CrossFileRule):
    """Check that new connectors have a corresponding test file."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="TE-001",
            name="New connectors must have test files",
            severity=Severity.WARNING,
            category=Category.TESTING,
            description="Each new connector should have a test file in backend/grpc-server/tests/.",
        )

    def check_all(
        self,
        classified_files: list[ClassifiedFile],
        repo_root: str,
    ) -> list[Finding]:
        # Find new connector files
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
        tests_dir = Path(repo_root) / "backend/grpc-server/tests"

        for name in new_connectors:
            # Check for various test file naming patterns
            test_patterns = [
                tests_dir / f"{name}_payment_flows_test.rs",
                tests_dir / f"{name}_test.rs",
                tests_dir / f"{name}.rs",
            ]

            # Also check if any test file references this connector in the diff
            has_test = any(p.exists() for p in test_patterns)
            if not has_test:
                # Check if a test file for this connector is in the diff
                has_test = any(
                    cf.file_type == FileType.GRPC_TEST and cf.connector_name == name
                    for cf in classified_files
                )

            if not has_test:
                findings.append(
                    self._make_finding(
                        file_path=f"backend/connector-integration/src/connectors/{name}.rs",
                        line_number=0,
                        message=f"New connector `{name}` has no test file.",
                        suggestion=f"Create `backend/grpc-server/tests/{name}_payment_flows_test.rs` with tests for all supported flows.",
                        context="Integration tests verify the connector works end-to-end through the gRPC server.",
                    )
                )
        return findings


class TestUsesGrpcTestMacroRule(FileContentRule):
    """Check that gRPC test files use the grpc_test! macro."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="TE-002",
            name="Test files should use grpc_test! macro",
            severity=Severity.SUGGESTION,
            category=Category.TESTING,
            description="gRPC test files should use the grpc_test! macro for consistent test setup.",
        )

    def check_file_content(
        self,
        classified_file: ClassifiedFile,
        content: str,
        repo_root: str,
        all_classified_files: list[ClassifiedFile] | None = None,
    ) -> list[Finding]:
        if classified_file.file_type != FileType.GRPC_TEST:
            return []

        if "grpc_test!" not in content:
            return [
                self._make_finding(
                    file_path=classified_file.path,
                    line_number=1,
                    message="Test file does not use `grpc_test!` macro.",
                    suggestion="Use `grpc_test!(test_name, client_type, |client| { ... })` for in-process gRPC testing.",
                    context="The grpc_test! macro handles server setup, Unix socket creation, and client configuration.",
                )
            ]
        return []


class TestLintAllowancesRule(FileContentRule):
    """Check that test files allow the strict Clippy lints."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="TE-003",
            name="Test files should relax strict Clippy lints",
            severity=Severity.SUGGESTION,
            category=Category.TESTING,
            description="Test files should allow unwrap, expect, and panic which are forbidden in production code.",
        )

    def check_file_content(
        self,
        classified_file: ClassifiedFile,
        content: str,
        repo_root: str,
        all_classified_files: list[ClassifiedFile] | None = None,
    ) -> list[Finding]:
        if classified_file.file_type not in (
            FileType.GRPC_TEST,
            FileType.CONNECTOR_TEST,
        ):
            return []

        if classified_file.changed_file.is_new:
            # Only check new test files - existing ones may have their own patterns
            has_allow = (
                "allow(clippy::unwrap_used)" in content
                or "allow(clippy::expect_used)" in content
            )
            if not has_allow:
                return [
                    self._make_finding(
                        file_path=classified_file.path,
                        line_number=1,
                        message="Test file does not relax strict Clippy lints.",
                        suggestion="Add `#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]` at the top of the test file.",
                        context="Test files are allowed to use unwrap/expect/panic since test failures are expected to panic.",
                    )
                ]
        return []


class NoHardcodedCredentialsInTestsRule(FileContentRule):
    """Check that test files don't contain hardcoded credentials."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="TE-004",
            name="No hardcoded credentials in tests",
            severity=Severity.CRITICAL,
            category=Category.TESTING,
            description="Test files must load credentials from the credential utility, not hardcode them.",
        )
        self._cred_patterns = re.compile(
            r"""(?:"|')(sk_live_|pk_live_|sk_test_|pk_test_)\w{10,}""",
        )

    def check_file_content(
        self,
        classified_file: ClassifiedFile,
        content: str,
        repo_root: str,
        all_classified_files: list[ClassifiedFile] | None = None,
    ) -> list[Finding]:
        if not classified_file.is_test:
            return []

        findings = []
        for i, line in enumerate(content.split("\n"), 1):
            if self._cred_patterns.search(line):
                findings.append(
                    self._make_finding(
                        file_path=classified_file.path,
                        line_number=i,
                        message="Hardcoded test credential detected in test file.",
                        line_content=line.strip()[:80] + "...",
                        suggestion="Use `credential_utils::load_credentials()` to load credentials from the encrypted creds file.",
                        context="Credentials should come from .github/test/creds.json or CONNECTOR_AUTH_FILE_PATH env var.",
                    )
                )
        return findings


def get_rules() -> list[Rule]:
    """Return all testing rules."""
    return [
        TestFileExistsRule(),
        TestUsesGrpcTestMacroRule(),
        TestLintAllowancesRule(),
        NoHardcodedCredentialsInTestsRule(),
    ]
