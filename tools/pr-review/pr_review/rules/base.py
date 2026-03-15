"""Base classes and types for the rule system."""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pr_review.diff_parser import ChangedFile
    from pr_review.file_classifier import ClassifiedFile


class Severity(Enum):
    """Severity level of a finding."""

    CRITICAL = "critical"
    WARNING = "warning"
    SUGGESTION = "suggestion"

    @property
    def score_penalty(self) -> int:
        """Score deduction for this severity level."""
        return {
            Severity.CRITICAL: 20,
            Severity.WARNING: 5,
            Severity.SUGGESTION: 1,
        }[self]

    @property
    def icon(self) -> str:
        return {
            Severity.CRITICAL: "!!",
            Severity.WARNING: "!",
            Severity.SUGGESTION: "*",
        }[self]


class Category(Enum):
    """Category of the rule/finding."""

    TYPE_SAFETY = "Type Safety"
    ARCHITECTURE = "Architecture Compliance"
    SECURITY = "Security"
    ERROR_HANDLING = "Error Handling"
    CONNECTOR_PATTERN = "Connector Patterns"
    DOMAIN_RULES = "Domain Rules"
    TESTING = "Testing"
    PR_QUALITY = "PR Quality"


@dataclass
class Finding:
    """A single issue found by a rule."""

    rule_id: str  # e.g., "TS-001"
    rule_name: str  # e.g., "No unwrap() calls"
    severity: Severity
    category: Category
    message: str  # Human-readable description of the issue
    file_path: str  # File where the issue was found
    line_number: int  # Line number (0 if file-level)
    line_content: str = ""  # The offending line content
    suggestion: str = ""  # Suggested fix or explanation
    context: str = ""  # Additional context about why this matters

    @property
    def location(self) -> str:
        """Format file:line location string."""
        if self.line_number > 0:
            return f"{self.file_path}:{self.line_number}"
        return self.file_path


class Rule(ABC):
    """Base class for all review rules.

    Each rule inspects changed files and produces zero or more findings.
    Rules can operate at different levels:
    - Per-line: Check individual added/changed lines
    - Per-file: Check the full file context
    - Per-diff: Check across multiple files
    """

    def __init__(
        self,
        rule_id: str,
        name: str,
        severity: Severity,
        category: Category,
        description: str,
    ):
        self.rule_id = rule_id
        self.name = name
        self.severity = severity
        self.category = category
        self.description = description

    @abstractmethod
    def check(
        self,
        classified_file: ClassifiedFile,
        repo_root: str,
        all_classified_files: list[ClassifiedFile] | None = None,
    ) -> list[Finding]:
        """Run the rule against a classified file.

        Args:
            classified_file: The file to check.
            repo_root: Path to the repository root.
            all_classified_files: All files in the diff (for cross-file rules).

        Returns:
            List of findings (empty if no issues).
        """
        ...

    def _make_finding(
        self,
        file_path: str,
        line_number: int,
        message: str,
        line_content: str = "",
        suggestion: str = "",
        context: str = "",
    ) -> Finding:
        """Helper to create a Finding with this rule's metadata."""
        return Finding(
            rule_id=self.rule_id,
            rule_name=self.name,
            severity=self.severity,
            category=self.category,
            message=message,
            file_path=file_path,
            line_number=line_number,
            line_content=line_content,
            suggestion=suggestion,
            context=context,
        )


class RegexLineRule(Rule):
    """A rule that checks each added line against a regex pattern.

    This is the most common rule type - it scans added lines in the diff
    for matches against a pattern and reports findings.
    """

    def __init__(
        self,
        rule_id: str,
        name: str,
        severity: Severity,
        category: Category,
        description: str,
        pattern: str,
        message_template: str,
        suggestion: str = "",
        context: str = "",
        file_filter: str | None = None,
        exclude_test_files: bool = False,
        exclude_patterns: list[str] | None = None,
    ):
        super().__init__(rule_id, name, severity, category, description)
        self._pattern = re.compile(pattern)
        self._message_template = message_template
        self._suggestion = suggestion
        self._context = context
        self._file_filter = re.compile(file_filter) if file_filter else None
        self._exclude_test_files = exclude_test_files
        self._exclude_patterns: list[re.Pattern[str]] = [
            re.compile(p) for p in (exclude_patterns or [])
        ]

    def check(
        self,
        classified_file: ClassifiedFile,
        repo_root: str,
        all_classified_files: list[ClassifiedFile] | None = None,
    ) -> list[Finding]:
        cf = classified_file.changed_file

        # Skip non-Rust files unless file_filter is set
        if self._file_filter:
            if not self._file_filter.search(cf.path):
                return []
        elif not cf.is_rust_file:
            return []

        # Skip deleted files
        if cf.is_deleted:
            return []

        # Skip test files if configured
        if self._exclude_test_files and classified_file.is_test:
            return []

        findings: list[Finding] = []
        for line in cf.added_lines:
            content = line.content

            # Skip lines matching exclusion patterns
            if any(ep.search(content) for ep in self._exclude_patterns):
                continue

            # Skip comments
            stripped = content.strip()
            if (
                stripped.startswith("//")
                or stripped.startswith("*")
                or stripped.startswith("/*")
            ):
                continue

            if self._pattern.search(content):
                findings.append(
                    self._make_finding(
                        file_path=cf.path,
                        line_number=line.line_number,
                        message=self._message_template,
                        line_content=content.strip(),
                        suggestion=self._suggestion,
                        context=self._context,
                    )
                )

        return findings


class FileContentRule(Rule):
    """A rule that checks the full file content (not just the diff).

    Useful for rules that need to verify the presence/absence of
    certain constructs in the complete file.
    """

    def __init__(
        self,
        rule_id: str,
        name: str,
        severity: Severity,
        category: Category,
        description: str,
    ):
        super().__init__(rule_id, name, severity, category, description)

    @abstractmethod
    def check_file_content(
        self,
        classified_file: ClassifiedFile,
        content: str,
        repo_root: str,
        all_classified_files: list[ClassifiedFile] | None = None,
    ) -> list[Finding]:
        """Check the full file content.

        Args:
            classified_file: The classified file.
            content: Full file content as a string.
            repo_root: Repository root path.
            all_classified_files: All files in the diff.

        Returns:
            List of findings.
        """
        ...

    def check(
        self,
        classified_file: ClassifiedFile,
        repo_root: str,
        all_classified_files: list[ClassifiedFile] | None = None,
    ) -> list[Finding]:
        cf = classified_file.changed_file
        if cf.is_deleted or cf.is_binary:
            return []

        content = cf.get_full_new_content(repo_root)
        if content is None:
            return []

        return self.check_file_content(
            classified_file, content, repo_root, all_classified_files
        )


class CrossFileRule(Rule):
    """A rule that checks relationships between multiple files.

    Used for rules like "every connector must have a transformer file"
    or "new connectors must be registered".
    """

    def __init__(
        self,
        rule_id: str,
        name: str,
        severity: Severity,
        category: Category,
        description: str,
    ):
        super().__init__(rule_id, name, severity, category, description)

    def check(
        self,
        classified_file: ClassifiedFile,
        repo_root: str,
        all_classified_files: list[ClassifiedFile] | None = None,
    ) -> list[Finding]:
        # CrossFileRules are invoked differently - through check_all
        return []

    @abstractmethod
    def check_all(
        self,
        classified_files: list[ClassifiedFile],
        repo_root: str,
    ) -> list[Finding]:
        """Check across all classified files.

        Args:
            classified_files: All classified files in the diff.
            repo_root: Repository root path.

        Returns:
            List of findings.
        """
        ...


class RuleRegistry:
    """Registry of all active rules."""

    def __init__(self) -> None:
        self._rules: list[Rule] = []
        self._cross_file_rules: list[CrossFileRule] = []

    def register(self, rule: Rule) -> None:
        """Register a rule."""
        if isinstance(rule, CrossFileRule):
            self._cross_file_rules.append(rule)
        self._rules.append(rule)

    def register_all(self, rules: list[Rule]) -> None:
        """Register multiple rules."""
        for rule in rules:
            self.register(rule)

    @property
    def rules(self) -> list[Rule]:
        return list(self._rules)

    @property
    def cross_file_rules(self) -> list[CrossFileRule]:
        return list(self._cross_file_rules)

    @property
    def per_file_rules(self) -> list[Rule]:
        """Rules that are not cross-file rules (or are but also do per-file checks)."""
        return [r for r in self._rules if not isinstance(r, CrossFileRule)]

    def count(self) -> int:
        return len(self._rules)
