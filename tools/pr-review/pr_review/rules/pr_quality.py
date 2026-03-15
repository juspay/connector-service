"""PR quality rules.

Validates PR title follows conventional commits, description is filled out,
test section is populated, and change scope is reasonable.
"""

from __future__ import annotations

import re
import subprocess

from pr_review.rules.base import (
    Rule,
    Finding,
    Severity,
    Category,
)
from pr_review.file_classifier import ClassifiedFile


class PRTitleConventionalCommitRule(Rule):
    """Check that the PR title follows conventional commits format."""

    _DEFAULT_COMMIT_TYPES = [
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

    def __init__(self, commit_types: list[str] | None = None) -> None:
        super().__init__(
            rule_id="PQ-001",
            name="PR title must follow conventional commits",
            severity=Severity.WARNING,
            category=Category.PR_QUALITY,
            description="PR title must match the format: type(scope): description",
        )
        types = commit_types if commit_types is not None else self._DEFAULT_COMMIT_TYPES
        types_pattern = "|".join(re.escape(t) for t in types)
        self._pattern = re.compile(
            rf"^({types_pattern})"
            r"(\([a-zA-Z0-9_-]+\))?!?:\s+.{3,}$"
        )
        self._types = types

    def check(
        self,
        classified_file: ClassifiedFile,
        repo_root: str,
        all_classified_files: list[ClassifiedFile] | None = None,
    ) -> list[Finding]:
        # This rule is handled specially - it checks git metadata, not files
        return []

    def check_title(self, title: str) -> list[Finding]:
        """Check a PR title string directly."""
        if not title:
            return [
                self._make_finding(
                    file_path="PR",
                    line_number=0,
                    message="PR title is empty.",
                    suggestion="Use format: type(scope): description (e.g., feat(connector): add Stripe integration)",
                )
            ]

        if not self._pattern.match(title):
            types_str = ", ".join(self._types)
            return [
                self._make_finding(
                    file_path="PR",
                    line_number=0,
                    message=f"PR title does not follow conventional commits format: `{title}`",
                    line_content=title,
                    suggestion=f"Format: type(scope): description. Types: {types_str}.",
                    context="Conventional commits are enforced in CI by cocogitto and used for automated changelog generation via git-cliff.",
                )
            ]
        return []


class FileScopeRule(Rule):
    """Check that the number of changed files is reasonable."""

    def __init__(self, max_files: int = 25) -> None:
        super().__init__(
            rule_id="PQ-002",
            name="PR should have a reasonable scope",
            severity=Severity.SUGGESTION,
            category=Category.PR_QUALITY,
            description="PRs with too many changed files are harder to review.",
        )
        self._max_files = max_files

    def check(
        self,
        classified_file: ClassifiedFile,
        repo_root: str,
        all_classified_files: list[ClassifiedFile] | None = None,
    ) -> list[Finding]:
        # This is handled at the analysis level, not per-file
        return []

    def check_file_count(self, file_count: int) -> list[Finding]:
        """Check the total number of files changed."""
        if file_count > self._max_files:
            return [
                self._make_finding(
                    file_path="PR",
                    line_number=0,
                    message=f"PR changes {file_count} files (threshold: {self._max_files}). Consider splitting into smaller PRs.",
                    suggestion="Break large PRs into focused, reviewable chunks. For connector PRs, separate the connector code from framework changes.",
                    context="Smaller PRs are reviewed more thoroughly and merged more quickly.",
                )
            ]
        return []


class BranchNameRule(Rule):
    """Check that the branch name follows conventions."""

    _DEFAULT_BRANCH_PREFIXES = [
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
    ]

    def __init__(self, branch_prefixes: list[str] | None = None) -> None:
        super().__init__(
            rule_id="PQ-003",
            name="Branch name should be descriptive",
            severity=Severity.SUGGESTION,
            category=Category.PR_QUALITY,
            description="Branch names should follow a descriptive pattern.",
        )
        prefixes = (
            branch_prefixes
            if branch_prefixes is not None
            else self._DEFAULT_BRANCH_PREFIXES
        )
        prefixes_pattern = "|".join(re.escape(p) for p in prefixes)
        self._pattern = re.compile(rf"^({prefixes_pattern})/[a-z0-9][a-z0-9_-]+$")

    def check(
        self,
        classified_file: ClassifiedFile,
        repo_root: str,
        all_classified_files: list[ClassifiedFile] | None = None,
    ) -> list[Finding]:
        return []

    def check_branch_name(self, branch_name: str) -> list[Finding]:
        """Check the branch name."""
        if not branch_name or branch_name in ("main", "master", "develop"):
            return []

        if not self._pattern.match(branch_name):
            return [
                self._make_finding(
                    file_path="PR",
                    line_number=0,
                    message=f"Branch name `{branch_name}` does not follow the convention.",
                    suggestion="Use: type/description (e.g., feat/add-stripe-connector, fix/payment-timeout).",
                    context="Consistent branch naming helps with CI/CD pipelines and automated release notes.",
                )
            ]
        return []


class WIPInTitleRule(Rule):
    """Check that non-draft PRs don't have WIP markers."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="PQ-004",
            name="No WIP markers in PR title",
            severity=Severity.SUGGESTION,
            category=Category.PR_QUALITY,
            description="Non-draft PRs should not have WIP/Draft markers in the title.",
        )
        self._wip_pattern = re.compile(
            r"\b(WIP|DRAFT|DO NOT MERGE|DNM)\b", re.IGNORECASE
        )

    def check(
        self,
        classified_file: ClassifiedFile,
        repo_root: str,
        all_classified_files: list[ClassifiedFile] | None = None,
    ) -> list[Finding]:
        return []

    def check_title(self, title: str) -> list[Finding]:
        """Check for WIP markers in the title."""
        if title and self._wip_pattern.search(title):
            return [
                self._make_finding(
                    file_path="PR",
                    line_number=0,
                    message=f"PR title contains WIP marker: `{title}`",
                    suggestion="Remove WIP/Draft markers or convert to a GitHub draft PR.",
                )
            ]
        return []


def get_git_branch_name(repo_root: str | None = None) -> str:
    """Get the current git branch name."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True,
            text=True,
            cwd=repo_root,
            timeout=10,
        )
        return result.stdout.strip() if result.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def get_last_commit_message(repo_root: str | None = None) -> str:
    """Get the last commit message (used as proxy for PR title)."""
    try:
        result = subprocess.run(
            ["git", "log", "-1", "--format=%s"],
            capture_output=True,
            text=True,
            cwd=repo_root,
            timeout=10,
        )
        return result.stdout.strip() if result.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def get_rules(learned_data: dict | None = None) -> list[Rule]:
    """Return all PR quality rules.

    Args:
        learned_data: Optional dict from learner.py with commit config.
    """
    # Extract commit types and branch prefixes from learned data
    commit_types = None
    branch_prefixes = None
    if learned_data:
        commit_config = learned_data.get("commit_config", {})
        ct = commit_config.get("commit_types")
        if ct and isinstance(ct, list) and len(ct) > 0:
            commit_types = ct
        bp = commit_config.get("branch_prefixes")
        if bp and isinstance(bp, list) and len(bp) > 0:
            branch_prefixes = bp

    return [
        PRTitleConventionalCommitRule(commit_types=commit_types),
        FileScopeRule(),
        BranchNameRule(branch_prefixes=branch_prefixes),
        WIPInTitleRule(),
    ]
