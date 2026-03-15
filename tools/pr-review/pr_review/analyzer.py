"""Analyzer: orchestrates rule execution and collects findings."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from pr_review.diff_parser import ChangedFile, parse_diff, get_diff
from pr_review.file_classifier import (
    ClassifiedFile,
    classify_files,
    get_connector_names,
)
from pr_review.rules.base import (
    Finding,
    FileContentRule,
    Severity,
    Category,
    CrossFileRule,
    RuleRegistry,
    Rule,
)
from pr_review.rules import get_all_rules
from pr_review.rules.pr_quality import (
    PRTitleConventionalCommitRule,
    FileScopeRule,
    BranchNameRule,
    WIPInTitleRule,
    get_git_branch_name,
    get_last_commit_message,
)

# Regex to extract backtick-quoted identifiers from finding messages
_BACKTICK_IDENT = re.compile(r"`([^`]+)`")


@dataclass
class AnalysisResult:
    """Complete result of a PR review analysis."""

    findings: list[Finding] = field(default_factory=list)
    files_analyzed: int = 0
    rules_applied: int = 0
    connector_names: set[str] = field(default_factory=set)
    classified_files: list[ClassifiedFile] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def warning_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.WARNING)

    @property
    def suggestion_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.SUGGESTION)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def quality_score(self) -> int:
        """Calculate quality score using the Quality Guardian algorithm."""
        score = 100
        score -= self.critical_count * Severity.CRITICAL.score_penalty
        score -= self.warning_count * Severity.WARNING.score_penalty
        score -= self.suggestion_count * Severity.SUGGESTION.score_penalty
        return max(0, score)

    @property
    def status(self) -> str:
        """Determine the review status based on quality score."""
        score = self.quality_score
        if score >= 95:
            return "PASS (Excellent)"
        elif score >= 80:
            return "PASS (Good)"
        elif score >= 60:
            return "PASS WITH WARNINGS"
        elif score >= 40:
            return "BLOCKED (Poor)"
        else:
            return "BLOCKED (Critical)"

    @property
    def is_passing(self) -> bool:
        return self.quality_score >= 60

    def findings_by_severity(self) -> dict[Severity, list[Finding]]:
        """Group findings by severity."""
        result: dict[Severity, list[Finding]] = {s: [] for s in Severity}
        for f in self.findings:
            result[f.severity].append(f)
        return result

    def findings_by_category(self) -> dict[Category, list[Finding]]:
        """Group findings by category."""
        result: dict[Category, list[Finding]] = {c: [] for c in Category}
        for f in self.findings:
            result[f.category].append(f)
        return result

    def findings_by_file(self) -> dict[str, list[Finding]]:
        """Group findings by file path."""
        result: dict[str, list[Finding]] = {}
        for f in self.findings:
            result.setdefault(f.file_path, []).append(f)
        return result


def _get_added_line_numbers(changed_file: ChangedFile) -> set[int]:
    """Return the set of line numbers that were added in this file's diff."""
    return {line.line_number for line in changed_file.added_lines}


def _get_added_line_contents(changed_file: ChangedFile) -> str:
    """Return the concatenated content of added lines for keyword searching.

    Excludes `use` import lines because identifiers in imports are
    boilerplate and don't indicate that a new construct was introduced.
    Without this exclusion, a PR that merely adds an import like
    ``use ... CompositeAuthorizeRequest, ...`` would falsely match
    file-level findings that mention that identifier.
    """
    return "\n".join(
        line.content
        for line in changed_file.added_lines
        if not line.content.strip().startswith("use ")
        and not line.content.strip().startswith("use{")
    )


def _is_finding_relevant_to_diff(
    finding: Finding,
    changed_file: ChangedFile,
) -> bool:
    """Determine if a FileContentRule finding is relevant to the PR diff.

    FileContentRule rules scan the full file content but should only report
    issues that are related to changes in the current PR:

    - Line-specific findings (line_number > 1): kept only if the finding's
      line number corresponds to an added line in the diff.
    - File-level findings (line_number <= 1): kept if the file is new, or
      if the *first* backtick-quoted identifier from the finding message
      appears in a non-import added line (meaning the PR introduced the
      relevant construct).
    """
    added_lines = _get_added_line_numbers(changed_file)

    if finding.line_number > 1:
        # Line-specific finding: must be on an added line
        return finding.line_number in added_lines

    # File-level finding (line_number == 0 or 1)
    if changed_file.is_new:
        # New files: all findings are relevant
        return True

    if not added_lines:
        # No added lines in this file: nothing is relevant
        return False

    # Check if the primary identifier from the finding message appears in
    # an added line (excluding import statements).
    #
    # We use the FIRST backtick-quoted identifier as the primary subject.
    # For example, in "`CompositeAuthorizeRequest` is missing
    # `CompositeAccessTokenRequest` trait", the first identifier
    # ("CompositeAuthorizeRequest") is the type being checked, while the
    # second ("CompositeAccessTokenRequest") is the trait name that would
    # appear in any impl line.  Checking only the first prevents false
    # matches where the trait name appears in an unrelated added line.
    identifiers = _BACKTICK_IDENT.findall(finding.message)
    if identifiers:
        added_text = _get_added_line_contents(changed_file)
        # Use only the first identifier (primary subject of the finding)
        return identifiers[0] in added_text

    # No identifiers to check — fall back to keeping the finding if there
    # are added lines (conservative: the file was touched, so the finding
    # might be relevant)
    return True


class Analyzer:
    """Orchestrates the PR review analysis pipeline."""

    def __init__(
        self,
        repo_root: str,
        rules: list[Rule] | None = None,
        pr_title: str | None = None,
    ):
        self.repo_root = repo_root
        self.registry = RuleRegistry()
        self.pr_title = pr_title

        # Register rules
        all_rules = rules if rules is not None else get_all_rules()
        self.registry.register_all(all_rules)

    def analyze_diff(self, diff_text: str) -> AnalysisResult:
        """Analyze a raw diff text.

        Args:
            diff_text: Raw git diff output.

        Returns:
            AnalysisResult with all findings.
        """
        # Parse diff into structured data
        changed_files = parse_diff(diff_text)
        if not changed_files:
            return AnalysisResult(rules_applied=self.registry.count())

        # Classify files
        classified_files = classify_files(changed_files)
        connector_names = get_connector_names(classified_files)

        # Build a lookup from file path to ChangedFile for diff filtering
        changed_file_map: dict[str, ChangedFile] = {
            cf.path: cf.changed_file for cf in classified_files
        }

        # Collect all findings
        all_findings: list[Finding] = []

        # Run per-file rules
        for cf in classified_files:
            for rule in self.registry.per_file_rules:
                findings = rule.check(cf, self.repo_root, classified_files)

                # Filter FileContentRule findings to only report issues on
                # lines that were actually added/changed in the PR diff.
                # RegexLineRule already only checks added lines, so no
                # filtering needed there.
                if isinstance(rule, FileContentRule):
                    findings = [
                        f
                        for f in findings
                        if _is_finding_relevant_to_diff(f, cf.changed_file)
                    ]

                all_findings.extend(findings)

        # Run cross-file rules
        for rule in self.registry.cross_file_rules:
            findings = rule.check_all(classified_files, self.repo_root)
            all_findings.extend(findings)

        # Run PR-level rules
        all_findings.extend(self._check_pr_metadata(classified_files))

        # Sort findings: critical first, then by file, then by line
        all_findings.sort(
            key=lambda f: (
                {Severity.CRITICAL: 0, Severity.WARNING: 1, Severity.SUGGESTION: 2}[
                    f.severity
                ],
                f.file_path,
                f.line_number,
            )
        )

        return AnalysisResult(
            findings=all_findings,
            files_analyzed=len(classified_files),
            rules_applied=self.registry.count(),
            connector_names=connector_names,
            classified_files=classified_files,
        )

    def analyze_branch(self, base_branch: str = "main") -> AnalysisResult:
        """Analyze the diff between the current branch and a base branch.

        Args:
            base_branch: The branch to diff against.

        Returns:
            AnalysisResult with all findings.
        """
        diff_text = get_diff(base_branch, self.repo_root)
        if not diff_text.strip():
            return AnalysisResult(rules_applied=self.registry.count())
        return self.analyze_diff(diff_text)

    def _check_pr_metadata(
        self, classified_files: list[ClassifiedFile]
    ) -> list[Finding]:
        """Run PR-level checks (title, scope, branch name)."""
        findings: list[Finding] = []

        # Determine PR title (from arg, or fall back to last commit message)
        title = self.pr_title
        if title is None:
            title = get_last_commit_message(self.repo_root)

        # Check PR title
        for rule in self.registry.rules:
            if isinstance(rule, PRTitleConventionalCommitRule):
                findings.extend(rule.check_title(title))
            elif isinstance(rule, WIPInTitleRule):
                findings.extend(rule.check_title(title))
            elif isinstance(rule, FileScopeRule):
                findings.extend(rule.check_file_count(len(classified_files)))
            elif isinstance(rule, BranchNameRule):
                branch = get_git_branch_name(self.repo_root)
                findings.extend(rule.check_branch_name(branch))

        return findings
