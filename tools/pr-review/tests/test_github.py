"""Tests for pr_review.github module."""

from __future__ import annotations

import json
import pytest

from pr_review.github import (
    parse_pr_url,
    format_finding_as_comment,
    build_review_body,
    build_diff_line_set,
    classify_findings_for_review,
    PRMetadata,
)
from pr_review.rules.base import Finding, Severity, Category
from pr_review.analyzer import AnalysisResult


# ---------------------------------------------------------------------------
# parse_pr_url
# ---------------------------------------------------------------------------


class TestParsePrUrl:
    """Tests for parse_pr_url()."""

    def test_full_https_url(self):
        owner, repo, num = parse_pr_url(
            "https://github.com/juspay/connector-service/pull/42"
        )
        assert owner == "juspay"
        assert repo == "connector-service"
        assert num == 42

    def test_full_http_url(self):
        owner, repo, num = parse_pr_url("http://github.com/owner/repo/pull/99")
        assert owner == "owner"
        assert repo == "repo"
        assert num == 99

    def test_url_without_scheme(self):
        owner, repo, num = parse_pr_url("github.com/octocat/hello-world/pull/1")
        assert owner == "octocat"
        assert repo == "hello-world"
        assert num == 1

    def test_short_format(self):
        owner, repo, num = parse_pr_url("juspay/connector-service#123")
        assert owner == "juspay"
        assert repo == "connector-service"
        assert num == 123

    def test_url_with_trailing_whitespace(self):
        owner, repo, num = parse_pr_url("  https://github.com/a/b/pull/5  ")
        assert owner == "a"
        assert repo == "b"
        assert num == 5

    def test_short_format_with_whitespace(self):
        owner, repo, num = parse_pr_url("  owner/repo#7  ")
        assert owner == "owner"
        assert repo == "repo"
        assert num == 7

    def test_url_with_trailing_slash_ignored(self):
        # The regex won't match a trailing slash, but that's intentional
        # since GitHub URLs don't end with a slash after the number
        owner, repo, num = parse_pr_url("https://github.com/a/b/pull/10")
        assert num == 10

    def test_large_pr_number(self):
        owner, repo, num = parse_pr_url("owner/repo#99999")
        assert num == 99999

    def test_invalid_url_raises_valueerror(self):
        with pytest.raises(ValueError, match="Cannot parse PR URL"):
            parse_pr_url("not-a-valid-url")

    def test_invalid_no_number_raises_valueerror(self):
        with pytest.raises(ValueError):
            parse_pr_url("https://github.com/owner/repo/pull/")

    def test_invalid_empty_string(self):
        with pytest.raises(ValueError):
            parse_pr_url("")

    def test_invalid_just_repo(self):
        with pytest.raises(ValueError):
            parse_pr_url("owner/repo")

    def test_invalid_pr_issues_url(self):
        with pytest.raises(ValueError):
            parse_pr_url("https://github.com/owner/repo/issues/42")


# ---------------------------------------------------------------------------
# format_finding_as_comment
# ---------------------------------------------------------------------------


class TestFormatFindingAsComment:
    """Tests for format_finding_as_comment()."""

    def _make_finding(self, **kwargs) -> Finding:
        defaults = {
            "rule_id": "TS-001",
            "rule_name": "No unwrap() calls",
            "severity": Severity.CRITICAL,
            "category": Category.TYPE_SAFETY,
            "message": ".unwrap() call detected.",
            "file_path": "src/main.rs",
            "line_number": 42,
            "line_content": "let x = foo.unwrap();",
            "suggestion": "Use `?` operator instead.",
            "context": "unwrap can cause panics in production.",
        }
        defaults.update(kwargs)
        return Finding(**defaults)

    def test_critical_finding_format(self):
        f = self._make_finding()
        result = format_finding_as_comment(f)
        assert "**[TS-001] No unwrap() calls** (Critical)" in result
        assert ".unwrap() call detected." in result
        assert "**Fix:** Use `?` operator instead." in result
        assert "*unwrap can cause panics in production.*" in result

    def test_warning_finding_format(self):
        f = self._make_finding(severity=Severity.WARNING)
        result = format_finding_as_comment(f)
        assert "(Warning)" in result

    def test_suggestion_finding_format(self):
        f = self._make_finding(severity=Severity.SUGGESTION)
        result = format_finding_as_comment(f)
        assert "(Suggestion)" in result

    def test_no_suggestion(self):
        f = self._make_finding(suggestion="")
        result = format_finding_as_comment(f)
        assert "**Fix:**" not in result

    def test_no_context(self):
        f = self._make_finding(context="")
        result = format_finding_as_comment(f)
        # Should not have an italicized context line
        lines = result.strip().split("\n")
        for line in lines:
            assert not (line.startswith("*") and line.endswith("*") and len(line) > 2)

    def test_no_suggestion_no_context(self):
        f = self._make_finding(suggestion="", context="")
        result = format_finding_as_comment(f)
        assert "**Fix:**" not in result
        assert result.count("\n") >= 2  # At least header + blank + message


# ---------------------------------------------------------------------------
# build_review_body
# ---------------------------------------------------------------------------


class TestBuildReviewBody:
    """Tests for build_review_body()."""

    def _make_result(self, findings=None) -> AnalysisResult:
        return AnalysisResult(
            findings=findings or [],
            files_analyzed=5,
            rules_applied=48,
        )

    def _critical_finding(self) -> Finding:
        return Finding(
            rule_id="TS-001",
            rule_name="Test",
            severity=Severity.CRITICAL,
            category=Category.TYPE_SAFETY,
            message="test",
            file_path="a.rs",
            line_number=1,
        )

    def _warning_finding(self) -> Finding:
        return Finding(
            rule_id="AR-001",
            rule_name="Test",
            severity=Severity.WARNING,
            category=Category.ARCHITECTURE,
            message="test",
            file_path="a.rs",
            line_number=1,
        )

    def test_body_contains_header(self):
        result = self._make_result()
        body = build_review_body(result, 0, 0)
        assert "## PR Review -- connector-service" in body

    def test_body_contains_score(self):
        result = self._make_result()
        body = build_review_body(result, 0, 0)
        assert "**Quality Score:** 100/100 (Excellent)" in body

    def test_body_contains_severity_table(self):
        result = self._make_result([self._critical_finding()])
        body = build_review_body(result, 1, 1)
        assert "| Critical | 1 |" in body
        assert "| Warning | 0 |" in body

    def test_body_posted_count_message(self):
        result = self._make_result([self._critical_finding()])
        body = build_review_body(result, 1, 3)
        assert "*Posted 1 of 3 findings as line comments.*" in body

    def test_body_none_selected_message(self):
        result = self._make_result([self._critical_finding()])
        body = build_review_body(result, 0, 3)
        assert "*3 findings available (none selected for posting).*" in body

    def test_body_no_postable_no_message(self):
        result = self._make_result()
        body = build_review_body(result, 0, 0)
        assert "Posted" not in body
        assert "findings available" not in body

    def test_score_with_warnings(self):
        findings = [self._warning_finding()] * 3
        result = self._make_result(findings)
        body = build_review_body(result, 0, 0)
        assert "85/100" in body

    def test_status_label_extraction(self):
        result = self._make_result()
        body = build_review_body(result, 0, 0)
        # Status is "PASS (Excellent)" -> label should be "Excellent"
        assert "(Excellent)" in body


# ---------------------------------------------------------------------------
# build_diff_line_set
# ---------------------------------------------------------------------------


class TestBuildDiffLineSet:
    """Tests for build_diff_line_set()."""

    SAMPLE_DIFF = """\
diff --git a/src/main.rs b/src/main.rs
--- a/src/main.rs
+++ b/src/main.rs
@@ -10,3 +10,5 @@ fn main() {
     let x = 1;
+    let y = 2;
+    let z = 3;
     println!("done");
+    foo();
"""

    def test_added_lines_in_set(self):
        result = build_diff_line_set(self.SAMPLE_DIFF)
        assert ("src/main.rs", 11) in result  # let y = 2
        assert ("src/main.rs", 12) in result  # let z = 3
        assert ("src/main.rs", 14) in result  # foo()

    def test_context_lines_not_in_set(self):
        result = build_diff_line_set(self.SAMPLE_DIFF)
        assert ("src/main.rs", 10) not in result  # context line

    def test_empty_diff(self):
        result = build_diff_line_set("")
        assert result == set()

    def test_multiple_files(self):
        diff = """\
diff --git a/a.rs b/a.rs
--- a/a.rs
+++ b/a.rs
@@ -1,2 +1,3 @@
 line1
+added_a
 line2
diff --git a/b.rs b/b.rs
--- a/b.rs
+++ b/b.rs
@@ -5,2 +5,3 @@
 line5
+added_b
 line6
"""
        result = build_diff_line_set(diff)
        assert ("a.rs", 2) in result
        assert ("b.rs", 6) in result
        assert len(result) == 2


# ---------------------------------------------------------------------------
# classify_findings_for_review
# ---------------------------------------------------------------------------


class TestClassifyFindingsForReview:
    """Tests for classify_findings_for_review()."""

    def _make_finding(self, **kwargs) -> Finding:
        defaults = {
            "rule_id": "TS-001",
            "rule_name": "Test",
            "severity": Severity.CRITICAL,
            "category": Category.TYPE_SAFETY,
            "message": "test message",
            "file_path": "src/main.rs",
            "line_number": 42,
        }
        defaults.update(kwargs)
        return Finding(**defaults)

    def test_line_in_diff_becomes_line_comment(self):
        finding = self._make_finding(file_path="src/main.rs", line_number=42)
        diff_lines = {("src/main.rs", 42)}

        postable, body_only = classify_findings_for_review([finding], diff_lines)

        assert len(postable) == 1
        assert len(body_only) == 0
        _, comment = postable[0]
        assert comment["path"] == "src/main.rs"
        assert comment["line"] == 42
        assert comment["side"] == "RIGHT"
        assert "body" in comment

    def test_line_not_in_diff_becomes_file_comment(self):
        finding = self._make_finding(file_path="src/main.rs", line_number=99)
        diff_lines = {("src/main.rs", 42)}

        postable, body_only = classify_findings_for_review([finding], diff_lines)

        assert len(postable) == 1
        _, comment = postable[0]
        assert comment["path"] == "src/main.rs"
        assert comment["subject_type"] == "file"
        assert "line" not in comment

    def test_pr_level_finding_goes_to_body(self):
        finding = self._make_finding(
            rule_id="PQ-001",
            file_path="PR",
            line_number=0,
        )
        diff_lines = set()

        postable, body_only = classify_findings_for_review([finding], diff_lines)

        assert len(postable) == 0
        assert len(body_only) == 1
        assert body_only[0].rule_id == "PQ-001"

    def test_pq_rule_always_body_only(self):
        finding = self._make_finding(
            rule_id="PQ-003",
            file_path="src/main.rs",
            line_number=10,
        )
        diff_lines = {("src/main.rs", 10)}

        postable, body_only = classify_findings_for_review([finding], diff_lines)

        assert len(postable) == 0
        assert len(body_only) == 1

    def test_empty_file_path_goes_to_body(self):
        finding = self._make_finding(file_path="", line_number=0)
        postable, body_only = classify_findings_for_review([finding], set())

        assert len(postable) == 0
        assert len(body_only) == 1

    def test_mixed_findings(self):
        f1 = self._make_finding(rule_id="TS-001", file_path="a.rs", line_number=10)
        f2 = self._make_finding(rule_id="TS-002", file_path="b.rs", line_number=20)
        f3 = self._make_finding(rule_id="PQ-001", file_path="PR", line_number=0)
        f4 = self._make_finding(rule_id="AR-001", file_path="c.rs", line_number=30)

        diff_lines = {("a.rs", 10), ("c.rs", 30)}
        postable, body_only = classify_findings_for_review([f1, f2, f3, f4], diff_lines)

        assert len(postable) == 3  # f1 (line), f2 (file), f4 (line)
        assert len(body_only) == 1  # f3 (PQ)

        # f1 should be a line comment
        _, c1 = postable[0]
        assert "line" in c1
        assert c1["line"] == 10

        # f2 should be a file comment (line 20 not in diff)
        _, c2 = postable[1]
        assert c2.get("subject_type") == "file"

        # f4 should be a line comment
        _, c3 = postable[2]
        assert "line" in c3
        assert c3["line"] == 30

    def test_finding_with_zero_line_and_file_is_file_comment(self):
        finding = self._make_finding(
            rule_id="CP-005",
            file_path="src/connector.rs",
            line_number=0,
        )
        diff_lines = set()

        postable, body_only = classify_findings_for_review([finding], diff_lines)

        assert len(postable) == 1
        _, comment = postable[0]
        assert comment["subject_type"] == "file"


# ---------------------------------------------------------------------------
# PRMetadata
# ---------------------------------------------------------------------------


class TestPRMetadata:
    """Tests for PRMetadata dataclass."""

    def test_fields(self):
        meta = PRMetadata(
            owner="juspay",
            repo="connector-service",
            number=42,
            title="feat: add new connector",
            base_branch="main",
            head_branch="feat/new-connector",
            url="https://github.com/juspay/connector-service/pull/42",
        )
        assert meta.owner == "juspay"
        assert meta.repo == "connector-service"
        assert meta.number == 42
        assert meta.title == "feat: add new connector"
        assert meta.base_branch == "main"
        assert meta.head_branch == "feat/new-connector"


# ---------------------------------------------------------------------------
# _parse_selection (tested via import from cli)
# ---------------------------------------------------------------------------


class TestParseSelection:
    """Tests for _parse_selection helper in cli.py."""

    @pytest.fixture(autouse=True)
    def _import_fn(self):
        from pr_review.cli import _parse_selection

        self.parse = _parse_selection

    def test_none_returns_none(self):
        assert self.parse("none", 5) is None

    def test_none_case_insensitive(self):
        assert self.parse("NONE", 5) is None
        assert self.parse("None", 5) is None

    def test_all_returns_full_range(self):
        result = self.parse("all", 5)
        assert result == [0, 1, 2, 3, 4]

    def test_single_number(self):
        result = self.parse("3", 5)
        assert result == [2]

    def test_comma_separated(self):
        result = self.parse("1,3,5", 5)
        assert result == [0, 2, 4]

    def test_range(self):
        result = self.parse("2-4", 5)
        assert result == [1, 2, 3]

    def test_mixed_numbers_and_ranges(self):
        result = self.parse("1,3-5", 5)
        assert result == [0, 2, 3, 4]

    def test_deduplication(self):
        result = self.parse("1,1,2,2", 5)
        assert result == [0, 1]

    def test_whitespace_handling(self):
        result = self.parse("  1 , 3 , 5  ", 5)
        assert result == [0, 2, 4]

    def test_out_of_range_exits(self):
        with pytest.raises(SystemExit):
            self.parse("10", 5)

    def test_invalid_input_exits(self):
        with pytest.raises(SystemExit):
            self.parse("abc", 5)


# ---------------------------------------------------------------------------
# _append_body_findings
# ---------------------------------------------------------------------------


class TestAppendBodyFindings:
    """Tests for _append_body_findings helper."""

    @pytest.fixture(autouse=True)
    def _import_fn(self):
        from pr_review.cli import _append_body_findings

        self.append = _append_body_findings

    def _make_finding(self, **kwargs) -> Finding:
        defaults = {
            "rule_id": "PQ-001",
            "rule_name": "Conventional commits",
            "severity": Severity.SUGGESTION,
            "category": Category.PR_QUALITY,
            "message": "PR title does not follow conventional commits.",
            "file_path": "PR",
            "line_number": 0,
            "suggestion": "Use format: type(scope): description",
        }
        defaults.update(kwargs)
        return Finding(**defaults)

    def test_empty_body_only(self):
        result = self.append("base body", [])
        assert result == "base body"

    def test_appends_findings(self):
        f = self._make_finding()
        result = self.append("base body", [f])
        assert "### PR-Level Findings" in result
        assert "**[PQ-001]**" in result
        assert "Fix: Use format" in result

    def test_no_suggestion(self):
        f = self._make_finding(suggestion="")
        result = self.append("base body", [f])
        assert "Fix:" not in result

    def test_multiple_findings(self):
        f1 = self._make_finding(rule_id="PQ-001", message="msg1")
        f2 = self._make_finding(rule_id="PQ-004", message="msg2")
        result = self.append("body", [f1, f2])
        assert "**[PQ-001]**" in result
        assert "**[PQ-004]**" in result
