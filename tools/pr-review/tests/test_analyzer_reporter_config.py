"""Tests for analyzer, reporter, and config modules."""

import json
import tempfile
from pathlib import Path

from pr_review.analyzer import (
    Analyzer,
    AnalysisResult,
    _is_finding_relevant_to_diff,
    _get_added_line_numbers,
    _get_added_line_contents,
)
from pr_review.diff_parser import ChangedFile, DiffHunk, DiffLine
from pr_review.reporter import (
    generate_terminal_report,
    generate_markdown_report,
    generate_json_report,
)
from pr_review.config import Config, RuleOverride
from pr_review.rules.base import Finding, Severity, Category
from pr_review.rules import get_all_rules


# --- AnalysisResult ---


class TestAnalysisResult:
    def test_empty_result(self):
        r = AnalysisResult()
        assert r.quality_score == 100
        assert r.total_findings == 0
        assert r.critical_count == 0
        assert r.warning_count == 0
        assert r.suggestion_count == 0
        assert r.is_passing
        assert "Excellent" in r.status

    def test_score_with_criticals(self):
        findings = [
            Finding(
                rule_id="TS-001",
                rule_name="test",
                severity=Severity.CRITICAL,
                category=Category.TYPE_SAFETY,
                message="msg",
                file_path="a.rs",
                line_number=1,
            ),
            Finding(
                rule_id="TS-002",
                rule_name="test2",
                severity=Severity.CRITICAL,
                category=Category.TYPE_SAFETY,
                message="msg2",
                file_path="b.rs",
                line_number=2,
            ),
        ]
        r = AnalysisResult(findings=findings)
        assert r.critical_count == 2
        assert r.quality_score == 100 - 2 * 20  # 60

    def test_score_with_mixed(self):
        findings = [
            Finding(
                rule_id="A",
                rule_name="",
                severity=Severity.CRITICAL,
                category=Category.TYPE_SAFETY,
                message="",
                file_path="a.rs",
                line_number=1,
            ),
            Finding(
                rule_id="B",
                rule_name="",
                severity=Severity.WARNING,
                category=Category.ARCHITECTURE,
                message="",
                file_path="a.rs",
                line_number=2,
            ),
            Finding(
                rule_id="C",
                rule_name="",
                severity=Severity.SUGGESTION,
                category=Category.SECURITY,
                message="",
                file_path="a.rs",
                line_number=3,
            ),
        ]
        r = AnalysisResult(findings=findings)
        # 100 - 20 - 5 - 1 = 74
        assert r.quality_score == 74

    def test_score_floor_at_zero(self):
        findings = [
            Finding(
                rule_id=f"X{i}",
                rule_name="",
                severity=Severity.CRITICAL,
                category=Category.TYPE_SAFETY,
                message="",
                file_path="a.rs",
                line_number=i,
            )
            for i in range(10)
        ]
        r = AnalysisResult(findings=findings)
        # 100 - 10*20 = -100, floored to 0
        assert r.quality_score == 0

    def test_status_levels(self):
        # Excellent: 95-100
        assert "Excellent" in AnalysisResult(findings=[]).status
        # Good: 80-94
        findings_1w = [
            Finding(
                rule_id="W",
                rule_name="",
                severity=Severity.WARNING,
                category=Category.TYPE_SAFETY,
                message="",
                file_path="a.rs",
                line_number=1,
            )
        ]
        r = AnalysisResult(findings=findings_1w)
        assert r.quality_score == 95
        assert "Excellent" in r.status

        # 2 warnings = 90 -> Good
        findings_2w = findings_1w * 2
        r2 = AnalysisResult(findings=findings_2w)
        assert r2.quality_score == 90
        assert "Good" in r2.status

    def test_is_passing_threshold(self):
        # Score 60 should pass
        findings = [
            Finding(
                rule_id="C",
                rule_name="",
                severity=Severity.CRITICAL,
                category=Category.TYPE_SAFETY,
                message="",
                file_path="a.rs",
                line_number=1,
            ),
            Finding(
                rule_id="C2",
                rule_name="",
                severity=Severity.CRITICAL,
                category=Category.TYPE_SAFETY,
                message="",
                file_path="a.rs",
                line_number=2,
            ),
        ]
        r = AnalysisResult(findings=findings)
        assert r.quality_score == 60
        assert r.is_passing

        # Score 59 should not pass
        findings.append(
            Finding(
                rule_id="S",
                rule_name="",
                severity=Severity.SUGGESTION,
                category=Category.TYPE_SAFETY,
                message="",
                file_path="a.rs",
                line_number=3,
            ),
        )
        r2 = AnalysisResult(findings=findings)
        assert r2.quality_score == 59
        assert not r2.is_passing

    def test_findings_by_severity(self):
        findings = [
            Finding(
                rule_id="C",
                rule_name="",
                severity=Severity.CRITICAL,
                category=Category.TYPE_SAFETY,
                message="",
                file_path="a.rs",
                line_number=1,
            ),
            Finding(
                rule_id="W",
                rule_name="",
                severity=Severity.WARNING,
                category=Category.TYPE_SAFETY,
                message="",
                file_path="a.rs",
                line_number=2,
            ),
        ]
        r = AnalysisResult(findings=findings)
        by_sev = r.findings_by_severity()
        assert len(by_sev[Severity.CRITICAL]) == 1
        assert len(by_sev[Severity.WARNING]) == 1
        assert len(by_sev[Severity.SUGGESTION]) == 0

    def test_findings_by_category(self):
        findings = [
            Finding(
                rule_id="C",
                rule_name="",
                severity=Severity.CRITICAL,
                category=Category.TYPE_SAFETY,
                message="",
                file_path="a.rs",
                line_number=1,
            ),
            Finding(
                rule_id="A",
                rule_name="",
                severity=Severity.WARNING,
                category=Category.ARCHITECTURE,
                message="",
                file_path="a.rs",
                line_number=2,
            ),
        ]
        r = AnalysisResult(findings=findings)
        by_cat = r.findings_by_category()
        assert len(by_cat[Category.TYPE_SAFETY]) == 1
        assert len(by_cat[Category.ARCHITECTURE]) == 1
        assert len(by_cat[Category.SECURITY]) == 0

    def test_findings_by_file(self):
        findings = [
            Finding(
                rule_id="C",
                rule_name="",
                severity=Severity.CRITICAL,
                category=Category.TYPE_SAFETY,
                message="",
                file_path="a.rs",
                line_number=1,
            ),
            Finding(
                rule_id="C2",
                rule_name="",
                severity=Severity.CRITICAL,
                category=Category.TYPE_SAFETY,
                message="",
                file_path="a.rs",
                line_number=2,
            ),
            Finding(
                rule_id="W",
                rule_name="",
                severity=Severity.WARNING,
                category=Category.TYPE_SAFETY,
                message="",
                file_path="b.rs",
                line_number=1,
            ),
        ]
        r = AnalysisResult(findings=findings)
        by_file = r.findings_by_file()
        assert len(by_file["a.rs"]) == 2
        assert len(by_file["b.rs"]) == 1


# --- Analyzer ---


class TestAnalyzer:
    def test_analyze_empty_diff(self):
        analyzer = Analyzer(repo_root="/fake")
        result = analyzer.analyze_diff("")
        assert result.total_findings == 0
        assert result.files_analyzed == 0

    def test_analyze_with_findings(self):
        diff = (
            "diff --git a/backend/connector-integration/src/connectors/acme.rs b/backend/connector-integration/src/connectors/acme.rs\n"
            "--- a/backend/connector-integration/src/connectors/acme.rs\n"
            "+++ b/backend/connector-integration/src/connectors/acme.rs\n"
            "@@ -10,3 +10,4 @@ fn process() {\n"
            "     let x = 1;\n"
            "+    let y = val.unwrap();\n"
            '+    println!("debug");\n'
            "     let z = 2;\n"
        )
        analyzer = Analyzer(repo_root="/fake", pr_title="feat(connector): add Acme")
        result = analyzer.analyze_diff(diff)
        assert result.files_analyzed == 1
        assert result.total_findings > 0
        # Should have at least TS-001 (unwrap) and TS-007 (println)
        rule_ids = [f.rule_id for f in result.findings]
        assert "TS-001" in rule_ids
        assert "TS-007" in rule_ids

    def test_analyzer_uses_pr_title(self):
        diff = (
            "diff --git a/README.md b/README.md\n"
            "--- a/README.md\n"
            "+++ b/README.md\n"
            "@@ -1 +1 @@\n"
            "-old\n"
            "+new\n"
        )
        analyzer = Analyzer(repo_root="/fake", pr_title="bad title no conventional")
        result = analyzer.analyze_diff(diff)
        rule_ids = [f.rule_id for f in result.findings]
        assert "PQ-001" in rule_ids

    def test_connector_names_detected(self):
        diff = (
            "diff --git a/backend/connector-integration/src/connectors/stripe.rs b/backend/connector-integration/src/connectors/stripe.rs\n"
            "--- a/backend/connector-integration/src/connectors/stripe.rs\n"
            "+++ b/backend/connector-integration/src/connectors/stripe.rs\n"
            "@@ -1 +1 @@\n"
            "-old\n"
            "+new\n"
        )
        analyzer = Analyzer(
            repo_root="/fake", pr_title="feat(connector): update stripe"
        )
        result = analyzer.analyze_diff(diff)
        assert "stripe" in result.connector_names

    def test_findings_sorted_by_severity(self):
        diff = (
            "diff --git a/backend/connector-integration/src/connectors/acme.rs b/backend/connector-integration/src/connectors/acme.rs\n"
            "--- a/backend/connector-integration/src/connectors/acme.rs\n"
            "+++ b/backend/connector-integration/src/connectors/acme.rs\n"
            "@@ -1,2 +1,3 @@\n"
            "+    let y = val.unwrap();\n"
            '+    println!("debug");\n'
            " existing\n"
        )
        analyzer = Analyzer(repo_root="/fake", pr_title="feat: test")
        result = analyzer.analyze_diff(diff)
        if len(result.findings) >= 2:
            sev_order = {"critical": 0, "warning": 1, "suggestion": 2}
            for i in range(len(result.findings) - 1):
                assert (
                    sev_order[result.findings[i].severity.value]
                    <= sev_order[result.findings[i + 1].severity.value]
                )


# --- Reporter ---


class TestTerminalReporter:
    def test_empty_report(self):
        r = AnalysisResult()
        report = generate_terminal_report(r)
        assert "100/100" in report
        assert "No issues found" in report

    def test_report_with_findings(self):
        findings = [
            Finding(
                rule_id="TS-001",
                rule_name="No unwrap()",
                severity=Severity.CRITICAL,
                category=Category.TYPE_SAFETY,
                message="unwrap detected",
                file_path="src/main.rs",
                line_number=10,
                line_content="val.unwrap()",
                suggestion="Use ? operator",
            ),
        ]
        r = AnalysisResult(findings=findings, files_analyzed=1, rules_applied=9)
        report = generate_terminal_report(r)
        assert "TS-001" in report
        assert "unwrap" in report
        assert "CRITICAL" in report


class TestMarkdownReporter:
    def test_empty_report(self):
        r = AnalysisResult()
        report = generate_markdown_report(r)
        assert "# PR Review Report" in report
        assert "100/100" in report
        assert "No issues found" in report

    def test_report_with_findings(self):
        findings = [
            Finding(
                rule_id="TS-001",
                rule_name="No unwrap()",
                severity=Severity.CRITICAL,
                category=Category.TYPE_SAFETY,
                message="unwrap detected",
                file_path="src/main.rs",
                line_number=10,
                line_content="val.unwrap()",
                suggestion="Use ? operator",
                context="Clippy forbids this.",
            ),
        ]
        r = AnalysisResult(findings=findings, files_analyzed=1, rules_applied=9)
        report = generate_markdown_report(r)
        assert "## Critical Issues" in report
        assert "TS-001" in report
        assert "```rust" in report
        assert "**Fix:**" in report


class TestJsonReporter:
    def test_empty_report(self):
        r = AnalysisResult()
        report = generate_json_report(r)
        data = json.loads(report)
        assert data["quality_score"] == 100
        assert data["is_passing"]
        assert data["findings"] == []

    def test_report_structure(self):
        findings = [
            Finding(
                rule_id="TS-001",
                rule_name="No unwrap()",
                severity=Severity.CRITICAL,
                category=Category.TYPE_SAFETY,
                message="unwrap detected",
                file_path="src/main.rs",
                line_number=10,
            ),
        ]
        r = AnalysisResult(
            findings=findings,
            files_analyzed=1,
            rules_applied=9,
            connector_names={"stripe"},
        )
        report = generate_json_report(r)
        data = json.loads(report)
        assert data["quality_score"] == 80
        assert data["summary"]["critical_count"] == 1
        assert data["summary"]["connector_names"] == ["stripe"]
        assert len(data["findings"]) == 1
        f = data["findings"][0]
        assert f["rule_id"] == "TS-001"
        assert f["severity"] == "critical"
        assert f["location"] == "src/main.rs:10"


# --- Config ---


class TestConfig:
    def test_default_config(self):
        config = Config()
        assert config.fail_under == 60
        assert config.max_file_count == 25
        assert config.rule_overrides == {}
        assert config.ignore_patterns == []

    def test_load_nonexistent_returns_default(self):
        config = Config.load("/nonexistent/path/config.toml")
        assert config.fail_under == 60

    def test_load_from_toml(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write("""
fail_under = 80
max_file_count = 30

[ignore]
patterns = ["sdk/**", "*.md"]

[rules.TS-006]
severity = "suggestion"

[rules.TS-009]
enabled = false
""")
            f.flush()
            config = Config.load(f.name)

        assert config.fail_under == 80
        assert config.max_file_count == 30
        assert "sdk/**" in config.ignore_patterns
        assert "*.md" in config.ignore_patterns
        assert "TS-006" in config.rule_overrides
        assert config.rule_overrides["TS-006"].severity == Severity.SUGGESTION
        assert "TS-009" in config.rule_overrides
        assert not config.rule_overrides["TS-009"].enabled

        import os

        os.unlink(f.name)

    def test_apply_to_rules_disables(self):
        config = Config()
        config.rule_overrides["TS-001"] = RuleOverride(enabled=False)

        rules = get_all_rules()
        original_count = len(rules)
        filtered = config.apply_to_rules(rules)
        assert len(filtered) == original_count - 1
        assert all(r.rule_id != "TS-001" for r in filtered)

    def test_apply_to_rules_overrides_severity(self):
        config = Config()
        config.rule_overrides["TS-006"] = RuleOverride(severity=Severity.SUGGESTION)

        rules = get_all_rules()
        filtered = config.apply_to_rules(rules)
        ts006 = next(r for r in filtered if r.rule_id == "TS-006")
        assert ts006.severity == Severity.SUGGESTION

    def test_apply_to_rules_does_not_mutate_originals(self):
        """Severity override must not modify the original rule object."""
        rules = get_all_rules()
        ts006_original = next(r for r in rules if r.rule_id == "TS-006")
        original_severity = ts006_original.severity

        # Override to a DIFFERENT severity than the original
        override_severity = (
            Severity.CRITICAL
            if original_severity != Severity.CRITICAL
            else Severity.WARNING
        )
        config = Config()
        config.rule_overrides["TS-006"] = RuleOverride(severity=override_severity)
        filtered = config.apply_to_rules(rules)

        # The returned rule has the overridden severity
        ts006_filtered = next(r for r in filtered if r.rule_id == "TS-006")
        assert ts006_filtered.severity == override_severity

        # But the original rule object is untouched
        assert ts006_original.severity == original_severity

    def test_should_ignore_file(self):
        config = Config()
        config.ignore_patterns = ["sdk/**", "*.md"]
        assert config.should_ignore_file("sdk/python/client.py")
        assert config.should_ignore_file("README.md")
        assert not config.should_ignore_file("backend/src/main.rs")


# --- Diff Filtering for FileContentRule ---


def _make_changed_file(
    path: str = "test.rs",
    is_new: bool = False,
    is_deleted: bool = False,
    added_lines: list[tuple[int, str]] | None = None,
) -> ChangedFile:
    """Helper to create a ChangedFile with specific added lines."""
    hunks = []
    if added_lines:
        diff_lines = [
            DiffLine(
                line_number=ln,
                content=content,
                is_added=True,
                is_removed=False,
                is_context=False,
            )
            for ln, content in added_lines
        ]
        hunks.append(
            DiffHunk(
                old_start=1,
                old_count=0,
                new_start=1,
                new_count=len(diff_lines),
                header="@@ -1,0 +1,{} @@".format(len(diff_lines)),
                lines=diff_lines,
            )
        )
    return ChangedFile(
        path=path,
        old_path=None,
        is_new=is_new,
        is_deleted=is_deleted,
        is_renamed=False,
        is_binary=False,
        hunks=hunks,
    )


def _make_finding(
    line_number: int = 1,
    message: str = "test issue",
    file_path: str = "test.rs",
) -> Finding:
    """Helper to create a Finding."""
    return Finding(
        rule_id="TEST-001",
        rule_name="Test Rule",
        severity=Severity.WARNING,
        category=Category.ARCHITECTURE,
        message=message,
        file_path=file_path,
        line_number=line_number,
    )


class TestGetAddedLineNumbers:
    def test_empty_file(self):
        cf = _make_changed_file()
        assert _get_added_line_numbers(cf) == set()

    def test_with_added_lines(self):
        cf = _make_changed_file(
            added_lines=[(10, "line10"), (20, "line20"), (30, "line30")]
        )
        assert _get_added_line_numbers(cf) == {10, 20, 30}


class TestGetAddedLineContents:
    def test_empty_file(self):
        cf = _make_changed_file()
        assert _get_added_line_contents(cf) == ""

    def test_with_added_lines(self):
        cf = _make_changed_file(added_lines=[(10, "hello"), (20, "world")])
        result = _get_added_line_contents(cf)
        assert "hello" in result
        assert "world" in result

    def test_excludes_use_import_lines(self):
        """Import lines (use ...) are excluded from the added text
        to prevent identifier matching on boilerplate imports."""
        cf = _make_changed_file(
            added_lines=[
                (1, "use grpc_api_types::payments::{CompositeAuthorizeRequest};"),
                (5, "    let payload = request.into_parts();"),
            ]
        )
        result = _get_added_line_contents(cf)
        assert "CompositeAuthorizeRequest" not in result
        assert "payload" in result


class TestIsFindingRelevantToDiff:
    """Tests for the diff-scoping logic that prevents false positives."""

    # --- Line-specific findings (line_number > 1) ---

    def test_line_specific_finding_on_added_line_is_kept(self):
        cf = _make_changed_file(added_lines=[(10, "some code")])
        finding = _make_finding(line_number=10)
        assert _is_finding_relevant_to_diff(finding, cf) is True

    def test_line_specific_finding_not_on_added_line_is_filtered(self):
        cf = _make_changed_file(added_lines=[(10, "some code")])
        finding = _make_finding(line_number=50)
        assert _is_finding_relevant_to_diff(finding, cf) is False

    def test_line_specific_finding_with_no_added_lines_is_filtered(self):
        cf = _make_changed_file()
        finding = _make_finding(line_number=10)
        assert _is_finding_relevant_to_diff(finding, cf) is False

    # --- File-level findings (line_number <= 1) on NEW files ---

    def test_file_level_finding_on_new_file_is_kept(self):
        cf = _make_changed_file(is_new=True)
        finding = _make_finding(line_number=1)
        assert _is_finding_relevant_to_diff(finding, cf) is True

    def test_file_level_finding_on_new_file_line_zero_is_kept(self):
        cf = _make_changed_file(is_new=True)
        finding = _make_finding(line_number=0)
        assert _is_finding_relevant_to_diff(finding, cf) is True

    # --- File-level findings on EXISTING files with identifier matching ---

    def test_file_level_finding_with_matching_identifier_in_added_lines(self):
        """CS-002 scenario: message mentions CompositeVoidRequest, and the
        type name appears in an added line."""
        cf = _make_changed_file(
            added_lines=[
                (5, "    request: tonic::Request<CompositeVoidRequest>,"),
                (6, ") -> Result<Response<CompositeVoidResponse>, Status> {"),
            ]
        )
        finding = _make_finding(
            line_number=1,
            message="`CompositeVoidRequest` is missing `CompositeAccessTokenRequest` trait implementation.",
        )
        assert _is_finding_relevant_to_diff(finding, cf) is True

    def test_file_level_finding_with_no_matching_identifier_in_added_lines(self):
        """CS-002 scenario: message mentions CompositeAuthorizeRequest, but
        the type name does NOT appear in any added line (pre-existing)."""
        cf = _make_changed_file(
            added_lines=[
                (5, "    request: tonic::Request<CompositeVoidRequest>,"),
            ]
        )
        finding = _make_finding(
            line_number=1,
            message="`CompositeAuthorizeRequest` is missing `CompositeAccessTokenRequest` trait implementation.",
        )
        assert _is_finding_relevant_to_diff(finding, cf) is False

    def test_file_level_finding_with_no_identifiers_and_added_lines_is_kept(self):
        """Conservative fallback: no backtick identifiers in message,
        but file has added lines — keep the finding."""
        cf = _make_changed_file(added_lines=[(5, "some code")])
        finding = _make_finding(
            line_number=1,
            message="File is missing something important.",
        )
        assert _is_finding_relevant_to_diff(finding, cf) is True

    def test_file_level_finding_with_no_added_lines_is_filtered(self):
        """File has no added lines — suppress all file-level findings."""
        cf = _make_changed_file()  # no added lines, not new
        finding = _make_finding(line_number=1, message="Missing `something`.")
        assert _is_finding_relevant_to_diff(finding, cf) is False

    # --- PT-003 scenario: sensitive field found on specific line ---

    def test_sensitive_field_on_added_line_is_kept(self):
        """PT-003: session_token found on line 48, and line 48 IS added."""
        cf = _make_changed_file(added_lines=[(48, "  string session_token = 5;")])
        finding = _make_finding(
            line_number=48,
            message="Sensitive field `session_token` uses `string` instead of `SecretString`.",
        )
        assert _is_finding_relevant_to_diff(finding, cf) is True

    def test_sensitive_field_on_preexisting_line_is_filtered(self):
        """PT-003: session_token found on line 48, but line 48 is NOT in the diff."""
        cf = _make_changed_file(added_lines=[(100, "  string new_field = 10;")])
        finding = _make_finding(
            line_number=48,
            message="Sensitive field `session_token` uses `string` instead of `SecretString`.",
        )
        assert _is_finding_relevant_to_diff(finding, cf) is False

    # --- GR-002 scenario: method missing tracing::instrument ---

    def test_grpc_method_finding_on_added_method_is_kept(self):
        """GR-002: new method on line 50, which IS an added line."""
        cf = _make_changed_file(
            added_lines=[
                (50, "    async fn void("),
                (51, "        &self,"),
                (52, "        request: tonic::Request<VoidRequest>,"),
            ]
        )
        finding = _make_finding(
            line_number=50,
            message="gRPC service method `void` is missing `#[tracing::instrument]`.",
        )
        assert _is_finding_relevant_to_diff(finding, cf) is True

    def test_grpc_method_finding_on_existing_method_is_filtered(self):
        """GR-002: existing method on line 10, not in the diff."""
        cf = _make_changed_file(added_lines=[(50, "    async fn void(")])
        finding = _make_finding(
            line_number=10,
            message="gRPC service method `authorize` is missing `#[tracing::instrument]`.",
        )
        assert _is_finding_relevant_to_diff(finding, cf) is False

    # --- Multiple identifiers in message ---

    def test_multiple_identifiers_first_match_keeps_finding(self):
        """Only the FIRST backtick-quoted identifier (the primary subject)
        is checked against added lines."""
        cf = _make_changed_file(
            added_lines=[
                (5, "    request: tonic::Request<CompositeVoidRequest>,"),
            ]
        )
        finding = _make_finding(
            line_number=1,
            message="`CompositeVoidRequest` is missing `CompositeAccessTokenRequest` trait.",
        )
        # First identifier "CompositeVoidRequest" is in the added line — should match
        assert _is_finding_relevant_to_diff(finding, cf) is True

    def test_multiple_identifiers_only_second_matches_filters(self):
        """If only a non-first identifier matches, the finding is filtered.
        This prevents false positives from trait names that appear in
        unrelated added lines."""
        cf = _make_changed_file(
            added_lines=[
                (67, "impl CompositeAccessTokenRequest for CompositeVoidRequest {"),
            ]
        )
        finding = _make_finding(
            line_number=1,
            message="`CompositeAuthorizeRequest` is missing `CompositeAccessTokenRequest` trait.",
        )
        # First identifier "CompositeAuthorizeRequest" is NOT in added lines;
        # only the second one "CompositeAccessTokenRequest" matches — should filter
        assert _is_finding_relevant_to_diff(finding, cf) is False

    def test_no_composite_identifiers_in_added_lines_filters(self):
        """Neither composite identifier appears in added lines — filter out."""
        cf = _make_changed_file(added_lines=[(5, "let x = 42;")])
        finding = _make_finding(
            line_number=1,
            message="`CompositeAuthorizeRequest` is missing `CompositeAccessTokenRequest` trait.",
        )
        # Neither identifier is in "let x = 42;" — should filter
        assert _is_finding_relevant_to_diff(finding, cf) is False

    def test_identifier_found_in_added_line_keeps(self):
        """First backtick identifier appears in an added line — keep."""
        cf = _make_changed_file(
            added_lines=[
                (
                    10,
                    "    let resp: ConnectorErrorResponse = serde_json::from_str(&body)?;",
                )
            ]
        )
        finding = _make_finding(
            line_number=0,
            message="`ConnectorErrorResponse` not found in transformer.",
        )
        # "ConnectorErrorResponse" IS in the added line — match
        assert _is_finding_relevant_to_diff(finding, cf) is True

    def test_only_foreign_from_in_added_line_filters(self):
        """Only the second identifier (ForeignFrom) appears; first doesn't — filter."""
        cf = _make_changed_file(added_lines=[(10, "    ForeignFrom<Foo> for Bar {")])
        finding = _make_finding(
            line_number=0,
            message="Using `impl From<>` instead of `ForeignFrom<>` for type conversion.",
        )
        # First identifier "impl From<>" NOT in added line — filter
        assert _is_finding_relevant_to_diff(finding, cf) is False

    def test_no_impl_from_identifiers_in_added_lines_filters(self):
        """Neither impl From<> nor ForeignFrom<> in added lines — filter out."""
        cf = _make_changed_file(added_lines=[(5, "let x = 42;")])
        finding = _make_finding(
            line_number=0,
            message="Using `impl From<>` instead of `ForeignFrom<>` for type conversion.",
        )
        assert _is_finding_relevant_to_diff(finding, cf) is False


class TestAnalyzerDiffFiltering:
    """Integration tests: verify the Analyzer filters FileContentRule findings."""

    def test_proto_sensitive_field_on_preexisting_line_not_reported(self):
        """Simulate PR #624 scenario: proto file is touched but the sensitive
        field `session_token` is on a pre-existing line, not in the diff."""
        diff = (
            "diff --git a/backend/grpc-api-types/proto/composite_payment.proto b/backend/grpc-api-types/proto/composite_payment.proto\n"
            "--- a/backend/grpc-api-types/proto/composite_payment.proto\n"
            "+++ b/backend/grpc-api-types/proto/composite_payment.proto\n"
            "@@ -120,3 +120,8 @@ message CompositeAuthorizeRequest {\n"
            "   string existing_field = 1;\n"
            "+  // New message for void flow\n"
            "+  message CompositeVoidRequest {\n"
            "+    string order_id = 1;\n"
            "+    string merchant_id = 2;\n"
            "+  }\n"
        )
        # Note: session_token is on line 48 in the full file, which is NOT
        # in the diff above (diff starts at line 120). The rule would find
        # it in the full file content, but the analyzer should filter it out.
        analyzer = Analyzer(
            repo_root="/fake",
            pr_title="feat(composite): add void flow",
        )
        result = analyzer.analyze_diff(diff)

        # No PT-003 findings should appear because line 48 is not added
        pt003_findings = [f for f in result.findings if f.rule_id == "PT-003"]
        assert len(pt003_findings) == 0


# --- get_all_rules ---


class TestGetAllRules:
    def test_returns_all_rules(self):
        rules = get_all_rules()
        # 9 + 6 + 6 + 5 + 9 + 5 + 4 + 4 + 6 + 5 + 4 = 63 rules
        assert len(rules) == 63

    def test_unique_rule_ids(self):
        rules = get_all_rules()
        ids = [r.rule_id for r in rules]
        assert len(ids) == len(set(ids)), (
            f"Duplicate rule IDs: {[x for x in ids if ids.count(x) > 1]}"
        )

    def test_all_categories_covered(self):
        rules = get_all_rules()
        categories = {r.category for r in rules}
        for cat in Category:
            assert cat in categories, f"Category {cat} has no rules"
