"""Tests for connector pattern and PR quality rules."""

import tempfile
import os
from pathlib import Path

from pr_review.diff_parser import ChangedFile, DiffHunk, DiffLine
from pr_review.file_classifier import (
    classify_file,
    classify_files,
    ClassifiedFile,
    FileType,
)
from pr_review.rules.connector_patterns import get_rules as get_connector_rules
from pr_review.rules.pr_quality import (
    PRTitleConventionalCommitRule,
    FileScopeRule,
    BranchNameRule,
    WIPInTitleRule,
    get_rules as get_pr_quality_rules,
)
from pr_review.rules.base import FileContentRule, CrossFileRule


# --- Helpers ---


def _make_classified_file(
    path: str,
    added_lines: list[tuple[int, str]] | None = None,
    *,
    is_new: bool = False,
) -> ClassifiedFile:
    diff_lines = [
        DiffLine(
            line_number=ln,
            content=content,
            is_added=True,
            is_removed=False,
            is_context=False,
        )
        for ln, content in (added_lines or [])
    ]
    hunk = DiffHunk(
        old_start=1,
        old_count=1,
        new_start=1,
        new_count=len(diff_lines),
        header="@@ -1 +1 @@",
        lines=diff_lines,
    )
    cf = ChangedFile(
        path=path,
        old_path=None,
        is_new=is_new,
        is_deleted=False,
        is_renamed=False,
        is_binary=False,
        hunks=[hunk] if diff_lines else [],
    )
    return classify_file(cf)


def _get_rule(rule_id: str):
    for r in get_connector_rules():
        if r.rule_id == rule_id:
            return r
    raise ValueError(f"Rule {rule_id} not found")


# --- Connector Pattern rules (FileContentRule) ---
# These need full file content on disk for FileContentRule checks.


class TestCP001_CreateAllPrerequisites:
    def test_detects_missing_macro(self):
        rule = _get_rule("CP-001")
        assert isinstance(rule, FileContentRule)

        # Create a temp file that simulates a connector without the macro
        with tempfile.TemporaryDirectory() as tmpdir:
            connector_dir = (
                Path(tmpdir) / "backend/connector-integration/src/connectors"
            )
            connector_dir.mkdir(parents=True)
            connector_file = connector_dir / "acme.rs"
            connector_file.write_text("impl ConnectorCommon for Acme {}\n")

            cf = _make_classified_file(
                "backend/connector-integration/src/connectors/acme.rs"
            )
            # Manually set path and use tmpdir as repo_root
            cf.changed_file.path = (
                "backend/connector-integration/src/connectors/acme.rs"
            )

            findings = rule.check(cf, tmpdir)
            assert len(findings) == 1
            assert findings[0].rule_id == "CP-001"

    def test_passes_with_macro(self):
        rule = _get_rule("CP-001")

        with tempfile.TemporaryDirectory() as tmpdir:
            connector_dir = (
                Path(tmpdir) / "backend/connector-integration/src/connectors"
            )
            connector_dir.mkdir(parents=True)
            connector_file = connector_dir / "acme.rs"
            connector_file.write_text(
                "macros::create_all_prerequisites!(\n    connector_name: Acme,\n)\n"
            )

            cf = _make_classified_file(
                "backend/connector-integration/src/connectors/acme.rs"
            )
            findings = rule.check(cf, tmpdir)
            assert len(findings) == 0


class TestCP003_ConnectorCommonTrait:
    def test_detects_missing_trait(self):
        rule = _get_rule("CP-003")

        with tempfile.TemporaryDirectory() as tmpdir:
            connector_dir = (
                Path(tmpdir) / "backend/connector-integration/src/connectors"
            )
            connector_dir.mkdir(parents=True)
            connector_file = connector_dir / "acme.rs"
            connector_file.write_text("create_all_prerequisites!()\n")

            cf = _make_classified_file(
                "backend/connector-integration/src/connectors/acme.rs"
            )
            findings = rule.check(cf, tmpdir)
            assert len(findings) == 1
            assert findings[0].rule_id == "CP-003"

    def test_passes_with_trait(self):
        rule = _get_rule("CP-003")

        with tempfile.TemporaryDirectory() as tmpdir:
            connector_dir = (
                Path(tmpdir) / "backend/connector-integration/src/connectors"
            )
            connector_dir.mkdir(parents=True)
            connector_file = connector_dir / "acme.rs"
            connector_file.write_text(
                "impl ConnectorCommon for Acme {\n"
                '    fn id(&self) -> &\'static str { "acme" }\n'
                '    fn base_url(&self) -> &str { "https://api.acme.com" }\n'
                "    fn get_currency_unit(&self) -> CurrencyUnit { CurrencyUnit::Minor }\n"
                "    fn get_auth_header(&self) -> Result<Vec<(String, Maskable<String>)>> { Ok(vec![]) }\n"
                "    fn build_error_response(&self, res: Response) -> RouterResult<ErrorResponse> { todo!() }\n"
                "}\n"
            )

            cf = _make_classified_file(
                "backend/connector-integration/src/connectors/acme.rs"
            )
            findings = rule.check(cf, tmpdir)
            assert len(findings) == 0

    def test_detects_missing_required_methods(self):
        """CP-003 should detect missing required methods in ConnectorCommon impl."""
        from pr_review.rules.connector_patterns import ConnectorCommonTraitRule

        rule = ConnectorCommonTraitRule(
            required_methods=["id", "base_url", "build_error_response"]
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            connector_dir = (
                Path(tmpdir) / "backend/connector-integration/src/connectors"
            )
            connector_dir.mkdir(parents=True)
            connector_file = connector_dir / "acme.rs"
            # Only implement id() -- missing base_url and build_error_response
            connector_file.write_text(
                "impl ConnectorCommon for Acme {\n"
                '    fn id(&self) -> &\'static str { "acme" }\n'
                "}\n"
            )

            cf = _make_classified_file(
                "backend/connector-integration/src/connectors/acme.rs"
            )
            findings = rule.check(cf, tmpdir)
            # Should have findings for missing base_url and build_error_response
            assert len(findings) == 2
            missing_methods = [f.message for f in findings]
            assert any("base_url" in m for m in missing_methods)
            assert any("build_error_response" in m for m in missing_methods)

    def test_no_findings_when_all_methods_present(self):
        """CP-003 should pass when all required methods are implemented."""
        from pr_review.rules.connector_patterns import ConnectorCommonTraitRule

        rule = ConnectorCommonTraitRule(required_methods=["id", "base_url"])

        with tempfile.TemporaryDirectory() as tmpdir:
            connector_dir = (
                Path(tmpdir) / "backend/connector-integration/src/connectors"
            )
            connector_dir.mkdir(parents=True)
            connector_file = connector_dir / "acme.rs"
            connector_file.write_text(
                "impl ConnectorCommon for Acme {\n"
                '    fn id(&self) -> &\'static str { "acme" }\n'
                '    fn base_url(&self) -> &str { "https://api.acme.com" }\n'
                "}\n"
            )

            cf = _make_classified_file(
                "backend/connector-integration/src/connectors/acme.rs"
            )
            findings = rule.check(cf, tmpdir)
            assert len(findings) == 0


class TestCP004_TransformerTryFrom:
    def test_detects_missing_tryfrom(self):
        rule = _get_rule("CP-004")

        with tempfile.TemporaryDirectory() as tmpdir:
            transformer_dir = (
                Path(tmpdir) / "backend/connector-integration/src/connectors/acme"
            )
            transformer_dir.mkdir(parents=True)
            transformer_file = transformer_dir / "transformers.rs"
            transformer_file.write_text(
                "pub struct AcmeRequest {\n    pub amount: i64,\n}\n"
            )

            cf = _make_classified_file(
                "backend/connector-integration/src/connectors/acme/transformers.rs"
            )
            findings = rule.check(cf, tmpdir)
            assert len(findings) == 1
            assert findings[0].rule_id == "CP-004"

    def test_passes_with_tryfrom(self):
        rule = _get_rule("CP-004")

        with tempfile.TemporaryDirectory() as tmpdir:
            transformer_dir = (
                Path(tmpdir) / "backend/connector-integration/src/connectors/acme"
            )
            transformer_dir.mkdir(parents=True)
            transformer_file = transformer_dir / "transformers.rs"
            transformer_file.write_text(
                "impl TryFrom<RouterDataV2<...>> for AcmeRequest {\n    type Error = ...;\n}\n"
            )

            cf = _make_classified_file(
                "backend/connector-integration/src/connectors/acme/transformers.rs"
            )
            findings = rule.check(cf, tmpdir)
            assert len(findings) == 0


class TestCP005_ErrorResponseStruct:
    def test_passes_with_learned_error_struct(self):
        """CP-005 should pass when transformer defines a struct matching learned patterns."""
        from pr_review.rules.connector_patterns import TransformerHasErrorResponseRule

        rule = TransformerHasErrorResponseRule(
            error_response_patterns=["AcmeFailureInfo", "AcmeGatewayError"]
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            transformer_dir = (
                Path(tmpdir) / "backend/connector-integration/src/connectors/acme"
            )
            transformer_dir.mkdir(parents=True)
            transformer_file = transformer_dir / "transformers.rs"
            # Struct name doesn't match hardcoded patterns but IS in learned data
            transformer_file.write_text(
                "pub struct AcmeRequest { pub amount: i64 }\n"
                "pub struct AcmeFailureInfo { pub code: String }\n"
            )

            cf = _make_classified_file(
                "backend/connector-integration/src/connectors/acme/transformers.rs"
            )
            findings = rule.check(cf, tmpdir)
            assert len(findings) == 0

    def test_fails_without_error_struct(self):
        """CP-005 should fire when no error struct is found at all."""
        from pr_review.rules.connector_patterns import TransformerHasErrorResponseRule

        rule = TransformerHasErrorResponseRule(
            error_response_patterns=["SomethingElse"]
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            transformer_dir = (
                Path(tmpdir) / "backend/connector-integration/src/connectors/acme"
            )
            transformer_dir.mkdir(parents=True)
            transformer_file = transformer_dir / "transformers.rs"
            transformer_file.write_text(
                "pub struct AcmeRequest { pub amount: i64 }\n"
                "pub struct AcmeResponse { pub status: String }\n"
            )

            cf = _make_classified_file(
                "backend/connector-integration/src/connectors/acme/transformers.rs"
            )
            findings = rule.check(cf, tmpdir)
            assert len(findings) == 1
            assert findings[0].rule_id == "CP-005"


# --- Cross-file rules ---


class TestCP006_FileStructure:
    def test_detects_missing_transformer(self):
        rule = _get_rule("CP-006")
        assert isinstance(rule, CrossFileRule)

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create connector file but no transformers file
            connector_dir = (
                Path(tmpdir) / "backend/connector-integration/src/connectors"
            )
            connector_dir.mkdir(parents=True)
            (connector_dir / "acme.rs").write_text("mod acme;")

            files = [
                _make_classified_file(
                    "backend/connector-integration/src/connectors/acme.rs"
                ),
            ]
            findings = rule.check_all(files, tmpdir)
            assert len(findings) == 1
            assert "transformers.rs" in findings[0].message

    def test_passes_when_both_exist(self):
        rule = _get_rule("CP-006")

        with tempfile.TemporaryDirectory() as tmpdir:
            connector_dir = (
                Path(tmpdir) / "backend/connector-integration/src/connectors"
            )
            connector_dir.mkdir(parents=True)
            (connector_dir / "acme.rs").write_text("mod acme;")
            acme_dir = connector_dir / "acme"
            acme_dir.mkdir()
            (acme_dir / "transformers.rs").write_text("mod transformers;")

            files = [
                _make_classified_file(
                    "backend/connector-integration/src/connectors/acme.rs"
                ),
            ]
            findings = rule.check_all(files, tmpdir)
            assert len(findings) == 0

    def test_passes_when_transformer_in_diff(self):
        """If both connector and transformer are in the diff, no finding."""
        rule = _get_rule("CP-006")

        with tempfile.TemporaryDirectory() as tmpdir:
            files = [
                _make_classified_file(
                    "backend/connector-integration/src/connectors/acme.rs"
                ),
                _make_classified_file(
                    "backend/connector-integration/src/connectors/acme/transformers.rs"
                ),
            ]
            findings = rule.check_all(files, tmpdir)
            assert len(findings) == 0


class TestCP007_SimilarNameDetection:
    def test_detects_similar_name(self):
        """CP-007 should flag a new connector with a name 1-char different from existing."""
        from pr_review.rules.connector_patterns import ConnectorRegistrationRule

        rule = ConnectorRegistrationRule(
            known_connectors=["stripe", "adyen", "braintree"]
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            connector_dir = (
                Path(tmpdir) / "backend/connector-integration/src/connectors"
            )
            connector_dir.mkdir(parents=True)
            # "strlpe" is 1 char different from "stripe" (same length, > 4 chars)
            (connector_dir / "strlpe.rs").write_text("mod strlpe;")

            # Also create connectors.rs and connector_types.rs so CP-007 can check registration
            connectors_rs = (
                Path(tmpdir) / "backend/connector-integration/src/connectors.rs"
            )
            connectors_rs.write_text("pub mod strlpe;")
            types_dir = Path(tmpdir) / "backend/domain_types/src"
            types_dir.mkdir(parents=True)
            (types_dir / "connector_types.rs").write_text("Strlpe,")

            files = [
                _make_classified_file(
                    "backend/connector-integration/src/connectors/strlpe.rs",
                    is_new=True,
                ),
            ]
            findings = rule.check_all(files, tmpdir)
            # Should have a similarity warning
            similarity_findings = [
                f for f in findings if "similar" in f.message.lower()
            ]
            assert len(similarity_findings) == 1
            assert "stripe" in similarity_findings[0].message

    def test_skips_versioned_connectors(self):
        """CP-007 should NOT flag versioned connectors like razorpayv2."""
        from pr_review.rules.connector_patterns import ConnectorRegistrationRule

        rule = ConnectorRegistrationRule(known_connectors=["razorpay"])

        with tempfile.TemporaryDirectory() as tmpdir:
            connector_dir = (
                Path(tmpdir) / "backend/connector-integration/src/connectors"
            )
            connector_dir.mkdir(parents=True)
            (connector_dir / "razorpayv2.rs").write_text("mod razorpayv2;")

            connectors_rs = (
                Path(tmpdir) / "backend/connector-integration/src/connectors.rs"
            )
            connectors_rs.write_text("pub mod razorpayv2;")
            types_dir = Path(tmpdir) / "backend/domain_types/src"
            types_dir.mkdir(parents=True)
            (types_dir / "connector_types.rs").write_text("Razorpayv2,")

            files = [
                _make_classified_file(
                    "backend/connector-integration/src/connectors/razorpayv2.rs",
                    is_new=True,
                ),
            ]
            findings = rule.check_all(files, tmpdir)
            # Should have NO similarity warnings (versioned is legitimate)
            similarity_findings = [
                f for f in findings if "similar" in f.message.lower()
            ]
            assert len(similarity_findings) == 0


# --- PR Quality Rules ---


class TestPQ001_ConventionalCommit:
    def test_valid_titles(self):
        rule = PRTitleConventionalCommitRule()
        valid = [
            "feat(connector): add Stripe integration",
            "fix: resolve payment timeout",
            "refactor(grpc): simplify error handling",
            "docs: update README",
            "test(stripe): add payment flow tests",
            "chore: bump dependencies",
            "ci: add pr-review step",
            "perf: optimize query",
            "feat!: breaking change",
        ]
        for title in valid:
            findings = rule.check_title(title)
            assert len(findings) == 0, f"Expected no findings for: {title}"

    def test_invalid_titles(self):
        rule = PRTitleConventionalCommitRule()
        invalid = [
            "Add new feature",
            "FEAT: uppercase type",
            "fix - missing colon",
            "fix:",  # too short description
            "fix: ab",  # description < 3 chars
            "",  # empty
        ]
        for title in invalid:
            findings = rule.check_title(title)
            assert len(findings) >= 1, f"Expected findings for: '{title}'"

    def test_empty_title(self):
        rule = PRTitleConventionalCommitRule()
        findings = rule.check_title("")
        assert len(findings) == 1
        assert "empty" in findings[0].message.lower()


class TestPQ002_FileScope:
    def test_under_threshold(self):
        rule = FileScopeRule(max_files=25)
        findings = rule.check_file_count(10)
        assert len(findings) == 0

    def test_over_threshold(self):
        rule = FileScopeRule(max_files=25)
        findings = rule.check_file_count(30)
        assert len(findings) == 1
        assert "30 files" in findings[0].message

    def test_at_threshold(self):
        rule = FileScopeRule(max_files=25)
        findings = rule.check_file_count(25)
        assert len(findings) == 0

    def test_custom_threshold(self):
        rule = FileScopeRule(max_files=5)
        findings = rule.check_file_count(6)
        assert len(findings) == 1


class TestPQ003_BranchName:
    def test_valid_branches(self):
        rule = BranchNameRule()
        valid = [
            "feat/add-stripe-connector",
            "fix/payment-timeout",
            "connector/adyen-refund",
            "hotfix/critical-fix",
            "chore/bump-deps",
        ]
        for branch in valid:
            findings = rule.check_branch_name(branch)
            assert len(findings) == 0, f"Expected no findings for: {branch}"

    def test_invalid_branches(self):
        rule = BranchNameRule()
        invalid = [
            "my-feature",
            "FEAT/uppercase",
            "feat/",  # no description
        ]
        for branch in invalid:
            findings = rule.check_branch_name(branch)
            assert len(findings) >= 1, f"Expected findings for: '{branch}'"

    def test_main_ignored(self):
        rule = BranchNameRule()
        for branch in ("main", "master", "develop"):
            findings = rule.check_branch_name(branch)
            assert len(findings) == 0


class TestPQ004_WIPInTitle:
    def test_detects_wip(self):
        rule = WIPInTitleRule()
        for title in [
            "WIP: adding feature",
            "feat: [DRAFT] work",
            "DO NOT MERGE: testing",
        ]:
            findings = rule.check_title(title)
            assert len(findings) >= 1, f"Expected WIP finding for: {title}"

    def test_no_wip(self):
        rule = WIPInTitleRule()
        findings = rule.check_title("feat(connector): add Stripe integration")
        assert len(findings) == 0


# --- Rule counts ---


class TestConnectorPatternRuleCounts:
    def test_rule_count(self):
        rules = get_connector_rules()
        assert len(rules) == 9
        ids = [r.rule_id for r in rules]
        for expected in [
            "CP-001",
            "CP-002",
            "CP-003",
            "CP-004",
            "CP-005",
            "CP-006",
            "CP-007",
            "CP-008",
            "CP-009",
        ]:
            assert expected in ids

    def test_cross_file_rules(self):
        rules = get_connector_rules()
        cross_file = [r for r in rules if isinstance(r, CrossFileRule)]
        assert len(cross_file) == 2  # CP-006 and CP-007

    def test_pr_quality_rule_count(self):
        rules = get_pr_quality_rules()
        assert len(rules) == 4
