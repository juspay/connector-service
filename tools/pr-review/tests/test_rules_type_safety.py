"""Tests for the rules base classes and type safety rules."""

from pr_review.diff_parser import ChangedFile, DiffHunk, DiffLine
from pr_review.file_classifier import classify_file, ClassifiedFile, FileType
from pr_review.rules.base import (
    Severity,
    Category,
    Finding,
    RegexLineRule,
    RuleRegistry,
)
from pr_review.rules.type_safety import get_rules as get_type_safety_rules


# --- Helpers ---


def _make_classified_file(
    path: str,
    added_lines: list[tuple[int, str]],
    *,
    is_new: bool = False,
    is_deleted: bool = False,
) -> ClassifiedFile:
    """Create a ClassifiedFile with specific added lines for testing rules."""
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
        is_deleted=is_deleted,
        is_renamed=False,
        is_binary=False,
        hunks=[hunk],
    )
    return classify_file(cf)


def _connector_file(added_lines: list[tuple[int, str]], **kwargs) -> ClassifiedFile:
    return _make_classified_file(
        "backend/connector-integration/src/connectors/stripe.rs",
        added_lines,
        **kwargs,
    )


def _transformer_file(added_lines: list[tuple[int, str]], **kwargs) -> ClassifiedFile:
    return _make_classified_file(
        "backend/connector-integration/src/connectors/stripe/transformers.rs",
        added_lines,
        **kwargs,
    )


def _get_rule(rule_id: str):
    """Get a specific rule by ID from type safety rules."""
    for rule in get_type_safety_rules():
        if rule.rule_id == rule_id:
            return rule
    raise ValueError(f"Rule {rule_id} not found")


# --- Severity ---


class TestSeverity:
    def test_score_penalties(self):
        assert Severity.CRITICAL.score_penalty == 20
        assert Severity.WARNING.score_penalty == 5
        assert Severity.SUGGESTION.score_penalty == 1

    def test_icons(self):
        assert Severity.CRITICAL.icon == "!!"
        assert Severity.WARNING.icon == "!"
        assert Severity.SUGGESTION.icon == "*"


# --- Finding ---


class TestFinding:
    def test_location_with_line(self):
        f = Finding(
            rule_id="TS-001",
            rule_name="test",
            severity=Severity.CRITICAL,
            category=Category.TYPE_SAFETY,
            message="msg",
            file_path="src/main.rs",
            line_number=42,
        )
        assert f.location == "src/main.rs:42"

    def test_location_without_line(self):
        f = Finding(
            rule_id="TS-001",
            rule_name="test",
            severity=Severity.CRITICAL,
            category=Category.TYPE_SAFETY,
            message="msg",
            file_path="src/main.rs",
            line_number=0,
        )
        assert f.location == "src/main.rs"


# --- RuleRegistry ---


class TestRuleRegistry:
    def test_register_and_count(self):
        registry = RuleRegistry()
        rules = get_type_safety_rules()
        registry.register_all(rules)
        assert registry.count() == len(rules)

    def test_per_file_rules(self):
        registry = RuleRegistry()
        rules = get_type_safety_rules()
        registry.register_all(rules)
        # All type safety rules are RegexLineRules, not CrossFileRules
        assert len(registry.per_file_rules) == len(rules)
        assert len(registry.cross_file_rules) == 0


# --- Type Safety Rules ---


class TestTS001_Unwrap:
    def test_detects_unwrap(self):
        rule = _get_rule("TS-001")
        cf = _connector_file([(10, "    let x = val.unwrap();")])
        findings = rule.check(cf, "/fake/root")
        assert len(findings) == 1
        assert findings[0].rule_id == "TS-001"
        assert findings[0].line_number == 10

    def test_ignores_comment(self):
        rule = _get_rule("TS-001")
        cf = _connector_file([(10, "    // val.unwrap()")])
        findings = rule.check(cf, "/fake/root")
        assert len(findings) == 0

    def test_ignores_block_comment(self):
        rule = _get_rule("TS-001")
        cf = _connector_file([(10, "    * val.unwrap()")])
        findings = rule.check(cf, "/fake/root")
        assert len(findings) == 0

    def test_ignores_allow_attribute(self):
        rule = _get_rule("TS-001")
        cf = _connector_file([(10, "    #[allow(clippy::unwrap_used)] val.unwrap()")])
        findings = rule.check(cf, "/fake/root")
        assert len(findings) == 0

    def test_skips_deleted_files(self):
        rule = _get_rule("TS-001")
        cf = _connector_file([(10, "    val.unwrap()")], is_deleted=True)
        findings = rule.check(cf, "/fake/root")
        assert len(findings) == 0

    def test_skips_non_rust_files(self):
        rule = _get_rule("TS-001")
        cf = _make_classified_file("README.md", [(10, "val.unwrap()")])
        findings = rule.check(cf, "/fake/root")
        assert len(findings) == 0

    def test_skips_test_files(self):
        rule = _get_rule("TS-001")
        cf = _make_classified_file(
            "backend/grpc-server/tests/stripe_test.rs",
            [(10, "    val.unwrap()")],
        )
        findings = rule.check(cf, "/fake/root")
        assert len(findings) == 0


class TestTS002_Expect:
    def test_detects_expect(self):
        rule = _get_rule("TS-002")
        cf = _connector_file([(5, '    let x = val.expect("should work");')])
        findings = rule.check(cf, "/fake/root")
        assert len(findings) == 1
        assert findings[0].rule_id == "TS-002"

    def test_ignores_comment(self):
        rule = _get_rule("TS-002")
        cf = _connector_file([(5, '    // val.expect("x")')])
        findings = rule.check(cf, "/fake/root")
        assert len(findings) == 0


class TestTS003_Panic:
    def test_detects_panic(self):
        rule = _get_rule("TS-003")
        cf = _connector_file([(5, '    panic!("oh no");')])
        findings = rule.check(cf, "/fake/root")
        assert len(findings) == 1

    def test_no_false_positive_on_should_panic(self):
        rule = _get_rule("TS-003")
        cf = _connector_file([(5, "    // #[should_panic] is fine")])
        findings = rule.check(cf, "/fake/root")
        assert len(findings) == 0


class TestTS004_Todo:
    def test_detects_todo(self):
        rule = _get_rule("TS-004")
        cf = _connector_file([(5, '    todo!("implement later");')])
        findings = rule.check(cf, "/fake/root")
        assert len(findings) == 1

    def test_detects_unimplemented(self):
        rule = _get_rule("TS-004")
        cf = _connector_file([(5, '    unimplemented!("not yet");')])
        findings = rule.check(cf, "/fake/root")
        assert len(findings) == 1


class TestTS005_Unsafe:
    def test_detects_unsafe_block(self):
        rule = _get_rule("TS-005")
        cf = _connector_file([(5, "    unsafe { ptr.read() }")])
        findings = rule.check(cf, "/fake/root")
        assert len(findings) == 1

    def test_not_excluded_in_tests(self):
        """Unsafe is forbidden everywhere, including test files."""
        rule = _get_rule("TS-005")
        cf = _make_classified_file(
            "backend/grpc-server/tests/stripe_test.rs",
            [(5, "    unsafe { ptr.read() }")],
        )
        findings = rule.check(cf, "/fake/root")
        assert len(findings) == 1


class TestTS006_AsCast:
    def test_detects_numeric_as_cast(self):
        rule = _get_rule("TS-006")
        cf = _connector_file([(5, "    let x = val as u32;")])
        findings = rule.check(cf, "/fake/root")
        assert len(findings) == 1

    def test_ignores_non_numeric_cast(self):
        rule = _get_rule("TS-006")
        cf = _connector_file([(5, "    let x = val as Box<dyn Trait>;")])
        findings = rule.check(cf, "/fake/root")
        assert len(findings) == 0


class TestTS007_PrintMacro:
    def test_detects_println(self):
        rule = _get_rule("TS-007")
        cf = _connector_file([(5, '    println!("debug output");')])
        findings = rule.check(cf, "/fake/root")
        assert len(findings) == 1

    def test_detects_eprintln(self):
        rule = _get_rule("TS-007")
        cf = _connector_file([(5, '    eprintln!("error: {}", e);')])
        findings = rule.check(cf, "/fake/root")
        assert len(findings) == 1

    def test_detects_dbg(self):
        rule = _get_rule("TS-007")
        cf = _connector_file([(5, "    dbg!(value);")])
        findings = rule.check(cf, "/fake/root")
        assert len(findings) == 1


class TestTS008_Unreachable:
    def test_detects_unreachable(self):
        rule = _get_rule("TS-008")
        cf = _connector_file([(5, '    unreachable!("should not reach");')])
        findings = rule.check(cf, "/fake/root")
        assert len(findings) == 1


class TestTS009_Indexing:
    def test_detects_direct_indexing(self):
        rule = _get_rule("TS-009")
        cf = _connector_file([(5, "    let x = arr[0];")])
        findings = rule.check(cf, "/fake/root")
        assert len(findings) == 1

    def test_ignores_attributes(self):
        rule = _get_rule("TS-009")
        cf = _connector_file([(5, '    #[serde(rename = "field")]')])
        findings = rule.check(cf, "/fake/root")
        assert len(findings) == 0
