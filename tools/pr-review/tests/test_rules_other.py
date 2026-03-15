"""Tests for architecture, security, error handling, and domain rules."""

from pr_review.diff_parser import ChangedFile, DiffHunk, DiffLine
from pr_review.file_classifier import classify_file, ClassifiedFile, FileType
from pr_review.rules.architecture import get_rules as get_architecture_rules
from pr_review.rules.security import get_rules as get_security_rules
from pr_review.rules.error_handling import get_rules as get_error_handling_rules
from pr_review.rules.domain_rules import get_rules as get_domain_rules


# --- Helpers ---


def _make_classified_file(
    path: str,
    added_lines: list[tuple[int, str]],
    *,
    is_new: bool = False,
    is_deleted: bool = False,
) -> ClassifiedFile:
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


def _connector_file(lines: list[tuple[int, str]], **kw) -> ClassifiedFile:
    return _make_classified_file(
        "backend/connector-integration/src/connectors/stripe.rs", lines, **kw
    )


def _transformer_file(lines: list[tuple[int, str]], **kw) -> ClassifiedFile:
    return _make_classified_file(
        "backend/connector-integration/src/connectors/stripe/transformers.rs",
        lines,
        **kw,
    )


def _get_rule(rules_fn, rule_id: str):
    for r in rules_fn():
        if r.rule_id == rule_id:
            return r
    raise ValueError(f"Rule {rule_id} not found")


# --- Architecture Rules ---


class TestAR001_ConnectorIntegrationV2:
    def test_detects_v1_trait(self):
        rule = _get_rule(get_architecture_rules, "AR-001")
        cf = _connector_file([(10, "impl ConnectorIntegration for Stripe {")])
        findings = rule.check(cf, "/fake")
        assert len(findings) == 1

    def test_ignores_v2_trait(self):
        rule = _get_rule(get_architecture_rules, "AR-001")
        cf = _connector_file([(10, "impl ConnectorIntegrationV2 for Stripe {")])
        findings = rule.check(cf, "/fake")
        assert len(findings) == 0


class TestAR002_RouterDataV2:
    def test_detects_v1_router_data(self):
        rule = _get_rule(get_architecture_rules, "AR-002")
        cf = _connector_file([(10, "fn process(data: &RouterData) {")])
        findings = rule.check(cf, "/fake")
        assert len(findings) == 1

    def test_ignores_v2_router_data(self):
        rule = _get_rule(get_architecture_rules, "AR-002")
        cf = _connector_file([(10, "fn process(data: &RouterDataV2<F, Req, Resp>) {")])
        findings = rule.check(cf, "/fake")
        assert len(findings) == 0

    def test_ignores_response_router_data(self):
        rule = _get_rule(get_architecture_rules, "AR-002")
        cf = _connector_file([(10, "impl From<ResponseRouterData<...>> for ... {")])
        findings = rule.check(cf, "/fake")
        assert len(findings) == 0


class TestAR003_DomainTypes:
    def test_detects_hyperswitch_domain_models(self):
        rule = _get_rule(get_architecture_rules, "AR-003")
        cf = _connector_file([(10, "use hyperswitch_domain_models::payments;")])
        findings = rule.check(cf, "/fake")
        assert len(findings) == 1


class TestAR006_NoDirectReqwest:
    def test_detects_reqwest_usage(self):
        rule = _get_rule(get_architecture_rules, "AR-006")
        cf = _connector_file([(10, "    let client = reqwest::Client::new();")])
        findings = rule.check(cf, "/fake")
        assert len(findings) == 1

    def test_only_in_connector_integration(self):
        """Rule should only apply to connector-integration files."""
        rule = _get_rule(get_architecture_rules, "AR-006")
        cf = _make_classified_file(
            "backend/grpc-server/src/server.rs",
            [(10, "    let client = reqwest::Client::new();")],
        )
        findings = rule.check(cf, "/fake")
        assert len(findings) == 0


# --- Security Rules ---


class TestSE002_HardcodedURLs:
    def test_detects_hardcoded_url(self):
        rule = _get_rule(get_security_rules, "SE-002")
        cf = _connector_file(
            [(10, '    let url = "https://api.stripe.com/v1/charges";')]
        )
        findings = rule.check(cf, "/fake")
        assert len(findings) == 1

    def test_ignores_base_url_reference(self):
        rule = _get_rule(get_security_rules, "SE-002")
        cf = _connector_file([(10, '    base_url = "https://api.stripe.com";')])
        findings = rule.check(cf, "/fake")
        assert len(findings) == 0

    def test_only_in_connector_dir(self):
        rule = _get_rule(get_security_rules, "SE-002")
        cf = _make_classified_file(
            "backend/grpc-server/src/server.rs",
            [(10, '    let url = "https://example.com";')],
        )
        findings = rule.check(cf, "/fake")
        assert len(findings) == 0


class TestSE003_HardcodedCredentials:
    def test_detects_live_key(self):
        rule = _get_rule(get_security_rules, "SE-003")
        cf = _connector_file([(10, '    let key = "sk_live_1234567890abcdefghij";')])
        findings = rule.check(cf, "/fake")
        assert len(findings) == 1

    def test_detects_test_key(self):
        rule = _get_rule(get_security_rules, "SE-003")
        cf = _connector_file([(10, '    let key = "pk_test_1234567890abcdefghij";')])
        findings = rule.check(cf, "/fake")
        assert len(findings) == 1


class TestSE006_ExposeInLogging:
    def test_detects_expose_in_log(self):
        rule = _get_rule(get_security_rules, "SE-006")
        cf = _connector_file([(10, '    logger::info!("key: {}", secret.expose());')])
        findings = rule.check(cf, "/fake")
        assert len(findings) == 1

    def test_no_false_positive(self):
        rule = _get_rule(get_security_rules, "SE-006")
        cf = _connector_file([(10, "    let val = secret.expose();")])
        findings = rule.check(cf, "/fake")
        assert len(findings) == 0


# --- Error Handling Rules ---


class TestEH001_HardcodedFallback:
    def test_detects_unwrap_or_string(self):
        rule = _get_rule(get_error_handling_rules, "EH-001")
        cf = _connector_file([(10, '    let id = val.unwrap_or("N/A");')])
        findings = rule.check(cf, "/fake")
        assert len(findings) == 1

    def test_no_false_positive_on_unwrap_or_default(self):
        rule = _get_rule(get_error_handling_rules, "EH-001")
        cf = _connector_file([(10, "    let id = val.unwrap_or_default();")])
        findings = rule.check(cf, "/fake")
        assert len(findings) == 0


class TestEH003_ChangeContext:
    def test_detects_map_err_report(self):
        rule = _get_rule(get_error_handling_rules, "EH-003")
        cf = _connector_file(
            [(10, "    val.map_err(|_| report!(ConnectorError::ProcessingFailed))")]
        )
        findings = rule.check(cf, "/fake")
        assert len(findings) == 1


# --- Rule counts ---


class TestRuleCounts:
    def test_architecture_rule_count(self):
        rules = get_architecture_rules()
        assert len(rules) == 6
        ids = [r.rule_id for r in rules]
        assert ids == ["AR-001", "AR-002", "AR-003", "AR-004", "AR-005", "AR-006"]

    def test_security_rule_count(self):
        rules = get_security_rules()
        assert len(rules) == 6

    def test_error_handling_rule_count(self):
        rules = get_error_handling_rules()
        assert len(rules) == 5

    def test_domain_rule_count(self):
        rules = get_domain_rules()
        assert len(rules) == 5
