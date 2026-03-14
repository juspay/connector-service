use cucumber::{given, then, when};
use serde_json::{json, Value};
use std::fs;

use crate::TestWorld;
use ucs_connector_tests::harness::report::{
    extract_pm_and_pmt, generate_md, mask_bearer_tokens, md_path, now_epoch_ms,
    sanitize_report_entry_in_place, suite_sort_key, ReportEntry, ScenarioRunReport, MASKED_VALUE,
};

// ---------------------------------------------------------------------------
// Scenario: Extract payment method and type from card request
// ---------------------------------------------------------------------------

#[given("a request JSON with a card payment method of type \"credit\"")]
fn given_card_request(world: &mut TestWorld) {
    world.json_target = json!({
        "payment_method": {
            "card": {
                "card_type": "credit",
                "card_number": {"value": "4111111111111111"}
            }
        }
    });
}

#[when("payment method info is extracted")]
fn when_pm_extracted(world: &mut TestWorld) {
    let (pm, pmt) = extract_pm_and_pmt(Some(&world.json_target));
    world.report_pm = pm;
    world.report_pmt = pmt;
}

#[then(expr = "the payment method is {string}")]
#[allow(clippy::needless_pass_by_ref_mut)]
fn then_pm_is(world: &mut TestWorld, expected: String) {
    assert_eq!(world.report_pm.as_deref(), Some(expected.as_str()));
}

#[then(expr = "the payment method type is {string}")]
#[allow(clippy::needless_pass_by_ref_mut)]
fn then_pmt_is(world: &mut TestWorld, expected: String) {
    assert_eq!(world.report_pmt.as_deref(), Some(expected.as_str()));
}

// ---------------------------------------------------------------------------
// Scenario: Extract payment method from request without payment_method
// ---------------------------------------------------------------------------

#[given("a request JSON with only an amount field")]
fn given_amount_only(world: &mut TestWorld) {
    world.json_target = json!({"amount": 1000});
}

#[then("the payment method is absent")]
#[allow(clippy::needless_pass_by_ref_mut)]
fn then_pm_absent(world: &mut TestWorld) {
    assert!(world.report_pm.is_none());
}

#[then("the payment method type is absent")]
#[allow(clippy::needless_pass_by_ref_mut)]
fn then_pmt_absent(world: &mut TestWorld) {
    assert!(world.report_pmt.is_none());
}

// ---------------------------------------------------------------------------
// Scenario: Suite ordering is consistent
// ---------------------------------------------------------------------------

#[then(expr = "{string} sorts before {string}")]
#[allow(clippy::needless_pass_by_ref_mut)]
fn then_sorts_before(_world: &mut TestWorld, left: String, right: String) {
    assert!(
        suite_sort_key(&left) < suite_sort_key(&right),
        "expected `{left}` (key {}) to sort before `{right}` (key {})",
        suite_sort_key(&left),
        suite_sort_key(&right),
    );
}

// ---------------------------------------------------------------------------
// Scenario: Generated markdown uses plain status without badges
// ---------------------------------------------------------------------------

#[given("a report with stripe PASS and paypal FAIL entries for authorize suite")]
fn given_stripe_paypal_report(world: &mut TestWorld) {
    let temp_root = std::env::temp_dir().join(format!("ucs-report-cucumber-{}", now_epoch_ms()));
    fs::create_dir_all(&temp_root).expect("temp dir should be creatable");

    let json_path = temp_root.join("report.json");

    let report = ScenarioRunReport {
        runs: vec![
            ReportEntry {
                run_at_epoch_ms: now_epoch_ms(),
                suite: "authorize".to_string(),
                scenario: "no3ds_auto_capture_credit_card".to_string(),
                connector: "stripe".to_string(),
                pm: Some("card".to_string()),
                pmt: Some("credit".to_string()),
                endpoint: "localhost:8000".to_string(),
                is_dependency: false,
                assertion_result: "PASS".to_string(),
                response_status: None,
                error: None,
                dependency: vec![],
                req_body: Some(json!({"field": "value"})),
                res_body: Some(json!({"status": "CHARGED"})),
                grpc_request: None,
                grpc_response: None,
            },
            ReportEntry {
                run_at_epoch_ms: now_epoch_ms(),
                suite: "create_customer".to_string(),
                scenario: "create_customer".to_string(),
                connector: "paypal".to_string(),
                pm: None,
                pmt: None,
                endpoint: "localhost:8000".to_string(),
                is_dependency: true,
                assertion_result: "PASS".to_string(),
                response_status: None,
                error: None,
                dependency: vec![],
                req_body: Some(json!({"dep_req": "value"})),
                res_body: Some(json!({"dep_res": "ok"})),
                grpc_request: None,
                grpc_response: None,
            },
            ReportEntry {
                run_at_epoch_ms: now_epoch_ms(),
                suite: "authorize".to_string(),
                scenario: "no3ds_auto_capture_credit_card".to_string(),
                connector: "paypal".to_string(),
                pm: Some("card".to_string()),
                pmt: Some("credit".to_string()),
                endpoint: "localhost:8000".to_string(),
                is_dependency: false,
                assertion_result: "FAIL".to_string(),
                response_status: None,
                error: Some("forced failure".to_string()),
                dependency: vec!["create_customer(create_customer)".to_string()],
                req_body: Some(json!({"field": "value"})),
                res_body: Some(json!({"error": "forced failure"})),
                grpc_request: None,
                grpc_response: None,
            },
        ],
    };

    let serialized =
        serde_json::to_string_pretty(&report).expect("report should serialize to JSON");
    fs::write(&json_path, &serialized).expect("report.json should be writable");

    world.report_temp_root = Some(temp_root);
}

#[when("markdown is generated from the report")]
fn when_markdown_generated(world: &mut TestWorld) {
    let temp_root = world
        .report_temp_root
        .as_ref()
        .expect("temp root must be set");
    let json_path = temp_root.join("report.json");
    let content = fs::read_to_string(&json_path).expect("report.json should be readable");
    let report: ScenarioRunReport =
        serde_json::from_str(&content).expect("report.json should parse");
    generate_md(&json_path, &report).expect("markdown generation should succeed");
}

#[then("the overview markdown does not contain shield badge URLs")]
#[allow(clippy::needless_pass_by_ref_mut)]
fn then_no_badges(world: &mut TestWorld) {
    let content = read_overview(world);
    assert!(!content.contains("img.shields.io"));
    assert!(!content.contains("![Result]"));
    assert!(!content.contains("![Pass Rate]"));
    assert!(!content.contains("![Passed]"));
    assert!(!content.contains("![Failed]"));
}

#[then("the overview contains a Connector Flow Matrix section")]
#[allow(clippy::needless_pass_by_ref_mut)]
fn then_overview_has_matrix(world: &mut TestWorld) {
    let content = read_overview(world);
    assert!(content.contains("## Connector Flow Matrix"));
}

#[then("the stripe pass rate link shows 100.0%")]
#[allow(clippy::needless_pass_by_ref_mut)]
fn then_stripe_100(world: &mut TestWorld) {
    let content = read_overview(world);
    assert!(content.contains("[100.0%](./connectors/stripe/authorize.md)"));
}

#[then("the paypal pass rate link shows 0.0%")]
#[allow(clippy::needless_pass_by_ref_mut)]
fn then_paypal_0(world: &mut TestWorld) {
    let content = read_overview(world);
    assert!(content.contains("[0.0%](./connectors/paypal/authorize.md)"));
}

#[then("the stripe suite detail has the correct heading and scenario links")]
#[allow(clippy::needless_pass_by_ref_mut)]
fn then_stripe_suite_detail(world: &mut TestWorld) {
    let content = read_connector_suite_md(world, "stripe", "authorize");
    assert!(content.contains("# Connector `stripe` / Suite `authorize`"));
    assert!(content
        .contains("[`no3ds_auto_capture_credit_card`](./authorize/no3ds-auto-capture-credit-card.md)"));
}

#[then("the stripe scenario detail has request and response sections")]
#[allow(clippy::needless_pass_by_ref_mut)]
fn then_stripe_scenario_detail(world: &mut TestWorld) {
    let content = read_connector_scenario_md(
        world,
        "stripe",
        "authorize",
        "no3ds-auto-capture-credit-card",
    );
    assert!(content.contains(
        "# Connector `stripe` / Suite `authorize` / Scenario `no3ds_auto_capture_credit_card`"
    ));
    assert!(content.contains("<summary>Show Request (masked)</summary>"));
    assert!(content.contains("<summary>Show Response (masked)</summary>"));
    assert!(content.contains("\"field\": \"value\""));
    assert!(content.contains("\"status\": \"CHARGED\""));
    assert!(content.contains(
        "[Back to Connector Suite](../authorize.md) | [Back to Overview](../../../test_overview.md)"
    ));
}

#[then("the paypal scenario detail has dependency request and response sections")]
#[allow(clippy::needless_pass_by_ref_mut)]
fn then_paypal_scenario_detail(world: &mut TestWorld) {
    let content = read_connector_scenario_md(
        world,
        "paypal",
        "authorize",
        "no3ds-auto-capture-credit-card",
    );
    assert!(content.contains("<summary>Show Dependency Request (masked)</summary>"));
    assert!(content.contains("<summary>Show Dependency Response (masked)</summary>"));
    assert!(content.contains("\"dep_req\": \"value\""));
    assert!(content.contains("\"dep_res\": \"ok\""));
}

#[then("the paypal suite detail has a Failed Scenarios section")]
#[allow(clippy::needless_pass_by_ref_mut)]
fn then_paypal_failed_scenarios(world: &mut TestWorld) {
    let content = read_connector_suite_md(world, "paypal", "authorize");
    assert!(content.contains("## Failed Scenarios"));
}

// ---------------------------------------------------------------------------
// Scenario: Sanitization masks sensitive gRPC trace and JSON fields
// ---------------------------------------------------------------------------

#[given("a report entry with sensitive api_key, card_number, bearer tokens in grpc traces")]
fn given_sensitive_entry(world: &mut TestWorld) {
    world.report_entry = Some(ReportEntry {
        run_at_epoch_ms: now_epoch_ms(),
        suite: "authorize".to_string(),
        scenario: "no3ds_auto_capture_credit_card".to_string(),
        connector: "stripe".to_string(),
        pm: Some("card".to_string()),
        pmt: Some("credit".to_string()),
        endpoint: "localhost:50051".to_string(),
        is_dependency: false,
        assertion_result: "PASS".to_string(),
        response_status: None,
        error: Some("Authorization: Bearer token123".to_string()),
        dependency: vec![],
        req_body: Some(json!({
            "api_key": "sk_test_123",
            "payment_method": {
                "card": {
                    "card_number": {"value": "4111111111111111"},
                    "card_cvc": "123"
                }
            }
        })),
        res_body: Some(json!({
            "access_token": "access_token_value"
        })),
        grpc_request: Some(
            "grpcurl -plaintext \\\n+  -H \"x-api-key: sk_test_123\" \\\n+  -H \"authorization: Bearer token123\" \\\n+  -d @ localhost:50051 types.PaymentService/Authorize <<'JSON'"
                .to_string(),
        ),
        grpc_response: Some(
            "Response headers received:\nauthorization: Bearer token123\nx-api-key: sk_test_123"
                .to_string(),
        ),
    });
}

#[when("the report entry is sanitized")]
fn when_sanitized(world: &mut TestWorld) {
    let entry = world
        .report_entry
        .as_mut()
        .expect("report entry must be set");
    sanitize_report_entry_in_place(entry);
}

#[then("the grpc_request does not contain the original api key or token")]
#[allow(clippy::needless_pass_by_ref_mut)]
fn then_grpc_request_masked(world: &mut TestWorld) {
    let grpc_request = world
        .report_entry
        .as_ref()
        .expect("entry must exist")
        .grpc_request
        .as_ref()
        .expect("grpc_request should exist");
    assert!(!grpc_request.contains("sk_test_123"));
    assert!(!grpc_request.contains("token123"));
    assert!(grpc_request.contains(MASKED_VALUE));
}

#[then("the grpc_response does not contain the original api key or token")]
#[allow(clippy::needless_pass_by_ref_mut)]
fn then_grpc_response_masked(world: &mut TestWorld) {
    let grpc_response = world
        .report_entry
        .as_ref()
        .expect("entry must exist")
        .grpc_response
        .as_ref()
        .expect("grpc_response should exist");
    assert!(!grpc_response.contains("sk_test_123"));
    assert!(!grpc_response.contains("token123"));
    assert!(grpc_response.contains(MASKED_VALUE));
}

#[then("the error text does not contain the original token")]
#[allow(clippy::needless_pass_by_ref_mut)]
fn then_error_masked(world: &mut TestWorld) {
    let error = world
        .report_entry
        .as_ref()
        .expect("entry must exist")
        .error
        .as_ref()
        .expect("error should exist");
    assert!(!error.contains("token123"));
    assert!(error.contains(MASKED_VALUE));
}

#[then("the request body api_key is masked")]
#[allow(clippy::needless_pass_by_ref_mut)]
fn then_req_api_key_masked(world: &mut TestWorld) {
    let req_body = world
        .report_entry
        .as_ref()
        .expect("entry must exist")
        .req_body
        .as_ref()
        .expect("req_body should exist");
    assert_eq!(
        req_body.get("api_key").and_then(Value::as_str),
        Some(MASKED_VALUE)
    );
}

#[then("the request body card_number is masked")]
#[allow(clippy::needless_pass_by_ref_mut)]
fn then_req_card_number_masked(world: &mut TestWorld) {
    let req_body = world
        .report_entry
        .as_ref()
        .expect("entry must exist")
        .req_body
        .as_ref()
        .expect("req_body should exist");
    assert_eq!(
        req_body
            .pointer("/payment_method/card/card_number")
            .and_then(Value::as_str),
        Some(MASKED_VALUE)
    );
}

#[then("the request body card_cvc is masked")]
#[allow(clippy::needless_pass_by_ref_mut)]
fn then_req_card_cvc_masked(world: &mut TestWorld) {
    let req_body = world
        .report_entry
        .as_ref()
        .expect("entry must exist")
        .req_body
        .as_ref()
        .expect("req_body should exist");
    assert_eq!(
        req_body
            .pointer("/payment_method/card/card_cvc")
            .and_then(Value::as_str),
        Some(MASKED_VALUE)
    );
}

#[then("the response body access_token is masked")]
#[allow(clippy::needless_pass_by_ref_mut)]
fn then_res_access_token_masked(world: &mut TestWorld) {
    let res_body = world
        .report_entry
        .as_ref()
        .expect("entry must exist")
        .res_body
        .as_ref()
        .expect("res_body should exist");
    assert_eq!(
        res_body.get("access_token").and_then(Value::as_str),
        Some(MASKED_VALUE)
    );
}

// ---------------------------------------------------------------------------
// Scenario: Bearer masking is idempotent and masks multiple tokens
// ---------------------------------------------------------------------------

#[given(
    "a line with multiple Bearer tokens \"abc123\" and \"def456\" and an already masked token"
)]
fn given_bearer_line(world: &mut TestWorld) {
    world.json_target = json!(format!(
        "authorization: Bearer abc123 Bearer {} Bearer def456",
        MASKED_VALUE
    ));
}

#[when("bearer tokens are masked twice")]
fn when_bearer_masked_twice(world: &mut TestWorld) {
    let line = format!(
        "authorization: Bearer abc123 Bearer {} Bearer def456",
        MASKED_VALUE
    );
    world.bearer_masked_once = mask_bearer_tokens(&line);
    world.bearer_masked_twice = mask_bearer_tokens(&world.bearer_masked_once.clone());
}

#[then("the result is the same both times")]
#[allow(clippy::needless_pass_by_ref_mut)]
fn then_idempotent(world: &mut TestWorld) {
    assert_eq!(world.bearer_masked_once, world.bearer_masked_twice);
}

#[then("neither \"abc123\" nor \"def456\" appear in the output")]
#[allow(clippy::needless_pass_by_ref_mut)]
fn then_tokens_gone(world: &mut TestWorld) {
    assert!(!world.bearer_masked_once.contains("abc123"));
    assert!(!world.bearer_masked_once.contains("def456"));
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn read_overview(world: &TestWorld) -> String {
    let temp_root = world
        .report_temp_root
        .as_ref()
        .expect("temp root must be set");
    let json_path = temp_root.join("report.json");
    let overview_path = md_path(&json_path);
    fs::read_to_string(&overview_path).expect("generated overview markdown should be readable")
}

fn read_connector_suite_md(world: &TestWorld, connector: &str, suite: &str) -> String {
    let temp_root = world
        .report_temp_root
        .as_ref()
        .expect("temp root must be set");
    let path = temp_root
        .join("test_report")
        .join("connectors")
        .join(connector)
        .join(format!("{suite}.md"));
    fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("suite detail markdown at '{}' should be readable: {e}", path.display()))
}

fn read_connector_scenario_md(
    world: &TestWorld,
    connector: &str,
    suite: &str,
    scenario: &str,
) -> String {
    let temp_root = world
        .report_temp_root
        .as_ref()
        .expect("temp root must be set");
    let path = temp_root
        .join("test_report")
        .join("connectors")
        .join(connector)
        .join(suite)
        .join(format!("{scenario}.md"));
    fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "scenario detail markdown at '{}' should be readable: {e}",
            path.display()
        )
    })
}
