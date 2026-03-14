#![allow(clippy::too_many_lines)]

use std::collections::{BTreeSet, HashMap};

use cucumber::{given, then, when};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};

use grpc_api_types::payments;

use crate::TestWorld;
use ucs_connector_tests::harness::scenario_api::{
    add_context, apply_context_map, build_grpcurl_command, build_grpcurl_request,
    deep_set_json_path, extract_json_body_from_grpc_output, get_the_assertion,
    get_the_assertion_for_connector, get_the_grpc_req_for_connector,
    normalize_tonic_request_json, prepare_context_placeholders,
    prune_unresolved_context_fields, run_test,
    DEFAULT_SCENARIO, DEFAULT_SUITE,
};
use ucs_connector_tests::harness::scenario_loader::{
    connector_spec_dir, discover_all_connectors, load_suite_scenarios,
    load_supported_suites_for_connector,
};
use ucs_connector_tests::harness::scenario_types::{ContextMap, FieldAssert};

// ---------------------------------------------------------------------------
// Helpers for proto schema validation
// ---------------------------------------------------------------------------

fn validate_tonic_payload_shape<T: DeserializeOwned>(
    connector: &str,
    suite: &str,
    scenario: &str,
    grpc_req: &Value,
) -> Result<(), String> {
    let normalized = normalize_tonic_request_json(connector, suite, scenario, grpc_req.clone());
    let serialized = serde_json::to_string(&normalized).map_err(|error| {
        format!(
            "{connector}/{suite}/{scenario}: failed to serialize normalized payload: {error}"
        )
    })?;

    let mut ignored_paths = BTreeSet::new();
    let mut deserializer = serde_json::Deserializer::from_str(&serialized);
    let _: T = serde_ignored::deserialize(&mut deserializer, |path| {
        ignored_paths.insert(path.to_string());
    })
    .map_err(|error| {
        format!(
            "{connector}/{suite}/{scenario}: proto parse failed (type/enum mismatch): {error}"
        )
    })?;

    if !ignored_paths.is_empty() {
        return Err(format!(
            "{connector}/{suite}/{scenario}: unknown/ignored request fields: {}",
            ignored_paths.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }

    Ok(())
}

fn validate_suite_scenario_schema(
    connector: &str,
    suite: &str,
    scenario: &str,
    grpc_req: &Value,
) -> Result<(), String> {
    match suite {
        "create_access_token" => validate_tonic_payload_shape::<
            payments::MerchantAuthenticationServiceCreateAccessTokenRequest,
        >(connector, suite, scenario, grpc_req),
        "create_customer" => validate_tonic_payload_shape::<
            payments::CustomerServiceCreateRequest,
        >(connector, suite, scenario, grpc_req),
        "authorize" => validate_tonic_payload_shape::<payments::PaymentServiceAuthorizeRequest>(
            connector, suite, scenario, grpc_req,
        ),
        "capture" => validate_tonic_payload_shape::<payments::PaymentServiceCaptureRequest>(
            connector, suite, scenario, grpc_req,
        ),
        "void" => validate_tonic_payload_shape::<payments::PaymentServiceVoidRequest>(
            connector, suite, scenario, grpc_req,
        ),
        "refund" => validate_tonic_payload_shape::<payments::PaymentServiceRefundRequest>(
            connector, suite, scenario, grpc_req,
        ),
        "get" => validate_tonic_payload_shape::<payments::PaymentServiceGetRequest>(
            connector, suite, scenario, grpc_req,
        ),
        "refund_sync" => validate_tonic_payload_shape::<payments::RefundServiceGetRequest>(
            connector, suite, scenario, grpc_req,
        ),
        "setup_recurring" => validate_tonic_payload_shape::<
            payments::PaymentServiceSetupRecurringRequest,
        >(connector, suite, scenario, grpc_req),
        "recurring_charge" => validate_tonic_payload_shape::<
            payments::RecurringPaymentServiceChargeRequest,
        >(connector, suite, scenario, grpc_req),
        _ => Err(format!(
            "{connector}/{suite}/{scenario}: suite is not mapped to a tonic request type"
        )),
    }
}

// ---------------------------------------------------------------------------
// Scenario: Run test accepts explicit suite and scenario
// ---------------------------------------------------------------------------

#[when(expr = "run_test is called with suite {string}, scenario {string}, connector {string}")]
fn when_run_test_explicit(world: &mut TestWorld, suite: String, scenario: String, connector: String) {
    world.run_test_result = Some(run_test(Some(&suite), Some(&scenario), Some(&connector)));
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then("run_test succeeds")]
fn then_run_test_succeeds(world: &mut TestWorld) {
    let result = world
        .run_test_result
        .as_ref()
        .expect("run_test_result should be set");
    assert!(result.is_ok(), "run_test should succeed: {:?}", result);
}

// ---------------------------------------------------------------------------
// Scenario: Run test uses default suite and scenario
// ---------------------------------------------------------------------------

#[allow(clippy::needless_pass_by_ref_mut)]
#[then(expr = "the default suite is {string}")]
fn then_default_suite_is(_world: &mut TestWorld, expected: String) {
    assert_eq!(DEFAULT_SUITE, expected);
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then(expr = "the default scenario is {string}")]
fn then_default_scenario_is(_world: &mut TestWorld, expected: String) {
    assert_eq!(DEFAULT_SCENARIO, expected);
}

#[when("run_test is called with no arguments")]
fn when_run_test_defaults(world: &mut TestWorld) {
    world.run_test_result = Some(run_test(None, None, None));
}

// ---------------------------------------------------------------------------
// Scenario: Connector override is applied to assertions
// ---------------------------------------------------------------------------

#[given(expr = "base assertions for authorize/no3ds_fail_payment")]
fn given_base_assertions(world: &mut TestWorld) {
    world.base_assertions =
        get_the_assertion("authorize", "no3ds_fail_payment").expect("base assertions should load");
}

#[given(expr = "connector-overridden assertions for authorize/no3ds_fail_payment on stripe")]
fn given_overridden_assertions(world: &mut TestWorld) {
    world.overridden_assertions =
        get_the_assertion_for_connector("authorize", "no3ds_fail_payment", "stripe")
            .expect("connector assertions should load");
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then(expr = "the base message assertion contains {string}")]
fn then_base_message_contains(world: &mut TestWorld, expected: String) {
    let rule = world
        .base_assertions
        .get("error.connector_details.message")
        .expect("base contains message assertion");
    assert!(
        matches!(rule, FieldAssert::Contains { contains } if contains == &expected),
        "base message rule should contain '{expected}': {:?}",
        rule
    );
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then(expr = "the overridden message assertion contains {string}")]
fn then_overridden_message_contains(world: &mut TestWorld, expected: String) {
    let rule = world
        .overridden_assertions
        .get("error.connector_details.message")
        .expect("overridden contains message assertion");
    assert!(
        matches!(rule, FieldAssert::Contains { contains } if contains == &expected),
        "overridden message rule should contain '{expected}': {:?}",
        rule
    );
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then("the base assertions include a status rule")]
fn then_base_has_status(world: &mut TestWorld) {
    assert!(
        world.base_assertions.contains_key("status"),
        "base assertions should include a status rule"
    );
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then("the overridden assertions do not include a status rule")]
fn then_overridden_no_status(world: &mut TestWorld) {
    assert!(
        !world.overridden_assertions.contains_key("status"),
        "overridden assertions should not include a status rule"
    );
}

// ---------------------------------------------------------------------------
// Scenario: Builds grpcurl command
// ---------------------------------------------------------------------------

#[when("a grpcurl command is built for authorize/no3ds_auto_capture_credit_card on stripe at localhost:50051")]
fn when_build_grpcurl_command(world: &mut TestWorld) {
    world.grpcurl_command = build_grpcurl_command(
        Some("authorize"),
        Some("no3ds_auto_capture_credit_card"),
        Some("localhost:50051"),
        Some("stripe"),
        Some("test_merchant"),
        Some("default"),
        true,
    )
    .expect("grpcurl command should build");
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then(expr = "the command contains {string}")]
fn then_command_contains(world: &mut TestWorld, expected: String) {
    assert!(
        world.grpcurl_command.contains(&expected),
        "command should contain '{expected}', got: {}",
        world.grpcurl_command
    );
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then("the command contains x-connector stripe")]
fn then_command_contains_connector(world: &mut TestWorld) {
    assert!(
        world.grpcurl_command.contains("\"x-connector: stripe\""),
        "command should contain x-connector header"
    );
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then("the command contains auth_type NO_THREE_DS")]
fn then_command_contains_auth_type(world: &mut TestWorld) {
    assert!(
        world.grpcurl_command.contains("\"auth_type\": \"NO_THREE_DS\""),
        "command should contain auth_type NO_THREE_DS"
    );
}

// ---------------------------------------------------------------------------
// Scenario: Builds grpcurl request struct
// ---------------------------------------------------------------------------

#[when("a grpcurl request struct is built for authorize/no3ds_auto_capture_credit_card on stripe at localhost:50051")]
fn when_build_grpcurl_request_struct(world: &mut TestWorld) {
    world.grpcurl_request = Some(
        build_grpcurl_request(
            Some("authorize"),
            Some("no3ds_auto_capture_credit_card"),
            Some("localhost:50051"),
            Some("stripe"),
            Some("test_merchant"),
            Some("default"),
            true,
            false,
        )
        .expect("grpcurl request should build"),
    );
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then(expr = "the request endpoint is {string}")]
fn then_request_endpoint(world: &mut TestWorld, expected: String) {
    let request = world.grpcurl_request.as_ref().expect("grpcurl_request should be set");
    assert_eq!(request.endpoint, expected);
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then(expr = "the request method is {string}")]
fn then_request_method(world: &mut TestWorld, expected: String) {
    let request = world.grpcurl_request.as_ref().expect("grpcurl_request should be set");
    assert_eq!(request.method, expected);
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then("the request payload contains auth_type NO_THREE_DS")]
fn then_request_payload_auth_type(world: &mut TestWorld) {
    let request = world.grpcurl_request.as_ref().expect("grpcurl_request should be set");
    assert!(
        request.payload.contains("\"auth_type\": \"NO_THREE_DS\""),
        "payload should contain auth_type NO_THREE_DS"
    );
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then("the request has non-empty headers")]
fn then_request_has_headers(world: &mut TestWorld) {
    let request = world.grpcurl_request.as_ref().expect("grpcurl_request should be set");
    assert!(!request.headers.is_empty(), "request should have non-empty headers");
}

// ---------------------------------------------------------------------------
// Scenario: Extracts JSON body from verbose grpc output
// ---------------------------------------------------------------------------

#[given(expr = "verbose grpc output with Response contents containing status {string} and connector_transaction_id {string}")]
fn given_verbose_grpc_output(world: &mut TestWorld, status: String, txn_id: String) {
    let verbose_output = format!(
        r#"
Resolved method descriptor:
rpc Authorize (...)

Request metadata to send:
x-connector: stripe

Response headers received:
content-type: application/grpc

Response contents:
{{
  "status": "{status}",
  "connector_transaction_id": {{
    "id": "{txn_id}"
  }}
}}

Response trailers received:
grpc-status: 0
"#
    );
    world.extracted_json_body = verbose_output;
}

#[when("the JSON body is extracted from grpc output")]
fn when_extract_json_body(world: &mut TestWorld) {
    let body = extract_json_body_from_grpc_output(&world.extracted_json_body, "")
        .expect("json body should be extracted from output");
    world.extracted_json_body = body;
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then(expr = "the extracted status is {string}")]
fn then_extracted_status(world: &mut TestWorld, expected: String) {
    let parsed: Value =
        serde_json::from_str(&world.extracted_json_body).expect("extracted body should parse");
    assert_eq!(parsed["status"], json!(expected));
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then(expr = "the extracted connector_transaction_id id is {string}")]
fn then_extracted_connector_txn_id(world: &mut TestWorld, expected: String) {
    let parsed: Value =
        serde_json::from_str(&world.extracted_json_body).expect("extracted body should parse");
    assert_eq!(parsed["connector_transaction_id"]["id"], json!(expected));
}

// ---------------------------------------------------------------------------
// Scenario: Extracts plain JSON body without verbose sections
// ---------------------------------------------------------------------------

#[given(expr = "plain grpc output with status {string}")]
fn given_plain_grpc_output(world: &mut TestWorld, status: String) {
    world.extracted_json_body = format!("{{\n  \"status\": \"{status}\"\n}}");
}

// ---------------------------------------------------------------------------
// Scenario: Build grpcurl request resolves auto_generate placeholders
// ---------------------------------------------------------------------------

#[when("a grpcurl request is built for authorize/no3ds_manual_capture_credit_card on stripe")]
fn when_build_grpcurl_request_auto_generate(world: &mut TestWorld) {
    world.grpcurl_request = Some(
        build_grpcurl_request(
            Some("authorize"),
            Some("no3ds_manual_capture_credit_card"),
            Some("localhost:50051"),
            Some("stripe"),
            Some("test_merchant"),
            Some("default"),
            true,
            false,
        )
        .expect("grpcurl request should build"),
    );
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then(expr = "the payload does not contain {string}")]
fn then_payload_not_contains(world: &mut TestWorld, forbidden: String) {
    let request = world.grpcurl_request.as_ref().expect("grpcurl_request should be set");
    assert!(
        !request.payload.contains(&forbidden),
        "payload should not contain '{forbidden}'"
    );
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then(expr = "the merchant_transaction_id starts with {string}")]
fn then_merchant_txn_id_starts_with(world: &mut TestWorld, prefix: String) {
    let request = world.grpcurl_request.as_ref().expect("grpcurl_request should be set");
    let payload: Value =
        serde_json::from_str(&request.payload).expect("payload should parse as json");
    let merchant_id = payload["merchant_transaction_id"]
        .as_str()
        .expect("merchant_transaction_id should be present");
    assert!(
        merchant_id.starts_with(&prefix),
        "merchant_transaction_id should start with '{prefix}', got: {merchant_id}"
    );
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then(expr = "the customer id starts with {string}")]
fn then_customer_id_starts_with(world: &mut TestWorld, prefix: String) {
    let request = world.grpcurl_request.as_ref().expect("grpcurl_request should be set");
    let payload: Value =
        serde_json::from_str(&request.payload).expect("payload should parse as json");
    let customer_id = payload["customer"]["id"]
        .as_str()
        .expect("customer.id should be present");
    assert!(
        customer_id.starts_with(&prefix),
        "customer.id should start with '{prefix}', got: {customer_id}"
    );
}

// ---------------------------------------------------------------------------
// Scenario: Add context overrides with latest index preference
// ---------------------------------------------------------------------------

#[given(expr = "previous requests with customer ids {string} and {string}")]
fn given_prev_reqs_customer_ids(world: &mut TestWorld, old: String, new: String) {
    world.prev_reqs = vec![
        json!({"customer": {"id": old}}),
        json!({"customer": {"id": new}}),
    ];
}

#[given(expr = "previous responses with transaction ids {string} and {string}")]
fn given_prev_res_txn_ids(world: &mut TestWorld, old: String, new: String) {
    world.prev_res = vec![
        json!({"connectorTransactionId": {"id": old}}),
        json!({"connectorTransactionId": {"id": new}}),
    ];
}

#[given("a current request with default customer id and transaction id")]
fn given_current_req_defaults(world: &mut TestWorld) {
    world.current_req = json!({
        "customer": {"id": "cust_default"},
        "connector_transaction_id": {"id": "txn_default"}
    });
}

#[when("context is added from previous requests and responses")]
fn when_context_added_from_prev(world: &mut TestWorld) {
    add_context(&world.prev_reqs.clone(), &world.prev_res.clone(), &mut world.current_req);
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then(expr = "the current customer id is {string}")]
fn then_current_customer_id(world: &mut TestWorld, expected: String) {
    assert_eq!(world.current_req["customer"]["id"], json!(expected));
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then(expr = "the current transaction id is {string}")]
fn then_current_txn_id(world: &mut TestWorld, expected: String) {
    assert_eq!(
        world.current_req["connector_transaction_id"]["id"],
        json!(expected)
    );
}

// ---------------------------------------------------------------------------
// Scenario: Add context keeps scenario-specific values when context is dependency-only
// ---------------------------------------------------------------------------

#[given(expr = "dependency requests with customer id {string}")]
fn given_dependency_reqs(world: &mut TestWorld, customer_id: String) {
    world.prev_reqs = vec![json!({"customer": {"id": customer_id}})];
}

#[given(expr = "dependency responses with access_token {string}")]
fn given_dependency_res_access_token(world: &mut TestWorld, token: String) {
    world.prev_res = vec![json!({"accessToken": token})];
}

#[when(expr = "context is added to a scenario with capture_method {string}")]
fn when_context_added_with_capture_method(world: &mut TestWorld, capture_method: String) {
    world.current_req = json!({
        "capture_method": capture_method,
        "customer": {"id": "auto_generate"},
        "access_token": "auto_generate"
    });
    add_context(&world.prev_reqs.clone(), &world.prev_res.clone(), &mut world.current_req);
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then(expr = "the capture_method remains {string}")]
fn then_capture_method_remains(world: &mut TestWorld, expected: String) {
    assert_eq!(world.current_req["capture_method"], json!(expected));
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then(expr = "the customer id is {string}")]
fn then_customer_id_is(world: &mut TestWorld, expected: String) {
    assert_eq!(world.current_req["customer"]["id"], json!(expected));
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then(expr = "the access_token is {string}")]
fn then_access_token_is(world: &mut TestWorld, expected: String) {
    assert_eq!(world.current_req["access_token"], json!(expected));
}

// ---------------------------------------------------------------------------
// Scenario: Add context maps refund_id from connector_refund_id
// ---------------------------------------------------------------------------

#[given(expr = "a previous response with connectorRefundId {string}")]
fn given_prev_res_refund_id(world: &mut TestWorld, refund_id: String) {
    world.prev_reqs = vec![];
    world.prev_res = vec![json!({"connectorRefundId": refund_id})];
}

#[given(expr = "a current request with refund_id {string}")]
fn given_current_req_refund_id(world: &mut TestWorld, refund_id: String) {
    world.current_req = json!({"refund_id": refund_id});
}

#[when("context is added")]
fn when_context_added(world: &mut TestWorld) {
    add_context(&world.prev_reqs.clone(), &world.prev_res.clone(), &mut world.current_req);
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then(expr = "the refund_id is {string}")]
fn then_refund_id_is(world: &mut TestWorld, expected: String) {
    assert_eq!(world.current_req["refund_id"], json!(expected));
}

// ---------------------------------------------------------------------------
// Scenario: Add context maps identifier PascalCase oneof variant
// ---------------------------------------------------------------------------

#[given(expr = "a previous response with connector_transaction_id id_type Id {string}")]
fn given_prev_res_id_type_id(world: &mut TestWorld, value: String) {
    world.prev_reqs = vec![];
    world.prev_res = vec![json!({
        "connector_transaction_id": {
            "id_type": {
                "Id": value
            }
        }
    })];
}

#[given(expr = "a current request with connector_transaction_id id {string}")]
fn given_current_req_connector_txn_id(world: &mut TestWorld, value: String) {
    world.current_req = json!({
        "connector_transaction_id": {
            "id": value
        }
    });
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then(expr = "the connector_transaction_id id is {string}")]
fn then_connector_txn_id_is(world: &mut TestWorld, expected: String) {
    assert_eq!(
        world.current_req["connector_transaction_id"]["id"],
        json!(expected)
    );
}

// ---------------------------------------------------------------------------
// Scenario: Add context maps mandate reference into mandate_reference_id
// ---------------------------------------------------------------------------

#[given(expr = "a previous response with mandateReference connectorMandateId {string}")]
fn given_prev_res_mandate_ref(world: &mut TestWorld, mandate_id: String) {
    world.prev_reqs = vec![];
    world.prev_res = vec![json!({
        "mandateReference": {
            "connectorMandateId": {
                "connectorMandateId": mandate_id
            }
        }
    })];
}

#[given(expr = "a current request with mandate_reference_id connector_mandate_id {string}")]
fn given_current_req_mandate_ref_id(world: &mut TestWorld, value: String) {
    world.current_req = json!({
        "mandate_reference_id": {
            "connector_mandate_id": {
                "connector_mandate_id": value
            }
        }
    });
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then(expr = "the mandate_reference_id connector_mandate_id is {string}")]
fn then_mandate_ref_id_is(world: &mut TestWorld, expected: String) {
    assert_eq!(
        world.current_req["mandate_reference_id"]["connector_mandate_id"]["connector_mandate_id"],
        json!(expected)
    );
}

// ---------------------------------------------------------------------------
// Scenario: Add context does not map mandate reference into connector_recurring_payment_id
// ---------------------------------------------------------------------------

#[given(expr = "a current request with connector_recurring_payment_id connector_mandate_id {string}")]
fn given_current_req_recurring_payment_id(world: &mut TestWorld, value: String) {
    world.current_req = json!({
        "connector_recurring_payment_id": {
            "connector_mandate_id": {
                "connector_mandate_id": value
            }
        }
    });
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then(expr = "the connector_recurring_payment_id connector_mandate_id remains {string}")]
fn then_recurring_payment_id_remains(world: &mut TestWorld, expected: String) {
    assert_eq!(
        world.current_req["connector_recurring_payment_id"]["connector_mandate_id"]
            ["connector_mandate_id"],
        json!(expected)
    );
}

// ---------------------------------------------------------------------------
// Scenario: Add context maps access token fields into state.access_token
// ---------------------------------------------------------------------------

#[given(expr = "a previous response with access_token {string}, token_type {string}, expires_in_seconds {int}")]
fn given_prev_res_access_token_fields(
    world: &mut TestWorld,
    token: String,
    token_type: String,
    expires: i64,
) {
    world.prev_reqs = vec![];
    world.prev_res = vec![json!({
        "access_token": token,
        "token_type": token_type,
        "expires_in_seconds": expires
    })];
}

#[given("a current request with empty state.access_token fields")]
fn given_current_req_empty_access_token(world: &mut TestWorld) {
    world.current_req = json!({
        "state": {
            "access_token": {
                "token": {
                    "value": ""
                },
                "token_type": "",
                "expires_in_seconds": 0
            }
        }
    });
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then(expr = "the state access_token token value is {string}")]
fn then_state_access_token_value(world: &mut TestWorld, expected: String) {
    assert_eq!(
        world.current_req["state"]["access_token"]["token"]["value"],
        json!(expected)
    );
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then(expr = "the state access_token token_type is {string}")]
fn then_state_access_token_type(world: &mut TestWorld, expected: String) {
    assert_eq!(
        world.current_req["state"]["access_token"]["token_type"],
        json!(expected)
    );
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then(expr = "the state access_token expires_in_seconds is {int}")]
fn then_state_access_token_expires(world: &mut TestWorld, expected: i64) {
    assert_eq!(
        world.current_req["state"]["access_token"]["expires_in_seconds"],
        json!(expected)
    );
}

// ---------------------------------------------------------------------------
// Scenario: Add context maps connector_customer_id to nested targets
// ---------------------------------------------------------------------------

#[given(expr = "a previous response with connector_customer_id {string}")]
fn given_prev_res_connector_customer_id(world: &mut TestWorld, customer_id: String) {
    world.prev_reqs = vec![];
    world.prev_res = vec![json!({"connector_customer_id": customer_id})];
}

#[when("context is added to a request with customer.connector_customer_id")]
fn when_context_added_customer_connector_customer_id(world: &mut TestWorld) {
    world.current_req = json!({
        "customer": {
            "connector_customer_id": ""
        }
    });
    add_context(&world.prev_reqs.clone(), &world.prev_res.clone(), &mut world.current_req);
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then(expr = "customer.connector_customer_id is {string}")]
fn then_customer_connector_customer_id(world: &mut TestWorld, expected: String) {
    assert_eq!(
        world.current_req["customer"]["connector_customer_id"],
        json!(expected)
    );
}

#[when("context is added to a request with state.connector_customer_id")]
fn when_context_added_state_connector_customer_id(world: &mut TestWorld) {
    world.current_req = json!({
        "state": {
            "connector_customer_id": ""
        }
    });
    add_context(&world.prev_reqs.clone(), &world.prev_res.clone(), &mut world.current_req);
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then(expr = "state.connector_customer_id is {string}")]
fn then_state_connector_customer_id(world: &mut TestWorld, expected: String) {
    assert_eq!(
        world.current_req["state"]["connector_customer_id"],
        json!(expected)
    );
}

// ---------------------------------------------------------------------------
// Scenario: Add context maps connector_feature_data value
// ---------------------------------------------------------------------------

#[given("a previous response with connectorFeatureData value containing authorize_id")]
fn given_prev_res_connector_feature_data(world: &mut TestWorld) {
    world.prev_reqs = vec![];
    world.prev_res = vec![json!({
        "connectorFeatureData": {
            "value": "{\"authorize_id\":\"auth_123\"}"
        }
    })];
}

#[given(expr = "a current request with connector_feature_data value {string}")]
fn given_current_req_connector_feature_data(world: &mut TestWorld, value: String) {
    world.current_req = json!({
        "connector_feature_data": {
            "value": value
        }
    });
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then(expr = "the connector_feature_data value contains {string}")]
fn then_connector_feature_data_contains(world: &mut TestWorld, expected: String) {
    let value = world.current_req["connector_feature_data"]["value"]
        .as_str()
        .expect("connector_feature_data.value should be a string");
    assert!(
        value.contains(&expected),
        "connector_feature_data.value should contain '{expected}', got: {value}"
    );
}

// ---------------------------------------------------------------------------
// Scenario: Prepare context placeholders converts empty values to auto_generate
// ---------------------------------------------------------------------------

#[given("a capture request with empty connector_customer_id and access_token fields")]
fn given_capture_req_empty_context_fields(world: &mut TestWorld) {
    world.current_req = json!({
        "customer": { "connector_customer_id": "" },
        "state": {
            "connector_customer_id": "",
            "access_token": {
                "token": { "value": "" },
                "token_type": "",
                "expires_in_seconds": 0
            }
        }
    });
}

#[when(expr = "context placeholders are prepared for {string} on {string}")]
fn when_prepare_context_placeholders(world: &mut TestWorld, suite: String, connector: String) {
    prepare_context_placeholders(&suite, &connector, &mut world.current_req);
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then("all context-carried fields are set to \"auto_generate\"")]
fn then_all_context_fields_auto_generate(world: &mut TestWorld) {
    assert_eq!(
        world.current_req["customer"]["connector_customer_id"],
        json!("auto_generate")
    );
    assert_eq!(
        world.current_req["state"]["connector_customer_id"],
        json!("auto_generate")
    );
    assert_eq!(
        world.current_req["state"]["access_token"]["token"]["value"],
        json!("auto_generate")
    );
    assert_eq!(
        world.current_req["state"]["access_token"]["token_type"],
        json!("auto_generate")
    );
    assert_eq!(
        world.current_req["state"]["access_token"]["expires_in_seconds"],
        json!("auto_generate")
    );
    assert_eq!(
        world.current_req["connector_feature_data"]["value"],
        json!("auto_generate")
    );
}

// ---------------------------------------------------------------------------
// Scenario: Prune unresolved context fields drops unresolved values
// ---------------------------------------------------------------------------

#[given("a request with unresolved auto_generate context fields and a real merchant_transaction_id")]
fn given_req_unresolved_context(world: &mut TestWorld) {
    world.current_req = json!({
        "customer": { "connector_customer_id": "auto_generate" },
        "state": {
            "connector_customer_id": "auto_generate",
            "access_token": {
                "token": { "value": "auto_generate" },
                "token_type": "auto_generate",
                "expires_in_seconds": "auto_generate"
            }
        },
        "connector_feature_data": { "value": "auto_generate" },
        "connector_transaction_id": { "id": "auto_generate" },
        "refund_id": "auto_generate",
        "merchant_transaction_id": { "id": "mti_real" }
    });
}

#[when(expr = "unresolved context fields are pruned for {string}")]
fn when_prune_unresolved(world: &mut TestWorld, connector: String) {
    prune_unresolved_context_fields(&connector, &mut world.current_req);
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then("the unresolved fields are removed or nullified")]
fn then_unresolved_removed(world: &mut TestWorld) {
    assert!(world.current_req["customer"]
        .get("connector_customer_id")
        .is_none());
    assert!(world.current_req["connector_feature_data"].is_null());
    assert!(world.current_req["connector_transaction_id"]
        .get("id")
        .is_none());
    assert!(world.current_req.get("refund_id").is_none());
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then(expr = "the merchant_transaction_id id is preserved as {string}")]
fn then_merchant_txn_id_preserved(world: &mut TestWorld, expected: String) {
    assert_eq!(
        world.current_req["merchant_transaction_id"]["id"],
        json!(expected)
    );
}

// ---------------------------------------------------------------------------
// Scenario: Prune unresolved context fields keeps resolved values
// ---------------------------------------------------------------------------

#[given("a request with fully resolved context fields")]
fn given_req_resolved_context(world: &mut TestWorld) {
    world.current_req = json!({
        "customer": { "connector_customer_id": "cust_123" },
        "state": {
            "connector_customer_id": "cust_state_123",
            "access_token": {
                "token": { "value": "tok_123" },
                "token_type": "Bearer",
                "expires_in_seconds": 3600
            }
        },
        "connector_feature_data": { "value": "{\"authorize_id\":\"auth_123\"}" },
        "connector_transaction_id": { "id": "pi_123" },
        "refund_id": "re_123"
    });
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then("all resolved fields are preserved")]
fn then_all_resolved_preserved(world: &mut TestWorld) {
    assert_eq!(
        world.current_req["customer"]["connector_customer_id"],
        json!("cust_123")
    );
    assert_eq!(
        world.current_req["state"]["access_token"]["token"]["value"],
        json!("tok_123")
    );
    assert_eq!(
        world.current_req["connector_feature_data"]["value"],
        json!("{\"authorize_id\":\"auth_123\"}")
    );
    assert_eq!(
        world.current_req["connector_transaction_id"]["id"],
        json!("pi_123")
    );
    assert_eq!(world.current_req["refund_id"], json!("re_123"));
}

// ---------------------------------------------------------------------------
// Scenario: Normalizer unwraps value wrappers
// ---------------------------------------------------------------------------

#[given("a request with value-wrapped card_number and email fields")]
fn given_req_value_wrapped(world: &mut TestWorld) {
    world.current_req = json!({
        "payment_method": {
            "card": {
                "card_number": { "value": "4111111111111111" },
                "card_holder_name": { "value": "John Doe" }
            }
        },
        "customer": {
            "email": { "value": "john@example.com" }
        }
    });
}

#[when(expr = "the request is normalized for tonic for {string} {string}")]
fn when_normalize_tonic(world: &mut TestWorld, connector: String, suite: String) {
    let normalized = normalize_tonic_request_json(
        &connector,
        &suite,
        "cucumber_test",
        world.current_req.clone(),
    );
    world.current_req = normalized;
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then("the card_number is unwrapped to a plain string")]
fn then_card_number_unwrapped(world: &mut TestWorld) {
    assert_eq!(
        world.current_req["payment_method"]["payment_method"]["card"]["card_number"],
        json!("4111111111111111")
    );
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then("the email is unwrapped to a plain string")]
fn then_email_unwrapped(world: &mut TestWorld) {
    assert_eq!(
        world.current_req["customer"]["email"],
        json!("john@example.com")
    );
}

// ---------------------------------------------------------------------------
// Scenario: Normalizer drops legacy get handle_response bool
// ---------------------------------------------------------------------------

#[given("a get request with handle_response true")]
fn given_get_req_handle_response(world: &mut TestWorld) {
    world.current_req = json!({
        "connector_transaction_id": "txn_123",
        "handle_response": true
    });
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then("the handle_response field is removed")]
fn then_handle_response_removed(world: &mut TestWorld) {
    assert!(
        world.current_req.get("handle_response").is_none(),
        "handle_response should be removed"
    );
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then("the connector_transaction_id is preserved")]
fn then_connector_txn_id_preserved(world: &mut TestWorld) {
    assert_eq!(
        world.current_req["connector_transaction_id"],
        json!("txn_123")
    );
}

// ---------------------------------------------------------------------------
// Scenario: Normalizer adds authorize order_details default
// ---------------------------------------------------------------------------

#[given("an authorize request without order_details")]
fn given_authorize_req_no_order_details(world: &mut TestWorld) {
    world.current_req = json!({
        "merchant_transaction_id": "m_123",
        "amount": {"minor_amount": 1000, "currency": "USD"}
    });
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then("the order_details is set to an empty array")]
fn then_order_details_empty_array(world: &mut TestWorld) {
    assert_eq!(world.current_req["order_details"], json!([]));
}

// ---------------------------------------------------------------------------
// Scenario: Normalizer adds customer_acceptance accepted_at default
// ---------------------------------------------------------------------------

#[given("a setup_recurring request with customer_acceptance but no accepted_at")]
fn given_setup_recurring_no_accepted_at(world: &mut TestWorld) {
    world.current_req = json!({
        "customer_acceptance": {
            "acceptance_type": "OFFLINE"
        }
    });
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then("the accepted_at is set to a non-negative integer")]
fn then_accepted_at_non_negative(world: &mut TestWorld) {
    let accepted_at = world.current_req["customer_acceptance"]["accepted_at"]
        .as_i64()
        .expect("accepted_at should be injected as i64");
    assert!(accepted_at >= 0);
}

// ---------------------------------------------------------------------------
// Scenario: Normalizer wraps connector recurring mandate oneof
// ---------------------------------------------------------------------------

#[given("a recurring_charge request with connector_recurring_payment_id mandate")]
fn given_recurring_charge_mandate(world: &mut TestWorld) {
    world.current_req = json!({
        "connector_recurring_payment_id": {
            "connector_mandate_id": {
                "connector_mandate_id": "mandate_123"
            }
        }
    });
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then("the mandate is wrapped in mandate_id_type ConnectorMandateId")]
fn then_mandate_wrapped(world: &mut TestWorld) {
    assert_eq!(
        world.current_req["connector_recurring_payment_id"]["mandate_id_type"]
            ["ConnectorMandateId"]["connector_mandate_id"],
        json!("mandate_123")
    );
}

// ---------------------------------------------------------------------------
// Scenario: Deep set creates intermediate objects
// ---------------------------------------------------------------------------

#[given("an empty JSON object")]
fn given_empty_json(world: &mut TestWorld) {
    world.json_target = json!({});
}

#[when(expr = "deep_set is called with path {string} and value {string}")]
fn when_deep_set_string(world: &mut TestWorld, path: String, value: String) {
    deep_set_json_path(&mut world.json_target, &path, json!(value));
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then(expr = "the value at state.access_token.token.value is {string}")]
fn then_deep_value_at_path(world: &mut TestWorld, expected: String) {
    assert_eq!(
        world.json_target["state"]["access_token"]["token"]["value"],
        json!(expected)
    );
}

// ---------------------------------------------------------------------------
// Scenario: Deep set overwrites existing leaf
// ---------------------------------------------------------------------------

#[given(expr = "a JSON object with existing state.access_token.token.value {string}")]
fn given_json_with_existing_path(world: &mut TestWorld, value: String) {
    world.json_target = json!({"state": {"access_token": {"token": {"value": value}}}});
}

// ---------------------------------------------------------------------------
// Scenario: Deep set single segment
// ---------------------------------------------------------------------------

#[given(expr = "a JSON object with foo {string}")]
fn given_json_with_foo(world: &mut TestWorld, value: String) {
    world.json_target = json!({"foo": value});
}

#[when(expr = "deep_set is called with path {string} and value {int}")]
fn when_deep_set_int(world: &mut TestWorld, path: String, value: i64) {
    deep_set_json_path(&mut world.json_target, &path, json!(value));
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then(expr = "the value at baz is {int}")]
fn then_value_at_baz(world: &mut TestWorld, expected: i64) {
    assert_eq!(world.json_target["baz"], json!(expected));
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then(expr = "the value at foo is {string}")]
fn then_value_at_foo(world: &mut TestWorld, expected: String) {
    assert_eq!(world.json_target["foo"], json!(expected));
}

// ---------------------------------------------------------------------------
// Scenario: Deep set partial existing path
// ---------------------------------------------------------------------------

#[given(expr = "a JSON object with state.existing true")]
fn given_json_with_state_existing(world: &mut TestWorld) {
    world.json_target = json!({"state": {"existing": true}});
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then(expr = "the value at state.existing is true")]
fn then_state_existing_true(world: &mut TestWorld) {
    assert_eq!(world.json_target["state"]["existing"], json!(true));
}

// ---------------------------------------------------------------------------
// Scenario: Apply context map maps response field to deep target
// ---------------------------------------------------------------------------

#[given(expr = "a context map entry from {string} to {string}")]
fn given_context_map_entry(world: &mut TestWorld, source: String, target: String) {
    let mut context_map: ContextMap = HashMap::new();
    context_map.insert(target, source);
    world.context_map_collected = vec![(context_map, json!({}), json!({}))];
}

#[given(expr = "a dependency response with access_token {string}")]
fn given_dep_res_access_token(world: &mut TestWorld, token: String) {
    if let Some(entry) = world.context_map_collected.last_mut() {
        entry.2 = json!({"access_token": token});
    }
}

#[given(expr = "a request with amount minor_amount {int}")]
fn given_req_amount(world: &mut TestWorld, amount: i64) {
    world.current_req = json!({"amount": {"minor_amount": amount}});
}

#[when("the context map is applied")]
fn when_context_map_applied(world: &mut TestWorld) {
    let collected = world.context_map_collected.clone();
    apply_context_map(&collected, &mut world.current_req);
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then(expr = "state.access_token.token.value is {string}")]
fn then_state_access_token_token_value(world: &mut TestWorld, expected: String) {
    assert_eq!(
        world.current_req["state"]["access_token"]["token"]["value"],
        json!(expected)
    );
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then(expr = "amount.minor_amount is {int}")]
fn then_amount_minor_amount(world: &mut TestWorld, expected: i64) {
    assert_eq!(world.current_req["amount"]["minor_amount"], json!(expected));
}

// ---------------------------------------------------------------------------
// Scenario: Apply context map maps request field with req prefix
// ---------------------------------------------------------------------------

#[given(expr = "a dependency request with customer id {string}")]
fn given_dep_req_customer_id(world: &mut TestWorld, customer_id: String) {
    if let Some(entry) = world.context_map_collected.last_mut() {
        entry.1 = json!({"customer": {"id": customer_id}});
    }
}

#[given(expr = "a request with customer id {string}")]
fn given_req_customer_id(world: &mut TestWorld, customer_id: String) {
    world.current_req = json!({"customer": {"id": customer_id}});
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then(expr = "customer.id is {string}")]
fn then_customer_id(world: &mut TestWorld, expected: String) {
    assert_eq!(world.current_req["customer"]["id"], json!(expected));
}

// ---------------------------------------------------------------------------
// Scenario: Apply context map defaults to response when no prefix
// ---------------------------------------------------------------------------

#[given(expr = "a dependency response with connectorTransactionId id {string}")]
fn given_dep_res_connector_txn_id(world: &mut TestWorld, txn_id: String) {
    if let Some(entry) = world.context_map_collected.last_mut() {
        entry.2 = json!({"connectorTransactionId": {"id": txn_id}});
    }
}

#[given(expr = "a request with connector_transaction_id id {string}")]
fn given_req_connector_txn_id(world: &mut TestWorld, txn_id: String) {
    world.current_req = json!({"connector_transaction_id": {"id": txn_id}});
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then(expr = "connector_transaction_id.id is {string}")]
fn then_connector_txn_id_dot(world: &mut TestWorld, expected: String) {
    assert_eq!(
        world.current_req["connector_transaction_id"]["id"],
        json!(expected)
    );
}

// ---------------------------------------------------------------------------
// Scenario: Apply context map skips null source values
// ---------------------------------------------------------------------------

#[given("a dependency response without missing_field")]
fn given_dep_res_without_missing(world: &mut TestWorld) {
    if let Some(entry) = world.context_map_collected.last_mut() {
        entry.2 = json!({"other_field": "val"});
    }
}

#[given(expr = "a request with field_a {string}")]
fn given_req_field_a(world: &mut TestWorld, value: String) {
    world.current_req = json!({"field_a": value});
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then(expr = "field_a is {string}")]
fn then_field_a(world: &mut TestWorld, expected: String) {
    assert_eq!(world.current_req["field_a"], json!(expected));
}

// ---------------------------------------------------------------------------
// Scenario: Apply context map with multiple dependencies
// ---------------------------------------------------------------------------

#[given("two context maps with access_token and customer_id mappings")]
fn given_two_context_maps(world: &mut TestWorld) {
    let mut map1: ContextMap = HashMap::new();
    map1.insert(
        "state.access_token.token.value".to_string(),
        "res.access_token".to_string(),
    );

    let mut map2: ContextMap = HashMap::new();
    map2.insert("customer.id".to_string(), "res.customer_id".to_string());

    world.context_map_collected = vec![
        (map1, json!({}), json!({})),
        (map2, json!({}), json!({})),
    ];
}

#[given(expr = "dependency responses with access_token {string} and customer_id {string}")]
fn given_dep_res_access_token_and_customer_id(
    world: &mut TestWorld,
    token: String,
    customer_id: String,
) {
    world.context_map_collected[0].2 = json!({"access_token": token});
    world.context_map_collected[1].2 = json!({"customer_id": customer_id});
}

// ---------------------------------------------------------------------------
// Scenario: Apply context map with camelCase response lookup
// ---------------------------------------------------------------------------

#[given(expr = "a dependency response with tokenType {string}")]
fn given_dep_res_token_type(world: &mut TestWorld, token_type: String) {
    if let Some(entry) = world.context_map_collected.last_mut() {
        entry.2 = json!({"tokenType": token_type});
    }
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then(expr = "state.access_token.token_type is {string}")]
fn then_state_access_token_token_type(world: &mut TestWorld, expected: String) {
    assert_eq!(
        world.current_req["state"]["access_token"]["token_type"],
        json!(expected)
    );
}

// ---------------------------------------------------------------------------
// Scenario: Apply context map empty map is noop
// ---------------------------------------------------------------------------

#[given("an empty context map")]
fn given_empty_context_map(world: &mut TestWorld) {
    let context_map: ContextMap = HashMap::new();
    world.context_map_collected =
        vec![(context_map, json!({"some": "req"}), json!({"some": "res"}))];
}

#[given(expr = "a request with field {string}")]
fn given_req_field(world: &mut TestWorld, value: String) {
    world.current_req = json!({"field": value});
}

#[allow(clippy::needless_pass_by_ref_mut)]
#[then(expr = "field is {string}")]
fn then_field(world: &mut TestWorld, expected: String) {
    assert_eq!(world.current_req["field"], json!(expected));
}

// ---------------------------------------------------------------------------
// Scenario: Apply context map with id_type.id unwrapping
// ---------------------------------------------------------------------------

#[given(expr = "a dependency response with connectorTransactionId idType id {string}")]
fn given_dep_res_id_type_unwrap(world: &mut TestWorld, txn_id: String) {
    if let Some(entry) = world.context_map_collected.last_mut() {
        entry.2 = json!({
            "connectorTransactionId": {
                "idType": {
                    "id": txn_id
                }
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Scenario: Explicit context map overrides implicit context value
// ---------------------------------------------------------------------------

#[given("a request with empty state.access_token.token.value")]
fn given_req_empty_access_token_value(world: &mut TestWorld) {
    world.current_req = json!({"state": {"access_token": {"token": {"value": ""}}}});
}

#[given(expr = "implicit dependency responses set access_token to {string}")]
fn given_implicit_dep_res(world: &mut TestWorld, token: String) {
    world.prev_reqs = vec![];
    world.prev_res = vec![json!({"access_token": token})];
}

#[when("implicit context is applied")]
fn when_implicit_context_applied(world: &mut TestWorld) {
    add_context(&world.prev_reqs.clone(), &world.prev_res.clone(), &mut world.current_req);
}

#[when(expr = "explicit context map sets state.access_token.token.value from {string}")]
fn when_explicit_context_map(world: &mut TestWorld, token: String) {
    let mut context_map: ContextMap = HashMap::new();
    context_map.insert(
        "state.access_token.token.value".to_string(),
        "res.access_token".to_string(),
    );
    let explicit_dep_res = json!({"access_token": token});
    apply_context_map(
        &[(context_map, json!({}), explicit_dep_res)],
        &mut world.current_req,
    );
}

// ---------------------------------------------------------------------------
// Scenario: All supported scenarios match proto schema for all connectors
// ---------------------------------------------------------------------------

#[allow(clippy::needless_pass_by_ref_mut)]
#[then("every connector's scenarios match their proto schema")]
fn then_all_connectors_match_schema(_world: &mut TestWorld) {
    let connectors =
        discover_all_connectors().expect("connector discovery should work for schema checks");
    assert!(
        !connectors.is_empty(),
        "at least one connector must exist for schema checks"
    );

    let mut failures = Vec::new();

    for connector in &connectors {
        let suites = match load_supported_suites_for_connector(connector) {
            Ok(suites) => suites,
            Err(error) => {
                failures.push(format!(
                    "{connector}: failed to load supported suites: {error}"
                ));
                continue;
            }
        };

        for suite in suites {
            let suite_scenarios = match load_suite_scenarios(&suite) {
                Ok(file) => file,
                Err(error) => {
                    failures.push(format!(
                        "{connector}/{suite}: failed to load scenario file: {error}"
                    ));
                    continue;
                }
            };

            let mut scenario_names = suite_scenarios.keys().cloned().collect::<Vec<_>>();
            scenario_names.sort();

            for scenario in scenario_names {
                let grpc_req =
                    match get_the_grpc_req_for_connector(&suite, &scenario, connector) {
                        Ok(req) => req,
                        Err(error) => {
                            failures.push(format!(
                                "{connector}/{suite}/{scenario}: failed to build effective request: {error}"
                            ));
                            continue;
                        }
                    };

                if let Err(error) =
                    validate_suite_scenario_schema(connector, &suite, &scenario, &grpc_req)
                {
                    failures.push(error);
                }
            }
        }
    }

    assert!(
        failures.is_empty(),
        "proto schema compatibility failures:\n{}",
        failures.join("\n")
    );
}

// ---------------------------------------------------------------------------
// Scenario: All override entries match existing scenarios and proto schema
// ---------------------------------------------------------------------------

#[allow(clippy::needless_pass_by_ref_mut)]
#[then("every connector's override entries reference valid scenarios and match proto schema")]
fn then_all_overrides_match_schema(_world: &mut TestWorld) {
    let connectors =
        discover_all_connectors().expect("connector discovery should work for override checks");
    let mut failures = Vec::new();

    for connector in &connectors {
        let override_path = connector_spec_dir(connector).join("override.json");
        if !override_path.is_file() {
            continue;
        }

        let raw = match std::fs::read_to_string(&override_path) {
            Ok(content) => content,
            Err(error) => {
                failures.push(format!(
                    "{}: failed to read override file: {error}",
                    override_path.display()
                ));
                continue;
            }
        };

        let json: Value = match serde_json::from_str(&raw) {
            Ok(value) => value,
            Err(error) => {
                failures.push(format!(
                    "{}: failed to parse override JSON: {error}",
                    override_path.display()
                ));
                continue;
            }
        };

        let Some(suites_obj) = json.as_object() else {
            failures.push(format!(
                "{}: override root must be an object keyed by suite",
                override_path.display()
            ));
            continue;
        };

        for (suite, suite_value) in suites_obj {
            let suite_scenarios = match load_suite_scenarios(suite) {
                Ok(file) => file,
                Err(error) => {
                    failures.push(format!(
                        "{connector}/{suite}: override references unknown or invalid suite: {error}"
                    ));
                    continue;
                }
            };

            let Some(scenario_obj) = suite_value.as_object() else {
                failures.push(format!(
                    "{connector}/{suite}: override suite entry must be an object keyed by scenario"
                ));
                continue;
            };

            for scenario in scenario_obj.keys() {
                if !suite_scenarios.contains_key(scenario) {
                    failures.push(format!(
                        "{connector}/{suite}/{scenario}: override references missing scenario in suite file"
                    ));
                    continue;
                }

                let grpc_req =
                    match get_the_grpc_req_for_connector(suite, scenario, connector) {
                        Ok(req) => req,
                        Err(error) => {
                            failures.push(format!(
                                "{connector}/{suite}/{scenario}: failed to materialize request with override: {error}"
                            ));
                            continue;
                        }
                    };

                if let Err(error) =
                    validate_suite_scenario_schema(connector, suite, scenario, &grpc_req)
                {
                    failures.push(error);
                }
            }
        }
    }

    assert!(
        failures.is_empty(),
        "override schema compatibility failures:\n{}",
        failures.join("\n")
    );
}
