use grpc_api_types::payments::PaymentStatus;
use serial_test::serial;
use ucs_connector_tests::harness::{
    base_requests, context::FlowContext, executor::AuthorizedotnetExecutor,
};

use crate::authorizedotnet::suites::{
    authorize, create_customer, extract_id, generated_input_variants,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaptureScenario {
    Default,
}

#[derive(Clone, Copy)]
pub struct CaptureOverrides {
    pub amount_to_capture_minor: i64,
}

#[derive(Clone, Copy)]
pub struct CaptureExpectation {
    pub expected_status: PaymentStatus,
    pub require_no_error: bool,
    pub require_connector_transaction_id: bool,
}

pub fn default_scenario() -> CaptureScenario {
    CaptureScenario::Default
}

#[allow(dead_code)]
pub fn variants() -> &'static [CaptureScenario] {
    &[CaptureScenario::Default]
}

fn scenario_overrides(context: &FlowContext, scenario: CaptureScenario) -> CaptureOverrides {
    match scenario {
        CaptureScenario::Default => CaptureOverrides {
            amount_to_capture_minor: context.amount_minor,
        },
    }
}

fn scenario_expectation(scenario: CaptureScenario) -> CaptureExpectation {
    match scenario {
        CaptureScenario::Default => CaptureExpectation {
            expected_status: PaymentStatus::Charged,
            require_no_error: true,
            require_connector_transaction_id: true,
        },
    }
}

fn assert_expectation(
    response: &grpc_api_types::payments::PaymentServiceCaptureResponse,
    expectation: CaptureExpectation,
) {
    if expectation.require_no_error {
        assert!(
            response.error.is_none(),
            "Capture should not include error details"
        );
    }

    assert_eq!(
        response.status,
        i32::from(expectation.expected_status),
        "Capture should return expected status"
    );

    if expectation.require_connector_transaction_id {
        assert!(
            extract_id(response.connector_transaction_id.as_ref()).is_some(),
            "Capture should return connector_transaction_id"
        );
    }
}

pub async fn execute(
    executor: &AuthorizedotnetExecutor,
    flow_name: &str,
    context: &mut FlowContext,
    scenario: CaptureScenario,
) {
    let overrides = scenario_overrides(context, scenario);
    let expectation = scenario_expectation(scenario);

    let transaction_id = context.require_connector_transaction_id("capture");
    let mut request =
        base_requests::capture_request(&transaction_id, overrides.amount_to_capture_minor);
    context.apply_to_capture_request(&mut request);

    let step = format!("capture_{scenario:?}");
    let (request_id, connector_ref_id) = AuthorizedotnetExecutor::step_ids(flow_name, &step);
    let response = executor
        .payment_client()
        .capture(executor.request_with_ids(request, &request_id, &connector_ref_id))
        .await
        .expect("capture should return a response")
        .into_inner();

    assert_expectation(&response, expectation);

    let capture_txn_id = extract_id(response.connector_transaction_id.as_ref());
    context.set_connector_transaction_id(capture_txn_id);
    context.capture_from_capture_response(&response);
}

/// @capability capability_id=ANET-CAP-002
/// @capability connector=authorizedotnet
/// @capability layer=suite
/// @capability flow=capture
/// @capability payment_method=card
/// @capability payment_method_subtype=no3ds
/// @capability scenario=after_manual_authorize
/// @capability support=dependent
/// @capability expected=status=CHARGED and connector_transaction_id present
#[tokio::test]
#[serial]
async fn test_authorizedotnet__suite_capture__after_manual_authorize__returns_charged_and_connector_transaction_id(
) {
    let executor = AuthorizedotnetExecutor::new().await;

    for case in generated_input_variants() {
        let mut context = FlowContext::new(case, "capture_suite");
        create_customer::execute(
            &executor,
            "capture_suite",
            &mut context,
            create_customer::default_scenario(),
        )
        .await;
        authorize::execute(
            &executor,
            "capture_suite",
            &mut context,
            authorize::default_manual_scenario(),
        )
        .await;
        execute(&executor, "capture_suite", &mut context, default_scenario()).await;
    }
}
