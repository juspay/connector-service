use grpc_api_types::payments::PaymentStatus;
use serial_test::serial;
use ucs_connector_tests::harness::{
    base_requests, context::FlowContext, executor::AuthorizedotnetExecutor,
};

use crate::authorizedotnet::suites::{authorize, create_customer, extract_id, generated_cases};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaptureScenario {
    Default,
}

pub fn default_scenario() -> CaptureScenario {
    CaptureScenario::Default
}

#[allow(dead_code)]
pub fn variants() -> &'static [CaptureScenario] {
    &[CaptureScenario::Default]
}

pub async fn execute(
    executor: &AuthorizedotnetExecutor,
    flow_name: &str,
    context: &mut FlowContext,
    scenario: CaptureScenario,
) {
    let transaction_id = context.require_connector_transaction_id("capture");
    let request = match scenario {
        CaptureScenario::Default => {
            base_requests::capture_request(&transaction_id, context.amount_minor)
        }
    };

    let step = format!("capture_{scenario:?}");
    let (request_id, connector_ref_id) = AuthorizedotnetExecutor::step_ids(flow_name, &step);
    let response = executor
        .payment_client()
        .capture(executor.request_with_ids(request, &request_id, &connector_ref_id))
        .await
        .expect("capture should return a response")
        .into_inner();

    assert!(
        response.error.is_none(),
        "Capture should not include error details"
    );
    assert_eq!(
        response.status,
        i32::from(PaymentStatus::Charged),
        "Capture should return CHARGED"
    );

    let capture_txn_id = extract_id(response.connector_transaction_id.as_ref());
    context.set_connector_transaction_id(capture_txn_id);
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

    for case in generated_cases() {
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
