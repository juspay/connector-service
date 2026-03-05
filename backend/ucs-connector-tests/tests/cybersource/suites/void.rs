use grpc_api_types::payments::PaymentStatus;
use serial_test::serial;
use ucs_connector_tests::harness::{
    base_requests, context::FlowContext, executor::CybersourceExecutor,
};

use crate::cybersource::suites::{authorize, generated_input_variants};

#[derive(Clone, Copy)]
pub struct VoidExpectation {
    pub expected_status: PaymentStatus,
}

pub async fn execute(executor: &CybersourceExecutor, flow_name: &str, context: &mut FlowContext) {
    let expectation = VoidExpectation {
        expected_status: PaymentStatus::Voided,
    };

    let transaction_id = context.require_connector_transaction_id("cybersource void");
    let mut request = base_requests::void_request_for_connector(
        "cybersource",
        &transaction_id,
        context.amount_minor,
    );
    context.apply_to_void_request(&mut request);

    let (request_id, connector_ref_id) = CybersourceExecutor::step_ids(flow_name, "void");
    let response = executor
        .payment_client()
        .void(executor.request_with_ids(request, &request_id, &connector_ref_id))
        .await
        .expect("cybersource void should return a response")
        .into_inner();

    assert!(
        response.error.is_none(),
        "cybersource void should not include errors"
    );
    assert_eq!(
        response.status,
        i32::from(expectation.expected_status),
        "cybersource void should return VOIDED"
    );

    context.capture_from_void_response(&response);
}

/// @capability capability_id=CYB-CAP-007
/// @capability connector=cybersource
/// @capability layer=suite
/// @capability flow=void
/// @capability payment_method=card
/// @capability payment_method_subtype=no3ds
/// @capability scenario=void_after_manual_authorize
/// @capability support=dependent
/// @capability expected=status=VOIDED
#[tokio::test]
#[serial]
async fn test_cybersource__suite_void__after_manual_authorize__returns_voided() {
    let executor = CybersourceExecutor::new().await;

    for case in generated_input_variants() {
        let mut context = FlowContext::new(case, "cybersource_void_suite");
        authorize::execute(
            &executor,
            "cybersource_void_suite",
            &mut context,
            authorize::default_manual_scenario(),
        )
        .await;
        execute(&executor, "cybersource_void_suite", &mut context).await;
    }
}
