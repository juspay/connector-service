use grpc_api_types::payments::PaymentStatus;
use serial_test::serial;
use ucs_connector_tests::harness::{base_requests, context::FlowContext, executor::StripeExecutor};

use crate::stripe::suites::{authorize, generated_input_variants};

#[derive(Clone, Copy)]
pub struct VoidExpectation {
    pub expected_status: PaymentStatus,
}

pub async fn execute(executor: &StripeExecutor, flow_name: &str, context: &mut FlowContext) {
    let expectation = VoidExpectation {
        expected_status: PaymentStatus::Voided,
    };

    let transaction_id = context.require_connector_transaction_id("stripe void");
    let mut request = base_requests::void_request(&transaction_id, context.amount_minor);
    context.apply_to_void_request(&mut request);

    let (request_id, connector_ref_id) = StripeExecutor::step_ids(flow_name, "void");
    let response = executor
        .payment_client()
        .void(executor.request_with_ids(request, &request_id, &connector_ref_id))
        .await
        .expect("stripe void should return a response")
        .into_inner();

    assert!(
        response.error.is_none(),
        "stripe void should not include errors"
    );
    assert_eq!(
        response.status,
        i32::from(expectation.expected_status),
        "stripe void should return VOIDED"
    );

    context.capture_from_void_response(&response);
}

/// @capability capability_id=STP-CAP-007
/// @capability connector=stripe
/// @capability layer=suite
/// @capability flow=void
/// @capability payment_method=card
/// @capability payment_method_subtype=no3ds
/// @capability scenario=void_after_manual_authorize
/// @capability support=dependent
/// @capability expected=status=VOIDED
#[tokio::test]
#[serial]
async fn test_stripe__suite_void__after_manual_authorize__returns_voided() {
    let executor = StripeExecutor::new().await;

    for case in generated_input_variants() {
        let mut context = FlowContext::new(case, "stripe_void_suite");
        authorize::execute(
            &executor,
            "stripe_void_suite",
            &mut context,
            authorize::default_manual_scenario(),
        )
        .await;
        execute(&executor, "stripe_void_suite", &mut context).await;
    }
}
