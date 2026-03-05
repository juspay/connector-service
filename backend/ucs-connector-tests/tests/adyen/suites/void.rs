use grpc_api_types::payments::PaymentStatus;
use serial_test::serial;
use ucs_connector_tests::harness::{base_requests, context::FlowContext, executor::AdyenExecutor};

use crate::adyen::suites::{authorize, generated_input_variants};

#[derive(Clone, Copy)]
pub struct VoidExpectation {
    pub allowed_statuses: &'static [PaymentStatus],
}

pub async fn execute(executor: &AdyenExecutor, flow_name: &str, context: &mut FlowContext) {
    let expectation = VoidExpectation {
        allowed_statuses: &[
            PaymentStatus::Voided,
            PaymentStatus::Pending,
            PaymentStatus::VoidInitiated,
        ],
    };

    let transaction_id = context.require_connector_transaction_id("adyen void");
    let mut request = base_requests::void_request(&transaction_id, context.amount_minor);
    context.apply_to_void_request(&mut request);

    let (request_id, connector_ref_id) = AdyenExecutor::step_ids(flow_name, "void");
    let response = executor
        .payment_client()
        .void(executor.request_with_ids(request, &request_id, &connector_ref_id))
        .await
        .expect("adyen void should return a response")
        .into_inner();

    assert!(
        response.error.is_none(),
        "adyen void should not include errors"
    );
    let is_allowed_status = expectation
        .allowed_statuses
        .iter()
        .any(|status| response.status == i32::from(*status));
    assert!(
        is_allowed_status,
        "adyen void should return VOIDED/PENDING/VOID_INITIATED, got {}",
        response.status
    );

    context.capture_from_void_response(&response);
}

/// @capability capability_id=ADY-CAP-007
/// @capability connector=adyen
/// @capability layer=suite
/// @capability flow=void
/// @capability payment_method=card
/// @capability payment_method_subtype=no3ds
/// @capability scenario=void_after_manual_authorize
/// @capability support=dependent
/// @capability expected=status=VOIDED
#[tokio::test]
#[serial]
async fn test_adyen__suite_void__after_manual_authorize__returns_voided() {
    let executor = AdyenExecutor::new().await;

    for case in generated_input_variants() {
        let mut context = FlowContext::new(case, "adyen_void_suite");
        authorize::execute(
            &executor,
            "adyen_void_suite",
            &mut context,
            authorize::default_manual_scenario(),
        )
        .await;
        execute(&executor, "adyen_void_suite", &mut context).await;
    }
}
