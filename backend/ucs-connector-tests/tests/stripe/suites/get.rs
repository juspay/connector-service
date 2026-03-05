use grpc_api_types::payments::PaymentStatus;
use serial_test::serial;
use ucs_connector_tests::harness::{base_requests, context::FlowContext, executor::StripeExecutor};

use crate::stripe::suites::{authorize, capture, generated_input_variants};

#[derive(Clone, Copy)]
pub struct GetExpectation {
    pub allowed_statuses: &'static [PaymentStatus],
    pub max_attempts: usize,
}

pub async fn execute(executor: &StripeExecutor, flow_name: &str, context: &mut FlowContext) {
    let expectation = GetExpectation {
        allowed_statuses: &[
            PaymentStatus::Charged,
            PaymentStatus::Authorized,
            PaymentStatus::Pending,
        ],
        max_attempts: 3,
    };

    let transaction_id = context.require_connector_transaction_id("stripe get");

    for attempt in 0..expectation.max_attempts {
        let mut request = base_requests::get_request(&transaction_id, context.amount_minor);
        context.apply_to_get_request(&mut request);

        let step = format!("get_{attempt}");
        let (request_id, connector_ref_id) = StripeExecutor::step_ids(flow_name, &step);
        let response = executor
            .payment_client()
            .get(executor.request_with_ids(request, &request_id, &connector_ref_id))
            .await
            .expect("stripe get should return a response")
            .into_inner();

        context.capture_from_get_response(&response);

        let is_allowed_status = expectation
            .allowed_statuses
            .iter()
            .any(|status| response.status == i32::from(*status));

        if response.error.is_none() && is_allowed_status {
            return;
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
    }

    panic!("stripe get did not settle to an expected success status");
}

/// @capability capability_id=STP-CAP-006
/// @capability connector=stripe
/// @capability layer=suite
/// @capability flow=get
/// @capability payment_method=card
/// @capability payment_method_subtype=no3ds
/// @capability scenario=sync_after_manual_authorize_and_capture
/// @capability support=dependent
/// @capability expected=status=CHARGED_or_AUTHORIZED_or_PENDING_without_error
#[tokio::test]
#[serial]
async fn test_stripe__suite_get__after_manual_authorize_and_capture__returns_success_sync_status() {
    let executor = StripeExecutor::new().await;

    for case in generated_input_variants() {
        let mut context = FlowContext::new(case, "stripe_get_suite");
        authorize::execute(
            &executor,
            "stripe_get_suite",
            &mut context,
            authorize::default_manual_scenario(),
        )
        .await;
        capture::execute(
            &executor,
            "stripe_get_suite",
            &mut context,
            capture::CaptureScenario::FullCapture,
        )
        .await;
        execute(&executor, "stripe_get_suite", &mut context).await;
    }
}
