use grpc_api_types::payments::RefundStatus;
use serial_test::serial;
use ucs_connector_tests::harness::{base_requests, context::FlowContext, executor::StripeExecutor};

use crate::stripe::suites::{authorize, capture, generated_input_variants};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefundScenario {
    FullRefund,
    PartialRefund,
}

#[derive(Clone, Copy)]
pub struct RefundOverrides {
    pub refund_amount: i64,
}

#[derive(Clone, Copy)]
pub struct RefundExpectation {
    pub allowed_statuses: &'static [RefundStatus],
}

fn scenario_overrides(context: &FlowContext, scenario: RefundScenario) -> RefundOverrides {
    match scenario {
        RefundScenario::FullRefund => RefundOverrides {
            refund_amount: context.amount_minor,
        },
        RefundScenario::PartialRefund => RefundOverrides {
            refund_amount: std::cmp::max(1, context.amount_minor / 3),
        },
    }
}

fn scenario_expectation(_scenario: RefundScenario) -> RefundExpectation {
    RefundExpectation {
        allowed_statuses: &[RefundStatus::RefundSuccess, RefundStatus::RefundPending],
    }
}

pub async fn execute(
    executor: &StripeExecutor,
    flow_name: &str,
    context: &mut FlowContext,
    scenario: RefundScenario,
) {
    let overrides = scenario_overrides(context, scenario);
    let expectation = scenario_expectation(scenario);

    let transaction_id = context.require_connector_transaction_id("stripe refund");
    let merchant_refund_id = context.next_merchant_refund_id(flow_name);
    let mut request = base_requests::refund_request_for_connector(
        "stripe",
        &transaction_id,
        &merchant_refund_id,
        overrides.refund_amount,
        Some(context.merchant_customer_id.clone()),
    );
    context.apply_to_refund_request(&mut request);

    let step = format!("refund_{scenario:?}");
    let (request_id, connector_ref_id) = StripeExecutor::step_ids(flow_name, &step);
    let response = executor
        .payment_client()
        .refund(executor.request_with_ids(request, &request_id, &connector_ref_id))
        .await
        .expect("stripe refund should return a response")
        .into_inner();

    let is_allowed_status = expectation
        .allowed_statuses
        .iter()
        .any(|status| response.status == i32::from(*status));
    assert!(
        is_allowed_status,
        "stripe refund returned unexpected status {}",
        response.status
    );

    let has_connector_refund_id = !response.connector_refund_id.trim().is_empty();
    assert!(
        response.error.is_none() || has_connector_refund_id,
        "stripe refund should return no error or a connector_refund_id"
    );

    context.capture_from_refund_response(&response);
}

/// @capability capability_id=STP-CAP-008
/// @capability connector=stripe
/// @capability layer=suite
/// @capability flow=refund
/// @capability payment_method=card
/// @capability payment_method_subtype=no3ds
/// @capability scenario=full_refund_after_manual_authorize_and_capture
/// @capability support=dependent
/// @capability expected=status=REFUND_SUCCESS_or_REFUND_PENDING
#[tokio::test]
#[serial]
async fn test_stripe__suite_refund__full_refund_after_manual_authorize_and_capture__returns_expected_refund_status(
) {
    let executor = StripeExecutor::new().await;

    for case in generated_input_variants() {
        let mut context = FlowContext::new(case, "stripe_refund_full_suite");
        authorize::execute(
            &executor,
            "stripe_refund_full_suite",
            &mut context,
            authorize::default_manual_scenario(),
        )
        .await;
        capture::execute(
            &executor,
            "stripe_refund_full_suite",
            &mut context,
            capture::CaptureScenario::FullCapture,
        )
        .await;
        execute(
            &executor,
            "stripe_refund_full_suite",
            &mut context,
            RefundScenario::FullRefund,
        )
        .await;
    }
}

/// @capability capability_id=STP-CAP-009
/// @capability connector=stripe
/// @capability layer=suite
/// @capability flow=refund
/// @capability payment_method=card
/// @capability payment_method_subtype=no3ds
/// @capability scenario=partial_refund_after_manual_authorize_and_capture
/// @capability support=dependent
/// @capability expected=status=REFUND_SUCCESS_or_REFUND_PENDING
#[tokio::test]
#[serial]
async fn test_stripe__suite_refund__partial_refund_after_manual_authorize_and_capture__returns_expected_partial_refund_status(
) {
    let executor = StripeExecutor::new().await;

    for case in generated_input_variants() {
        let mut context = FlowContext::new(case, "stripe_refund_partial_suite");
        authorize::execute(
            &executor,
            "stripe_refund_partial_suite",
            &mut context,
            authorize::default_manual_scenario(),
        )
        .await;
        capture::execute(
            &executor,
            "stripe_refund_partial_suite",
            &mut context,
            capture::CaptureScenario::FullCapture,
        )
        .await;
        execute(
            &executor,
            "stripe_refund_partial_suite",
            &mut context,
            RefundScenario::PartialRefund,
        )
        .await;
    }
}
