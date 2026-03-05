use grpc_api_types::payments::{CaptureMethod, PaymentStatus};
use serial_test::serial;
use ucs_connector_tests::harness::{base_requests, context::FlowContext, executor::StripeExecutor};

use crate::stripe::suites::{authorize, generated_input_variants};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaptureScenario {
    FullCapture,
    PartialCapture,
}

#[derive(Clone, Copy)]
pub struct CaptureOverrides {
    pub amount_to_capture: i64,
}

#[derive(Clone, Copy)]
pub struct CaptureExpectation {
    pub allowed_statuses: &'static [PaymentStatus],
}

fn scenario_overrides(context: &FlowContext, scenario: CaptureScenario) -> CaptureOverrides {
    match scenario {
        CaptureScenario::FullCapture => CaptureOverrides {
            amount_to_capture: context.amount_minor,
        },
        CaptureScenario::PartialCapture => CaptureOverrides {
            amount_to_capture: std::cmp::max(1, context.amount_minor / 3),
        },
    }
}

fn scenario_expectation(_scenario: CaptureScenario) -> CaptureExpectation {
    CaptureExpectation {
        allowed_statuses: &[PaymentStatus::Charged, PaymentStatus::Pending],
    }
}

pub async fn execute(
    executor: &StripeExecutor,
    flow_name: &str,
    context: &mut FlowContext,
    scenario: CaptureScenario,
) {
    let overrides = scenario_overrides(context, scenario);
    let expectation = scenario_expectation(scenario);

    let transaction_id = context.require_connector_transaction_id("stripe capture");
    let mut request = base_requests::capture_request(&transaction_id, overrides.amount_to_capture);
    request.capture_method = Some(i32::from(CaptureMethod::Manual));
    context.apply_to_capture_request(&mut request);

    let step = format!("capture_{scenario:?}");
    let (request_id, connector_ref_id) = StripeExecutor::step_ids(flow_name, &step);
    let response = executor
        .payment_client()
        .capture(executor.request_with_ids(request, &request_id, &connector_ref_id))
        .await
        .expect("stripe capture should return a response")
        .into_inner();

    assert!(
        response.error.is_none(),
        "stripe capture should not have errors"
    );
    let is_allowed = expectation
        .allowed_statuses
        .iter()
        .any(|status| response.status == i32::from(*status));
    assert!(
        is_allowed,
        "stripe capture returned unexpected status {}",
        response.status
    );

    context.capture_from_capture_response(&response);
}

/// @capability capability_id=STP-CAP-004
/// @capability connector=stripe
/// @capability layer=suite
/// @capability flow=capture
/// @capability payment_method=card
/// @capability payment_method_subtype=no3ds
/// @capability scenario=capture_full_after_manual_authorize
/// @capability support=dependent
/// @capability expected=status=CHARGED_or_PENDING
#[tokio::test]
#[serial]
async fn test_stripe__suite_capture__full_capture_after_manual_authorize__returns_expected_capture_status(
) {
    let executor = StripeExecutor::new().await;

    for case in generated_input_variants() {
        let mut context = FlowContext::new(case, "stripe_capture_full_suite");
        authorize::execute(
            &executor,
            "stripe_capture_full_suite",
            &mut context,
            authorize::default_manual_scenario(),
        )
        .await;
        execute(
            &executor,
            "stripe_capture_full_suite",
            &mut context,
            CaptureScenario::FullCapture,
        )
        .await;
    }
}

/// @capability capability_id=STP-CAP-005
/// @capability connector=stripe
/// @capability layer=suite
/// @capability flow=capture
/// @capability payment_method=card
/// @capability payment_method_subtype=no3ds
/// @capability scenario=partial_capture_after_manual_authorize
/// @capability support=dependent
/// @capability expected=status=CHARGED_or_PENDING
#[tokio::test]
#[serial]
async fn test_stripe__suite_capture__partial_capture_after_manual_authorize__returns_expected_partial_capture_status(
) {
    let executor = StripeExecutor::new().await;

    for case in generated_input_variants() {
        let mut context = FlowContext::new(case, "stripe_capture_partial_suite");
        authorize::execute(
            &executor,
            "stripe_capture_partial_suite",
            &mut context,
            authorize::default_manual_scenario(),
        )
        .await;
        execute(
            &executor,
            "stripe_capture_partial_suite",
            &mut context,
            CaptureScenario::PartialCapture,
        )
        .await;
    }
}
