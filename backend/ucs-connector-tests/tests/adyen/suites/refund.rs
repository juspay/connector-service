use grpc_api_types::payments::RefundStatus;
use serial_test::serial;
use ucs_connector_tests::harness::{base_requests, context::FlowContext, executor::AdyenExecutor};

use crate::adyen::suites::{authorize, generated_input_variants};

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
        allowed_statuses: &[RefundStatus::RefundPending, RefundStatus::RefundSuccess],
    }
}

pub async fn execute(
    executor: &AdyenExecutor,
    flow_name: &str,
    context: &mut FlowContext,
    scenario: RefundScenario,
) {
    let overrides = scenario_overrides(context, scenario);
    let expectation = scenario_expectation(scenario);

    let transaction_id = context.require_connector_transaction_id("adyen refund");
    let merchant_refund_id = context.next_merchant_refund_id(flow_name);
    let mut request = base_requests::refund_request_for_connector(
        "adyen",
        &transaction_id,
        &merchant_refund_id,
        overrides.refund_amount,
        Some(context.merchant_customer_id.clone()),
    );
    context.apply_to_refund_request(&mut request);

    let step = format!("refund_{scenario:?}");
    let (request_id, connector_ref_id) = AdyenExecutor::step_ids(flow_name, &step);
    let response = executor
        .payment_client()
        .refund(executor.request_with_ids(request, &request_id, &connector_ref_id))
        .await
        .expect("adyen refund should return a response")
        .into_inner();

    let is_allowed_status = expectation
        .allowed_statuses
        .iter()
        .any(|status| response.status == i32::from(*status));
    assert!(
        is_allowed_status,
        "adyen refund returned unexpected status {} error={:?} connector_refund_id='{}'",
        response.status, response.error, response.connector_refund_id
    );

    let has_connector_refund_id = !response.connector_refund_id.trim().is_empty();
    assert!(
        response.error.is_none() || has_connector_refund_id,
        "adyen refund should return no error or a connector_refund_id"
    );

    context.capture_from_refund_response(&response);
}

/// @capability capability_id=ADY-CAP-008
/// @capability connector=adyen
/// @capability layer=suite
/// @capability flow=refund
/// @capability payment_method=card
/// @capability payment_method_subtype=no3ds
/// @capability scenario=full_refund_after_no3ds_auto_capture
/// @capability support=dependent
/// @capability expected=status=REFUND_PENDING_or_REFUND_SUCCESS
#[tokio::test]
#[serial]
async fn test_adyen__suite_refund__full_refund_after_no3ds_auto_capture__returns_expected_refund_status(
) {
    let executor = AdyenExecutor::new().await;

    for case in generated_input_variants() {
        let mut context = FlowContext::new(case, "adyen_refund_full_suite");
        authorize::execute(
            &executor,
            "adyen_refund_full_suite",
            &mut context,
            authorize::AuthorizeScenario::No3dsAutoCapture,
        )
        .await;
        execute(
            &executor,
            "adyen_refund_full_suite",
            &mut context,
            RefundScenario::FullRefund,
        )
        .await;
    }
}

/// @capability capability_id=ADY-CAP-009
/// @capability connector=adyen
/// @capability layer=suite
/// @capability flow=refund
/// @capability payment_method=card
/// @capability payment_method_subtype=no3ds
/// @capability scenario=partial_refund_after_no3ds_auto_capture
/// @capability support=dependent
/// @capability expected=status=REFUND_PENDING_or_REFUND_SUCCESS
#[tokio::test]
#[serial]
async fn test_adyen__suite_refund__partial_refund_after_no3ds_auto_capture__returns_expected_partial_refund_status(
) {
    let executor = AdyenExecutor::new().await;

    for case in generated_input_variants() {
        let mut context = FlowContext::new(case, "adyen_refund_partial_suite");
        authorize::execute(
            &executor,
            "adyen_refund_partial_suite",
            &mut context,
            authorize::AuthorizeScenario::No3dsAutoCapture,
        )
        .await;
        execute(
            &executor,
            "adyen_refund_partial_suite",
            &mut context,
            RefundScenario::PartialRefund,
        )
        .await;
    }
}
