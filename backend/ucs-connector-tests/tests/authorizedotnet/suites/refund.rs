use grpc_api_types::payments::{RefundResponse, RefundStatus};
use serial_test::serial;
use ucs_connector_tests::harness::{
    base_requests, context::FlowContext, executor::AuthorizedotnetExecutor,
};

use crate::authorizedotnet::suites::{
    authorize, capture, create_customer, extract_id, generated_input_variants,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefundScenario {
    WithCustomerId,
    WithoutCustomerId,
}

#[derive(Clone)]
pub struct RefundOverrides {
    pub customer_id: Option<String>,
}

#[derive(Clone, Copy)]
pub struct RefundExpectation {
    pub allowed_statuses: &'static [RefundStatus],
    pub enforce_connector_signal: bool,
}

#[allow(dead_code)]
pub fn default_scenario() -> RefundScenario {
    RefundScenario::WithCustomerId
}

pub fn variants() -> &'static [RefundScenario] {
    &[
        RefundScenario::WithCustomerId,
        RefundScenario::WithoutCustomerId,
    ]
}

fn scenario_overrides(context: &FlowContext, scenario: RefundScenario) -> RefundOverrides {
    match scenario {
        RefundScenario::WithCustomerId => RefundOverrides {
            customer_id: Some(context.merchant_customer_id.clone()),
        },
        RefundScenario::WithoutCustomerId => RefundOverrides { customer_id: None },
    }
}

fn scenario_expectation(_scenario: RefundScenario) -> RefundExpectation {
    RefundExpectation {
        allowed_statuses: &[
            RefundStatus::RefundFailure,
            RefundStatus::RefundTransactionFailure,
        ],
        enforce_connector_signal: true,
    }
}

fn assert_expectation(
    response: &RefundResponse,
    expectation: RefundExpectation,
    merchant_refund_id: &str,
) {
    let is_allowed_status = expectation
        .allowed_statuses
        .iter()
        .any(|status| response.status == i32::from(*status));
    assert!(
        is_allowed_status,
        "Refund should return failure status for Authorize.Net refund path, got {}",
        response.status
    );

    if let Some(returned_merchant_refund_id) = extract_id(response.merchant_refund_id.as_ref()) {
        assert_eq!(
            returned_merchant_refund_id, merchant_refund_id,
            "merchant_refund_id should match request"
        );
    }

    if expectation.enforce_connector_signal {
        let has_connector_refund_id = !response.connector_refund_id.trim().is_empty();
        let connector_error_details = response
            .error
            .as_ref()
            .and_then(|error| error.connector_details.as_ref());

        let has_connector_error_details = connector_error_details.is_some_and(|connector| {
            let has_code = connector
                .code
                .as_deref()
                .map(|value| !value.trim().is_empty())
                .unwrap_or(false);
            let has_message = connector
                .message
                .as_deref()
                .map(|value| !value.trim().is_empty())
                .unwrap_or(false);
            has_code && has_message
        });

        assert!(
            has_connector_error_details || has_connector_refund_id,
            "Refund non-success should include connector error details or connector_refund_id"
        );

        if response.status == i32::from(RefundStatus::RefundFailure)
            || response.status == i32::from(RefundStatus::RefundTransactionFailure)
        {
            assert!(
                has_connector_error_details,
                "Refund failure statuses should include connector error details"
            );
        }
    }
}

pub async fn execute(
    executor: &AuthorizedotnetExecutor,
    flow_name: &str,
    context: &mut FlowContext,
    scenario: RefundScenario,
) {
    let overrides = scenario_overrides(context, scenario);
    let expectation = scenario_expectation(scenario);

    let transaction_id = context.require_connector_transaction_id("refund");
    let merchant_refund_id = context.next_merchant_refund_id(flow_name);

    let mut request = base_requests::refund_request(
        &transaction_id,
        &merchant_refund_id,
        context.amount_minor,
        overrides.customer_id,
    );
    context.apply_to_refund_request(&mut request);

    assert!(
        request.metadata.is_some(),
        "Authorize.Net refund request should inherit metadata from previous request context"
    );

    let step = format!("refund_{scenario:?}");
    let (request_id, connector_ref_id) = AuthorizedotnetExecutor::step_ids(flow_name, &step);
    let response = executor
        .payment_client()
        .refund(executor.request_with_ids(request, &request_id, &connector_ref_id))
        .await
        .expect("refund should return a response")
        .into_inner();

    assert_expectation(&response, expectation, &merchant_refund_id);
    context.capture_from_refund_response(&response);
}

/// @capability capability_id=ANET-CAP-005
/// @capability connector=authorizedotnet
/// @capability layer=suite
/// @capability flow=refund
/// @capability payment_method=card
/// @capability payment_method_subtype=no3ds
/// @capability scenario=after_manual_authorize_and_capture_with_and_without_customer_id
/// @capability support=dependent
/// @capability expected=status=REFUND_FAILURE_or_REFUND_TRANSACTION_FAILURE_with_connector_signal
#[tokio::test]
#[serial]
async fn test_authorizedotnet__suite_refund__after_manual_authorize_and_capture__with_and_without_customer_id__returns_failure_with_connector_signal(
) {
    let executor = AuthorizedotnetExecutor::new().await;

    for case in generated_input_variants() {
        for variant in variants() {
            let mut context = FlowContext::new(case.clone(), "refund_suite");
            create_customer::execute(
                &executor,
                "refund_suite",
                &mut context,
                create_customer::default_scenario(),
            )
            .await;
            authorize::execute(
                &executor,
                "refund_suite",
                &mut context,
                authorize::default_manual_scenario(),
            )
            .await;
            capture::execute(
                &executor,
                "refund_suite",
                &mut context,
                capture::default_scenario(),
            )
            .await;
            execute(&executor, "refund_suite", &mut context, *variant).await;
        }
    }
}
