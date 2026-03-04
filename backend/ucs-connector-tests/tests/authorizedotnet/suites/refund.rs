use grpc_api_types::payments::RefundStatus;
use serial_test::serial;
use ucs_connector_tests::harness::{
    base_requests, context::FlowContext, executor::AuthorizedotnetExecutor,
};

use crate::authorizedotnet::suites::{
    authorize, capture, create_customer, extract_id, generated_cases,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefundScenario {
    WithCustomerId,
    WithoutCustomerId,
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

pub async fn execute(
    executor: &AuthorizedotnetExecutor,
    flow_name: &str,
    context: &mut FlowContext,
    scenario: RefundScenario,
) {
    let transaction_id = context.require_connector_transaction_id("refund");
    let merchant_refund_id = context.next_merchant_refund_id(flow_name);
    let customer_id = match scenario {
        RefundScenario::WithCustomerId => Some(context.merchant_customer_id.clone()),
        RefundScenario::WithoutCustomerId => None,
    };

    let request = base_requests::refund_request(
        &transaction_id,
        &merchant_refund_id,
        context.amount_minor,
        customer_id,
    );
    let step = format!("refund_{scenario:?}");
    let (request_id, connector_ref_id) = AuthorizedotnetExecutor::step_ids(flow_name, &step);
    let response = executor
        .payment_client()
        .refund(executor.request_with_ids(request, &request_id, &connector_ref_id))
        .await
        .expect("refund should return a response")
        .into_inner();

    assert_ne!(
        response.status,
        i32::from(RefundStatus::RefundSuccess),
        "Refund scenario should not return REFUND_SUCCESS for immediate refund path"
    );

    if let Some(returned_merchant_refund_id) = extract_id(response.merchant_refund_id.as_ref()) {
        assert_eq!(
            returned_merchant_refund_id, merchant_refund_id,
            "merchant_refund_id should match request"
        );
    }

    let has_connector_refund_id = !response.connector_refund_id.trim().is_empty();
    let connector_error_details = response
        .error
        .as_ref()
        .and_then(|error| error.connector_details.as_ref());

    let has_connector_error_details = connector_error_details.is_some_and(|connector| {
        connector
            .code
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
            && connector
                .message
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty())
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

/// @capability capability_id=ANET-CAP-005
/// @capability connector=authorizedotnet
/// @capability layer=suite
/// @capability flow=refund
/// @capability payment_method=card
/// @capability payment_method_subtype=no3ds
/// @capability scenario=after_manual_authorize_and_capture_with_and_without_customer_id
/// @capability support=dependent
/// @capability expected=non_success_with_connector_signal
#[tokio::test]
#[serial]
async fn test_authorizedotnet__suite_refund__after_manual_authorize_and_capture__with_and_without_customer_id__returns_non_success_with_connector_signal(
) {
    let executor = AuthorizedotnetExecutor::new().await;

    for case in generated_cases() {
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
