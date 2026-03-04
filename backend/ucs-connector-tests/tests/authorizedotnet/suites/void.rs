use grpc_api_types::payments::PaymentStatus;
use serial_test::serial;
use ucs_connector_tests::harness::{
    base_requests, context::FlowContext, executor::AuthorizedotnetExecutor,
};

use crate::authorizedotnet::suites::{authorize, create_customer, generated_cases};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VoidScenario {
    Default,
}

pub fn default_scenario() -> VoidScenario {
    VoidScenario::Default
}

pub fn variants() -> &'static [VoidScenario] {
    &[VoidScenario::Default]
}

pub async fn execute(
    executor: &AuthorizedotnetExecutor,
    flow_name: &str,
    context: &mut FlowContext,
    scenario: VoidScenario,
) {
    let transaction_id = context.require_connector_transaction_id("void");
    let request = match scenario {
        VoidScenario::Default => base_requests::void_request(&transaction_id, context.amount_minor),
    };

    let step = format!("void_{scenario:?}");
    let (request_id, connector_ref_id) = AuthorizedotnetExecutor::step_ids(flow_name, &step);
    let response = executor
        .payment_client()
        .void(executor.request_with_ids(request, &request_id, &connector_ref_id))
        .await
        .expect("void should return a response")
        .into_inner();

    assert!(
        response.error.is_none(),
        "Void should not include error details"
    );
    assert_eq!(
        response.status,
        i32::from(PaymentStatus::Voided),
        "Void should return VOIDED"
    );
}

/// @capability capability_id=ANET-CAP-004
/// @capability connector=authorizedotnet
/// @capability layer=suite
/// @capability flow=void
/// @capability payment_method=card
/// @capability payment_method_subtype=no3ds
/// @capability scenario=after_manual_authorize
/// @capability support=dependent
/// @capability expected=status=VOIDED
#[tokio::test]
#[serial]
async fn test_authorizedotnet__suite_void__after_manual_authorize__returns_voided() {
    let executor = AuthorizedotnetExecutor::new().await;

    for case in generated_cases() {
        let mut context = FlowContext::new(case, "void_suite");
        create_customer::execute(
            &executor,
            "void_suite",
            &mut context,
            create_customer::default_scenario(),
        )
        .await;
        authorize::execute(
            &executor,
            "void_suite",
            &mut context,
            authorize::default_manual_scenario(),
        )
        .await;
        execute(&executor, "void_suite", &mut context, default_scenario()).await;
    }
}
