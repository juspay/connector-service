use grpc_api_types::payments::PaymentStatus;
use serial_test::serial;
use ucs_connector_tests::harness::{
    base_requests, context::FlowContext, executor::AuthorizedotnetExecutor,
};

use crate::authorizedotnet::suites::{authorize, create_customer, generated_input_variants};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VoidScenario {
    Default,
}

#[derive(Clone, Copy)]
pub struct VoidOverrides {
    pub amount_minor: i64,
}

#[derive(Clone, Copy)]
pub struct VoidExpectation {
    pub expected_status: PaymentStatus,
    pub require_no_error: bool,
}

pub fn default_scenario() -> VoidScenario {
    VoidScenario::Default
}

pub fn variants() -> &'static [VoidScenario] {
    &[VoidScenario::Default]
}

fn scenario_overrides(context: &FlowContext, scenario: VoidScenario) -> VoidOverrides {
    match scenario {
        VoidScenario::Default => VoidOverrides {
            amount_minor: context.amount_minor,
        },
    }
}

fn scenario_expectation(scenario: VoidScenario) -> VoidExpectation {
    match scenario {
        VoidScenario::Default => VoidExpectation {
            expected_status: PaymentStatus::Voided,
            require_no_error: true,
        },
    }
}

pub async fn execute(
    executor: &AuthorizedotnetExecutor,
    flow_name: &str,
    context: &mut FlowContext,
    scenario: VoidScenario,
) {
    let overrides = scenario_overrides(context, scenario);
    let expectation = scenario_expectation(scenario);

    let transaction_id = context.require_connector_transaction_id("void");
    let mut request = base_requests::void_request(&transaction_id, overrides.amount_minor);
    context.apply_to_void_request(&mut request);

    let step = format!("void_{scenario:?}");
    let (request_id, connector_ref_id) = AuthorizedotnetExecutor::step_ids(flow_name, &step);
    let response = executor
        .payment_client()
        .void(executor.request_with_ids(request, &request_id, &connector_ref_id))
        .await
        .expect("void should return a response")
        .into_inner();

    if expectation.require_no_error {
        assert!(
            response.error.is_none(),
            "Void should not include error details"
        );
    }
    assert_eq!(
        response.status,
        i32::from(expectation.expected_status),
        "Void should return expected status"
    );

    context.capture_from_void_response(&response);
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

    for case in generated_input_variants() {
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
