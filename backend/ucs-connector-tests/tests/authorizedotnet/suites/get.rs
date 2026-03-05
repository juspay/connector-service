use grpc_api_types::payments::PaymentStatus;
use serial_test::serial;
use ucs_connector_tests::harness::{
    base_requests, context::FlowContext, executor::AuthorizedotnetExecutor,
};

use crate::authorizedotnet::suites::{
    authorize, capture, create_customer, generated_input_variants,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GetScenario {
    Default,
}

#[derive(Clone, Copy)]
pub struct GetOverrides {
    pub max_attempts: usize,
}

#[derive(Clone, Copy)]
pub struct GetExpectation {
    pub expected_status: PaymentStatus,
    pub require_no_error: bool,
}

pub fn default_scenario() -> GetScenario {
    GetScenario::Default
}

#[allow(dead_code)]
pub fn variants() -> &'static [GetScenario] {
    &[GetScenario::Default]
}

fn scenario_overrides(_context: &FlowContext, scenario: GetScenario) -> GetOverrides {
    match scenario {
        GetScenario::Default => GetOverrides { max_attempts: 3 },
    }
}

fn scenario_expectation(scenario: GetScenario) -> GetExpectation {
    match scenario {
        GetScenario::Default => GetExpectation {
            expected_status: PaymentStatus::Charged,
            require_no_error: true,
        },
    }
}

pub async fn execute(
    executor: &AuthorizedotnetExecutor,
    flow_name: &str,
    context: &mut FlowContext,
    scenario: GetScenario,
) {
    let overrides = scenario_overrides(context, scenario);
    let expectation = scenario_expectation(scenario);

    let transaction_id = context.require_connector_transaction_id("get");
    let mut last_observed: Option<(i32, bool)> = None;

    for attempt in 0..overrides.max_attempts {
        let mut request = base_requests::get_request(&transaction_id, context.amount_minor);
        context.apply_to_get_request(&mut request);

        let step = format!("get_{scenario:?}_{attempt}");
        let (request_id, connector_ref_id) = AuthorizedotnetExecutor::step_ids(flow_name, &step);
        let response = executor
            .payment_client()
            .get(executor.request_with_ids(request, &request_id, &connector_ref_id))
            .await
            .expect("get should return a response")
            .into_inner();

        let is_expected_status = response.status == i32::from(expectation.expected_status);
        let has_no_error = response.error.is_none();
        context.capture_from_get_response(&response);
        if is_expected_status && (!expectation.require_no_error || has_no_error) {
            return;
        }

        last_observed = Some((response.status, has_no_error));
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
    }

    let (status, has_no_error) =
        last_observed.expect("at least one get attempt should have been recorded");

    assert_eq!(
        status,
        i32::from(expectation.expected_status),
        "Get should settle to expected status"
    );

    if expectation.require_no_error {
        assert!(has_no_error, "Get should settle without error details");
    }
}

/// @capability capability_id=ANET-CAP-003
/// @capability connector=authorizedotnet
/// @capability layer=suite
/// @capability flow=get
/// @capability payment_method=card
/// @capability payment_method_subtype=no3ds
/// @capability scenario=after_manual_authorize_and_capture
/// @capability support=dependent
/// @capability expected=status=CHARGED without error
#[tokio::test]
#[serial]
async fn test_authorizedotnet__suite_get__after_manual_authorize_and_capture__returns_charged_without_error(
) {
    let executor = AuthorizedotnetExecutor::new().await;

    for case in generated_input_variants() {
        let mut context = FlowContext::new(case, "get_suite");
        create_customer::execute(
            &executor,
            "get_suite",
            &mut context,
            create_customer::default_scenario(),
        )
        .await;
        authorize::execute(
            &executor,
            "get_suite",
            &mut context,
            authorize::default_manual_scenario(),
        )
        .await;
        capture::execute(
            &executor,
            "get_suite",
            &mut context,
            capture::default_scenario(),
        )
        .await;
        execute(&executor, "get_suite", &mut context, default_scenario()).await;
    }
}
