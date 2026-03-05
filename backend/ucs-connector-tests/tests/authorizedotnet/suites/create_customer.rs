use serial_test::serial;
use ucs_connector_tests::harness::{
    base_requests, context::FlowContext, executor::AuthorizedotnetExecutor,
};

use crate::authorizedotnet::suites::{extract_id, generated_input_variants};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CreateCustomerScenario {
    Default,
}

#[derive(Clone)]
pub struct CreateCustomerOverrides {
    pub merchant_customer_id: String,
}

#[derive(Clone, Copy)]
pub struct CreateCustomerExpectation {
    pub require_no_error: bool,
    pub require_connector_customer_id: bool,
}

pub fn default_scenario() -> CreateCustomerScenario {
    CreateCustomerScenario::Default
}

#[allow(dead_code)]
pub fn variants() -> &'static [CreateCustomerScenario] {
    &[CreateCustomerScenario::Default]
}

fn scenario_overrides(
    context: &FlowContext,
    scenario: CreateCustomerScenario,
) -> CreateCustomerOverrides {
    match scenario {
        CreateCustomerScenario::Default => CreateCustomerOverrides {
            merchant_customer_id: context.merchant_customer_id.clone(),
        },
    }
}

fn scenario_expectation(scenario: CreateCustomerScenario) -> CreateCustomerExpectation {
    match scenario {
        CreateCustomerScenario::Default => CreateCustomerExpectation {
            require_no_error: true,
            require_connector_customer_id: true,
        },
    }
}

pub async fn execute(
    executor: &AuthorizedotnetExecutor,
    flow_name: &str,
    context: &mut FlowContext,
    scenario: CreateCustomerScenario,
) {
    let overrides = scenario_overrides(context, scenario);
    let expectation = scenario_expectation(scenario);

    let request =
        base_requests::customer_create_request(&overrides.merchant_customer_id, &context.case);

    let (request_id, connector_ref_id) =
        AuthorizedotnetExecutor::step_ids(flow_name, "create_customer");
    let response = executor
        .customer_client()
        .create(executor.request_with_ids(request, &request_id, &connector_ref_id))
        .await
        .expect("customer create should return a response")
        .into_inner();

    if expectation.require_no_error {
        assert!(
            response.error.is_none(),
            "Customer create should not return error details"
        );
    }
    if expectation.require_connector_customer_id {
        assert!(
            !response.connector_customer_id.trim().is_empty(),
            "Customer create should return connector_customer_id"
        );
    }

    if let Some(merchant_customer_id) = extract_id(response.merchant_customer_id.as_ref()) {
        assert!(
            !merchant_customer_id.trim().is_empty(),
            "merchant_customer_id should be non-empty when returned"
        );
    }

    context.capture_from_customer_create_response(&response);
}

/// @capability capability_id=ANET-CAP-001
/// @capability connector=authorizedotnet
/// @capability layer=suite
/// @capability flow=create_customer
/// @capability payment_method=card
/// @capability payment_method_subtype=not_applicable
/// @capability scenario=with_billing_profile
/// @capability support=supported
/// @capability expected=non_empty_connector_customer_id
#[tokio::test]
#[serial]
async fn test_authorizedotnet__suite_create_customer__with_billing_profile__returns_non_empty_connector_customer_id(
) {
    let executor = AuthorizedotnetExecutor::new().await;

    for case in generated_input_variants() {
        let mut context = FlowContext::new(case, "create_customer_suite");
        execute(
            &executor,
            "create_customer_suite",
            &mut context,
            default_scenario(),
        )
        .await;
    }
}
