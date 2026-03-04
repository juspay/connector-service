use serial_test::serial;
use ucs_connector_tests::harness::{
    base_requests, context::FlowContext, executor::AuthorizedotnetExecutor,
};

use crate::authorizedotnet::suites::{extract_id, generated_cases};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CreateCustomerScenario {
    Default,
}

pub fn default_scenario() -> CreateCustomerScenario {
    CreateCustomerScenario::Default
}

#[allow(dead_code)]
pub fn variants() -> &'static [CreateCustomerScenario] {
    &[CreateCustomerScenario::Default]
}

pub async fn execute(
    executor: &AuthorizedotnetExecutor,
    flow_name: &str,
    context: &mut FlowContext,
    scenario: CreateCustomerScenario,
) {
    let request = match scenario {
        CreateCustomerScenario::Default => {
            base_requests::customer_create_request(&context.merchant_customer_id, &context.case)
        }
    };

    let (request_id, connector_ref_id) =
        AuthorizedotnetExecutor::step_ids(flow_name, "create_customer");
    let response = executor
        .customer_client()
        .create(executor.request_with_ids(request, &request_id, &connector_ref_id))
        .await
        .expect("customer create should return a response")
        .into_inner();

    assert!(
        response.error.is_none(),
        "Customer create should not return error details"
    );
    assert!(
        !response.connector_customer_id.trim().is_empty(),
        "Customer create should return connector_customer_id"
    );

    if let Some(merchant_customer_id) = extract_id(response.merchant_customer_id.as_ref()) {
        assert!(
            !merchant_customer_id.trim().is_empty(),
            "merchant_customer_id should be non-empty when returned"
        );
    }

    context.connector_customer_id = Some(response.connector_customer_id);
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

    for case in generated_cases() {
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
