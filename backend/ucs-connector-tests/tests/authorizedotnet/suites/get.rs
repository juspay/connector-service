use grpc_api_types::payments::PaymentStatus;
use serial_test::serial;
use ucs_connector_tests::harness::{
    base_requests, context::FlowContext, executor::AuthorizedotnetExecutor,
};

use crate::authorizedotnet::suites::{authorize, capture, create_customer, generated_cases};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GetScenario {
    Default,
}

pub fn default_scenario() -> GetScenario {
    GetScenario::Default
}

#[allow(dead_code)]
pub fn variants() -> &'static [GetScenario] {
    &[GetScenario::Default]
}

pub async fn execute(
    executor: &AuthorizedotnetExecutor,
    flow_name: &str,
    context: &mut FlowContext,
    scenario: GetScenario,
) {
    let transaction_id = context.require_connector_transaction_id("get");
    let mut last_observed: Option<(i32, bool)> = None;

    for attempt in 0..3 {
        let request = match scenario {
            GetScenario::Default => {
                base_requests::get_request(&transaction_id, context.amount_minor)
            }
        };

        let step = format!("get_{scenario:?}_{attempt}");
        let (request_id, connector_ref_id) = AuthorizedotnetExecutor::step_ids(flow_name, &step);
        let response = executor
            .payment_client()
            .get(executor.request_with_ids(request, &request_id, &connector_ref_id))
            .await
            .expect("get should return a response")
            .into_inner();

        let is_charged = response.status == i32::from(PaymentStatus::Charged);
        let has_no_error = response.error.is_none();
        if is_charged && has_no_error {
            return;
        }

        last_observed = Some((response.status, has_no_error));
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
    }

    let (status, has_no_error) =
        last_observed.expect("at least one get attempt should have been recorded");

    assert_eq!(
        status,
        i32::from(PaymentStatus::Charged),
        "Get should settle to CHARGED"
    );
    assert!(has_no_error, "Get should settle without error details");
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

    for case in generated_cases() {
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
