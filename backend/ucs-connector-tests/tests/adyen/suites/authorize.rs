use std::str::FromStr;

use cards::CardNumber;
use grpc_api_types::payments::{
    payment_method, AuthenticationType, CaptureMethod, PaymentMethod,
    PaymentServiceAuthorizeRequest, PaymentServiceAuthorizeResponse, PaymentStatus,
};
use hyperswitch_masking::Secret;
use serial_test::serial;
use ucs_connector_tests::harness::{
    assertions, base_requests, context::FlowContext, executor::AdyenExecutor,
};

use crate::adyen::suites::generated_input_variants;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorizeScenario {
    No3dsAutoCapture,
    No3dsManualCapture,
    No3dsFailPayment,
}

#[derive(Clone, Copy)]
pub struct AuthorizeOverrides {
    pub card_number: &'static str,
    pub card_exp_month: &'static str,
    pub card_exp_year: &'static str,
    pub card_cvc: &'static str,
    pub card_holder_name: &'static str,
    pub capture_method: CaptureMethod,
    pub auth_type: AuthenticationType,
    pub enrolled_for_3ds: bool,
}

#[derive(Clone, Copy)]
pub struct AuthorizeExpectation {
    pub allowed_statuses: &'static [PaymentStatus],
    pub require_error_details: bool,
    pub error_message_contains: Option<&'static str>,
}

pub fn default_manual_scenario() -> AuthorizeScenario {
    AuthorizeScenario::No3dsManualCapture
}

fn scenario_overrides(scenario: AuthorizeScenario) -> AuthorizeOverrides {
    match scenario {
        AuthorizeScenario::No3dsAutoCapture => AuthorizeOverrides {
            card_number: "4111111111111111",
            card_exp_month: "03",
            card_exp_year: "30",
            card_cvc: "737",
            card_holder_name: "John Doe",
            capture_method: CaptureMethod::Automatic,
            auth_type: AuthenticationType::NoThreeDs,
            enrolled_for_3ds: false,
        },
        AuthorizeScenario::No3dsManualCapture => AuthorizeOverrides {
            card_number: "4111111111111111",
            card_exp_month: "03",
            card_exp_year: "30",
            card_cvc: "737",
            card_holder_name: "John Doe",
            capture_method: CaptureMethod::Manual,
            auth_type: AuthenticationType::NoThreeDs,
            enrolled_for_3ds: false,
        },
        AuthorizeScenario::No3dsFailPayment => AuthorizeOverrides {
            card_number: "4242424242424242",
            card_exp_month: "01",
            card_exp_year: "35",
            card_cvc: "123",
            card_holder_name: "joseph Doe",
            capture_method: CaptureMethod::Automatic,
            auth_type: AuthenticationType::NoThreeDs,
            enrolled_for_3ds: false,
        },
    }
}

fn scenario_expectation(scenario: AuthorizeScenario) -> AuthorizeExpectation {
    match scenario {
        AuthorizeScenario::No3dsAutoCapture => AuthorizeExpectation {
            allowed_statuses: &[
                PaymentStatus::Charged,
                PaymentStatus::Authorized,
                PaymentStatus::Pending,
            ],
            require_error_details: false,
            error_message_contains: None,
        },
        AuthorizeScenario::No3dsManualCapture => AuthorizeExpectation {
            allowed_statuses: &[PaymentStatus::Authorized],
            require_error_details: false,
            error_message_contains: None,
        },
        AuthorizeScenario::No3dsFailPayment => AuthorizeExpectation {
            allowed_statuses: &[
                PaymentStatus::Failure,
                PaymentStatus::AuthorizationFailed,
                PaymentStatus::RouterDeclined,
            ],
            require_error_details: true,
            error_message_contains: Some("refus"),
        },
    }
}

fn apply_overrides(request: &mut PaymentServiceAuthorizeRequest, overrides: AuthorizeOverrides) {
    request.auth_type = i32::from(overrides.auth_type);
    request.enrolled_for_3ds = Some(overrides.enrolled_for_3ds);
    request.capture_method = Some(i32::from(overrides.capture_method));

    if let Some(PaymentMethod {
        payment_method: Some(payment_method::PaymentMethod::Card(card)),
    }) = request.payment_method.as_mut()
    {
        card.card_number = Some(CardNumber::from_str(overrides.card_number).expect("valid card"));
        card.card_exp_month = Some(Secret::new(overrides.card_exp_month.to_string()));
        card.card_exp_year = Some(Secret::new(overrides.card_exp_year.to_string()));
        card.card_cvc = Some(Secret::new(overrides.card_cvc.to_string()));
        card.card_holder_name = Some(Secret::new(overrides.card_holder_name.to_string()));
        card.card_network = None;
    }
}

fn assert_expectation(
    response: &PaymentServiceAuthorizeResponse,
    expectation: AuthorizeExpectation,
    context: &str,
) {
    if expectation.require_error_details {
        assertions::assert_error_details_present(response, context);
        if let Some(message) = expectation.error_message_contains {
            assertions::assert_error_message_contains(response, message, context);
        }
        assertions::assert_payment_status(response.status, expectation.allowed_statuses, context);
        return;
    }

    assertions::assert_no_error(response, context);
    assertions::assert_payment_status(response.status, expectation.allowed_statuses, context);
    assert!(
        assertions::extract_connector_transaction_id(response).is_some(),
        "{context}: expected connector_transaction_id for success flow"
    );
}

pub async fn execute(
    executor: &AdyenExecutor,
    flow_name: &str,
    context: &mut FlowContext,
    scenario: AuthorizeScenario,
) {
    let overrides = scenario_overrides(scenario);
    let expectation = scenario_expectation(scenario);

    let mut request = base_requests::base_authorize_request_for_connector("adyen", &context.case);
    apply_overrides(&mut request, overrides);
    context.apply_customer_to_authorize(&mut request);

    let step = format!("authorize_{scenario:?}");
    let (request_id, connector_ref_id) = AdyenExecutor::step_ids(flow_name, &step);
    let response = executor
        .payment_client()
        .authorize(executor.request_with_ids(request, &request_id, &connector_ref_id))
        .await
        .expect("adyen authorize should return a response")
        .into_inner();

    context.capture_from_authorize_response(&response);
    assert_expectation(&response, expectation, "adyen authorize");
}

/// @capability capability_id=ADY-CAP-001
/// @capability connector=adyen
/// @capability layer=suite
/// @capability flow=authorize
/// @capability payment_method=card
/// @capability payment_method_subtype=no3ds
/// @capability scenario=no3ds_auto_capture
/// @capability support=supported
/// @capability expected=status=CHARGED_or_AUTHORIZED_or_PENDING
#[tokio::test]
#[serial]
async fn test_adyen__suite_authorize__no3ds_auto_capture__returns_expected_outcome() {
    let executor = AdyenExecutor::new().await;

    for case in generated_input_variants() {
        let mut context = FlowContext::new(case, "adyen_authorize_no3ds_auto_suite");
        execute(
            &executor,
            "adyen_authorize_no3ds_auto_suite",
            &mut context,
            AuthorizeScenario::No3dsAutoCapture,
        )
        .await;
    }
}

/// @capability capability_id=ADY-CAP-002
/// @capability connector=adyen
/// @capability layer=suite
/// @capability flow=authorize
/// @capability payment_method=card
/// @capability payment_method_subtype=no3ds
/// @capability scenario=no3ds_manual_capture
/// @capability support=supported
/// @capability expected=status=AUTHORIZED
#[tokio::test]
#[serial]
async fn test_adyen__suite_authorize__no3ds_manual_capture__returns_expected_outcome() {
    let executor = AdyenExecutor::new().await;

    for case in generated_input_variants() {
        let mut context = FlowContext::new(case, "adyen_authorize_no3ds_manual_suite");
        execute(
            &executor,
            "adyen_authorize_no3ds_manual_suite",
            &mut context,
            AuthorizeScenario::No3dsManualCapture,
        )
        .await;
    }
}

/// @capability capability_id=ADY-CAP-003
/// @capability connector=adyen
/// @capability layer=suite
/// @capability flow=authorize
/// @capability payment_method=card
/// @capability payment_method_subtype=no3ds
/// @capability scenario=no3ds_fail_payment
/// @capability support=negative_trigger
/// @capability expected=status=FAILURE_with_refused_signal
#[tokio::test]
#[serial]
async fn test_adyen__suite_authorize__no3ds_fail_payment__returns_expected_outcome() {
    let executor = AdyenExecutor::new().await;

    for case in generated_input_variants() {
        let mut context = FlowContext::new(case, "adyen_authorize_no3ds_fail_suite");
        execute(
            &executor,
            "adyen_authorize_no3ds_fail_suite",
            &mut context,
            AuthorizeScenario::No3dsFailPayment,
        )
        .await;
    }
}
