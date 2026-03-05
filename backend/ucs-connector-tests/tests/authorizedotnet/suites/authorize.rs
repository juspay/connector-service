use std::str::FromStr;

use cards::CardNumber;
use grpc_api_types::payments::{
    payment_method, Address, AuthenticationType, CaptureMethod, PaymentAddress, PaymentMethod,
    PaymentServiceAuthorizeRequest, PaymentStatus,
};
use hyperswitch_masking::Secret;
use serial_test::serial;
use ucs_connector_tests::harness::{
    assertions, base_requests, context::FlowContext, executor::AuthorizedotnetExecutor,
};

use crate::authorizedotnet::suites::generated_input_variants;

const SUCCESS_CARD: &str = "5123456789012346";
const DECLINE_TRIGGER_CARD: &str = "4111111111111111";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorizeScenario {
    No3dsAutoCharged,
    No3dsManualAuthorized,
    AvsZip46203Decline,
    DeclineZip46282Code2,
    Cvv901DeclineCode65,
    ExpiredCardDecline,
}

#[derive(Clone, Copy)]
pub struct AuthorizeOverrides {
    pub auth_type: AuthenticationType,
    pub capture_method: CaptureMethod,
    pub enrolled_for_3ds: bool,
    pub card_number: &'static str,
    pub card_cvc: Option<&'static str>,
    pub card_expiry: Option<(&'static str, &'static str)>,
    pub billing_zip: Option<&'static str>,
    pub amount_minor_override: Option<i64>,
}

#[derive(Clone, Copy)]
pub struct AuthorizeExpectation {
    pub primary_statuses: &'static [PaymentStatus],
    pub fallback_statuses: &'static [PaymentStatus],
    pub error_message_contains: &'static [&'static str],
    pub connector_error_code: Option<&'static str>,
    pub require_error_on_primary: bool,
    pub allow_fallback_success: bool,
    pub require_transaction_id_on_success: bool,
}

pub fn default_manual_scenario() -> AuthorizeScenario {
    AuthorizeScenario::No3dsManualAuthorized
}

#[allow(dead_code)]
pub fn default_auto_scenario() -> AuthorizeScenario {
    AuthorizeScenario::No3dsAutoCharged
}

#[allow(dead_code)]
pub fn variants() -> &'static [AuthorizeScenario] {
    &[
        AuthorizeScenario::No3dsAutoCharged,
        AuthorizeScenario::No3dsManualAuthorized,
        AuthorizeScenario::AvsZip46203Decline,
        AuthorizeScenario::DeclineZip46282Code2,
        AuthorizeScenario::Cvv901DeclineCode65,
        AuthorizeScenario::ExpiredCardDecline,
    ]
}

fn scenario_overrides(scenario: AuthorizeScenario) -> AuthorizeOverrides {
    match scenario {
        AuthorizeScenario::No3dsAutoCharged => AuthorizeOverrides {
            auth_type: AuthenticationType::NoThreeDs,
            capture_method: CaptureMethod::Automatic,
            enrolled_for_3ds: false,
            card_number: SUCCESS_CARD,
            card_cvc: None,
            card_expiry: None,
            billing_zip: None,
            amount_minor_override: None,
        },
        AuthorizeScenario::No3dsManualAuthorized => AuthorizeOverrides {
            auth_type: AuthenticationType::NoThreeDs,
            capture_method: CaptureMethod::Manual,
            enrolled_for_3ds: false,
            card_number: SUCCESS_CARD,
            card_cvc: None,
            card_expiry: None,
            billing_zip: None,
            amount_minor_override: None,
        },
        AuthorizeScenario::AvsZip46203Decline => AuthorizeOverrides {
            auth_type: AuthenticationType::NoThreeDs,
            capture_method: CaptureMethod::Automatic,
            enrolled_for_3ds: false,
            card_number: DECLINE_TRIGGER_CARD,
            card_cvc: None,
            card_expiry: None,
            billing_zip: Some("46203"),
            amount_minor_override: None,
        },
        AuthorizeScenario::DeclineZip46282Code2 => AuthorizeOverrides {
            auth_type: AuthenticationType::NoThreeDs,
            capture_method: CaptureMethod::Automatic,
            enrolled_for_3ds: false,
            card_number: DECLINE_TRIGGER_CARD,
            card_cvc: None,
            card_expiry: None,
            billing_zip: Some("46282"),
            amount_minor_override: None,
        },
        AuthorizeScenario::Cvv901DeclineCode65 => AuthorizeOverrides {
            auth_type: AuthenticationType::NoThreeDs,
            capture_method: CaptureMethod::Automatic,
            enrolled_for_3ds: false,
            card_number: DECLINE_TRIGGER_CARD,
            card_cvc: Some("901"),
            card_expiry: None,
            billing_zip: Some("94122"),
            amount_minor_override: Some(1000),
        },
        AuthorizeScenario::ExpiredCardDecline => AuthorizeOverrides {
            auth_type: AuthenticationType::NoThreeDs,
            capture_method: CaptureMethod::Automatic,
            enrolled_for_3ds: false,
            card_number: DECLINE_TRIGGER_CARD,
            card_cvc: Some("123"),
            card_expiry: Some(("01", "2000")),
            billing_zip: Some("94122"),
            amount_minor_override: Some(1000),
        },
    }
}

fn scenario_expectation(scenario: AuthorizeScenario) -> AuthorizeExpectation {
    match scenario {
        AuthorizeScenario::No3dsAutoCharged => AuthorizeExpectation {
            primary_statuses: &[PaymentStatus::Charged],
            fallback_statuses: &[],
            error_message_contains: &[],
            connector_error_code: None,
            require_error_on_primary: false,
            allow_fallback_success: false,
            require_transaction_id_on_success: true,
        },
        AuthorizeScenario::No3dsManualAuthorized => AuthorizeExpectation {
            primary_statuses: &[PaymentStatus::Authorized],
            fallback_statuses: &[],
            error_message_contains: &[],
            connector_error_code: None,
            require_error_on_primary: false,
            allow_fallback_success: false,
            require_transaction_id_on_success: true,
        },
        AuthorizeScenario::AvsZip46203Decline => AuthorizeExpectation {
            primary_statuses: &[PaymentStatus::Failure],
            fallback_statuses: &[PaymentStatus::Charged],
            error_message_contains: &["avs mismatch", "address provided does not match"],
            connector_error_code: None,
            require_error_on_primary: true,
            allow_fallback_success: true,
            require_transaction_id_on_success: true,
        },
        AuthorizeScenario::DeclineZip46282Code2 => AuthorizeExpectation {
            primary_statuses: &[PaymentStatus::Failure],
            fallback_statuses: &[],
            error_message_contains: &[],
            connector_error_code: Some("2"),
            require_error_on_primary: true,
            allow_fallback_success: false,
            require_transaction_id_on_success: false,
        },
        AuthorizeScenario::Cvv901DeclineCode65 => AuthorizeExpectation {
            primary_statuses: &[PaymentStatus::Failure],
            fallback_statuses: &[PaymentStatus::Charged],
            error_message_contains: &["declined"],
            connector_error_code: Some("65"),
            require_error_on_primary: true,
            allow_fallback_success: true,
            require_transaction_id_on_success: true,
        },
        AuthorizeScenario::ExpiredCardDecline => AuthorizeExpectation {
            primary_statuses: &[PaymentStatus::Failure],
            fallback_statuses: &[],
            error_message_contains: &["expired"],
            connector_error_code: None,
            require_error_on_primary: true,
            allow_fallback_success: false,
            require_transaction_id_on_success: false,
        },
    }
}

fn set_card_number(request: &mut PaymentServiceAuthorizeRequest, card_number: &str) {
    if let Some(PaymentMethod {
        payment_method: Some(payment_method::PaymentMethod::Card(card)),
    }) = request.payment_method.as_mut()
    {
        card.card_number = Some(CardNumber::from_str(card_number).expect("valid card number"));
        card.card_network = Some(2);
    }
}

fn set_card_cvc(request: &mut PaymentServiceAuthorizeRequest, card_cvc: &str) {
    if let Some(PaymentMethod {
        payment_method: Some(payment_method::PaymentMethod::Card(card)),
    }) = request.payment_method.as_mut()
    {
        card.card_cvc = Some(Secret::new(card_cvc.to_string()));
    }
}

fn set_card_expiry(request: &mut PaymentServiceAuthorizeRequest, month: &str, year: &str) {
    if let Some(PaymentMethod {
        payment_method: Some(payment_method::PaymentMethod::Card(card)),
    }) = request.payment_method.as_mut()
    {
        card.card_exp_month = Some(Secret::new(month.to_string()));
        card.card_exp_year = Some(Secret::new(year.to_string()));
    }
}

fn set_billing_zip(request: &mut PaymentServiceAuthorizeRequest, zip: &str) {
    let Some(address) = request.address.as_mut() else {
        request.address = Some(PaymentAddress {
            billing_address: Some(Address {
                zip_code: Some(zip.to_string().into()),
                ..Default::default()
            }),
            shipping_address: None,
        });
        return;
    };

    match address.billing_address.as_mut() {
        Some(billing) => billing.zip_code = Some(zip.to_string().into()),
        None => {
            address.billing_address = Some(Address {
                zip_code: Some(zip.to_string().into()),
                ..Default::default()
            });
        }
    }
}

fn set_amount_minor(request: &mut PaymentServiceAuthorizeRequest, amount_minor: i64) {
    if let Some(amount) = request.amount.as_mut() {
        amount.minor_amount = amount_minor;
    }
}

fn apply_overrides(request: &mut PaymentServiceAuthorizeRequest, overrides: AuthorizeOverrides) {
    request.auth_type = i32::from(overrides.auth_type);
    request.capture_method = Some(i32::from(overrides.capture_method));
    request.enrolled_for_3ds = Some(overrides.enrolled_for_3ds);
    set_card_number(request, overrides.card_number);

    if let Some((month, year)) = overrides.card_expiry {
        set_card_expiry(request, month, year);
    }
    if let Some(cvc) = overrides.card_cvc {
        set_card_cvc(request, cvc);
    }
    if let Some(zip) = overrides.billing_zip {
        set_billing_zip(request, zip);
    }
    if let Some(amount_minor) = overrides.amount_minor_override {
        set_amount_minor(request, amount_minor);
    }
}

fn build_request(
    context: &FlowContext,
    overrides: AuthorizeOverrides,
) -> PaymentServiceAuthorizeRequest {
    let mut request = base_requests::base_authorize_request(&context.case);
    apply_overrides(&mut request, overrides);
    request
}

fn assert_expectation(
    response: &grpc_api_types::payments::PaymentServiceAuthorizeResponse,
    scenario: AuthorizeScenario,
    expectation: AuthorizeExpectation,
) {
    let is_primary = expectation
        .primary_statuses
        .iter()
        .any(|status| response.status == i32::from(*status));
    let is_fallback = expectation
        .fallback_statuses
        .iter()
        .any(|status| response.status == i32::from(*status));

    if is_primary {
        if expectation.require_error_on_primary {
            assertions::assert_error_details_present(&response, "Authorize primary failure");
            for expected_message in expectation.error_message_contains {
                assertions::assert_error_message_contains(
                    &response,
                    expected_message,
                    "Authorize primary failure",
                );
            }
            if let Some(expected_code) = expectation.connector_error_code {
                assertions::assert_connector_error_code_and_message(
                    &response,
                    expected_code,
                    expectation
                        .error_message_contains
                        .first()
                        .copied()
                        .unwrap_or("declined"),
                    "Authorize primary failure code",
                );
            }
        } else {
            assertions::assert_no_error(&response, "Authorize primary success");
            if expectation.require_transaction_id_on_success {
                assert!(
                    assertions::extract_connector_transaction_id(&response).is_some(),
                    "Authorize success should provide connector_transaction_id"
                );
            }
        }
        return;
    }

    if expectation.allow_fallback_success && is_fallback {
        assertions::assert_no_error(&response, "Authorize fallback success");
        if expectation.require_transaction_id_on_success {
            assert!(
                assertions::extract_connector_transaction_id(&response).is_some(),
                "Authorize fallback success should provide connector_transaction_id"
            );
        }
        return;
    }

    let allowed = expectation
        .primary_statuses
        .iter()
        .chain(expectation.fallback_statuses.iter())
        .copied()
        .collect::<Vec<_>>();
    assertions::assert_payment_status(response.status, &allowed, "Authorize status check");

    match scenario {
        AuthorizeScenario::DeclineZip46282Code2 => {
            assertions::assert_decline_error_strict(response)
        }
        AuthorizeScenario::ExpiredCardDecline => {
            assertions::assert_error_message_contains(response, "expired", "Expired card authorize")
        }
        _ => {}
    }
}

pub async fn execute(
    executor: &AuthorizedotnetExecutor,
    flow_name: &str,
    context: &mut FlowContext,
    scenario: AuthorizeScenario,
) {
    let overrides = scenario_overrides(scenario);
    let expectation = scenario_expectation(scenario);

    let mut request = build_request(context, overrides);
    context.apply_customer_to_authorize(&mut request);

    let step = format!("authorize_{scenario:?}");
    let (request_id, connector_ref_id) = AuthorizedotnetExecutor::step_ids(flow_name, &step);
    let result = executor
        .payment_client()
        .authorize(executor.request_with_ids(request, &request_id, &connector_ref_id))
        .await;

    match result {
        Ok(response) => {
            let response = response.into_inner();
            context.capture_from_authorize_response(&response);
            assert_expectation(&response, scenario, expectation);
        }
        Err(status) => {
            let message = status.message().to_ascii_lowercase();
            match scenario {
                AuthorizeScenario::No3dsAutoCharged | AuthorizeScenario::No3dsManualAuthorized => {
                    panic!("Successful authorize scenario failed with status message: {message}");
                }
                AuthorizeScenario::AvsZip46203Decline => assert!(
                    message.contains("avs")
                        || message.contains("postal")
                        || message.contains("address"),
                    "Expected AVS failure message, got: {message}"
                ),
                AuthorizeScenario::DeclineZip46282Code2 => {
                    assertions::assert_decline_error_in_status(&status)
                }
                AuthorizeScenario::Cvv901DeclineCode65 => assert!(
                    message.contains("declined") || message.contains("transaction"),
                    "Expected CVV decline message, got: {message}"
                ),
                AuthorizeScenario::ExpiredCardDecline => assert!(
                    message.contains("expired") || message.contains("invalid"),
                    "Expected expired-card message, got: {message}"
                ),
            }
        }
    }
}

/// @capability capability_id=ANET-CAP-006
/// @capability connector=authorizedotnet
/// @capability layer=suite
/// @capability flow=authorize
/// @capability payment_method=card
/// @capability payment_method_subtype=no3ds
/// @capability scenario=no3ds_auto_capture
/// @capability support=supported
/// @capability expected=status=CHARGED
#[tokio::test]
#[serial]
async fn test_authorizedotnet__suite_authorize__card_no3ds_auto_capture__returns_charged() {
    let executor = AuthorizedotnetExecutor::new().await;
    for case in generated_input_variants() {
        let mut context = FlowContext::new(case, "authorize_auto_suite");
        execute(
            &executor,
            "authorize_auto_suite",
            &mut context,
            AuthorizeScenario::No3dsAutoCharged,
        )
        .await;
    }
}

/// @capability capability_id=ANET-CAP-007
/// @capability connector=authorizedotnet
/// @capability layer=suite
/// @capability flow=authorize
/// @capability payment_method=card
/// @capability payment_method_subtype=no3ds
/// @capability scenario=no3ds_manual_capture
/// @capability support=supported
/// @capability expected=status=AUTHORIZED
#[tokio::test]
#[serial]
async fn test_authorizedotnet__suite_authorize__card_no3ds_manual_capture__returns_authorized() {
    let executor = AuthorizedotnetExecutor::new().await;
    for case in generated_input_variants() {
        let mut context = FlowContext::new(case, "authorize_manual_suite");
        execute(
            &executor,
            "authorize_manual_suite",
            &mut context,
            AuthorizeScenario::No3dsManualAuthorized,
        )
        .await;
    }
}

/// @capability capability_id=ANET-CAP-008
/// @capability connector=authorizedotnet
/// @capability layer=suite
/// @capability flow=authorize
/// @capability payment_method=card
/// @capability payment_method_subtype=no3ds
/// @capability scenario=zip_46203_avs_trigger
/// @capability support=conditional
/// @capability expected=failure_with_avs_mismatch_signal
/// @capability fallback=if_not_failed_must_be_CHARGED_with_no_error_and_transaction_id
#[tokio::test]
#[serial]
async fn test_authorizedotnet__suite_authorize__card_zip_46203_avs_trigger__returns_failure_or_charged_safeguard(
) {
    let executor = AuthorizedotnetExecutor::new().await;
    for case in generated_input_variants() {
        let mut context = FlowContext::new(case, "authorize_avs_suite");
        execute(
            &executor,
            "authorize_avs_suite",
            &mut context,
            AuthorizeScenario::AvsZip46203Decline,
        )
        .await;
    }
}

/// @capability capability_id=ANET-CAP-009
/// @capability connector=authorizedotnet
/// @capability layer=suite
/// @capability flow=authorize
/// @capability payment_method=card
/// @capability payment_method_subtype=no3ds
/// @capability scenario=zip_46282_decline_trigger
/// @capability support=negative_trigger
/// @capability expected=status=FAILURE_and_connector_code=2
#[tokio::test]
#[serial]
async fn test_authorizedotnet__suite_authorize__card_zip_46282_decline_trigger__returns_failure_code_2(
) {
    let executor = AuthorizedotnetExecutor::new().await;
    for case in generated_input_variants() {
        let mut context = FlowContext::new(case, "authorize_decline_zip_suite");
        execute(
            &executor,
            "authorize_decline_zip_suite",
            &mut context,
            AuthorizeScenario::DeclineZip46282Code2,
        )
        .await;
    }
}

/// @capability capability_id=ANET-CAP-010
/// @capability connector=authorizedotnet
/// @capability layer=suite
/// @capability flow=authorize
/// @capability payment_method=card
/// @capability payment_method_subtype=no3ds
/// @capability scenario=cvv_901_trigger
/// @capability support=conditional
/// @capability expected=failure_with_connector_code=65
/// @capability fallback=if_not_failed_must_be_CHARGED_with_no_error_and_transaction_id
#[tokio::test]
#[serial]
async fn test_authorizedotnet__suite_authorize__card_cvv_901_trigger__returns_failure_code_65_or_charged_safeguard(
) {
    let executor = AuthorizedotnetExecutor::new().await;
    for case in generated_input_variants() {
        let mut context = FlowContext::new(case, "authorize_cvv_suite");
        execute(
            &executor,
            "authorize_cvv_suite",
            &mut context,
            AuthorizeScenario::Cvv901DeclineCode65,
        )
        .await;
    }
}

/// @capability capability_id=ANET-CAP-011
/// @capability connector=authorizedotnet
/// @capability layer=suite
/// @capability flow=authorize
/// @capability payment_method=card
/// @capability payment_method_subtype=no3ds
/// @capability scenario=expired_012000_trigger
/// @capability support=negative_trigger
/// @capability expected=status=FAILURE_with_expired_signal
#[tokio::test]
#[serial]
async fn test_authorizedotnet__suite_authorize__card_expired_012000_trigger__returns_failure_with_expired_signal(
) {
    let executor = AuthorizedotnetExecutor::new().await;
    for case in generated_input_variants() {
        let mut context = FlowContext::new(case, "authorize_expired_suite");
        execute(
            &executor,
            "authorize_expired_suite",
            &mut context,
            AuthorizeScenario::ExpiredCardDecline,
        )
        .await;
    }
}
