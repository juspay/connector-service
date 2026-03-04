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

use crate::authorizedotnet::suites::generated_cases;

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

fn build_request(
    context: &FlowContext,
    scenario: AuthorizeScenario,
) -> PaymentServiceAuthorizeRequest {
    let mut request = base_requests::base_authorize_request(&context.case);
    match scenario {
        AuthorizeScenario::No3dsAutoCharged => {
            request.auth_type = i32::from(AuthenticationType::NoThreeDs);
            request.capture_method = Some(i32::from(CaptureMethod::Automatic));
            request.enrolled_for_3ds = Some(false);
            set_card_number(&mut request, SUCCESS_CARD);
        }
        AuthorizeScenario::No3dsManualAuthorized => {
            request.auth_type = i32::from(AuthenticationType::NoThreeDs);
            request.capture_method = Some(i32::from(CaptureMethod::Manual));
            request.enrolled_for_3ds = Some(false);
            set_card_number(&mut request, SUCCESS_CARD);
        }
        AuthorizeScenario::AvsZip46203Decline => {
            request.auth_type = i32::from(AuthenticationType::NoThreeDs);
            request.capture_method = Some(i32::from(CaptureMethod::Automatic));
            request.enrolled_for_3ds = Some(false);
            set_card_number(&mut request, DECLINE_TRIGGER_CARD);
            set_billing_zip(&mut request, "46203");
        }
        AuthorizeScenario::DeclineZip46282Code2 => {
            request.auth_type = i32::from(AuthenticationType::NoThreeDs);
            request.capture_method = Some(i32::from(CaptureMethod::Automatic));
            request.enrolled_for_3ds = Some(false);
            set_card_number(&mut request, DECLINE_TRIGGER_CARD);
            set_billing_zip(&mut request, "46282");
        }
        AuthorizeScenario::Cvv901DeclineCode65 => {
            request.auth_type = i32::from(AuthenticationType::NoThreeDs);
            request.capture_method = Some(i32::from(CaptureMethod::Automatic));
            request.enrolled_for_3ds = Some(false);
            set_card_number(&mut request, DECLINE_TRIGGER_CARD);
            set_billing_zip(&mut request, "94122");
            set_card_cvc(&mut request, "901");
            set_amount_minor(&mut request, 1000);
        }
        AuthorizeScenario::ExpiredCardDecline => {
            request.auth_type = i32::from(AuthenticationType::NoThreeDs);
            request.capture_method = Some(i32::from(CaptureMethod::Automatic));
            request.enrolled_for_3ds = Some(false);
            set_card_number(&mut request, DECLINE_TRIGGER_CARD);
            set_card_expiry(&mut request, "01", "2000");
            set_billing_zip(&mut request, "94122");
            set_card_cvc(&mut request, "123");
            set_amount_minor(&mut request, 1000);
        }
    }
    request
}

pub async fn execute(
    executor: &AuthorizedotnetExecutor,
    flow_name: &str,
    context: &mut FlowContext,
    scenario: AuthorizeScenario,
) {
    let mut request = build_request(context, scenario);
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
            match scenario {
                AuthorizeScenario::No3dsAutoCharged => {
                    assertions::assert_no_error(&response, "No3DS auto authorize");
                    assertions::assert_payment_status(
                        response.status,
                        &[PaymentStatus::Charged],
                        "No3DS auto authorize",
                    );
                    let transaction_id = assertions::extract_connector_transaction_id(&response)
                        .expect("No3DS auto authorize should return connector_transaction_id");
                    context.set_connector_transaction_id(Some(transaction_id));
                }
                AuthorizeScenario::No3dsManualAuthorized => {
                    assertions::assert_no_error(&response, "No3DS manual authorize");
                    assertions::assert_payment_status(
                        response.status,
                        &[PaymentStatus::Authorized],
                        "No3DS manual authorize",
                    );
                    let transaction_id = assertions::extract_connector_transaction_id(&response)
                        .expect("No3DS manual authorize should return connector_transaction_id");
                    context.set_connector_transaction_id(Some(transaction_id));
                }
                AuthorizeScenario::AvsZip46203Decline => {
                    if response.status == i32::from(PaymentStatus::Failure) {
                        assertions::assert_error_details_present(
                            &response,
                            "AVS mismatch authorize",
                        );
                        assertions::assert_error_message_contains(
                            &response,
                            "avs mismatch",
                            "AVS mismatch authorize",
                        );
                        assertions::assert_error_message_contains(
                            &response,
                            "address provided does not match",
                            "AVS mismatch authorize",
                        );
                    } else {
                        assertions::assert_payment_status(
                            response.status,
                            &[PaymentStatus::Charged],
                            "AVS mismatch authorize fallback",
                        );
                        assertions::assert_no_error(
                            &response,
                            "AVS mismatch authorize fallback should be clean success",
                        );
                        assert!(
                            assertions::extract_connector_transaction_id(&response).is_some(),
                            "AVS mismatch authorize fallback should provide connector_transaction_id"
                        );
                    }
                }
                AuthorizeScenario::DeclineZip46282Code2 => {
                    assertions::assert_payment_status(
                        response.status,
                        &[PaymentStatus::Failure],
                        "Decline ZIP authorize",
                    );
                    assertions::assert_decline_error_strict(&response);
                }
                AuthorizeScenario::Cvv901DeclineCode65 => {
                    if response.status == i32::from(PaymentStatus::Failure) {
                        assertions::assert_connector_error_code_and_message(
                            &response,
                            "65",
                            "declined",
                            "CVV mismatch authorize",
                        );
                    } else {
                        assertions::assert_payment_status(
                            response.status,
                            &[PaymentStatus::Charged],
                            "CVV mismatch authorize fallback",
                        );
                        assertions::assert_no_error(
                            &response,
                            "CVV mismatch authorize fallback should be clean success",
                        );
                        assert!(
                            assertions::extract_connector_transaction_id(&response).is_some(),
                            "CVV mismatch authorize fallback should provide connector_transaction_id"
                        );
                    }
                }
                AuthorizeScenario::ExpiredCardDecline => {
                    assertions::assert_payment_status(
                        response.status,
                        &[PaymentStatus::Failure],
                        "Expired card authorize",
                    );
                    assertions::assert_error_details_present(&response, "Expired card authorize");
                    assertions::assert_error_message_contains(
                        &response,
                        "expired",
                        "Expired card authorize",
                    );
                }
            }
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
    for case in generated_cases() {
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
    for case in generated_cases() {
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
    for case in generated_cases() {
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
    for case in generated_cases() {
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
    for case in generated_cases() {
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
    for case in generated_cases() {
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
