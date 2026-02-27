use std::str::FromStr;

use cards::CardNumber;
use cucumber::{given, then, when};
use grpc_api_types::payments::{
    identifier::IdType, payment_method, AuthenticationType, CaptureMethod, CardDetails,
    Currency, Identifier, PaymentMethod, PaymentServiceAuthorizeRequest,
    PaymentServiceCaptureRequest, PaymentServiceGetRequest, PaymentServiceRefundRequest,
    PaymentServiceVoidRequest, PaymentStatus, RefundServiceGetRequest, RefundStatus,
};
use hyperswitch_masking::Secret;
use tonic::Request;
use uuid::Uuid;

use crate::bdd::world::StripeWorld;

// Constants for test data
const TEST_CARD_NUMBER: &str = "4111111111111111";
const TEST_CARD_EXP_MONTH: &str = "12";
const TEST_CARD_EXP_YEAR: &str = "2050";
const TEST_CARD_CVC: &str = "123";
const TEST_CARD_HOLDER: &str = "Test User";
const TEST_EMAIL: &str = "customer@example.com";
const TEST_AMOUNT: i64 = 1000;

// Helper functions
fn generate_unique_id(prefix: &str) -> String {
    format!("{}_{}", prefix, Uuid::new_v4())
}

fn create_authorize_request(capture_method: CaptureMethod) -> PaymentServiceAuthorizeRequest {
    let card_details = CardDetails {
        card_number: Some(CardNumber::from_str(TEST_CARD_NUMBER).unwrap()),
        card_exp_month: Some(Secret::new(TEST_CARD_EXP_MONTH.to_string())),
        card_exp_year: Some(Secret::new(TEST_CARD_EXP_YEAR.to_string())),
        card_cvc: Some(Secret::new(TEST_CARD_CVC.to_string())),
        card_holder_name: Some(Secret::new(TEST_CARD_HOLDER.to_string())),
        card_issuer: None,
        card_network: Some(1),
        card_type: None,
        card_issuing_country_alpha2: None,
        bank_code: None,
        nick_name: None,
    };

    PaymentServiceAuthorizeRequest {
        amount: Some(grpc_api_types::payments::Money {
            minor_amount: TEST_AMOUNT,
            currency: i32::from(Currency::Usd),
        }),
        payment_method: Some(PaymentMethod {
            payment_method: Some(payment_method::PaymentMethod::Card(card_details)),
        }),
        return_url: Some("https://example.com/return".to_string()),
        webhook_url: Some("https://example.com/webhook".to_string()),
        customer: Some(grpc_api_types::payments::Customer {
            email: Some(TEST_EMAIL.to_string().into()),
            name: None,
            id: None,  // Don't send fake customer ID - Stripe will reject it
            connector_id: None,  // Don't send fake connector customer ID
            phone_number: None,
        }),
        address: Some(grpc_api_types::payments::PaymentAddress::default()),
        auth_type: i32::from(AuthenticationType::NoThreeDs),
        merchant_transaction_id: Some(Identifier {
            id_type: Some(IdType::Id(generate_unique_id("stripe_test"))),
        }),
        enrolled_for_3ds: Some(false),
        request_incremental_authorization: Some(false),
        capture_method: Some(i32::from(capture_method)),
        ..Default::default()
    }
}

fn create_capture_request(transaction_id: &str) -> PaymentServiceCaptureRequest {
    PaymentServiceCaptureRequest {
        connector_transaction_id: Some(Identifier {
            id_type: Some(IdType::Id(transaction_id.to_string())),
        }),
        amount_to_capture: Some(grpc_api_types::payments::Money {
            minor_amount: TEST_AMOUNT,
            currency: i32::from(Currency::Usd),
        }),
        multiple_capture_data: None,
        merchant_capture_id: None,
        ..Default::default()
    }
}

fn create_void_request(transaction_id: &str) -> PaymentServiceVoidRequest {
    PaymentServiceVoidRequest {
        connector_transaction_id: Some(Identifier {
            id_type: Some(IdType::Id(transaction_id.to_string())),
        }),
        cancellation_reason: None,
        request_ref_id: Some(Identifier {
            id_type: Some(IdType::Id(generate_unique_id("stripe_void"))),
        }),
        all_keys_required: None,
        browser_info: None,
        amount: None,
        ..Default::default()
    }
}

fn create_refund_request(transaction_id: &str) -> PaymentServiceRefundRequest {
    create_refund_request_with_amount(transaction_id, TEST_AMOUNT, Currency::Usd)
}

fn create_refund_request_with_amount(
    transaction_id: &str,
    refund_amount: i64,
    currency: Currency,
) -> PaymentServiceRefundRequest {
    PaymentServiceRefundRequest {
        merchant_refund_id: Some(Identifier {
            id_type: Some(IdType::Id(format!("refund_{}", generate_unique_id("test")))),
        }),
        connector_transaction_id: Some(Identifier {
            id_type: Some(IdType::Id(transaction_id.to_string())),
        }),
        payment_amount: TEST_AMOUNT,
        refund_amount: Some(grpc_api_types::payments::Money {
            minor_amount: refund_amount,
            currency: i32::from(currency),
        }),
        reason: None,
        browser_info: None,
        merchant_account_id: None,
        capture_method: None,
        webhook_url: Some("https://example.com/webhook".to_string()),
        ..Default::default()
    }
}

fn create_sync_request(transaction_id: &str) -> PaymentServiceGetRequest {
    PaymentServiceGetRequest {
        connector_transaction_id: Some(Identifier {
            id_type: Some(IdType::Id(transaction_id.to_string())),
        }),
        encoded_data: None,
        capture_method: None,
        handle_response: None,
        amount: Some(grpc_api_types::payments::Money {
            minor_amount: TEST_AMOUNT,
            currency: i32::from(Currency::Usd),
        }),
        state: None,
        metadata: None,
        feature_data: None,
        setup_future_usage: None,
        sync_type: None,
        connector_order_reference_id: None,
        test_mode: None,
        payment_experience: None,
    }
}

fn create_refund_sync_request(transaction_id: &str, refund_id: &str) -> RefundServiceGetRequest {
    RefundServiceGetRequest {
        connector_transaction_id: Some(Identifier {
            id_type: Some(IdType::Id(transaction_id.to_string())),
        }),
        refund_id: refund_id.to_string(),
        refund_reason: None,
        request_ref_id: None,
        ..Default::default()
    }
}

// Step Definitions

#[given("I am using the Stripe connector")]
fn set_stripe_connector(world: &mut StripeWorld) {
    world.connector_name = "stripe".to_string();
    world.auth_type = "header-key".to_string();
}

#[given("I have a valid merchant account")]
fn set_merchant(world: &mut StripeWorld) {
    world.merchant_id = "merchant_1234".to_string();
}

#[given(expr = "I have a test card with number {string}")]
fn set_test_card(world: &mut StripeWorld, card_number: String) {
    world.test_card_number = card_number;
}

#[given(expr = "I want to process a payment of {int} cents in {string}")]
fn set_payment_amount(world: &mut StripeWorld, amount: i64, currency: String) {
    world.payment_amount = amount;
    world.currency = currency;
}

#[given("I want to use automatic capture")]
fn set_auto_capture(world: &mut StripeWorld) {
    world.capture_method = CaptureMethod::Automatic;
}

#[given("I want to use manual capture")]
fn set_manual_capture(world: &mut StripeWorld) {
    world.capture_method = CaptureMethod::Manual;
}

#[when("I authorize the payment")]
async fn authorize_payment(world: &mut StripeWorld) {
    let request = create_authorize_request(world.capture_method);

    // DEBUG: Print the request being sent
    eprintln!("\n========== STRIPE REQUEST ==========");
    eprintln!("Amount: {} cents", request.amount.as_ref().map(|m| m.minor_amount).unwrap_or(0));
    eprintln!("Currency: {:?}", request.amount.as_ref().map(|m| m.currency));
    eprintln!("Capture Method: {:?}", world.capture_method);
    eprintln!("Connector: {}", world.connector_name);
    eprintln!("Merchant ID: {}", world.merchant_id);

    let mut grpc_request = Request::new(request);

    // Add metadata
    world.add_metadata(&mut grpc_request);

    eprintln!("\nSending gRPC authorize request...");
    eprintln!("=====================================\n");

    match world.payment_client.authorize(grpc_request).await {
        Ok(response) => {
            let inner = response.into_inner();

            // DEBUG: Print the response received
            eprintln!("\n========== STRIPE RESPONSE ==========");
            eprintln!("Status Code: {}", inner.status);
            eprintln!("Status: {:?}", PaymentStatus::try_from(inner.status));
            eprintln!("Transaction ID: {:?}", inner.connector_transaction_id);
            eprintln!("Error: {:?}", inner.error);
            eprintln!("Redirection Data: {:?}", inner.redirection_data);
            eprintln!("======================================\n");

            // Capture error from response if present
            if let Some(ref error_info) = inner.error {
                let (code, message) = error_info.connector_details.as_ref()
                    .map(|d| (d.code.as_deref(), d.message.as_deref()))
                    .unwrap_or((None, None));
                world.error = Some(format!(
                    "Payment error: code={:?}, message={:?}",
                    code, message
                ));
            }

            world.last_payment_status = match PaymentStatus::try_from(inner.status) {
                Ok(status) => Some(status),
                Err(_) => {
                    world.error = Some(format!("Invalid payment status: {}", inner.status));
                    Some(PaymentStatus::AttemptStatusUnspecified)
                }
            };

            world.last_transaction_id = inner.connector_transaction_id.and_then(|id| {
                id.id_type.map(|id_type| match id_type {
                    IdType::Id(s) => s,
                    _ => String::new(),
                })
            });
        }
        Err(e) => {
            eprintln!("\n========== STRIPE ERROR ==========");
            eprintln!("gRPC Error: {}", e);
            eprintln!("===================================\n");
            world.error = Some(e.to_string());
        }
    }
}

#[when("I capture the payment")]
async fn capture_payment(world: &mut StripeWorld) {
    let transaction_id = world
        .last_transaction_id
        .clone()
        .expect("No transaction ID available");

    let request = create_capture_request(&transaction_id);
    let mut grpc_request = Request::new(request);

    world.add_metadata(&mut grpc_request);

    match world.payment_client.capture(grpc_request).await {
        Ok(response) => {
            let inner = response.into_inner();
            world.last_payment_status = Some(PaymentStatus::try_from(inner.status).unwrap());
        }
        Err(e) => {
            world.error = Some(e.to_string());
        }
    }
}

#[when("I void the payment")]
async fn void_payment(world: &mut StripeWorld) {
    let transaction_id = world
        .last_transaction_id
        .clone()
        .expect("No transaction ID available");

    let request = create_void_request(&transaction_id);
    let mut grpc_request = Request::new(request);

    world.add_metadata(&mut grpc_request);

    match world.payment_client.void(grpc_request).await {
        Ok(response) => {
            let inner = response.into_inner();
            world.last_payment_status = Some(PaymentStatus::try_from(inner.status).unwrap());
        }
        Err(e) => {
            world.error = Some(e.to_string());
        }
    }
}

#[when("I process a refund")]
async fn process_refund(world: &mut StripeWorld) {
    let transaction_id = world
        .last_transaction_id
        .clone()
        .expect("No transaction ID available");

    let request = create_refund_request(&transaction_id);
    let mut grpc_request = Request::new(request);

    world.add_metadata(&mut grpc_request);

    match world.payment_client.refund(grpc_request).await {
        Ok(response) => {
            let inner = response.into_inner();
            world.last_refund_status = Some(RefundStatus::try_from(inner.status).unwrap());
            world.last_refund_id = Some(inner.connector_refund_id);
        }
        Err(e) => {
            world.error = Some(e.to_string());
        }
    }
}

#[when(expr = "I want to attempt a refund of the payment for {int} cents in {string}")]
async fn process_refund_with_amount(world: &mut StripeWorld, refund_amount: i64, currency: String) {
    let transaction_id = world
        .last_transaction_id
        .clone()
        .expect("No transaction ID available");

    let currency_enum = match currency.as_str() {
        "USD" => Currency::Usd,
        "EUR" => Currency::Eur,
        "GBP" => Currency::Gbp,
        _ => panic!("Unsupported currency: {}", currency),
    };

    let request = create_refund_request_with_amount(&transaction_id, refund_amount, currency_enum);
    let mut grpc_request = Request::new(request);

    world.add_metadata(&mut grpc_request);

    match world.payment_client.refund(grpc_request).await {
        Ok(response) => {
            let inner = response.into_inner();
            world.last_refund_status = Some(RefundStatus::try_from(inner.status).unwrap());
            world.last_refund_id = Some(inner.connector_refund_id);
        }
        Err(e) => {
            world.error = Some(e.to_string());
        }
    }
}

#[when("I sync the payment status")]
async fn sync_payment(world: &mut StripeWorld) {
    let transaction_id = world
        .last_transaction_id
        .clone()
        .expect("No transaction ID available");

    let request = create_sync_request(&transaction_id);
    let mut grpc_request = Request::new(request);

    world.add_metadata(&mut grpc_request);

    match world.payment_client.get(grpc_request).await {
        Ok(response) => {
            let inner = response.into_inner();
            world.last_payment_status = Some(PaymentStatus::try_from(inner.status).unwrap());
        }
        Err(e) => {
            world.error = Some(e.to_string());
        }
    }
}

#[when("I sync the refund status")]
async fn sync_refund(world: &mut StripeWorld) {
    let transaction_id = world
        .last_transaction_id
        .clone()
        .expect("No transaction ID available");
    let refund_id = world
        .last_refund_id
        .clone()
        .expect("No refund ID available");

    let request = create_refund_sync_request(&transaction_id, &refund_id);
    let mut grpc_request = Request::new(request);

    world.add_metadata(&mut grpc_request);

    match world.refund_client.get(grpc_request).await {
        Ok(response) => {
            let inner = response.into_inner();
            world.last_refund_status = Some(RefundStatus::try_from(inner.status).unwrap());
        }
        Err(e) => {
            world.error = Some(e.to_string());
        }
    }
}

// Then steps for assertions

#[then(expr = "the payment should be {string}")]
fn check_payment_status(world: &mut StripeWorld, expected_status: String) {
    let actual_status = world
        .last_payment_status
        .as_ref()
        .expect("No payment status available");

    let expected = match expected_status.as_str() {
        "authorized" => PaymentStatus::Authorized,
        "charged" | "captured" => PaymentStatus::Charged,
        "voided" | "cancelled" => PaymentStatus::Voided,
        "failed" => PaymentStatus::Failure,
        _ => panic!("Unknown payment status: {}", expected_status),
    };

    // Handle AttemptStatusUnspecified (0) as a special case - treat as failure
    if *actual_status == PaymentStatus::AttemptStatusUnspecified {
        panic!(
            "Payment status is 'AttemptStatusUnspecified' - this usually means the payment failed or returned an error. Check world.error: {:?}",
            world.error
        );
    }

    assert_eq!(*actual_status, expected, "Payment status mismatch");
}

#[then(expr = "the refund should be {string}")]
fn check_refund_status(world: &mut StripeWorld, expected_status: String) {
    let actual_status = world
        .last_refund_status
        .as_ref()
        .expect("No refund status available");

    let expected = match expected_status.as_str() {
        "successful" | "success" => RefundStatus::RefundSuccess,
        "failed" | "failure" => RefundStatus::RefundFailure,
        _ => panic!("Unknown refund status: {}", expected_status),
    };

    // Handle Unspecified status - treat as failure if we're expecting failure
    if *actual_status == RefundStatus::Unspecified {
        if expected == RefundStatus::RefundFailure {
            // This is expected - the refund failed and status is unspecified
            return;
        }
        panic!(
            "Refund status is 'Unspecified' - this usually means the refund failed. Check world.error: {:?}",
            world.error
        );
    }

    assert_eq!(*actual_status, expected, "Refund status mismatch");
}

#[then("I should receive a transaction ID")]
fn check_transaction_id(world: &mut StripeWorld) {
    assert!(
        world.last_transaction_id.is_some(),
        "Transaction ID should be present"
    );
    assert!(
        !world.last_transaction_id.as_ref().unwrap().is_empty(),
        "Transaction ID should not be empty"
    );
}

#[then("I should receive a refund ID")]
fn check_refund_id(world: &mut StripeWorld) {
    assert!(
        world.last_refund_id.is_some(),
        "Refund ID should be present"
    );
    assert!(
        !world.last_refund_id.as_ref().unwrap().is_empty(),
        "Refund ID should not be empty"
    );
}

#[then("no error should occur")]
fn check_no_error(world: &mut StripeWorld) {
    if let Some(ref error) = world.error {
        panic!("Expected no error but got: {}", error);
    }
}
