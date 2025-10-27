#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]

use cards::CardNumber;
use grpc_server::{app, configs};
mod common;
use std::{
    collections::HashMap,
    env,
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

use grpc_api_types::{
    health_check::{health_client::HealthClient, HealthCheckRequest},
    payments::{
        card_payment_method_type, identifier::IdType, payment_method,
        payment_service_client::PaymentServiceClient, AuthenticationType, CaptureMethod,
        CardDetails, CardPaymentMethodType, Currency, Identifier, PaymentMethod,
        PaymentServiceAuthorizeRequest, PaymentServiceAuthorizeResponse,
        PaymentServiceCaptureRequest, PaymentServiceGetRequest, PaymentServiceVoidRequest,
        PaymentStatus,
    },
};
use hyperswitch_masking::Secret;
use serde_json::json;
use tonic::{transport::Channel, Request};

// Constants for Peachpayments connector
const CONNECTOR_NAME: &str = "peachpayments";
const AUTH_TYPE: &str = "body-key";
const MERCHANT_ID: &str = "merchant_1758520172";

// Environment variable names for API credentials (can be set or overridden with
// provided values)
const PEACHPAYMENTS_API_KEY_ENV: &str = "TEST_PEACHPAYMENTS_API_KEY";
const PEACHPAYMENTS_KEY1_ENV: &str = "TEST_PEACHPAYMENTS_KEY1";

// Test card data
const TEST_AMOUNT: i64 = 1000;
const TEST_CARD_NUMBER: &str = "4242424242424242"; // Valid test card for Peachpayments
const TEST_CARD_EXP_MONTH: &str = "10";
const TEST_CARD_EXP_YEAR: &str = "25";
const TEST_CARD_CVC: &str = "123";
const TEST_CARD_HOLDER: &str = "Test User";
const TEST_EMAIL: &str = "customer@example.com";

// Helper function to get current timestamp
fn get_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// Helper function to add Peachpayments metadata headers to a request
fn add_peachpayments_metadata<T>(request: &mut Request<T>) {
    // Get API credentials from environment variables - throw error if not set
    let api_key = env::var(PEACHPAYMENTS_API_KEY_ENV)
        .expect("TEST_PEACHPAYMENTS_API_KEY environment variable is required");
    let key1 = env::var(PEACHPAYMENTS_KEY1_ENV)
        .expect("TEST_PEACHPAYMENTS_KEY1 environment variable is required");

    request.metadata_mut().append(
        "x-connector",
        CONNECTOR_NAME.parse().expect("Failed to parse x-connector"),
    );
    request
        .metadata_mut()
        .append("x-auth", AUTH_TYPE.parse().expect("Failed to parse x-auth"));

    request.metadata_mut().append(
        "x-api-key",
        api_key.parse().expect("Failed to parse x-api-key"),
    );
    request
        .metadata_mut()
        .append("x-key1", key1.parse().expect("Failed to parse x-key1"));
    request.metadata_mut().append(
        "x-merchant-id",
        MERCHANT_ID.parse().expect("Failed to parse x-merchant-id"),
    );
    request.metadata_mut().append(
        "x-request-id",
        format!("test_request_{}", get_timestamp())
            .parse()
            .expect("Failed to parse x-request-id"),
    );
}

// Helper function to extract connector transaction ID from response
fn extract_transaction_id(response: &PaymentServiceAuthorizeResponse) -> String {
    match &response.transaction_id {
        Some(id) => match id.id_type.as_ref().unwrap() {
            IdType::Id(id) => id.clone(),
            _ => panic!("Expected connector transaction ID"),
        },
        None => panic!("Resource ID is None"),
    }
}

// Helper function to create a payment authorize request
fn create_payment_authorize_request(
    capture_method: CaptureMethod,
) -> PaymentServiceAuthorizeRequest {
    let card_details = card_payment_method_type::CardType::Credit(CardDetails {
        card_number: Some(CardNumber::from_str(TEST_CARD_NUMBER).unwrap()),
        card_exp_month: Some(Secret::new(TEST_CARD_EXP_MONTH.to_string())),
        card_exp_year: Some(Secret::new(TEST_CARD_EXP_YEAR.to_string())),
        card_cvc: Some(Secret::new(TEST_CARD_CVC.to_string())),
        card_holder_name: Some(Secret::new(TEST_CARD_HOLDER.to_string())),
        card_network: Some(1),
        card_issuer: None,
        card_type: None,
        card_issuing_country_alpha2: None,
        bank_code: None,
        nick_name: None,
    });
    let mut metadata: HashMap<String, String> = HashMap::new();

    let client_merchant_reference_id =
        env::var("TEST_CLIENT_MERCHANT_REFERENCE_ID").expect("missing env var");
    let merchant_name = env::var("TEST_MERCHANT_NAME").expect("missing env var");
    let mcc = env::var("TEST_MCC").expect("missing env var");
    let route = env::var("TEST_ROUTE").expect("missing env var");
    let merchant_id = env::var("TEST_PEACHPAYMENTS_MERCHANT_ID").expect("missing env var");

    let tid = env::var("TEST_TID").expect("missing env var");
    let connector_meta_data = json!({
        "client_merchant_reference_id": client_merchant_reference_id,
        "name": merchant_name,
        "mcc": mcc,
        "route": route,
        "mid": merchant_id,
        "tid": tid,
    })
    .to_string();

    metadata.insert("connector_meta_data".to_string(), connector_meta_data);

    PaymentServiceAuthorizeRequest {
        amount: TEST_AMOUNT,
        minor_amount: TEST_AMOUNT,
        currency: i32::from(Currency::Usd),
        payment_method: Some(PaymentMethod {
            payment_method: Some(payment_method::PaymentMethod::Card(CardPaymentMethodType {
                card_type: Some(card_details),
            })),
        }),
        return_url: Some("https://duck.com".to_string()),
        email: Some(TEST_EMAIL.to_string().into()),
        address: Some(grpc_api_types::payments::PaymentAddress::default()),
        auth_type: i32::from(AuthenticationType::NoThreeDs),
        request_ref_id: Some(Identifier {
            id_type: Some(IdType::Id(format!("ref_{}", get_timestamp()))),
        }),
        enrolled_for_3ds: false,
        request_incremental_authorization: false,
        capture_method: Some(i32::from(capture_method)),
        metadata,
        ..Default::default()
    }
}

// Helper function to create a payment sync request
fn create_payment_sync_request(transaction_id: &str) -> PaymentServiceGetRequest {
    PaymentServiceGetRequest {
        transaction_id: Some(Identifier {
            id_type: Some(IdType::Id(transaction_id.to_string())),
        }),
        request_ref_id: None,
        access_token: None,
        // all_keys_required: None,
        capture_method: None,
        handle_response: None,
        amount: TEST_AMOUNT,
        currency: i32::from(Currency::Eur),
    }
}

// Helper function to create a payment capture request
fn create_payment_capture_request(transaction_id: &str) -> PaymentServiceCaptureRequest {
    PaymentServiceCaptureRequest {
        transaction_id: Some(Identifier {
            id_type: Some(IdType::Id(transaction_id.to_string())),
        }),
        amount_to_capture: TEST_AMOUNT,
        currency: i32::from(Currency::Usd),
        multiple_capture_data: None,
        request_ref_id: None,
        ..Default::default()
    }
}

// Helper function to create a payment void request
fn create_payment_void_request(transaction_id: &str) -> PaymentServiceVoidRequest {
    PaymentServiceVoidRequest {
        transaction_id: Some(Identifier {
            id_type: Some(IdType::Id(transaction_id.to_string())),
        }),
        cancellation_reason: Some("requested by customer".to_string()),
        request_ref_id: Some(Identifier {
            id_type: Some(IdType::Id(format!("void_ref_{}", get_timestamp()))),
        }),
        all_keys_required: None,
        browser_info: None,
        access_token: None,
        amount: None,
        currency: Some(i32::from(Currency::Zar)),
    }
}

// Test for basic health check
#[tokio::test]
async fn test_health() {
    grpc_test!(client, HealthClient<Channel>, {
        let response = client
            .check(Request::new(HealthCheckRequest {
                service: "connector_service".to_string(),
            }))
            .await
            .expect("Failed to call health check")
            .into_inner();

        assert_eq!(
            response.status(),
            grpc_api_types::health_check::health_check_response::ServingStatus::Serving
        );
    });
}

// Test payment authorization with manual capture
#[tokio::test]
async fn test_payment_authorization_manual_capture() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        // Add delay of 4 seconds
        tokio::time::sleep(std::time::Duration::from_secs(4)).await;

        // Create the payment authorization request with manual capture
        let auth_request = create_payment_authorize_request(CaptureMethod::Manual);

        // Add metadata headers for auth request
        let mut auth_grpc_request = Request::new(auth_request);
        add_peachpayments_metadata(&mut auth_grpc_request);

        // Send the auth request
        let auth_response = client
            .authorize(auth_grpc_request)
            .await
            .expect("gRPC authorize call failed")
            .into_inner();

        // Verify payment status
        assert!(
            auth_response.status == i32::from(PaymentStatus::AuthenticationPending)
                || auth_response.status == i32::from(PaymentStatus::Pending)
                || auth_response.status == i32::from(PaymentStatus::Authorized),
            "Payment should be in AuthenticationPending or Pending state"
        );

        // Extract the transaction ID
        let transaction_id = extract_transaction_id(&auth_response);

        // Create capture request
        let capture_request = create_payment_capture_request(&transaction_id);

        // Add metadata headers for capture request - make sure they include the terminal_id
        let mut capture_grpc_request = Request::new(capture_request);
        add_peachpayments_metadata(&mut capture_grpc_request);

        // Send the capture request
        let capture_response = client
            .capture(capture_grpc_request)
            .await
            .expect("gRPC payment_capture call failed")
            .into_inner();

        // Verify payment status is charged after capture
        assert!(
            capture_response.status == i32::from(PaymentStatus::Charged),
            "Payment should be in CHARGED state after capture"
        );
    });
}

// Test payment void
#[tokio::test]
async fn test_payment_void() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        // Add delay of 12 seconds
        tokio::time::sleep(std::time::Duration::from_secs(12)).await;

        // First create a payment with manual capture to void
        let auth_request = create_payment_authorize_request(CaptureMethod::Manual);

        // Add metadata headers for auth request
        let mut auth_grpc_request = Request::new(auth_request);
        add_peachpayments_metadata(&mut auth_grpc_request);

        // Send the auth request
        let auth_response = client
            .authorize(auth_grpc_request)
            .await
            .expect("gRPC payment_authorize call failed")
            .into_inner();

        // Extract the transaction ID
        let transaction_id = extract_transaction_id(&auth_response);

        // Verify payment status
        assert!(
            auth_response.status == i32::from(PaymentStatus::Authorized),
            "Payment should be in AUTHORIZED state before voiding"
        );

        // Create void request with a unique reference ID
        let void_request = create_payment_void_request(&transaction_id);

        // Add metadata headers for void request
        let mut void_grpc_request = Request::new(void_request);
        add_peachpayments_metadata(&mut void_grpc_request);

        // Send the void request
        let void_response = client
            .void(void_grpc_request)
            .await
            .expect("gRPC void_payment call failed")
            .into_inner();

        // Verify the void response
        assert!(
            void_response.status == i32::from(PaymentStatus::Voided),
            "Payment should be in VOIDED state after void"
        );

        // Verify the payment status with a sync operation
        let sync_request = create_payment_sync_request(&transaction_id);
        let mut sync_grpc_request = Request::new(sync_request.clone());
        add_peachpayments_metadata(&mut sync_grpc_request);

        // Send the sync request to verify void status
        let sync_response = client
            .get(sync_grpc_request)
            .await
            .expect("gRPC payment_sync call failed")
            .into_inner();

        // Verify the payment is properly voided
        assert!(
            sync_response.status == i32::from(PaymentStatus::Voided),
            "Payment should be in VOIDED state after void sync"
        );
    });
}
