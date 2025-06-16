#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]

use grpc_server::{app, configs};
mod common;
use base64::{engine::general_purpose, Engine};
use grpc_api_types::{
    health_check::{health_client::HealthClient, HealthCheckRequest},
    payments::{
        payment_service_client::PaymentServiceClient, AccessToken, AttemptStatus, AuthenticationType, CaptureMethod, Currency, PaymentMethod, PaymentMethodType, PaymentsAuthorizeRequest, PaymentsAuthorizeResponse, PaymentsCaptureRequest, PaymentsSyncRequest, RefundStatus, RefundsRequest, RefundsSyncRequest
    },
};
use std::env;
use std::time::{SystemTime, UNIX_EPOCH};
use tonic::{transport::Channel, Request};

// Helper function to get current timestamp
fn get_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// Constants for Jpmorgan connector
const CONNECTOR_NAME: &str = "jpmorgan";

// Environment variable names for API credentials (can be set or overridden with provided values)
const JPMORGAN_ACCESS_TOKEN_ENV: &str = "TEST_JPMORGAN_ACCESS_TOKEN";

// Test card data
const TEST_AMOUNT: i64 = 10000;
const TEST_CARD_NUMBER: &str = "4000000000001091"; // Valid test card for Jpmorgan
const TEST_CARD_EXP_MONTH: &str = "12";
const TEST_CARD_EXP_YEAR: &str = "2027";
const TEST_CARD_CVC: &str = "123";
const TEST_CARD_HOLDER: &str = "Test User";
const TEST_EMAIL: &str = "customer@example.com";

fn add_jpmorgan_metadata<T>(request: &mut Request<T>) {
    request.metadata_mut().append(
        "x-connector",
        CONNECTOR_NAME.parse().expect("Failed to parse x-connector"),
    );
    request.metadata_mut().append(
        "x-auth",
        "no-key".parse().expect("Failed to parse x-auth"),
    );
}

// Helper function to extract connector transaction ID from response
fn extract_transaction_id(response: &PaymentsAuthorizeResponse) -> String {
    match &response.resource_id {
        Some(id) => match id.id.as_ref().unwrap() {
            grpc_api_types::payments::response_id::Id::ConnectorTransactionId(id) => id.clone(),
            _ => panic!("Expected connector transaction ID"),
        },
        None => panic!("Resource ID is None"),
    }
}

// Helper function to create payment authorize request
fn create_payment_authorize_request(capture_method: CaptureMethod) -> PaymentsAuthorizeRequest {
    let access_token =
        env::var(JPMORGAN_ACCESS_TOKEN_ENV).expect("TEST_JPMORGAN_ACCESS_TOKEN environment variable is required");

    // Initialize with all required fields
    PaymentsAuthorizeRequest {
        amount: TEST_AMOUNT,
        minor_amount: TEST_AMOUNT,
        currency: i32::from(Currency::Usd),
        payment_method: i32::from(PaymentMethod::Card),
        payment_method_data: Some(grpc_api_types::payments::PaymentMethodData {
            data: Some(grpc_api_types::payments::payment_method_data::Data::Card(
                grpc_api_types::payments::Card {
                    card_number: TEST_CARD_NUMBER.to_string(),
                    card_exp_month: TEST_CARD_EXP_MONTH.to_string(),
                    card_exp_year: TEST_CARD_EXP_YEAR.to_string(),
                    card_cvc: TEST_CARD_CVC.to_string(),
                    card_holder_name: Some(TEST_CARD_HOLDER.to_string()),
                    card_issuer: None,
                    card_network: None,
                    card_type: None,
                    card_issuing_country: None,
                    bank_code: None,
                    nick_name: None,
                },
            )),
        }),
        return_url: Some("https://hyperswitch.io/connector-service/".to_string()),
        email: Some(TEST_EMAIL.to_string()),
        access_token: Some(AccessToken{
            token:access_token,
            expires: 10000000,
        }),
        address: Some(grpc_api_types::payments::PaymentAddress::default()),
        auth_type: i32::from(AuthenticationType::NoThreeDs),
        connector_request_reference_id: format!("jpmorgan_test_{}", get_timestamp()),
        enrolled_for_3ds: false,
        request_incremental_authorization: false,
        capture_method: Some(i32::from(capture_method)),
        payment_method_type: Some(i32::from(PaymentMethodType::Credit)),
        ..Default::default()
    }
}

// Helper function to create a payment sync request
fn create_payment_sync_request(transaction_id: &str) -> PaymentsSyncRequest {
    PaymentsSyncRequest {
        resource_id: transaction_id.to_string(),
        connector_request_reference_id: Some(format!("jpmorgan_sync_{}", get_timestamp())),
    }
}

// Test payment authorization with auto capture
#[tokio::test]
async fn test_payment_authorization_auto_capture() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        // Create the payment authorization request
        let request = create_payment_authorize_request(CaptureMethod::Automatic);

        // Add metadata headers
        let mut grpc_request = Request::new(request);
        add_jpmorgan_metadata(&mut grpc_request);

        // Send the request
        let response = client
            .payment_authorize(grpc_request)
            .await
            .expect("gRPC payment_authorize call failed")
            .into_inner();

        assert!(
            response.status == i32::from(AttemptStatus::Charged),
            "Payment should be in Charged state"
        );
    });
}

// Test payment authorization with manual capture
#[tokio::test]
async fn test_payment_authorization_manual_capture() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        // Create the payment authorization request with manual capture
        let auth_request = create_payment_authorize_request(CaptureMethod::Manual);

        // Add metadata headers for auth request
        let mut auth_grpc_request = Request::new(auth_request);
        add_jpmorgan_metadata(&mut auth_grpc_request);

        // Send the auth request
        let auth_response = client
            .payment_authorize(auth_grpc_request)
            .await
            .expect("gRPC payment_authorize call failed")
            .into_inner();

        // Verify payment status
        assert!(
            auth_response.status == i32::from(AttemptStatus::Authorized),
            "Payment should be in Authorized state"
        );
    });
}

