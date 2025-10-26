#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]

use grpc_server::{app, configs};
mod common;

use grpc_api_types::{
    health_check::{health_client::HealthClient, HealthCheckRequest},
    payments::{
        identifier::IdType, payment_method, payment_service_client::PaymentServiceClient,
        AuthenticationType, CaptureMethod, CryptoCurrency, CryptoCurrencyPaymentMethodType,
        Currency, Identifier, PaymentMethod, PaymentServiceAuthorizeRequest,
        PaymentServiceAuthorizeResponse, PaymentServiceGetRequest, PaymentStatus,
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

// Constants for Cryptopay connector
const CONNECTOR_NAME: &str = "cryptopay";
const AUTH_TYPE: &str = "body-key";
const MERCHANT_ID: &str = "merchant_1234";

// Environment variable names for API credentials (can be set or overridden with provided values)
const CRYPTOPAY_API_KEY_ENV: &str = "TEST_CRYPTOPAY_API_KEY";
const CRYPTOPAY_KEY1_ENV: &str = "TEST_CRYPTOPAY_KEY1";

const TEST_EMAIL: &str = "customer@example.com";

// Test card data
const TEST_AMOUNT: i64 = 1000;
const TEST_PAY_CURRENCY: &str = "LTC";
const TEST_NETWORK: &str = "litecoin";

fn add_cryptopay_metadata<T>(request: &mut Request<T>) {
    // Get API credentials from environment variables - throw error if not set
    let api_key = env::var(CRYPTOPAY_API_KEY_ENV)
        .expect("TEST_CRYPTOPAY_API_KEY environment variable is required");
    let key1 = env::var(CRYPTOPAY_KEY1_ENV)
        .expect("TEST_CRYPTOPAY_KEY1_ENV environment variable is required");

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
fn extract_request_ref_id(response: &PaymentServiceAuthorizeResponse) -> String {
    match &response.response_ref_id {
        Some(id) => match id.id_type.as_ref().unwrap() {
            IdType::Id(id) => id.clone(),
            _ => panic!("Expected connector response_ref_id"),
        },
        None => panic!("Resource ID is None"),
    }
}

// Helper function to create a payment authorize request
fn create_authorize_request(capture_method: CaptureMethod) -> PaymentServiceAuthorizeRequest {
    PaymentServiceAuthorizeRequest {
        amount: TEST_AMOUNT,
        minor_amount: TEST_AMOUNT,
        currency: i32::from(Currency::Usd),
        payment_method: Some(PaymentMethod {
            payment_method: Some(payment_method::PaymentMethod::Crypto(
                CryptoCurrencyPaymentMethodType {
                    crypto_currency: Some(CryptoCurrency {
                        pay_currency: Some(TEST_PAY_CURRENCY.to_string()),
                        network: Some(TEST_NETWORK.to_string()),
                    }),
                },
            )),
        }),
        return_url: Some(
            "https://hyperswitch.io/connector-service/authnet_webhook_grpcurl".to_string(),
        ),
        webhook_url: Some(
            "https://hyperswitch.io/connector-service/authnet_webhook_grpcurl".to_string(),
        ),
        email: Some(TEST_EMAIL.to_string().into()),
        address: Some(grpc_api_types::payments::PaymentAddress::default()),
        auth_type: i32::from(AuthenticationType::NoThreeDs),
        request_ref_id: Some(Identifier {
            id_type: Some(IdType::Id(format!("cryptopay_test_{}", get_timestamp()))),
        }),
        enrolled_for_3ds: false,
        request_incremental_authorization: false,
        capture_method: Some(i32::from(capture_method)),
        // payment_method_type: Some(i32::from(PaymentMethodType::Credit)),
        ..Default::default()
    }
}

// Helper function to create a payment sync request
fn create_payment_sync_request(request_ref_id: &str) -> PaymentServiceGetRequest {
    PaymentServiceGetRequest {
        transaction_id: Some(Identifier {
            id_type: Some(IdType::Id("not_required".to_string())),
        }),
        request_ref_id: Some(Identifier {
            id_type: Some(IdType::Id(request_ref_id.to_string())),
        }),
        capture_method: None,
        access_token: None,
        handle_response: None,
        amount: TEST_AMOUNT,
        currency: i32::from(Currency::Usd),
        state: None,
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

// Test payment authorization with auto capture
#[tokio::test]
async fn test_payment_authorization_and_psync() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        // Create the payment authorization request
        let request = create_authorize_request(CaptureMethod::Automatic);

        // Add metadata headers
        let mut grpc_request = Request::new(request);
        add_cryptopay_metadata(&mut grpc_request);

        // Send the request
        let response = client
            .authorize(grpc_request)
            .await
            .expect("gRPC authorize call failed")
            .into_inner();

        assert!(
            response.status == i32::from(PaymentStatus::AuthenticationPending),
            "Payment should be in AuthenticationPending state"
        );

        let request_ref_id = extract_request_ref_id(&response);

        // Create sync request
        let sync_request = create_payment_sync_request(&request_ref_id);

        // Add metadata headers for sync request
        let mut sync_grpc_request = Request::new(sync_request);
        add_cryptopay_metadata(&mut sync_grpc_request);

        // Send the sync request
        let sync_response = client
            .get(sync_grpc_request)
            .await
            .expect("gRPC payment_sync call failed")
            .into_inner();

        // Verify the sync response
        assert!(
            sync_response.status == i32::from(PaymentStatus::AuthenticationPending),
            "Payment should be in AuthenticationPending state"
        );
    });
}
