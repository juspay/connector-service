#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]

use grpc_server::{app, configs};
use hyperswitch_masking::Secret;
mod common;

use std::{
    env,
    time::{SystemTime, UNIX_EPOCH},
};

use grpc_api_types::{
    health_check::{health_client::HealthClient, HealthCheckRequest},
    payments::{
        identifier::IdType, payment_method, payment_service_client::PaymentServiceClient,
        wallet_payment_method_type, AuthenticationType, CaptureMethod, Currency, Identifier,
        MifinityWallet, PaymentMethod, PaymentServiceAuthorizeRequest,
        PaymentServiceAuthorizeResponse, PaymentServiceGetRequest, PaymentStatus,
        WalletPaymentMethodType,
    },
};
use tonic::{transport::Channel, Request};

// Helper function to get current timestamp
fn get_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// Constants for Mifinity connector
const CONNECTOR_NAME: &str = "mifinity";

// Environment variable names for API credentials (can be set or overridden with provided values)
const MIFINITY_API_KEY_ENV: &str = "TEST_MIFINITY_API_KEY";

// Test card data
const TEST_AMOUNT: i64 = 1000;
const TEST_DESTINATION_ACCOUNT_NUMBER: &str = "5001000001223369"; // Valid test destination account number for Mifinity
const TEST_BRAND_ID: &str = "001";
const TEST_DATE_OF_BIRTH: &str = "2001-10-16";
const TEST_EMAIL: &str = "customer@example.com";

fn add_mifinity_metadata<T>(request: &mut Request<T>) {
    // Get API credentials from environment variables - throw error if not set
    let api_key = env::var(MIFINITY_API_KEY_ENV)
        .expect("TEST_MIFINITY_API_KEY environment variable is required");

    request.metadata_mut().append(
        "x-connector",
        CONNECTOR_NAME.parse().expect("Failed to parse x-connector"),
    );
    request.metadata_mut().append(
        "x-auth",
        "header-key".parse().expect("Failed to parse x-auth"),
    );
    request.metadata_mut().append(
        "x-api-key",
        api_key.parse().expect("Failed to parse x-api-key"),
    );
    // Add merchant ID which is required by the server
    request.metadata_mut().append(
        "x-merchant-id",
        "12abc123-f8a3-99b8-9ef8-b31180358hh4"
            .parse()
            .expect("Failed to parse x-merchant-id"),
    );
    // Add tenant ID which is required by the server
    request.metadata_mut().append(
        "x-tenant-id",
        "default".parse().expect("Failed to parse x-tenant-id"),
    );
    // Add request ID which is required by the server
    request.metadata_mut().append(
        "x-request-id",
        format!("mifinity_req_{}", get_timestamp())
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
fn create_authorize_request(capture_method: CaptureMethod) -> PaymentServiceAuthorizeRequest {
    let wallet_details = wallet_payment_method_type::WalletType::Mifinity(MifinityWallet {
        date_of_birth: Some(Secret::new(TEST_DATE_OF_BIRTH.to_string())),
        language_preference: Some("en-US".to_string()),
    });

    // Create connector metadata JSON string
    let connector_meta_data = format!(
        "{{\"brand_id\":\"{TEST_BRAND_ID}\",\"destination_account_number\":\"{TEST_DESTINATION_ACCOUNT_NUMBER}\"}}"
    );

    PaymentServiceAuthorizeRequest {
        amount: TEST_AMOUNT,
        minor_amount: TEST_AMOUNT,
        currency: i32::from(Currency::Eur),
        payment_method: Some(PaymentMethod {
            payment_method: Some(payment_method::PaymentMethod::Wallet(
                WalletPaymentMethodType {
                    wallet_type: Some(wallet_details),
                },
            )),
        }),
        return_url: Some(
            "https://hyperswitch.io/connector-service/authnet_webhook_grpcurl".to_string(),
        ),
        email: Some(TEST_EMAIL.to_string().into()),
        address: Some(grpc_api_types::payments::PaymentAddress {
            shipping_address: Some(grpc_api_types::payments::Address::default()),
            billing_address: Some(grpc_api_types::payments::Address {
                first_name: Some("joseph".to_string().into()),
                last_name: Some("Doe".to_string().into()),
                phone_number: Some("8056594427".to_string().into()),
                phone_country_code: Some("+91".to_string()),
                email: Some("swangi@gmail.com".to_string().into()),
                line1: Some("1467".to_string().into()),
                line2: Some("Harrison Street".to_string().into()),
                line3: Some("Harrison Street".to_string().into()),
                city: Some("San Fransico".to_string().into()),
                state: Some("California".to_string().into()),
                zip_code: Some("94122".to_string().into()),
                country_alpha2_code: Some(grpc_api_types::payments::CountryAlpha2::De.into()),
            }),
        }),
        auth_type: i32::from(AuthenticationType::NoThreeDs),
        request_ref_id: Some(Identifier {
            id_type: Some(IdType::Id(format!("mifinity_test_{}", get_timestamp()))),
        }),
        connector_customer_id: Some("Test_customer".to_string()),
        enrolled_for_3ds: false,
        request_incremental_authorization: false,
        capture_method: Some(i32::from(capture_method)),
        metadata: {
            let mut metadata = std::collections::HashMap::new();
            metadata.insert("connector_meta_data".to_string(), connector_meta_data);
            metadata
        },
        // payment_method_type: Some(i32::from(PaymentMethodType::Credit)),
        ..Default::default()
    }
}

// Helper function to create a payment sync request
fn create_payment_sync_request(transaction_id: &str) -> PaymentServiceGetRequest {
    PaymentServiceGetRequest {
        transaction_id: Some(Identifier {
            id_type: Some(IdType::Id(transaction_id.to_string())),
        }),
        request_ref_id: Some(Identifier {
            id_type: Some(IdType::Id(transaction_id.to_string())),
        }),
        access_token: None,
        capture_method: None,
        handle_response: None,
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
async fn test_payment_authorization_auto_capture() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        // Create the payment authorization request
        let request = create_authorize_request(CaptureMethod::Automatic);

        // Add metadata headers
        let mut grpc_request = Request::new(request);
        add_mifinity_metadata(&mut grpc_request);

        // Send the request
        let response = client
            .authorize(grpc_request)
            .await
            .expect("gRPC authorize call failed")
            .into_inner();

        assert!(
            response.status == i32::from(PaymentStatus::AuthenticationPending)
                || response.status == i32::from(PaymentStatus::Pending),
            "Payment should be in AuthenticationPending or Pending state"
        );
    });
}

// Test payment sync with auto capture
#[tokio::test]
async fn test_payment_sync_auto_capture() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        // Add delay of 2 seconds
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        // Create the payment authorization request
        let request = create_authorize_request(CaptureMethod::Automatic);

        // Add metadata headers
        let mut grpc_request = Request::new(request);
        add_mifinity_metadata(&mut grpc_request);

        // Send the request
        let response = client
            .authorize(grpc_request)
            .await
            .expect("gRPC authorize call failed")
            .into_inner();

        // Extract the transaction ID
        let transaction_id = extract_transaction_id(&response);

        // Create sync request
        let sync_request = create_payment_sync_request(&transaction_id);

        // Add metadata headers for sync request
        let mut sync_grpc_request = Request::new(sync_request);
        add_mifinity_metadata(&mut sync_grpc_request);

        // Send the sync request
        let sync_response = client
            .get(sync_grpc_request)
            .await
            .expect("gRPC payment_sync call failed")
            .into_inner();

        // Verify the sync response
        assert!(
            sync_response.status == i32::from(PaymentStatus::AuthenticationPending)
                || sync_response.status == i32::from(PaymentStatus::Charged),
            "Payment should be in AuthenticationPending or Charged state"
        );
    });
}
