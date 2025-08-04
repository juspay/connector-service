#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]

use grpc_server::{app, configs};
mod common;

use std::{
    env,
    time::{SystemTime, UNIX_EPOCH},
};

use grpc_api_types::{
    health_check::{health_client::HealthClient, HealthCheckRequest},
    payments::{
        card_payment_method_type, identifier::IdType, payment_method,
        payment_service_client::PaymentServiceClient, refund_service_client::RefundServiceClient,
        AuthenticationType, CaptureMethod, CardDetails, CardPaymentMethodType, Currency,
        Identifier, PaymentMethod, PaymentServiceAuthorizeRequest, PaymentServiceAuthorizeResponse,
        PaymentServiceCaptureRequest, PaymentServiceGetRequest, PaymentServiceRefundRequest,
        PaymentServiceVoidRequest, PaymentStatus, RefundResponse, RefundServiceGetRequest,
        RefundStatus,
    },
};
use tonic::{transport::Channel, Request};
use uuid::Uuid;

// Helper function to get current timestamp
fn get_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// Helper function to generate a unique ID using UUID
fn generate_unique_id(prefix: &str) -> String {
    format!("{}_{}", prefix, Uuid::new_v4())
}

// Constants for Fiuu connector
const CONNECTOR_NAME: &str = "fiuu";
const AUTH_TYPE: &str = "signature-key";
const MERCHANT_ID: &str = "merchant_1234";

// Environment variable names for API credentials (can be set or overridden with provided values)
const FIUU_API_KEY_ENV: &str = "TEST_FIUU_API_KEY";
const FIUU_KEY1_ENV: &str = "TEST_FIUU_KEY1"; // processing_channel_id
const FIUU_API_SECRET_ENV: &str = "TEST_FIUU_API_SECRET";

// Test card data
const TEST_AMOUNT: i64 = 1000;
const TEST_CARD_NUMBER: &str = "4111111111111111"; // Valid test card for Fiuu
const TEST_CARD_EXP_MONTH: &str = "12";
const TEST_CARD_EXP_YEAR: &str = "2025";
const TEST_CARD_CVC: &str = "123";
const TEST_CARD_HOLDER: &str = "Test User";
const TEST_EMAIL: &str = "customer@example.com";

fn add_fiuu_metadata<T>(request: &mut Request<T>) {
    // Get API credentials from environment variables - throw error if not set
    let api_key =
        env::var(FIUU_API_KEY_ENV).expect("TEST_FIUU_API_KEY environment variable is required");
    let key1 = env::var(FIUU_KEY1_ENV)
        .unwrap_or_else(|_| panic!("Environment variable {FIUU_KEY1_ENV} must be set"));
    let api_secret = env::var(FIUU_API_SECRET_ENV)
        .unwrap_or_else(|_| panic!("Environment variable {FIUU_API_SECRET_ENV} must be set"));

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
        "x-api-secret",
        api_secret.parse().expect("Failed to parse x-api-secret"),
    );
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

// Helper function to extract connector Refund ID from response
fn extract_refund_id(response: &RefundResponse) -> &String {
    &response.refund_id
}

// Helper function to create a payment authorize request
fn create_authorize_request(capture_method: CaptureMethod) -> PaymentServiceAuthorizeRequest {
    let card_details = card_payment_method_type::CardType::Credit(CardDetails {
        card_number: TEST_CARD_NUMBER.to_string(),
        card_exp_month: TEST_CARD_EXP_MONTH.to_string(),
        card_exp_year: TEST_CARD_EXP_YEAR.to_string(),
        card_cvc: TEST_CARD_CVC.to_string(),
        card_holder_name: Some(TEST_CARD_HOLDER.to_string()),
        card_issuer: None,
        card_network: Some(1),
        card_type: None,
        card_issuing_country_alpha2: None,
        bank_code: None,
        nick_name: None,
    });
    PaymentServiceAuthorizeRequest {
        amount: TEST_AMOUNT,
        minor_amount: TEST_AMOUNT,
        currency: i32::from(Currency::Myr),
        payment_method: Some(PaymentMethod {
            payment_method: Some(payment_method::PaymentMethod::Card(CardPaymentMethodType {
                card_type: Some(card_details),
            })),
        }),
        return_url: Some(
            "https://hyperswitch.io/connector-service/authnet_webhook_grpcurl".to_string(),
        ),
        webhook_url: Some(
            "https://hyperswitch.io/connector-service/authnet_webhook_grpcurl".to_string(),
        ),
        email: Some(TEST_EMAIL.to_string()),
        address: Some(grpc_api_types::payments::PaymentAddress::default()),
        auth_type: i32::from(AuthenticationType::NoThreeDs),
        request_ref_id: Some(Identifier {
            id_type: Some(IdType::Id(generate_unique_id("fiuu_test"))),
        }),
        enrolled_for_3ds: false,
        request_incremental_authorization: false,
        capture_method: Some(i32::from(capture_method)),
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
            id_type: Some(IdType::Id(generate_unique_id("fiuu_sync"))),
        }),
    }
}

// Helper function to create a payment capture request
fn create_payment_capture_request(transaction_id: &str) -> PaymentServiceCaptureRequest {
    PaymentServiceCaptureRequest {
        transaction_id: Some(Identifier {
            id_type: Some(IdType::Id(transaction_id.to_string())),
        }),
        amount_to_capture: TEST_AMOUNT,
        currency: i32::from(Currency::Myr),
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
        cancellation_reason: None,
        request_ref_id: Some(Identifier {
            id_type: Some(IdType::Id(generate_unique_id("fiuu_void"))),
        }),
        all_keys_required: None,
    }
}

// Helper function to create a refund request
fn create_refund_request(transaction_id: &str) -> PaymentServiceRefundRequest {
    PaymentServiceRefundRequest {
        refund_id: format!("refund_{}", generate_unique_id("test")),
        transaction_id: Some(Identifier {
            id_type: Some(IdType::Id(transaction_id.to_string())),
        }),
        currency: i32::from(Currency::Myr),
        payment_amount: TEST_AMOUNT,
        refund_amount: TEST_AMOUNT,
        minor_payment_amount: TEST_AMOUNT,
        minor_refund_amount: TEST_AMOUNT,
        reason: None,
        browser_info: None,
        merchant_account_id: None,
        capture_method: None,
        request_ref_id: None,
        webhook_url: Some(
            "https://hyperswitch.io/connector-service/authnet_webhook_grpcurl".to_string(),
        ),
        ..Default::default()
    }
}

// Helper function to create a refund sync request
fn create_refund_sync_request(transaction_id: &str, refund_id: &str) -> RefundServiceGetRequest {
    RefundServiceGetRequest {
        transaction_id: Some(Identifier {
            id_type: Some(IdType::Id(transaction_id.to_string())),
        }),
        refund_id: refund_id.to_string(),
        refund_reason: None,
        request_ref_id: None,
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
        add_fiuu_metadata(&mut grpc_request);

        // Send the request
        let response = client
            .authorize(grpc_request)
            .await
            .expect("gRPC authorize call failed")
            .into_inner();

        assert!(
            response.status == i32::from(PaymentStatus::Charged),
            "Payment should be in Charged state"
        );
    });
}

// Test payment authorization with manual capture
#[tokio::test]
async fn test_payment_authorization_manual_capture() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        // Create the payment authorization request with manual capture
        let auth_request = create_authorize_request(CaptureMethod::Manual);

        // Add metadata headers for auth request
        let mut auth_grpc_request = Request::new(auth_request);
        add_fiuu_metadata(&mut auth_grpc_request);

        // Send the auth request
        let auth_response = client
            .authorize(auth_grpc_request)
            .await
            .expect("gRPC authorize call failed")
            .into_inner();

        // Verify payment status
        assert!(
            auth_response.status == i32::from(PaymentStatus::Authorized),
            "Payment should be in Authorized state"
        );

        // Extract the transaction ID
        let transaction_id = extract_transaction_id(&auth_response);

        // Add delay of 15 seconds
        tokio::time::sleep(std::time::Duration::from_secs(15)).await;

        // Create capture request
        let capture_request = create_payment_capture_request(&transaction_id);

        // Add metadata headers for capture request - make sure they include the terminal_id
        let mut capture_grpc_request = Request::new(capture_request);
        add_fiuu_metadata(&mut capture_grpc_request);

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

// Test payment sync with auto capture
#[tokio::test]
async fn test_payment_sync_auto_capture() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        // Create the payment authorization request
        let request = create_authorize_request(CaptureMethod::Automatic);

        // Add metadata headers
        let mut grpc_request = Request::new(request);
        add_fiuu_metadata(&mut grpc_request);

        // Send the request
        let response = client
            .authorize(grpc_request)
            .await
            .expect("gRPC authorize call failed")
            .into_inner();

        // Extract the transaction ID
        let transaction_id = extract_transaction_id(&response);

        // Add delay of 10 seconds
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;

        // Create sync request
        let sync_request = create_payment_sync_request(&transaction_id);

        // Add metadata headers for sync request
        let mut sync_grpc_request = Request::new(sync_request);
        add_fiuu_metadata(&mut sync_grpc_request);

        // Send the sync request
        let sync_response = client
            .get(sync_grpc_request)
            .await
            .expect("gRPC payment_sync call failed")
            .into_inner();

        // Verify the sync response
        assert!(
            sync_response.status == i32::from(PaymentStatus::Charged),
            "Payment should be in Charged state"
        );
    });
}

// Test refund flow - handles both success and error cases
#[tokio::test]
async fn test_refund() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        // Create the payment authorization request
        let request = create_authorize_request(CaptureMethod::Automatic);

        // Add metadata headers
        let mut grpc_request = Request::new(request);
        add_fiuu_metadata(&mut grpc_request);

        // Send the request
        let response = client
            .authorize(grpc_request)
            .await
            .expect("gRPC authorize call failed")
            .into_inner();

        // Extract the transaction ID
        let transaction_id = extract_transaction_id(&response);

        assert!(
            response.status == i32::from(PaymentStatus::Charged),
            "Payment should be in Charged state"
        );

        // Wait a bit longer to ensure the payment is fully processed
        tokio::time::sleep(tokio::time::Duration::from_secs(12)).await;

        // Create refund request
        let refund_request = create_refund_request(&transaction_id);

        // Add metadata headers for refund request
        let mut refund_grpc_request = Request::new(refund_request);
        add_fiuu_metadata(&mut refund_grpc_request);

        // Send the refund request
        let refund_response = client
            .refund(refund_grpc_request)
            .await
            .expect("gRPC refund call failed")
            .into_inner();

        // Verify the refund response
        assert!(
            refund_response.status == i32::from(RefundStatus::RefundPending),
            "Refund should be in RefundPending state"
        );
    });
}

// Test refund sync flow - runs as a separate test since refund + sync is complex
#[tokio::test]
async fn test_refund_sync() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        grpc_test!(refund_client, RefundServiceClient<Channel>, {
            // Create the payment authorization request
            let request = create_authorize_request(CaptureMethod::Automatic);

            // Add metadata headers
            let mut grpc_request = Request::new(request);
            add_fiuu_metadata(&mut grpc_request);

            // Send the request
            let response = client
                .authorize(grpc_request)
                .await
                .expect("gRPC authorize call failed")
                .into_inner();

            // Extract the transaction ID
            let transaction_id = extract_transaction_id(&response);

            assert!(
                response.status == i32::from(PaymentStatus::Charged),
                "Payment should be in Charged state"
            );

            // Create refund request
            let refund_request = create_refund_request(&transaction_id);

            // Add metadata headers for refund request
            let mut refund_grpc_request = Request::new(refund_request);
            add_fiuu_metadata(&mut refund_grpc_request);

            // Send the refund request
            let refund_response = client
                .refund(refund_grpc_request)
                .await
                .expect("gRPC refund call failed")
                .into_inner();

            // Verify the refund response
            assert!(
                refund_response.status == i32::from(RefundStatus::RefundPending),
                "Refund should be in RefundPending state"
            );

            let refund_id = extract_refund_id(&refund_response);

            // Wait a bit longer to ensure the refund is fully processed
            std::thread::sleep(std::time::Duration::from_secs(250));

            // Create refund sync request
            let refund_sync_request = create_refund_sync_request(&transaction_id, refund_id);

            // Add metadata headers for refund sync request
            let mut refund_sync_grpc_request = Request::new(refund_sync_request);
            add_fiuu_metadata(&mut refund_sync_grpc_request);

            // Send the refund sync request
            let refund_sync_response = refund_client
                .get(refund_sync_grpc_request)
                .await
                .expect("gRPC refund sync call failed")
                .into_inner();

            // Verify the refund sync response
            assert!(
                refund_sync_response.status == i32::from(RefundStatus::RefundSuccess),
                "Refund Sync should be in RefundSuccess state"
            );
        });
    });
}

// Test payment void
#[tokio::test]
async fn test_payment_void() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        // First create a payment with manual capture to void
        let auth_request = create_authorize_request(CaptureMethod::Manual);

        // Add metadata headers for auth request
        let mut auth_grpc_request = Request::new(auth_request);
        add_fiuu_metadata(&mut auth_grpc_request);

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

        // Wait a bit longer to ensure the payment is fully processed
        std::thread::sleep(std::time::Duration::from_secs(12));

        // Create void request with a unique reference ID
        let void_request = create_payment_void_request(&transaction_id);

        // Add metadata headers for void request
        let mut void_grpc_request = Request::new(void_request);
        add_fiuu_metadata(&mut void_grpc_request);

        // Send the void request
        let void_response = client
            .void(void_grpc_request)
            .await
            .expect("gRPC void_payment call failed")
            .into_inner();

        // Verify the void response
        assert!(
            void_response.transaction_id.is_some(),
            "Transaction ID should be present in void response"
        );

        assert!(
            void_response.status == i32::from(PaymentStatus::Voided),
            "Payment should be in VOIDED state after void"
        );

        // Verify the payment status with a sync operation
        let sync_request = create_payment_sync_request(&transaction_id);
        let mut sync_grpc_request = Request::new(sync_request);
        add_fiuu_metadata(&mut sync_grpc_request);

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
