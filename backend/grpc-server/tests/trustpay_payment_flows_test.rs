#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]

use cards::CardNumber;
use grpc_server::{app, configs};
mod common;
use hyperswitch_masking::Secret;

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
        payment_service_client::PaymentServiceClient, refund_service_client::RefundServiceClient,
        AuthenticationType, CaptureMethod, CardDetails, CardPaymentMethodType, Currency,
        Identifier, PaymentMethod, PaymentServiceAuthorizeRequest, PaymentServiceAuthorizeResponse,
        PaymentServiceGetRequest, PaymentServiceRefundRequest, PaymentStatus, RefundResponse,
        RefundServiceGetRequest, RefundStatus,
    },
};
use tonic::{transport::Channel, Request};

// Constants for Trustpay connector
const CONNECTOR_NAME: &str = "trustpay";
const AUTH_TYPE: &str = "signature-key";
const MERCHANT_ID: &str = "merchant_17555143863";

// Environment variable names for API credentials (can be set or overridden with
// provided values)
const TRUSTPAY_API_KEY_ENV: &str = "TEST_TRUSTPAY_API_KEY";
const TRUSTPAY_KEY1_ENV: &str = "TEST_TRUSTPAY_KEY1";
const TRUSTPAY_API_SECRET_ENV: &str = "TEST_TRUSTPAY_API_SECRET";

// Test card data
const TEST_AMOUNT: i64 = 1000;
const TEST_CARD_NUMBER: &str = "4242424242424242"; // Valid test card for Trustpay
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

// Helper function to add Trustpay metadata headers to a request
fn add_trustpay_metadata<T>(request: &mut Request<T>) {
    // Get API credentials from environment variables - throw error if not set
    let api_key = env::var(TRUSTPAY_API_KEY_ENV)
        .expect("TEST_TRUSTPAY_API_KEY environment variable is required");
    let key1 =
        env::var(TRUSTPAY_KEY1_ENV).expect("TEST_TRUSTPAY_KEY1 environment variable is required");
    let api_secret = env::var(TRUSTPAY_API_SECRET_ENV)
        .unwrap_or_else(|_| panic!("Environment variable {TRUSTPAY_API_SECRET_ENV} must be set"));

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
    let mut metadata = HashMap::new();
    metadata.insert("merchant_account_id".to_string(), "Anand".to_string());
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
        address: Some(grpc_api_types::payments::PaymentAddress {
            shipping_address: Some(grpc_api_types::payments::Address::default()),
            billing_address: Some(grpc_api_types::payments::Address {
                first_name: Some("joseph".to_string().into()),
                last_name: Some("Doe".to_string().into()),
                phone_number: Some("8056594427".to_string().into()),
                phone_country_code: Some("+91".to_string()),
                email: Some("test@gmail.com".to_string().into()),
                line1: Some("1467".to_string().into()),
                line2: Some("Harrison Street".to_string().into()),
                line3: Some("Harrison Street".to_string().into()),
                city: Some("San Francisco".to_string().into()),
                state: Some("California".to_string().into()),
                zip_code: Some("94122".to_string().into()),
                country_alpha2_code: Some(grpc_api_types::payments::CountryAlpha2::Us.into()),
            }),
        }),
        browser_info: Some(grpc_api_types::payments::BrowserInformation {
            color_depth: Some(24),
            java_enabled: Some(false),
            screen_height: Some(1080),
            screen_width: Some(1920),
            user_agent: Some("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)".to_string()),
            accept_header: Some(
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".to_string(),
            ),
            java_script_enabled: Some(false),
            language: Some("en-US".to_string()),
            ip_address: Some("13.232.74.226".to_string()),
            os_type: None,
            os_version: None,
            device_model: None,
            accept_language: None,
            time_zone_offset_minutes: Some(30),
        }),
        auth_type: i32::from(AuthenticationType::NoThreeDs),
        request_ref_id: Some(Identifier {
            id_type: Some(IdType::Id(format!("trustpay_test_{}", get_timestamp()))),
        }),
        enrolled_for_3ds: false,
        request_incremental_authorization: false,
        capture_method: Some(i32::from(capture_method)),
        metadata,
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
        request_ref_id: None,
        access_token: None,
        capture_method: None,
        handle_response: None,
        // all_keys_required: None,
    }
}

// Helper function to create a refund request
fn create_refund_request(transaction_id: &str) -> PaymentServiceRefundRequest {
    let metadata = "{\"payment_method\": \"card\"}".to_string();
    PaymentServiceRefundRequest {
        refund_id: format!("refund_{}", get_timestamp()),
        transaction_id: Some(Identifier {
            id_type: Some(IdType::Id(transaction_id.to_string())),
        }),
        currency: i32::from(Currency::Usd),
        payment_amount: TEST_AMOUNT,
        refund_amount: TEST_AMOUNT,
        minor_payment_amount: TEST_AMOUNT,
        minor_refund_amount: TEST_AMOUNT,
        reason: Some("Test Refund".to_string()),
        webhook_url: None,
        browser_info: None,
        merchant_account_id: None,
        capture_method: None,
        request_ref_id: None,
        refund_metadata: {
            let mut refund_metadata = HashMap::new();
            refund_metadata.insert("refund_metadata".to_string(), metadata);
            refund_metadata
        },
        ..Default::default()
    }
}

// Helper function to create a refund sync request
fn create_refund_sync_request(transaction_id: &str, refund_id: &str) -> RefundServiceGetRequest {
    let mut refund_metadata = HashMap::new();
    refund_metadata.insert("payment_method".to_string(), "card".to_string());

    RefundServiceGetRequest {
        transaction_id: Some(Identifier {
            id_type: Some(IdType::Id(transaction_id.to_string())),
        }),
        refund_id: refund_id.to_string(),
        refund_reason: None,
        request_ref_id: Some(Identifier {
            id_type: Some(IdType::Id(format!("rsync_ref_{}", get_timestamp()))),
        }),
        browser_info: None,
        refund_metadata,
        access_token: None,
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
        let request = create_payment_authorize_request(CaptureMethod::Automatic);

        // Add metadata headers
        let mut grpc_request = Request::new(request);
        add_trustpay_metadata(&mut grpc_request);

        // Send the request
        let response = client
            .authorize(grpc_request)
            .await
            .expect("gRPC authorize call failed")
            .into_inner();

        assert!(
            response.status == i32::from(PaymentStatus::AuthenticationPending)
                || response.status == i32::from(PaymentStatus::Charged),
            "Payment should be in AuthenticationPending or Charged state"
        );
    });
}

// Test payment sync with auto capture
#[tokio::test]
async fn test_payment_sync_auto_capture() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        // Create the payment authorization request
        let request = create_payment_authorize_request(CaptureMethod::Automatic);

        // Add metadata headers
        let mut grpc_request = Request::new(request);
        add_trustpay_metadata(&mut grpc_request);

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
        add_trustpay_metadata(&mut sync_grpc_request);

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
        let request = create_payment_authorize_request(CaptureMethod::Automatic);

        // Add metadata headers
        let mut grpc_request = Request::new(request);
        add_trustpay_metadata(&mut grpc_request);

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

        // Add delay of 12 seconds
        tokio::time::sleep(std::time::Duration::from_secs(12)).await;
        // Create refund request
        let refund_request = create_refund_request(&transaction_id);

        // Add metadata headers for refund request
        let mut refund_grpc_request = Request::new(refund_request);
        add_trustpay_metadata(&mut refund_grpc_request);

        // Send the refund request
        let refund_response = client
            .refund(refund_grpc_request)
            .await
            .expect("gRPC refund call failed")
            .into_inner();

        // Verify the refund response
        assert!(
            refund_response.status == i32::from(RefundStatus::RefundSuccess),
            "Refund should be in RefundSuccess state"
        );
    });
}

// Test refund sync flow - runs as a separate test since refund + sync is complex
#[tokio::test]
async fn test_refund_sync() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        grpc_test!(refund_client, RefundServiceClient<Channel>, {
            // Create the payment authorization request
            let request = create_payment_authorize_request(CaptureMethod::Automatic);

            // Add metadata headers
            let mut grpc_request = Request::new(request);
            add_trustpay_metadata(&mut grpc_request);

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

            // Add delay of 14 seconds
            tokio::time::sleep(std::time::Duration::from_secs(14)).await;

            // Create refund request
            let refund_request = create_refund_request(&transaction_id);

            // Add metadata headers for refund request
            let mut refund_grpc_request = Request::new(refund_request);
            add_trustpay_metadata(&mut refund_grpc_request);

            // Send the refund request
            let refund_response = client
                .refund(refund_grpc_request)
                .await
                .expect("gRPC refund call failed")
                .into_inner();

            // Verify the refund response
            assert!(
                refund_response.status == i32::from(RefundStatus::RefundSuccess),
                "Refund should be in RefundSuccess state"
            );

            let refund_id = extract_refund_id(&refund_response);

            // Add delay of 4 seconds
            tokio::time::sleep(std::time::Duration::from_secs(4)).await;

            // Create refund sync request
            let refund_sync_request = create_refund_sync_request(&transaction_id, refund_id);

            // Add metadata headers for refund sync request
            let mut refund_sync_grpc_request = Request::new(refund_sync_request);
            add_trustpay_metadata(&mut refund_sync_grpc_request);

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
