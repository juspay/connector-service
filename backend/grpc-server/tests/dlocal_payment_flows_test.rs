#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]

use grpc_server::{app, configs};
mod common;

use std::{
    collections::HashMap,
    env,
    str::FromStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use cards::CardNumber;
use grpc_api_types::{
    health_check::{health_client::HealthClient, HealthCheckRequest},
    payments::{
        card_payment_method_type, identifier::IdType, payment_method,
        payment_service_client::PaymentServiceClient, refund_service_client::RefundServiceClient,
        Address, AuthenticationType, BrowserInformation, CaptureMethod, CardDetails,
        CardPaymentMethodType, CountryAlpha2, Currency, Identifier, PaymentAddress, PaymentMethod,
        PaymentServiceAuthorizeRequest, PaymentServiceAuthorizeResponse,
        PaymentServiceCaptureRequest, PaymentServiceGetRequest, PaymentServiceRefundRequest,
        PaymentServiceVoidRequest, PaymentStatus, RefundServiceGetRequest, RefundStatus,
    },
};
use hyperswitch_masking::Secret;
use tokio::time::sleep;
use tonic::{transport::Channel, Request};

// Constants for dlocal connector
const CONNECTOR_NAME: &str = "dlocal";

// Environment variable names for API credentials
const TEST_DLOCAL_API_KEY_ENV: &str = "TEST_DLOCAL_API_KEY";
const TEST_DLOCAL_KEY1_ENV: &str = "TEST_DLOCAL_KEY1";
const TEST_DLOCAL_API_SECRET_ENV: &str = "TEST_DLOCAL_API_SECRET";

const TEST_AMOUNT: i64 = 1000;
const TEST_CARD_NUMBER: &str = "5105105105105100";
const TEST_CARD_EXP_MONTH: &str = "10";
const TEST_CARD_EXP_YEAR: &str = "2040";
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

// Helper function to add dlocal metadata headers to a request
fn add_dlocal_metadata<T>(request: &mut Request<T>) {
    // Get API credentials from environment variables
    let api_key = env::var(TEST_DLOCAL_API_KEY_ENV)
        .unwrap_or_else(|_| panic!("Environment variable TEST_DLOCAL_API_KEY_ENV must be set"));
    let key1 = env::var(TEST_DLOCAL_KEY1_ENV)
        .unwrap_or_else(|_| panic!("Environment variable TEST_DLOCAL_KEY1_ENV must be set"));
    let api_secret = env::var(TEST_DLOCAL_API_SECRET_ENV)
        .unwrap_or_else(|_| panic!("Environment variable TEST_DLOCAL_API_SECRET_ENV must be set"));

    request.metadata_mut().append(
        "x-connector",
        CONNECTOR_NAME.parse().expect("Failed to parse x-connector"),
    );
    request.metadata_mut().append(
        "x-auth",
        "signature-key".parse().expect("Failed to parse x-auth"),
    );
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
        "test_merchant"
            .parse()
            .expect("Failed to parse x-merchant-id"),
    );
    request.metadata_mut().append(
        "x-tenant-id",
        "default".parse().expect("Failed to parse x-tenant-id"),
    );
    request.metadata_mut().append(
        "x-request-id",
        format!("test_request_{}", get_timestamp())
            .parse()
            .expect("Failed to parse x-request-id"),
    );
}

// Helper function to extract transaction ID from response
fn extract_transaction_id(response: &PaymentServiceAuthorizeResponse) -> String {
    match &response.transaction_id {
        Some(id) => match id.id_type.as_ref().unwrap() {
            IdType::Id(id) => id.clone(),
            _ => panic!("Expected connector transaction ID"),
        },
        None => panic!("Resource ID is None"),
    }
}

// Helper function to create a payment authorization request
#[allow(clippy::field_reassign_with_default)]
fn create_payment_authorize_request(
    capture_method: common_enums::CaptureMethod,
) -> PaymentServiceAuthorizeRequest {
    // Initialize with all required fields
    let mut request = PaymentServiceAuthorizeRequest::default();

    // Set request reference ID
    let mut request_ref_id = Identifier::default();
    request_ref_id.id_type = Some(IdType::Id(format!("dlocal_test_{}", get_timestamp())));
    request.request_ref_id = Some(request_ref_id);

    // Set the basic payment details
    request.amount = TEST_AMOUNT;
    request.minor_amount = TEST_AMOUNT;
    request.currency = i32::from(Currency::Myr);

    // Set up card payment method using the correct structure
    let card_details = card_payment_method_type::CardType::Credit(CardDetails {
        card_number: Some(CardNumber::from_str(TEST_CARD_NUMBER).unwrap()),
        card_exp_month: Some(Secret::new(TEST_CARD_EXP_MONTH.to_string())),
        card_exp_year: Some(Secret::new(TEST_CARD_EXP_YEAR.to_string())),
        card_cvc: Some(Secret::new(TEST_CARD_CVC.to_string())),
        card_holder_name: Some(Secret::new(TEST_CARD_HOLDER.to_string())),
        card_issuer: None,
        card_network: Some(1_i32), // Default to Visa network
        card_type: None,
        card_issuing_country_alpha2: None,
        bank_code: None,
        nick_name: None,
    });

    request.payment_method = Some(PaymentMethod {
        payment_method: Some(payment_method::PaymentMethod::Card(CardPaymentMethodType {
            card_type: Some(card_details),
        })),
    });

    // Set connector customer ID
    request.customer_id = Some("TEST_CONNECTOR".to_string());

    // Set the customer information with static email (can be made dynamic)
    request.email = Some(TEST_EMAIL.to_string().into());

    // Set up address structure
    request.address = Some(PaymentAddress {
        billing_address: Some(Address {
            first_name: Some("Test".to_string().into()),
            last_name: Some("User".to_string().into()),
            line1: Some("123 Test Street".to_string().into()),
            line2: None,
            line3: None,
            city: Some("Test City".to_string().into()),
            state: Some("NY".to_string().into()),
            zip_code: Some("10001".to_string().into()),
            country_alpha2_code: Some(i32::from(CountryAlpha2::My)),
            phone_number: None,
            phone_country_code: None,
            email: None,
        }),
        shipping_address: None,
    });

    // Set up browser information
    let browser_info = BrowserInformation {
        color_depth: None,
        java_enabled: Some(false),
        screen_height: Some(1080),
        screen_width: Some(1920),
        user_agent: Some("Mozilla/5.0 (compatible; TestAgent/1.0)".to_string()),
        accept_header: Some(
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".to_string(),
        ),
        java_script_enabled: Some(false),
        language: Some("en-US".to_string()),
        ip_address: None,
        os_type: None,
        os_version: None,
        device_model: None,
        accept_language: None,
        time_zone_offset_minutes: None,
        referer: None,
    };
    request.browser_info = Some(browser_info);

    // Set return URL
    request.return_url = Some("https://example.com/return".to_string());

    // Set the transaction details
    request.auth_type = i32::from(AuthenticationType::NoThreeDs);
    request.request_incremental_authorization = true;
    request.enrolled_for_3ds = true;

    // Set capture method with proper conversion
    if let common_enums::CaptureMethod::Manual = capture_method {
        request.capture_method = Some(i32::from(CaptureMethod::Manual));
    } else {
        request.capture_method = Some(i32::from(CaptureMethod::Automatic));
    }

    // Set connector metadata (empty for generic template)
    request.metadata = HashMap::new();

    request
}

// Helper function to create a payment sync request
fn create_payment_sync_request(transaction_id: &str) -> PaymentServiceGetRequest {
    PaymentServiceGetRequest {
        transaction_id: Some(Identifier {
            id_type: Some(IdType::Id(transaction_id.to_string())),
        }),
        request_ref_id: Some(Identifier {
            id_type: Some(IdType::Id(format!("dlocal_sync_{}", get_timestamp()))),
        }),
        access_token: None,
        capture_method: None,
        handle_response: None,
        amount: TEST_AMOUNT,
        currency: i32::from(Currency::Myr),
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
        metadata: HashMap::new(),
        request_ref_id: None,
        browser_info: None,
        access_token: None,
    }
}

// Helper function to create a refund request
fn create_refund_request(transaction_id: &str) -> PaymentServiceRefundRequest {
    PaymentServiceRefundRequest {
        refund_id: format!("refund_{}", get_timestamp()),
        transaction_id: Some(Identifier {
            id_type: Some(IdType::Id(transaction_id.to_string())),
        }),
        currency: i32::from(Currency::Myr),
        payment_amount: TEST_AMOUNT,
        refund_amount: TEST_AMOUNT,
        minor_payment_amount: TEST_AMOUNT,
        minor_refund_amount: TEST_AMOUNT,
        reason: None,
        webhook_url: None,
        metadata: HashMap::new(),
        refund_metadata: HashMap::new(),
        browser_info: None,
        merchant_account_id: None,
        capture_method: None,
        request_ref_id: None,
        access_token: None,
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
        browser_info: None,
        request_ref_id: None,
        refund_metadata: HashMap::new(),
        access_token: None,
    }
}

// Helper function to create a payment void request
fn create_payment_void_request(transaction_id: &str) -> PaymentServiceVoidRequest {
    PaymentServiceVoidRequest {
        transaction_id: Some(Identifier {
            id_type: Some(IdType::Id(transaction_id.to_string())),
        }),
        cancellation_reason: Some("Customer requested cancellation".to_string()),
        request_ref_id: None,
        all_keys_required: None,
        browser_info: None,
        access_token: None,
    }
}

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
        let request = create_payment_authorize_request(common_enums::CaptureMethod::Automatic);

        // Add metadata headers
        let mut grpc_request = Request::new(request);
        add_dlocal_metadata(&mut grpc_request);

        // Send the request
        let response = client
            .authorize(grpc_request)
            .await
            .expect("gRPC payment_authorize call failed")
            .into_inner();

        // Verify the response
        assert!(
            response.transaction_id.is_some(),
            "Transaction ID should be present"
        );

        // Extract the transaction ID
        let _transaction_id = extract_transaction_id(&response);

        // Verify payment status - in sandbox, payments may be rejected
        let acceptable_statuses = [i32::from(PaymentStatus::Charged)];
        assert!(
            acceptable_statuses.contains(&response.status),
            "Payment should be in CHARGED state (sandbox). Got status: {}",
            response.status
        );
    });
}

// Test payment authorization with manual capture
#[tokio::test]
async fn test_payment_authorization_manual_capture() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        // Create the payment authorization request with manual capture
        let auth_request = create_payment_authorize_request(common_enums::CaptureMethod::Manual);

        // Add metadata headers for auth request
        let mut auth_grpc_request = Request::new(auth_request);
        add_dlocal_metadata(&mut auth_grpc_request);

        // Send the auth request
        let auth_response = client
            .authorize(auth_grpc_request)
            .await
            .expect("gRPC payment_authorize call failed")
            .into_inner();

        assert!(
            auth_response.transaction_id.is_some(),
            "Transaction ID should be present"
        );

        // Extract the transaction ID
        let _transaction_id = extract_transaction_id(&auth_response);

        // Verify payment status - in sandbox, payments may be rejected
        let acceptable_auth_statuses = [i32::from(PaymentStatus::Authorized)];
        assert!(
            acceptable_auth_statuses.contains(&auth_response.status),
            "Payment should be in AUTHORIZED state (sandbox). Got status: {}",
            auth_response.status
        );
    });
}

// Test payment sync
#[tokio::test]
async fn test_payment_sync() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        // First create a payment to sync
        let auth_request = create_payment_authorize_request(common_enums::CaptureMethod::Manual);

        // Add metadata headers for auth request
        let mut auth_grpc_request = Request::new(auth_request);
        add_dlocal_metadata(&mut auth_grpc_request);

        // Send the auth request
        let auth_response = client
            .authorize(auth_grpc_request)
            .await
            .expect("gRPC payment_authorize call failed")
            .into_inner();

        // Extract the transaction ID
        let transaction_id = extract_transaction_id(&auth_response);

        // Add 5-second delay before sync request
        sleep(Duration::from_secs(5)).await;

        // Create sync request
        let sync_request = create_payment_sync_request(&transaction_id);

        // Add metadata headers for sync request
        let mut sync_grpc_request = Request::new(sync_request);
        add_dlocal_metadata(&mut sync_grpc_request);

        // Send the sync request
        let sync_response = client
            .get(sync_grpc_request)
            .await
            .expect("gRPC payment_sync call failed")
            .into_inner();

        // Verify the sync response - in sandbox, payments may be rejected
        let acceptable_sync_statuses = [i32::from(PaymentStatus::Authorized)];
        assert!(
            acceptable_sync_statuses.contains(&sync_response.status),
            "Payment should be in AUTHORIZED state (sandbox). Got status: {}",
            sync_response.status
        );
    });
}

// Test payment authorization with manual capture
#[tokio::test]
async fn test_payment_capture() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        // Create the payment authorization request with manual capture
        let auth_request = create_payment_authorize_request(common_enums::CaptureMethod::Manual);

        // Add metadata headers for auth request
        let mut auth_grpc_request = Request::new(auth_request);
        add_dlocal_metadata(&mut auth_grpc_request);

        // Send the auth request
        let auth_response = client
            .authorize(auth_grpc_request)
            .await
            .expect("gRPC payment_authorize call failed")
            .into_inner();

        assert!(
            auth_response.transaction_id.is_some(),
            "Transaction ID should be present"
        );

        // Extract the transaction ID
        let transaction_id = extract_transaction_id(&auth_response);

        // Verify payment status - in sandbox, payments may be rejected
        let acceptable_capture_auth_statuses = [i32::from(PaymentStatus::Authorized)];
        assert!(
            acceptable_capture_auth_statuses.contains(&auth_response.status),
            "Payment should be in AUTHORIZED state (sandbox). Got status: {}",
            auth_response.status
        );

        // Add 5-second delay before capture request
        sleep(Duration::from_secs(5)).await;

        // Create capture request
        let capture_request = create_payment_capture_request(&transaction_id);

        // Add metadata headers for capture request
        let mut capture_grpc_request = Request::new(capture_request);
        add_dlocal_metadata(&mut capture_grpc_request);

        // Send the capture request
        let capture_response = client
            .capture(capture_grpc_request)
            .await
            .expect("gRPC payment_capture call failed")
            .into_inner();

        // Verify payment status after capture - in sandbox, may still be rejected
        let acceptable_capture_statuses = [i32::from(PaymentStatus::Charged)];
        assert!(
            acceptable_capture_statuses.contains(&capture_response.status),
            "Payment should be in CHARGED state (sandbox). Got status: {}",
            capture_response.status
        );
    });
}

// Test refund flow
#[tokio::test]
async fn test_refund() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        // First create a payment to refund
        let auth_request = create_payment_authorize_request(common_enums::CaptureMethod::Automatic);

        // Add metadata headers for auth request
        let mut auth_grpc_request = Request::new(auth_request);
        add_dlocal_metadata(&mut auth_grpc_request);

        // Send the auth request
        let auth_response = client
            .authorize(auth_grpc_request)
            .await
            .expect("gRPC payment_authorize call failed")
            .into_inner();

        // Extract the transaction ID
        let transaction_id = extract_transaction_id(&auth_response);

        // Verify payment status - in sandbox, payments may be rejected
        let acceptable_payment_statuses = [i32::from(PaymentStatus::Charged)];
        assert!(
            acceptable_payment_statuses.contains(&auth_response.status),
            "Payment should be in CHARGED state (sandbox). Got status: {}",
            auth_response.status
        );

        // Add 5-second delay before refund request
        sleep(Duration::from_secs(5)).await;

        // Create refund request
        let refund_request = create_refund_request(&transaction_id);

        // Add metadata headers for refund request
        let mut refund_grpc_request = Request::new(refund_request);
        add_dlocal_metadata(&mut refund_grpc_request);

        // Send the refund request
        let refund_response = client
            .refund(refund_grpc_request)
            .await
            .expect("gRPC refund call failed")
            .into_inner();

        // Extract the refund ID
        let refund_id = refund_response.refund_id.clone();

        // Verify the refund response
        assert!(!refund_id.is_empty(), "Refund ID should not be empty");
        assert!(
            refund_response.status == i32::from(RefundStatus::RefundSuccess),
            "Refund should be in SUCCESS state"
        );
    });
}

// Test refund sync flow
#[tokio::test]
async fn test_refund_sync() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        grpc_test!(refund_client, RefundServiceClient<Channel>, {
            // First create a payment
            let auth_request =
                create_payment_authorize_request(common_enums::CaptureMethod::Automatic);

            // Add metadata headers for auth request
            let mut auth_grpc_request = Request::new(auth_request);
            add_dlocal_metadata(&mut auth_grpc_request);

            // Send the auth request
            let auth_response = client
                .authorize(auth_grpc_request)
                .await
                .expect("gRPC payment_authorize call failed")
                .into_inner();

            // Extract the transaction ID
            let transaction_id = extract_transaction_id(&auth_response);

            // Add 5-second delay before refund request
            sleep(Duration::from_secs(5)).await;

            // Create refund request
            let refund_request = create_refund_request(&transaction_id);

            // Add metadata headers for refund request
            let mut refund_grpc_request = Request::new(refund_request);
            add_dlocal_metadata(&mut refund_grpc_request);

            // Send the refund request
            let refund_response = client
                .refund(refund_grpc_request)
                .await
                .expect("gRPC refund call failed")
                .into_inner();

            // Extract the refund ID
            let refund_id = refund_response.refund_id.clone();

            // Verify the refund response
            assert!(!refund_id.is_empty(), "Refund ID should not be empty");

            // Add 5-second delay before refund sync request
            sleep(Duration::from_secs(5)).await;

            // Create refund sync request
            let refund_sync_request = create_refund_sync_request(&transaction_id, &refund_id);

            // Add metadata headers for refund sync request
            let mut refund_sync_grpc_request = Request::new(refund_sync_request);
            add_dlocal_metadata(&mut refund_sync_grpc_request);

            // Send the refund sync request
            let refund_sync_response = refund_client
                .get(refund_sync_grpc_request)
                .await
                .expect("gRPC refund_sync call failed")
                .into_inner();

            // Verify the refund sync response
            assert!(
                refund_sync_response.status == i32::from(RefundStatus::RefundSuccess),
                "Refund should be in SUCCESS state"
            );
        });
    });
}

// Test payment void flow
#[tokio::test]
async fn test_payment_void() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        // First create a payment with manual capture (so it stays in authorized state)
        let auth_request = create_payment_authorize_request(common_enums::CaptureMethod::Manual);

        // Add metadata headers for auth request
        let mut auth_grpc_request = Request::new(auth_request);
        add_dlocal_metadata(&mut auth_grpc_request);

        // Send the auth request
        let auth_response = client
            .authorize(auth_grpc_request)
            .await
            .expect("gRPC payment_authorize call failed")
            .into_inner();

        // Extract the transaction ID
        let transaction_id = extract_transaction_id(&auth_response);

        // Verify payment status - in sandbox, payments may be rejected
        let acceptable_void_auth_statuses = [i32::from(PaymentStatus::Authorized)];
        assert!(
            acceptable_void_auth_statuses.contains(&auth_response.status),
            "Payment should be in AUTHORIZED state (sandbox). Got status: {}",
            auth_response.status
        );

        // Add 5-second delay before void request
        sleep(Duration::from_secs(5)).await;

        // Create void request
        let void_request = create_payment_void_request(&transaction_id);

        // Add metadata headers for void request
        let mut void_grpc_request = Request::new(void_request);
        add_dlocal_metadata(&mut void_grpc_request);

        // Send the void request
        let void_response = client
            .void(void_grpc_request)
            .await
            .expect("gRPC payment_void call failed")
            .into_inner();

        // Verify the void response - in sandbox, may have different statuses
        let acceptable_void_statuses = [i32::from(PaymentStatus::Voided)];
        assert!(
            acceptable_void_statuses.contains(&void_response.status),
            "Payment should be in VOIDED state (sandbox). Got status: {}",
            void_response.status
        );
    });
}
