#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]

use grpc_server::{app, configs};
mod common;

use std::{
    collections::HashMap,
    env,
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

use cards::CardNumber;
use grpc_api_types::{
    health_check::{health_client::HealthClient, HealthCheckRequest},
    payments::{
        card_payment_method_type, identifier::IdType, payment_method,
        payment_service_client::PaymentServiceClient, refund_service_client::RefundServiceClient,
        Address, AuthenticationType, CaptureMethod, CardDetails, CardPaymentMethodType,
        CountryAlpha2, Currency, Identifier, PaymentAddress, PaymentMethod,
        PaymentServiceAuthorizeRequest, PaymentServiceAuthorizeResponse,
        PaymentServiceCaptureRequest, PaymentServiceGetRequest, PaymentServiceRefundRequest,
        PaymentServiceVoidRequest, PaymentStatus, RefundResponse, RefundServiceGetRequest,
        RefundStatus,
    },
};
use hyperswitch_masking::Secret;
use tonic::{transport::Channel, Request};

// Constants for Helcim connector
const CONNECTOR_NAME: &str = "helcim";
const AUTH_TYPE: &str = "header-key";

// Environment variable names for API credentials
const HELCIM_API_KEY_ENV: &str = "TEST_HELCIM_API_KEY";

// Test card data
const TEST_AMOUNT: i64 = 1000;
const TEST_AMOUNT_MANUAL: i64 = 1100;
const TEST_AMOUNT_VOID: i64 = 1200;
const TEST_AMOUNT_SYNC: i64 = 1300;
const TEST_AMOUNT_REFUND: i64 = 1400;
const TEST_CARD_NUMBER: &str = "5413330089099130"; // Valid test card for Helcim
const TEST_CARD_EXP_MONTH: &str = "01";
const TEST_CARD_EXP_YEAR: &str = "2027";
const TEST_CARD_CVC: &str = "123";
const TEST_CARD_HOLDER: &str = "joseph Doe";
const TEST_EMAIL: &str = "customer@example.com";

// Helper function to get current timestamp with microseconds for uniqueness
fn get_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64
}

// Helper function to add Helcim metadata headers to a request
fn add_helcim_metadata<T>(request: &mut Request<T>) {
    // Get API credentials from environment variables - throw error if not set
    let api_key =
        env::var(HELCIM_API_KEY_ENV).expect("TEST_HELCIM_API_KEY environment variable is required");

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
    // Add merchant ID which is required by the server
    request.metadata_mut().append(
        "x-merchant-id",
        "12abc123-f8a3-99b8-9ef8-b31180358hh4"
            .parse()
            .expect("Failed to parse x-merchant-id"),
    );
    request.metadata_mut().append(
        "x-tenant-id",
        "default".parse().expect("Failed to parse x-tenant-id"),
    );
    // Add request ID which is required by the server
    request.metadata_mut().append(
        "x-request-id",
        format!("helcim_req_{}", get_timestamp())
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

// Helper function to extract connector request ref ID from response
fn extract_request_ref_id(response: &PaymentServiceAuthorizeResponse) -> String {
    match &response.response_ref_id {
        Some(id) => match id.id_type.as_ref().unwrap() {
            IdType::Id(id) => id.clone(),
            _ => panic!("Expected connector response_ref_id"),
        },
        None => panic!("Resource ID is None"),
    }
}

// Helper function to create a proper billing address
fn create_test_billing_address() -> PaymentAddress {
    PaymentAddress {
        shipping_address: Some(Address::default()),
        billing_address: Some(Address {
            first_name: Some("John".to_string()),
            last_name: Some("Doe".to_string()),
            phone_number: Some("1234567890".to_string().into()),
            phone_country_code: Some("+1".to_string()),
            email: Some(TEST_EMAIL.to_string().into()),
            line1: Some("123 Main St".to_string().into()),
            line2: Some("Apt 4B".to_string().into()),
            line3: None,
            city: Some("New York".to_string().into()),
            state: Some("NY".to_string().into()),
            zip_code: Some("10001".to_string().into()),
            country_alpha2_code: Some(CountryAlpha2::Us.into()),
        }),
    }
}

// Helper function to create a payment authorize request
fn create_payment_authorize_request(
    capture_method: CaptureMethod,
) -> PaymentServiceAuthorizeRequest {
    create_payment_authorize_request_with_amount(capture_method, TEST_AMOUNT)
}

// Helper function to create a payment authorize request with custom amount
fn create_payment_authorize_request_with_amount(
    capture_method: CaptureMethod,
    amount: i64,
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
    metadata.insert(
        "description".to_string(),
        "Its my first payment request".to_string(),
    );
    PaymentServiceAuthorizeRequest {
        amount,
        minor_amount: amount,
        currency: i32::from(Currency::Usd),
        payment_method: Some(PaymentMethod {
            payment_method: Some(payment_method::PaymentMethod::Card(CardPaymentMethodType {
                card_type: Some(card_details),
            })),
        }),
        return_url: Some("https://duck.com".to_string()),
        email: Some(TEST_EMAIL.to_string().into()),
        address: Some(create_test_billing_address()),
        auth_type: i32::from(AuthenticationType::NoThreeDs),
        request_ref_id: Some(Identifier {
            id_type: Some(IdType::Id(format!("helcim_test_{}", get_timestamp()))),
        }),
        enrolled_for_3ds: false,
        request_incremental_authorization: false,
        capture_method: Some(i32::from(capture_method)),
        order_category: Some("PAY".to_string()),
        metadata,
        // payment_method_type: Some(i32::from(PaymentMethodType::Credit)),
        ..Default::default()
    }
}

// Helper function to create a payment sync request
fn create_payment_sync_request(
    transaction_id: &str,
    request_ref_id: &str,
) -> PaymentServiceGetRequest {
    PaymentServiceGetRequest {
        transaction_id: Some(Identifier {
            id_type: Some(IdType::Id(transaction_id.to_string())),
        }),
        request_ref_id: Some(Identifier {
            id_type: Some(IdType::Id(request_ref_id.to_string())),
        }),
        // all_keys_required: None,
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
        request_ref_id: Some(Identifier {
            id_type: Some(IdType::Id(format!("capture_ref_{}", get_timestamp()))),
        }),
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
            id_type: Some(IdType::Id(format!("void_ref_{}", get_timestamp()))),
        }),
        all_keys_required: None,
        browser_info: None,
    }
}

// Helper function to create a refund request
fn create_refund_request(transaction_id: &str) -> PaymentServiceRefundRequest {
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
        reason: None,
        webhook_url: None,
        browser_info: None,
        merchant_account_id: None,
        capture_method: None,
        request_ref_id: None,
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
        request_ref_id: Some(Identifier {
            id_type: Some(IdType::Id(format!("rsync_ref_{}", get_timestamp()))),
        }),
        browser_info: None,
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
        add_helcim_metadata(&mut grpc_request);
        // Send the request
        let response = client
            .authorize(grpc_request)
            .await
            .expect("gRPC payment_authorize call failed")
            .into_inner();
        // Verify the response
        assert!(
            response.transaction_id.is_some(),
            "Resource ID should be present"
        );

        println!(
            "Response status: {}, Expected: {}",
            response.status,
            i32::from(PaymentStatus::Charged)
        );
        println!("Response: {:?}", response);

        assert!(
            response.status == i32::from(PaymentStatus::Charged),
            "Payment should be in Charged state. Got status: {}",
            response.status
        );
    });
}

// Test payment authorization with manual capture
#[tokio::test]
async fn test_payment_authorization_manual_capture() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        // Create the payment authorization request with manual capture
        let auth_request =
            create_payment_authorize_request_with_amount(CaptureMethod::Manual, TEST_AMOUNT_MANUAL);

        // Add metadata headers for auth request
        let mut auth_grpc_request = Request::new(auth_request);
        add_helcim_metadata(&mut auth_grpc_request);

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

        // Debug the auth response
        println!("Manual capture auth response: {:?}", auth_response);

        // Extract the transaction ID
        let transaction_id = extract_transaction_id(&auth_response);

        // Verify payment status is authorized
        if auth_response.status == i32::from(PaymentStatus::Authorized) {
            // Create capture request
            let capture_request = create_payment_capture_request(&transaction_id);

            // Add metadata headers for capture request
            let mut capture_grpc_request = Request::new(capture_request);
            add_helcim_metadata(&mut capture_grpc_request);

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
        }
    });
}

// Test payment void
#[tokio::test]
async fn test_payment_void() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        // First create a payment with manual capture to void
        let auth_request = create_payment_authorize_request(CaptureMethod::Manual);

        // Add metadata headers for auth request
        let mut auth_grpc_request = Request::new(auth_request);
        add_helcim_metadata(&mut auth_grpc_request);

        // Send the auth request
        let auth_response = client
            .authorize(auth_grpc_request)
            .await
            .expect("gRPC payment_authorize call failed")
            .into_inner();

        // Extract the transaction ID
        let transaction_id = extract_transaction_id(&auth_response);

        // Extract the request ref ID
        let request_ref_id = extract_request_ref_id(&auth_response);

        // After authentication, sync the payment to get updated status
        let sync_request = create_payment_sync_request(&transaction_id, &request_ref_id);
        let mut sync_grpc_request = Request::new(sync_request);
        add_helcim_metadata(&mut sync_grpc_request);

        let void_request = create_payment_void_request(&transaction_id);

        // Add metadata headers for void request
        let mut void_grpc_request = Request::new(void_request);
        add_helcim_metadata(&mut void_grpc_request);

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
        let sync_request = create_payment_sync_request(&transaction_id, &request_ref_id);
        let mut sync_grpc_request = Request::new(sync_request);
        add_helcim_metadata(&mut sync_grpc_request);

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

// Test payment sync
#[tokio::test]
async fn test_payment_sync() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        // First create a payment to sync
        let auth_request = create_payment_authorize_request(CaptureMethod::Automatic);

        // Add metadata headers for auth request
        let mut auth_grpc_request = Request::new(auth_request);
        add_helcim_metadata(&mut auth_grpc_request);

        // Send the auth request
        let auth_response = client
            .authorize(auth_grpc_request)
            .await
            .expect("gRPC payment_authorize call failed")
            .into_inner();

        // Extract the transaction ID
        let transaction_id = extract_transaction_id(&auth_response);

        // Extract the request ref ID
        let request_ref_id = extract_request_ref_id(&auth_response);

        // Wait longer for the transaction to be processed - some async processing may happen
        std::thread::sleep(std::time::Duration::from_secs(2));

        // Create sync request with the specific transaction ID
        let sync_request = create_payment_sync_request(&transaction_id, &request_ref_id);

        // Add metadata headers for sync request
        let mut sync_grpc_request = Request::new(sync_request);
        add_helcim_metadata(&mut sync_grpc_request);

        // Send the sync request
        let sync_response = client
            .get(sync_grpc_request)
            .await
            .expect("Payment sync request failed")
            .into_inner();

        // Verify the sync response - could be charged, authorized, or pending for automatic capture
        assert!(
            sync_response.status == i32::from(PaymentStatus::Charged),
            "Payment should be in CHARGED state"
        );
    });
}

// Test refund flow
#[tokio::test]
async fn test_refund() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        // First create a payment with automatic capture
        let auth_request = create_payment_authorize_request(CaptureMethod::Automatic);

        // Add metadata headers for auth request
        let mut auth_grpc_request = Request::new(auth_request);
        add_helcim_metadata(&mut auth_grpc_request);

        // Send the auth request
        let auth_response = client
            .authorize(auth_grpc_request)
            .await
            .expect("gRPC payment_authorize call failed")
            .into_inner();

        // Extract the transaction ID
        let transaction_id = extract_transaction_id(&auth_response);

        assert!(
            auth_response.status == i32::from(PaymentStatus::Charged),
            "Payment should be in Charged state with auto capture"
        );

        // Create refund request
        let refund_request = create_refund_request(&transaction_id);

        // Add metadata headers for refund request
        let mut refund_grpc_request = Request::new(refund_request);
        add_helcim_metadata(&mut refund_grpc_request);

        // Send the refund request and expect a successful response
        let refund_response = client
            .refund(refund_grpc_request)
            .await
            .expect("gRPC refund call failed")
            .into_inner();

        // Verify the refund status
        assert!(
            refund_response.status == i32::from(RefundStatus::RefundSuccess),
            "Refund should be in RefundSuccess state"
        );
    });
}

// Test refund sync flow
#[tokio::test]
async fn test_refund_sync() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        grpc_test!(refund_client, RefundServiceClient<Channel>, {
            // First create a payment with manual capture (same as the script)
            let auth_request = create_payment_authorize_request(CaptureMethod::Automatic);

            // Add metadata headers for auth request
            let mut auth_grpc_request = Request::new(auth_request);
            add_helcim_metadata(&mut auth_grpc_request);

            // Send the auth request
            let auth_response = client
                .authorize(auth_grpc_request)
                .await
                .expect("gRPC payment_authorize call failed")
                .into_inner();

            // Extract the transaction ID
            let transaction_id = extract_transaction_id(&auth_response);

            // Verify payment status is Charged
            assert!(
                auth_response.status == i32::from(PaymentStatus::Charged),
                "Payment should be in AUTHENTICATIONPENDING state with auto capture"
            );

            // Create refund request
            let refund_request = create_refund_request(&transaction_id);

            // Add metadata headers for refund request
            let mut refund_grpc_request = Request::new(refund_request);
            add_helcim_metadata(&mut refund_grpc_request);

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

            // Wait a bit longer to ensure the refund is fully processed
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

            // Create refund sync request
            let refund_sync_request = create_refund_sync_request(&transaction_id, refund_id);

            // Add metadata headers for refund sync request
            let mut refund_sync_grpc_request = Request::new(refund_sync_request);
            add_helcim_metadata(&mut refund_sync_grpc_request);

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

// Helper function to extract connector Refund ID from response
fn extract_refund_id(response: &RefundResponse) -> &String {
    &response.refund_id
}
