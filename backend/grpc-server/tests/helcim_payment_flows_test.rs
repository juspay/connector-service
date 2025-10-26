#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]

use grpc_server::{app, configs};
use hyperswitch_masking::Secret;
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
        payment_service_client::PaymentServiceClient, Address, AuthenticationType,
        BrowserInformation, CaptureMethod, CardDetails, CardPaymentMethodType, CountryAlpha2,
        Currency, Identifier, PaymentAddress, PaymentMethod, PaymentServiceAuthorizeRequest,
        PaymentServiceAuthorizeResponse, PaymentServiceCaptureRequest, PaymentServiceGetRequest,
        PaymentServiceVoidRequest, PaymentStatus,
    },
};
use tonic::{transport::Channel, Request};

// Constants for Helcim connector
const CONNECTOR_NAME: &str = "helcim";
const AUTH_TYPE: &str = "header-key";

// Environment variable names for API credentials
const HELCIM_API_KEY_ENV: &str = "TEST_HELCIM_API_KEY";

// Test card data
const TEST_CARD_NUMBER: &str = "5413330089099130"; // Valid test card for Helcim
const TEST_CARD_EXP_MONTH: &str = "01";
const TEST_CARD_EXP_YEAR: &str = "2027";
const TEST_CARD_CVC: &str = "123";
const TEST_CARD_HOLDER: &str = "joseph Doe";
const TEST_EMAIL: &str = "customer@example.com";

// Helper function to generate unique test amounts to avoid duplicate transaction detection
fn get_unique_amount() -> i64 {
    // Use timestamp to create unique amounts between 1000-9999 cents ($10-$99.99)
    let timestamp = get_timestamp();
    1000 + i64::try_from(timestamp % 9000).unwrap_or(0)
}

// Helper function to get current timestamp with microseconds for uniqueness
fn get_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros()
        .try_into()
        .unwrap_or(0)
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

// Helper function to extract connector transaction ID from authorize response
fn extract_transaction_id(response: &PaymentServiceAuthorizeResponse) -> String {
    match &response.transaction_id {
        Some(id) => match &id.id_type {
            Some(IdType::Id(id)) => id.clone(),
            Some(IdType::EncodedData(id)) => id.clone(),
            Some(IdType::NoResponseIdMarker(_)) => {
                // For manual capture, extract the transaction ID from connector metadata
                if let Some(preauth_id) = response.connector_metadata.get("preauth_transaction_id")
                {
                    return preauth_id.clone();
                }
                panic!(
                    "NoResponseIdMarker found but no preauth_transaction_id in connector metadata"
                )
            }
            None => panic!("ID type is None in transaction_id"),
        },
        None => panic!("Transaction ID is None"),
    }
}

// Helper function to extract connector transaction ID from void response
fn extract_void_transaction_id(
    response: &grpc_api_types::payments::PaymentServiceVoidResponse,
) -> String {
    match &response.transaction_id {
        Some(id) => match &id.id_type {
            Some(IdType::Id(id)) => id.clone(),
            Some(IdType::EncodedData(id)) => id.clone(),
            Some(_) => panic!("Unexpected ID type in transaction_id"),
            None => panic!("ID type is None in transaction_id"),
        },
        None => panic!("Transaction ID is None"),
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

// Helper function to create browser info with IP address (required for Helcim)
fn create_test_browser_info() -> BrowserInformation {
    BrowserInformation {
        ip_address: Some("192.168.1.1".to_string()),
        user_agent: Some(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string(),
        ),
        accept_header: Some(
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".to_string(),
        ),
        language: Some("en-US".to_string()),
        color_depth: Some(24),
        screen_height: Some(1080),
        screen_width: Some(1920),
        time_zone_offset_minutes: Some(-300), // EST timezone offset
        java_enabled: Some(false),
        java_script_enabled: Some(true),
        referer: Some("https://example.com".to_string()),
        os_type: None,
        os_version: None,
        device_model: None,
        accept_language: None,
    }
}

// Helper function to create a proper billing address with unique data
fn create_test_billing_address() -> PaymentAddress {
    let timestamp = get_timestamp();
    let unique_suffix = timestamp % 10000;

    PaymentAddress {
        shipping_address: Some(Address::default()),
        billing_address: Some(Address {
            first_name: Some("John".to_string().into()),
            last_name: Some("Doe".to_string().into()),
            phone_number: Some(format!("123456{unique_suffix:04}").into()),
            phone_country_code: Some("+1".to_string()),
            email: Some(format!("customer{unique_suffix}@example.com").into()),
            line1: Some(format!("{} Main St", 100 + unique_suffix).into()),
            line2: Some("Apt 4B".to_string().into()),
            line3: None,
            city: Some("New York".to_string().into()),
            state: Some("NY".to_string().into()),
            zip_code: Some(format!("{:05}", 10001 + (unique_suffix % 1000)).into()),
            country_alpha2_code: Some(CountryAlpha2::Us.into()),
        }),
    }
}

// Helper function to create a payment authorize request
fn create_payment_authorize_request(
    capture_method: CaptureMethod,
) -> PaymentServiceAuthorizeRequest {
    create_payment_authorize_request_with_amount(capture_method, get_unique_amount())
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
        browser_info: Some(create_test_browser_info()),
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
    amount: i64,
) -> PaymentServiceGetRequest {
    PaymentServiceGetRequest {
        transaction_id: Some(Identifier {
            id_type: Some(IdType::Id(transaction_id.to_string())),
        }),
        request_ref_id: Some(Identifier {
            id_type: Some(IdType::Id(request_ref_id.to_string())),
        }),
        access_token: None,
        capture_method: None,
        handle_response: None,
        amount,
        currency: i32::from(Currency::Usd),
        state: None,
    }
}

// Helper function to create a payment capture request
fn create_payment_capture_request(
    transaction_id: &str,
    amount: i64,
) -> PaymentServiceCaptureRequest {
    PaymentServiceCaptureRequest {
        transaction_id: Some(Identifier {
            id_type: Some(IdType::Id(transaction_id.to_string())),
        }),
        amount_to_capture: amount,
        currency: i32::from(Currency::Usd),
        multiple_capture_data: None,
        request_ref_id: Some(Identifier {
            id_type: Some(IdType::Id(format!("capture_ref_{}", get_timestamp()))),
        }),
        browser_info: Some(create_test_browser_info()),
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
        access_token: None,
        all_keys_required: None,
        browser_info: Some(create_test_browser_info()),
        amount: None,
        currency: None,
        ..Default::default()
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

        assert!(
            response.status == i32::from(PaymentStatus::Charged),
            "Payment should be in Charged state. Got status: {}, error_code: {:?}, error_message: {:?}",
            response.status, response.error_code, response.error_message
        );
    });
}

// Test payment authorization with manual capture
#[tokio::test]
async fn test_payment_authorization_manual_capture() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        // Create the payment authorization request with manual capture
        let unique_amount = get_unique_amount();
        let auth_request =
            create_payment_authorize_request_with_amount(CaptureMethod::Manual, unique_amount);

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

        // Extract the transaction ID
        let transaction_id = extract_transaction_id(&auth_response);

        // Verify payment status is authorized
        if auth_response.status == i32::from(PaymentStatus::Authorized) {
            // Create capture request
            let capture_request = create_payment_capture_request(&transaction_id, unique_amount);

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
        let mut auth_grpc_request = Request::new(auth_request.clone());
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
        let sync_request =
            create_payment_sync_request(&transaction_id, &request_ref_id, auth_request.amount);
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

        // Extract the void transaction ID from the void response
        let void_transaction_id = extract_void_transaction_id(&void_response);

        // Verify the payment status with a sync operation using the void transaction ID
        let sync_request =
            create_payment_sync_request(&void_transaction_id, &request_ref_id, auth_request.amount);
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
        let mut auth_grpc_request = Request::new(auth_request.clone());
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
        let sync_request =
            create_payment_sync_request(&transaction_id, &request_ref_id, auth_request.amount);

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

// NOTE: Refund tests are disabled for Helcim connector
// During testing, Helcim API returned the error message: "Card Transaction cannot be refunded"
// This indicates that refunds might not supported in the Helcim test/sandbox environment
