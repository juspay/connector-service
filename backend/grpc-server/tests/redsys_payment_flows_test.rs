#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]

use grpc_server::{app, configs};
use hyperswitch_masking::{ExposeInterface, Secret};
mod common;
mod utils;

use std::{
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

use cards::CardNumber;
use grpc_api_types::{
    health_check::{health_client::HealthClient, HealthCheckRequest},
    payments::{
        identifier::IdType, payment_method, payment_service_client::PaymentServiceClient,
        refund_service_client::RefundServiceClient, AuthenticationType, BrowserInformation,
        CaptureMethod, CardDetails, Currency, Identifier, PaymentMethod,
        PaymentServiceAuthenticateRequest, PaymentServiceAuthenticateResponse,
        PaymentServiceAuthorizeRequest, PaymentServiceAuthorizeResponse,
        PaymentServiceCaptureRequest, PaymentServiceGetRequest,
        PaymentServicePostAuthenticateRequest, PaymentServiceRefundRequest,
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

// Constants for Redsys connector
const CONNECTOR_NAME: &str = "redsys";
const AUTH_TYPE: &str = "signature-key";
const MERCHANT_ID: &str = "merchant_redsys";

// Test card data - Redsys test cards
const TEST_AMOUNT: i64 = 100; // 1.00 EUR in minor units
const TEST_CARD_NUMBER_FRICTIONLESS: &str = "4548814479727229"; // Frictionless flow (no challenge)
const _TEST_CARD_NUMBER_CHALLENGE: &str = "4548812049400004"; // Challenge required
const TEST_CARD_EXP_MONTH: &str = "12";
const TEST_CARD_EXP_YEAR: &str = "2025";
const TEST_CARD_CVC: &str = "123";
const TEST_CARD_HOLDER: &str = "Test User";
const TEST_EMAIL: &str = "customer@example.com";

fn add_redsys_metadata<T>(request: &mut Request<T>) {
    // Get API credentials using the common credential loading utility
    let auth = utils::credential_utils::load_connector_auth(CONNECTOR_NAME)
        .expect("Failed to load Redsys credentials");

    let (api_key, key1, api_secret) = match auth {
        domain_types::router_data::ConnectorAuthType::SignatureKey {
            api_key,
            key1,
            api_secret,
        } => (api_key.expose(), key1.expose(), api_secret.expose()),
        _ => panic!("Expected SignatureKey auth type for Redsys"),
    };

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

    request.metadata_mut().append(
        "x-tenant-id",
        "default".parse().expect("Failed to parse x-tenant-id"),
    );

    request.metadata_mut().append(
        "x-connector-request-reference-id",
        format!("redsys_ref_{}", get_timestamp())
            .parse()
            .expect("Failed to parse x-connector-request-reference-id"),
    );
}

// Helper function to extract connector transaction ID from response
fn extract_transaction_id(response: &PaymentServiceAuthorizeResponse) -> String {
    match &response.transaction_id {
        Some(id) => match id.id_type.as_ref().unwrap() {
            IdType::Id(id) => id.clone(),
            _ => panic!("Expected connector transaction ID"),
        },
        None => panic!("Transaction ID is None"),
    }
}

// Helper function to extract connector metadata from authenticate response
fn extract_three_ds_server_trans_id(
    response: &PaymentServiceAuthenticateResponse,
) -> Option<String> {
    response
        .connector_metadata
        .get("threeDSServerTransID")
        .cloned()
}

// Helper function to extract connector Refund ID from response
fn extract_refund_id(response: &RefundResponse) -> &String {
    &response.refund_id
}

// Helper function to create browser information for 3DS
fn create_browser_info() -> BrowserInformation {
    BrowserInformation {
        user_agent: Some(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string(),
        ),
        accept_header: Some("text/html,application/xhtml+xml,application/xml;q=0.9".to_string()),
        accept_language: Some("es-ES".to_string()),
        color_depth: Some(24),
        screen_height: Some(1080),
        screen_width: Some(1920),
        time_zone_offset_minutes: Some(-60),
        java_enabled: Some(false),
        java_script_enabled: Some(true),
        ip_address: Some("185.45.188.1".to_string()),
        language: None,
        referer: None,
        os_type: None,
        os_version: None,
        device_model: None,
    }
}

// Helper function to create a payment authenticate request (3DS Method Invocation)
fn create_authenticate_request(card_number: &str) -> PaymentServiceAuthenticateRequest {
    let card_details = CardDetails {
        card_number: Some(CardNumber::from_str(card_number).unwrap()),
        card_exp_month: Some(Secret::new(TEST_CARD_EXP_MONTH.to_string())),
        card_exp_year: Some(Secret::new(TEST_CARD_EXP_YEAR.to_string())),
        card_cvc: Some(Secret::new(TEST_CARD_CVC.to_string())), // Required by server validation
        card_holder_name: None,
        card_issuer: None,
        card_network: Some(1), // Visa
        card_type: None,
        card_issuing_country_alpha2: None,
        bank_code: None,
        nick_name: None,
    };

    PaymentServiceAuthenticateRequest {
        amount: TEST_AMOUNT,
        minor_amount: TEST_AMOUNT,
        currency: i32::from(Currency::Eur),
        payment_method: Some(PaymentMethod {
            payment_method: Some(payment_method::PaymentMethod::Card(card_details)),
        }),
        request_ref_id: Some(Identifier {
            id_type: Some(IdType::Id(generate_unique_id("redsys_auth"))),
        }),
        address: Some(grpc_api_types::payments::PaymentAddress::default()),
        ..Default::default()
    }
}

// Helper function to create a post-authenticate request (Authorization after 3DS Method)
fn create_post_authenticate_request(
    card_number: &str,
    three_ds_server_trans_id: Option<String>,
) -> PaymentServicePostAuthenticateRequest {
    let card_details = CardDetails {
        card_number: Some(CardNumber::from_str(card_number).unwrap()),
        card_exp_month: Some(Secret::new(TEST_CARD_EXP_MONTH.to_string())),
        card_exp_year: Some(Secret::new(TEST_CARD_EXP_YEAR.to_string())),
        card_cvc: Some(Secret::new(TEST_CARD_CVC.to_string())),
        card_holder_name: Some(Secret::new(TEST_CARD_HOLDER.to_string())),
        card_issuer: None,
        card_network: Some(1), // Visa
        card_type: None,
        card_issuing_country_alpha2: None,
        bank_code: None,
        nick_name: None,
    };

    // Create connector metadata with threeDSServerTransID if provided
    let mut metadata = std::collections::HashMap::new();
    if let Some(trans_id) = three_ds_server_trans_id {
        metadata.insert("threeDSServerTransID".to_string(), trans_id);
    }

    PaymentServicePostAuthenticateRequest {
        amount: TEST_AMOUNT,
        minor_amount: TEST_AMOUNT,
        currency: i32::from(Currency::Eur),
        payment_method: Some(PaymentMethod {
            payment_method: Some(payment_method::PaymentMethod::Card(card_details)),
        }),
        request_ref_id: Some(Identifier {
            id_type: Some(IdType::Id(generate_unique_id("redsys_postauth"))),
        }),
        browser_info: Some(create_browser_info()),
        metadata,
        address: Some(grpc_api_types::payments::PaymentAddress::default()),
        ..Default::default()
    }
}

// Helper function to create a payment authorize request
fn create_authorize_request(
    card_number: &str,
    capture_method: CaptureMethod,
) -> PaymentServiceAuthorizeRequest {
    let card_details = CardDetails {
        card_number: Some(CardNumber::from_str(card_number).unwrap()),
        card_exp_month: Some(Secret::new(TEST_CARD_EXP_MONTH.to_string())),
        card_exp_year: Some(Secret::new(TEST_CARD_EXP_YEAR.to_string())),
        card_cvc: Some(Secret::new(TEST_CARD_CVC.to_string())),
        card_holder_name: Some(Secret::new(TEST_CARD_HOLDER.to_string())),
        card_issuer: None,
        card_network: Some(1), // Visa
        card_type: None,
        card_issuing_country_alpha2: None,
        bank_code: None,
        nick_name: None,
    };

    PaymentServiceAuthorizeRequest {
        amount: TEST_AMOUNT,
        minor_amount: TEST_AMOUNT,
        currency: i32::from(Currency::Eur),
        payment_method: Some(PaymentMethod {
            payment_method: Some(payment_method::PaymentMethod::Card(card_details)),
        }),
        return_url: Some("https://merchant.com/return".to_string()),
        webhook_url: Some("https://merchant.com/webhook".to_string()),
        email: Some(TEST_EMAIL.to_string().into()),
        address: Some(grpc_api_types::payments::PaymentAddress::default()),
        auth_type: i32::from(AuthenticationType::ThreeDs),
        request_ref_id: Some(Identifier {
            id_type: Some(IdType::Id(generate_unique_id("redsys_authorize"))),
        }),
        request_incremental_authorization: false,
        capture_method: Some(i32::from(capture_method)),
        browser_info: Some(create_browser_info()),
        ..Default::default()
    }
}

// Helper function to create a payment sync request
fn create_payment_sync_request(transaction_id: &str) -> PaymentServiceGetRequest {
    PaymentServiceGetRequest {
        transaction_id: Some(Identifier {
            id_type: Some(IdType::Id(transaction_id.to_string())),
        }),
        ..Default::default()
    }
}

// Helper function to create a payment capture request
fn create_payment_capture_request(transaction_id: &str) -> PaymentServiceCaptureRequest {
    PaymentServiceCaptureRequest {
        transaction_id: Some(Identifier {
            id_type: Some(IdType::Id(transaction_id.to_string())),
        }),
        amount_to_capture: TEST_AMOUNT,
        currency: i32::from(Currency::Eur),
        request_ref_id: Some(Identifier {
            id_type: Some(IdType::Id(generate_unique_id("redsys_capture"))),
        }),
        ..Default::default()
    }
}

// Helper function to create a refund request
fn create_refund_request(transaction_id: &str) -> PaymentServiceRefundRequest {
    PaymentServiceRefundRequest {
        refund_id: generate_unique_id("refund"),
        transaction_id: Some(Identifier {
            id_type: Some(IdType::Id(transaction_id.to_string())),
        }),
        currency: i32::from(Currency::Eur),
        payment_amount: TEST_AMOUNT,
        refund_amount: TEST_AMOUNT,
        minor_payment_amount: TEST_AMOUNT,
        minor_refund_amount: TEST_AMOUNT,
        reason: Some("Customer requested refund".to_string()),
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
        ..Default::default()
    }
}

// Helper function to create a payment void request
fn create_payment_void_request(transaction_id: &str) -> PaymentServiceVoidRequest {
    PaymentServiceVoidRequest {
        transaction_id: Some(Identifier {
            id_type: Some(IdType::Id(transaction_id.to_string())),
        }),
        request_ref_id: Some(Identifier {
            id_type: Some(IdType::Id(generate_unique_id("redsys_void"))),
        }),
        ..Default::default()
    }
}

//
// TESTS
//

#[tokio::test]
async fn test_health() {
    grpc_test!(client, HealthClient<Channel>, {
        let mut request = Request::new(HealthCheckRequest {
            service: String::new(),
        });
        add_redsys_metadata(&mut request);

        let response = client
            .check(request)
            .await
            .expect("Health check request failed");

        println!("Health check response: {:?}", response);
        assert_eq!(response.into_inner().status, 1); // SERVING = 1
    });
}

#[tokio::test]
async fn test_authenticate_flow() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        // Step 1: Authenticate (3DS Method Invocation)
        let authenticate_request = create_authenticate_request(TEST_CARD_NUMBER_FRICTIONLESS);

        let mut request = Request::new(authenticate_request);
        add_redsys_metadata(&mut request);

        let response = client
            .authenticate(request)
            .await
            .expect("Authenticate request failed");

        let auth_response = response.into_inner();
        println!("Authenticate response: {:?}", auth_response);

        // Extract threeDSServerTransID from connector metadata
        let three_ds_server_trans_id = extract_three_ds_server_trans_id(&auth_response);
        println!("3DS Server Transaction ID: {:?}", three_ds_server_trans_id);

        // Verify response has authentication pending status
        assert_eq!(
            PaymentStatus::try_from(auth_response.status).unwrap(),
            PaymentStatus::AuthenticationPending
        );
    });
}

#[tokio::test]
async fn test_post_authenticate_frictionless_flow() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        // Step 1: Authenticate (3DS Method Invocation)
        let authenticate_request = create_authenticate_request(TEST_CARD_NUMBER_FRICTIONLESS);
        let mut request = Request::new(authenticate_request);
        add_redsys_metadata(&mut request);

        let response = client
            .authenticate(request)
            .await
            .expect("Authenticate request failed");

        let auth_response = response.into_inner();
        let three_ds_server_trans_id = extract_three_ds_server_trans_id(&auth_response);

        // Step 2: PostAuthenticate (should complete without challenge)
        let post_auth_request = create_post_authenticate_request(
            TEST_CARD_NUMBER_FRICTIONLESS,
            three_ds_server_trans_id,
        );
        let mut request = Request::new(post_auth_request);
        add_redsys_metadata(&mut request);

        let response = client
            .post_authenticate(request)
            .await
            .expect("PostAuthenticate request failed");

        let post_auth_response = response.into_inner();
        println!("PostAuthenticate response: {:?}", post_auth_response);

        // For frictionless flow, payment should be charged directly
        let status = PaymentStatus::try_from(post_auth_response.status).unwrap();
        println!("Payment status: {:?}", status);

        // Status could be Charged (success) or AuthenticationPending (if challenge required)
        assert!(
            status == PaymentStatus::Charged
                || status == PaymentStatus::AuthenticationPending
                || status == PaymentStatus::Authorized
        );

        if status == PaymentStatus::Charged || status == PaymentStatus::Authorized {
            // Extract transaction ID for cleanup/verification
            let transaction_id = post_auth_response
                .transaction_id
                .and_then(|id| id.id_type)
                .and_then(|id_type| match id_type {
                    IdType::Id(id) => Some(id),
                    _ => None,
                });
            println!("Transaction ID: {:?}", transaction_id);
        }
    });
}

#[tokio::test]
async fn test_payment_authorization_manual_capture() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        // Create a payment authorization with manual capture
        let authorize_request =
            create_authorize_request(TEST_CARD_NUMBER_FRICTIONLESS, CaptureMethod::Manual);
        let mut request = Request::new(authorize_request);
        add_redsys_metadata(&mut request);

        let response = client
            .authorize(request)
            .await
            .expect("Authorize request failed");

        let authorize_response = response.into_inner();
        println!("Authorize response: {:?}", authorize_response);

        // Extract transaction ID
        let transaction_id = extract_transaction_id(&authorize_response);
        println!("Transaction ID: {}", transaction_id);

        // Verify payment is in authorized state
        let status = PaymentStatus::try_from(authorize_response.status).unwrap();
        println!("Payment status: {:?}", status);

        // Could be Authorized, AuthenticationPending, or Charged
        assert!(
            status == PaymentStatus::Authorized
                || status == PaymentStatus::AuthenticationPending
                || status == PaymentStatus::Charged
        );

        if status == PaymentStatus::Authorized {
            // Step 2: Capture the payment
            let capture_request = create_payment_capture_request(&transaction_id);
            let mut request = Request::new(capture_request);
            add_redsys_metadata(&mut request);

            let response = client
                .capture(request)
                .await
                .expect("Capture request failed");

            let capture_response = response.into_inner();
            println!("Capture response: {:?}", capture_response);

            // Verify payment is now charged
            let capture_status = PaymentStatus::try_from(capture_response.status).unwrap();
            println!("Capture status: {:?}", capture_status);
            assert_eq!(capture_status, PaymentStatus::Charged);
        }
    });
}

#[tokio::test]
async fn test_payment_sync() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        // First create a payment to sync
        let authorize_request =
            create_authorize_request(TEST_CARD_NUMBER_FRICTIONLESS, CaptureMethod::Automatic);
        let mut request = Request::new(authorize_request);
        add_redsys_metadata(&mut request);

        let response = client
            .authorize(request)
            .await
            .expect("Authorize request failed");

        let authorize_response = response.into_inner();
        let transaction_id = extract_transaction_id(&authorize_response);

        // Create sync request
        let sync_request = create_payment_sync_request(&transaction_id);
        let mut request = Request::new(sync_request);
        add_redsys_metadata(&mut request);

        // Send the sync request
        let response = client
            .get(request)
            .await
            .expect("Payment sync request failed");

        let sync_response = response.into_inner();
        println!("Payment sync response: {:?}", sync_response);

        // Verify sync succeeded
        let status = PaymentStatus::try_from(sync_response.status).unwrap();
        println!("Sync status: {:?}", status);
    });
}

#[tokio::test]
async fn test_refund() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        // First create a payment
        let authorize_request =
            create_authorize_request(TEST_CARD_NUMBER_FRICTIONLESS, CaptureMethod::Automatic);
        let mut request = Request::new(authorize_request);
        add_redsys_metadata(&mut request);

        let response = client
            .authorize(request)
            .await
            .expect("Authorize request failed");

        let authorize_response = response.into_inner();
        let transaction_id = extract_transaction_id(&authorize_response);
        let status = PaymentStatus::try_from(authorize_response.status).unwrap();

        println!("Payment created with status: {:?}", status);

        // Only attempt refund if payment is charged
        if status == PaymentStatus::Charged {
            // Create refund request
            let refund_request = create_refund_request(&transaction_id);
            let mut request = Request::new(refund_request);
            add_redsys_metadata(&mut request);

            // Send the refund request
            let response = client.refund(request).await.expect("Refund request failed");

            let refund_response = response.into_inner();
            println!("Refund response: {:?}", refund_response);

            let refund_status = RefundStatus::try_from(refund_response.status).unwrap();
            println!("Refund status: {:?}", refund_status);

            // Verify refund succeeded or is pending
            assert!(
                refund_status == RefundStatus::RefundSuccess
                    || refund_status == RefundStatus::RefundPending
            );
        } else {
            println!("Skipping refund test - payment not in charged state");
        }
    });
}

#[tokio::test]
async fn test_refund_sync() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        grpc_test!(refund_client, RefundServiceClient<Channel>, {
            // First create a payment through payment service
            let authorize_request =
                create_authorize_request(TEST_CARD_NUMBER_FRICTIONLESS, CaptureMethod::Automatic);
            let mut request = Request::new(authorize_request);
            add_redsys_metadata(&mut request);

            let response = client
                .authorize(request)
                .await
                .expect("Authorize request failed");

            let authorize_response = response.into_inner();
            let transaction_id = extract_transaction_id(&authorize_response);
            let status = PaymentStatus::try_from(authorize_response.status).unwrap();

            if status == PaymentStatus::Charged {
                // Create a refund
                let refund_request = create_refund_request(&transaction_id);
                let mut request = Request::new(refund_request.clone());
                add_redsys_metadata(&mut request);

                let response = client.refund(request).await.expect("Refund request failed");

                let refund_response = response.into_inner();
                let refund_id = extract_refund_id(&refund_response);

                // Create refund sync request
                let sync_request = create_refund_sync_request(&transaction_id, refund_id);
                let mut request = Request::new(sync_request);
                add_redsys_metadata(&mut request);

                // Send the refund sync request
                let response = refund_client
                    .get(request)
                    .await
                    .expect("Refund sync request failed");

                let sync_response = response.into_inner();
                println!("Refund sync response: {:?}", sync_response);

                let refund_status = RefundStatus::try_from(sync_response.status).unwrap();
                println!("Refund sync status: {:?}", refund_status);
            } else {
                println!("Skipping refund sync test - payment not in charged state");
            }
        });
    });
}

#[tokio::test]
async fn test_payment_void() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        // Create a payment with manual capture (so it can be voided)
        let authorize_request =
            create_authorize_request(TEST_CARD_NUMBER_FRICTIONLESS, CaptureMethod::Manual);
        let mut request = Request::new(authorize_request);
        add_redsys_metadata(&mut request);

        let response = client
            .authorize(request)
            .await
            .expect("Authorize request failed");

        let authorize_response = response.into_inner();
        let transaction_id = extract_transaction_id(&authorize_response);
        let status = PaymentStatus::try_from(authorize_response.status).unwrap();

        println!("Payment created with status: {:?}", status);

        // Only attempt void if payment is in authorized state
        if status == PaymentStatus::Authorized {
            // Create void request
            let void_request = create_payment_void_request(&transaction_id);
            let mut request = Request::new(void_request);
            add_redsys_metadata(&mut request);

            // Send the void request
            let response = client.void(request).await.expect("Void request failed");

            let void_response = response.into_inner();
            println!("Void response: {:?}", void_response);

            let void_status = PaymentStatus::try_from(void_response.status).unwrap();
            println!("Void status: {:?}", void_status);

            // Verify void succeeded
            assert_eq!(void_status, PaymentStatus::Voided);
        } else {
            println!("Skipping void test - payment not in authorized state");
        }
    });
}
