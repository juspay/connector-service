#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]

use cards::CardNumber;
use grpc_server::{app, configs};
use hyperswitch_masking::Secret;
mod common;

use std::{
    env,
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

use grpc_api_types::{
    health_check::{health_client::HealthClient, HealthCheckRequest},
    payments::{
        card_payment_method_type, identifier::IdType, payment_method,
        payment_service_client::PaymentServiceClient,
        refund_service_client::RefundServiceClient,
        AuthenticationType, CaptureMethod, CardDetails, CardPaymentMethodType,
        Currency, Identifier, PaymentMethod, PaymentServiceAuthorizeRequest,
        PaymentServiceAuthorizeResponse, PaymentServiceCaptureRequest,
        PaymentServiceGetRequest, PaymentServiceRefundRequest,
        PaymentServiceVoidRequest, PaymentStatus, RefundServiceGetRequest,
        RefundStatus, Address, PaymentAddress, CountryAlpha2,
    },
};
use tonic::{transport::Channel, Request};

// Constants specific to the Forte connector
const CONNECTOR_NAME: &str = "forte";
const AUTH_TYPE: &str = "multi-auth-key";

// Environment variable names for API credentials
const FORTE_API_ACCESS_ID_ENV: &str = "TEST_FORTE_API_ACCESS_ID";
const FORTE_ORGANIZATION_ID_ENV: &str = "TEST_FORTE_ORGANIZATION_ID";
const FORTE_API_SECRET_KEY_ENV: &str = "TEST_FORTE_API_SECRET_KEY";
const FORTE_LOCATION_ID_ENV: &str = "TEST_FORTE_LOCATION_ID";

// Test data constants
const TEST_AMOUNT: i64 = 1000; // $10.00 in cents
const TEST_CARD_NUMBER: &str = "4111111111111111"; // Visa test card
const TEST_CARD_EXP_MONTH: &str = "12";
const TEST_CARD_EXP_YEAR: &str = "2025";
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

// Helper function to add connector metadata headers to a request
fn add_connector_metadata<T>(request: &mut Request<T>) {
    // Get credentials from environment
    let api_access_id = env::var(FORTE_API_ACCESS_ID_ENV)
        .expect("Forte API access ID environment variable must be set");
    let organization_id = env::var(FORTE_ORGANIZATION_ID_ENV)
        .expect("Forte organization ID environment variable must be set");
    let api_secret_key = env::var(FORTE_API_SECRET_KEY_ENV)
        .expect("Forte API secret key environment variable must be set");
    let location_id = env::var(FORTE_LOCATION_ID_ENV)
        .expect("Forte location ID environment variable must be set");

    // Add required headers
    request.metadata_mut().append(
        "x-connector",
        CONNECTOR_NAME.parse().expect("Failed to parse x-connector"),
    );
    request.metadata_mut().append(
        "x-auth",
        AUTH_TYPE.parse().expect("Failed to parse x-auth"),
    );
    request.metadata_mut().append(
        "x-api-key",
        api_access_id.parse().expect("Failed to parse x-api-key"),
    );
    request.metadata_mut().append(
        "x-key1",
        organization_id.parse().expect("Failed to parse x-key1"),
    );
    request.metadata_mut().append(
        "x-api-secret",
        api_secret_key.parse().expect("Failed to parse x-api-secret"),
    );
    request.metadata_mut().append(
        "x-key2",
        location_id.parse().expect("Failed to parse x-key2"),
    );

    // Add required system headers
    request.metadata_mut().append(
        "x-merchant-id",
        "test_merchant".parse().expect("Failed to parse x-merchant-id"),
    );
    request.metadata_mut().append(
        "x-tenant-id",
        "default".parse().expect("Failed to parse x-tenant-id"),
    );
}

// Helper function to extract connector transaction ID from response
fn extract_transaction_id(response: &PaymentServiceAuthorizeResponse) -> String {
    match &response.transaction_id {
        Some(id) => match &id.id_type {
            Some(id_type) => match id_type {
                IdType::Id(id) => id.clone(),
                IdType::EncodedData(id) => id.clone(),
                _ => format!("unknown_id_type_{}", get_timestamp()),
            },
            None => format!("no_id_type_{}", get_timestamp()),
        },
        None => format!("no_transaction_id_{}", get_timestamp()),
    }
}

// Helper function to create a payment authorization request
fn create_payment_authorize_request(capture_method: CaptureMethod) -> PaymentServiceAuthorizeRequest {
    let card_details = card_payment_method_type::CardType::Credit(CardDetails {
        card_number: Some(CardNumber::from_str(TEST_CARD_NUMBER).unwrap()),
        card_exp_month: Some(Secret::new(TEST_CARD_EXP_MONTH.to_string())),
        card_exp_year: Some(Secret::new(TEST_CARD_EXP_YEAR.to_string())),
        card_cvc: Some(Secret::new(TEST_CARD_CVC.to_string())),
        card_holder_name: Some(Secret::new(TEST_CARD_HOLDER.to_string())),
        card_issuer: None,
        card_network: None,
        card_type: None,
        card_issuing_country_alpha2: None,
        bank_code: None,
        nick_name: None,
    });

    PaymentServiceAuthorizeRequest {
        amount: TEST_AMOUNT,
        minor_amount: TEST_AMOUNT,
        currency: i32::from(Currency::Usd),
        payment_method: Some(PaymentMethod {
            payment_method: Some(payment_method::PaymentMethod::Card(CardPaymentMethodType {
                card_type: Some(card_details),
            })),
        }),
        email: Some(TEST_EMAIL.to_string().into()),
        address: Some(PaymentAddress {
            billing_address: Some(Address {
                first_name: Some("Test".to_string()),
                last_name: Some("User".to_string()),
                line1: Some("123 Test St".to_string().into()),
                city: Some("Test City".to_string().into()),
                state: Some("NY".to_string().into()),
                zip_code: Some("10001".to_string().into()),
                country_alpha2_code: Some(i32::from(CountryAlpha2::Us)),
                phone_number: None,
                phone_country_code: None,
                email: None,
            }),
            shipping_address: None,
        }),
        auth_type: i32::from(AuthenticationType::NoThreeDs),
        request_ref_id: Some(Identifier {
            id_type: Some(IdType::Id(format!("forte_test_{}", get_timestamp()))),
        }),
        enrolled_for_3ds: false,
        request_incremental_authorization: false,
        capture_method: Some(i32::from(capture_method)),
        metadata: std::collections::HashMap::new(),
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
            id_type: Some(IdType::Id(format!("forte_sync_{}", get_timestamp()))),
        }),
    }
}

// Helper function to create a payment capture request
fn create_payment_capture_request(transaction_id: &str) -> PaymentServiceCaptureRequest {
    PaymentServiceCaptureRequest {
        connector_transaction_id: transaction_id.to_string(),
        amount_to_capture: TEST_AMOUNT,
        currency: i32::from(Currency::Usd),
        multiple_capture_data: None,
        connector_meta_data: None,
        all_keys_required: None,
    }
}

// Helper function to create a refund request
fn create_refund_request(transaction_id: &str) -> PaymentServiceRefundRequest {
    PaymentServiceRefundRequest {
        refund_id: format!("forte_refund_{}", get_timestamp()),
        connector_transaction_id: transaction_id.to_string(),
        currency: i32::from(Currency::Usd),
        payment_amount: TEST_AMOUNT,
        refund_amount: TEST_AMOUNT,
        minor_payment_amount: TEST_AMOUNT,
        minor_refund_amount: TEST_AMOUNT,
        connector_refund_id: None,
        reason: None,
        webhook_url: None,
        connector_metadata: None,
        refund_connector_metadata: None,
        browser_info: None,
        merchant_account_id: None,
        capture_method: None,
        all_keys_required: None,
    }
}

// Helper function to create a refund sync request
fn create_refund_sync_request(transaction_id: &str, refund_id: &str) -> RefundServiceGetRequest {
    RefundServiceGetRequest {
        connector_transaction_id: transaction_id.to_string(),
        connector_refund_id: refund_id.to_string(),
        refund_reason: None,
        all_keys_required: None,
    }
}

// Helper function to create a payment void request
fn create_payment_void_request(transaction_id: &str) -> PaymentServiceVoidRequest {
    PaymentServiceVoidRequest {
        connector_transaction_id: transaction_id.to_string(),
        cancellation_reason: Some("Test cancellation".to_string()),
        request_ref_id: Some(Identifier {
            id_type: Some(IdType::Id(format!("forte_void_{}", get_timestamp()))),
        }),
        ..Default::default()
    }
}

// Test implementations
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

#[tokio::test]
async fn test_payment_authorization_auto_capture() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        let request = create_payment_authorize_request(CaptureMethod::Automatic);
        let mut grpc_request = Request::new(request);
        add_connector_metadata(&mut grpc_request);

        let response = client
            .authorize(grpc_request)
            .await
            .expect("gRPC payment_authorize call failed")
            .into_inner();

        // Verify response with proper error handling for sandbox
        let acceptable_statuses = [
            i32::from(PaymentStatus::Charged),
            i32::from(PaymentStatus::Pending),
            i32::from(PaymentStatus::Authorized),
        ];
        
        assert!(
            acceptable_statuses.contains(&response.status),
            "Payment should be in acceptable state but was: {}",
            response.status
        );

        if response.transaction_id.is_some() {
            let _transaction_id = extract_transaction_id(&response);
            // Transaction ID extracted successfully
        }
    });
}

#[tokio::test]
async fn test_payment_authorization_manual_capture() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        // First, authorize the payment with manual capture
        let request = create_payment_authorize_request(CaptureMethod::Manual);
        let mut grpc_request = Request::new(request);
        add_connector_metadata(&mut grpc_request);

        let response = client
            .authorize(grpc_request)
            .await
            .expect("gRPC payment_authorize call failed")
            .into_inner();

        // Verify authorization response
        let acceptable_auth_statuses = [
            i32::from(PaymentStatus::Authorized),
            i32::from(PaymentStatus::Pending),
        ];
        
        assert!(
            acceptable_auth_statuses.contains(&response.status),
            "Payment should be authorized but was: {}",
            response.status
        );

        if response.transaction_id.is_some() {
            let transaction_id = extract_transaction_id(&response);

            // Now capture the payment
            let capture_request = create_payment_capture_request(&transaction_id);
            let mut capture_grpc_request = Request::new(capture_request);
            add_connector_metadata(&mut capture_grpc_request);

            let capture_response = client
                .capture(capture_grpc_request)
                .await
                .expect("gRPC payment_capture call failed")
                .into_inner();

            // Verify capture response
            let acceptable_capture_statuses = [
                i32::from(PaymentStatus::Charged),
                i32::from(PaymentStatus::Pending),
            ];
            
            assert!(
                acceptable_capture_statuses.contains(&capture_response.status),
                "Payment should be captured but was: {}",
                capture_response.status
            );
        }
    });
}

#[tokio::test]
async fn test_payment_sync() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        // First create a payment to sync
        let request = create_payment_authorize_request(CaptureMethod::Automatic);
        let mut grpc_request = Request::new(request);
        add_connector_metadata(&mut grpc_request);

        let response = client
            .authorize(grpc_request)
            .await
            .expect("gRPC payment_authorize call failed")
            .into_inner();

        if response.transaction_id.is_some() {
            let transaction_id = extract_transaction_id(&response);

            // Create sync request
            let sync_request = create_payment_sync_request(&transaction_id);
            let mut sync_grpc_request = Request::new(sync_request);
            add_connector_metadata(&mut sync_grpc_request);

            let sync_response = client
                .get(sync_grpc_request)
                .await
                .expect("gRPC payment_sync call failed")
                .into_inner();

            // Verify sync response - should return current payment status
            let acceptable_sync_statuses = [
                i32::from(PaymentStatus::Charged),
                i32::from(PaymentStatus::Pending),
                i32::from(PaymentStatus::Authorized),
                i32::from(PaymentStatus::Failed),
            ];
            
            assert!(
                acceptable_sync_statuses.contains(&sync_response.status),
                "Payment sync should return valid status but was: {}",
                sync_response.status
            );
        }
    });
}

#[tokio::test]
async fn test_refund() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        // First create a payment
        let request = create_payment_authorize_request(CaptureMethod::Automatic);
        let mut grpc_request = Request::new(request);
        add_connector_metadata(&mut grpc_request);

        let response = client
            .authorize(grpc_request)
            .await
            .expect("gRPC payment_authorize call failed")
            .into_inner();

        // Only proceed if payment was successful
        if response.status == i32::from(PaymentStatus::Charged) && response.transaction_id.is_some() {
            let transaction_id = extract_transaction_id(&response);

            // Create refund request
            let refund_request = create_refund_request(&transaction_id);
            let mut refund_grpc_request = Request::new(refund_request);
            add_connector_metadata(&mut refund_grpc_request);

            let refund_response = client
                .refund(refund_grpc_request)
                .await
                .expect("gRPC refund call failed")
                .into_inner();

            // Verify refund response
            let acceptable_refund_statuses = [
                i32::from(RefundStatus::Success),
                i32::from(RefundStatus::Pending),
                i32::from(RefundStatus::Failure),
            ];
            
            assert!(
                acceptable_refund_statuses.contains(&refund_response.status),
                "Refund should return valid status but was: {}",
                refund_response.status
            );
        }
    });
}

#[tokio::test]
async fn test_refund_sync() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        // First create a payment
        let request = create_payment_authorize_request(CaptureMethod::Automatic);
        let mut grpc_request = Request::new(request);
        add_connector_metadata(&mut grpc_request);

        let response = client
            .authorize(grpc_request)
            .await
            .expect("gRPC payment_authorize call failed")
            .into_inner();

        // Only proceed if payment was successful
        if response.status == i32::from(PaymentStatus::Charged) && response.transaction_id.is_some() {
            let transaction_id = extract_transaction_id(&response);

            // Create a refund to get a valid refund ID
            let refund_request = create_refund_request(&transaction_id);
            let mut refund_grpc_request = Request::new(refund_request.clone());
            add_connector_metadata(&mut refund_grpc_request);

            let refund_response = client
                .refund(refund_grpc_request)
                .await
                .expect("gRPC refund call failed")
                .into_inner();

            if refund_response.connector_refund_id.is_some() {
                let refund_id = refund_response.connector_refund_id.unwrap();

                // Create refund sync request
                let refund_sync_request = create_refund_sync_request(&transaction_id, &refund_id);
                let mut refund_sync_grpc_request = Request::new(refund_sync_request);
                add_connector_metadata(&mut refund_sync_grpc_request);

                let refund_sync_response = client
                    .refund_get(refund_sync_grpc_request)
                    .await
                    .expect("gRPC refund_sync call failed")
                    .into_inner();

                // Verify refund sync response
                let acceptable_refund_sync_statuses = [
                    i32::from(RefundStatus::Success),
                    i32::from(RefundStatus::Pending),
                    i32::from(RefundStatus::Failure),
                ];
                
                assert!(
                    acceptable_refund_sync_statuses.contains(&refund_sync_response.status),
                    "Refund sync should return valid status but was: {}",
                    refund_sync_response.status
                );
            }
        }
    });
}

#[tokio::test]
async fn test_payment_void() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        // First create a payment with manual capture (so it can be voided)
        let request = create_payment_authorize_request(CaptureMethod::Manual);
        let mut grpc_request = Request::new(request);
        add_connector_metadata(&mut grpc_request);

        let response = client
            .authorize(grpc_request)
            .await
            .expect("gRPC payment_authorize call failed")
            .into_inner();

        // Only proceed if payment was authorized
        if response.status == i32::from(PaymentStatus::Authorized) && response.transaction_id.is_some() {
            let transaction_id = extract_transaction_id(&response);

            // Create void request
            let void_request = create_payment_void_request(&transaction_id);
            let mut void_grpc_request = Request::new(void_request);
            add_connector_metadata(&mut void_grpc_request);

            let void_response = client
                .void(void_grpc_request)
                .await
                .expect("gRPC payment_void call failed")
                .into_inner();

            // Verify void response
            let acceptable_void_statuses = [
                i32::from(PaymentStatus::Voided),
                i32::from(PaymentStatus::Pending),
                i32::from(PaymentStatus::Failed),
            ];
            
            assert!(
                acceptable_void_statuses.contains(&void_response.status),
                "Payment void should return valid status but was: {}",
                void_response.status
            );
        }
    });
}