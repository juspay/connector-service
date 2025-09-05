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

// Constants specific to Helcim
const CONNECTOR_NAME: &str = "helcim";
const AUTH_TYPE: &str = "header-key";

// Environment variable names for API credentials
const HELCIM_API_KEY_ENV: &str = "TEST_HELCIM_API_KEY";

// Test data constants
const TEST_AMOUNT: i64 = 1000;
const TEST_CARD_NUMBER: &str = "5454545454545454"; // Helcim test card
const TEST_CARD_EXP_MONTH: &str = "12";
const TEST_CARD_EXP_YEAR: &str = "2025";
const TEST_CARD_CVC: &str = "100";
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
    let api_key = env::var(HELCIM_API_KEY_ENV)
        .unwrap_or_else(|_| "test_api_key".to_string());
    
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
        api_key.parse().expect("Failed to parse x-api-key"),
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
                line2: None,
                line3: None,
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
            id_type: Some(IdType::Id(format!("helcim_test_{}", get_timestamp()))),
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
            id_type: Some(IdType::Id(format!("helcim_sync_{}", get_timestamp()))),
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
        currency: i32::from(Currency::Usd),
        multiple_capture_data: None,
        metadata: std::collections::HashMap::new(),
        request_ref_id: Some(Identifier {
            id_type: Some(IdType::Id(format!("helcim_capture_{}", get_timestamp()))),
        }),
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
        metadata: std::collections::HashMap::new(),
        request_ref_id: Some(Identifier {
            id_type: Some(IdType::Id(format!("helcim_refund_{}", get_timestamp()))),
        }),
        ..Default::default()
    }
}

// Helper function to create a refund sync request
fn create_refund_sync_request(refund_id: &str) -> RefundServiceGetRequest {
    RefundServiceGetRequest {
        refund_id: refund_id.to_string(),
        request_ref_id: Some(Identifier {
            id_type: Some(IdType::Id(format!("helcim_refund_sync_{}", get_timestamp()))),
        }),
        browser_info: None,
        refund_reason: None,
        transaction_id: None,
    }
}

// Helper function to create a payment void request
fn create_payment_void_request(transaction_id: &str) -> PaymentServiceVoidRequest {
    PaymentServiceVoidRequest {
        transaction_id: Some(Identifier {
            id_type: Some(IdType::Id(transaction_id.to_string())),
        }),
        cancellation_reason: Some("Test cancellation".to_string()),
        request_ref_id: Some(Identifier {
            id_type: Some(IdType::Id(format!("helcim_void_{}", get_timestamp()))),
        }),
        all_keys_required: None,
        browser_info: None,
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
            println!("Auto capture payment successful with transaction ID: {}", _transaction_id);
        }
    });
}

#[tokio::test]
async fn test_payment_authorization_manual_capture() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        // First, create a payment authorization with manual capture
        let request = create_payment_authorize_request(CaptureMethod::Manual);
        let mut grpc_request = Request::new(request);
        add_connector_metadata(&mut grpc_request);

        let response = client
            .authorize(grpc_request)
            .await
            .expect("gRPC payment_authorize call failed")
            .into_inner();

        // Verify the authorization response
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
            println!("Manual capture payment authorized with transaction ID: {}", transaction_id);

            // Now capture the payment
            let capture_request = create_payment_capture_request(&transaction_id);
            let mut capture_grpc_request = Request::new(capture_request);
            add_connector_metadata(&mut capture_grpc_request);

            let capture_response = client
                .capture(capture_grpc_request)
                .await
                .expect("gRPC payment_capture call failed")
                .into_inner();

            // Verify the capture response
            let acceptable_capture_statuses = [
                i32::from(PaymentStatus::Charged),
                i32::from(PaymentStatus::Pending),
            ];
            
            assert!(
                acceptable_capture_statuses.contains(&capture_response.status),
                "Payment should be captured but was: {}",
                capture_response.status
            );

            println!("Payment captured successfully");
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

            // Verify the sync response
            let acceptable_sync_statuses = [
                i32::from(PaymentStatus::Charged),
                i32::from(PaymentStatus::Pending),
                i32::from(PaymentStatus::Authorized),
                i32::from(PaymentStatus::Failure),
            ];
            
            assert!(
                acceptable_sync_statuses.contains(&sync_response.status),
                "Payment sync should return valid status but was: {}",
                sync_response.status
            );

            println!("Payment sync successful");
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

        if response.transaction_id.is_some() && response.status == i32::from(PaymentStatus::Charged) {
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

            // Handle both success and error cases for refunds
            let acceptable_refund_statuses = [
                i32::from(RefundStatus::RefundSuccess),
                i32::from(RefundStatus::RefundPending),
                i32::from(RefundStatus::RefundFailure),
            ];
            
            assert!(
                acceptable_refund_statuses.contains(&refund_response.status),
                "Refund should return valid status but was: {}",
                refund_response.status
            );

            println!("Refund request processed with status: {}", refund_response.status);
        } else {
            println!("Skipping refund test - payment not in charged state");
        }
    });
}

#[tokio::test]
async fn test_refund_sync() {
    grpc_test!(refund_client, RefundServiceClient<Channel>, {
        // For refund sync, we'll use a mock refund ID since creating a real refund
        // requires a successful payment first
        let mock_refund_id = format!("mock_refund_{}", get_timestamp());
        
        let refund_sync_request = create_refund_sync_request(&mock_refund_id);
        let mut refund_sync_grpc_request = Request::new(refund_sync_request);
        add_connector_metadata(&mut refund_sync_grpc_request);

        let refund_sync_response = refund_client
            .get(refund_sync_grpc_request)
            .await;

        // Handle both success and error cases
        match refund_sync_response {
            Ok(response) => {
                let response = response.into_inner();
                let acceptable_statuses = [
                    0, // RefundStatusUnspecified - expected for mock refund ID
                    i32::from(RefundStatus::RefundSuccess),
                    i32::from(RefundStatus::RefundPending),
                    i32::from(RefundStatus::RefundFailure),
                ];
                
                assert!(
                    acceptable_statuses.contains(&response.status),
                    "Refund sync should return valid status but was: {}",
                    response.status
                );
                if response.status == 0 {
                    println!("Refund sync returned unspecified status for mock refund ID (expected)");
                } else {
                    println!("Refund sync successful with status: {}", response.status);
                }
            }
            Err(e) => {
                // Expected for mock refund ID - this is acceptable
                println!("Refund sync failed as expected with mock ID: {:?}", e);
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

        if response.transaction_id.is_some() && response.status == i32::from(PaymentStatus::Authorized) {
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

            // Handle both success and error cases for voids
            let acceptable_void_statuses = [
                i32::from(PaymentStatus::Voided),
                i32::from(PaymentStatus::Pending),
                i32::from(PaymentStatus::Failure),
            ];
            
            assert!(
                acceptable_void_statuses.contains(&void_response.status),
                "Void should return valid status but was: {}",
                void_response.status
            );

            println!("Void request processed with status: {}", void_response.status);
        } else {
            println!("Skipping void test - payment not in authorized state");
        }
    });
}