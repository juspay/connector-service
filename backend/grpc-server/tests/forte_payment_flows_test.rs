use std::env;

use grpc_api_types::{
    payments::{
        PaymentsCaptureRequest, PaymentsRequest, PaymentsSyncRequest, PaymentVoidRequest,
    },
    refunds::{RefundsRequest, RefundsSyncRequest},
};
use tonic::{metadata::MetadataValue, Request};

mod common;
use common::*;

// Constants specific to the Forte connector
const CONNECTOR_NAME: &str = "forte";

// Authentication related constants
const AUTH_TYPE: &str = "multi-auth-key";

// Environment variable names for API credentials
const FORTE_ORGANIZATION_ID_ENV: &str = "TEST_FORTE_ORGANIZATION_ID";
const FORTE_LOCATION_ID_ENV: &str = "TEST_FORTE_LOCATION_ID";
const FORTE_API_ACCESS_ID_ENV: &str = "TEST_FORTE_API_ACCESS_ID";
const FORTE_SECURE_KEY_ENV: &str = "TEST_FORTE_SECURE_KEY";

// Test data constants
const TEST_CARD_NUMBER: &str = "4111111111111111";
const TEST_CARD_EXP_MONTH: &str = "12";
const TEST_CARD_EXP_YEAR: &str = "2025";
const TEST_CARD_CVV: &str = "123";
const TEST_AMOUNT: i64 = 1000; // $10.00 in cents

// Helper function to generate timestamp
fn generate_timestamp() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string()
}

// Helper function to add connector metadata headers to a request
fn add_connector_metadata<T>(request: &mut Request<T>) {
    // Add connector header
    request.metadata_mut().insert(
        "connector",
        MetadataValue::from_str(CONNECTOR_NAME).unwrap(),
    );

    // Add auth type header
    request.metadata_mut().insert(
        "auth-type",
        MetadataValue::from_str(AUTH_TYPE).unwrap(),
    );

    // Add authentication headers for MultiAuthKey
    if let Ok(org_id) = env::var(FORTE_ORGANIZATION_ID_ENV) {
        request.metadata_mut().insert(
            "api-key",
            MetadataValue::from_str(&org_id).unwrap(),
        );
    } else {
        request.metadata_mut().insert(
            "api-key",
            MetadataValue::from_str("test_org_id").unwrap(),
        );
    }

    if let Ok(location_id) = env::var(FORTE_LOCATION_ID_ENV) {
        request.metadata_mut().insert(
            "key1",
            MetadataValue::from_str(&location_id).unwrap(),
        );
    } else {
        request.metadata_mut().insert(
            "key1",
            MetadataValue::from_str("test_location_id").unwrap(),
        );
    }

    if let Ok(api_access_id) = env::var(FORTE_API_ACCESS_ID_ENV) {
        request.metadata_mut().insert(
            "api-secret",
            MetadataValue::from_str(&api_access_id).unwrap(),
        );
    } else {
        request.metadata_mut().insert(
            "api-secret",
            MetadataValue::from_str("test_api_access_id").unwrap(),
        );
    }

    if let Ok(secure_key) = env::var(FORTE_SECURE_KEY_ENV) {
        request.metadata_mut().insert(
            "key2",
            MetadataValue::from_str(&secure_key).unwrap(),
        );
    } else {
        request.metadata_mut().insert(
            "key2",
            MetadataValue::from_str("test_secure_key").unwrap(),
        );
    }
}

// Helper function to extract transaction ID from payment response
fn extract_transaction_id(response: &grpc_api_types::payments::PaymentsResponse) -> String {
    response.connector_transaction_id.clone().unwrap_or_else(|| {
        response.payment_id.clone().unwrap_or_else(|| {
            panic!("No transaction ID found in response")
        })
    })
}

// Helper function to extract refund ID from refund response
fn extract_refund_id(response: &grpc_api_types::refunds::RefundsResponse) -> String {
    response.connector_refund_id.clone().unwrap_or_else(|| {
        response.refund_id.clone().unwrap_or_else(|| {
            panic!("No refund ID found in response")
        })
    })
}

// Request creation functions
fn create_payment_request_auto_capture() -> PaymentsRequest {
    PaymentsRequest {
        payment_id: Some(format!("test_payment_{}", generate_timestamp())),
        merchant_id: Some("test_merchant".to_string()),
        amount: Some(TEST_AMOUNT),
        currency: Some("USD".to_string()),
        capture_method: Some(grpc_api_types::payments::CaptureMethod::Automatic as i32),
        payment_method: Some(grpc_api_types::payments::PaymentMethodData {
            payment_method: Some(grpc_api_types::payments::payment_method_data::PaymentMethod::Card(
                grpc_api_types::payments::Card {
                    card_number: Some(TEST_CARD_NUMBER.to_string()),
                    card_exp_month: Some(TEST_CARD_EXP_MONTH.to_string()),
                    card_exp_year: Some(TEST_CARD_EXP_YEAR.to_string()),
                    card_holder_name: Some("John Doe".to_string()),
                    card_cvc: Some(TEST_CARD_CVV.to_string()),
                    ..Default::default()
                }
            )),
        }),
        billing: Some(grpc_api_types::payments::Address {
            first_name: Some("John".to_string()),
            last_name: Some("Doe".to_string()),
            line1: Some("123 Main St".to_string()),
            city: Some("New York".to_string()),
            state: Some("NY".to_string()),
            zip: Some("10001".to_string()),
            country: Some("US".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn create_payment_request_manual_capture() -> PaymentsRequest {
    let mut request = create_payment_request_auto_capture();
    request.capture_method = Some(grpc_api_types::payments::CaptureMethod::Manual as i32);
    request.payment_id = Some(format!("test_payment_manual_{}", generate_timestamp()));
    request
}

fn create_payment_sync_request(transaction_id: &str) -> PaymentsSyncRequest {
    PaymentsSyncRequest {
        payment_id: Some(transaction_id.to_string()),
        merchant_id: Some("test_merchant".to_string()),
        connector_transaction_id: Some(transaction_id.to_string()),
        ..Default::default()
    }
}

fn create_payment_capture_request(transaction_id: &str) -> PaymentsCaptureRequest {
    PaymentsCaptureRequest {
        payment_id: Some(transaction_id.to_string()),
        merchant_id: Some("test_merchant".to_string()),
        amount_to_capture: Some(TEST_AMOUNT),
        ..Default::default()
    }
}

fn create_refund_request(transaction_id: &str) -> RefundsRequest {
    RefundsRequest {
        payment_id: Some(transaction_id.to_string()),
        refund_id: Some(format!("test_refund_{}", generate_timestamp())),
        merchant_id: Some("test_merchant".to_string()),
        amount: Some(TEST_AMOUNT / 2), // Partial refund
        reason: Some("Customer request".to_string()),
        ..Default::default()
    }
}

fn create_refund_sync_request(transaction_id: &str, refund_id: &str) -> RefundsSyncRequest {
    RefundsSyncRequest {
        refund_id: Some(refund_id.to_string()),
        payment_id: Some(transaction_id.to_string()),
        merchant_id: Some("test_merchant".to_string()),
        connector_refund_id: Some(refund_id.to_string()),
        ..Default::default()
    }
}

fn create_payment_void_request(transaction_id: &str) -> PaymentVoidRequest {
    PaymentVoidRequest {
        payment_id: Some(transaction_id.to_string()),
        merchant_id: Some("test_merchant".to_string()),
        cancellation_reason: Some("Customer request".to_string()),
        ..Default::default()
    }
}

// Test implementations
#[tokio::test]
async fn test_health() {
    let mut client = get_client().await;
    let request = tonic::Request::new(grpc_api_types::health::HealthCheckRequest {
        service: "payments".to_string(),
    });

    let response = client.check(request).await;
    assert!(response.is_ok(), "Health check failed: {:?}", response.err());
}

#[tokio::test]
async fn test_payment_authorization_auto_capture() {
    let mut client = get_payments_client().await;
    let payment_request = create_payment_request_auto_capture();
    let mut request = Request::new(payment_request);
    add_connector_metadata(&mut request);

    let response = client.payments_create(request).await;
    assert!(response.is_ok(), "Payment authorization failed: {:?}", response.err());

    let payment_response = response.unwrap().into_inner();
    println!("Payment Response: {:?}", payment_response);
    
    // Verify payment was successful
    assert!(payment_response.status.is_some());
    assert!(payment_response.payment_id.is_some());
}

#[tokio::test]
async fn test_payment_authorization_manual_capture() {
    let mut client = get_payments_client().await;
    let payment_request = create_payment_request_manual_capture();
    let mut request = Request::new(payment_request);
    add_connector_metadata(&mut request);

    let response = client.payments_create(request).await;
    assert!(response.is_ok(), "Payment authorization failed: {:?}", response.err());

    let payment_response = response.unwrap().into_inner();
    println!("Payment Response: {:?}", payment_response);
    
    // Verify payment was authorized (not captured yet)
    assert!(payment_response.status.is_some());
    assert!(payment_response.payment_id.is_some());
    
    let transaction_id = extract_transaction_id(&payment_response);
    
    // Now test capture
    let capture_request = create_payment_capture_request(&transaction_id);
    let mut capture_req = Request::new(capture_request);
    add_connector_metadata(&mut capture_req);

    let capture_response = client.payments_capture(capture_req).await;
    assert!(capture_response.is_ok(), "Payment capture failed: {:?}", capture_response.err());
    
    let capture_result = capture_response.unwrap().into_inner();
    println!("Capture Response: {:?}", capture_result);
}

#[tokio::test]
async fn test_payment_sync() {
    // First create a payment
    let mut client = get_payments_client().await;
    let payment_request = create_payment_request_auto_capture();
    let mut request = Request::new(payment_request);
    add_connector_metadata(&mut request);

    let response = client.payments_create(request).await;
    assert!(response.is_ok(), "Payment creation failed: {:?}", response.err());

    let payment_response = response.unwrap().into_inner();
    let transaction_id = extract_transaction_id(&payment_response);

    // Now test sync
    let sync_request = create_payment_sync_request(&transaction_id);
    let mut sync_req = Request::new(sync_request);
    add_connector_metadata(&mut sync_req);

    let sync_response = client.payments_retrieve(sync_req).await;
    assert!(sync_response.is_ok(), "Payment sync failed: {:?}", sync_response.err());
    
    let sync_result = sync_response.unwrap().into_inner();
    println!("Sync Response: {:?}", sync_result);
}

#[tokio::test]
async fn test_refund() {
    // First create a payment
    let mut client = get_payments_client().await;
    let payment_request = create_payment_request_auto_capture();
    let mut request = Request::new(payment_request);
    add_connector_metadata(&mut request);

    let response = client.payments_create(request).await;
    assert!(response.is_ok(), "Payment creation failed: {:?}", response.err());

    let payment_response = response.unwrap().into_inner();
    let transaction_id = extract_transaction_id(&payment_response);

    // Now test refund
    let mut refunds_client = get_refunds_client().await;
    let refund_request = create_refund_request(&transaction_id);
    let mut refund_req = Request::new(refund_request);
    add_connector_metadata(&mut refund_req);

    let refund_response = refunds_client.refunds_create(refund_req).await;
    assert!(refund_response.is_ok(), "Refund failed: {:?}", refund_response.err());
    
    let refund_result = refund_response.unwrap().into_inner();
    println!("Refund Response: {:?}", refund_result);
}

#[tokio::test]
async fn test_refund_sync() {
    // First create a payment
    let mut client = get_payments_client().await;
    let payment_request = create_payment_request_auto_capture();
    let mut request = Request::new(payment_request);
    add_connector_metadata(&mut request);

    let response = client.payments_create(request).await;
    assert!(response.is_ok(), "Payment creation failed: {:?}", response.err());

    let payment_response = response.unwrap().into_inner();
    let transaction_id = extract_transaction_id(&payment_response);

    // Create a refund
    let mut refunds_client = get_refunds_client().await;
    let refund_request = create_refund_request(&transaction_id);
    let mut refund_req = Request::new(refund_request);
    add_connector_metadata(&mut refund_req);

    let refund_response = refunds_client.refunds_create(refund_req).await;
    assert!(refund_response.is_ok(), "Refund creation failed: {:?}", refund_response.err());
    
    let refund_result = refund_response.unwrap().into_inner();
    let refund_id = extract_refund_id(&refund_result);

    // Now test refund sync
    let refund_sync_request = create_refund_sync_request(&transaction_id, &refund_id);
    let mut refund_sync_req = Request::new(refund_sync_request);
    add_connector_metadata(&mut refund_sync_req);

    let refund_sync_response = refunds_client.refunds_retrieve(refund_sync_req).await;
    assert!(refund_sync_response.is_ok(), "Refund sync failed: {:?}", refund_sync_response.err());
    
    let refund_sync_result = refund_sync_response.unwrap().into_inner();
    println!("Refund Sync Response: {:?}", refund_sync_result);
}

#[tokio::test]
async fn test_payment_void() {
    // First create a payment with manual capture (so it can be voided)
    let mut client = get_payments_client().await;
    let payment_request = create_payment_request_manual_capture();
    let mut request = Request::new(payment_request);
    add_connector_metadata(&mut request);

    let response = client.payments_create(request).await;
    assert!(response.is_ok(), "Payment creation failed: {:?}", response.err());

    let payment_response = response.unwrap().into_inner();
    let transaction_id = extract_transaction_id(&payment_response);

    // Now test void
    let void_request = create_payment_void_request(&transaction_id);
    let mut void_req = Request::new(void_request);
    add_connector_metadata(&mut void_req);

    let void_response = client.payments_cancel(void_req).await;
    assert!(void_response.is_ok(), "Payment void failed: {:?}", void_response.err());
    
    let void_result = void_response.unwrap().into_inner();
    println!("Void Response: {:?}", void_result);
}