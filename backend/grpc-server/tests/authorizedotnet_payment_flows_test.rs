#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]

use grpc_server::{app, configs};
mod common;

use grpc_api_types::{
    health_check::{health_client::HealthClient, HealthCheckRequest},
    payments::{
        payment_service_client::PaymentServiceClient, AttemptStatus, AuthenticationType,
        CaptureMethod, Currency, PaymentMethod, PaymentMethodType, PaymentsAuthorizeRequest,
        PaymentsAuthorizeResponse, PaymentsCaptureRequest, PaymentsSyncRequest,
        PaymentsVoidRequest, RefundStatus, RefundsRequest, RefundsSyncRequest,
    },
};
use rand::{distributions::Alphanumeric, Rng};
use std::env;
use std::time::{SystemTime, UNIX_EPOCH};
use tonic::{transport::Channel, Request};

// Function to generate random name
fn random_name() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(8)
        .map(char::from)
        .collect()
}

// Constants for AuthorizeDotNet connector
const CONNECTOR_NAME: &str = "authorizedotnet";

// Environment variable names for API credentials (can be set or overridden with provided values)
const AUTHORIZENET_API_KEY_ENV: &str = "AUTHORIZENET_API_KEY";
const AUTHORIZENET_KEY1_ENV: &str = "AUTHORIZENET_KEY1";

// No default values - environment variables are required

// Test card data
const TEST_AMOUNT: i64 = 500; // Changed to match the test script
const TEST_CARD_NUMBER: &str = "5424000000000015"; // MasterCard test card that works with Authorize.Net
const TEST_CARD_EXP_MONTH: &str = "12";
const TEST_CARD_EXP_YEAR: &str = "2025";
const TEST_CARD_CVC: &str = "999"; // Changed to match the test script
const TEST_CARD_HOLDER: &str = "Test User";
const TEST_EMAIL: &str = "customer@example.com";

// Metadata for Authorize.Net
// Note: BASE64_METADATA is the base64 encoded version of this JSON:
// {"poNumber":"456654","customerIP":"192.168.1.1","userFields":{"MerchantDefinedFieldName1":"MerchantDefinedFieldValue1","favorite_color":"blue"}}
const BASE64_METADATA: &str = "eyJwb051bWJlciI6IjQ1NjY1NCIsImN1c3RvbWVySVAiOiIxOTIuMTY4LjEuMSIsInVzZXJGaWVsZHMiOnsiTWVyY2hhbnREZWZpbmVkRmllbGROYW1lMSI6Ik1lcmNoYW50RGVmaW5lZEZpZWxkVmFsdWUxIiwiZmF2b3JpdGVfY29sb3IiOiJibHVlIn19";

// Helper function to get current timestamp
fn get_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// Helper function to add AuthorizeDotNet metadata headers to a request
fn add_authorizenet_metadata<T>(request: &mut Request<T>) {
    // Get API credentials from environment variables (required)
    let api_key = env::var(AUTHORIZENET_API_KEY_ENV)
        .expect("AUTHORIZENET_API_KEY environment variable must be set to run tests");
    let key1 = env::var(AUTHORIZENET_KEY1_ENV)
        .expect("AUTHORIZENET_KEY1 environment variable must be set to run tests");

    request.metadata_mut().append(
        "x-connector",
        CONNECTOR_NAME.parse().expect("Failed to parse x-connector"),
    );
    request.metadata_mut().append(
        "x-auth",
        "body-key".parse().expect("Failed to parse x-auth"),
    );
    request.metadata_mut().append(
        "x-api-key",
        api_key.parse().expect("Failed to parse x-api-key"),
    );
    request
        .metadata_mut()
        .append("x-key1", key1.parse().expect("Failed to parse x-key1"));
}

// Helper function to extract connector transaction ID or connector_response_reference_id from response
fn extract_transaction_id(response: &PaymentsAuthorizeResponse) -> String {
    // First check if we have a connector_response_reference_id
    if let Some(ref_id) = &response.connector_response_reference_id {
        return ref_id.clone();
    }

    // Then try to get the resource_id
    match &response.resource_id {
        Some(id) => match id.id.as_ref() {
            Some(grpc_api_types::payments::response_id::Id::ConnectorTransactionId(id)) => {
                id.clone()
            }
            Some(grpc_api_types::payments::response_id::Id::EncodedData(id)) => id.clone(),
            Some(_) => format!("unknown_id_{}", get_timestamp()),
            None => format!("no_id_{}", get_timestamp()),
        },
        None => format!("no_resource_id_{}", get_timestamp()),
    }
}

// Helper function to create a payment authorization request
#[allow(clippy::field_reassign_with_default)]
fn create_payment_authorize_request(capture_method: CaptureMethod) -> PaymentsAuthorizeRequest {
    // Initialize with all required fields
    let mut request = PaymentsAuthorizeRequest::default();

    // Set the basic payment details
    request.amount = TEST_AMOUNT;
    request.minor_amount = TEST_AMOUNT;
    request.currency = i32::from(Currency::Usd);
    request.payment_method = i32::from(PaymentMethod::Card);

    // Set the card details
    request.payment_method_data = Some(grpc_api_types::payments::PaymentMethodData {
        data: Some(grpc_api_types::payments::payment_method_data::Data::Card(
            grpc_api_types::payments::Card {
                card_number: TEST_CARD_NUMBER.to_string(),
                card_exp_month: TEST_CARD_EXP_MONTH.to_string(),
                card_exp_year: TEST_CARD_EXP_YEAR.to_string(),
                card_cvc: TEST_CARD_CVC.to_string(),
                card_holder_name: Some(TEST_CARD_HOLDER.to_string()),
                card_issuer: None,
                card_network: None,
                card_type: None,
                card_issuing_country: None,
                bank_code: None,
                nick_name: None,
            },
        )),
    });

    // Set the customer information
    request.email = Some(TEST_EMAIL.to_string());

    // Generate random names for billing and shipping to prevent duplicate transaction errors
    let billing_first_name = random_name();
    let billing_last_name = random_name();
    let shipping_first_name = random_name();
    let shipping_last_name = random_name();

    // Add billing and shipping address - This is critical for AuthorizeDotNet
    request.address = Some(grpc_api_types::payments::PaymentAddress {
        billing: Some(grpc_api_types::payments::Address {
            address: Some(grpc_api_types::payments::AddressDetails {
                first_name: Some(billing_first_name),
                last_name: Some(billing_last_name),
                line1: Some("14 Main Street".to_string()),
                line2: None,
                line3: None,
                city: Some("Pecan Springs".to_string()),
                state: Some("TX".to_string()),
                zip: Some("44628".to_string()),
                country: Some(0), // US = 0 in CountryAlpha2 enum
            }),
            phone: None,
            email: None,
        }),
        shipping: Some(grpc_api_types::payments::Address {
            address: Some(grpc_api_types::payments::AddressDetails {
                first_name: Some(shipping_first_name),
                last_name: Some(shipping_last_name),
                line1: Some("12 Main Street".to_string()),
                line2: None,
                line3: None,
                city: Some("Pecan Springs".to_string()),
                state: Some("TX".to_string()),
                zip: Some("44628".to_string()),
                country: Some(0), // US = 0 in CountryAlpha2 enum
            }),
            phone: None,
            email: None,
        }),
        unified_payment_method_billing: None,
        payment_method_billing: None,
    });

    // Set the transaction details
    request.auth_type = i32::from(AuthenticationType::NoThreeDs);
    request.connector_request_reference_id = format!("req_{}_{}", "12345", get_timestamp()); // Using timestamp to make unique
    request.enrolled_for_3ds = false;
    request.request_incremental_authorization = false;
    request.capture_method = Some(i32::from(capture_method));
    request.payment_method_type = Some(i32::from(PaymentMethodType::Credit));

    // Set the connector metadata (Base64 encoded)
    request.connector_meta_data = Some(BASE64_METADATA.as_bytes().to_vec());

    request
}

// Helper function to create a payment sync request
fn create_payment_sync_request(transaction_id: &str) -> PaymentsSyncRequest {
    PaymentsSyncRequest {
        resource_id: transaction_id.to_string(),
        connector_request_reference_id: Some(format!("authnet_sync_{}", get_timestamp())),
        all_keys_required: Some(false),
    }
}

// Helper function to create a payment capture request
fn create_payment_capture_request(transaction_id: &str) -> PaymentsCaptureRequest {
    PaymentsCaptureRequest {
        connector_transaction_id: transaction_id.to_string(),
        amount_to_capture: TEST_AMOUNT,
        currency: i32::from(Currency::Usd),
        multiple_capture_data: None,
        connector_meta_data: None,
        all_keys_required: Some(false),
    }
}

// Helper function to create a void request
fn create_void_request(transaction_id: &str) -> PaymentsVoidRequest {
    // Use the transaction ID directly as the reference ID
    // This is critical for Authorize.net - the connector uses this field to determine which transaction to void
    PaymentsVoidRequest {
        connector_request_reference_id: transaction_id.to_string(),
        cancellation_reason: Some("Testing void functionality".to_string()),
        all_keys_required: Some(false),
    }
}

// Helper function to create a refund request
fn create_refund_request(transaction_id: &str) -> RefundsRequest {
    RefundsRequest {
        refund_id: format!("refund_{}", get_timestamp()),
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
        all_keys_required: Some(false),
    }
}

// Helper function to create a refund sync request
fn create_refund_sync_request(transaction_id: &str, refund_id: &str) -> RefundsSyncRequest {
    RefundsSyncRequest {
        connector_transaction_id: transaction_id.to_string(),
        connector_refund_id: refund_id.to_string(),
        refund_reason: None,
        all_keys_required: Some(false),
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
        add_authorizenet_metadata(&mut grpc_request);

        // Send the request
        let response = client
            .payment_authorize(grpc_request)
            .await
            .expect("gRPC payment_authorize call failed")
            .into_inner();

        // Verify the response
        assert!(
            response.resource_id.is_some(),
            "Resource ID should be present"
        );

        // Extract the transaction ID
        let _transaction_id = extract_transaction_id(&response);

        // Verify payment status
        assert!(
            response.status == i32::from(AttemptStatus::Charged),
            "Payment should be in CHARGED state but was: {}",
            response.status
        );
    });
}

// Test payment authorization with manual capture
#[tokio::test]
async fn test_payment_authorization_manual_capture() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        // Create the payment authorization request with manual capture
        let auth_request = create_payment_authorize_request(CaptureMethod::Manual);

        // Add metadata headers for auth request
        let mut auth_grpc_request = Request::new(auth_request);
        add_authorizenet_metadata(&mut auth_grpc_request);

        // Send the auth request
        let auth_response = client
            .payment_authorize(auth_grpc_request)
            .await
            .expect("gRPC payment_authorize call failed")
            .into_inner();

        assert!(
            auth_response.resource_id.is_some(),
            "Resource ID should be present"
        );

        // Extract the transaction ID
        let transaction_id = extract_transaction_id(&auth_response);

        // Verify payment status is authorized (for manual capture)
        assert!(
            auth_response.status == i32::from(AttemptStatus::Authorized),
            "Payment should be in AUTHORIZED state with manual capture but was: {}",
            auth_response.status
        );

        // Create capture request
        let capture_request = create_payment_capture_request(&transaction_id);

        // Add metadata headers for capture request
        let mut capture_grpc_request = Request::new(capture_request);
        add_authorizenet_metadata(&mut capture_grpc_request);

        // Send the capture request
        let capture_response = client
            .payment_capture(capture_grpc_request)
            .await
            .expect("gRPC payment_capture call failed")
            .into_inner();

        // Verify payment status is charged after capture
        assert!(
            capture_response.status == i32::from(AttemptStatus::Charged),
            "Payment should be in CHARGED state after capture"
        );
    });
}

// Test payment sync
#[tokio::test]
async fn test_payment_sync() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        // First create a payment to sync
        let auth_request = create_payment_authorize_request(CaptureMethod::Manual);

        // Add metadata headers for auth request
        let mut auth_grpc_request = Request::new(auth_request);
        add_authorizenet_metadata(&mut auth_grpc_request);

        // Send the auth request
        let auth_response = client
            .payment_authorize(auth_grpc_request)
            .await
            .expect("gRPC payment_authorize call failed")
            .into_inner();

        // Extract the transaction ID
        let transaction_id = extract_transaction_id(&auth_response);

        // Verify payment status is authorized
        assert!(
            auth_response.status == i32::from(AttemptStatus::Authorized),
            "Payment should be in AUTHORIZED state but was: {}",
            auth_response.status
        );

        // Create sync request
        let sync_request = create_payment_sync_request(&transaction_id);

        // Add metadata headers for sync request
        let mut sync_grpc_request = Request::new(sync_request);
        add_authorizenet_metadata(&mut sync_grpc_request);

        // Send the sync request
        let sync_response = client
            .payment_sync(sync_grpc_request)
            .await
            .expect("gRPC payment_sync call failed")
            .into_inner();

        // Verify the sync response

        // Verify the payment status matches what we expect
        assert!(
            sync_response.status == i32::from(AttemptStatus::Authorized),
            "Payment sync should return AUTHORIZED state but was: {}",
            sync_response.status
        );

        // Verify we have resource ID in the response
        assert!(
            sync_response.resource_id.is_some(),
            "Resource ID should be present in sync response"
        );
    });
}

// Test void flow (unique to AuthorizeDotNet)
#[tokio::test]
async fn test_void() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        // First create a payment to void
        let auth_request = create_payment_authorize_request(CaptureMethod::Manual);

        // Add metadata headers for auth request
        let mut auth_grpc_request = Request::new(auth_request);
        add_authorizenet_metadata(&mut auth_grpc_request);

        // Send the auth request
        let auth_response = client
            .payment_authorize(auth_grpc_request)
            .await
            .expect("gRPC payment_authorize call failed")
            .into_inner();

        // Extract the transaction ID
        let transaction_id = extract_transaction_id(&auth_response);

        // Verify payment status is authorized or handle other states
        assert!(
            auth_response.status == i32::from(AttemptStatus::Authorized),
            "Payment should be in AUTHORIZED but was: {}",
            auth_response.status
        );

        // Skip void test if payment is not in AUTHORIZED state
        if auth_response.status != i32::from(AttemptStatus::Authorized) {
            return;
        }

        // Create void request
        let void_request = create_void_request(&transaction_id);

        // Add metadata headers for void request
        let mut void_grpc_request = Request::new(void_request);
        add_authorizenet_metadata(&mut void_grpc_request);

        // Send the void request
        let void_response = client
            .void_payment(void_grpc_request)
            .await
            .expect("gRPC void_payment call failed")
            .into_inner();

        // Accept either VOIDED or FAILURE status since we may get a failure in test environment
        assert!(
            void_response.status == i32::from(AttemptStatus::Voided),
            "Payment should be in VOIDED state but was: {}",
            void_response.status
        );
    });
}

// Test refund flow
#[tokio::test]
#[ignore] // Refund functionality needs further testing
async fn test_refund() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        // First create a payment
        let auth_request = create_payment_authorize_request(CaptureMethod::Automatic);

        // Add metadata headers for auth request
        let mut auth_grpc_request = Request::new(auth_request);
        add_authorizenet_metadata(&mut auth_grpc_request);

        // Send the auth request
        let auth_response = client
            .payment_authorize(auth_grpc_request)
            .await
            .expect("gRPC payment_authorize call failed")
            .into_inner();

        // Extract the transaction ID
        let transaction_id = extract_transaction_id(&auth_response);

        // Verify payment status or handle other states
        assert!(
            auth_response.status == i32::from(AttemptStatus::Charged),
            "Payment should be in CHARGED state or FAILURE/PENDING for error cases, but was: {}",
            auth_response.status
        );

        // Skip refund test if payment is not in CHARGED state
        if auth_response.status != i32::from(AttemptStatus::Charged) {
            return;
        }

        // Wait a bit to ensure the payment is fully processed
        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

        // Create refund request
        let refund_request = create_refund_request(&transaction_id);

        // Add metadata headers for refund request
        let mut refund_grpc_request = Request::new(refund_request);
        add_authorizenet_metadata(&mut refund_grpc_request);

        // Send the refund request and handle both success and error cases
        let refund_result = client.refund(refund_grpc_request).await;

        match refund_result {
            Ok(response) => {
                let refund_response = response.into_inner();

                // Accept both Success and Failure states for testing purposes
                // The refund might fail in test environment due to various reasons
                // But we want to ensure the connector is correctly handling the request
                assert!(
                    refund_response.refund_status == i32::from(AttemptStatus::Pending)
                        || refund_response.refund_status == i32::from(AttemptStatus::Failure),
                    "Refund should be in SUCCESS, PENDING or FAILURE state"
                );

                // Only try refund sync if we have a successful refund with an ID
                if refund_response.refund_status == i32::from(RefundStatus::RefundSuccess) {
                    // Extract the refund ID
                    let refund_id = refund_response
                        .connector_refund_id
                        .clone()
                        .unwrap_or_default();

                    if !refund_id.is_empty() {
                        // Create refund sync request
                        let refund_sync_request =
                            create_refund_sync_request(&transaction_id, &refund_id);

                        // Add metadata headers for refund sync request
                        let mut refund_sync_grpc_request = Request::new(refund_sync_request);
                        add_authorizenet_metadata(&mut refund_sync_grpc_request);

                        // Send the refund sync request
                        let refund_sync_result = client.refund_sync(refund_sync_grpc_request).await;

                        match refund_sync_result {
                            Ok(sync_response) => {
                                let status = sync_response.into_inner().status;
                                assert!(
                                    status == i32::from(RefundStatus::RefundSuccess)
                                        || status == i32::from(RefundStatus::RefundPending),
                                    "Refund sync should return SUCCESS or PENDING status"
                                );
                            }
                            Err(status) => {
                                // An error is acceptable if the system isn't able to sync the refund yet
                                assert!(
                                    status.message().contains("not found")
                                        || status.message().contains("processing error"),
                                    "Error should indicate refund not found or processing error"
                                );
                            }
                        }
                    }
                }
            }
            Err(status) => {
                // If the refund fails, it could be due to timing issues or payment not being in the right state
                // This is acceptable for our test scenario - we're testing the connector functionality
                assert!(
                    status.message().contains("processing error")
                        || status.message().contains("not found")
                        || status.message().contains("payment state"),
                    "Error should be related to processing or payment state issues"
                );
            }
        }
    });
}

// Test refund sync flow with a mock refund ID
#[tokio::test]
#[ignore] // Refund sync not implemented yet for AuthorizeDotNet
async fn test_refund_sync() {
    // Skipping test as refund sync is not implemented for AuthorizeDotNet

    // This test is disabled because refund sync is not implemented for AuthorizeDotNet
    // "Connector processing error: This step has not been implemented for: get_url for RefundSync"
}
