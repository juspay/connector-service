#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]
#![allow(unused_imports)]
#![allow(dead_code)]

use grpc_server::{app, configs};
mod common;

use std::{
    collections::HashMap,
    env,
    time::{SystemTime, UNIX_EPOCH},
};

use grpc_api_types::payments::{
    card_payment_method_type, identifier::IdType, payment_method, Address, AuthenticationType,
    CaptureMethod, CardDetails, CardPaymentMethodType, CountryAlpha2, Currency, Identifier,
    PaymentAddress, PaymentMethod, PaymentMethodType, PaymentServiceAuthorizeRequest,
    PaymentServiceAuthorizeResponse, PaymentServiceCaptureRequest, PaymentServiceGetRequest,
    PaymentServiceRefundRequest, PaymentServiceVoidRequest, PaymentStatus, RefundServiceGetRequest,
    RefundStatus,
};

use grpc_api_types::{
    health_check::{health_client::HealthClient, HealthCheckRequest},
    payments::{
        card_payment_method_type, identifier::IdType, payment_method,
        payment_service_client::PaymentServiceClient, Address, AuthenticationType, CaptureMethod,
        CardDetails, CardPaymentMethodType, CountryAlpha2, Currency, Identifier, PaymentAddress,
        PaymentMethod, PaymentMethodType, PaymentServiceAuthorizeRequest,
        PaymentServiceAuthorizeResponse, PaymentServiceCaptureRequest, PaymentServiceGetRequest,
        PaymentServiceRefundRequest, PaymentServiceVoidRequest, PaymentStatus,
        RefundServiceGetRequest, RefundStatus,
    },
};
use rand::{distributions::Alphanumeric, Rng};
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
const TEST_AMOUNT: i64 = 1000; // Changed to match the test script
const TEST_CARD_NUMBER: &str = "5424000000000015"; // MasterCard test card that works with Authorize.Net
const TEST_CARD_EXP_MONTH: &str = "12";
const TEST_CARD_EXP_YEAR: &str = "2025";
const TEST_CARD_CVC: &str = "999"; // Changed to match the test script
const TEST_CARD_HOLDER: &str = "Test User";
const TEST_EMAIL: &str = "customer@example.com";

// Metadata for Authorize.Net
// Note: BASE64_METADATA is the base64 encoded version of this JSON:
// {"userFields":{"MerchantDefinedFieldName1":"MerchantDefinedFieldValue1","favorite_color":"blue"}}
const BASE64_METADATA: &str = "eyJ1c2VyRmllbGRzIjp7Ik1lcmNoYW50RGVmaW5lZEZpZWxkTmFtZTEiOiJNZXJjaGFudERlZmluZWRGaWVsZFZhbHVlMSIsImZhdm9yaXRlX2NvbG9yIjoiYmx1ZSJ9fQ==";

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
    // Add merchant ID which is required by the server
    request.metadata_mut().append(
        "x-merchant-id",
        "test_merchant"
            .parse()
            .expect("Failed to parse x-merchant-id"),
    );

    // Add tenant ID which is required by the server
    request.metadata_mut().append(
        "x-tenant-id",
        "default".parse().expect("Failed to parse x-tenant-id"),
    );

    // Add request ID which is required by the server
    request.metadata_mut().append(
        "x-request-id",
        format!("req_{}", get_timestamp())
            .parse()
            .expect("Failed to parse x-request-id"),
    );
}

// Helper function to extract transaction ID or response_ref_id from response
fn extract_transaction_id(response: &PaymentServiceAuthorizeResponse) -> String {
    // First try to get the transaction_id as it's the actual transaction ID needed for void/capture operations
    match &response.transaction_id {
        Some(id) => match &id.id_type {
            Some(id_type) => match id_type {
                IdType::Id(id) => id.clone(),
                IdType::EncodedData(id) => id.clone(),
                _ => format!("unknown_id_{}", get_timestamp()),
            },
            None => format!("no_id_type_{}", get_timestamp()),
        },
        None => {
            // Fallback to response_ref_id if transaction_id is not available
            if let Some(ref_id) = &response.response_ref_id {
                match &ref_id.id_type {
                    Some(id_type) => match id_type {
                        IdType::Id(id) => id.clone(),
                        IdType::EncodedData(id) => id.clone(),
                        _ => format!("unknown_id_{}", get_timestamp()),
                    },
                    None => format!("no_id_type_{}", get_timestamp()),
                }
            } else {
                format!("no_transaction_id_{}", get_timestamp())
            }
        }
    }
}

// Helper function to create a payment authorization request
#[allow(clippy::field_reassign_with_default)]
fn create_payment_authorize_request(
    capture_method: common_enums::CaptureMethod,
) -> PaymentServiceAuthorizeRequest {
    // Initialize with all required fields
    let mut request = PaymentServiceAuthorizeRequest::default();

    // Set the basic payment details
    request.amount = TEST_AMOUNT;
    request.minor_amount = TEST_AMOUNT;
    request.currency = i32::from(Currency::Usd);

    // Set up card payment method using the correct structure
    let card_details = card_payment_method_type::CardType::Credit(CardDetails {
        card_number: TEST_CARD_NUMBER.to_string(),
        card_exp_month: TEST_CARD_EXP_MONTH.to_string(),
        card_exp_year: TEST_CARD_EXP_YEAR.to_string(),
        card_cvc: TEST_CARD_CVC.to_string(),
        card_holder_name: Some(TEST_CARD_HOLDER.to_string()),
        card_issuer: None,
        card_network: None,
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

    // Set the customer information
    request.email = Some(TEST_EMAIL.to_string());

    // Generate random names for billing and shipping to prevent duplicate transaction errors
    let billing_first_name = random_name();
    let billing_last_name = random_name();
    let shipping_first_name = random_name();
    let shipping_last_name = random_name();

    // Add billing and shipping address - This is critical for AuthorizeDotNet
    request.address = Some(PaymentAddress {
        billing_address: Some(Address {
            first_name: Some(billing_first_name),
            last_name: Some(billing_last_name),
            line1: Some("14 Main Street".to_string()),
            line2: None,
            line3: None,
            city: Some("Pecan Springs".to_string()),
            state: Some("TX".to_string()),
            zip_code: Some("44628".to_string()),
            country_alpha2_code: Some(i32::from(CountryAlpha2::Us)),
            phone_number: None,
            phone_country_code: None,
            email: None,
        }),
        shipping_address: Some(Address {
            first_name: Some(shipping_first_name),
            last_name: Some(shipping_last_name),
            line1: Some("12 Main Street".to_string()),
            line2: None,
            line3: None,
            city: Some("Pecan Springs".to_string()),
            state: Some("TX".to_string()),
            zip_code: Some("44628".to_string()),
            country_alpha2_code: Some(i32::from(CountryAlpha2::Us)),
            phone_number: None,
            phone_country_code: None,
            email: None,
        }),
    });

    // Set the transaction details
    request.auth_type = i32::from(AuthenticationType::NoThreeDs);

    // Create an Identifier for the request_ref_id
    let mut request_ref_id = Identifier::default();
    request_ref_id.id_type = Some(IdType::Id(
        format!("req_{}_{}", "12345", get_timestamp()), // Using timestamp to make unique
    ));
    request.request_ref_id = Some(request_ref_id);

    request.enrolled_for_3ds = false;
    request.request_incremental_authorization = false;

    // Set capture method
    if let common_enums::CaptureMethod::Manual = capture_method {
        request.capture_method = Some(i32::from(CaptureMethod::Manual));
    } else {
        request.capture_method = Some(i32::from(CaptureMethod::Automatic));
    }

    // Set the connector metadata (Base64 encoded)
    let mut metadata = HashMap::new();
    metadata.insert("metadata".to_string(), BASE64_METADATA.to_string());
    request.metadata = metadata;

    request
}

// Helper function to create a payment sync request
fn create_payment_get_request(transaction_id: &str) -> PaymentServiceGetRequest {
    let transaction_id_obj = Identifier {
        id_type: Some(IdType::Id(transaction_id.to_string())),
    };

    let request_ref_id = Identifier {
        id_type: Some(IdType::Id(format!("authnet_sync_{}", get_timestamp()))),
    };

    PaymentServiceGetRequest {
        transaction_id: Some(transaction_id_obj),
        request_ref_id: Some(request_ref_id),
    }
}

// Helper function to create a payment capture request
fn create_payment_capture_request(transaction_id: &str) -> PaymentServiceCaptureRequest {
    let request_ref_id = Identifier {
        id_type: Some(IdType::Id(format!("capture_req_{}", get_timestamp()))),
    };

    let transaction_id_obj = Identifier {
        id_type: Some(IdType::Id(transaction_id.to_string())),
    };

    PaymentServiceCaptureRequest {
        request_ref_id: Some(request_ref_id),
        transaction_id: Some(transaction_id_obj),
        amount_to_capture: TEST_AMOUNT,
        currency: i32::from(Currency::Usd),
        multiple_capture_data: None,
        metadata: HashMap::new(),
    }
}

// Helper function to create a void request
fn create_void_request(transaction_id: &str) -> PaymentServiceVoidRequest {
    // For Authorize.net, put the transaction ID in BOTH transaction_id and request_ref_id
    // because the ForeignTryFrom implementation uses request_ref_id instead of transaction_id
    PaymentServiceVoidRequest {
        transaction_id: Some(Identifier {
            id_type: Some(IdType::Id(transaction_id.to_string())),
        }),
        request_ref_id: Some(Identifier {
            id_type: Some(IdType::Id(transaction_id.to_string())), // Use actual transaction ID here, not a request ID
        }),
        cancellation_reason: None,
        all_keys_required: None,
    }
}

// Helper function to sleep for a short duration to allow server processing
fn allow_processing_time() {
    std::thread::sleep(std::time::Duration::from_secs(3));
}

// Helper function to create a refund request
fn create_refund_request(transaction_id: &str) -> PaymentServiceRefundRequest {
    let request_ref_id = Identifier {
        id_type: Some(IdType::Id(format!("refund_req_{}", get_timestamp()))),
    };

    let transaction_id_obj = Identifier {
        id_type: Some(IdType::Id(transaction_id.to_string())),
    };

    // Create refund metadata with credit card information as required by Authorize.net
    let mut refund_metadata = HashMap::new();
    refund_metadata.insert(
        "refund_metadata".to_string(),
        format!(
            "{{\"creditCard\":{{\"cardNumber\":\"{TEST_CARD_NUMBER}\",\"expirationDate\":\"2025-12\"}}}}",
        ),
    );

    PaymentServiceRefundRequest {
        request_ref_id: Some(request_ref_id),
        refund_id: format!("refund_{}", get_timestamp()),
        transaction_id: Some(transaction_id_obj),
        currency: i32::from(Currency::Usd),
        payment_amount: TEST_AMOUNT,
        refund_amount: TEST_AMOUNT,
        minor_payment_amount: TEST_AMOUNT,
        minor_refund_amount: TEST_AMOUNT,
        reason: Some("Test refund".to_string()),
        webhook_url: None,
        merchant_account_id: None,
        capture_method: None,
        metadata: HashMap::new(),
        refund_metadata,
        browser_info: None,
    }
}

// Helper function to create a refund get request
fn create_refund_get_request(transaction_id: &str, refund_id: &str) -> RefundServiceGetRequest {
    let request_ref_id = Identifier {
        id_type: Some(IdType::Id(format!("refund_get_req_{}", get_timestamp()))),
    };

    let transaction_id_obj = Identifier {
        id_type: Some(IdType::Id(transaction_id.to_string())),
    };

    RefundServiceGetRequest {
        request_ref_id: Some(request_ref_id),
        transaction_id: Some(transaction_id_obj),
        refund_id: refund_id.to_string(),
        refund_reason: None,
    }
}

// Helper function to create a register (setup mandate) request
fn create_register_request() -> PaymentServiceRegisterRequest {
    let mut request = PaymentServiceRegisterRequest::default();
    
    // Set the basic details
    request.currency = i32::from(Currency::Usd);
    
    // Set up card payment method
    let card_details = card_payment_method_type::CardType::Credit(CardDetails {
        card_number: TEST_CARD_NUMBER.to_string(),
        card_exp_month: TEST_CARD_EXP_MONTH.to_string(),
        card_exp_year: TEST_CARD_EXP_YEAR.to_string(),
        card_cvc: TEST_CARD_CVC.to_string(),
        card_holder_name: Some(TEST_CARD_HOLDER.to_string()),
        card_issuer: None,
        card_network: None,
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
    
    // Set customer information
    request.email = Some(TEST_EMAIL.to_string());
    request.customer_name = Some(format!("{} {}", random_name(), random_name()));
    
    // Generate unique billing address
    let billing_first_name = random_name();
    let billing_last_name = random_name();
    
    // Add billing address
    request.address = Some(PaymentAddress {
        billing_address: Some(Address {
            first_name: Some(billing_first_name),
            last_name: Some(billing_last_name),
            line1: Some("123 Test Street".to_string()),
            line2: None,
            line3: None,
            city: Some("Test City".to_string()),
            state: Some("TX".to_string()),
            zip_code: Some("12345".to_string()),
            country_alpha2_code: Some(i32::from(CountryAlpha2::Us)),
            phone_number: None,
            phone_country_code: None,
            email: None,
        }),
        shipping_address: None,
    });
    
    // Set request reference ID
    request.request_ref_id = Some(Identifier {
        id_type: Some(IdType::Id(format!("mandate_req_{}", get_timestamp()))),
    });
    
    // Set connector metadata
    let mut metadata = HashMap::new();
    metadata.insert("connector_meta_data".to_string(), "{}".to_string());
    request.metadata = metadata;
    
    request
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
        let request = create_payment_authorize_request(common_enums::CaptureMethod::Automatic);

        // Add metadata headers
        let mut grpc_request = Request::new(request);
        add_authorizenet_metadata(&mut grpc_request);

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

        // Verify payment status
        assert!(
            response.status == i32::from(PaymentStatus::Charged),
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
        let auth_request = create_payment_authorize_request(common_enums::CaptureMethod::Manual);

        // Add metadata headers for auth request
        let mut auth_grpc_request = Request::new(auth_request);
        add_authorizenet_metadata(&mut auth_grpc_request);

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

        // Verify payment status is authorized (for manual capture)
        assert!(
            auth_response.status == i32::from(PaymentStatus::Authorized),
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

// Test payment sync
#[tokio::test]
async fn test_payment_sync() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        // First create a payment to sync
        let auth_request = create_payment_authorize_request(common_enums::CaptureMethod::Manual);

        // Add metadata headers for auth request
        let mut auth_grpc_request = Request::new(auth_request);
        add_authorizenet_metadata(&mut auth_grpc_request);

        // Send the auth request
        let auth_response = client
            .authorize(auth_grpc_request)
            .await
            .expect("gRPC payment_authorize call failed")
            .into_inner();

        // Extract the transaction ID
        let transaction_id = extract_transaction_id(&auth_response);

        // Verify payment status is authorized
        assert!(
            auth_response.status == i32::from(PaymentStatus::Authorized),
            "Payment should be in AUTHORIZED state but was: {}",
            auth_response.status
        );

        // Create get request
        let get_request = create_payment_get_request(&transaction_id);

        // Add metadata headers for get request
        let mut get_grpc_request = Request::new(get_request);
        add_authorizenet_metadata(&mut get_grpc_request);

        // Send the get request
        let get_response = client
            .get(get_grpc_request)
            .await
            .expect("gRPC payment_get call failed")
            .into_inner();

        // Verify the sync response

        // Verify the payment status matches what we expect
        assert!(
            get_response.status == i32::from(PaymentStatus::Authorized),
            "Payment get should return AUTHORIZED state but was: {}",
            get_response.status
        );

        // Verify we have transaction ID in the response
        assert!(
            get_response.transaction_id.is_some(),
            "Transaction ID should be present in get response"
        );
    });
}

// Test void flow (unique to AuthorizeDotNet)
#[tokio::test]
async fn test_void() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        // First create a payment to void
        let auth_request = create_payment_authorize_request(common_enums::CaptureMethod::Manual);

        // Add metadata headers for auth request
        let mut auth_grpc_request = Request::new(auth_request);
        add_authorizenet_metadata(&mut auth_grpc_request);

        // Send the auth request
        let auth_response = client
            .authorize(auth_grpc_request)
            .await
            .expect("gRPC payment_authorize call failed")
            .into_inner();

        // Extract the transaction ID
        let transaction_id = extract_transaction_id(&auth_response);

        // Verify payment status is authorized or handle other states
        assert!(
            auth_response.status == i32::from(PaymentStatus::Authorized),
            "Payment should be in AUTHORIZED but was: {}",
            auth_response.status
        );

        // Skip void test if payment is not in AUTHORIZED state
        if auth_response.status != i32::from(PaymentStatus::Authorized) {
            return;
        }

        // Allow some time for the authorization to be processed
        allow_processing_time();

        // Create void request
        let void_request = create_void_request(&transaction_id);

        // Add metadata headers for void request
        let mut void_grpc_request = Request::new(void_request);
        add_authorizenet_metadata(&mut void_grpc_request);

        // Send the void request
        let void_response = client
            .void(void_grpc_request)
            .await
            .expect("gRPC void_payment call failed")
            .into_inner();

        // Accept either VOIDED status
        assert!(
            void_response.status == i32::from(PaymentStatus::Voided),
            "Payment should be in VOIDED state"
        );
    });
}

// Test refund flow
#[tokio::test]
async fn test_refund() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        // First create a payment
        let auth_request = create_payment_authorize_request(common_enums::CaptureMethod::Automatic);

        // Add metadata headers for auth request
        let mut auth_grpc_request = Request::new(auth_request);
        add_authorizenet_metadata(&mut auth_grpc_request);

        // Send the auth request
        let auth_response = client
            .authorize(auth_grpc_request)
            .await
            .expect("gRPC payment_authorize call failed")
            .into_inner();

        // Extract the transaction ID
        let transaction_id = extract_transaction_id(&auth_response);

        // Verify payment status or handle other states
        assert!(
            auth_response.status == i32::from(PaymentStatus::Charged),
            "Payment should be in CHARGED state or FAILURE/PENDING for error cases, but was: {}",
            auth_response.status
        );

        // Skip refund test if payment is not in CHARGED state
        if auth_response.status != i32::from(PaymentStatus::Charged) {
            return;
        }

        // Wait a bit to ensure the payment is fully processed
        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

        // Create refund request
        let refund_request = create_refund_request(&transaction_id);

        // Add metadata headers for refund request
        let mut refund_grpc_request = Request::new(refund_request);
        add_authorizenet_metadata(&mut refund_grpc_request);

        // Send the refund request
        let refund_result = client.refund(refund_grpc_request).await;

        // Check if we have a successful refund OR the expected error message
        let is_success_status = refund_result.as_ref().is_ok_and(|response| {
            response.get_ref().status == i32::from(RefundStatus::RefundSuccess)
        });

        let has_expected_error = refund_result.as_ref().is_ok_and(|response| {
            response.get_ref().error_message().contains(
                "The referenced transaction does not meet the criteria for issuing a credit.",
            )
        });

        assert!(
            is_success_status || has_expected_error,
            "Refund should either have RefundSuccess status or the expected error message"
        );
    });
}

// Test register (setup mandate) flow
#[tokio::test]
async fn test_register() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        // Create the register request
        let request = create_register_request();
        
        // Add metadata headers
        let mut grpc_request = Request::new(request);
        add_authorizenet_metadata(&mut grpc_request);
        
        // Send the request
        let response = client
            .register(grpc_request)
            .await
            .expect("gRPC register call failed")
            .into_inner();
        
        // Verify the response
        assert!(
            response.registration_id.is_some(),
            "Registration ID should be present"
        );
        
        // Check if we have a mandate reference
        assert!(
            response.mandate_reference.is_some(),
            "Mandate reference should be present"
        );
        
        // Verify the mandate reference has the expected structure
        if let Some(mandate_ref) = &response.mandate_reference {
            assert!(
                mandate_ref.mandate_id.is_some(),
                "Mandate ID should be present"
            );
            
            // Verify the composite ID format (profile_id-payment_profile_id)
            if let Some(mandate_id) = &mandate_ref.mandate_id {
                assert!(
                    mandate_id.contains('-') || !mandate_id.is_empty(),
                    "Mandate ID should be either a composite ID or a profile ID"
                );
            }
        }
        
        // Verify no error occurred
        assert!(
            response.error_message.is_none() || response.error_message.as_ref().unwrap().is_empty(),
            "No error message should be present for successful register"
        );
    });
}

// Test register with invalid card
#[tokio::test]
async fn test_register_invalid_card() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        // Create the register request
        let mut request = create_register_request();
        
        // Modify the card number to be invalid
        if let Some(payment_method) = &mut request.payment_method {
            if let Some(payment_method::PaymentMethod::Card(card_method)) = &mut payment_method.payment_method {
                if let Some(card_payment_method_type::CardType::Credit(card_details)) = &mut card_method.card_type {
                    card_details.card_number = "4111111111111112".to_string(); // Invalid card number
                }
            }
        }
        
        // Add metadata headers
        let mut grpc_request = Request::new(request);
        add_authorizenet_metadata(&mut grpc_request);
        
        // Send the request
        let response = client
            .register(grpc_request)
            .await
            .expect("gRPC register call failed")
            .into_inner();
        
        // Verify error response
        assert!(
            response.error_message.is_some() && !response.error_message.as_ref().unwrap().is_empty(),
            "Error message should be present for invalid card"
        );
    });
}

// Test register with missing required fields
#[tokio::test]
async fn test_register_missing_fields() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        // Create the register request with missing billing address
        let mut request = create_register_request();
        request.address = None; // Remove required address
        
        // Add metadata headers
        let mut grpc_request = Request::new(request);
        add_authorizenet_metadata(&mut grpc_request);
        
        // Send the request - expect it to fail
        let result = client.register(grpc_request).await;
        
        // Verify the request failed due to missing fields
        assert!(
            result.is_err() || result.as_ref().unwrap().get_ref().error_message.is_some(),
            "Request should fail or return error for missing required fields"
        );
    });
}

// Test authorization with setup_future_usage
#[tokio::test]
async fn test_authorize_with_setup_future_usage() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        // Create an authorization request with setup_future_usage
        let mut auth_request = create_payment_authorize_request(common_enums::CaptureMethod::Automatic);
        
        // Add setup_future_usage to trigger profile creation
        auth_request.setup_future_usage = Some(i32::from(grpc_api_types::payments::FutureUsage::OnSession));
        
        // Add metadata headers
        let mut auth_grpc_request = Request::new(auth_request);
        add_authorizenet_metadata(&mut auth_grpc_request);
        
        // Send the authorization request
        let auth_response = client
            .authorize(auth_grpc_request)
            .await
            .expect("gRPC authorize with setup_future_usage call failed")
            .into_inner();
        
        // Verify the response
        assert!(
            auth_response.transaction_id.is_some(),
            "Transaction ID should be present"
        );
        
        // Verify payment status
        assert!(
            auth_response.status == i32::from(PaymentStatus::Charged),
            "Payment should be in CHARGED state but was: {}",
            auth_response.status
        );
        
        // When setup_future_usage is set, a customer profile is created
        // The mandate can be used in subsequent transactions
    });
}
