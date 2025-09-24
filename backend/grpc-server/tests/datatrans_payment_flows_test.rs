#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]

use grpc_server::{app, configs};
mod common;

use std::{
    env,
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

use cards::CardNumber;
use grpc_api_types::{
    health_check::{health_client::HealthClient, HealthCheckRequest},
    payments::{
        card_payment_method_type, identifier::IdType, payment_method,
        payment_service_client::PaymentServiceClient, Address, AuthenticationType, CaptureMethod,
        CardDetails, CardPaymentMethodType, Currency, Identifier, PaymentAddress, PaymentMethod,
        PaymentServiceAuthorizeRequest, PaymentStatus,
    },
};
use hyperswitch_masking::Secret;
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

// Constants for Datatrans connector
const CONNECTOR_NAME: &str = "datatrans";
const AUTH_TYPE: &str = "body-key";
const MERCHANT_ID: &str = "merchant_1234";

// Environment variable names for API credentials
const DATATRANS_KEY1_ENV: &str = "TEST_DATATRANS_KEY1"; // merchant_id
const DATATRANS_API_KEY_ENV: &str = "TEST_DATATRANS_API_KEY"; // api_key

// Test card data
const TEST_AMOUNT: i64 = 1000;
const TEST_CARD_NUMBER: &str = "4111111111111111"; // Valid test card
const TEST_CARD_EXP_MONTH: &str = "12";
const TEST_CARD_EXP_YEAR: &str = "2025";
const TEST_CARD_CVC: &str = "123";
const TEST_CARD_HOLDER: &str = "Test User";
const TEST_EMAIL: &str = "customer@example.com";

fn add_datatrans_metadata<T>(request: &mut Request<T>) {
    println!("datatrans: Setting up test metadata");
    
    // Get API credentials from environment variables with defaults
    let key1 = env::var(DATATRANS_KEY1_ENV)
        .unwrap_or_else(|_| "1110017152".to_string());
    let api_key = env::var(DATATRANS_API_KEY_ENV)
        .unwrap_or_else(|_| "jZJZjQH9eL5FdjvA".to_string());

    println!("datatrans: Using merchant_id: {}", key1);
    println!("datatrans: Using api_key: {}...", &api_key[..8.min(api_key.len())]);

    request.metadata_mut().append(
        "x-connector",
        CONNECTOR_NAME.parse().expect("Failed to parse x-connector"),
    );
    request
        .metadata_mut()
        .append("x-auth", AUTH_TYPE.parse().expect("Failed to parse x-auth"));
    request
        .metadata_mut()
        .append("x-key1", key1.parse().expect("Failed to parse x-key1"));
    request.metadata_mut().append(
        "x-api-key",
        api_key.parse().expect("Failed to parse x-api-key"),
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
    
    println!("datatrans: Metadata setup completed");
}

// Helper function to create a payment authorize request
fn create_authorize_request(capture_method: CaptureMethod) -> PaymentServiceAuthorizeRequest {
    println!("datatrans: Creating authorize request with capture_method: {:?}", capture_method);
    
    let card_details = card_payment_method_type::CardType::Credit(CardDetails {
        card_number: Some(CardNumber::from_str(TEST_CARD_NUMBER).unwrap()),
        card_exp_month: Some(Secret::new(TEST_CARD_EXP_MONTH.to_string())),
        card_exp_year: Some(Secret::new(TEST_CARD_EXP_YEAR.to_string())),
        card_cvc: Some(Secret::new(TEST_CARD_CVC.to_string())),
        card_holder_name: Some(Secret::new(TEST_CARD_HOLDER.to_string())),
        card_issuer: None,
        card_network: Some(1),
        card_type: None,
        card_issuing_country_alpha2: None,
        bank_code: None,
        nick_name: None,
    });
    
    let address = PaymentAddress {
        billing_address: Some(Address {
            first_name: Some("John".to_string().into()),
            last_name: Some("Doe".to_string().into()),
            email: Some("test@test.com".to_string().into()),
            ..Default::default()
        }),
        shipping_address: None,
    };
    
    let request = PaymentServiceAuthorizeRequest {
        amount: TEST_AMOUNT,
        minor_amount: TEST_AMOUNT,
        currency: i32::from(Currency::Usd),
        payment_method: Some(PaymentMethod {
            payment_method: Some(payment_method::PaymentMethod::Card(CardPaymentMethodType {
                card_type: Some(card_details),
            })),
        }),
        return_url: Some("https://hyperswitch.io/".to_string()),
        webhook_url: Some("https://hyperswitch.io/".to_string()),
        email: Some(TEST_EMAIL.to_string().into()),
        address: Some(address),
        auth_type: i32::from(AuthenticationType::NoThreeDs),
        request_ref_id: Some(Identifier {
            id_type: Some(IdType::Id(generate_unique_id("datatrans_test"))),
        }),
        enrolled_for_3ds: false,
        request_incremental_authorization: false,
        capture_method: Some(i32::from(capture_method)),
        ..Default::default()
    };
    
    println!("datatrans: Authorize request created successfully");
    request
}

// Test for basic health check
#[tokio::test]
async fn test_health() {
    println!("datatrans: Starting health check test");
    
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
        
        println!("datatrans: Health check test passed");
    });
}

// Test payment authorization with auto capture
#[tokio::test]
async fn test_payment_authorization_auto_capture() {
    println!("datatrans: Starting payment authorization auto capture test");
    
    grpc_test!(client, PaymentServiceClient<Channel>, {
        println!("datatrans: Creating payment authorization request");
        
        // Create the payment authorization request
        let request = create_authorize_request(CaptureMethod::Automatic);

        // Add metadata headers
        let mut grpc_request = Request::new(request);
        add_datatrans_metadata(&mut grpc_request);

        println!("datatrans: Sending authorization request to connector");
        
        // Send the request
        let response = client
            .authorize(grpc_request)
            .await
            .expect("gRPC authorize call failed")
            .into_inner();

        println!("datatrans: Received response with status: {:?}", response.status);
        println!("datatrans: Response details: {:?}", response);

        // For datatrans, we expect either Charged or Authorized status for auto capture
        assert!(
            response.status == i32::from(PaymentStatus::Charged) ||
            response.status == i32::from(PaymentStatus::Authorized),
            "Payment should be in Charged or Authorized state, got: {:?}", response.status
        );
        
        println!("datatrans: Payment authorization auto capture test passed");
    });
}

// Test payment authorization with manual capture
#[tokio::test]
async fn test_payment_authorization_manual_capture() {
    println!("datatrans: Starting payment authorization manual capture test");
    
    grpc_test!(client, PaymentServiceClient<Channel>, {
        println!("datatrans: Creating payment authorization request for manual capture");
        
        // Create the payment authorization request
        let request = create_authorize_request(CaptureMethod::Manual);

        // Add metadata headers
        let mut grpc_request = Request::new(request);
        add_datatrans_metadata(&mut grpc_request);

        println!("datatrans: Sending authorization request to connector");
        
        // Send the request
        let response = client
            .authorize(grpc_request)
            .await
            .expect("gRPC authorize call failed")
            .into_inner();

        println!("datatrans: Received response with status: {:?}", response.status);
        println!("datatrans: Response details: {:?}", response);

        // For manual capture, we expect Authorized status
        assert!(
            response.status == i32::from(PaymentStatus::Authorized),
            "Payment should be in Authorized state for manual capture, got: {:?}", response.status
        );
        
        println!("datatrans: Payment authorization manual capture test passed");
    });
}