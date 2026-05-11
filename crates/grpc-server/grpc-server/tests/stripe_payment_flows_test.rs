#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]

use grpc_server::app;
use hyperswitch_masking::{ExposeInterface, Secret};
use ucs_env::configs;
mod common;
mod utils;

use std::{
    fmt::Write as FmtWrite,
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

use cards::CardNumber;
use common_utils::crypto::{HmacSha256, SignMessage};
use grpc_api_types::{
    health_check::{health_client::HealthClient, HealthCheckRequest},
    payments::{
        dispute_service_client::DisputeServiceClient,
        event_service_client::EventServiceClient, payment_method,
        payment_service_client::PaymentServiceClient,
        refund_service_client::RefundServiceClient, AuthenticationType, CaptureMethod, CardDetails,
        Currency, DisputeServiceAcceptRequest, DisputeServiceDefendRequest,
        DisputeServiceSubmitEvidenceRequest, DisputeStatus, EvidenceDocument, EvidenceType,
        EventServiceHandleRequest, EventServiceHandleResponse, MobilePayRedirectWallet,
        OpenBankingUk, Oxxo, PaymentMethod, PaymentServiceAuthorizeRequest,
        PaymentServiceAuthorizeResponse, PaymentServiceCaptureRequest,
        PaymentServiceGetRequest, PaymentServiceRefundRequest, PaymentServiceVoidRequest,
        PaymentStatus, PaypalRedirectWallet, PromptPay, RefundResponse, RefundServiceGetRequest,
        RefundStatus, RequestDetails, Satispay, SevenEleven, TwintRedirectWallet, WebhookSecrets,
        Wero,
    },
};
use serde_json::json;
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

// Constants for Stripe connector
const CONNECTOR_NAME: &str = "stripe";
const AUTH_TYPE: &str = "header-key";
const MERCHANT_ID: &str = "merchant_1234";

// Test card data
const TEST_AMOUNT: i64 = 1000;
const TEST_CARD_NUMBER: &str = "4111111111111111"; // Valid test card for Stripe
const TEST_CARD_EXP_MONTH: &str = "12";
const TEST_CARD_EXP_YEAR: &str = "2050";
const TEST_CARD_CVC: &str = "123";
const TEST_CARD_HOLDER: &str = "Test User";
const TEST_EMAIL: &str = "customer@example.com";

fn add_stripe_metadata<T>(request: &mut Request<T>) {
    // Get API credentials using the common credential loading utility
    let auth = utils::credential_utils::load_connector_auth(CONNECTOR_NAME)
        .expect("Failed to load Stripe credentials");

    let api_key = match auth {
        domain_types::router_data::ConnectorAuthType::HeaderKey { api_key } => api_key.expose(),
        _ => panic!("Expected HeaderKey auth type for Stripe"),
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
        format!("conn_ref_{}", get_timestamp())
            .parse()
            .expect("Failed to parse x-connector-request-reference-id"),
    );
}

// Helper function to extract connector transaction ID from response
fn extract_transaction_id(response: &PaymentServiceAuthorizeResponse) -> String {
    match &response.connector_transaction_id {
        Some(id) => id.clone(),
        None => panic!("Resource ID is None"),
    }
}

// Helper function to extract connector Refund ID from response
fn extract_refund_id(response: &RefundResponse) -> &String {
    &response.connector_refund_id
}

// Helper function to create a payment authorize request
fn create_authorize_request(capture_method: CaptureMethod) -> PaymentServiceAuthorizeRequest {
    let card_details = CardDetails {
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
    };
    PaymentServiceAuthorizeRequest {
        amount: Some(grpc_api_types::payments::Money {
            minor_amount: TEST_AMOUNT,
            currency: i32::from(Currency::Usd),
        }),
        payment_method: Some(PaymentMethod {
            payment_method: Some(payment_method::PaymentMethod::Card(card_details)),
        }),
        return_url: Some(
            "https://hyperswitch.io/connector-service/authnet_webhook_grpcurl".to_string(),
        ),
        webhook_url: Some(
            "https://hyperswitch.io/connector-service/authnet_webhook_grpcurl".to_string(),
        ),
        customer: Some(grpc_api_types::payments::Customer {
            email: Some(TEST_EMAIL.to_string().into()),
            name: None,
            id: Some("cus_TE8065JzRWlLQf".to_string()),
            connector_customer_id: Some("cus_TE8065JzRWlLQf".to_string()),
            phone_number: None,
            phone_country_code: None,
        }),
        address: Some(grpc_api_types::payments::PaymentAddress::default()),
        auth_type: i32::from(AuthenticationType::NoThreeDs),
        merchant_transaction_id: Some(generate_unique_id("stripe_test")),
        enrolled_for_3ds: Some(false),
        request_incremental_authorization: Some(false),
        capture_method: Some(i32::from(capture_method)),
        // payment_method_type: Some(i32::from(PaymentMethodType::Card)),
        ..Default::default()
    }
}

// Helper function to create a payment sync request
fn create_payment_sync_request(transaction_id: &str) -> PaymentServiceGetRequest {
    PaymentServiceGetRequest {
        connector_transaction_id: transaction_id.to_string(),
        encoded_data: None,
        capture_method: None,
        merchant_transaction_id: None,
        amount: Some(grpc_api_types::payments::Money {
            minor_amount: TEST_AMOUNT,
            currency: i32::from(Currency::Usd),
        }),
        state: None,
        metadata: None,
        connector_feature_data: None,
        setup_future_usage: None,
        sync_type: None,
        connector_order_reference_id: None,
        test_mode: None,
        payment_experience: None,
    }
}

// Helper function to create a payment capture request
fn create_payment_capture_request(transaction_id: &str) -> PaymentServiceCaptureRequest {
    PaymentServiceCaptureRequest {
        connector_transaction_id: transaction_id.to_string(),
        amount_to_capture: Some(grpc_api_types::payments::Money {
            minor_amount: TEST_AMOUNT,
            currency: i32::from(Currency::Usd),
        }),
        multiple_capture_data: None,
        merchant_capture_id: None,
        ..Default::default()
    }
}

// Helper function to create a payment void request
fn create_payment_void_request(transaction_id: &str) -> PaymentServiceVoidRequest {
    PaymentServiceVoidRequest {
        connector_transaction_id: transaction_id.to_string(),
        cancellation_reason: None,
        merchant_void_id: Some(generate_unique_id("stripe_void")),
        all_keys_required: None,
        browser_info: None,
        amount: None,
        ..Default::default()
    }
}

// Helper function to create a refund request
fn create_refund_request(transaction_id: &str) -> PaymentServiceRefundRequest {
    PaymentServiceRefundRequest {
        merchant_refund_id: Some(format!("refund_{}", generate_unique_id("test"))),
        connector_transaction_id: transaction_id.to_string(),
        payment_amount: TEST_AMOUNT,
        refund_amount: Some(grpc_api_types::payments::Money {
            minor_amount: TEST_AMOUNT,
            currency: i32::from(Currency::Usd),
        }),
        reason: None,
        browser_info: None,
        merchant_account_id: None,
        capture_method: None,
        webhook_url: Some(
            "https://hyperswitch.io/connector-service/authnet_webhook_grpcurl".to_string(),
        ),
        ..Default::default()
    }
}

// Helper function to create a refund sync request
fn create_refund_sync_request(transaction_id: &str, refund_id: &str) -> RefundServiceGetRequest {
    RefundServiceGetRequest {
        connector_transaction_id: transaction_id.to_string(),
        refund_id: refund_id.to_string(),
        refund_reason: None,
        merchant_refund_id: None,
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
        let request = create_authorize_request(CaptureMethod::Automatic);

        // Add metadata headers
        let mut grpc_request = Request::new(request);
        add_stripe_metadata(&mut grpc_request);

        // Send the request
        let response = client
            .authorize(grpc_request)
            .await
            .expect("gRPC authorize call failed")
            .into_inner();

        assert!(
            response.status == i32::from(PaymentStatus::Charged),
            "Payment should be in Charged state"
        );
    });
}

// Test payment authorization with manual capture
#[tokio::test]
async fn test_payment_authorization_manual_capture() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        // Create the payment authorization request with manual capture
        let auth_request = create_authorize_request(CaptureMethod::Manual);

        // Add metadata headers for auth request
        let mut auth_grpc_request = Request::new(auth_request);
        add_stripe_metadata(&mut auth_grpc_request);

        // Send the auth request
        let auth_response = client
            .authorize(auth_grpc_request)
            .await
            .expect("gRPC authorize call failed")
            .into_inner();

        // Verify payment status
        assert!(
            auth_response.status == i32::from(PaymentStatus::Authorized),
            "Payment should be in Authorized state"
        );

        // Extract the transaction ID
        let transaction_id = extract_transaction_id(&auth_response);

        // Create capture request
        let capture_request = create_payment_capture_request(&transaction_id);

        // Add metadata headers for capture request - make sure they include the terminal_id
        let mut capture_grpc_request = Request::new(capture_request);
        add_stripe_metadata(&mut capture_grpc_request);

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

// Test payment sync with auto capture
#[tokio::test]
async fn test_payment_sync_auto_capture() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        // Create the payment authorization request
        let request = create_authorize_request(CaptureMethod::Automatic);

        // Add metadata headers
        let mut grpc_request = Request::new(request);
        add_stripe_metadata(&mut grpc_request);

        // Send the request
        let response = client
            .authorize(grpc_request)
            .await
            .expect("gRPC authorize call failed")
            .into_inner();

        // Extract the transaction ID
        let transaction_id = extract_transaction_id(&response);

        // Create sync request
        let sync_request = create_payment_sync_request(&transaction_id);

        // Add metadata headers for sync request
        let mut sync_grpc_request = Request::new(sync_request);
        add_stripe_metadata(&mut sync_grpc_request);

        // Send the sync request
        let sync_response = client
            .get(sync_grpc_request)
            .await
            .expect("gRPC payment_sync call failed")
            .into_inner();

        // Verify the sync response
        assert!(
            sync_response.status == i32::from(PaymentStatus::Charged),
            "Payment should be in Charged state"
        );
    });
}

// Test payment void
#[tokio::test]
async fn test_payment_void() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        // First create a payment with manual capture to void
        let auth_request = create_authorize_request(CaptureMethod::Manual);

        // Add metadata headers for auth request
        let mut auth_grpc_request = Request::new(auth_request);
        add_stripe_metadata(&mut auth_grpc_request);

        // Send the auth request
        let auth_response = client
            .authorize(auth_grpc_request)
            .await
            .expect("gRPC payment_authorize call failed")
            .into_inner();

        // Extract the transaction ID
        let transaction_id = extract_transaction_id(&auth_response);

        // Verify payment status
        assert!(
            auth_response.status == i32::from(PaymentStatus::Authorized),
            "Payment should be in AUTHORIZED state before voiding"
        );

        // Create void request with a unique reference ID
        let void_request = create_payment_void_request(&transaction_id);

        // Add metadata headers for void request
        let mut void_grpc_request = Request::new(void_request);
        add_stripe_metadata(&mut void_grpc_request);

        // Send the void request
        let void_response = client
            .void(void_grpc_request)
            .await
            .expect("gRPC void_payment call failed")
            .into_inner();

        // Verify the void response
        assert!(
            !void_response.connector_transaction_id.is_empty(),
            "Transaction ID should be present in void response"
        );

        assert!(
            void_response.status == i32::from(PaymentStatus::Voided),
            "Payment should be in VOIDED state after void"
        );

        // Verify the payment status with a sync operation
        let sync_request = create_payment_sync_request(&transaction_id);
        let mut sync_grpc_request = Request::new(sync_request);
        add_stripe_metadata(&mut sync_grpc_request);

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

#[tokio::test]
async fn test_refund() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        // Create the payment authorization request
        let request = create_authorize_request(CaptureMethod::Automatic);

        // Add metadata headers
        let mut grpc_request = Request::new(request);
        add_stripe_metadata(&mut grpc_request);

        // Send the request
        let response = client
            .authorize(grpc_request)
            .await
            .expect("gRPC authorize call failed")
            .into_inner();

        // Extract the transaction ID
        let transaction_id = extract_transaction_id(&response);

        assert!(
            response.status == i32::from(PaymentStatus::Charged),
            "Payment should be in Charged state"
        );

        // Create refund request
        let refund_request = create_refund_request(&transaction_id);

        // Add metadata headers for refund request
        let mut refund_grpc_request = Request::new(refund_request);
        add_stripe_metadata(&mut refund_grpc_request);

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
    });
}

#[tokio::test]
async fn test_refund_sync() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        grpc_test!(refund_client, RefundServiceClient<Channel>, {
            // Create the payment authorization request
            let request = create_authorize_request(CaptureMethod::Automatic);

            // Add metadata headers
            let mut grpc_request = Request::new(request);
            add_stripe_metadata(&mut grpc_request);

            // Send the request
            let response = client
                .authorize(grpc_request)
                .await
                .expect("gRPC authorize call failed")
                .into_inner();

            // Extract the transaction ID
            let transaction_id = extract_transaction_id(&response);

            assert!(
                response.status == i32::from(PaymentStatus::Charged),
                "Payment should be in Charged state"
            );

            // Create refund request
            let refund_request = create_refund_request(&transaction_id);

            // Add metadata headers for refund request
            let mut refund_grpc_request = Request::new(refund_request);
            add_stripe_metadata(&mut refund_grpc_request);

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

            // Create refund sync request
            let refund_sync_request = create_refund_sync_request(&transaction_id, refund_id);

            // Add metadata headers for refund sync request
            let mut refund_sync_grpc_request = Request::new(refund_sync_request);
            add_stripe_metadata(&mut refund_sync_grpc_request);

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

// ============================================================================
// Payment Method Authorize Tests
// ============================================================================

fn create_authorize_request_for_method(
    payment_method_variant: payment_method::PaymentMethod,
    currency: Currency,
    amount: i64,
) -> PaymentServiceAuthorizeRequest {
    PaymentServiceAuthorizeRequest {
        amount: Some(grpc_api_types::payments::Money {
            minor_amount: amount,
            currency: i32::from(currency),
        }),
        payment_method: Some(PaymentMethod {
            payment_method: Some(payment_method_variant),
        }),
        return_url: Some("https://hyperswitch.io/redirect/complete".to_string()),
        webhook_url: Some("https://hyperswitch.io/webhooks/stripe".to_string()),
        customer: Some(grpc_api_types::payments::Customer {
            email: Some(TEST_EMAIL.to_string().into()),
            name: Some("Test User".to_string()),
            id: Some("cus_test_pm".to_string()),
            connector_customer_id: None,
            phone_number: None,
            phone_country_code: None,
        }),
        address: Some(grpc_api_types::payments::PaymentAddress::default()),
        auth_type: i32::from(AuthenticationType::NoThreeDs),
        merchant_transaction_id: Some(generate_unique_id("stripe_pm_test")),
        enrolled_for_3ds: Some(false),
        request_incremental_authorization: Some(false),
        capture_method: Some(i32::from(CaptureMethod::Automatic)),
        ..Default::default()
    }
}

#[tokio::test]
#[ignore = "requires live Stripe credentials"]
async fn test_authorize_oxxo() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        let request = create_authorize_request_for_method(
            payment_method::PaymentMethod::Oxxo(Oxxo {}),
            Currency::Mxn,
            50000, // 500.00 MXN
        );
        let mut grpc_request = Request::new(request);
        add_stripe_metadata(&mut grpc_request);

        let response = client
            .authorize(grpc_request)
            .await
            .expect("gRPC authorize call failed for Oxxo")
            .into_inner();

        assert!(
            response.status == i32::from(PaymentStatus::AuthenticationPending)
                || response.status == i32::from(PaymentStatus::Pending),
            "Oxxo payment should be in pending/authentication-pending state, got: {}",
            response.status
        );
    });
}

#[tokio::test]
#[ignore = "requires live Stripe credentials"]
async fn test_authorize_konbini() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        let request = create_authorize_request_for_method(
            payment_method::PaymentMethod::SevenEleven(SevenEleven {}),
            Currency::Jpy,
            1000, // 1000 JPY (zero-decimal currency)
        );
        let mut grpc_request = Request::new(request);
        add_stripe_metadata(&mut grpc_request);

        let response = client
            .authorize(grpc_request)
            .await
            .expect("gRPC authorize call failed for Konbini (SevenEleven)")
            .into_inner();

        assert!(
            response.status == i32::from(PaymentStatus::AuthenticationPending)
                || response.status == i32::from(PaymentStatus::Pending),
            "Konbini payment should be in pending/authentication-pending state, got: {}",
            response.status
        );
    });
}

#[tokio::test]
#[ignore = "requires live Stripe credentials"]
async fn test_authorize_promptpay() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        let request = create_authorize_request_for_method(
            payment_method::PaymentMethod::PromptPay(PromptPay {}),
            Currency::Thb,
            2000, // 20.00 THB
        );
        let mut grpc_request = Request::new(request);
        add_stripe_metadata(&mut grpc_request);

        let response = client
            .authorize(grpc_request)
            .await
            .expect("gRPC authorize call failed for PromptPay")
            .into_inner();

        assert!(
            response.status == i32::from(PaymentStatus::AuthenticationPending)
                || response.status == i32::from(PaymentStatus::Pending),
            "PromptPay payment should be in pending/authentication-pending state, got: {}",
            response.status
        );
    });
}

#[tokio::test]
#[ignore = "requires live Stripe credentials"]
async fn test_authorize_mobilepay() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        let request = create_authorize_request_for_method(
            payment_method::PaymentMethod::MobilePayRedirect(MobilePayRedirectWallet {}),
            Currency::Dkk,
            5000, // 50.00 DKK
        );
        let mut grpc_request = Request::new(request);
        add_stripe_metadata(&mut grpc_request);

        let response = client
            .authorize(grpc_request)
            .await
            .expect("gRPC authorize call failed for MobilePay")
            .into_inner();

        assert!(
            response.status == i32::from(PaymentStatus::AuthenticationPending)
                || response.status == i32::from(PaymentStatus::Pending),
            "MobilePay payment should be in pending/authentication-pending state, got: {}",
            response.status
        );
    });
}

#[tokio::test]
#[ignore = "requires live Stripe credentials"]
async fn test_authorize_twint() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        let request = create_authorize_request_for_method(
            payment_method::PaymentMethod::TwintRedirect(TwintRedirectWallet {}),
            Currency::Chf,
            2000, // 20.00 CHF
        );
        let mut grpc_request = Request::new(request);
        add_stripe_metadata(&mut grpc_request);

        let response = client
            .authorize(grpc_request)
            .await
            .expect("gRPC authorize call failed for Twint")
            .into_inner();

        assert!(
            response.status == i32::from(PaymentStatus::AuthenticationPending)
                || response.status == i32::from(PaymentStatus::Pending),
            "Twint payment should be in pending/authentication-pending state, got: {}",
            response.status
        );
    });
}

#[tokio::test]
#[ignore = "requires live Stripe credentials"]
async fn test_authorize_satispay() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        let request = create_authorize_request_for_method(
            payment_method::PaymentMethod::Satispay(Satispay {}),
            Currency::Eur,
            1000, // 10.00 EUR
        );
        let mut grpc_request = Request::new(request);
        add_stripe_metadata(&mut grpc_request);

        let response = client
            .authorize(grpc_request)
            .await
            .expect("gRPC authorize call failed for Satispay")
            .into_inner();

        assert!(
            response.status == i32::from(PaymentStatus::AuthenticationPending)
                || response.status == i32::from(PaymentStatus::Pending),
            "Satispay payment should be in pending/authentication-pending state, got: {}",
            response.status
        );
    });
}

#[tokio::test]
#[ignore = "requires live Stripe credentials"]
async fn test_authorize_wero() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        let request = create_authorize_request_for_method(
            payment_method::PaymentMethod::Wero(Wero {}),
            Currency::Eur,
            1500, // 15.00 EUR
        );
        let mut grpc_request = Request::new(request);
        add_stripe_metadata(&mut grpc_request);

        let response = client
            .authorize(grpc_request)
            .await
            .expect("gRPC authorize call failed for Wero")
            .into_inner();

        assert!(
            response.status == i32::from(PaymentStatus::AuthenticationPending)
                || response.status == i32::from(PaymentStatus::Pending),
            "Wero payment should be in pending/authentication-pending state, got: {}",
            response.status
        );
    });
}

#[tokio::test]
#[ignore = "requires live Stripe credentials"]
async fn test_authorize_paypal() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        let request = create_authorize_request_for_method(
            payment_method::PaymentMethod::PaypalRedirect(PaypalRedirectWallet {
                email: Some(Secret::new(TEST_EMAIL.to_string())),
            }),
            Currency::Eur,
            2000, // 20.00 EUR
        );
        let mut grpc_request = Request::new(request);
        add_stripe_metadata(&mut grpc_request);

        let response = client
            .authorize(grpc_request)
            .await
            .expect("gRPC authorize call failed for PayPal")
            .into_inner();

        assert!(
            response.status == i32::from(PaymentStatus::AuthenticationPending)
                || response.status == i32::from(PaymentStatus::Pending),
            "PayPal payment should be in pending/authentication-pending state, got: {}",
            response.status
        );
    });
}

#[tokio::test]
#[ignore = "requires live Stripe credentials"]
async fn test_authorize_openbanking_uk() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        let request = create_authorize_request_for_method(
            payment_method::PaymentMethod::OpenBankingUk(OpenBankingUk {
                country: Some("GB".to_string()),
                issuer: None,
            }),
            Currency::Gbp,
            1000, // 10.00 GBP
        );
        let mut grpc_request = Request::new(request);
        add_stripe_metadata(&mut grpc_request);

        let response = client
            .authorize(grpc_request)
            .await
            .expect("gRPC authorize call failed for OpenBankingUk")
            .into_inner();

        assert!(
            response.status == i32::from(PaymentStatus::AuthenticationPending)
                || response.status == i32::from(PaymentStatus::Pending),
            "OpenBankingUk payment should be in pending/authentication-pending state, got: {}",
            response.status
        );
    });
}

// ============================================================================
// Dispute Flow Tests
// ============================================================================

#[tokio::test]
#[ignore = "requires live Stripe credentials and an active dispute"]
async fn test_dispute_accept() {
    grpc_test!(client, DisputeServiceClient<Channel>, {
        let mut request = Request::new(DisputeServiceAcceptRequest {
            connector_transaction_id: "pi_test_dispute_accept".to_string(),
            dispute_id: "dp_test_accept".to_string(),
            merchant_dispute_id: Some(generate_unique_id("accept_dispute")),
        });
        add_stripe_metadata(&mut request);

        let response = client
            .accept(request)
            .await
            .expect("gRPC accept dispute call failed")
            .into_inner();

        assert_eq!(
            DisputeStatus::try_from(response.dispute_status)
                .expect("Failed to convert dispute status"),
            DisputeStatus::DisputeAccepted,
            "AcceptDispute should yield DisputeAccepted (Lost → DisputeAccepted in accept flow)"
        );
    });
}

#[tokio::test]
#[ignore = "requires live Stripe credentials and an active dispute"]
async fn test_dispute_submit_evidence() {
    grpc_test!(client, DisputeServiceClient<Channel>, {
        let mut request = Request::new(DisputeServiceSubmitEvidenceRequest {
            dispute_id: "dp_test_evidence".to_string(),
            connector_transaction_id: Some("pi_test_dispute_evidence".to_string()),
            evidence_documents: vec![EvidenceDocument {
                evidence_type: i32::from(EvidenceType::Receipt),
                file_content: None,
                file_mime_type: None,
                provider_file_id: None,
                text_content: Some("Order delivered on 2024-01-15".to_string()),
            }],
            ..Default::default()
        });
        add_stripe_metadata(&mut request);

        let response = client
            .submit_evidence(request)
            .await
            .expect("gRPC submit evidence call failed")
            .into_inner();

        assert!(
            response.dispute_status == i32::from(DisputeStatus::DisputeChallenged)
                || response.dispute_status == i32::from(DisputeStatus::DisputeOpened),
            "SubmitEvidence should yield DisputeChallenged or DisputeOpened, got: {}",
            response.dispute_status
        );
    });
}

#[tokio::test]
#[ignore = "requires live Stripe credentials and an active dispute"]
async fn test_dispute_defend() {
    grpc_test!(client, DisputeServiceClient<Channel>, {
        let mut request = Request::new(DisputeServiceDefendRequest {
            connector_transaction_id: "pi_test_dispute_defend".to_string(),
            dispute_id: "dp_test_defend".to_string(),
            merchant_dispute_id: Some(generate_unique_id("defend_dispute")),
            reason_code: Some("product_delivered".to_string()),
        });
        add_stripe_metadata(&mut request);

        let response = client
            .defend(request)
            .await
            .expect("gRPC defend dispute call failed")
            .into_inner();

        assert!(
            response.dispute_status == i32::from(DisputeStatus::DisputeChallenged)
                || response.dispute_status == i32::from(DisputeStatus::DisputeOpened),
            "DefendDispute (submit: true) should yield DisputeChallenged or DisputeOpened, got: {}",
            response.dispute_status
        );
    });
}

// ============================================================================
// Webhook HMAC-SHA256 Tests
// ============================================================================

const STRIPE_TEST_WEBHOOK_SECRET: &str = "whsec_test_secret_for_hmac_verification";

fn stripe_sample_webhook_body() -> serde_json::Value {
    json!({
        "id": "evt_test_001",
        "object": "event",
        "type": "payment_intent.succeeded",
        "data": {
            "object": {
                "id": "pi_test_001",
                "object": "payment_intent",
                "amount": 2000,
                "currency": "usd",
                "status": "succeeded",
                "created": 1686089970,
                "metadata": {}
            }
        },
        "livemode": false,
        "created": 1686089970,
        "pending_webhooks": 0
    })
}

fn generate_stripe_webhook_signature(body: &[u8], secret: &str, timestamp: i64) -> String {
    let body_str = String::from_utf8_lossy(body);
    let signed_payload = format!("{timestamp}.{body_str}");
    let sig = HmacSha256
        .sign_message(secret.as_bytes(), signed_payload.as_bytes())
        .expect("Failed to compute HMAC-SHA256");
    let mut hex_sig = String::with_capacity(sig.len() * 2);
    for b in sig {
        write!(&mut hex_sig, "{b:02x}").expect("hex write failed");
    }
    format!("t={timestamp},v1={hex_sig}")
}

async fn process_stripe_webhook(
    client: &mut EventServiceClient<Channel>,
    body_bytes: Vec<u8>,
    signature_header: Option<String>,
    webhook_secret: &str,
) -> Result<EventServiceHandleResponse, String> {
    let mut headers = std::collections::HashMap::new();
    if let Some(sig) = signature_header {
        headers.insert("stripe-signature".to_string(), sig);
    }

    let mut request = Request::new(EventServiceHandleRequest {
        merchant_event_id: Some("stripe_webhook_test".to_string()),
        request_details: Some(RequestDetails {
            method: grpc_api_types::payments::HttpMethod::Post.into(),
            headers,
            uri: Some("/webhooks/stripe".to_string()),
            query_params: None,
            body: body_bytes,
        }),
        webhook_secrets: Some(WebhookSecrets {
            secret: webhook_secret.to_string(),
            additional_secret: None,
        }),
        access_token: None,
        event_context: None,
    });

    add_stripe_metadata(&mut request);

    client
        .handle_event(request)
        .await
        .map(|r| r.into_inner())
        .map_err(|e| format!("{e}"))
}

#[tokio::test]
async fn test_stripe_webhook_valid_signature() {
    grpc_test!(client, EventServiceClient<Channel>, {
        let body = stripe_sample_webhook_body();
        let body_bytes = serde_json::to_vec(&body).expect("serialize webhook body");
        let now = i64::try_from(get_timestamp()).expect("timestamp fits i64");
        let signature =
            generate_stripe_webhook_signature(&body_bytes, STRIPE_TEST_WEBHOOK_SECRET, now);

        let result = process_stripe_webhook(
            &mut client,
            body_bytes,
            Some(signature),
            STRIPE_TEST_WEBHOOK_SECRET,
        )
        .await;

        assert!(result.is_ok(), "Valid HMAC-SHA256 webhook should succeed");
        let response = result.unwrap();
        assert!(
            response.source_verified,
            "Valid signature should set source_verified = true"
        );
    });
}

#[tokio::test]
async fn test_stripe_webhook_expired_timestamp() {
    grpc_test!(client, EventServiceClient<Channel>, {
        let body = stripe_sample_webhook_body();
        let body_bytes = serde_json::to_vec(&body).expect("serialize webhook body");
        let expired_ts =
            i64::try_from(get_timestamp()).expect("timestamp fits i64") - 600;
        let signature = generate_stripe_webhook_signature(
            &body_bytes,
            STRIPE_TEST_WEBHOOK_SECRET,
            expired_ts,
        );

        let result = process_stripe_webhook(
            &mut client,
            body_bytes,
            Some(signature),
            STRIPE_TEST_WEBHOOK_SECRET,
        )
        .await;

        match result {
            Ok(response) => {
                assert!(
                    !response.source_verified,
                    "Expired timestamp (>300s) should set source_verified = false"
                );
            }
            Err(_) => {
                // Some implementations may reject outright — also acceptable
            }
        }
    });
}

#[tokio::test]
async fn test_stripe_webhook_tampered_body() {
    grpc_test!(client, EventServiceClient<Channel>, {
        let original_body = stripe_sample_webhook_body();
        let original_bytes =
            serde_json::to_vec(&original_body).expect("serialize original body");
        let now = i64::try_from(get_timestamp()).expect("timestamp fits i64");
        let signature = generate_stripe_webhook_signature(
            &original_bytes,
            STRIPE_TEST_WEBHOOK_SECRET,
            now,
        );

        let tampered_body = json!({
            "id": "evt_test_001",
            "object": "event",
            "type": "payment_intent.succeeded",
            "data": {
                "object": {
                    "id": "pi_TAMPERED",
                    "object": "payment_intent",
                    "amount": 999999,
                    "currency": "usd",
                    "status": "succeeded",
                    "created": 1686089970,
                    "metadata": {}
                }
            },
            "livemode": false,
            "created": 1686089970,
            "pending_webhooks": 0
        });
        let tampered_bytes =
            serde_json::to_vec(&tampered_body).expect("serialize tampered body");

        let result = process_stripe_webhook(
            &mut client,
            tampered_bytes,
            Some(signature),
            STRIPE_TEST_WEBHOOK_SECRET,
        )
        .await;

        match result {
            Ok(response) => {
                assert!(
                    !response.source_verified,
                    "Tampered body should set source_verified = false"
                );
            }
            Err(_) => {
                // Some implementations may reject outright — also acceptable
            }
        }
    });
}
