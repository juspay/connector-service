#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]

//! Vault payment flow integration tests
//!
//! Tests payment authorization through vault proxies:
//! - VGS (Very Good Security) proxy → Stripe
//! - Hyperswitch Vault transformation → Adyen
//!
//! These tests require vault credentials in `.github/test/creds.json` under
//! keys `vault_vgs` and `vault_hyperswitch`, plus connector credentials under
//! `stripe` and `adyen` respectively.

use grpc_server::app;
use hyperswitch_masking::{ExposeInterface, Secret};
use ucs_env::configs;
mod common;
mod utils;

use std::time::{SystemTime, UNIX_EPOCH};

use grpc_api_types::payments::{
    identifier::IdType, payment_method, payment_service_client::PaymentServiceClient,
    AuthenticationType, BrowserInformation, CaptureMethod, Currency, Identifier, PaymentMethod,
    PaymentServiceAuthorizeRequest, PaymentServiceAuthorizeResponse, PaymentStatus,
    ProxyCardDetails,
};
use tonic::{transport::Channel, Request};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn get_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn generate_unique_id(prefix: &str) -> String {
    format!("{}_{}", prefix, Uuid::new_v4())
}

fn extract_transaction_id(response: &PaymentServiceAuthorizeResponse) -> String {
    match &response.connector_transaction_id {
        Some(id) => match id.id_type.as_ref().unwrap() {
            IdType::Id(id) => id.clone(),
            _ => panic!("Expected connector transaction ID"),
        },
        None => panic!("Resource ID is None"),
    }
}

// ---------------------------------------------------------------------------
// Metadata builders
// ---------------------------------------------------------------------------

/// Add Stripe connector auth headers + vault metadata header to a gRPC request.
fn add_vgs_stripe_metadata<T>(request: &mut Request<T>) {
    let auth = utils::credential_utils::load_connector_auth("stripe")
        .expect("Failed to load Stripe credentials");
    let api_key = match auth {
        domain_types::router_data::ConnectorAuthType::HeaderKey { api_key } => api_key.expose(),
        _ => panic!("Expected HeaderKey auth type for Stripe"),
    };

    request.metadata_mut().append(
        "x-connector",
        "stripe".parse().expect("parse x-connector"),
    );
    request
        .metadata_mut()
        .append("x-auth", "header-key".parse().expect("parse x-auth"));
    request
        .metadata_mut()
        .append("x-api-key", api_key.parse().expect("parse x-api-key"));
    request.metadata_mut().append(
        "x-merchant-id",
        "merchant_vault_test".parse().expect("parse x-merchant-id"),
    );
    request.metadata_mut().append(
        "x-request-id",
        format!("vault_test_{}", get_timestamp())
            .parse()
            .expect("parse x-request-id"),
    );
    request.metadata_mut().append(
        "x-tenant-id",
        "default".parse().expect("parse x-tenant-id"),
    );
    request.metadata_mut().append(
        "x-connector-request-reference-id",
        format!("vault_ref_{}", get_timestamp())
            .parse()
            .expect("parse ref id"),
    );

    // Add VGS vault metadata
    let vault_creds = utils::credential_utils::load_vault_credentials("vault_vgs")
        .expect("Failed to load VGS vault credentials");
    let vault_header = utils::credential_utils::build_vault_metadata_header(&vault_creds);
    request.metadata_mut().append(
        "x-external-vault-metadata",
        vault_header.parse().expect("parse vault metadata"),
    );
}

/// Add Adyen connector auth headers + vault metadata header to a gRPC request.
fn add_hs_vault_adyen_metadata<T>(request: &mut Request<T>) {
    let auth = utils::credential_utils::load_connector_auth("adyen")
        .expect("Failed to load Adyen credentials");
    let (api_key, key1) = match auth {
        domain_types::router_data::ConnectorAuthType::BodyKey { api_key, key1 } => {
            (api_key.expose(), key1.expose())
        }
        _ => panic!("Expected BodyKey auth type for Adyen"),
    };

    request
        .metadata_mut()
        .append("x-connector", "adyen".parse().expect("parse x-connector"));
    request
        .metadata_mut()
        .append("x-auth", "body-key".parse().expect("parse x-auth"));
    request
        .metadata_mut()
        .append("x-api-key", api_key.parse().expect("parse x-api-key"));
    request
        .metadata_mut()
        .append("x-key1", key1.parse().expect("parse x-key1"));
    request.metadata_mut().append(
        "x-merchant-id",
        "merchant_vault_test".parse().expect("parse x-merchant-id"),
    );
    request.metadata_mut().append(
        "x-request-id",
        format!("vault_test_{}", get_timestamp())
            .parse()
            .expect("parse x-request-id"),
    );
    request.metadata_mut().append(
        "x-tenant-id",
        "default".parse().expect("parse x-tenant-id"),
    );
    request.metadata_mut().append(
        "x-connector-request-reference-id",
        format!("vault_ref_{}", get_timestamp())
            .parse()
            .expect("parse ref id"),
    );

    // Add Hyperswitch Vault metadata
    let vault_creds = utils::credential_utils::load_vault_credentials("vault_hyperswitch")
        .expect("Failed to load Hyperswitch Vault credentials");
    let vault_header = utils::credential_utils::build_vault_metadata_header(&vault_creds);
    request.metadata_mut().append(
        "x-external-vault-metadata",
        vault_header.parse().expect("parse vault metadata"),
    );
}

// ---------------------------------------------------------------------------
// Request builders
// ---------------------------------------------------------------------------

/// Build a VGS proxy authorize request using `card_proxy` (ProxyCardDetails).
///
/// For VGS, the card_number contains VGS-aliased tokens rather than raw PANs.
/// In the test we use real card numbers because VGS sandbox transparently proxies them.
fn create_vgs_authorize_request() -> PaymentServiceAuthorizeRequest {
    let proxy_card = ProxyCardDetails {
        card_number: Some(Secret::new("4111111111111111".to_string())),
        card_exp_month: Some(Secret::new("12".to_string())),
        card_exp_year: Some(Secret::new("2050".to_string())),
        card_cvc: Some(Secret::new("123".to_string())),
        card_holder_name: Some(Secret::new("Vault Test User".to_string())),
        card_issuer: None,
        card_network: Some(1), // Visa
        card_type: None,
        card_issuing_country_alpha2: None,
        bank_code: None,
        nick_name: None,
    };

    PaymentServiceAuthorizeRequest {
        amount: Some(grpc_api_types::payments::Money {
            minor_amount: 1500,
            currency: i32::from(Currency::Usd),
        }),
        payment_method: Some(PaymentMethod {
            payment_method: Some(payment_method::PaymentMethod::CardProxy(proxy_card)),
        }),
        return_url: Some("https://example.com/return".to_string()),
        webhook_url: Some("https://example.com/webhook".to_string()),
        customer: Some(grpc_api_types::payments::Customer {
            email: Some("vault-test@example.com".to_string().into()),
            name: None,
            id: Some("cus_vault_test".to_string()),
            connector_customer_id: None,
            phone_number: None,
            phone_country_code: None,
        }),
        address: Some(grpc_api_types::payments::PaymentAddress::default()),
        auth_type: i32::from(AuthenticationType::NoThreeDs),
        merchant_transaction_id: Some(Identifier {
            id_type: Some(IdType::Id(generate_unique_id("vgs_stripe_test"))),
        }),
        enrolled_for_3ds: Some(false),
        request_incremental_authorization: Some(false),
        capture_method: Some(i32::from(CaptureMethod::Automatic)),
        ..Default::default()
    }
}

/// Pre-tokenize a card via Hyperswitch Vault's `/v2/payment-methods` endpoint,
/// then build an authorize request with the resulting payment method ID.
///
/// Returns `(authorize_request, payment_method_id)`.
async fn create_hs_vault_adyen_authorize_request(
) -> (PaymentServiceAuthorizeRequest, String) {
    let vault_creds = utils::credential_utils::load_vault_credentials("vault_hyperswitch")
        .expect("Failed to load Hyperswitch Vault credentials");

    let api_key = vault_creds
        .metadata
        .get("vault_auth_data")
        .and_then(|v| v.get("api_key"))
        .and_then(|v| v.as_str())
        .expect("Missing vault api_key");
    let profile_id = vault_creds
        .metadata
        .get("vault_auth_data")
        .and_then(|v| v.get("api_secret"))
        .and_then(|v| v.as_str())
        .expect("Missing vault profile_id (api_secret)");

    // Step 1: Pre-tokenize card via HS Vault
    let client = reqwest::Client::new();
    let tokenize_body = serde_json::json!({
        "payment_method": "card",
        "payment_method_type": "credit",
        "payment_method_subtype": "credit",
        "card": {
            "card_number": "4111111111111111",
            "card_exp_month": "03",
            "card_exp_year": "2030",
            "card_holder_name": "Vault Test User",
            "card_cvc": "737"
        },
        "customer_id": "vault_test_customer"
    });

    let vault_endpoint = vault_creds
        .metadata
        .get("vault_endpoint")
        .and_then(|v| v.as_str())
        .expect("Missing vault_endpoint");
    // The tokenize endpoint is /v2/payment-methods (not /v2/proxy)
    let tokenize_url = vault_endpoint.replace("/v2/proxy", "/v2/payment-methods");

    let resp = client
        .post(&tokenize_url)
        .header("Content-Type", "application/json")
        .header("api-key", api_key)
        .header("x-profile-id", profile_id)
        .json(&tokenize_body)
        .send()
        .await
        .expect("Failed to call HS Vault tokenize endpoint");

    let resp_status = resp.status();
    let resp_body: serde_json::Value = resp
        .json()
        .await
        .expect("Failed to parse HS Vault tokenize response");

    assert!(
        resp_status.is_success(),
        "HS Vault tokenize failed: status={}, body={}",
        resp_status,
        resp_body
    );

    let pm_id = resp_body["id"]
        .as_str()
        .expect("No payment method ID in tokenize response")
        .to_string();

    // Step 2: Build authorize request with tokenized card references
    // For HS Vault, the card_number is the payment method ID (token)
    let proxy_card = ProxyCardDetails {
        card_number: Some(Secret::new(pm_id.clone())),
        card_exp_month: Some(Secret::new("03".to_string())),
        card_exp_year: Some(Secret::new("2030".to_string())),
        card_cvc: Some(Secret::new("737".to_string())),
        card_holder_name: Some(Secret::new("Vault Test User".to_string())),
        card_issuer: None,
        card_network: Some(1), // Visa
        card_type: None,
        card_issuing_country_alpha2: None,
        bank_code: None,
        nick_name: None,
    };

    let request = PaymentServiceAuthorizeRequest {
        amount: Some(grpc_api_types::payments::Money {
            minor_amount: 2000,
            currency: i32::from(Currency::Eur),
        }),
        payment_method: Some(PaymentMethod {
            payment_method: Some(payment_method::PaymentMethod::CardProxy(proxy_card)),
        }),
        return_url: Some("https://example.com/return".to_string()),
        webhook_url: Some("https://example.com/webhook".to_string()),
        customer: Some(grpc_api_types::payments::Customer {
            email: Some("vault-test@example.com".to_string().into()),
            name: None,
            id: Some("vault_test_customer".to_string()),
            connector_customer_id: None,
            phone_number: None,
            phone_country_code: None,
        }),
        address: Some(grpc_api_types::payments::PaymentAddress::default()),
        auth_type: i32::from(AuthenticationType::NoThreeDs),
        merchant_transaction_id: Some(Identifier {
            id_type: Some(IdType::Id(generate_unique_id("hs_vault_adyen_test"))),
        }),
        enrolled_for_3ds: Some(false),
        request_incremental_authorization: Some(false),
        capture_method: Some(i32::from(CaptureMethod::Automatic)),
        browser_info: Some(BrowserInformation {
            user_agent: Some("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)".to_string()),
            accept_header: Some("text/html".to_string()),
            language: Some("en-US".to_string()),
            color_depth: Some(24),
            screen_height: Some(1080),
            screen_width: Some(1920),
            time_zone_offset_minutes: Some(-330),
            java_enabled: Some(false),
            java_script_enabled: Some(true),
            ip_address: Some("127.0.0.1".to_string()),
            os_type: None,
            os_version: None,
            accept_language: None,
            referer: None,
            device_model: None,
        }),
        ..Default::default()
    };

    (request, pm_id)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Test: VGS proxy → Stripe authorize (auto-capture)
///
/// This test sends a payment through the VGS proxy to Stripe's sandbox.
/// The card data goes through VGS outbound proxy which can alias/dealias tokens.
/// In sandbox mode, VGS transparently proxies real test card numbers.
#[tokio::test]
async fn test_vgs_stripe_authorize() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        let request = create_vgs_authorize_request();
        let mut grpc_request = Request::new(request);
        add_vgs_stripe_metadata(&mut grpc_request);

        let response = client
            .authorize(grpc_request)
            .await
            .expect("gRPC authorize call failed for VGS+Stripe")
            .into_inner();

        let txn_id = extract_transaction_id(&response);
        println!(
            "VGS+Stripe vault test: transaction_id={}, status={}",
            txn_id, response.status
        );

        assert_eq!(
            response.status,
            i32::from(PaymentStatus::Charged),
            "VGS+Stripe payment should be Charged (auto-capture). Got status: {}",
            response.status
        );
    });
}

/// Test: Hyperswitch Vault → Adyen authorize (auto-capture)
///
/// This test:
/// 1. Pre-tokenizes a card via HS Vault's `/v2/payment-methods` endpoint
/// 2. Sends the payment method ID through the vault proxy to Adyen's sandbox
/// 3. The vault proxy de-tokenizes and forwards raw card data to Adyen
///
/// Note: HS Vault only works with JSON-native connectors (Adyen, Checkout.com),
/// NOT with form-urlencoded connectors (Stripe).
#[tokio::test]
async fn test_hyperswitch_vault_adyen_authorize() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        let (request, pm_id) = create_hs_vault_adyen_authorize_request().await;
        println!("HS Vault tokenized payment method ID: {}", pm_id);

        let mut grpc_request = Request::new(request);
        add_hs_vault_adyen_metadata(&mut grpc_request);

        let response = client
            .authorize(grpc_request)
            .await
            .expect("gRPC authorize call failed for HSVault+Adyen")
            .into_inner();

        let txn_id = extract_transaction_id(&response);
        println!(
            "HSVault+Adyen vault test: transaction_id={}, status={}",
            txn_id, response.status
        );

        assert_eq!(
            response.status,
            i32::from(PaymentStatus::Charged),
            "HSVault+Adyen payment should be Charged (auto-capture). Got status: {}",
            response.status
        );
    });
}
