#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]

use grpc_server::app;
use hyperswitch_masking::{ExposeInterface, Secret};
use ucs_env::configs;
mod common;
mod utils;

use std::time::{SystemTime, UNIX_EPOCH};

use grpc_api_types::payments::{
    payment_service_client::PaymentServiceClient, AcceptanceType, Currency, CustomerAcceptance,
    FutureUsage, MandateAmountData, MandateType, PaymentAddress, PaymentServiceTokenSetupRecurringRequest,
    PaymentStatus, SetupMandateDetails,
};
use grpc_api_types::payments::mandate_type::MandateType as MandateTypeInner;
use tonic::{transport::Channel, Request};
use uuid::Uuid;

const CONNECTOR_NAME: &str = "braintree";
const MERCHANT_ID: &str = "merchant_braintree_test";

// Braintree sandbox fake nonces for testing
// https://developer.paypal.com/braintree/docs/reference/general/testing
const FAKE_VALID_NONCE: &str = "fake-valid-nonce";
const FAKE_PROCESSOR_DECLINED_NONCE: &str = "fake-processor-declined-visa-nonce";

fn get_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn generate_unique_id(prefix: &str) -> String {
    format!("{}_{}", prefix, Uuid::new_v4())
}

fn add_braintree_metadata<T>(request: &mut Request<T>) {
    let auth = utils::credential_utils::load_connector_auth(CONNECTOR_NAME)
        .expect("Failed to load braintree credentials");

    let (api_key, _key1, api_secret) = match auth {
        domain_types::router_data::ConnectorAuthType::SignatureKey {
            api_key,
            key1,
            api_secret,
        } => (api_key.expose(), key1.expose(), api_secret.expose()),
        _ => panic!("Expected SignatureKey auth type for braintree"),
    };

    let metadata = utils::credential_utils::load_connector_metadata(CONNECTOR_NAME)
        .expect("Failed to load braintree metadata");
    let merchant_account_id = metadata
        .get("merchant_account_id")
        .expect("merchant_account_id missing from braintree metadata")
        .clone();
    let merchant_config_currency = metadata
        .get("merchant_config_currency")
        .cloned()
        .unwrap_or_else(|| "USD".to_string());

    // x-connector-config with full Braintree config; repeated fields must be empty arrays.
    let connector_config_json = format!(
        r#"{{"config":{{"Braintree":{{"public_key":"{public_key}","private_key":"{private_key}","merchant_account_id":"{merchant_account_id}","merchant_config_currency":"{merchant_config_currency}","apple_pay_supported_networks":[],"apple_pay_merchant_capabilities":[],"gpay_allowed_auth_methods":[],"gpay_allowed_card_networks":[]}}}}}}"#,
        public_key = api_key,
        private_key = api_secret,
        merchant_account_id = merchant_account_id,
        merchant_config_currency = merchant_config_currency,
    );
    request.metadata_mut().insert(
        "x-connector-config",
        connector_config_json
            .parse()
            .expect("Failed to parse x-connector-config"),
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

/// Add bad credentials metadata for negative auth tests.
fn add_bad_braintree_metadata<T>(request: &mut Request<T>) {
    let connector_config_json = r#"{"config":{"Braintree":{"public_key":"bad_key","private_key":"bad_secret","merchant_account_id":"bad_account","merchant_config_currency":"USD","apple_pay_supported_networks":[],"apple_pay_merchant_capabilities":[],"gpay_allowed_auth_methods":[],"gpay_allowed_card_networks":[]}}}"#;
    request.metadata_mut().insert(
        "x-connector-config",
        connector_config_json
            .parse()
            .expect("Failed to parse x-connector-config"),
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

fn create_token_setup_recurring_request(
    nonce: &str,
) -> PaymentServiceTokenSetupRecurringRequest {
    PaymentServiceTokenSetupRecurringRequest {
        merchant_recurring_payment_id: generate_unique_id("braintree_mandate"),
        amount: Some(grpc_api_types::payments::Money {
            minor_amount: 0,
            currency: i32::from(Currency::Usd),
        }),
        connector_token: Some(Secret::new(nonce.to_string())),
        customer: Some(grpc_api_types::payments::Customer {
            email: Some(format!("test_{}@example.com", get_timestamp()).into()),
            name: Some("Test User".to_string()),
            id: None,
            connector_customer_id: None,
            phone_number: None,
            phone_country_code: None,
        }),
        customer_acceptance: Some(CustomerAcceptance {
            acceptance_type: i32::from(AcceptanceType::Offline),
            accepted_at: 0,
            online_mandate_details: None,
        }),
        address: Some(PaymentAddress::default()),
        setup_future_usage: Some(i32::from(FutureUsage::OffSession)),
        setup_mandate_details: Some(SetupMandateDetails {
            update_mandate_id: None,
            customer_acceptance: None,
            mandate_type: Some(MandateType {
                mandate_type: Some(MandateTypeInner::MultiUse(MandateAmountData {
                    amount: 0,
                    currency: i32::from(Currency::Usd),
                    start_date: None,
                    end_date: None,
                    amount_type: Some("max".to_string()),
                    frequency: Some("monthly".to_string()),
                })),
            }),
        }),
        ..Default::default()
    }
}

/// TC-1: Happy path — card nonce vaults successfully, status = Charged,
/// connector_transaction_id (verification.id) and connector_mandate_id (paymentMethod.id) present.
#[tokio::test]
async fn test_setup_mandate_happy_path() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        let request = create_token_setup_recurring_request(FAKE_VALID_NONCE);
        let mut grpc_request = Request::new(request);
        add_braintree_metadata(&mut grpc_request);

        let response = client
            .token_setup_recurring(grpc_request)
            .await
            .expect("gRPC token_setup_recurring call failed")
            .into_inner();

        assert_eq!(
            response.status,
            i32::from(PaymentStatus::Charged),
            "Happy path: expected Charged, got status {}",
            response.status
        );

        // connector_recurring_payment_id maps to verification.id
        assert!(
            response.connector_recurring_payment_id.as_deref().map(|s| !s.is_empty()).unwrap_or(false),
            "Happy path: connector_transaction_id (verification.id) must be present"
        );

        // mandate_reference.connector_mandate_id maps to paymentMethod.id
        let mandate_ref = response
            .mandate_reference
            .as_ref()
            .expect("Happy path: mandate_reference must be present");
        let has_connector_mandate_id = match &mandate_ref.mandate_id_type {
            Some(grpc_api_types::payments::mandate_reference::MandateIdType::ConnectorMandateId(
                ref_id,
            )) => ref_id.connector_mandate_id.as_deref().map(|s| !s.is_empty()).unwrap_or(false),
            _ => false,
        };
        assert!(
            has_connector_mandate_id,
            "Happy path: connector_mandate_id (paymentMethod.id) must be present"
        );
    });
}

/// TC-2: Declined card — processor-declined nonce → status = Failure.
#[tokio::test]
async fn test_setup_mandate_declined_card() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        let request = create_token_setup_recurring_request(FAKE_PROCESSOR_DECLINED_NONCE);
        let mut grpc_request = Request::new(request);
        add_braintree_metadata(&mut grpc_request);

        let response = client
            .token_setup_recurring(grpc_request)
            .await
            .expect("gRPC token_setup_recurring call failed")
            .into_inner();

        assert_eq!(
            response.status,
            i32::from(PaymentStatus::Failure),
            "Declined card: expected Failure, got status {}",
            response.status
        );
        assert!(
            response.error.is_some(),
            "Declined card: error info should be present"
        );
    });
}

/// TC-3: Invalid credentials — bad API keys → gRPC error or Failure status.
#[tokio::test]
async fn test_setup_mandate_invalid_credentials() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        let request = create_token_setup_recurring_request(FAKE_VALID_NONCE);
        let mut grpc_request = Request::new(request);
        add_bad_braintree_metadata(&mut grpc_request);

        let result = client.token_setup_recurring(grpc_request).await;

        match result {
            Err(status) => {
                // gRPC-level error — acceptable for auth failure
                let code = status.code();
                assert!(
                    code == tonic::Code::Unauthenticated
                        || code == tonic::Code::PermissionDenied
                        || code == tonic::Code::Internal,
                    "Invalid credentials: unexpected gRPC error code {:?}",
                    code
                );
            }
            Ok(response) => {
                let inner = response.into_inner();
                assert_eq!(
                    inner.status,
                    i32::from(PaymentStatus::Failure),
                    "Invalid credentials: expected Failure status, got {}",
                    inner.status
                );
            }
        }
    });
}

/// TC-4: Missing required fields — empty connector_token → error response.
#[tokio::test]
async fn test_setup_mandate_missing_token() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        let request = create_token_setup_recurring_request("");
        let mut grpc_request = Request::new(request);
        add_braintree_metadata(&mut grpc_request);

        let result = client.token_setup_recurring(grpc_request).await;

        match result {
            Err(status) => {
                // gRPC-level validation error — acceptable
                assert!(
                    status.code() == tonic::Code::InvalidArgument
                        || status.code() == tonic::Code::FailedPrecondition
                        || status.code() == tonic::Code::Internal,
                    "Missing token: unexpected gRPC error code {:?}",
                    status.code()
                );
            }
            Ok(response) => {
                let inner = response.into_inner();
                assert_eq!(
                    inner.status,
                    i32::from(PaymentStatus::Failure),
                    "Missing token: expected Failure, got {}",
                    inner.status
                );
            }
        }
    });
}

/// Offline unit test: verify x-connector-config JSON deserializes correctly.
#[test]
fn test_braintree_config_deser() {
    let json = r#"{"config":{"Braintree":{"public_key":"testkey","private_key":"testsecret","merchant_account_id":"juspay","merchant_config_currency":"USD","apple_pay_supported_networks":[],"apple_pay_merchant_capabilities":[],"gpay_allowed_auth_methods":[],"gpay_allowed_card_networks":[]}}}"#;
    let result: Result<grpc_api_types::payments::ConnectorSpecificConfig, _> =
        serde_json::from_str(json);
    assert!(result.is_ok(), "Config deser failed: {:?}", result.err());
}
