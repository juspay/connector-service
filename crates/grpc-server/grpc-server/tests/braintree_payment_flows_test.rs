#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]

use grpc_server::app;
use hyperswitch_masking::{ExposeInterface, Secret};
use ucs_env::configs;
mod common;
mod utils;

use std::{
    collections::HashMap,
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

use cards::CardNumber;
use grpc_api_types::payments::mandate_type::MandateType as MandateTypeInner;
use grpc_api_types::payments::MandateType;
use grpc_api_types::payments::{
    payment_method, payment_method_service_client::PaymentMethodServiceClient,
    payment_service_client::PaymentServiceClient, AcceptanceType, CardDetails, Currency, Customer,
    CustomerAcceptance, FutureUsage, MandateAmountData, Money, PaymentAddress, PaymentMethod,
    PaymentMethodServiceTokenizeRequest, PaymentServiceTokenSetupRecurringRequest, PaymentStatus,
    SetupMandateDetails,
};
use tonic::{transport::Channel, Request};
use uuid::Uuid;

const CONNECTOR_NAME: &str = "braintree";
const MERCHANT_ID: &str = "merchant_braintree_test";

const TEST_CARD_NUMBER: &str = "4242424242424242";
const TEST_CARD_EXP_MONTH: &str = "10";
const TEST_CARD_EXP_YEAR: &str = "25";
const TEST_CARD_CVC: &str = "123";
const TEST_CARD_HOLDER: &str = "Test User";

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

    // Use x-connector-config with full Braintree config so merchant_account_id is available.
    // Repeated proto fields (apple_pay_supported_networks etc.) must be present as empty arrays.
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

fn create_card_payment_method() -> PaymentMethod {
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
    PaymentMethod {
        payment_method: Some(payment_method::PaymentMethod::Card(card_details)),
    }
}

fn create_tokenize_request() -> PaymentMethodServiceTokenizeRequest {
    PaymentMethodServiceTokenizeRequest {
        amount: Some(Money {
            minor_amount: 0,
            currency: i32::from(Currency::Usd),
        }),
        payment_method: Some(create_card_payment_method()),
        customer: Some(Customer {
            email: Some(format!("test_{}@example.com", get_timestamp()).into()),
            name: Some(TEST_CARD_HOLDER.to_string()),
            id: None,
            connector_customer_id: None,
            phone_number: None,
            phone_country_code: None,
        }),
        address: Some(PaymentAddress::default()),
        ..Default::default()
    }
}

fn create_token_setup_recurring_request(
    connector_token: String,
) -> PaymentServiceTokenSetupRecurringRequest {
    let mut merchant_account_metadata_map = HashMap::new();
    merchant_account_metadata_map.insert("merchant_account_id".to_string(), "test_merchant_account".to_string());
    merchant_account_metadata_map.insert("merchant_config_currency".to_string(), "USD".to_string());
    merchant_account_metadata_map.insert("currency".to_string(), "USD".to_string());
    let merchant_account_metadata_json =
        serde_json::to_string(&merchant_account_metadata_map).unwrap();

    PaymentServiceTokenSetupRecurringRequest {
        merchant_recurring_payment_id: generate_unique_id("braintree_mandate"),
        amount: Some(Money {
            minor_amount: 0,
            currency: i32::from(Currency::Usd),
        }),
        connector_token: Some(Secret::new(connector_token)),
        customer: Some(Customer {
            email: Some(format!("test_{}@example.com", get_timestamp()).into()),
            name: Some(TEST_CARD_HOLDER.to_string()),
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
        metadata: Some(Secret::new(merchant_account_metadata_json)),
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

#[tokio::test]
async fn test_setup_mandate() {
    grpc_test!(
        [
            pm_client: PaymentMethodServiceClient<Channel>,
            payment_client: PaymentServiceClient<Channel>
        ],
        {
            // Step 1: Tokenize card to get a payment method token (Braintree nonce/vaultToken).
            // SetupMandate transformer only accepts PaymentMethodToken, not raw card data.
            let tokenize_request = create_tokenize_request();
            let mut tok_grpc_request = Request::new(tokenize_request);
            add_braintree_metadata(&mut tok_grpc_request);

            let tokenize_response = pm_client
                .tokenize(tok_grpc_request)
                .await
                .expect("gRPC Tokenize call failed")
                .into_inner();

            assert!(
                tokenize_response.error.is_none(),
                "Tokenize should succeed, got error: {:?}",
                tokenize_response.error
            );

            let token = tokenize_response.payment_method_token;
            assert!(!token.is_empty(), "Tokenize should return a non-empty token");

            // Step 2: Use the token in TokenSetupRecurring (vaultPaymentMethod flow).
            let setup_request = create_token_setup_recurring_request(token);
            let mut setup_grpc_request = Request::new(setup_request);
            add_braintree_metadata(&mut setup_grpc_request);

            let response = payment_client
                .token_setup_recurring(setup_grpc_request)
                .await
                .expect("gRPC TokenSetupRecurring call failed")
                .into_inner();

            assert!(
                response.status == i32::from(PaymentStatus::Charged)
                    || response.status == i32::from(PaymentStatus::AuthenticationPending)
                    || response.status == i32::from(PaymentStatus::Pending),
                "Setup mandate should be in Charged, AuthenticationPending, or Pending state, got: {}",
                response.status
            );
        }
    );
}

#[test]
fn test_braintree_config_deser() {
    let json = r#"{"config":{"Braintree":{"public_key":"testkey","private_key":"testsecret","merchant_account_id":"test_merchant_account","merchant_config_currency":"USD","apple_pay_supported_networks":[],"apple_pay_merchant_capabilities":[],"gpay_allowed_auth_methods":[],"gpay_allowed_card_networks":[]}}}"#;
    let result: Result<grpc_api_types::payments::ConnectorSpecificConfig, _> =
        serde_json::from_str(json);
    assert!(result.is_ok(), "Failed: {:?}", result.err());
}
