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
use grpc_api_types::payments::{
    payment_method, payment_service_client::PaymentServiceClient, AcceptanceType,
    AuthenticationType, CardDetails, Currency, CustomerAcceptance, FutureUsage, MandateAmountData,
    PaymentAddress, PaymentMethod, PaymentServiceSetupRecurringRequest, PaymentStatus,
    SetupMandateDetails,
};
use grpc_api_types::payments::mandate_type::MandateType as MandateTypeInner;
use grpc_api_types::payments::MandateType;
use tonic::{transport::Channel, Request};
use uuid::Uuid;

const CONNECTOR_NAME: &str = "braintree";
const AUTH_TYPE: &str = "signature-key";
const MERCHANT_ID: &str = "merchant_17555143863";

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

    let (api_key, key1, api_secret) = match auth {
        domain_types::router_data::ConnectorAuthType::SignatureKey {
            api_key,
            key1,
            api_secret,
        } => (api_key.expose(), key1.expose(), api_secret.expose()),
        _ => panic!("Expected SignatureKey auth type for braintree"),
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
    request
        .metadata_mut()
        .append("x-key1", key1.parse().expect("Failed to parse x-key1"));
    request.metadata_mut().append(
        "x-api-secret",
        api_secret.parse().expect("Failed to parse x-api-secret"),
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

fn create_setup_recurring_request() -> PaymentServiceSetupRecurringRequest {
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

    let mut merchant_account_metadata_map = HashMap::new();
    merchant_account_metadata_map.insert("merchant_account_id".to_string(), "Anand".to_string());
    merchant_account_metadata_map
        .insert("merchant_config_currency".to_string(), "USD".to_string());
    merchant_account_metadata_map.insert("currency".to_string(), "USD".to_string());
    let merchant_account_metadata_json =
        serde_json::to_string(&merchant_account_metadata_map).unwrap();

    PaymentServiceSetupRecurringRequest {
        merchant_recurring_payment_id: generate_unique_id("braintree_mandate"),
        amount: Some(grpc_api_types::payments::Money {
            minor_amount: 0,
            currency: i32::from(Currency::Usd),
        }),
        payment_method: Some(PaymentMethod {
            payment_method: Some(payment_method::PaymentMethod::Card(card_details)),
        }),
        customer: Some(grpc_api_types::payments::Customer {
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
        auth_type: i32::from(AuthenticationType::NoThreeDs),
        setup_future_usage: Some(i32::from(FutureUsage::OffSession)),
        enrolled_for_3ds: false,
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
    grpc_test!(client, PaymentServiceClient<Channel>, {
        let request = create_setup_recurring_request();
        let mut grpc_request = Request::new(request);
        add_braintree_metadata(&mut grpc_request);

        let response = client
            .setup_recurring(grpc_request)
            .await
            .expect("gRPC setup_recurring call failed")
            .into_inner();

        assert!(
            response.status == i32::from(PaymentStatus::Charged)
                || response.status == i32::from(PaymentStatus::AuthenticationPending)
                || response.status == i32::from(PaymentStatus::Pending),
            "Setup mandate should be in Charged, AuthenticationPending, or Pending state, got: {}",
            response.status
        );
    });
}
