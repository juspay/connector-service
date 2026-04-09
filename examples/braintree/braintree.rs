// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py braintree
//
// Braintree — all scenarios and flows in one file.
// Run a scenario:  cargo run --example braintree -- process_checkout_card

use grpc_api_types::payments::*;
use hyperswitch_payments_client::ConnectorClient;
use std::collections::HashMap;
use grpc_api_types::payments::payment_method;

#[allow(dead_code)]
fn build_client() -> ConnectorClient {
    // Set connector_config to authenticate: use ConnectorSpecificConfig with your BraintreeConfig
    let config = ConnectorConfig {
        connector_config: None,  // TODO: Some(ConnectorSpecificConfig { config: Some(...) })
        options: Some(SdkOptions {
            environment: Environment::Sandbox.into(),
        }),
    };
    ConnectorClient::new(config, None).unwrap()
}

pub fn build_capture_request(connector_transaction_id: &str) -> PaymentServiceCaptureRequest {
    PaymentServiceCaptureRequest {
        merchant_capture_id: Some("probe_capture_001".to_string()),  // Identification.
        connector_transaction_id: connector_transaction_id.to_string(),
        amount_to_capture: Some(Money {  // Capture Details.
            minor_amount: 1000,  // Amount in minor units (e.g., 1000 = $10.00).
            currency: Currency::from_str_name("USD").unwrap_or_default().into(),  // ISO 4217 currency code (e.g., "USD", "EUR").
            ..Default::default()
        }),
        ..Default::default()
    }
}

pub fn build_create_client_authentication_token_request() -> MerchantAuthenticationServiceCreateClientAuthenticationTokenRequest {
    MerchantAuthenticationServiceCreateClientAuthenticationTokenRequest {
        merchant_client_session_id: "probe_sdk_session_001".to_string(),  // Infrastructure.
        // domain_context: {"payment": {"amount": {"minor_amount": 1000, "currency": "USD"}}}
        ..Default::default()
    }
}

pub fn build_get_request(connector_transaction_id: &str) -> PaymentServiceGetRequest {
    PaymentServiceGetRequest {
        merchant_transaction_id: Some("probe_merchant_txn_001".to_string()),  // Identification.
        connector_transaction_id: connector_transaction_id.to_string(),
        amount: Some(Money {  // Amount Information.
            minor_amount: 1000,  // Amount in minor units (e.g., 1000 = $10.00).
            currency: Currency::from_str_name("USD").unwrap_or_default().into(),  // ISO 4217 currency code (e.g., "USD", "EUR").
            ..Default::default()
        }),
        ..Default::default()
    }
}

pub fn build_refund_request(connector_transaction_id: &str) -> PaymentServiceRefundRequest {
    PaymentServiceRefundRequest {
        merchant_refund_id: Some("probe_refund_001".to_string()),  // Identification.
        connector_transaction_id: connector_transaction_id.to_string(),
        payment_amount: 1000,  // Amount Information.
        refund_amount: Some(Money {
            minor_amount: 1000,  // Amount in minor units (e.g., 1000 = $10.00).
            currency: Currency::from_str_name("USD").unwrap_or_default().into(),  // ISO 4217 currency code (e.g., "USD", "EUR").
            ..Default::default()
        }),
        reason: Some("customer_request".to_string()),  // Reason for the refund.
        ..Default::default()
    }
}

pub fn build_refund_get_request() -> RefundServiceGetRequest {
    RefundServiceGetRequest {
        merchant_refund_id: Some("probe_refund_001".to_string()),  // Identification.
        connector_transaction_id: "probe_connector_txn_001".to_string(),
        refund_id: "probe_refund_id_001".to_string(),
        refund_metadata: Some("{\"currency\":\"USD\"}".to_string()),  // Metadata specific to the refund sync.
        ..Default::default()
    }
}

pub fn build_tokenize_request() -> PaymentMethodServiceTokenizeRequest {
    PaymentMethodServiceTokenizeRequest {
        amount: Some(Money {  // Payment Information.
            minor_amount: 1000,  // Amount in minor units (e.g., 1000 = $10.00).
            currency: Currency::from_str_name("USD").unwrap_or_default().into(),  // ISO 4217 currency code (e.g., "USD", "EUR").
            ..Default::default()
        }),
        payment_method: Some(PaymentMethod {
            payment_method: Some(payment_method::PaymentMethod::Card(CardDetails {
                card_number: Some("4111111111111111".to_string()),  // Card Identification.
                card_exp_month: Some("03".to_string()),
                card_exp_year: Some("2030".to_string()),
                card_cvc: Some("737".to_string()),
                card_holder_name: Some("John Doe".to_string()),  // Cardholder Information.
                ..Default::default()
            })),
            ..Default::default()
        }),
        address: Some(PaymentAddress {  // Address Information.
            billing_address: Some(Address {
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    }
}

pub fn build_void_request(connector_transaction_id: &str) -> PaymentServiceVoidRequest {
    PaymentServiceVoidRequest {
        merchant_void_id: Some("probe_void_001".to_string()),  // Identification.
        connector_transaction_id: connector_transaction_id.to_string(),
        ..Default::default()
    }
}


// Flow: PaymentService.Capture
#[allow(dead_code)]
pub async fn capture(client: &ConnectorClient, _merchant_transaction_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    let response = client.capture(build_capture_request("probe_connector_txn_001"), &HashMap::new(), None).await?;
    Ok(format!("status: {:?}", response.status()))
}

// Flow: MerchantAuthenticationService.CreateClientAuthenticationToken
#[allow(dead_code)]
pub async fn create_client_authentication_token(client: &ConnectorClient, _merchant_transaction_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    let response = client.create_client_authentication_token(build_create_client_authentication_token_request(), &HashMap::new(), None).await?;
    Ok(format!("status: {:?}", response.status_code))
}

// Flow: PaymentService.Get
#[allow(dead_code)]
pub async fn get(client: &ConnectorClient, _merchant_transaction_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    let response = client.get(build_get_request("probe_connector_txn_001"), &HashMap::new(), None).await?;
    Ok(format!("status: {:?}", response.status()))
}

// Flow: PaymentService.Refund
#[allow(dead_code)]
pub async fn refund(client: &ConnectorClient, _merchant_transaction_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    let response = client.refund(build_refund_request("probe_connector_txn_001"), &HashMap::new(), None).await?;
    Ok(format!("status: {:?}", response.status()))
}

// Flow: RefundService.Get
#[allow(dead_code)]
pub async fn refund_get(client: &ConnectorClient, _merchant_transaction_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    let response = client.refund_get(build_refund_get_request(), &HashMap::new(), None).await?;
    Ok(format!("status: {:?}", response.status()))
}

// Flow: PaymentMethodService.Tokenize
#[allow(dead_code)]
pub async fn tokenize(client: &ConnectorClient, _merchant_transaction_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    let response = client.tokenize(build_tokenize_request(), &HashMap::new(), None).await?;
    Ok(format!("token: {}", response.payment_method_token))
}

// Flow: PaymentService.Void
#[allow(dead_code)]
pub async fn void(client: &ConnectorClient, _merchant_transaction_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    let response = client.void(build_void_request("probe_connector_txn_001"), &HashMap::new(), None).await?;
    Ok(format!("status: {:?}", response.status()))
}

#[allow(dead_code)]
#[tokio::main]
async fn main() {
    let client = build_client();
    let flow = std::env::args().nth(1).unwrap_or_else(|| "capture".to_string());
    let result: Result<String, Box<dyn std::error::Error>> = match flow.as_str() {
        "capture" => capture(&client, "order_001").await,
        "create_client_authentication_token" => create_client_authentication_token(&client, "order_001").await,
        "get" => get(&client, "order_001").await,
        "refund" => refund(&client, "order_001").await,
        "refund_get" => refund_get(&client, "order_001").await,
        "tokenize" => tokenize(&client, "order_001").await,
        "void" => void(&client, "order_001").await,
        _ => { eprintln!("Unknown flow: {}. Available: capture, create_client_authentication_token, get, refund, refund_get, tokenize, void", flow); return; }
    };
    match result {
        Ok(msg) => println!("✓ {msg}"),
        Err(e) => eprintln!("✗ {e}"),
    }
}
