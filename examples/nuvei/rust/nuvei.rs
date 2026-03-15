// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py nuvei
//
// Nuvei — all scenarios and flows in one file.
// Run a scenario:  cargo run --example nuvei -- process_checkout_card

use grpc_api_types::payments::*;
use hyperswitch_payments_client::ConnectorClient;
use std::collections::HashMap;


fn build_client() -> ConnectorClient {
    let config = ConnectorConfig {
        connector: Connector::Nuvei.into(),
        environment: Environment::Sandbox.into(),
        // auth: Some(ConnectorAuth { ... })  — set your connector auth here
        ..Default::default()
    };
    ConnectorClient::new(config, None).unwrap()
}


// Flow: PaymentService.Capture
pub async fn capture(client: &ConnectorClient, merchant_transaction_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    let response = client.capture(serde_json::from_value::<PaymentServiceCaptureRequest>(serde_json::json!({
    "merchant_capture_id": "probe_capture_001",  // Identification
    "connector_transaction_id": "probe_connector_txn_001",
    "amount_to_capture": {  // Capture Details
        "minor_amount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
        "currency": "USD",  // ISO 4217 currency code (e.g., "USD", "EUR")
    },
    })).unwrap_or_default(), &HashMap::new(), None).await?;
    return Ok(format!("status: {:?}", response.status()));
}

// Flow: MerchantAuthenticationService.CreateSessionToken
pub async fn create_session_token(client: &ConnectorClient, merchant_transaction_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    let response = client.create_session_token(serde_json::from_value::<MerchantAuthenticationServiceCreateSessionTokenRequest>(serde_json::json!({
    "amount": {  // Amount Information
        "minor_amount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
        "currency": "USD",  // ISO 4217 currency code (e.g., "USD", "EUR")
    },
    })).unwrap_or_default(), &HashMap::new(), None).await?;
    return Ok(format!("status: {:?}", response.status()));
}

// Flow: PaymentService.Get
pub async fn get(client: &ConnectorClient, merchant_transaction_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    let response = client.get(serde_json::from_value::<PaymentServiceGetRequest>(serde_json::json!({
    "connector_transaction_id": "probe_connector_txn_001",
    "amount": {  // Amount Information
        "minor_amount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
        "currency": "USD",  // ISO 4217 currency code (e.g., "USD", "EUR")
    },
    })).unwrap_or_default(), &HashMap::new(), None).await?;
    return Ok(format!("status: {:?}", response.status()));
}

// Flow: PaymentService.Refund
pub async fn refund(client: &ConnectorClient, merchant_transaction_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    let response = client.refund(serde_json::from_value::<PaymentServiceRefundRequest>(serde_json::json!({
    "merchant_refund_id": "probe_refund_001",  // Identification
    "connector_transaction_id": "probe_connector_txn_001",
    "payment_amount": 1000,  // Amount Information
    "refund_amount": {
        "minor_amount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
        "currency": "USD",  // ISO 4217 currency code (e.g., "USD", "EUR")
    },
    "reason": "customer_request",  // Reason for the refund
    })).unwrap_or_default(), &HashMap::new(), None).await?;
    return Ok(format!("status: {:?}", response.status()));
}

// Flow: PaymentService.Void
pub async fn void(client: &ConnectorClient, merchant_transaction_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    let response = client.void(serde_json::from_value::<PaymentServiceVoidRequest>(serde_json::json!({
    "merchant_void_id": "probe_void_001",  // Identification
    "connector_transaction_id": "probe_connector_txn_001",
    "amount": {  // Amount Information
        "minor_amount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
        "currency": "USD",  // ISO 4217 currency code (e.g., "USD", "EUR")
    },
    })).unwrap_or_default(), &HashMap::new(), None).await?;
    return Ok(format!("status: {:?}", response.status()));
}


#[tokio::main]
async fn main() {
    let client = build_client();
    let flow = std::env::args().nth(1).unwrap_or_else(|| "capture".to_string());
    let result: Result<String, Box<dyn std::error::Error>> = match flow.as_str() {
        "capture" => capture(&client, "order_001").await,
        "create_session_token" => create_session_token(&client, "order_001").await,
        "get" => get(&client, "order_001").await,
        "refund" => refund(&client, "order_001").await,
        "void" => void(&client, "order_001").await,
        _ => { eprintln!("Unknown flow: {}. Available: capture, create_session_token, get, refund, void", flow); return; }
    };
    match result {
        Ok(msg) => println!("✓ {msg}"),
        Err(e) => eprintln!("✗ {e}"),
    }
}
