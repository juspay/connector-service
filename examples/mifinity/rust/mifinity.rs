// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py mifinity
//
// Mifinity — all scenarios and flows in one file.
// Run a scenario:  cargo run --example mifinity -- process_checkout_card

use grpc_api_types::payments::*;
use hyperswitch_payments_client::ConnectorClient;
use std::collections::HashMap;


fn build_client() -> ConnectorClient {
    let config = ConnectorConfig {
        connector: Connector::Mifinity.into(),
        environment: Environment::Sandbox.into(),
        // auth: Some(ConnectorAuth { ... })  — set your connector auth here
        ..Default::default()
    };
    ConnectorClient::new(config, None).unwrap()
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


#[tokio::main]
async fn main() {
    let client = build_client();
    let flow = std::env::args().nth(1).unwrap_or_else(|| "get".to_string());
    let result: Result<String, Box<dyn std::error::Error>> = match flow.as_str() {
        "get" => get(&client, "order_001").await,
        _ => { eprintln!("Unknown flow: {}. Available: get", flow); return; }
    };
    match result {
        Ok(msg) => println!("✓ {msg}"),
        Err(e) => eprintln!("✗ {e}"),
    }
}
