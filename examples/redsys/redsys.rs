// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py redsys
//
// Redsys — all scenarios and flows in one file.
// Run a scenario:  cargo run --example redsys -- process_checkout_card

use grpc_api_types::payments::*;
use hyperswitch_payments_client::ConnectorClient;
use std::collections::HashMap;

#[allow(dead_code)]
fn build_client() -> ConnectorClient {
    // Set connector_config to authenticate: use ConnectorSpecificConfig with your RedsysConfig
    let config = ConnectorConfig {
        connector_config: None,  // TODO: Some(ConnectorSpecificConfig { config: Some(...) })
        options: Some(SdkOptions {
            environment: Environment::Sandbox.into(),
        }),
    };
    ConnectorClient::new(config, None).unwrap()
}

// Flow: PaymentService.authenticate
#[allow(dead_code)]
pub async fn authenticate(client: &ConnectorClient, _merchant_transaction_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    let response = client.authenticate(serde_json::from_value::<>(serde_json::json!({
    "amount": {
        "minor_amount": 1000,
        "currency": "USD",
    },
    "payment_method": {
        "card": {
            "card_number": "4111111111111111",
            "card_exp_month": "03",
            "card_exp_year": "2030",
            "card_cvc": "737",
            "card_holder_name": "John Doe",
        },
    },
    "address": {
        "billing_address": {
        },
    },
    "authentication_data": {
        "eci": "05",
        "cavv": "AAAAAAAAAA==",
        "threeds_server_transaction_id": "probe-3ds-txn-001",
        "message_version": "2.1.0",
        "ds_transaction_id": "probe-ds-txn-001",
    },
    "return_url": "https://example.com/3ds-return",
    "continue_redirection_url": "https://example.com/3ds-continue",
    "browser_info": {
        "color_depth": 24,
        "screen_height": 900,
        "screen_width": 1440,
        "java_enabled": false,
        "java_script_enabled": true,
        "language": "en-US",
        "time_zone_offset_minutes": -480,
        "accept_header": "application/json",
        "user_agent": "Mozilla/5.0 (probe-bot)",
        "accept_language": "en-US,en;q=0.9",
        "ip_address": "1.2.3.4",
    },
    })).unwrap_or_default(), &HashMap::new(), None).await?;
    Ok(format!("status: {:?}", response.status()))
}

// Flow: PaymentService.capture
#[allow(dead_code)]
pub async fn capture(client: &ConnectorClient, _merchant_transaction_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    let response = client.capture(serde_json::from_value::<>(serde_json::json!({
    "merchant_capture_id": "probe_capture_001",
    "connector_transaction_id": "probe_connector_txn_001",
    "amount_to_capture": {
        "minor_amount": 1000,
        "currency": "USD",
    },
    })).unwrap_or_default(), &HashMap::new(), None).await?;
    Ok(format!("status: {:?}", response.status()))
}

// Flow: PaymentService.get
#[allow(dead_code)]
pub async fn get(client: &ConnectorClient, _merchant_transaction_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    let response = client.get(serde_json::from_value::<>(serde_json::json!({
    "merchant_transaction_id": "probe_merchant_txn_001",
    "connector_transaction_id": "probe_connector_txn_001",
    "amount": {
        "minor_amount": 1000,
        "currency": "USD",
    },
    })).unwrap_or_default(), &HashMap::new(), None).await?;
    Ok(format!("status: {:?}", response.status()))
}

// Flow: PaymentService.pre_authenticate
#[allow(dead_code)]
pub async fn pre_authenticate(client: &ConnectorClient, _merchant_transaction_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    let response = client.pre_authenticate(serde_json::from_value::<>(serde_json::json!({
    "amount": {
        "minor_amount": 1000,
        "currency": "USD",
    },
    "payment_method": {
        "card": {
            "card_number": "4111111111111111",
            "card_exp_month": "03",
            "card_exp_year": "2030",
            "card_cvc": "737",
            "card_holder_name": "John Doe",
        },
    },
    "address": {
        "billing_address": {
        },
    },
    "enrolled_for_3ds": false,
    "return_url": "https://example.com/3ds-return",
    })).unwrap_or_default(), &HashMap::new(), None).await?;
    Ok(format!("status: {:?}", response.status()))
}

// Flow: PaymentService.refund
#[allow(dead_code)]
pub async fn refund(client: &ConnectorClient, _merchant_transaction_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    let response = client.refund(serde_json::from_value::<>(serde_json::json!({
    "merchant_refund_id": "probe_refund_001",
    "connector_transaction_id": "probe_connector_txn_001",
    "payment_amount": 1000,
    "refund_amount": {
        "minor_amount": 1000,
        "currency": "USD",
    },
    "reason": "customer_request",
    })).unwrap_or_default(), &HashMap::new(), None).await?;
    Ok(format!("status: {:?}", response.status()))
}

// Flow: PaymentService.refund_get
#[allow(dead_code)]
pub async fn refund_get(client: &ConnectorClient, _merchant_transaction_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    let response = client.refund_get(serde_json::from_value::<>(serde_json::json!({
    "merchant_refund_id": "probe_refund_001",
    "connector_transaction_id": "probe_connector_txn_001",
    "refund_id": "probe_refund_id_001",
    })).unwrap_or_default(), &HashMap::new(), None).await?;
    Ok(format!("status: {:?}", response.status()))
}

// Flow: PaymentService.void
#[allow(dead_code)]
pub async fn void(client: &ConnectorClient, _merchant_transaction_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    let response = client.void(serde_json::from_value::<>(serde_json::json!({
    "merchant_void_id": "probe_void_001",
    "connector_transaction_id": "probe_connector_txn_001",
    "amount": {
        "minor_amount": 1000,
        "currency": "USD",
    },
    })).unwrap_or_default(), &HashMap::new(), None).await?;
    Ok(format!("status: {:?}", response.status()))
}

#[allow(dead_code)]
#[tokio::main]
async fn main() {
    let client = build_client();
    let flow = std::env::args().nth(1).unwrap_or_else(|| "authenticate".to_string());
    let result: Result<String, Box<dyn std::error::Error>> = match flow.as_str() {
        "authenticate" => authenticate(&client, "order_001").await,
        "capture" => capture(&client, "order_001").await,
        "get" => get(&client, "order_001").await,
        "pre_authenticate" => pre_authenticate(&client, "order_001").await,
        "refund" => refund(&client, "order_001").await,
        "refund_get" => refund_get(&client, "order_001").await,
        "void" => void(&client, "order_001").await,
        _ => { eprintln!("Unknown flow: {}. Available: authenticate, capture, get, pre_authenticate, refund, refund_get, void", flow); return; }
    };
    match result {
        Ok(msg) => println!("✓ {msg}"),
        Err(e) => eprintln!("✗ {e}"),
    }
}
