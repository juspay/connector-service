// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py jpmorgan
//
// Jpmorgan — all scenarios and flows in one file.
// Run a scenario:  cargo run --example jpmorgan -- process_checkout_card

use grpc_api_types::payments::*;
use hyperswitch_payments_client::ConnectorClient;
use std::collections::HashMap;


fn build_client() -> ConnectorClient {
    // Set connector_config to authenticate: use ConnectorSpecificConfig with your JpmorganConfig
    let config = ConnectorConfig {
        connector_config: None,  // TODO: Some(ConnectorSpecificConfig { config: Some(...) })
        options: Some(SdkOptions {
            environment: Environment::Sandbox.into(),
        }),
    };
    ConnectorClient::new(config, None).unwrap()
}

fn build_capture_request(connector_transaction_id: &str) -> PaymentServiceCaptureRequest {
    serde_json::from_value::<PaymentServiceCaptureRequest>(serde_json::json!({
    "merchant_capture_id": "probe_capture_001",  // Identification
    "connector_transaction_id": connector_transaction_id,
    "amount_to_capture": {  // Capture Details
        "minor_amount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
        "currency": "USD",  // ISO 4217 currency code (e.g., "USD", "EUR")
    },
    "state": {  // State Information
        "access_token": {  // Access token obtained from connector
            "token": "probe_access_token",  // The token string.
            "expires_in_seconds": 3600,  // Expiration timestamp (seconds since epoch)
            "token_type": "Bearer",  // Token type (e.g., "Bearer", "Basic").
        },
    },
    })).unwrap_or_default()
}

fn build_get_request(connector_transaction_id: &str) -> PaymentServiceGetRequest {
    serde_json::from_value::<PaymentServiceGetRequest>(serde_json::json!({
    "connector_transaction_id": connector_transaction_id,
    "amount": {  // Amount Information
        "minor_amount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
        "currency": "USD",  // ISO 4217 currency code (e.g., "USD", "EUR")
    },
    "state": {  // State Information
        "access_token": {  // Access token obtained from connector
            "token": "probe_access_token",  // The token string.
            "expires_in_seconds": 3600,  // Expiration timestamp (seconds since epoch)
            "token_type": "Bearer",  // Token type (e.g., "Bearer", "Basic").
        },
    },
    })).unwrap_or_default()
}

fn build_void_request(connector_transaction_id: &str) -> PaymentServiceVoidRequest {
    serde_json::from_value::<PaymentServiceVoidRequest>(serde_json::json!({
    "merchant_void_id": "probe_void_001",  // Identification
    "connector_transaction_id": connector_transaction_id,
    "state": {  // State Information
        "access_token": {  // Access token obtained from connector
            "token": "probe_access_token",  // The token string.
            "expires_in_seconds": 3600,  // Expiration timestamp (seconds since epoch)
            "token_type": "Bearer",  // Token type (e.g., "Bearer", "Basic").
        },
    },
    })).unwrap_or_default()
}


// Flow: PaymentService.Capture
pub async fn capture(client: &ConnectorClient, merchant_transaction_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    let response = client.capture(build_capture_request("probe_connector_txn_001"), &HashMap::new(), None).await?;
    return Ok(format!("status: {:?}", response.status()));
}

// Flow: MerchantAuthenticationService.CreateAccessToken
pub async fn create_access_token(client: &ConnectorClient, merchant_transaction_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    let response = client.create_access_token(serde_json::from_value::<MerchantAuthenticationServiceCreateAccessTokenRequest>(serde_json::json!({

    })).unwrap_or_default(), &HashMap::new(), None).await?;
    return Ok(format!("status: {:?}", response.status()));
}

// Flow: PaymentService.Get
pub async fn get(client: &ConnectorClient, merchant_transaction_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    let response = client.get(build_get_request("probe_connector_txn_001"), &HashMap::new(), None).await?;
    return Ok(format!("status: {:?}", response.status()));
}

// Flow: PaymentService.Void
pub async fn void(client: &ConnectorClient, merchant_transaction_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    let response = client.void(build_void_request("probe_connector_txn_001"), &HashMap::new(), None).await?;
    return Ok(format!("status: {:?}", response.status()));
}


#[tokio::main]
async fn main() {
    let client = build_client();
    let flow = std::env::args().nth(1).unwrap_or_else(|| "capture".to_string());
    let result: Result<String, Box<dyn std::error::Error>> = match flow.as_str() {
        "capture" => capture(&client, "order_001").await,
        "create_access_token" => create_access_token(&client, "order_001").await,
        "get" => get(&client, "order_001").await,
        "void" => void(&client, "order_001").await,
        _ => { eprintln!("Unknown flow: {}. Available: capture, create_access_token, get, void", flow); return; }
    };
    match result {
        Ok(msg) => println!("✓ {msg}"),
        Err(e) => eprintln!("✗ {e}"),
    }
}
