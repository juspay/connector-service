// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py billwerk
//
// Billwerk — all scenarios and flows in one file.
// Run a scenario:  cargo run --example billwerk -- process_checkout_card

use grpc_api_types::payments::*;
use hyperswitch_payments_client::ConnectorClient;
use std::collections::HashMap;

#[allow(dead_code)]
fn build_client() -> ConnectorClient {
    // Set connector_config to authenticate: use ConnectorSpecificConfig with your BillwerkConfig
    let config = ConnectorConfig {
        connector_config: None,  // TODO: Some(ConnectorSpecificConfig { config: Some(...) })
        options: Some(SdkOptions {
            environment: Environment::Sandbox.into(),
        }),
    };
    ConnectorClient::new(config, None).unwrap()
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
    "connector_order_reference_id": "probe_order_ref_001",
    })).unwrap_or_default(), &HashMap::new(), None).await?;
    Ok(format!("status: {:?}", response.status()))
}

// Flow: PaymentService.recurring_charge
#[allow(dead_code)]
pub async fn recurring_charge(client: &ConnectorClient, _merchant_transaction_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    let response = client.recurring_charge(serde_json::from_value::<>(serde_json::json!({
    "connector_recurring_payment_id": {
        "mandate_id_type": {
            "connector_mandate_id": {
                "connector_mandate_id": "probe-mandate-123",
            },
        },
    },
    "amount": {
        "minor_amount": 1000,
        "currency": "USD",
    },
    "payment_method": {
        "token": {
            "token": "probe_pm_token",
        },
    },
    "return_url": "https://example.com/recurring-return",
    "connector_customer_id": "cust_probe_123",
    "payment_method_type": "PAY_PAL",
    "off_session": true,
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

// Flow: PaymentService.token_authorize
#[allow(dead_code)]
pub async fn token_authorize(client: &ConnectorClient, _merchant_transaction_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    let response = client.token_authorize(serde_json::from_value::<>(serde_json::json!({
    "merchant_transaction_id": "probe_tokenized_txn_001",
    "amount": {
        "minor_amount": 1000,
        "currency": "USD",
    },
    "connector_token": "pm_1AbcXyzStripeTestToken",
    "address": {
        "billing_address": {
        },
    },
    "capture_method": "AUTOMATIC",
    "return_url": "https://example.com/return",
    })).unwrap_or_default(), &HashMap::new(), None).await?;
    Ok(format!("status: {:?}", response.status()))
}

// Flow: PaymentService.token_setup_recurring
#[allow(dead_code)]
pub async fn token_setup_recurring(client: &ConnectorClient, _merchant_transaction_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    let response = client.token_setup_recurring(serde_json::from_value::<>(serde_json::json!({
    "merchant_recurring_payment_id": "probe_tokenized_mandate_001",
    "amount": {
        "minor_amount": 0,
        "currency": "USD",
    },
    "connector_token": "pm_1AbcXyzStripeTestToken",
    "address": {
        "billing_address": {
        },
    },
    "customer_acceptance": {
        "acceptance_type": "ONLINE",
        "accepted_at": 0,
        "online_mandate_details": {
            "ip_address": "127.0.0.1",
            "user_agent": "Mozilla/5.0",
        },
    },
    "setup_mandate_details": {
        "mandate_type": {
            "multi_use": {
                "amount": 0,
                "currency": "USD",
            },
        },
    },
    "setup_future_usage": "OFF_SESSION",
    })).unwrap_or_default(), &HashMap::new(), None).await?;
    Ok(format!("status: {:?}", response.status()))
}

// Flow: PaymentService.tokenize
#[allow(dead_code)]
pub async fn tokenize(client: &ConnectorClient, _merchant_transaction_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    let response = client.tokenize(serde_json::from_value::<>(serde_json::json!({
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
    })).unwrap_or_default(), &HashMap::new(), None).await?;
    Ok(format!("token: {}", response.payment_method_token))
}

// Flow: PaymentService.void
#[allow(dead_code)]
pub async fn void(client: &ConnectorClient, _merchant_transaction_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    let response = client.void(serde_json::from_value::<>(serde_json::json!({
    "merchant_void_id": "probe_void_001",
    "connector_transaction_id": "probe_connector_txn_001",
    })).unwrap_or_default(), &HashMap::new(), None).await?;
    Ok(format!("status: {:?}", response.status()))
}

#[allow(dead_code)]
#[tokio::main]
async fn main() {
    let client = build_client();
    let flow = std::env::args().nth(1).unwrap_or_else(|| "capture".to_string());
    let result: Result<String, Box<dyn std::error::Error>> = match flow.as_str() {
        "capture" => capture(&client, "order_001").await,
        "get" => get(&client, "order_001").await,
        "recurring_charge" => recurring_charge(&client, "order_001").await,
        "refund" => refund(&client, "order_001").await,
        "refund_get" => refund_get(&client, "order_001").await,
        "token_authorize" => token_authorize(&client, "order_001").await,
        "token_setup_recurring" => token_setup_recurring(&client, "order_001").await,
        "tokenize" => tokenize(&client, "order_001").await,
        "void" => void(&client, "order_001").await,
        _ => { eprintln!("Unknown flow: {}. Available: capture, get, recurring_charge, refund, refund_get, token_authorize, token_setup_recurring, tokenize, void", flow); return; }
    };
    match result {
        Ok(msg) => println!("✓ {msg}"),
        Err(e) => eprintln!("✗ {e}"),
    }
}
