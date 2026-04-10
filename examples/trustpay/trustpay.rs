// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py trustpay
//
// Trustpay — all scenarios and flows in one file.
// Run a scenario:  cargo run --example trustpay -- process_checkout_card

use grpc_api_types::payments::*;
use hyperswitch_payments_client::ConnectorClient;
use std::collections::HashMap;

#[allow(dead_code)]
fn build_client() -> ConnectorClient {
    // Set connector_config to authenticate: use ConnectorSpecificConfig with your TrustpayConfig
    let config = ConnectorConfig {
        connector_config: None,  // TODO: Some(ConnectorSpecificConfig { config: Some(...) })
        options: Some(SdkOptions {
            environment: Environment::Sandbox.into(),
        }),
    };
    ConnectorClient::new(config, None).unwrap()
}

// Scenario: One-step Payment (Authorize + Capture)
// Simple payment that authorizes and captures in one call. Use for immediate charges.
#[allow(dead_code)]
pub async fn process_checkout_autocapture(client: &ConnectorClient, _merchant_transaction_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Step 1: Authorize — reserve funds on the payment method
    let authorize_response = client.authorize(serde_json::from_value::<>(serde_json::json!({
        "merchant_transaction_id": "probe_txn_001",
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
        "capture_method": "AUTOMATIC",
        "customer": {
            "email": "test@example.com",
        },
        "address": {
            "billing_address": {
                "first_name": "John",
                "line1": "123 Main St",
                "city": "Seattle",
                "zip_code": "98101",
                "country_alpha2_code": "US",
            },
        },
        "auth_type": "NO_THREE_DS",
        "return_url": "https://example.com/return",
        "browser_info": {
            "user_agent": "Mozilla/5.0 (probe-bot)",
            "ip_address": "1.2.3.4",
        },
        "state": {
            "access_token": {
                "token": "probe_access_token",
                "expires_in_seconds": 3600,
                "token_type": "Bearer",
            },
        },
    })).unwrap_or_default(), &HashMap::new(), None).await?;

    match authorize_response.status() {
        PaymentStatus::Failure | PaymentStatus::AuthorizationFailed => return Err(format!("Payment failed: {:?}", authorize_response.error).into()),
        PaymentStatus::Pending => return Ok("pending — awaiting webhook".to_string()),
        _                      => {},
    }

    Ok(format!("Payment: {:?} — {}", authorize_response.status(), authorize_response.connector_transaction_id.as_deref().unwrap_or("")))
}

// Scenario: Refund
// Return funds to the customer for a completed payment.
#[allow(dead_code)]
pub async fn process_refund(client: &ConnectorClient, _merchant_transaction_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Step 1: Authorize — reserve funds on the payment method
    let authorize_response = client.authorize(serde_json::from_value::<>(serde_json::json!({
        "merchant_transaction_id": "probe_txn_001",
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
        "capture_method": "AUTOMATIC",
        "customer": {
            "email": "test@example.com",
        },
        "address": {
            "billing_address": {
                "first_name": "John",
                "line1": "123 Main St",
                "city": "Seattle",
                "zip_code": "98101",
                "country_alpha2_code": "US",
            },
        },
        "auth_type": "NO_THREE_DS",
        "return_url": "https://example.com/return",
        "browser_info": {
            "user_agent": "Mozilla/5.0 (probe-bot)",
            "ip_address": "1.2.3.4",
        },
        "state": {
            "access_token": {
                "token": "probe_access_token",
                "expires_in_seconds": 3600,
                "token_type": "Bearer",
            },
        },
    })).unwrap_or_default(), &HashMap::new(), None).await?;

    match authorize_response.status() {
        PaymentStatus::Failure | PaymentStatus::AuthorizationFailed => return Err(format!("Payment failed: {:?}", authorize_response.error).into()),
        PaymentStatus::Pending => return Ok("pending — awaiting webhook".to_string()),
        _                      => {},
    }

    // Step 2: Refund — return funds to the customer
    let refund_response = client.refund(serde_json::from_value::<>(serde_json::json!({
        "merchant_refund_id": "probe_refund_001",
        "payment_amount": 1000,
        "refund_amount": {
            "minor_amount": 1000,
            "currency": "USD",
        },
        "reason": "customer_request",
        "state": {
            "access_token": {
                "token": "probe_access_token",
                "expires_in_seconds": 3600,
                "token_type": "Bearer",
            },
        },
        "connector_transaction_id": &authorize_response.connector_transaction_id,  // from Authorize
    })).unwrap_or_default(), &HashMap::new(), None).await?;

    if refund_response.status() == RefundStatus::RefundFailure {
        return Err(format!("Refund failed: {:?}", refund_response.error).into());
    }

    Ok(format!("Refunded: {:?}", refund_response.status()))
}

// Scenario: Get Payment Status
// Retrieve current payment status from the connector.
#[allow(dead_code)]
pub async fn process_get_payment(client: &ConnectorClient, _merchant_transaction_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Step 1: Authorize — reserve funds on the payment method
    let authorize_response = client.authorize(serde_json::from_value::<>(serde_json::json!({
        "merchant_transaction_id": "probe_txn_001",
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
        "capture_method": "MANUAL",
        "customer": {
            "email": "test@example.com",
        },
        "address": {
            "billing_address": {
                "first_name": "John",
                "line1": "123 Main St",
                "city": "Seattle",
                "zip_code": "98101",
                "country_alpha2_code": "US",
            },
        },
        "auth_type": "NO_THREE_DS",
        "return_url": "https://example.com/return",
        "browser_info": {
            "user_agent": "Mozilla/5.0 (probe-bot)",
            "ip_address": "1.2.3.4",
        },
        "state": {
            "access_token": {
                "token": "probe_access_token",
                "expires_in_seconds": 3600,
                "token_type": "Bearer",
            },
        },
    })).unwrap_or_default(), &HashMap::new(), None).await?;

    match authorize_response.status() {
        PaymentStatus::Failure | PaymentStatus::AuthorizationFailed => return Err(format!("Payment failed: {:?}", authorize_response.error).into()),
        PaymentStatus::Pending => return Ok("pending — awaiting webhook".to_string()),
        _                      => {},
    }

    // Step 2: Get — retrieve current payment status from the connector
    let get_response = client.get(serde_json::from_value::<>(serde_json::json!({
        "merchant_transaction_id": "probe_merchant_txn_001",
        "amount": {
            "minor_amount": 1000,
            "currency": "USD",
        },
        "state": {
            "access_token": {
                "token": "probe_access_token",
                "expires_in_seconds": 3600,
                "token_type": "Bearer",
            },
        },
        "connector_transaction_id": &authorize_response.connector_transaction_id,  // from Authorize
    })).unwrap_or_default(), &HashMap::new(), None).await?;

    Ok(format!("Status: {:?}", get_response.status()))
}

// Flow: PaymentService.authorize (Card)
#[allow(dead_code)]
pub async fn authorize(client: &ConnectorClient, _merchant_transaction_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    let response = client.authorize(serde_json::from_value::<>(serde_json::json!({
    "merchant_transaction_id": "probe_txn_001",
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
    "capture_method": "AUTOMATIC",
    "customer": {
        "email": "test@example.com",
    },
    "address": {
        "billing_address": {
            "first_name": "John",
            "line1": "123 Main St",
            "city": "Seattle",
            "zip_code": "98101",
            "country_alpha2_code": "US",
        },
    },
    "auth_type": "NO_THREE_DS",
    "return_url": "https://example.com/return",
    "browser_info": {
        "user_agent": "Mozilla/5.0 (probe-bot)",
        "ip_address": "1.2.3.4",
    },
    "state": {
        "access_token": {
            "token": "probe_access_token",
            "expires_in_seconds": 3600,
            "token_type": "Bearer",
        },
    },
    })).unwrap_or_default(), &HashMap::new(), None).await?;
    match response.status() {
        PaymentStatus::Failure | PaymentStatus::AuthorizationFailed
            => Err(format!("Authorize failed: {:?}", response.error).into()),
        PaymentStatus::Pending => Ok("pending — await webhook".to_string()),
        _  => Ok(format!("Authorized: {}", response.connector_transaction_id.as_deref().unwrap_or(""))),
    }
}

// Flow: PaymentService.create_order
#[allow(dead_code)]
pub async fn create_order(client: &ConnectorClient, _merchant_transaction_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    let response = client.create_order(serde_json::from_value::<>(serde_json::json!({
    "merchant_order_id": "probe_order_001",
    "amount": {
        "minor_amount": 1000,
        "currency": "USD",
    },
    "state": {
        "access_token": {
            "token": "probe_access_token",
            "expires_in_seconds": 3600,
            "token_type": "Bearer",
        },
    },
    })).unwrap_or_default(), &HashMap::new(), None).await?;
    Ok(format!("status: {:?}", response.status()))
}

// Flow: PaymentService.create_server_authentication_token
#[allow(dead_code)]
pub async fn create_server_authentication_token(client: &ConnectorClient, _merchant_transaction_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    let response = client.create_server_authentication_token(serde_json::from_value::<>(serde_json::json!({

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
    "state": {
        "access_token": {
            "token": "probe_access_token",
            "expires_in_seconds": 3600,
            "token_type": "Bearer",
        },
    },
    })).unwrap_or_default(), &HashMap::new(), None).await?;
    Ok(format!("status: {:?}", response.status()))
}

// Flow: PaymentService.handle_event
#[allow(dead_code)]
pub async fn handle_event(client: &ConnectorClient, _merchant_transaction_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    let response = client.handle_event(serde_json::from_value::<>(serde_json::json!({

    })).unwrap_or_default(), &HashMap::new(), None).await?;
    Ok(format!("status: {:?}", response.status()))
}

// Flow: PaymentService.proxy_authorize
#[allow(dead_code)]
pub async fn proxy_authorize(client: &ConnectorClient, _merchant_transaction_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    let response = client.proxy_authorize(serde_json::from_value::<>(serde_json::json!({
    "merchant_transaction_id": "probe_proxy_txn_001",
    "amount": {
        "minor_amount": 1000,
        "currency": "USD",
    },
    "card_proxy": {
        "card_number": "4111111111111111",
        "card_exp_month": "03",
        "card_exp_year": "2030",
        "card_cvc": "123",
        "card_holder_name": "John Doe",
    },
    "customer": {
        "email": "test@example.com",
    },
    "address": {
        "billing_address": {
            "first_name": "John",
            "line1": "123 Main St",
            "city": "Seattle",
            "zip_code": "98101",
            "country_alpha2_code": "US",
        },
    },
    "capture_method": "AUTOMATIC",
    "auth_type": "NO_THREE_DS",
    "return_url": "https://example.com/return",
    "browser_info": {
        "user_agent": "Mozilla/5.0 (probe-bot)",
        "ip_address": "1.2.3.4",
    },
    "state": {
        "access_token": {
            "token": "probe_access_token",
            "expires_in_seconds": 3600,
            "token_type": "Bearer",
        },
    },
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
    "state": {
        "access_token": {
            "token": "probe_access_token",
            "expires_in_seconds": 3600,
            "token_type": "Bearer",
        },
    },
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
    "state": {
        "access_token": {
            "token": "probe_access_token",
            "expires_in_seconds": 3600,
            "token_type": "Bearer",
        },
    },
    })).unwrap_or_default(), &HashMap::new(), None).await?;
    Ok(format!("status: {:?}", response.status()))
}

#[allow(dead_code)]
#[tokio::main]
async fn main() {
    let client = build_client();
    let flow = std::env::args().nth(1).unwrap_or_else(|| "process_checkout_autocapture".to_string());
    let result: Result<String, Box<dyn std::error::Error>> = match flow.as_str() {
        "process_checkout_autocapture" => process_checkout_autocapture(&client, "order_001").await,
        "process_refund" => process_refund(&client, "order_001").await,
        "process_get_payment" => process_get_payment(&client, "order_001").await,
        "authorize" => authorize(&client, "order_001").await,
        "create_order" => create_order(&client, "order_001").await,
        "create_server_authentication_token" => create_server_authentication_token(&client, "order_001").await,
        "get" => get(&client, "order_001").await,
        "handle_event" => handle_event(&client, "order_001").await,
        "proxy_authorize" => proxy_authorize(&client, "order_001").await,
        "refund" => refund(&client, "order_001").await,
        "refund_get" => refund_get(&client, "order_001").await,
        _ => { eprintln!("Unknown flow: {}. Available: process_checkout_autocapture, process_refund, process_get_payment, authorize, create_order, create_server_authentication_token, get, handle_event, proxy_authorize, refund, refund_get", flow); return; }
    };
    match result {
        Ok(msg) => println!("✓ {msg}"),
        Err(e) => eprintln!("✗ {e}"),
    }
}
