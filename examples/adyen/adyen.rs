// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py adyen
//
// Adyen — all scenarios and flows in one file.
// Run a scenario:  cargo run --example adyen -- process_checkout_card

use grpc_api_types::payments::*;
use hyperswitch_payments_client::ConnectorClient;
use std::collections::HashMap;

#[allow(dead_code)]
fn build_client() -> ConnectorClient {
    // Set connector_config to authenticate: use ConnectorSpecificConfig with your AdyenConfig
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
        "address": {
            "billing_address": {
            },
        },
        "auth_type": "NO_THREE_DS",
        "return_url": "https://example.com/return",
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

    match authorize_response.status() {
        PaymentStatus::Failure | PaymentStatus::AuthorizationFailed => return Err(format!("Payment failed: {:?}", authorize_response.error).into()),
        PaymentStatus::Pending => return Ok("pending — awaiting webhook".to_string()),
        _                      => {},
    }

    Ok(format!("Payment: {:?} — {}", authorize_response.status(), authorize_response.connector_transaction_id.as_deref().unwrap_or("")))
}

// Scenario: Card Payment (Authorize + Capture)
// Two-step card payment. First authorize, then capture. Use when you need to verify funds before finalizing.
#[allow(dead_code)]
pub async fn process_checkout_card(client: &ConnectorClient, _merchant_transaction_id: &str) -> Result<String, Box<dyn std::error::Error>> {
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
        "address": {
            "billing_address": {
            },
        },
        "auth_type": "NO_THREE_DS",
        "return_url": "https://example.com/return",
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

    match authorize_response.status() {
        PaymentStatus::Failure | PaymentStatus::AuthorizationFailed => return Err(format!("Payment failed: {:?}", authorize_response.error).into()),
        PaymentStatus::Pending => return Ok("pending — awaiting webhook".to_string()),
        _                      => {},
    }

    // Step 2: Capture — settle the reserved funds
    let capture_response = client.capture(serde_json::from_value::<>(serde_json::json!({
        "merchant_capture_id": "probe_capture_001",
        "amount_to_capture": {
            "minor_amount": 1000,
            "currency": "USD",
        },
        "connector_transaction_id": &authorize_response.connector_transaction_id,  // from Authorize
    })).unwrap_or_default(), &HashMap::new(), None).await?;

    if capture_response.status() == PaymentStatus::Failure {
        return Err(format!("Capture failed: {:?}", capture_response.error).into());
    }

    Ok(format!("Payment completed: {}", authorize_response.connector_transaction_id.as_deref().unwrap_or("")))
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
        "address": {
            "billing_address": {
            },
        },
        "auth_type": "NO_THREE_DS",
        "return_url": "https://example.com/return",
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
        "connector_transaction_id": &authorize_response.connector_transaction_id,  // from Authorize
    })).unwrap_or_default(), &HashMap::new(), None).await?;

    if refund_response.status() == RefundStatus::RefundFailure {
        return Err(format!("Refund failed: {:?}", refund_response.error).into());
    }

    Ok(format!("Refunded: {:?}", refund_response.status()))
}

// Scenario: Void Payment
// Cancel an authorized but not-yet-captured payment.
#[allow(dead_code)]
pub async fn process_void_payment(client: &ConnectorClient, _merchant_transaction_id: &str) -> Result<String, Box<dyn std::error::Error>> {
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
        "address": {
            "billing_address": {
            },
        },
        "auth_type": "NO_THREE_DS",
        "return_url": "https://example.com/return",
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

    match authorize_response.status() {
        PaymentStatus::Failure | PaymentStatus::AuthorizationFailed => return Err(format!("Payment failed: {:?}", authorize_response.error).into()),
        PaymentStatus::Pending => return Ok("pending — awaiting webhook".to_string()),
        _                      => {},
    }

    // Step 2: Void — release reserved funds (cancel authorization)
    let void_response = client.void(serde_json::from_value::<>(serde_json::json!({
        "merchant_void_id": "probe_void_001",
        "connector_transaction_id": &authorize_response.connector_transaction_id,  // from Authorize
    })).unwrap_or_default(), &HashMap::new(), None).await?;

    Ok(format!("Voided: {:?}", void_response.status()))
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
    "address": {
        "billing_address": {
        },
    },
    "auth_type": "NO_THREE_DS",
    "return_url": "https://example.com/return",
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
    match response.status() {
        PaymentStatus::Failure | PaymentStatus::AuthorizationFailed
            => Err(format!("Authorize failed: {:?}", response.error).into()),
        PaymentStatus::Pending => Ok("pending — await webhook".to_string()),
        _  => Ok(format!("Authorized: {}", response.connector_transaction_id.as_deref().unwrap_or(""))),
    }
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

// Flow: PaymentService.dispute_accept
#[allow(dead_code)]
pub async fn dispute_accept(client: &ConnectorClient, _merchant_transaction_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    let response = client.dispute_accept(serde_json::from_value::<>(serde_json::json!({
    "merchant_dispute_id": "probe_dispute_001",
    "connector_transaction_id": "probe_txn_001",
    "dispute_id": "probe_dispute_id_001",
    })).unwrap_or_default(), &HashMap::new(), None).await?;
    Ok(format!("dispute_status: {:?}", response.dispute_status()))
}

// Flow: PaymentService.dispute_defend
#[allow(dead_code)]
pub async fn dispute_defend(client: &ConnectorClient, _merchant_transaction_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    let response = client.dispute_defend(serde_json::from_value::<>(serde_json::json!({
    "merchant_dispute_id": "probe_dispute_001",
    "connector_transaction_id": "probe_txn_001",
    "dispute_id": "probe_dispute_id_001",
    "reason_code": "probe_reason",
    })).unwrap_or_default(), &HashMap::new(), None).await?;
    Ok(format!("dispute_status: {:?}", response.dispute_status()))
}

// Flow: PaymentService.dispute_submit_evidence
#[allow(dead_code)]
pub async fn dispute_submit_evidence(client: &ConnectorClient, _merchant_transaction_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    let response = client.dispute_submit_evidence(serde_json::from_value::<>(serde_json::json!({
    "merchant_dispute_id": "probe_dispute_001",
    "connector_transaction_id": "probe_txn_001",
    "dispute_id": "probe_dispute_id_001",
    // "evidence_documents": [{"evidence_type": "SERVICE_DOCUMENTATION", "file_content": [112, 114, 111, 98, 101, 32, 101, 118, 105, 100, 101, 110, 99, 101, 32, 99, 111, 110, 116, 101, 110, 116], "file_mime_type": "application/pdf"}]
    })).unwrap_or_default(), &HashMap::new(), None).await?;
    Ok(format!("dispute_status: {:?}", response.dispute_status()))
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
    "address": {
        "billing_address": {
        },
    },
    "capture_method": "AUTOMATIC",
    "auth_type": "NO_THREE_DS",
    "return_url": "https://example.com/return",
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

// Flow: PaymentService.proxy_setup_recurring
#[allow(dead_code)]
pub async fn proxy_setup_recurring(client: &ConnectorClient, _merchant_transaction_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    let response = client.proxy_setup_recurring(serde_json::from_value::<>(serde_json::json!({
    "merchant_recurring_payment_id": "probe_proxy_mandate_001",
    "amount": {
        "minor_amount": 0,
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
        "id": "probe_customer_001",
    },
    "address": {
        "billing_address": {
        },
    },
    "return_url": "https://example.com/return",
    "customer_acceptance": {
        "acceptance_type": "OFFLINE",
        "accepted_at": 0,
    },
    "auth_type": "NO_THREE_DS",
    "setup_future_usage": "OFF_SESSION",
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

// Flow: PaymentService.setup_recurring
#[allow(dead_code)]
pub async fn setup_recurring(client: &ConnectorClient, _merchant_transaction_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    let response = client.setup_recurring(serde_json::from_value::<>(serde_json::json!({
    "merchant_recurring_payment_id": "probe_mandate_001",
    "amount": {
        "minor_amount": 0,
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
    "customer": {
        "id": "cust_probe_123",
    },
    "address": {
        "billing_address": {
        },
    },
    "auth_type": "NO_THREE_DS",
    "enrolled_for_3ds": false,
    "return_url": "https://example.com/mandate-return",
    "setup_future_usage": "OFF_SESSION",
    "request_incremental_authorization": false,
    "customer_acceptance": {
        "acceptance_type": "OFFLINE",
        "accepted_at": 0,
    },
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
    if response.status() == PaymentStatus::Failure {
        return Err(format!("Setup failed: {:?}", response.error).into());
    }
    Ok(format!("Mandate: {}", response.connector_recurring_payment_id.as_deref().unwrap_or("")))
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
    let flow = std::env::args().nth(1).unwrap_or_else(|| "process_checkout_autocapture".to_string());
    let result: Result<String, Box<dyn std::error::Error>> = match flow.as_str() {
        "process_checkout_autocapture" => process_checkout_autocapture(&client, "order_001").await,
        "process_checkout_card" => process_checkout_card(&client, "order_001").await,
        "process_refund" => process_refund(&client, "order_001").await,
        "process_void_payment" => process_void_payment(&client, "order_001").await,
        "authorize" => authorize(&client, "order_001").await,
        "capture" => capture(&client, "order_001").await,
        "dispute_accept" => dispute_accept(&client, "order_001").await,
        "dispute_defend" => dispute_defend(&client, "order_001").await,
        "dispute_submit_evidence" => dispute_submit_evidence(&client, "order_001").await,
        "handle_event" => handle_event(&client, "order_001").await,
        "proxy_authorize" => proxy_authorize(&client, "order_001").await,
        "proxy_setup_recurring" => proxy_setup_recurring(&client, "order_001").await,
        "recurring_charge" => recurring_charge(&client, "order_001").await,
        "refund" => refund(&client, "order_001").await,
        "setup_recurring" => setup_recurring(&client, "order_001").await,
        "void" => void(&client, "order_001").await,
        _ => { eprintln!("Unknown flow: {}. Available: process_checkout_autocapture, process_checkout_card, process_refund, process_void_payment, authorize, capture, dispute_accept, dispute_defend, dispute_submit_evidence, handle_event, proxy_authorize, proxy_setup_recurring, recurring_charge, refund, setup_recurring, void", flow); return; }
    };
    match result {
        Ok(msg) => println!("✓ {msg}"),
        Err(e) => eprintln!("✗ {e}"),
    }
}
