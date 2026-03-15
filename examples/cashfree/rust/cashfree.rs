// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py cashfree
//
// Cashfree — all scenarios and flows in one file.
// Run a scenario:  cargo run --example cashfree -- process_checkout_card

use grpc_api_types::payments::*;
use hyperswitch_payments_client::ConnectorClient;
use std::collections::HashMap;


fn build_client() -> ConnectorClient {
    let config = ConnectorConfig {
        connector: Connector::Cashfree.into(),
        environment: Environment::Sandbox.into(),
        // auth: Some(ConnectorAuth { ... })  — set your connector auth here
        ..Default::default()
    };
    ConnectorClient::new(config, None).unwrap()
}


// Flow: PaymentService.Authorize (UpiCollect)
pub async fn authorize(client: &ConnectorClient, merchant_transaction_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    let response = client.authorize(serde_json::from_value::<PaymentServiceAuthorizeRequest>(serde_json::json!({
    "merchant_transaction_id": "probe_txn_001",  // Identification
    "amount": {  // The amount for the payment
        "minor_amount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
        "currency": "USD",  // ISO 4217 currency code (e.g., "USD", "EUR")
    },
    "payment_method": {  // Payment method to be used
        "payment_method": {
            "upi_collect": {  // UPI Collect
                "vpa_id": "test@upi",  // Virtual Payment Address
            },
        }
    },
    "capture_method": "AUTOMATIC",  // Method for capturing the payment
    "customer": {  // Customer Information
        "name": "John Doe",  // Customer's full name
        "email": "test@example.com",  // Customer's email address
        "id": "cust_probe_123",  // Internal customer ID
        "phone_number": "4155552671",  // Customer's phone number
        "phone_country_code": "+1",  // Customer's phone country code
    },
    "address": {  // Address Information
        "shipping_address": {
            "first_name": "John",  // Personal Information
            "last_name": "Doe",
            "line1": "123 Main St",  // Address Details
            "city": "Seattle",
            "state": "WA",
            "zip_code": "98101",
            "country_alpha2_code": "US",
            "email": "test@example.com",  // Contact Information
            "phone_number": "4155552671",
            "phone_country_code": "+1",
        },
        "billing_address": {
            "first_name": "John",  // Personal Information
            "last_name": "Doe",
            "line1": "123 Main St",  // Address Details
            "city": "Seattle",
            "state": "WA",
            "zip_code": "98101",
            "country_alpha2_code": "US",
            "email": "test@example.com",  // Contact Information
            "phone_number": "4155552671",
            "phone_country_code": "+1",
        },
    },
    "auth_type": "NO_THREE_DS",  // Authentication Details
    "return_url": "https://example.com/return",  // URLs for Redirection and Webhooks
    "webhook_url": "https://example.com/webhook",
    "complete_authorize_url": "https://example.com/complete",
    "merchant_order_id": "probe_session_id",
    "browser_info": {
        "color_depth": 24,  // Display Information
        "screen_height": 900,
        "screen_width": 1440,
        "java_enabled": false,  // Browser Settings
        "java_script_enabled": true,
        "language": "en-US",
        "time_zone_offset_minutes": -480,
        "accept_header": "application/json",  // Browser Headers
        "user_agent": "Mozilla/5.0 (probe-bot)",
        "accept_language": "en-US,en;q=0.9",
        "ip_address": "1.2.3.4",  // Device Information
    },
    })).unwrap_or_default(), &HashMap::new(), None).await?;
    match response.status() {
        PaymentStatus::Failure | PaymentStatus::AuthorizationFailed
            => return Err(format!("Authorize failed: {:?}", response.error).into()),
        PaymentStatus::Pending => return Ok("pending — await webhook".to_string()),
        _  => return Ok(format!("Authorized: {}", response.connector_transaction_id.as_deref().unwrap_or(""))),
    }
}


#[tokio::main]
async fn main() {
    let client = build_client();
    let flow = std::env::args().nth(1).unwrap_or_else(|| "authorize".to_string());
    let result: Result<String, Box<dyn std::error::Error>> = match flow.as_str() {
        "authorize" => authorize(&client, "order_001").await,
        _ => { eprintln!("Unknown flow: {}. Available: authorize", flow); return; }
    };
    match result {
        Ok(msg) => println!("✓ {msg}"),
        Err(e) => eprintln!("✗ {e}"),
    }
}
