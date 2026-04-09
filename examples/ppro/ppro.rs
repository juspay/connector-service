// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py ppro
//
// Ppro — all scenarios and flows in one file.
// Run a scenario:  cargo run --example ppro -- process_checkout_card

use grpc_api_types::payments::*;
use hyperswitch_payments_client::ConnectorClient;
use std::collections::HashMap;
use grpc_api_types::payments::payment_method;

#[allow(dead_code)]
fn build_client() -> ConnectorClient {
    // Set connector_config to authenticate: use ConnectorSpecificConfig with your PproConfig
    let config = ConnectorConfig {
        connector_config: None,  // TODO: Some(ConnectorSpecificConfig { config: Some(...) })
        options: Some(SdkOptions {
            environment: Environment::Sandbox.into(),
        }),
    };
    ConnectorClient::new(config, None).unwrap()
}

pub fn build_authorize_request(capture_method: &str) -> PaymentServiceAuthorizeRequest {
    PaymentServiceAuthorizeRequest {
        merchant_transaction_id: Some("probe_txn_001".to_string()),  // Identification.
        amount: Some(Money {  // The amount for the payment.
            minor_amount: 1000,  // Amount in minor units (e.g., 1000 = $10.00).
            currency: Currency::from_str_name("USD").unwrap_or_default().into(),  // ISO 4217 currency code (e.g., "USD", "EUR").
            ..Default::default()
        }),
        payment_method: Some(PaymentMethod {  // Payment method to be used.
            payment_method: Some(payment_method::PaymentMethod::Ideal(Ideal {
                ..Default::default()
            })),
            ..Default::default()
        }),
        capture_method: Some(CaptureMethod::from_str_name(capture_method).unwrap_or_default().into()),  // Method for capturing the payment.
        address: Some(PaymentAddress {  // Address Information.
            billing_address: Some(Address {
                ..Default::default()
            }),
            ..Default::default()
        }),
        auth_type: AuthenticationType::from_str_name("NO_THREE_DS").unwrap_or_default().into(),  // Authentication Details.
        return_url: Some("https://example.com/return".to_string()),  // URLs for Redirection and Webhooks.
        ..Default::default()
    }
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

pub fn build_handle_event_request() -> EventServiceHandleRequest {
    EventServiceHandleRequest {

        ..Default::default()
    }
}

pub fn build_recurring_charge_request() -> RecurringPaymentServiceChargeRequest {
    RecurringPaymentServiceChargeRequest {
        connector_recurring_payment_id: Some(MandateReference {  // Reference to existing mandate.
            // mandate_id_type: {"connector_mandate_id": {"connector_mandate_id": "probe-mandate-123"}}
            ..Default::default()
        }),
        amount: Some(Money {  // Amount Information.
            minor_amount: 1000,  // Amount in minor units (e.g., 1000 = $10.00).
            currency: Currency::from_str_name("USD").unwrap_or_default().into(),  // ISO 4217 currency code (e.g., "USD", "EUR").
            ..Default::default()
        }),
        payment_method: Some(PaymentMethod {  // Optional payment Method Information (for network transaction flows).
            payment_method: Some(payment_method::PaymentMethod::Token(TokenPaymentMethodType {
                token: Some("probe_pm_token".to_string()),  // The token string representing a payment method.
                ..Default::default()
            })),
            ..Default::default()
        }),
        return_url: Some("https://example.com/recurring-return".to_string()),
        connector_customer_id: Some("cust_probe_123".to_string()),
        payment_method_type: Some(PaymentMethodType::from_str_name("PAY_PAL").unwrap_or_default().into()),
        off_session: Some(true),  // Behavioral Flags and Preferences.
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
        ..Default::default()
    }
}

pub fn build_void_request(connector_transaction_id: &str) -> PaymentServiceVoidRequest {
    PaymentServiceVoidRequest {
        merchant_void_id: Some("probe_void_001".to_string()),  // Identification.
        connector_transaction_id: connector_transaction_id.to_string(),
        amount: Some(Money {  // Amount Information.
            minor_amount: 1000,  // Amount in minor units (e.g., 1000 = $10.00).
            currency: Currency::from_str_name("USD").unwrap_or_default().into(),  // ISO 4217 currency code (e.g., "USD", "EUR").
            ..Default::default()
        }),
        ..Default::default()
    }
}


// Flow: PaymentService.Authorize (Ideal)
#[allow(dead_code)]
pub async fn authorize(client: &ConnectorClient, _merchant_transaction_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    let response = client.authorize(build_authorize_request("AUTOMATIC"), &HashMap::new(), None).await?;
    match response.status() {
        PaymentStatus::Failure | PaymentStatus::AuthorizationFailed
            => Err(format!("Authorize failed: {:?}", response.error).into()),
        PaymentStatus::Pending => Ok("pending — await webhook".to_string()),
        _  => Ok(format!("Authorized: {}", response.connector_transaction_id.as_deref().unwrap_or(""))),
    }
}

// Flow: PaymentService.Capture
#[allow(dead_code)]
pub async fn capture(client: &ConnectorClient, _merchant_transaction_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    let response = client.capture(build_capture_request("probe_connector_txn_001"), &HashMap::new(), None).await?;
    Ok(format!("status: {:?}", response.status()))
}

// Flow: PaymentService.Get
#[allow(dead_code)]
pub async fn get(client: &ConnectorClient, _merchant_transaction_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    let response = client.get(build_get_request("probe_connector_txn_001"), &HashMap::new(), None).await?;
    Ok(format!("status: {:?}", response.status()))
}

// Flow: EventService.HandleEvent
#[allow(dead_code)]
pub async fn handle_event(client: &ConnectorClient, _merchant_transaction_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    let response = client.handle_event(build_handle_event_request(), &HashMap::new(), None).await?;
    Ok(format!("status: {:?}", response.status()))
}

// Flow: RecurringPaymentService.Charge
#[allow(dead_code)]
pub async fn recurring_charge(client: &ConnectorClient, _merchant_transaction_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    let response = client.recurring_charge(build_recurring_charge_request(), &HashMap::new(), None).await?;
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
    let flow = std::env::args().nth(1).unwrap_or_else(|| "authorize".to_string());
    let result: Result<String, Box<dyn std::error::Error>> = match flow.as_str() {
        "authorize" => authorize(&client, "order_001").await,
        "capture" => capture(&client, "order_001").await,
        "get" => get(&client, "order_001").await,
        "handle_event" => handle_event(&client, "order_001").await,
        "recurring_charge" => recurring_charge(&client, "order_001").await,
        "refund" => refund(&client, "order_001").await,
        "refund_get" => refund_get(&client, "order_001").await,
        "void" => void(&client, "order_001").await,
        _ => { eprintln!("Unknown flow: {}. Available: authorize, capture, get, handle_event, recurring_charge, refund, refund_get, void", flow); return; }
    };
    match result {
        Ok(msg) => println!("✓ {msg}"),
        Err(e) => eprintln!("✗ {e}"),
    }
}
