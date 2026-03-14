// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py paypal
//
// Flow: RecurringPaymentService.Charge
//
// SDK: sdk/rust (native Rust — uses hyperswitch_payments_client)
// Build: cargo check -p hyperswitch-payments-client  (from repo root)

use grpc_api_types::payments::{Connector, ConnectorConfig, Environment, RecurringPaymentServiceChargeRequest};
use hyperswitch_payments_client::ConnectorClient;

#[tokio::main]
async fn main() {
    let config = ConnectorConfig {
        connector: Connector::Paypal.into(),
        environment: Environment::Sandbox.into(),
        // auth: Some(ConnectorAuth { ... })  — set your connector auth here
        ..Default::default()
    };

    let client = ConnectorClient::new(config);

    // Build request with probe-verified field values.
    // Note: sensitive fields use Secret::new("value") and card_number uses .try_into().
    // See sdk/rust/examples/basic.rs for the full type-safe construction pattern.
    let request = RecurringPaymentServiceChargeRequest {
    connector_recurring_payment_id: Some(MandateReference {  // Reference to existing mandate
        mandate_id_type: Some(Message {
            connector_mandate_id: Some("probe_mandate_123".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    }),
    amount: Some(Money {  // Amount Information
        minor_amount: Some(1000),  // Amount in minor units (e.g., 1000 = $10.00)
        currency: Some("USD".to_string()),  // ISO 4217 currency code (e.g., "USD", "EUR")
        ..Default::default()
    }),
    payment_method: Some(PaymentMethod {  // Optional payment Method Information (for network transaction flows)
        token: Some("probe_pm_token".to_string()),  // Payment tokens
        ..Default::default()
    }),
    return_url: Some("https://example.com/recurring-return".to_string()),
    connector_customer_id: Some("probe_cust_connector_001".to_string()),
    payment_method_type: Some("PAY_PAL".to_string()),
    off_session: Some(true),  // Behavioral Flags and Preferences
    state: Some(ConnectorState {  // State Information
        access_token: Some(AccessToken {  // Access token obtained from connector
            token: Some("probe_access_token".to_string()),  // The token string.
            expires_in_seconds: Some(3600),  // Expiration timestamp (seconds since epoch)
            token_type: Some("Bearer".to_string()),  // Token type (e.g., "Bearer", "Basic").
            ..Default::default()
        }),
        ..Default::default()
    }),
        ..Default::default()
    };

    let response = client.recurring_charge(request).await.unwrap();
    println!("Status: {:?}", response.status());
}
