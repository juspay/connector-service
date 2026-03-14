// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py rapyd
//
// Flow: PaymentService.Authorize (Card)
//
// SDK: sdk/rust (native Rust — uses hyperswitch_payments_client)
// Build: cargo check -p hyperswitch-payments-client  (from repo root)

use grpc_api_types::payments::{Connector, ConnectorConfig, Environment, PaymentServiceAuthorizeRequest};
use hyperswitch_payments_client::ConnectorClient;

#[tokio::main]
async fn main() {
    let config = ConnectorConfig {
        connector: Connector::Rapyd.into(),
        environment: Environment::Sandbox.into(),
        // auth: Some(ConnectorAuth { ... })  — set your connector auth here
        ..Default::default()
    };

    let client = ConnectorClient::new(config);

    // Build request with probe-verified field values.
    // Note: sensitive fields use Secret::new("value") and card_number uses .try_into().
    // See sdk/rust/examples/basic.rs for the full type-safe construction pattern.
    let request = PaymentServiceAuthorizeRequest {
    merchant_transaction_id: Some("probe_txn_001".to_string()),  // Identification
    amount: Some(Money {  // The amount for the payment
        minor_amount: Some(1000),  // Amount in minor units (e.g., 1000 = $10.00)
        currency: Some("USD".to_string()),  // ISO 4217 currency code (e.g., "USD", "EUR")
        ..Default::default()
    }),
    payment_method: Some(PaymentMethod {  // Payment method to be used
        card: Some(CardDetails {  // Generic card payment
            card_number: Some("4111111111111111".to_string()),  // Card Identification
            card_exp_month: Some("03".to_string()),
            card_exp_year: Some("2030".to_string()),
            card_cvc: Some("737".to_string()),
            card_holder_name: Some("John Doe".to_string()),  // Cardholder Information
            ..Default::default()
        }),
        ..Default::default()
    }),
    capture_method: Some("AUTOMATIC".to_string()),  // Method for capturing the payment
    customer: Some(Customer {  // Customer Information
        name: Some("John Doe".to_string()),  // Customer's full name
        email: Some("test@example.com".to_string()),  // Customer's email address
        id: Some("cust_probe_123".to_string()),  // Internal customer ID
        phone_number: Some("4155552671".to_string()),  // Customer's phone number
        phone_country_code: Some("+1".to_string()),  // Customer's phone country code
        ..Default::default()
    }),
    address: Some(PaymentAddress {  // Address Information
        shipping_address: Some(Address {
            first_name: Some("John".to_string()),  // Personal Information
            last_name: Some("Doe".to_string()),
            line1: Some("123 Main St".to_string()),  // Address Details
            city: Some("Seattle".to_string()),
            state: Some("WA".to_string()),
            zip_code: Some("98101".to_string()),
            country_alpha2_code: Some("US".to_string()),
            email: Some("test@example.com".to_string()),  // Contact Information
            phone_number: Some("4155552671".to_string()),
            phone_country_code: Some("+1".to_string()),
            ..Default::default()
        }),
        billing_address: Some(Address {
            first_name: Some("John".to_string()),  // Personal Information
            last_name: Some("Doe".to_string()),
            line1: Some("123 Main St".to_string()),  // Address Details
            city: Some("Seattle".to_string()),
            state: Some("WA".to_string()),
            zip_code: Some("98101".to_string()),
            country_alpha2_code: Some("US".to_string()),
            email: Some("test@example.com".to_string()),  // Contact Information
            phone_number: Some("4155552671".to_string()),
            phone_country_code: Some("+1".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    }),
    auth_type: Some("NO_THREE_DS".to_string()),  // Authentication Details
    return_url: Some("https://example.com/return".to_string()),  // URLs for Redirection and Webhooks
    webhook_url: Some("https://example.com/webhook".to_string()),
    complete_authorize_url: Some("https://example.com/complete".to_string()),
    browser_info: Some(BrowserInformation {
        color_depth: Some(24),  // Display Information
        screen_height: Some(900),
        screen_width: Some(1440),
        java_enabled: Some(false),  // Browser Settings
        java_script_enabled: Some(true),
        language: Some("en-US".to_string()),
        time_zone_offset_minutes: Some(-480),
        accept_header: Some("application/json".to_string()),  // Browser Headers
        user_agent: Some("Mozilla/5.0 (probe-bot)".to_string()),
        accept_language: Some("en-US,en;q=0.9".to_string()),
        ip_address: Some("1.2.3.4".to_string()),  // Device Information
        ..Default::default()
    }),
        ..Default::default()
    };

    let response = client.authorize(request).await.unwrap();
    match response.status() {
        PaymentStatus::Failed  => panic!("Authorize failed: {:?}", response.error),
        PaymentStatus::Pending => println!("Pending — await webhook"),
        _                      => println!("Authorized: {}", response.connector_transaction_id),
    }
}
