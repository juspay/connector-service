// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py adyen
//
// Flow: PaymentService.SetupRecurring
//
// SDK: sdk/rust (native Rust — uses hyperswitch_payments_client)
// Build: cargo check -p hyperswitch-payments-client  (from repo root)

use grpc_api_types::payments::{Connector, ConnectorConfig, Environment, PaymentServiceSetupRecurringRequest};
use hyperswitch_payments_client::ConnectorClient;

#[tokio::main]
async fn main() {
    let config = ConnectorConfig {
        connector: Connector::Adyen.into(),
        environment: Environment::Sandbox.into(),
        // auth: Some(ConnectorAuth { ... })  — set your connector auth here
        ..Default::default()
    };

    let client = ConnectorClient::new(config);

    // Build request with probe-verified field values.
    // Note: sensitive fields use Secret::new("value") and card_number uses .try_into().
    // See sdk/rust/examples/basic.rs for the full type-safe construction pattern.
    let request = PaymentServiceSetupRecurringRequest {
    merchant_recurring_payment_id: Some("probe_mandate_001".to_string()),  // Identification
    amount: Some(Money {  // Mandate Details
        minor_amount: Some(0),  // Amount in minor units (e.g., 1000 = $10.00)
        currency: Some("USD".to_string()),  // ISO 4217 currency code (e.g., "USD", "EUR")
        ..Default::default()
    }),
    payment_method: Some(PaymentMethod {
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
    customer: Some(Customer {
        name: Some("John Doe".to_string()),  // Customer's full name
        email: Some("test@example.com".to_string()),  // Customer's email address
        id: Some("cust_probe_123".to_string()),  // Internal customer ID
        phone_number: Some("4155552671".to_string()),  // Customer's phone number
        phone_country_code: Some("+1".to_string()),  // Customer's phone country code
        ..Default::default()
    }),
    address: Some(PaymentAddress {  // Address Information
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
    auth_type: Some("NO_THREE_DS".to_string()),  // Type of authentication to be used
    enrolled_for_3ds: Some(false),  // Indicates if the customer is enrolled for 3D Secure
    return_url: Some("https://example.com/mandate-return".to_string()),  // URL to redirect after setup
    setup_future_usage: Some("OFF_SESSION".to_string()),  // Indicates future usage intention
    request_incremental_authorization: Some(false),  // Indicates if incremental authorization is requested
    customer_acceptance: Some(CustomerAcceptance {  // Details of customer acceptance
        acceptance_type: Some("OFFLINE".to_string()),  // Type of acceptance (e.g., online, offline).
        accepted_at: Some(0),  // Timestamp when the acceptance was made (Unix timestamp, seconds since epoch).
        ..Default::default()
    }),
    browser_info: Some(BrowserInformation {  // Information about the customer's browser
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

    let response = client.setup_recurring(request).await.unwrap();
    if response.status() == PaymentStatus::Failed {
        panic!("Setup failed: {:?}", response.error);
    }
    println!("Mandate: {}", response.connector_transaction_id);
}
