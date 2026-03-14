// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py finix
//
// Flow: CustomerService.Create
//
// SDK: sdk/rust (native Rust — uses hyperswitch_payments_client)
// Build: cargo check -p hyperswitch-payments-client  (from repo root)

use grpc_api_types::payments::{Connector, ConnectorConfig, Environment, CustomerServiceCreateRequest};
use hyperswitch_payments_client::ConnectorClient;

#[tokio::main]
async fn main() {
    let config = ConnectorConfig {
        connector: Connector::Finix.into(),
        environment: Environment::Sandbox.into(),
        // auth: Some(ConnectorAuth { ... })  — set your connector auth here
        ..Default::default()
    };

    let client = ConnectorClient::new(config);

    // Build request with probe-verified field values.
    // Note: sensitive fields use Secret::new("value") and card_number uses .try_into().
    // See sdk/rust/examples/basic.rs for the full type-safe construction pattern.
    let request = CustomerServiceCreateRequest {
    customer_name: Some("John Doe".to_string()),  // Name of the customer
    email: Some("test@example.com".to_string()),  // Email address of the customer
    phone_number: Some("4155552671".to_string()),  // Phone number of the customer
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
        ..Default::default()
    };

    let response = client.create_customer(request).await.unwrap();
    println!("Status: {:?}", response.status());
}
