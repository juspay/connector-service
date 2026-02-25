use std::collections::HashMap;

use grpc_api_types::payments::{self, PaymentServiceAuthorizeRequest};
use hyperswitch_payments_client::ConnectorClient;

#[tokio::main]
async fn main() {
    let request = build_authorize_request();
    let metadata = build_metadata();

    // Demo 1: Low-level - call authorize_req_handler directly, print connector request JSON
    demo_low_level(&request, &metadata);

    // Demo 2: Full round-trip - use ConnectorClient to make actual HTTP call
    demo_full_round_trip(request, &metadata).await;
}

/// Build a sample PaymentServiceAuthorizeRequest (Stripe card payment).
///
/// Field structure mirrors sdk/python/main.py build_authorize_request_msg().
fn build_authorize_request() -> PaymentServiceAuthorizeRequest {
    PaymentServiceAuthorizeRequest {
        // Identification
        request_ref_id: Some(payments::Identifier {
            id_type: Some(payments::identifier::IdType::Id(
                "test_payment_123456".to_string(),
            )),
        }),

        // Payment details
        amount: 1000,
        minor_amount: 1000,
        currency: payments::Currency::Usd.into(),
        capture_method: Some(payments::CaptureMethod::Automatic.into()),

        // Card payment method
        payment_method: Some(payments::PaymentMethod {
            payment_method: Some(payments::payment_method::PaymentMethod::Card(
                payments::CardDetails {
                    card_number: Some(
                        "4111111111111111"
                            .to_string()
                            .try_into()
                            .expect("valid card number"),
                    ),
                    card_exp_month: Some(hyperswitch_masking::Secret::new("12".to_string())),
                    card_exp_year: Some(hyperswitch_masking::Secret::new("2050".to_string())),
                    card_cvc: Some(hyperswitch_masking::Secret::new("123".to_string())),
                    card_holder_name: Some(hyperswitch_masking::Secret::new(
                        "Test User".to_string(),
                    )),
                    ..Default::default()
                },
            )),
        }),

        // Customer info
        email: Some(hyperswitch_masking::Secret::new(
            "customer@example.com".to_string(),
        )),
        customer_name: Some("Test Customer".to_string()),

        // Auth / 3DS
        auth_type: payments::AuthenticationType::NoThreeDs.into(),
        enrolled_for_3ds: Some(false),

        // URLs
        return_url: Some("https://example.com/return".to_string()),
        webhook_url: Some("https://example.com/webhook".to_string()),

        // Address (required, but empty)
        address: Some(payments::PaymentAddress::default()),

        // Misc
        description: Some("Test payment".to_string()),
        test_mode: Some(true),

        ..Default::default()
    }
}

/// Build metadata for Stripe with HeaderKey auth.
///
/// Two purposes:
///   1. `"connector"` and `"connector_auth_type"` are used to build FfiMetadataPayload
///   2. `x-*` headers are used by ffi_headers_to_masked_metadata for MaskedMetadata
fn build_metadata() -> HashMap<String, String> {
    let api_key =
        std::env::var("STRIPE_API_KEY").unwrap_or_else(|_| "sk_test_placeholder".to_string());

    let mut metadata = HashMap::new();

    // Connector routing (used by parse_metadata / build_ffi_request)
    metadata.insert("connector".to_string(), "Stripe".to_string());
    metadata.insert(
        "connector_auth_type".to_string(),
        serde_json::json!({
            "auth_type": "HeaderKey",
            "api_key": api_key,
        })
        .to_string(),
    );

    // Required metadata headers (used by ffi_headers_to_masked_metadata)
    metadata.insert("x-connector".to_string(), "Stripe".to_string());
    metadata.insert("x-merchant-id".to_string(), "test_merchant_123".to_string());
    metadata.insert("x-request-id".to_string(), "test-request-001".to_string());
    metadata.insert("x-tenant-id".to_string(), "public".to_string());
    metadata.insert("x-auth".to_string(), "header-key".to_string());

    // Optional headers
    metadata.insert("x-api-key".to_string(), api_key);

    metadata
}

/// Demo 1: Low-level handler call.
///
/// Calls `authorize_req_handler` directly to get the connector HTTP request JSON.
/// No actual HTTP call is made — useful for inspecting what would be sent.
fn demo_low_level(request: &PaymentServiceAuthorizeRequest, metadata: &HashMap<String, String>) {
    eprintln!("=== Demo 1: Low-Level Handler Call ===\n");

    let ffi_request =
        match hyperswitch_payments_client::build_ffi_request(request.clone(), metadata) {
            Ok(req) => req,
            Err(e) => {
                eprintln!("Failed to build FFI request: {}", e);
                return;
            }
        };

    match connector_service_ffi::handlers::payments::authorize_req_handler(ffi_request, None) {
        Ok(Some(connector_request)) => {
            let raw_json =
                external_services::service::extract_raw_connector_request(&connector_request);

            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&raw_json) {
                eprintln!("Connector HTTP request generated successfully:");
                eprintln!("  URL:    {}", parsed["url"].as_str().unwrap_or("N/A"));
                eprintln!("  Method: {}", parsed["method"].as_str().unwrap_or("N/A"));
                if let Some(headers) = parsed["headers"].as_object() {
                    let keys: Vec<&String> = headers.keys().collect();
                    eprintln!("  Headers: {:?}", keys);
                }
                eprintln!(
                    "\nFull request JSON:\n{}\n",
                    serde_json::to_string_pretty(&parsed).unwrap_or(raw_json)
                );
            } else {
                eprintln!("Connector Request (raw):\n{}\n", raw_json);
            }
        }
        Ok(None) => {
            eprintln!("No connector request generated (connector may not require an HTTP call)\n");
        }
        Err(e) => {
            eprintln!("Handler returned an error (FFI boundary is working):");
            eprintln!("  {:?}", e);
            eprintln!("\nThis is expected with placeholder data. To get a full request,");
            eprintln!("provide valid STRIPE_API_KEY and complete payment fields.\n");
        }
    }
}

/// Demo 2: Full round-trip.
///
/// Uses ConnectorClient to make an actual HTTP call to the connector.
/// Requires a valid STRIPE_API_KEY environment variable.
async fn demo_full_round_trip(
    request: PaymentServiceAuthorizeRequest,
    metadata: &HashMap<String, String>,
) {
    eprintln!("\n=== Demo 2: Full Round-Trip (ConnectorClient) ===\n");

    let api_key = std::env::var("STRIPE_API_KEY").unwrap_or_default();
    if api_key.is_empty() || api_key == "sk_test_placeholder" {
        eprintln!("Skipping full round-trip: STRIPE_API_KEY not set.");
        eprintln!("Run with: STRIPE_API_KEY=sk_test_xxx cargo run\n");
        return;
    }

    eprintln!("Connector: Stripe");
    eprintln!("Sending authorize request...\n");

    let client = ConnectorClient;
    match client.authorize(request, metadata).await {
        Ok(response) => {
            eprintln!("Authorize response received:");
            eprintln!(
                "{}",
                serde_json::to_string_pretty(&response)
                    .unwrap_or_else(|_| format!("{:?}", response))
            );
        }
        Err(e) => {
            eprintln!("Error during round-trip: {}\n", e);
        }
    }
}
