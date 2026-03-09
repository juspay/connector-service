use std::collections::HashMap;

use grpc_api_types::payments::{
    self, Connector, ConnectorAuth, ConnectorConfig, Environment, FfiOptions,
    PaymentServiceAuthorizeRequest, RequestConfig,
};
use hyperswitch_masking::Secret;
use hyperswitch_payments_client::ConnectorClient;

#[tokio::main]
async fn main() {
    let request = build_authorize_request();
    let api_key =
        std::env::var("STRIPE_API_KEY").unwrap_or_else(|_| "sk_test_placeholder".to_string());

    // Define the final configuration context
    let ffi_options = FfiOptions {
        environment: Environment::Sandbox.into(),
        connector: Connector::Stripe.into(),
        auth: Some(ConnectorAuth {
            auth_type: Some(payments::connector_auth::AuthType::Stripe(
                payments::StripeAuth {
                    api_key: Some(Secret::new(api_key.to_string())),
                },
            )),
        }),
    };

    let metadata = build_metadata(&api_key);

    // Demo 1: Low-level - call authorize_req_handler directly
    demo_low_level(&request, &metadata, &ffi_options);

    // Demo 2: Full round-trip - use ConnectorClient to make actual HTTP call
    demo_full_round_trip(request, &metadata, ffi_options).await;
}

/// Build a sample PaymentServiceAuthorizeRequest (Stripe card payment).
fn build_authorize_request() -> PaymentServiceAuthorizeRequest {
    PaymentServiceAuthorizeRequest {
        // Identification
        merchant_transaction_id: Some(payments::Identifier {
            id_type: Some(payments::identifier::IdType::Id(
                "test_rust_stripe_123".to_string(),
            )),
        }),

        // Payment details
        amount: Some(grpc_api_types::payments::Money {
            minor_amount: 1000,
            currency: payments::Currency::Usd.into(),
        }),
        capture_method: Some(payments::CaptureMethod::Automatic.into()),

        // Card payment method
        payment_method: Some(payments::PaymentMethod {
            payment_method: Some(payments::payment_method::PaymentMethod::Card(
                payments::CardDetails {
                    card_number: Some(
                        "4242424242424242"
                            .to_string()
                            .try_into()
                            .expect("valid card number"),
                    ),
                    card_exp_month: Some(Secret::new("12".to_string())),
                    card_exp_year: Some(Secret::new("2050".to_string())),
                    card_cvc: Some(Secret::new("123".to_string())),
                    card_holder_name: Some(Secret::new("Rust Test User".to_string())),
                    ..Default::default()
                },
            )),
        }),

        // Customer info
        customer: Some(payments::Customer {
            email: Some(Secret::new("customer@example.com".to_string())),
            name: Some("Test Customer".to_string()),
            ..Default::default()
        }),

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
fn build_metadata(api_key: &str) -> HashMap<String, String> {
    let mut metadata = HashMap::new();

    // Connector routing (used by parse_metadata / build_ffi_request)
    metadata.insert("connector".to_string(), "Stripe".to_string());
    metadata.insert(
        "connector_auth_type".to_string(),
        serde_json::json!({
            "Stripe": {
                "api_key": api_key,
            }
        })
        .to_string(),
    );
    metadata
}

/// Demo 1: Low-level handler call.
fn demo_low_level(
    request: &PaymentServiceAuthorizeRequest,
    metadata: &HashMap<String, String>,
    ffi_options: &FfiOptions,
) {
    eprintln!("=== Demo 1: Low-Level Handler Call ===\n");

    let ffi_request = match hyperswitch_payments_client::build_ffi_request(
        request.clone(),
        metadata,
        ffi_options,
    ) {
        Ok(req) => req,
        Err(e) => {
            eprintln!("Failed to build FFI request: {}", e);
            return;
        }
    };

    let environment = Some(
        grpc_api_types::payments::Environment::try_from(ffi_options.environment)
            .unwrap_or_default(),
    );

    match connector_service_ffi::handlers::payments::authorize_req_handler(ffi_request, environment)
    {
        Ok(Some(connector_request)) => {
            let url = connector_request.url.clone();
            let method = connector_request.method;
            let headers: HashMap<String, String> = connector_request.get_headers_map();
            let (body, _) = connector_request
                .body
                .as_ref()
                .map(|b| b.get_body_bytes())
                .transpose()
                .unwrap_or_default()
                .unwrap_or((None, None));

            eprintln!("Connector HTTP request generated successfully:");
            eprintln!("  URL:    {}", url);
            eprintln!("  Method: {:?}", method);
            eprintln!("  Headers: {:?}", headers.keys().collect::<Vec<_>>());
            if let Some(b) = body {
                eprintln!("  Body Length: {} bytes", b.len());
                if let Ok(body_str) = String::from_utf8(b) {
                    eprintln!("  Body (UTF-8):\n{}\n", body_str);
                }
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
async fn demo_full_round_trip(
    request: PaymentServiceAuthorizeRequest,
    metadata: &HashMap<String, String>,
    ffi_options: FfiOptions,
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

    // 1. ConnectorConfig (connector, auth, environment)
    let config = ConnectorConfig {
        connector: ffi_options.connector,
        auth: ffi_options.auth.clone(),
        environment: ffi_options.environment,
    };

    // 2. Optional RequestConfig defaults (http, vault)
    let defaults = RequestConfig::default();

    let client =
        ConnectorClient::new(config, Some(defaults)).expect("Failed to create ConnectorClient");

    // 3. Call authorize
    match client.authorize(request, metadata, None).await {
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
