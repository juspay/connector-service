use domain_types::utils::ForeignTryFrom;
use grpc_api_types::payments::{self, PaymentServiceAuthorizeRequest};
use hyperswitch_payments_client::{
    connector_auth, ConnectorAuth, ConnectorClient, ConnectorName, ConnectorConfig,
    HeaderKeyAuth,
};
use std::collections::HashMap;

#[tokio::main]
async fn main() {
    let request = build_authorize_request();

    demo_low_level(&request);

    demo_full_round_trip(request).await;
}

fn build_authorize_request() -> PaymentServiceAuthorizeRequest {
    PaymentServiceAuthorizeRequest {
        request_ref_id: Some(payments::Identifier {
            id_type: Some(payments::identifier::IdType::Id(
                "test_payment_123456".to_string(),
            )),
        }),
        amount: 1000,
        minor_amount: 1000,
        currency: payments::Currency::Usd.into(),
        capture_method: Some(payments::CaptureMethod::Automatic.into()),
        payment_method: Some(payments::PaymentMethod {
            payment_method: Some(payments::payment_method::PaymentMethod::Card(
                payments::CardDetails {
                    card_number: Some(
                        "4111111111111111"
                            .parse::<cards::validate::CardNumber>()
                            .unwrap(),
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
        email: Some(hyperswitch_masking::Secret::new(
            "customer@example.com".to_string(),
        )),
        customer_name: Some("Test Customer".to_string()),
        auth_type: payments::AuthenticationType::NoThreeDs.into(),
        enrolled_for_3ds: Some(false),
        return_url: Some("https://example.com/return".to_string()),
        webhook_url: Some("https://example.com/webhook".to_string()),
        address: Some(payments::PaymentAddress::default()),
        description: Some("Test payment".to_string()),
        test_mode: Some(true),
        ..Default::default()
    }
}

fn build_masked_metadata() -> Option<common_utils::metadata::MaskedMetadata> {
    let mut headers = HashMap::new();
    headers.insert(
        common_utils::consts::X_MERCHANT_ID.to_string(),
        "dummy_merchant".to_string(),
    );
    headers.insert(
        common_utils::consts::X_TENANT_ID.to_string(),
        "dummy_tenant".to_string(),
    );
    headers.insert(
        common_utils::consts::X_CONNECTOR_NAME.to_string(),
        "stripe".to_string(),
    );
    headers.insert(
        common_utils::consts::X_REQUEST_ID.to_string(),
        "dummy_request_id".to_string(),
    );
    headers.insert(
        common_utils::consts::X_AUTH.to_string(),
        "dummy_auth".to_string(),
    );
    connector_service_ffi::utils::ffi_headers_to_masked_metadata(&headers).ok()
}

fn demo_low_level(request: &PaymentServiceAuthorizeRequest) {
    eprintln!("=== Demo 1: Low-Level Handler Call ===\n");

    let api_key =
        std::env::var("STRIPE_API_KEY").unwrap_or_else(|_| "sk_test_placeholder".to_string());

    let config = ConnectorConfig {
        connector: ConnectorName::Stripe as i32,
        auth: Some(ConnectorAuth {
            auth_type: Some(connector_auth::AuthType::HeaderKey(HeaderKeyAuth {
                api_key,
            })),
        }),
    };

    let metadata = connector_service_ffi::types::FfiConnectorConfig::foreign_try_from(config)
        .expect("config conversion failed");

    let ffi_request = connector_service_ffi::types::FfiRequestData {
        payload: request.clone(),
        extracted_metadata: metadata,
        masked_metadata: build_masked_metadata(),
    };

    match connector_service_ffi::handlers::payments::authorize_req_handler(ffi_request) {
        Ok(Some(connector_request)) => {
            let raw_json =
                external_services::service::extract_raw_connector_request(&connector_request);
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&raw_json) {
                eprintln!("Connector HTTP request generated:");
                eprintln!("  URL:    {}", parsed["url"].as_str().unwrap_or("N/A"));
                eprintln!("  Method: {}", parsed["method"].as_str().unwrap_or("N/A"));
                eprintln!(
                    "\nFull JSON:\n{}\n",
                    serde_json::to_string_pretty(&parsed).unwrap_or(raw_json)
                );
            }
        }
        Ok(None) => eprintln!("No connector request generated.\n"),
        Err(e) => {
            eprintln!("Handler error: {:?}\n", e);
        }
    }
}

async fn demo_full_round_trip(request: PaymentServiceAuthorizeRequest) {
    eprintln!("\n=== Demo 2: Full Round-Trip (ConnectorClient) ===\n");

    let api_key = std::env::var("STRIPE_API_KEY").unwrap_or_default();
    if api_key.is_empty() || api_key == "sk_test_placeholder" {
        eprintln!(
            "Skipping: STRIPE_API_KEY not set. Run with: STRIPE_API_KEY=sk_test_xxx cargo run\n"
        );
        return;
    }

    let config = ConnectorConfig {
        connector: ConnectorName::Stripe as i32,
        auth: Some(ConnectorAuth {
            auth_type: Some(connector_auth::AuthType::HeaderKey(HeaderKeyAuth {
                api_key,
            })),
        }),
    };

    let client = ConnectorClient::new(config);

    eprintln!("Connector: Stripe");
    eprintln!("Sending authorize request...\n");

    match client.authorize(request).await {
        Ok(response) => {
            eprintln!(
                "Response: {}",
                serde_json::to_string_pretty(&response)
                    .unwrap_or_else(|_| format!("{:?}", response))
            );
        }
        Err(e) => eprintln!("Error: {}\n", e),
    }
}
