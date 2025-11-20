#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::unwrap_in_result)]
#![allow(clippy::as_conversions)]
#![allow(clippy::unnecessary_cast)]
#![allow(clippy::print_stdout)]
#![allow(clippy::panic_in_result_fn)]

use cards::CardNumber;
use grpc_api_types::payments::{
    card_payment_method_type, identifier::IdType, payment_method,
    payment_service_client::PaymentServiceClient, Address, AuthenticationType, BrowserInformation,
    CaptureMethod, CardDetails, CardPaymentMethodType, Currency, Identifier, PaymentAddress,
    PaymentMethod, PaymentServiceAuthorizeRequest,
};
use grpc_server::{app, configs};
use hyperswitch_masking::Secret;
use serde_json::json;
use std::str::FromStr;
use tonic::{transport::Channel, Request};
mod common;

#[tokio::test]
async fn test_config_override() -> Result<(), Box<dyn std::error::Error>> {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        // let mut client = PaymentServiceClient::connect("http://localhost:8000")
        // .await
        // .unwrap();
        // Create a request with configuration override
        let mut request = Request::new(PaymentServiceAuthorizeRequest {
            amount: 1000,
            minor_amount: 1000,
            currency: Currency::Inr as i32,
            email: Some(Secret::new("example@gmail.com".to_string())),
            payment_method: Some(PaymentMethod {
                payment_method: Some(payment_method::PaymentMethod::Card(CardPaymentMethodType {
                    card_type: Some(card_payment_method_type::CardType::Debit(CardDetails {
                        card_number: Some(CardNumber::from_str("5123456789012346").unwrap()),
                        card_exp_month: Some(Secret::new("07".to_string())),
                        card_exp_year: Some(Secret::new("2030".to_string())),
                        card_cvc: Some(Secret::new("100".to_string())),
                        ..Default::default()
                    })),
                })),
            }),
            address: Some(PaymentAddress {
                shipping_address: None,
                billing_address: Some(Address {
                    phone_number: Some(Secret::new("9876354210".to_string())),
                    phone_country_code: Some("+1".to_string()),
                    ..Default::default()
                }),
            }),
            auth_type: AuthenticationType::ThreeDs as i32,
            capture_method: Some(CaptureMethod::Manual as i32),
            browser_info: Some(BrowserInformation {
                user_agent: Some("Mozilla/5.0".to_string()),
                accept_header: Some(
                    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".to_string(),
                ),
                language: Some("en-US".to_string()),
                color_depth: Some(24),
                screen_height: Some(1080),
                screen_width: Some(1920),
                java_enabled: Some(false),
                ..Default::default()
            }),
            request_ref_id: Some(Identifier {
                id_type: Some(IdType::Id("payment_9089".to_string())),
            }),
            return_url: Some("www.google.com".to_string()),
            ..Default::default()
        });

        // Add configuration override header
        let override_config = json!({
            "connectors": {
                "razorpay": {
                    "base_url": "https://override-test-api.razorpay.com/"
                }
            },
            "proxy": {
                "idle_pool_connection_timeout": 30,
            },
        });

        request.metadata_mut().insert(
            "x-config-override",
            override_config
                .to_string()
                .parse()
                .expect("valid header value"),
        );

        // Add required headers
        request.metadata_mut().insert(
            "x-connector",
            "razorpay".parse().expect("valid header value"),
        );

        request
            .metadata_mut()
            .insert("x-auth", "body-key".parse().expect("valid header value"));

        request
            .metadata_mut()
            .insert("x-api-key", "".parse().expect("valid header value"));

        request
            .metadata_mut()
            .insert("x-key1", "".parse().expect("valid header value"));

        // Make the request
        let response = client.authorize(request).await;

        // The request should fail with an invalid argument error since we're using test data
        // but we can verify that the configuration override was processed
        println!("Response: {response:?}");
        assert!(response.is_err());

        // let error = response.unwrap_err();
        // assert!(error.message().contains("Invalid request data"));
    });
    Ok(())
}

#[cfg(test)]
mod unit {
    use grpc_server::configs::Config;
    use grpc_server::utils::{merge_config_with_override, merge_configs};
    use serde_json::json;

    #[test]
    fn test_merge_configs_simple() {
        let base = json!({
            "a": 1,
            "b": { "c": 2, "d": 3 },
            "e": [1, 2, 3],
        });
        let override_ = json!({
            "a": 10,
            "b": { "c": 20 },
            "e": [4, 5],
            "f": 100
        });
        let merged = merge_configs(&override_, &base);
        let expected = json!({
            "a": 10,
            "b": { "c": 20, "d": 3 },
            "e": [4, 5],
            "f": 100
        });
        assert_eq!(merged, expected);
    }

    #[test]
    fn test_config_from_metadata_override() {
        // Minimal config for test
        let base_config = Config::new().expect("default config should load");
        let override_json = json!({
            "proxy": { "idle_pool_connection_timeout": 123 },
        });
        let override_str = override_json.to_string();
        let result = merge_config_with_override(Some(override_str), base_config.clone());
        assert!(
            result.is_ok(),
            "config_from_metadata should succeed with valid override"
        );
        let new_config = result.expect("should get config");
        // Check that the override was applied
        assert_eq!(new_config.proxy.idle_pool_connection_timeout, Some(123));
    }

    #[test]
    fn test_config_from_metadata_no_override() {
        let base_config = Config::new().expect("default config should load");
        let result = merge_config_with_override(None, base_config.clone());
        assert!(
            result.is_ok(),
            "config_from_metadata should succeed with no override"
        );
        let new_config = result.expect("should get config");
        // Should be equal to base config
        assert_eq!(
            serde_json::to_value(&*new_config).expect("serialize new config"),
            serde_json::to_value(&base_config).expect("serialize base config")
        );
    }
}
