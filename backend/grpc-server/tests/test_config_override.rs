#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::unwrap_in_result)]
#![allow(clippy::as_conversions)]
#![allow(clippy::unnecessary_cast)]
#![allow(clippy::print_stdout)]
#![allow(clippy::panic_in_result_fn)]

use cards::CardNumber;
use grpc_api_types::payments::{
    identifier::IdType, payment_method, payment_service_client::PaymentServiceClient, Address,
    AuthenticationType, BrowserInformation, CaptureMethod, CardDetails, Currency, Identifier,
    PaymentAddress, PaymentMethod, PaymentServiceAuthorizeRequest,
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
                payment_method: Some(payment_method::PaymentMethod::Card(CardDetails {
                    card_number: Some(CardNumber::from_str("5123456789012346").unwrap()),
                    card_exp_month: Some(Secret::new("07".to_string())),
                    card_exp_year: Some(Secret::new("2030".to_string())),
                    card_cvc: Some(Secret::new("100".to_string())),
                    ..Default::default()
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
    use base64::{engine::general_purpose, Engine as _};
    use common_utils::{consts, metadata::MaskedMetadata};
    use grpc_server::configs;
    use grpc_server::configs::Config;
    use grpc_server::logger::config::{LogFormat, LogKafka};
    use grpc_server::utils::merge_config_with_override;
    use serde_json::json;
    use tonic::metadata::MetadataMap;

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
    fn test_log_kafka_partial_override() {
        let mut base_config = Config::new().expect("default config should load");
        base_config.log.kafka = Some(LogKafka {
            enabled: true,
            level: serde_json::from_value(json!("INFO")).expect("level should parse"),
            filtering_directive: Some("info".to_string()),
            brokers: vec!["localhost:9092".to_string()],
            topic: "base-topic".to_string(),
            ..Default::default()
        });

        let override_json = json!({
            "log": {
                "kafka": {
                    "level": "ERROR"
                }
            }
        });
        let override_str = override_json.to_string();
        let result = merge_config_with_override(Some(override_str), base_config.clone());
        assert!(
            result.is_ok(),
            "config_from_metadata should succeed with valid override"
        );
        let new_config = result.expect("should get config");
        let kafka_config = new_config
            .log
            .kafka
            .as_ref()
            .expect("kafka config should be present");
        assert_eq!(kafka_config.level.into_level(), tracing::Level::ERROR);
        assert!(kafka_config.enabled);
        assert_eq!(kafka_config.brokers, vec!["localhost:9092".to_string()]);
        assert_eq!(kafka_config.topic.as_str(), "base-topic");
        assert_eq!(kafka_config.filtering_directive.as_deref(), Some("info"));
    }

    #[test]
    fn test_proxy_mitm_cert_override_base64() {
        let base_config = Config::new().expect("default config should load");
        let pem = "-----BEGIN CERTIFICATE-----\nTEST_CERT\n-----END CERTIFICATE-----\n";
        let encoded = general_purpose::STANDARD.encode(pem.as_bytes());
        let override_json = json!({
            "proxy": {
                "mitm_ca_cert": encoded
            }
        });
        let result =
            merge_config_with_override(Some(override_json.to_string()), base_config.clone());
        assert!(
            result.is_ok(),
            "config_from_metadata should succeed with valid override"
        );
        let new_config = result.expect("should get config");
        assert_eq!(new_config.proxy.mitm_ca_cert.as_deref(), Some(pem));
    }

    #[test]
    fn test_proxy_mitm_cert_override_rejects_pem() {
        let base_config = Config::new().expect("default config should load");
        let override_json = json!({
            "proxy": {
                "mitm_ca_cert": "-----BEGIN CERTIFICATE-----\nTEST_CERT\n-----END CERTIFICATE-----\n"
            }
        });
        let result =
            merge_config_with_override(Some(override_json.to_string()), base_config.clone());
        assert!(
            result.is_err(),
            "config_from_metadata should reject raw PEM in mitm_ca_cert override"
        );
    }

    #[test]
    fn test_full_config_override_applies_all_sections() {
        let base_config = Config::new().expect("default config should load");
        let pem = "-----BEGIN CERTIFICATE-----\nTEST_CERT\n-----END CERTIFICATE-----\n";
        let encoded = general_purpose::STANDARD.encode(pem.as_bytes());
        let override_json = json!({
            "common": {
                "environment": "sandbox"
            },
            "server": {
                "host": "127.0.0.2",
                "port": 5555,
                "type": "http"
            },
            "metrics": {
                "host": "127.0.0.3",
                "port": 9091
            },
            "log": {
                "console": {
                    "enabled": true,
                    "level": "ERROR",
                    "log_format": "default",
                    "filtering_directive": "debug"
                },
                "kafka": {
                    "enabled": true,
                    "level": "WARN",
                    "filtering_directive": null,
                    "brokers": ["kafka:9092"],
                    "topic": "override-topic",
                    "batch_size": 10,
                    "flush_interval_ms": 250,
                    "buffer_limit": 1000
                }
            },
            "proxy": {
                "http_url": "http://proxy.local",
                "https_url": null,
                "idle_pool_connection_timeout": 45,
                "bypass_proxy_urls": ["http://no-proxy.local"],
                "mitm_proxy_enabled": true,
                "mitm_ca_cert": encoded
            },
            "connectors": {
                "razorpay": {
                    "base_url": "https://razorpay.example",
                    "dispute_base_url": "https://dispute.razorpay.example"
                },
                "trustpay": {
                    "base_url": "https://trustpay.example",
                    "base_url_bank_redirects": "https://trustpay-bank.example"
                }
            },
            "events": {
                "enabled": true,
                "topic": "events-override",
                "brokers": ["broker1:9092", "broker2:9092"],
                "partition_key_field": "merchant_id",
                "transformations": { "order_id": "payment_id" },
                "static_values": { "app": "grpc" },
                "extractions": { "path": "metadata.path" }
            },
            "lineage": {
                "enabled": true,
                "header_name": "x-lineage-test",
                "field_prefix": "test_"
            },
            "unmasked_headers": {
                "keys": ["x-request-id", "x-trace-id"]
            },
            "test": {
                "enabled": true,
                "mock_server_url": "http://mock.local"
            },
            "api_tags": {
                "tags": { "psync": "PSYNC_TAG" }
            }
        });

        let result =
            merge_config_with_override(Some(override_json.to_string()), base_config.clone());
        assert!(
            result.is_ok(),
            "config_from_metadata should succeed with full override"
        );
        let new_config = result.expect("should get config");

        assert_eq!(new_config.common.environment, consts::Env::Sandbox);
        assert_eq!(new_config.server.host.as_str(), "127.0.0.2");
        assert_eq!(new_config.server.port, 5555);
        assert_eq!(new_config.server.type_, configs::ServiceType::Http);
        assert_eq!(new_config.metrics.host.as_str(), "127.0.0.3");
        assert_eq!(new_config.metrics.port, 9091);

        assert!(new_config.log.console.enabled);
        assert_eq!(
            new_config.log.console.level.into_level(),
            tracing::Level::ERROR
        );
        assert!(matches!(
            new_config.log.console.log_format,
            LogFormat::Default
        ));
        assert_eq!(
            new_config.log.console.filtering_directive.as_deref(),
            Some("debug")
        );

        let kafka_config = new_config
            .log
            .kafka
            .as_ref()
            .expect("kafka config should be present");
        assert!(kafka_config.enabled);
        assert_eq!(kafka_config.level.into_level(), tracing::Level::WARN);
        assert!(kafka_config.filtering_directive.is_none());
        assert_eq!(kafka_config.brokers, vec!["kafka:9092".to_string()]);
        assert_eq!(kafka_config.topic.as_str(), "override-topic");
        assert_eq!(kafka_config.batch_size, Some(10));
        assert_eq!(kafka_config.flush_interval_ms, Some(250));
        assert_eq!(kafka_config.buffer_limit, Some(1000));

        assert_eq!(
            new_config.proxy.http_url.as_deref(),
            Some("http://proxy.local")
        );
        assert_eq!(new_config.proxy.https_url, None);
        assert_eq!(new_config.proxy.idle_pool_connection_timeout, Some(45));
        assert_eq!(
            new_config.proxy.bypass_proxy_urls,
            vec!["http://no-proxy.local".to_string()]
        );
        assert!(new_config.proxy.mitm_proxy_enabled);
        assert_eq!(new_config.proxy.mitm_ca_cert.as_deref(), Some(pem));

        assert_eq!(
            new_config.connectors.razorpay.base_url.as_str(),
            "https://razorpay.example"
        );
        assert_eq!(
            new_config.connectors.razorpay.dispute_base_url.as_deref(),
            Some("https://dispute.razorpay.example")
        );
        assert_eq!(
            new_config.connectors.trustpay.base_url.as_str(),
            "https://trustpay.example"
        );
        assert_eq!(
            new_config
                .connectors
                .trustpay
                .base_url_bank_redirects
                .as_str(),
            "https://trustpay-bank.example"
        );

        assert!(new_config.events.enabled);
        assert_eq!(new_config.events.topic.as_str(), "events-override");
        assert_eq!(
            new_config.events.brokers,
            vec!["broker1:9092".to_string(), "broker2:9092".to_string()]
        );
        assert_eq!(
            new_config.events.partition_key_field.as_str(),
            "merchant_id"
        );
        assert_eq!(
            new_config
                .events
                .transformations
                .get("order_id")
                .map(String::as_str),
            Some("payment_id")
        );
        assert_eq!(
            new_config
                .events
                .static_values
                .get("app")
                .map(String::as_str),
            Some("grpc")
        );
        assert_eq!(
            new_config
                .events
                .extractions
                .get("path")
                .map(String::as_str),
            Some("metadata.path")
        );

        assert!(new_config.lineage.enabled);
        assert_eq!(new_config.lineage.header_name.as_str(), "x-lineage-test");
        assert_eq!(new_config.lineage.field_prefix.as_str(), "test_");

        assert!(new_config.unmasked_headers.should_unmask("x-request-id"));
        assert!(new_config.unmasked_headers.should_unmask("x-trace-id"));
        assert!(!new_config.unmasked_headers.should_unmask("authorization"));

        assert!(new_config.test.enabled);
        assert_eq!(
            new_config.test.mock_server_url.as_deref(),
            Some("http://mock.local")
        );
        assert_eq!(
            new_config.api_tags.tags.get("psync").map(String::as_str),
            Some("PSYNC_TAG")
        );
    }

    #[test]
    fn test_unmasked_headers_override_keeps_masking() {
        let base_config = Config::new().expect("default config should load");
        let override_json = json!({
            "unmasked_headers": {
                "keys": ["x-request-id"]
            }
        });
        let result =
            merge_config_with_override(Some(override_json.to_string()), base_config.clone());
        assert!(
            result.is_ok(),
            "config_from_metadata should succeed with header override"
        );
        let new_config = result.expect("should get config");

        let mut metadata = MetadataMap::new();
        metadata.insert("x-request-id", "req_123".parse().expect("valid header"));
        metadata.insert("authorization", "secret".parse().expect("valid header"));

        let masked_metadata = MaskedMetadata::new(metadata, new_config.unmasked_headers.clone());
        let request_id = masked_metadata
            .get_maskable("x-request-id")
            .expect("request id should be present");
        let auth = masked_metadata
            .get_maskable("authorization")
            .expect("authorization should be present");

        assert!(request_id.is_normal(), "unmasked header should be normal");
        assert!(auth.is_masked(), "masked header should remain masked");
    }
}
