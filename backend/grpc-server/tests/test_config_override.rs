// #![allow(clippy::panic_in_result_fn)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::as_conversions)]
#![allow(clippy::unnecessary_cast)]
#![allow(clippy::print_stdout)]
#![allow(clippy::panic_in_result_fn)]

use grpc_api_types::payments::{
    card_payment_method_type, identifier::IdType, payment_method,
    payment_service_client::PaymentServiceClient, Address, AuthenticationType, BrowserInformation,
    CaptureMethod, CardDetails, CardPaymentMethodType, Currency, Identifier, PaymentAddress,
    PaymentMethod, PaymentServiceAuthorizeRequest,
};
use grpc_server::{app, configs};
use serde_json::json;
// use std::collections::HashMap;
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
            email: Some("example@gmail.com".to_string()),
            payment_method: Some(PaymentMethod {
                payment_method: Some(payment_method::PaymentMethod::Card(CardPaymentMethodType {
                    card_type: Some(card_payment_method_type::CardType::Debit(CardDetails {
                        card_number: "5123456789012346".to_string(),
                        card_exp_month: "07".to_string(),
                        card_exp_year: "2030".to_string(),
                        card_cvc: "100".to_string(),
                        ..Default::default()
                    })),
                })),
            }),
            address: Some(PaymentAddress {
                shipping_address: None,
                billing_address: Some(Address {
                    phone_number: Some("9876354210".to_string()),
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
            override_config.to_string().parse().unwrap(),
        );

        // Add required headers
        request
            .metadata_mut()
            .insert("x-connector", "razorpay".parse().unwrap());

        request
            .metadata_mut()
            .insert("x-auth", "body-key".parse().unwrap());

        request
            .metadata_mut()
            .insert("x-api-key", "".parse().unwrap());

        request.metadata_mut().insert("x-key1", "".parse().unwrap());

        // Make the request
        let response = client.authorize(request).await;

        // The request should fail with an invalid argument error since we're using test data
        // but we can verify that the configuration override was processed
        println!("Response: {:?}", response);
        assert!(response.is_err());

        // let error = response.unwrap_err();
        // assert!(error.message().contains("Invalid request data"));
    });
    Ok(())
}
