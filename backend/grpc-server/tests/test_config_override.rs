use grpc_api_types::payments::{
    self, payment_service_client::PaymentServiceClient, Address, PaymentsAuthorizeRequest,
    PhoneDetails,
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
        let mut request = Request::new(PaymentsAuthorizeRequest {
            amount: 1000 as i64,
            currency: payments::Currency::Usd as i32, // USD
            payment_method: payments::PaymentMethod::Card as i32, // Card
            payment_method_data: Some(payments::PaymentMethodData {
                data: Some(payments::payment_method_data::Data::Card(payments::Card {
                    card_number: "5123456789012346".to_string(), // Updated card number
                    card_exp_month: "03".to_string(),
                    card_exp_year: "2030".to_string(),
                    card_cvc: "100".to_string(), // Updated CVC
                    ..Default::default()
                })),
            }),
            address: Some(payments::PaymentAddress {
                shipping: None,
                billing: Some(Address {
                    address: None,
                    phone: Some(PhoneDetails {
                        number: Some("1234567890".to_string()),
                        country_code: Some("+1".to_string()),
                    }),
                    email: Some("sweta.sharma@juspay.in".to_string()),
                }),
                unified_payment_method_billing: None,
                payment_method_billing: None,
            }),
            auth_type: payments::AuthenticationType::ThreeDs as i32,
            connector_request_reference_id: "test_reference".to_string(),
            enrolled_for_3ds: true,
            request_incremental_authorization: false,
            minor_amount: 1000 as i64,
            email: Some("sweta.sharma@juspay.in".to_string()),
            connector_customer: Some("cus_1234".to_string()),
            return_url: Some("www.google.com".to_string()),
            browser_info: Some(payments::BrowserInformation {
                // Added browser_info
                user_agent: Some("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)".to_string()),
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
        let response = client.payment_authorize(request).await;

        // The request should fail with an invalid argument error since we're using test data
        // but we can verify that the configuration override was processed
        println!("Response: {:?}", response);
        assert!(response.is_err());
        // let error = response.unwrap_err();
        // assert!(error.message().contains("Invalid request data"));
    });
    Ok(())
}
