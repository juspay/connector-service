#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]

use grpc_server::app;
use hyperswitch_masking::ExposeInterface;
use ucs_env::configs;
mod common;
mod utils;

use std::time::{SystemTime, UNIX_EPOCH};

use grpc_api_types::payments::{
    merchant_authentication_service_client::MerchantAuthenticationServiceClient,
    merchant_authentication_service_create_client_authentication_token_request::DomainContext,
    Currency, MerchantAuthenticationServiceCreateClientAuthenticationTokenRequest, Money,
    PaymentClientAuthenticationContext,
};
use tonic::{transport::Channel, Request};
use uuid::Uuid;

const CONNECTOR_NAME: &str = "ppro";
const AUTH_TYPE: &str = "body-key";
const MERCHANT_ID: &str = "test_merchant";

fn get_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn add_ppro_metadata<T>(request: &mut Request<T>) {
    let auth = utils::credential_utils::load_connector_auth(CONNECTOR_NAME)
        .expect("Failed to load ppro credentials");

    let (api_key, key1) = match auth {
        domain_types::router_data::ConnectorAuthType::BodyKey { api_key, key1 } => {
            (api_key.expose(), key1.expose())
        }
        _ => panic!("Expected BodyKey auth type for ppro"),
    };

    request.metadata_mut().append(
        "x-connector",
        CONNECTOR_NAME.parse().expect("Failed to parse x-connector"),
    );
    request.metadata_mut().append(
        "x-auth",
        AUTH_TYPE.parse().expect("Failed to parse x-auth"),
    );
    request.metadata_mut().append(
        "x-api-key",
        api_key.parse().expect("Failed to parse x-api-key"),
    );
    request
        .metadata_mut()
        .append("x-key1", key1.parse().expect("Failed to parse x-key1"));
    request.metadata_mut().append(
        "x-merchant-id",
        MERCHANT_ID.parse().expect("Failed to parse x-merchant-id"),
    );
    request.metadata_mut().append(
        "x-request-id",
        format!("ppro_req_{}", get_timestamp())
            .parse()
            .expect("Failed to parse x-request-id"),
    );
    request.metadata_mut().append(
        "x-tenant-id",
        "default".parse().expect("Failed to parse x-tenant-id"),
    );
    request.metadata_mut().append(
        "x-connector-request-reference-id",
        format!("ppro_ref_{}", Uuid::new_v4())
            .parse()
            .expect("Failed to parse x-connector-request-reference-id"),
    );
}

fn create_client_auth_token_request(
) -> MerchantAuthenticationServiceCreateClientAuthenticationTokenRequest {
    MerchantAuthenticationServiceCreateClientAuthenticationTokenRequest {
        merchant_client_session_id: format!("ppro_session_{}", Uuid::new_v4()),
        domain_context: Some(DomainContext::Payment(
            PaymentClientAuthenticationContext {
                amount: Some(Money {
                    minor_amount: 1000,
                    currency: i32::from(Currency::Eur),
                }),
                return_url: Some("https://example.com/return".to_string()),
                ..Default::default()
            },
        )),
        ..Default::default()
    }
}

#[tokio::test]
async fn test_create_client_authentication_token() {
    grpc_test!(client, MerchantAuthenticationServiceClient<Channel>, {
        let request = create_client_auth_token_request();

        let mut grpc_request = Request::new(request);
        add_ppro_metadata(&mut grpc_request);

        let response = client
            .create_client_authentication_token(grpc_request)
            .await
            .expect("gRPC create_client_authentication_token call failed")
            .into_inner();

        assert!(
            response.session_data.is_some(),
            "Session data should be present in response"
        );
    });
}
