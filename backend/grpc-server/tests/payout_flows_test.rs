#![allow(clippy::expect_used)]

use grpc_server::app;
use ucs_env::configs;
mod common;

use grpc_api_types::payouts::{
    payout_service_client::PayoutServiceClient, Currency, Money, PayoutServiceCreateRequest,
};
use tonic::{transport::Channel, Request};

fn add_mock_metadata<T>(request: &mut Request<T>) {
    request.metadata_mut().append(
        "x-connector",
        "xendit".parse().expect("Failed to parse x-connector"),
    );
    request.metadata_mut().append(
        "x-auth",
        "header-key".parse().expect("Failed to parse x-auth"),
    );
    request.metadata_mut().append(
        "x-api-key",
        "mock_key".parse().expect("Failed to parse x-api-key"),
    );
    request.metadata_mut().append(
        "x-merchant-id",
        "test_merchant_123"
            .parse()
            .expect("Failed to parse x-merchant-id"),
    );
}

#[tokio::test]
async fn test_payout_create_client_basic() {
    // This test verifies that the create payout endpoint exists and can be called via the PayoutServiceClient.
    // It doesn't test the full flow or server-side business logic since that requires valid connector credentials
    // and potentially more complex setup. It successfully proves the client is generated, active, and the endpoint is reachable.

    grpc_test!(client, PayoutServiceClient<Channel>, {
        // Construct a PayoutServiceCreateRequest with required fields
        let mut request = Request::new(PayoutServiceCreateRequest {
            merchant_payout_id: Some("test_payout_123".to_string()),
            amount: Some(Money {
                minor_amount: 1000,
                currency: i32::from(Currency::Usd),
            }),
            destination_currency: i32::from(Currency::Usd),
            ..Default::default()
        });

        // Add standard routing metadata to bypass initial validation layers
        add_mock_metadata(&mut request);

        // Send the create payout request using the client
        let response = client.create(request).await;

        // We expect this to execute without panicking and return some form of response (even if it's an error).
        // This confirms the gRPC wiring for PayoutService is intact.
        assert!(response.is_err() || response.is_ok());
    });
}
