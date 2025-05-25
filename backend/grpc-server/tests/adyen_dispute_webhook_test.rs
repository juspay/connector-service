#![allow(clippy::expect_used)]

use grpc_server::{app, configs};
mod common;
use grpc_api_types::payments::{
    payment_service_client::PaymentServiceClient,
    webhook_response_content::Content as GrpcWebhookContent, DisputeStage as GrpcDisputeStage,
    DisputeStatus as GrpcDisputeStatus, DisputesSyncResponse, IncomingWebhookRequest,
    RequestDetails,
};
use serde_json::json;
use tonic::{transport::Channel, Request};

// Helper function to construct Adyen webhook JSON body
fn build_adyen_webhook_json_body(
    event_code: &str,
    reason: &str,
    adyen_dispute_status: Option<&str>,
) -> serde_json::Value {
    let mut additional_data = serde_json::Map::new();
    if let Some(status) = adyen_dispute_status {
        additional_data.insert("disputeStatus".to_string(), json!(status));
    }
    let psp_reference = "9915555555555555"; // Default
    let original_reference = "9913333333333333"; // Default
    let merchant_account_code = "YOUR_MERCHANT_ACCOUNT"; // Default
    let merchant_reference = "YOUR_REFERENCE"; // Default
    let payment_method = "mc"; // Default
    let amount_currency = "EUR"; // Default
    let amount_value = 1000; // Default
    let event_date = "2023-12-01T12:00:00Z"; // Default
    let success_status = "true";

    json!({
        "live": "false",
        "notificationItems": [
            {
                "NotificationRequestItem": {
                    "eventCode": event_code,
                    "success": success_status,
                    "pspReference": psp_reference,
                    "originalReference": original_reference,
                    "merchantAccountCode": merchant_account_code,
                    "merchantReference": merchant_reference,
                    "paymentMethod": payment_method,
                    "eventDate": event_date,
                    "additionalData": additional_data,
                    "reason": reason,
                    "amount": {
                        "value": amount_value,
                        "currency": amount_currency
                    }
                }
            }
        ]
    })
}

// Helper to make the gRPC call and return the DisputesSyncResponse
async fn process_webhook_and_get_response(
    client: &mut PaymentServiceClient<Channel>,
    json_body: serde_json::Value,
) -> DisputesSyncResponse {
    let request_body_bytes =
        serde_json::to_vec(&json_body).expect("Failed to serialize json_body to Vec<u8>");

    let mut request = Request::new(IncomingWebhookRequest {
        request_details: Some(RequestDetails {
            method: grpc_api_types::payments::Method::Post as i32,
            headers: std::collections::HashMap::new(),
            uri: Some("/webhooks/adyen".to_string()),
            query_params: None,
            body: request_body_bytes,
        }),
        webhook_secrets: None,
    });

    let api_key = std::env::var("API_KEY").unwrap_or_else(|_| "test_adyen_api_key".to_string());
    let key1 =
        std::env::var("ADYEN_MERCHANT_ACCOUNT").unwrap_or_else(|_| "test_merchant_acc".to_string());
    let api_secret =
        std::env::var("ADYEN_WEBHOOK_HMAC_KEY").unwrap_or_else(|_| "test_hmac_key".to_string());

    request
        .metadata_mut()
        .append("x-connector", "adyen".parse().unwrap());
    request
        .metadata_mut()
        .append("x-auth", "signature-key".parse().unwrap());
    request
        .metadata_mut()
        .append("x-api-key", api_key.parse().unwrap());
    request
        .metadata_mut()
        .append("x-key1", key1.parse().unwrap());
    request
        .metadata_mut()
        .append("x-api-secret", api_secret.parse().unwrap());

    let response = client
        .incoming_webhook(request)
        .await
        .expect("gRPC incoming_webhook call failed")
        .into_inner();

    match response.content.and_then(|c| c.content) {
        Some(GrpcWebhookContent::DisputesResponse(dispute_response)) => dispute_response,
        Some(other_content) => panic!(
            "Incorrect webhook content type received: {:?}",
            other_content
        ),
        None => panic!("Webhook response content is missing"),
    }
}

// --- Test Cases ---
// Adyen Doc: https://docs.adyen.com/risk-management/disputes-api/dispute-notifications/#notification_of_chargeback
#[tokio::test]
async fn test_notification_of_chargeback_undefended() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        let event_code = "NOTIFICATION_OF_CHARGEBACK";
        let reason = "Fraudulent transaction";
        let adyen_dispute_status = Some("Undefended");

        let json_body = build_adyen_webhook_json_body(event_code, reason, adyen_dispute_status);
        let dispute_response = process_webhook_and_get_response(&mut client, json_body).await;

        assert_eq!(dispute_response.stage, GrpcDisputeStage::PreDispute as i32);
        assert_eq!(
            dispute_response.status,
            GrpcDisputeStatus::DisputeOpened as i32
        );
        assert_eq!(dispute_response.dispute_message, Some(reason.to_string()));
    });
}

// Adyen Doc: https://docs.adyen.com/risk-management/disputes-api/dispute-notifications/#notification_of_chargeback
#[tokio::test]
async fn test_notification_of_chargeback_pending() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        let event_code = "NOTIFICATION_OF_CHARGEBACK";
        let reason = "Product not received";
        let adyen_dispute_status = Some("Pending");

        let json_body = build_adyen_webhook_json_body(event_code, reason, adyen_dispute_status);
        let dispute_response = process_webhook_and_get_response(&mut client, json_body).await;

        assert_eq!(dispute_response.stage, GrpcDisputeStage::PreDispute as i32);
        assert_eq!(
            dispute_response.status,
            GrpcDisputeStatus::DisputeOpened as i32
        );
        assert_eq!(dispute_response.dispute_message, Some(reason.to_string()));
    });
}

// Adyen Doc: https://docs.adyen.com/risk-management/disputes-api/dispute-notifications/#chargeback
#[tokio::test]
async fn test_chargeback_undefended() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        let event_code = "CHARGEBACK";
        let reason = "Service not rendered";
        let adyen_dispute_status = Some("Undefended");

        let json_body = build_adyen_webhook_json_body(event_code, reason, adyen_dispute_status);
        let dispute_response = process_webhook_and_get_response(&mut client, json_body).await;

        assert_eq!(
            dispute_response.stage,
            GrpcDisputeStage::ActiveDispute as i32
        );
        assert_eq!(
            dispute_response.status,
            GrpcDisputeStatus::DisputeOpened as i32
        );
        assert_eq!(dispute_response.dispute_message, Some(reason.to_string()));
    });
}

// Adyen Doc: https://docs.adyen.com/risk-management/disputes-api/dispute-notifications/#chargeback
#[tokio::test]
async fn test_chargeback_pending() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        let event_code = "CHARGEBACK";
        let reason = "Credit not processed";
        let adyen_dispute_status = Some("Pending");

        let json_body = build_adyen_webhook_json_body(event_code, reason, adyen_dispute_status);
        let dispute_response = process_webhook_and_get_response(&mut client, json_body).await;

        assert_eq!(
            dispute_response.stage,
            GrpcDisputeStage::ActiveDispute as i32
        );
        assert_eq!(
            dispute_response.status,
            GrpcDisputeStatus::DisputeOpened as i32
        );
        assert_eq!(dispute_response.dispute_message, Some(reason.to_string()));
    });
}

// Adyen Doc: https://docs.adyen.com/risk-management/disputes-api/dispute-notifications/#chargeback
#[tokio::test]
async fn test_chargeback_lost() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        let event_code = "CHARGEBACK";
        let reason = "Duplicate transaction";
        let adyen_dispute_status = Some("Lost");

        let json_body = build_adyen_webhook_json_body(event_code, reason, adyen_dispute_status);
        let dispute_response = process_webhook_and_get_response(&mut client, json_body).await;

        assert_eq!(
            dispute_response.stage,
            GrpcDisputeStage::ActiveDispute as i32
        );
        assert_eq!(
            dispute_response.status,
            GrpcDisputeStatus::DisputeLost as i32
        );
        assert_eq!(dispute_response.dispute_message, Some(reason.to_string()));
    });
}

// Adyen Doc: https://docs.adyen.com/risk-management/disputes-api/dispute-notifications/#chargeback
#[tokio::test]
async fn test_chargeback_accepted() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        let event_code = "CHARGEBACK";
        let reason = "Fraudulent transaction - merchant accepted";
        let adyen_dispute_status = Some("Accepted");

        let json_body = build_adyen_webhook_json_body(event_code, reason, adyen_dispute_status);
        let dispute_response = process_webhook_and_get_response(&mut client, json_body).await;

        assert_eq!(
            dispute_response.stage,
            GrpcDisputeStage::ActiveDispute as i32
        );
        assert_eq!(
            dispute_response.status,
            GrpcDisputeStatus::DisputeAccepted as i32
        );
        assert_eq!(dispute_response.dispute_message, Some(reason.to_string()));
    });
}

// Adyen Doc: https://docs.adyen.com/risk-management/disputes-api/dispute-notifications/#chargeback_reversed
#[tokio::test]
async fn test_chargeback_reversed_pending() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        let event_code = "CHARGEBACK_REVERSED";
        let reason = "Defense successful, awaiting bank review";
        let adyen_dispute_status = Some("Pending");

        let json_body = build_adyen_webhook_json_body(event_code, reason, adyen_dispute_status);
        let dispute_response = process_webhook_and_get_response(&mut client, json_body).await;

        assert_eq!(
            dispute_response.stage,
            GrpcDisputeStage::ActiveDispute as i32
        );
        assert_eq!(
            dispute_response.status,
            GrpcDisputeStatus::DisputeChallenged as i32
        );
        assert_eq!(dispute_response.dispute_message, Some(reason.to_string()));
    });
}

// Adyen Doc: https://docs.adyen.com/risk-management/disputes-api/dispute-notifications/#chargeback_reversed
#[tokio::test]
async fn test_chargeback_reversed_won() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        let event_code = "CHARGEBACK_REVERSED";
        let reason = "Defense accepted by bank";
        let adyen_dispute_status = Some("Won");

        let json_body = build_adyen_webhook_json_body(event_code, reason, adyen_dispute_status);
        let dispute_response = process_webhook_and_get_response(&mut client, json_body).await;

        assert_eq!(
            dispute_response.stage,
            GrpcDisputeStage::ActiveDispute as i32
        );
        assert_eq!(
            dispute_response.status,
            GrpcDisputeStatus::DisputeWon as i32
        );
        assert_eq!(dispute_response.dispute_message, Some(reason.to_string()));
    });
}

// Adyen Doc: https://docs.adyen.com/risk-management/disputes-api/dispute-notifications/#second_chargeback
#[tokio::test]
async fn test_second_chargeback_lost() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        let event_code = "SECOND_CHARGEBACK";
        let reason = "Defense declined after initial reversal";
        let adyen_dispute_status = Some("Lost");

        let json_body = build_adyen_webhook_json_body(event_code, reason, adyen_dispute_status);
        let dispute_response = process_webhook_and_get_response(&mut client, json_body).await;

        assert_eq!(
            dispute_response.stage,
            GrpcDisputeStage::PreArbitration as i32
        );
        assert_eq!(
            dispute_response.status,
            GrpcDisputeStatus::DisputeLost as i32
        );
        assert_eq!(dispute_response.dispute_message, Some(reason.to_string()));
    });
}

// Adyen Doc: https://docs.adyen.com/risk-management/disputes-api/dispute-notifications/#prearbitration_won
#[tokio::test]
async fn test_prearbitration_won_with_status_won() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        let event_code = "PREARBITRATION_WON";
        let reason = "Pre-arbitration won by merchant";
        let adyen_dispute_status = Some("Won");

        let json_body = build_adyen_webhook_json_body(event_code, reason, adyen_dispute_status);
        let dispute_response = process_webhook_and_get_response(&mut client, json_body).await;

        assert_eq!(
            dispute_response.stage,
            GrpcDisputeStage::PreArbitration as i32
        );
        assert_eq!(
            dispute_response.status,
            GrpcDisputeStatus::DisputeWon as i32
        );
        assert_eq!(dispute_response.dispute_message, Some(reason.to_string()));
    });
}

// Adyen Doc: https://docs.adyen.com/risk-management/disputes-api/dispute-notifications/#prearbitration_won
#[tokio::test]
async fn test_prearbitration_won_with_status_pending() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        let event_code = "PREARBITRATION_WON";
        let reason = "Pre-arbitration outcome pending";
        let adyen_dispute_status = Some("Pending");

        let json_body = build_adyen_webhook_json_body(event_code, reason, adyen_dispute_status);
        let dispute_response = process_webhook_and_get_response(&mut client, json_body).await;

        assert_eq!(
            dispute_response.stage,
            GrpcDisputeStage::PreArbitration as i32
        );
        assert_eq!(
            dispute_response.status,
            GrpcDisputeStatus::DisputeOpened as i32
        );
        assert_eq!(dispute_response.dispute_message, Some(reason.to_string()));
    });
}

// Adyen Doc: https://docs.adyen.com/risk-management/disputes-api/dispute-notifications/#prearbitration_lost
#[tokio::test]
async fn test_prearbitration_lost() {
    grpc_test!(client, PaymentServiceClient<Channel>, {
        let event_code = "PREARBITRATION_LOST";
        let reason = "Pre-arbitration lost by merchant";
        let adyen_dispute_status = Some("Lost");

        let json_body = build_adyen_webhook_json_body(event_code, reason, adyen_dispute_status);
        let dispute_response = process_webhook_and_get_response(&mut client, json_body).await;

        assert_eq!(
            dispute_response.stage,
            GrpcDisputeStage::PreArbitration as i32
        );
        assert_eq!(
            dispute_response.status,
            GrpcDisputeStatus::DisputeLost as i32
        );
        assert_eq!(dispute_response.dispute_message, Some(reason.to_string()));
    });
}
