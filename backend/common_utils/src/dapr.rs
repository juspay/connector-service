use anyhow::{Context as _, Result};
use dapr::Client;
use serde::Serialize;
use std::{collections::HashMap, time::Duration};
use tracing::info;

use crate::events::ApiEventsType;

#[derive(Debug, Serialize)]
pub struct PaymentEvent {
    pub event_type: String,
    pub payment_id: Option<String>,
    pub reference_id: Option<String>,
    pub connector: Option<String>,
    pub merchant_id: Option<String>,
    pub tenant_id: Option<String>,
    pub amount: Option<i64>,
    pub currency: Option<String>,
    pub status: Option<String>,
    pub timestamp: i64,
    pub request_id: Option<String>,
    pub stage: String,
}

pub enum PaymentStage {
    RequestReceivedForFlow,
    TxnInitiatedWithConnector,
    ResponseReceivedFromConnector,
    ErrorReceived,
}

impl PaymentStage {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RequestReceivedForFlow => "REQUEST_RECIEVED_FOR_FLOW",
            Self::TxnInitiatedWithConnector => "TXN_INITIATED_WITH_CONNECTOR",
            Self::ResponseReceivedFromConnector => "RESPONSE_RECIEVED_FROM_CONNECTOR",
            Self::ErrorReceived => "ERROR_RECEIVED",
        }
    }
}

/// Create a Dapr client connection
pub async fn create_client() -> Result<Client<dapr::client::TonicClient>> {
    let dapr_port = std::env::var("DAPR_GRPC_PORT").unwrap_or_else(|_| "50001".to_string());
    let addr = format!("http://localhost:{}", dapr_port);

    info!("Connecting to Dapr sidecar at: {}", addr);

    let client = Client::<dapr::client::TonicClient>::connect(addr)
        .await
        .context("Failed to connect to Dapr sidecar")?;

    info!("Successfully connected to Dapr sidecar");
    Ok(client)
}

/// Publish a payment event through Dapr using the SDK client
pub async fn publish_payment_event(event: PaymentEvent) -> Result<()> {
    info!("Request to publish payment event through Dapr SDK");
    info!("Event details: {:?}", event);

    let event_json = serde_json::to_string(&event)?;
    let mut client = create_client().await?;

    let pubsub_name =
        std::env::var("DAPR_PUBSUB_NAME").unwrap_or_else(|_| "events-pubsub".to_string());
    let topic = "payment-events".to_string();
    let content_type = "application/json".to_string();

    let mut metadata = HashMap::<String, String>::new();
    metadata.insert("event_type".to_string(), event.event_type.clone());

    client
        .publish_event(
            &pubsub_name,
            &topic,
            &content_type,
            event_json.into_bytes(),
            Some(metadata),
        )
        .await
        .context("Failed to publish event through Dapr SDK")?;

    info!(
        "Successfully published payment event to pubsub component: {}",
        pubsub_name
    );
    Ok(())
}

/// Create a payment event from API event type
pub fn create_payment_event(
    event_type: ApiEventsType,
    connector: Option<String>,
    merchant_id: Option<String>,
    tenant_id: Option<String>,
    amount: Option<i64>,
    currency: Option<String>,
    status: Option<String>,
    request_id: Option<String>,
    stage: PaymentStage,
) -> PaymentEvent {
    let payment_id = match &event_type {
        ApiEventsType::Payment { payment_id } => Some(payment_id.get_string_repr().to_string()),
        _ => request_id.clone(),
    };

    info!("Creating payment event with payment_id: {:?}", payment_id);

    let event_type_str = match event_type {
        ApiEventsType::Payment { .. } => "payment".to_string(),
        ApiEventsType::Refund { .. } => "refund".to_string(),
        ApiEventsType::PaymentMethod { .. } => "payment_method".to_string(),
        _ => "payment".to_string(), // Default to "payment" instead of "other" to match our search
    };

    // payment_id will be updated with connector transaction ID later in the process
    let reference_id = payment_id.clone();

    PaymentEvent {
        event_type: event_type_str,
        payment_id,
        reference_id,
        connector,
        merchant_id,
        tenant_id,
        amount,
        currency,
        status,
        timestamp: chrono::Utc::now().timestamp(),
        request_id,
        stage: stage.as_str().to_string(),
    }
}
