use anyhow::{Context as _, Result};
use dapr::Client;
use serde::Serialize;
use std::{collections::HashMap, time::Duration};
use tracing::info;

use crate::events::ApiEventsType;

// Define a payment event structure that will be published to Kafka
#[derive(Debug, Serialize)]
pub struct PaymentEvent {
    pub event_type: String,
    pub payment_id: Option<String>, // Will hold the connector transaction ID
    pub reference_id: Option<String>, // Will hold our internal reference ID
    pub connector: Option<String>,
    pub merchant_id: Option<String>,
    pub tenant_id: Option<String>,
    pub amount: Option<i64>,
    pub currency: Option<String>,
    pub status: Option<String>,
    pub timestamp: i64,
    pub request_id: Option<String>,
    pub stage: String, // Added to track the payment processing stage
}

// Define payment processing stages for event publishing
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
    // Get the Dapr gRPC port (default to 50001 if not set)
    let dapr_port = std::env::var("DAPR_GRPC_PORT").unwrap_or_else(|_| "50001".to_string());
    let addr = format!("http://localhost:{}", dapr_port);

    info!("Connecting to Dapr sidecar at: {}", addr);

    // Introduce a small delay to ensure Dapr gRPC port is ready (recommended in Dapr SDK docs)
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect to the Dapr sidecar
    let client = Client::<dapr::client::TonicClient>::connect(addr)
        .await
        .context("Failed to connect to Dapr sidecar")?;

    info!("Successfully connected to Dapr sidecar");
    Ok(client)
}

/// Publish a payment event through Dapr using the SDK client
pub async fn publish_payment_event(event: PaymentEvent) -> Result<()> {
    info!("Request to publish payment event through Dapr SDK");

    // Log the event details
    info!("Event details: {:?}", event);

    // Serialize the event to JSON
    let event_json = serde_json::to_string(&event)?;

    // Create a new client for this request
    let mut client = create_client().await?;

    // Get pubsub component name from environment or use default
    let pubsub_name =
        std::env::var("DAPR_PUBSUB_NAME").unwrap_or_else(|_| "events-pubsub".to_string());
    let topic = "payment-events".to_string(); // topic name
    let content_type = "application/json".to_string();

    // Create metadata
    let mut metadata = HashMap::<String, String>::new();
    metadata.insert("event_type".to_string(), event.event_type.clone());

    // Use the SDK to publish the event
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
    // Extract payment_id from event_type or fallback to request_id
    let payment_id = match &event_type {
        ApiEventsType::SimplePayment { payment_id } => {
            // For SimplePayment, use the string directly
            Some(payment_id.clone())
        }
        _ => request_id.clone(), // For other types, use request_id
    };

    // Log the extracted payment_id for debugging
    info!("Creating payment event with payment_id: {:?}", payment_id);

    let event_type_str = match event_type {
        ApiEventsType::Payment { .. } => "payment".to_string(),
        ApiEventsType::SimplePayment { .. } => "payment".to_string(),
        ApiEventsType::Refund { .. } => "refund".to_string(),
        ApiEventsType::PaymentMethod { .. } => "payment_method".to_string(),
        _ => "payment".to_string(), // Default to "payment" instead of "other" to match our search
    };

    // Use payment_id as reference_id initially
    // (later in the process, payment_id can be updated with connector transaction ID)
    let reference_id = payment_id.clone();

    PaymentEvent {
        event_type: event_type_str,
        payment_id,   // Will be updated with connector txn ID later
        reference_id, // Keeps our internal reference ID
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
