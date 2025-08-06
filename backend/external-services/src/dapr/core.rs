//! Interactions with the Dapr SDK

use std::{sync::Arc, time::Instant};
use tokio::sync::Mutex;

use common_utils::errors::CustomResult;
use error_stack::ResultExt;
use tracing as logger;

/// Configuration parameters required for constructing a [`DaprClient`].
#[derive(Clone, Debug, Default, serde::Deserialize)]
#[serde(default)]
pub struct DaprConfig {
    /// The Dapr host to connect to.
    pub host: String,

    /// The Dapr gRPC port to connect to.
    pub grpc_port: u16,

    /// The pubsub component name.
    pub pubsub_component: String,

    /// The topic to publish events to.
    pub topic: String,
}

/// Client for Dapr operations.
pub struct DaprClient {
    dapr_client: Arc<Mutex<dapr::Client<dapr::client::TonicClient>>>,
    pubsub_component: String,
    topic: String,
}

impl Clone for DaprClient {
    fn clone(&self) -> Self {
        Self {
            dapr_client: Arc::clone(&self.dapr_client),
            pubsub_component: self.pubsub_component.clone(),
            topic: self.topic.clone(),
        }
    }
}

impl DaprClient {
    /// Constructs a new Dapr client.
    ///
    /// Creates a single-instance client that will be stored in the application state.
    pub async fn new(config: &DaprConfig) -> CustomResult<Self, DaprError> {
        let dapr_endpoint = format!("http://{}:{}", config.host, config.grpc_port);
        logger::info!(
            dapr_endpoint = %dapr_endpoint,
            pubsub_component = %config.pubsub_component,
            topic = %config.topic,
            "Attempting to connect to Dapr"
        );

        let dapr_client = dapr::Client::<dapr::client::TonicClient>::connect(dapr_endpoint.clone())
            .await
            .inspect_err(|error| {
                logger::error!(
                    dapr_endpoint = %dapr_endpoint,
                    dapr_connection_error=?error,
                    "Failed to connect to Dapr"
                );
            })
            .change_context(DaprError::ConnectionFailed)?;

        logger::info!(
            dapr_endpoint = %dapr_endpoint,
            "Successfully connected to Dapr"
        );

        Ok(Self {
            dapr_client: Arc::new(Mutex::new(dapr_client)),
            pubsub_component: config.pubsub_component.clone(),
            topic: config.topic.clone(),
        })
    }

    /// Publishes an event to the configured topic
    ///
    /// This method uses interior mutability to work with the DAPR SDK requirements.
    pub async fn emit_event(&self, event_type: &str, data: &[u8]) -> CustomResult<(), DaprError> {
        let start = Instant::now();

        let event_data = serde_json::json!({
            "event_type": event_type,
            "data": String::from_utf8_lossy(data),
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });

        let mut client = self.dapr_client.lock().await;

        client
            .publish_event(
                &self.pubsub_component,
                &self.topic,
                &"application/json".to_string(),
                serde_json::to_vec(&event_data).unwrap_or_default(),
                None,
            )
            .await
            .inspect_err(|error| {
                logger::error!(dapr_sdk_error=?error, "Failed to publish event to Dapr");
            })
            .change_context(DaprError::EventPublishFailed)?;

        let time_taken = start.elapsed();
        logger::debug!(
            event_type = event_type,
            topic = &self.topic,
            time_taken_ms = time_taken.as_millis(),
            "Successfully published event to Dapr"
        );

        Ok(())
    }
}

/// Errors that could occur during Dapr operations.
#[derive(Debug, thiserror::Error)]
pub enum DaprError {
    /// An error occurred when connecting to Dapr.
    #[error("Failed to connect to Dapr")]
    ConnectionFailed,

    /// An error occurred when publishing event to Dapr.
    #[error("Failed to publish event to Dapr")]
    EventPublishFailed,

    /// The Dapr client has not been initialized.
    #[error("The Dapr client has not been initialized")]
    DaprClientNotInitialized,
}

impl DaprConfig {
    /// Verifies that the [`DaprClient`] configuration is usable.
    pub fn validate(&self) -> Result<(), &'static str> {
        use common_utils::{ext_traits::ConfigExt, fp_utils::when};

        when(self.host.is_default_or_empty(), || {
            Err("Dapr host must not be empty")
        })?;

        when(self.grpc_port == 0, || {
            Err("Dapr gRPC port must not be zero")
        })?;

        when(self.pubsub_component.is_default_or_empty(), || {
            Err("Dapr pubsub component must not be empty")
        })?;

        when(self.topic.is_default_or_empty(), || {
            Err("Dapr topic must not be empty")
        })
    }

    /// Converts DaprConfig to EventConfig for compatibility with external services
    pub fn to_event_config(&self) -> common_utils::dapr::EventConfig {
        common_utils::dapr::EventConfig {
            enabled: true,
            pubsub_component: self.pubsub_component.clone(),
            topic: self.topic.clone(),
            dapr: common_utils::dapr::DaprConfig {
                host: self.host.clone(),
                grpc_port: self.grpc_port,
            },
            partition_key_field: "request_id".to_string(),
            transformations: std::collections::HashMap::new(),
            static_values: std::collections::HashMap::new(),
            extractions: std::collections::HashMap::new(),
        }
    }
}
