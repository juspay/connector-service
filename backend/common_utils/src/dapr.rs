use anyhow::{Context as _, Result};
use dapr::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::info;
use uuid::Uuid;

use crate::pii::SecretSerdeValue;
use hyperswitch_masking::ExposeInterface;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub event_uuid: String,
    pub timestamp: String,
    pub flow_type: String,
    pub connector: String,
    pub stage: String,
    pub latency: Option<u64>,
    pub status_code: Option<u16>,
    pub error_code: Option<String>,
    pub error_reason: Option<String>,
    pub request_data: Option<SecretSerdeValue>,
    pub response_data: Option<SecretSerdeValue>,

    #[serde(flatten)]
    pub additional_fields: HashMap<String, SecretSerdeValue>,
}

impl Event {
    /// Generate a new unique event UUID using UUID v7 (time-ordered)
    pub fn generate_event_uuid() -> String {
        Uuid::now_v7().to_string()
    }

    /// Create a new Event with all parameters
    pub fn new(
        event_uuid: String,
        timestamp: String,
        flow_type: String,
        connector: String,
        stage: String,
        latency: Option<u64>,
        status_code: Option<u16>,
        error_code: Option<String>,
        error_reason: Option<String>,
        request_data: Option<SecretSerdeValue>,
        response_data: Option<SecretSerdeValue>,
        additional_fields: HashMap<String, SecretSerdeValue>,
    ) -> Self {
        Self {
            event_uuid,
            timestamp,
            flow_type,
            connector,
            stage,
            latency,
            status_code,
            error_code,
            error_reason,
            request_data,
            response_data,
            additional_fields,
        }
    }
}

/// Configuration for events system
#[derive(Debug, Clone, Deserialize)]
pub struct EventConfig {
    pub enabled: bool,
    pub pubsub_component: String,
    pub topic: String,
    pub dapr: DaprConfig,
    #[serde(default)]
    pub transformations: HashMap<String, String>, // target_path → source_field
    #[serde(default)]
    pub static_values: HashMap<String, String>, // target_path → static_value
    #[serde(default)]
    pub extractions: HashMap<String, String>, // target_path → extraction_path
}

impl Default for EventConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            pubsub_component: "kafka-pubsub".to_string(),
            topic: "events".to_string(),
            dapr: DaprConfig::default(),
            transformations: HashMap::new(),
            static_values: HashMap::new(),
            extractions: HashMap::new(),
        }
    }
}

/// Context data available for event processing
#[derive(Debug, Clone, Default)]
pub struct EventContext {
    pub request_data: Option<serde_json::Value>,
}

// Define FlowName enum locally to avoid circular dependency
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowName {
    Authorize,
    Refund,
    Capture,
    Void,
    Psync,
    Rsync,
    AcceptDispute,
    SubmitEvidence,
    DefendDispute,
    Dsync,
    IncomingWebhook,
    SetupMandate,
    CreateOrder,
}

impl FlowName {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Authorize => "Authorize",
            Self::Refund => "Refund",
            Self::Capture => "Capture",
            Self::Void => "Void",
            Self::Psync => "Psync",
            Self::Rsync => "Rsync",
            Self::AcceptDispute => "AcceptDispute",
            Self::SubmitEvidence => "SubmitEvidence",
            Self::DefendDispute => "DefendDispute",
            Self::Dsync => "Dsync",
            Self::IncomingWebhook => "IncomingWebhook",
            Self::SetupMandate => "SetupMandate",
            Self::CreateOrder => "CreateOrder",
        }
    }
}

#[derive(Debug, Clone)]
pub enum EventStage {
    RequestReceived,
    RequestSent,
    ResponseReceived,
}

impl EventStage {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RequestReceived => "RequestReceived",
            Self::RequestSent => "RequestSent",
            Self::ResponseReceived => "ResponseReceived",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct DaprConfig {
    pub host: String,
    pub grpc_port: u16,
}

impl Default for DaprConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            grpc_port: 50001,
        }
    }
}

/// Create a Dapr client connection using configuration
pub async fn create_client(config: &DaprConfig) -> Result<Client<dapr::client::TonicClient>> {
    let addr = format!("http://{}:{}", config.host, config.grpc_port);

    info!("Connecting to Dapr sidecar at: {}", addr);

    let client = Client::<dapr::client::TonicClient>::connect(addr)
        .await
        .context("Failed to connect to Dapr sidecar")?;

    info!("Successfully connected to Dapr sidecar");
    Ok(client)
}

struct EventProcessor {
    config: EventConfig,
}

impl EventProcessor {
    fn new(config: EventConfig) -> Self {
        Self { config }
    }

    fn process_event(&self, base_event: &Event, context: &EventContext) -> serde_json::Value {
        let mut result = serde_json::json!({});

        // 1. Apply transformations (field mappings)
        for (target_path, source_field) in &self.config.transformations {
            if let Some(value) = self.get_field_value(base_event, source_field) {
                self.set_nested_value(&mut result, target_path, value);
            }
        }

        // 2. Apply static values
        for (target_path, static_value) in &self.config.static_values {
            let value = serde_json::json!(static_value);
            self.set_nested_value(&mut result, target_path, value);
        }

        // 3. Apply extractions
        for (target_path, extraction_path) in &self.config.extractions {
            if let Some(value) = self.extract_from_context(context, extraction_path) {
                self.set_nested_value(&mut result, target_path, value);
            }
        }

        result
    }

    /// Get a field value from the base event
    fn get_field_value(&self, event: &Event, field_name: &str) -> Option<serde_json::Value> {
        match field_name {
            "event_uuid" => Some(serde_json::json!(event.event_uuid)),
            "timestamp" => Some(serde_json::json!(event.timestamp)),
            "flow_type" => Some(serde_json::json!(event.flow_type)),
            "connector" => Some(serde_json::json!(event.connector)),
            "stage" => Some(serde_json::json!(event.stage)),
            "latency" => event.latency.map(|v| serde_json::json!(v)),
            "status_code" => event.status_code.map(|v| serde_json::json!(v)),
            "error_code" => event.error_code.as_ref().map(|v| serde_json::json!(v)),
            "error_reason" => event.error_reason.as_ref().map(|v| serde_json::json!(v)),
            "request_data" => event
                .request_data
                .as_ref()
                .map(|secret| secret.clone().expose().clone()),
            "response_data" => event
                .response_data
                .as_ref()
                .map(|secret| secret.clone().expose().clone()),
            _ => {
                // Check additional fields
                event
                    .additional_fields
                    .get(field_name)
                    .map(|secret| secret.clone().expose().clone())
            }
        }
    }

    /// Extract values from context using dot notation paths
    fn extract_from_context(
        &self,
        context: &EventContext,
        extraction_path: &str,
    ) -> Option<serde_json::Value> {
        let path_parts: Vec<&str> = extraction_path.split('.').collect();
        if path_parts.is_empty() {
            return None;
        }

        let source = match path_parts[0] {
            "request_data" => context.request_data.as_ref()?,
            "req" => context.request_data.as_ref()?, // Allow 'req' as alias for request_data
            _ => return None,
        };

        // If the path is just "req" or "request_data", return the entire source
        if path_parts.len() == 1 {
            return Some(source.clone());
        }

        let mut current = source;
        for part in &path_parts[1..] {
            current = current.get(part)?;
        }

        Some(current.clone())
    }

    fn set_nested_value(
        &self,
        target: &mut serde_json::Value,
        path: &str,
        value: serde_json::Value,
    ) {
        let path_parts: Vec<&str> = path.split('.').collect();

        if path_parts.len() == 1 {
            target[path_parts[0]] = value;
            return;
        }

        let mut current = target;
        for (i, part) in path_parts.iter().enumerate() {
            if i == path_parts.len() - 1 {
                current[*part] = value;
                break;
            } else {
                if !current[*part].is_object() {
                    current[*part] = serde_json::json!({});
                }
                current = &mut current[*part];
            }
        }
    }
}

async fn publish_to_dapr(
    event: serde_json::Value,
    pubsub_component: &str,
    topic: &str,
    dapr_config: &DaprConfig,
) -> Result<()> {
    info!(
        "Publishing event to Dapr: component={}, topic={}",
        pubsub_component, topic
    );

    let event_json = serde_json::to_string(&event)?;
    let mut client = create_client(dapr_config).await?;

    let content_type = "application/json".to_string();
    let metadata = HashMap::<String, String>::new();

    client
        .publish_event(
            pubsub_component,
            topic,
            &content_type,
            event_json.into_bytes(),
            Some(metadata),
        )
        .await
        .context("Failed to publish event through Dapr SDK")?;

    info!(
        "Successfully published event to pubsub component: {}",
        pubsub_component
    );
    Ok(())
}

pub async fn emit_event_with_config(
    base_event: Event,
    context: EventContext,
    config: &EventConfig,
) -> Result<()> {
    if !config.enabled {
        return Ok(());
    }

    let processor = EventProcessor::new(config.clone());
    let processed_event = processor.process_event(&base_event, &context);

    publish_to_dapr(
        processed_event,
        &config.pubsub_component,
        &config.topic,
        &config.dapr,
    )
    .await
}
