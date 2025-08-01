use anyhow::{Context as _, Result};
use dapr::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::info;

use crate::pii::SecretSerdeValue;
use hyperswitch_masking::ExposeInterface;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub request_id: String,
    pub timestamp: i64,
    pub flow_type: FlowName,
    pub connector: String,
    pub url: Option<String>,
    pub stage: EventStage,
    pub latency: Option<u64>,
    pub status_code: Option<u16>,
    pub request_data: Option<SecretSerdeValue>,
    pub connector_request_data: Option<SecretSerdeValue>,
    pub connector_response_data: Option<SecretSerdeValue>,

    #[serde(flatten)]
    pub additional_fields: HashMap<String, SecretSerdeValue>,
}

impl Event {
    /// Create a new Event with all parameters
    pub fn new(
        request_id: String,
        timestamp: i64,
        flow_type: FlowName,
        connector: String,
        url: Option<String>,
        stage: EventStage,
        latency: Option<u64>,
        status_code: Option<u16>,
        request_data: Option<SecretSerdeValue>,
        connector_request_data: Option<SecretSerdeValue>,
        connector_response_data: Option<SecretSerdeValue>,
        additional_fields: HashMap<String, SecretSerdeValue>,
    ) -> Self {
        Self {
            request_id,
            timestamp,
            flow_type,
            connector,
            url,
            stage,
            latency,
            status_code,
            request_data,
            connector_request_data,
            connector_response_data,
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

// Define FlowName enum locally to avoid circular dependency
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventStage {
    ConnectorCall,
}

impl EventStage {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ConnectorCall => "CONNECTOR_CALL",
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

    fn process_event(&self, base_event: &Event) -> serde_json::Value {
        let mut result = serde_json::to_value(base_event).unwrap_or_default();

        for (target_path, source_field) in &self.config.transformations {
            if let Some(value) = result.get(source_field).cloned() {
                self.set_nested_value(&mut result, target_path, value);
            }
        }

        for (target_path, static_value) in &self.config.static_values {
            let value = serde_json::json!(static_value);
            self.set_nested_value(&mut result, target_path, value);
        }

        for (target_path, extraction_path) in &self.config.extractions {
            if let Some(value) = self.extract_from_request(base_event, extraction_path) {
                self.set_nested_value(&mut result, target_path, value);
            }
        }

        result
    }

    fn extract_from_request(
        &self,
        event: &Event,
        extraction_path: &str,
    ) -> Option<serde_json::Value> {
        let path_parts: Vec<&str> = extraction_path.split('.').collect();
        if path_parts.is_empty() {
            return None;
        }

        let source = match path_parts[0] {
            "request_data" | "req" => event.request_data.as_ref()?.clone().expose().clone(),
            _ => return None,
        };

        if path_parts.len() == 1 {
            return Some(source);
        }

        let mut current = &source;
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
    let mut metadata = HashMap::<String, String>::new();

    metadata.insert("rawPayload".to_string(), "true".to_string());

    if let Some(request_id) = event.get("request_id").and_then(|v| v.as_str()) {
        metadata.insert("partitionKey".to_string(), request_id.to_string());
        info!("Setting Kafka message key to request_id: {}", request_id);
    } else {
        info!("Warning: request_id not found in event, message will be published without key");
    }

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

pub async fn emit_event_with_config(base_event: Event, config: &EventConfig) -> Result<()> {
    if !config.enabled {
        return Ok(());
    }

    let processor = EventProcessor::new(config.clone());
    let processed_event = processor.process_event(&base_event);

    publish_to_dapr(
        processed_event,
        &config.pubsub_component,
        &config.topic,
        &config.dapr,
    )
    .await
}
