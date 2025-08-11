use anyhow::{Context as _, Result};
use dapr::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::info;

use crate::pii::SecretSerdeValue;
use hyperswitch_masking::ExposeInterface;

// Constants for better code practices
const DEFAULT_CONTENT_TYPE: &str = "application/json";
const RAW_PAYLOAD_KEY: &str = "rawPayload";
const RAW_PAYLOAD_VALUE: &str = "true";
const PARTITION_KEY_METADATA: &str = "partitionKey";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub request_id: String,
    pub timestamp: i128,
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

/// Configuration for events system
#[derive(Debug, Clone, Deserialize)]
pub struct EventConfig {
    pub enabled: bool,
    pub pubsub_component: String,
    pub topic: String,
    pub dapr: DaprConfig,
    pub partition_key_field: String,
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
            partition_key_field: "request_id".to_string(),
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
    pub protocol: String,
}

impl Default for DaprConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            grpc_port: 50001,
            protocol: "http".to_string(),
        }
    }
}

/// Create a Dapr client connection using configuration
pub async fn create_client(config: &DaprConfig) -> Result<Client<dapr::client::TonicClient>> {
    let addr = format!("{}://{}:{}", config.protocol, config.host, config.grpc_port);

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

    fn process_event(&self, base_event: &Event) -> Result<serde_json::Value> {
        let mut result =
            serde_json::to_value(base_event).context("Failed to serialize base event to JSON")?;

        self.config
            .transformations
            .iter()
            .for_each(|(target_path, source_field)| {
                result.get(source_field).cloned().map(|value| {
                    self.set_nested_value(&mut result, target_path, value)
                        .unwrap_or_else(|e| {
                            tracing::warn!(
                                "Failed to set transformation for path {}: {}",
                                target_path,
                                e
                            )
                        })
                });
            });

        self.config
            .static_values
            .iter()
            .for_each(|(target_path, static_value)| {
                let value = serde_json::json!(static_value);
                self.set_nested_value(&mut result, target_path, value)
                    .unwrap_or_else(|e| {
                        tracing::warn!("Failed to set static value for path {}: {}", target_path, e)
                    });
            });

        self.config
            .extractions
            .iter()
            .for_each(|(target_path, extraction_path)| {
                self.extract_from_request(base_event, extraction_path)
                    .map(|value| {
                        self.set_nested_value(&mut result, target_path, value)
                            .unwrap_or_else(|e| {
                                tracing::warn!(
                                    "Failed to set extraction for path {}: {}",
                                    target_path,
                                    e
                                )
                            })
                    });
            });

        Ok(result)
    }

    fn extract_from_request(
        &self,
        event: &Event,
        extraction_path: &str,
    ) -> Option<serde_json::Value> {
        let mut path_parts = extraction_path.split('.');

        let first_part = path_parts.next()?;

        let source = match first_part {
            "req" => event.request_data.as_ref()?.clone().expose().clone(),
            _ => return None,
        };

        let mut current = &source;
        for part in path_parts {
            current = current.get(part)?;
        }

        Some(current.clone())
    }

    fn set_nested_value(
        &self,
        target: &mut serde_json::Value,
        path: &str,
        value: serde_json::Value,
    ) -> Result<()> {
        let path_parts: Vec<&str> = path.split('.').filter(|s| !s.is_empty()).collect();

        if path_parts.is_empty() {
            return Err(anyhow::anyhow!("Empty path provided"));
        }

        if path_parts.len() == 1 {
            if let Some(key) = path_parts.first() {
                target[*key] = value;
                return Ok(());
            }
        }

        let result = path_parts.iter().enumerate().try_fold(
            target,
            |current, (index, &part)| -> Result<&mut serde_json::Value> {
                if index == path_parts.len() - 1 {
                    current[part] = value.clone();
                    Ok(current)
                } else {
                    if !current[part].is_object() {
                        current[part] = serde_json::json!({});
                    }
                    current
                        .get_mut(part)
                        .ok_or_else(|| anyhow::anyhow!("Failed to access nested path: {}", part))
                }
            },
        );

        result.map(|_| ())
    }
}

async fn publish_to_dapr(
    event: serde_json::Value,
    pubsub_component: &str,
    topic: &str,
    dapr_config: &DaprConfig,
    partition_key_field: &str,
) -> Result<()> {
    info!(
        "Publishing event to Dapr: component={}, topic={}",
        pubsub_component, topic
    );

    let event_json = serde_json::to_string(&event)?;
    let mut client = create_client(dapr_config).await?;

    let content_type = DEFAULT_CONTENT_TYPE.to_string();
    let mut metadata = HashMap::<String, String>::new();

    metadata.insert(RAW_PAYLOAD_KEY.to_string(), RAW_PAYLOAD_VALUE.to_string());

    if let Some(partition_key_value) = event.get(partition_key_field).and_then(|v| v.as_str()) {
        metadata.insert(
            PARTITION_KEY_METADATA.to_string(),
            partition_key_value.to_string(),
        );
    } else {
        info!(
            "Warning: {} not found in event, message will be published without key",
            partition_key_field
        );
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
    let processed_event = processor.process_event(&base_event)?;

    publish_to_dapr(
        processed_event,
        &config.pubsub_component,
        &config.topic,
        &config.dapr,
        &config.partition_key_field,
    )
    .await
}
