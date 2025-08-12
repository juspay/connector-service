use anyhow::Result;
use rdkafka::message::{Header, OwnedHeaders};
use serde_json;
use std::sync::Arc;
use tracing_kafka::KafkaWriter;

// Use the centralized event definitions from the events module
use crate::events::{Event, EventConfig};

const DEFAULT_CONTENT_TYPE: &str = "application/json";
const RAW_PAYLOAD_KEY: &str = "rawPayload";
const RAW_PAYLOAD_VALUE: &str = "true";
const PARTITION_KEY_METADATA: &str = "partitionKey";

/// An event publisher that sends events directly to Kafka.
#[derive(Clone)]
pub struct EventPublisher {
    writer: Arc<KafkaWriter>,
    config: EventConfig,
}

impl EventPublisher {
    /// Creates a new EventPublisher, initializing the KafkaWriter.
    pub fn new(config: &EventConfig) -> Result<Self> {
        let writer = KafkaWriter::new(
            config.brokers.clone(),
            config.topic.clone(),
            None,
            None,
            None,
            None,
            None,
            None,
        )?;

        Ok(Self {
            writer: Arc::new(writer),
            config: config.clone(),
        })
    }

    /// Publishes a single event to Kafka with metadata as headers.
    pub async fn publish_event(
        &self,
        event: serde_json::Value,
        topic: &str,
        partition_key_field: &str,
    ) -> Result<()> {
        tracing::info!("Publishing event to Kafka: topic={}", topic);

        let mut headers: OwnedHeaders = OwnedHeaders::new();

        let key = if let Some(partition_key_value) = event.get(partition_key_field).and_then(|v| v.as_str()) {
            headers = headers.insert(Header {
                key: PARTITION_KEY_METADATA,
                value: Some(partition_key_value.as_bytes()),
            });
            Some(partition_key_value)
        } else {
            tracing::info!(
                "Warning: {} not found in event, message will be published without key",
                partition_key_field
            );
            None
        };

        if let Err(e) = self.writer.publish_event(
            &self.config.topic,
            key,
            &serde_json::to_vec(&event)?,
            Some(headers),
        ) {
            tracing::error!("Failed to queue event for Kafka: {:?}", e);
        }

        Ok(())
    }

    pub async fn emit_event_with_config(
        &self,
        base_event: Event,
        config: &EventConfig,
    ) -> Result<()> {
        if !config.enabled {
            return Ok(());
        }

        let processed_event = self.process_event(&base_event)?;

        self.publish_event(processed_event, &config.topic, &config.partition_key_field)
            .await
    }

    fn process_event(&self, event: &Event) -> Result<serde_json::Value> {
        let mut result = serde_json::to_value(event)?;

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
                self.extract_from_request(&serde_json::to_value(event).unwrap(), extraction_path)
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
        event: &serde_json::Value,
        extraction_path: &str,
    ) -> Option<serde_json::Value> {
        let mut path_parts = extraction_path.split('.');

        let first_part = path_parts.next()?;

        let source = match first_part {
            "req" => event.get("request_data")?.clone(),
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
