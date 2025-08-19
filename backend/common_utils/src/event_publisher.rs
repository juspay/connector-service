use std::sync::Arc;

use once_cell::sync::OnceCell;
use rdkafka::message::{Header, OwnedHeaders};
use serde_json;
use tracing_kafka::{builder::KafkaWriterBuilder, KafkaWriter};

// Use the centralized event definitions from the events module
use crate::events::{Event, EventConfig};
use crate::{CustomResult, EventPublisherError};

const PARTITION_KEY_METADATA: &str = "partitionKey";

/// Global static EventPublisher instance
static EVENT_PUBLISHER: OnceCell<EventPublisher> = OnceCell::new();

/// An event publisher that sends events directly to Kafka.
#[derive(Clone)]
pub struct EventPublisher {
    writer: Arc<KafkaWriter>,
    config: EventConfig,
}

impl EventPublisher {
    /// Creates a new EventPublisher, initializing the KafkaWriter.
    pub fn new(config: &EventConfig) -> CustomResult<Self, EventPublisherError> {
        // Validate configuration before attempting to create writer
        if config.brokers.is_empty() {
            return Err(error_stack::Report::new(
                EventPublisherError::InvalidConfiguration {
                    message: "brokers list cannot be empty".to_string(),
                },
            ));
        }

        if config.topic.is_empty() {
            return Err(error_stack::Report::new(
                EventPublisherError::InvalidConfiguration {
                    message: "topic cannot be empty".to_string(),
                },
            ));
        }

        tracing::debug!(
            brokers = ?config.brokers,
            topic = %config.topic,
            "Creating EventPublisher with configuration"
        );

        let writer = KafkaWriterBuilder::new()
            .brokers(config.brokers.clone())
            .topic(config.topic.clone())
            .build()
            .map_err(|e| {
                tracing::error!(
                    error = ?e,
                    brokers = ?config.brokers,
                    topic = %config.topic,
                    "Failed to create KafkaWriter"
                );
                error_stack::Report::new(EventPublisherError::KafkaWriterInitializationFailed)
                    .attach_printable(format!(
                        "Brokers: {:?}, Topic: {}",
                        config.brokers, config.topic
                    ))
            })?;

        tracing::info!(
            brokers = ?config.brokers,
            topic = %config.topic,
            "EventPublisher created successfully"
        );

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
    ) -> CustomResult<(), EventPublisherError> {
        tracing::debug!(
            topic = %topic,
            partition_key_field = %partition_key_field,
            "Starting event publication to Kafka"
        );

        let mut headers: OwnedHeaders = OwnedHeaders::new();

        let key = if let Some(partition_key_value) =
            event.get(partition_key_field).and_then(|v| v.as_str())
        {
            headers = headers.insert(Header {
                key: PARTITION_KEY_METADATA,
                value: Some(partition_key_value.as_bytes()),
            });
            Some(partition_key_value)
        } else {
            tracing::warn!(
                partition_key_field = %partition_key_field,
                "Partition key field not found in event, message will be published without key"
            );
            None
        };

        let event_bytes = serde_json::to_vec(&event).map_err(|e| {
            tracing::error!(
                error = ?e,
                request_id = %event.get("request_id").unwrap_or(&serde_json::Value::Null),
                connector = %event.get("connector").unwrap_or(&serde_json::Value::Null),
                flow_type = %event.get("flow_type").unwrap_or(&serde_json::Value::Null),
                "Failed to serialize audit event to JSON bytes"
            );
            error_stack::Report::new(EventPublisherError::EventSerializationFailed)
                .attach_printable(format!("Serialization error: {e}"))
                .attach_printable(format!(
                    "Event context: request_id={}, connector={}, flow_type={}",
                    event.get("request_id").unwrap_or(&serde_json::Value::Null),
                    event.get("connector").unwrap_or(&serde_json::Value::Null),
                    event.get("flow_type").unwrap_or(&serde_json::Value::Null)
                ))
        })?;

        self.writer
            .publish_event(&self.config.topic, key, &event_bytes, Some(headers))
            .map_err(|e| {
                tracing::error!(
                    error = ?e,
                    topic = %topic,
                    request_id = %event.get("request_id").unwrap_or(&serde_json::Value::Null),
                    connector = %event.get("connector").unwrap_or(&serde_json::Value::Null),
                    flow_type = %event.get("flow_type").unwrap_or(&serde_json::Value::Null),
                    event_size = event_bytes.len(),
                    "Failed to publish audit event - critical data may be lost"
                );
                error_stack::Report::new(EventPublisherError::EventPublishFailed)
                    .attach_printable(format!("Kafka publish error: {e}"))
                    .attach_printable(format!("Topic: {topic}"))
                    .attach_printable(format!(
                        "Event context: request_id={}, connector={}, flow_type={}",
                        event.get("request_id").unwrap_or(&serde_json::Value::Null),
                        event.get("connector").unwrap_or(&serde_json::Value::Null),
                        event.get("flow_type").unwrap_or(&serde_json::Value::Null)
                    ))
            })?;

        tracing::info!(
            topic = %topic,
            has_partition_key = key.is_some(),
            "Event successfully published to Kafka"
        );

        Ok(())
    }

    pub async fn emit_event_with_config(
        &self,
        base_event: Event,
        config: &EventConfig,
    ) -> CustomResult<(), EventPublisherError> {
        let processed_event = self.process_event(&base_event)?;

        self.publish_event(processed_event, &config.topic, &config.partition_key_field)
            .await
    }

    fn process_event(&self, event: &Event) -> CustomResult<serde_json::Value, EventPublisherError> {
        let mut result = serde_json::to_value(event).map_err(|e| {
            tracing::error!(
                error = ?e,
                "Failed to serialize event to JSON value"
            );
            error_stack::Report::new(EventPublisherError::EventSerializationFailed)
                .attach_printable(format!("Event serialization error: {e}"))
        })?;

        // Process transformations
        for (target_path, source_field) in &self.config.transformations {
            if let Some(value) = result.get(source_field).cloned() {
                if let Err(e) = self.set_nested_value(&mut result, target_path, value) {
                    tracing::warn!(
                        target_path = %target_path,
                        source_field = %source_field,
                        error = %e,
                        "Failed to set transformation, continuing with event processing"
                    );
                }
            }
        }

        // Process static values - log warnings but continue processing
        for (target_path, static_value) in &self.config.static_values {
            let value = serde_json::json!(static_value);
            if let Err(e) = self.set_nested_value(&mut result, target_path, value) {
                tracing::warn!(
                    target_path = %target_path,
                    static_value = %static_value,
                    error = %e,
                    "Failed to set static value, continuing with event processing"
                );
            }
        }

        // Process extraction
        for (target_path, extraction_path) in &self.config.extractions {
            if let Some(value) = self.extract_from_request(&result, extraction_path) {
                if let Err(e) = self.set_nested_value(&mut result, target_path, value) {
                    tracing::warn!(
                        target_path = %target_path,
                        extraction_path = %extraction_path,
                        error = %e,
                        "Failed to set extraction, continuing with event processing"
                    );
                }
            }
        }

        Ok(result)
    }

    fn extract_from_request(
        &self,
        event_value: &serde_json::Value,
        extraction_path: &str,
    ) -> Option<serde_json::Value> {
        let mut path_parts = extraction_path.split('.');

        let first_part = path_parts.next()?;

        let source = match first_part {
            "req" => event_value.get("request_data")?.clone(),
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
    ) -> CustomResult<(), EventPublisherError> {
        let path_parts: Vec<&str> = path.split('.').filter(|s| !s.is_empty()).collect();

        if path_parts.is_empty() {
            return Err(error_stack::Report::new(EventPublisherError::InvalidPath {
                path: path.to_string(),
            }));
        }

        if path_parts.len() == 1 {
            if let Some(key) = path_parts.first() {
                target[*key] = value;
                return Ok(());
            }
        }

        let result = path_parts.iter().enumerate().try_fold(
            target,
            |current,
             (index, &part)|
             -> CustomResult<&mut serde_json::Value, EventPublisherError> {
                if index == path_parts.len() - 1 {
                    current[part] = value.clone();
                    Ok(current)
                } else {
                    if !current[part].is_object() {
                        current[part] = serde_json::json!({});
                    }
                    current.get_mut(part).ok_or_else(|| {
                        error_stack::Report::new(EventPublisherError::InvalidPath {
                            path: format!("{path}.{part}"),
                        })
                    })
                }
            },
        );

        result.map(|_| ())
    }
}

/// Initialize the global EventPublisher with the given configuration
pub fn init_event_publisher(config: &EventConfig) -> CustomResult<(), EventPublisherError> {
    tracing::info!(
        brokers = ?config.brokers,
        topic = %config.topic,
        enabled = config.enabled,
        "Initializing global EventPublisher"
    );

    let publisher = EventPublisher::new(config)?;

    EVENT_PUBLISHER.set(publisher).map_err(|failed_publisher| {
        tracing::error!(
            existing_brokers = ?failed_publisher.config.brokers,
            existing_topic = %failed_publisher.config.topic,
            new_brokers = ?config.brokers,
            new_topic = %config.topic,
            "EventPublisher already initialized with different configuration"
        );
        error_stack::Report::new(EventPublisherError::AlreadyInitialized)
            .attach_printable("EventPublisher was already initialized")
            .attach_printable(format!(
                "Existing config: brokers={:?}, topic={}",
                failed_publisher.config.brokers, failed_publisher.config.topic
            ))
            .attach_printable(format!(
                "New config: brokers={:?}, topic={}",
                config.brokers, config.topic
            ))
    })?;

    tracing::info!("Global EventPublisher initialized successfully");
    Ok(())
}

/// Get or initialize the global EventPublisher
fn get_event_publisher(
    config: &EventConfig,
) -> CustomResult<&'static EventPublisher, EventPublisherError> {
    EVENT_PUBLISHER.get_or_try_init(|| EventPublisher::new(config))
}

/// Standalone function to emit events using the global EventPublisher
pub async fn emit_event_with_config(
    event: Event,
    config: &EventConfig,
) -> CustomResult<bool, EventPublisherError> {
    if !config.enabled {
        return Ok(false);
    }

    let publisher: &'static EventPublisher = get_event_publisher(config)?;
    publisher.emit_event_with_config(event, config).await?;
    Ok(true)
}
