//! A Kafka tracing layer that integrates with the tracing ecosystem.
//!
//! This crate provides a simple way to send tracing logs to Kafka while maintaining
//! consistent JSON formatting through the log_utils infrastructure.
//!
//! # Examples
//! ```no_run
//! use tracing_kafka::KafkaLayer;
//! use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
//!
//! let kafka_layer = KafkaLayer::builder()
//!     .brokers(&["localhost:9092"])
//!     .topic("application-logs")
//!     .build()
//!     .expect("Failed to create Kafka layer");
//!
//! tracing_subscriber::registry()
//!     .with(kafka_layer)
//!     .init();
//! ```

mod layer;
mod writer;

use std::collections::HashMap;
use std::time::Duration;

pub use layer::{KafkaLayer, KafkaLayerError};
pub use writer::{KafkaWriter, KafkaWriterError};

/// Builder for creating a KafkaLayer with custom configuration.
#[derive(Debug, Clone, Default)]
pub struct KafkaLayerBuilder {
    brokers: Option<Vec<String>>,
    topic: Option<String>,
    batch_size: Option<usize>,
    flush_interval: Option<Duration>,
    static_fields: HashMap<String, serde_json::Value>,
}

impl KafkaLayerBuilder {
    /// Creates a new builder with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the Kafka brokers to connect to.
    pub fn brokers(mut self, brokers: &[&str]) -> Self {
        self.brokers = Some(brokers.iter().map(|s| s.to_string()).collect());
        self
    }

    /// Sets the Kafka topic to send logs to.
    pub fn topic(mut self, topic: &str) -> Self {
        self.topic = Some(topic.to_string());
        self
    }

    /// Sets the batch size for buffering messages before sending.
    /// If not set, uses Kafka's default (16384 bytes).
    pub fn batch_size(mut self, size: usize) -> Self {
        self.batch_size = Some(size);
        self
    }

    /// Sets the flush interval for sending buffered messages.
    /// If not set, uses Kafka's default (0ms - immediate send).
    pub fn flush_interval(mut self, interval: Duration) -> Self {
        self.flush_interval = Some(interval);
        self
    }

    /// Adds static fields that will be included in every log entry.
    /// These fields are added at the top level of the JSON output.
    pub fn static_fields(mut self, fields: HashMap<String, serde_json::Value>) -> Self {
        self.static_fields = fields;
        self
    }

    /// Adds a single static field that will be included in every log entry.
    pub fn add_static_field(mut self, key: String, value: serde_json::Value) -> Self {
        self.static_fields.insert(key, value);
        self
    }

    /// Builds the KafkaLayer with the configured settings.
    pub fn build<S>(self) -> Result<KafkaLayer<S>, KafkaLayerError>
    where
        S: tracing::Subscriber,
    {
        let brokers = self.brokers.ok_or(KafkaLayerError::MissingBrokers)?;
        let topic = self.topic.ok_or(KafkaLayerError::MissingTopic)?;

        // Convert flush_interval to milliseconds for Kafka's linger.ms setting if provided
        let linger_ms = self.flush_interval.map(|d| d.as_millis() as u64);

        let kafka_writer = KafkaWriter::new(brokers, topic, self.batch_size, linger_ms)?;

        KafkaLayer::from_writer(kafka_writer, self.static_fields)
    }
}
