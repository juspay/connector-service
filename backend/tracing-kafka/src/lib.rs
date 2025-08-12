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

// Prometheus metrics
use once_cell::sync::Lazy;
use prometheus::{register_int_counter, register_int_gauge, IntCounter, IntGauge};

/// Total number of logs successfully sent to Kafka
pub static KAFKA_LOGS_SENT: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "kafka_logs_sent_total",
        "Total number of logs successfully sent to Kafka"
    )
    .expect("Failed to register kafka_logs_sent_total metric")
});

/// Total number of logs dropped due to Kafka queue full or errors
pub static KAFKA_LOGS_DROPPED: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "kafka_logs_dropped_total",
        "Total number of logs dropped due to Kafka queue full or errors"
    )
    .expect("Failed to register kafka_logs_dropped_total metric")
});

/// Current size of Kafka producer queue
pub static KAFKA_QUEUE_SIZE: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "kafka_producer_queue_size",
        "Current size of Kafka producer queue"
    )
    .expect("Failed to register kafka_producer_queue_size metric")
});

/// Logs dropped due to queue full
pub static KAFKA_DROPS_QUEUE_FULL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "kafka_drops_queue_full_total",
        "Total number of logs dropped due to Kafka queue being full"
    )
    .expect("Failed to register kafka_drops_queue_full_total metric")
});

/// Logs dropped due to message too large
pub static KAFKA_DROPS_MSG_TOO_LARGE: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "kafka_drops_msg_too_large_total",
        "Total number of logs dropped due to message size exceeding limit"
    )
    .expect("Failed to register kafka_drops_msg_too_large_total metric")
});

/// Logs dropped due to timeout
pub static KAFKA_DROPS_TIMEOUT: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "kafka_drops_timeout_total",
        "Total number of logs dropped due to timeout"
    )
    .expect("Failed to register kafka_drops_timeout_total metric")
});

/// Logs dropped due to other errors
pub static KAFKA_DROPS_OTHER: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "kafka_drops_other_total",
        "Total number of logs dropped due to other errors"
    )
    .expect("Failed to register kafka_drops_other_total metric")
});

/// Total number of audit events successfully sent to Kafka
pub static KAFKA_AUDIT_EVENTS_SENT: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "kafka_audit_events_sent_total",
        "Total number of audit events successfully sent to Kafka"
    )
    .expect("Failed to register kafka_audit_events_sent_total metric")
});

/// Total number of audit events dropped due to Kafka queue full or errors
pub static KAFKA_AUDIT_EVENTS_DROPPED: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "kafka_audit_events_dropped_total",
        "Total number of audit events dropped due to Kafka queue full or errors"
    )
    .expect("Failed to register kafka_audit_events_dropped_total metric")
});

/// Builder for creating a KafkaLayer with custom configuration.
#[derive(Debug, Clone, Default)]
pub struct KafkaLayerBuilder {
    brokers: Option<Vec<String>>,
    topic: Option<String>,
    batch_size: Option<usize>,
    flush_interval: Option<Duration>,
    static_fields: HashMap<String, serde_json::Value>,
    queue_buffering_max_messages: Option<usize>,
    queue_buffering_max_kbytes: Option<usize>,
    reconnect_backoff_ms: Option<u64>,
    reconnect_backoff_max_ms: Option<u64>,
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
    pub fn batch_size(mut self, size: usize) -> Self {
        self.batch_size = Some(size);
        self
    }

    /// Sets the flush interval for sending buffered messages.
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

    /// Sets the maximum number of messages to buffer in the producer's queue.
    pub fn queue_buffering_max_messages(mut self, size: usize) -> Self {
        self.queue_buffering_max_messages = Some(size);
        self
    }

    /// Sets the maximum size of the producer's queue in kilobytes.
    pub fn queue_buffering_max_kbytes(mut self, size: usize) -> Self {
        self.queue_buffering_max_kbytes = Some(size);
        self
    }

    /// Sets the initial and maximum backoff time for reconnecting to a broker.
    pub fn reconnect_backoff(mut self, min: Duration, max: Duration) -> Self {
        self.reconnect_backoff_ms = Some(min.as_millis() as u64);
        self.reconnect_backoff_max_ms = Some(max.as_millis() as u64);
        self
    }

    /// Builds the KafkaLayer with the configured settings.
    pub fn build(self) -> Result<KafkaLayer, KafkaLayerError> {
        let brokers: Vec<String> = self.brokers.ok_or(KafkaLayerError::MissingBrokers)?;
        let topic = self.topic.ok_or(KafkaLayerError::MissingTopic)?;

        // Convert flush_interval to milliseconds for Kafka's linger.ms setting if provided
        let linger_ms = self.flush_interval.map(|d| d.as_millis() as u64);

        let kafka_writer = KafkaWriter::new(
            brokers,
            topic,
            self.batch_size,
            linger_ms,
            self.queue_buffering_max_messages,
            self.queue_buffering_max_kbytes,
            self.reconnect_backoff_ms,
            self.reconnect_backoff_max_ms,
        )?;

        KafkaLayer::from_writer(kafka_writer, self.static_fields)
    }
}
