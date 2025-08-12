

use std::collections::HashMap;
use std::time::Duration;

use super::{KafkaLayer, KafkaLayerError, KafkaWriter};

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
