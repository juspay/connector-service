//! Kafka writer implementation for sending formatted log messages to Kafka.

use std::io::{self, Write};
use std::sync::Arc;

use rdkafka::{
    config::ClientConfig,
    producer::{BaseRecord, DefaultProducerContext, Producer, ThreadedProducer},
};

/// A writer that sends log messages to Kafka.
#[derive(Clone)]
pub struct KafkaWriter {
    producer: Arc<ThreadedProducer<DefaultProducerContext>>,
    topic: String,
}

impl std::fmt::Debug for KafkaWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KafkaWriter")
            .field("topic", &self.topic)
            .finish()
    }
}

impl KafkaWriter {
    /// Creates a new KafkaWriter with the specified brokers and topic.
    pub fn new(brokers: Vec<String>, topic: String) -> Result<Self, KafkaWriterError> {
        let producer = ClientConfig::new()
            .set("bootstrap.servers", brokers.join(","))
            .create::<ThreadedProducer<DefaultProducerContext>>()
            .map_err(KafkaWriterError::ProducerCreation)?;

        Ok(Self {
            producer: Arc::new(producer),
            topic,
        })
    }
}

impl Write for KafkaWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Convert bytes to string for Kafka message
        let message = std::str::from_utf8(buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        // Send to Kafka (fire and forget for simplicity)
        let record: BaseRecord<'_, (), str> = BaseRecord::to(&self.topic).payload(message);
        
        match self.producer.send(record) {
            Ok(_) => Ok(buf.len()),
            Err((kafka_error, _)) => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to send to Kafka: {}", kafka_error),
            )),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        // Flush the producer to ensure messages are sent
        self.producer
            .flush(rdkafka::util::Timeout::After(std::time::Duration::from_secs(1)))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Kafka flush failed: {}", e)))
    }
}

/// Errors that can occur when creating or using a KafkaWriter.
#[derive(Debug, thiserror::Error)]
pub enum KafkaWriterError {
    #[error("Failed to create Kafka producer: {0}")]
    ProducerCreation(#[from] rdkafka::error::KafkaError),
}

/// Make KafkaWriter compatible with tracing_appender's MakeWriter trait.
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for KafkaWriter {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}
