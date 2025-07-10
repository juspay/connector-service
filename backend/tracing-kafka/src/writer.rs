//! Kafka writer implementation for sending formatted log messages to Kafka.

use std::io::{self, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rdkafka::{
    config::ClientConfig,
    error::KafkaError,
    producer::{BaseRecord, DefaultProducerContext, Producer, ThreadedProducer},
};

use crate::{KAFKA_LOGS_DROPPED, KAFKA_LOGS_SENT};

/// Global counter for dropped logs (for monitoring during load tests)
pub static DROPPED_LOGS: AtomicU64 = AtomicU64::new(0);

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
    /// Optionally accepts batch_size and linger_ms for custom configuration.
    pub fn new(
        brokers: Vec<String>,
        topic: String,
        batch_size: Option<usize>,
        linger_ms: Option<u64>,
    ) -> Result<Self, KafkaWriterError> {
        let mut config = ClientConfig::new();
        config.set("bootstrap.servers", brokers.join(","));

        config.set("queue.buffering.max.messages", "10000"); // Limit queue size
        config.set("queue.buffering.max.kbytes", "102400"); // 100MB max memory
        config.set("socket.timeout.ms", "5000"); // 5 second socket timeout
        config.set("message.timeout.ms", "30000"); // 30 second message timeout
        config.set("request.timeout.ms", "10000"); // 10 second request timeout

        // Only set custom values if provided, otherwise use Kafka defaults
        if let Some(size) = batch_size {
            config.set("batch.size", size.to_string());
        }
        if let Some(ms) = linger_ms {
            config.set("linger.ms", ms.to_string());
        }

        let producer = config
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
        let message =
            std::str::from_utf8(buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        // Create Kafka record
        let record: BaseRecord<'_, (), str> = BaseRecord::to(&self.topic).payload(message);

        match self.producer.send(record) {
            Ok(_) => {
                // Increment success counter
                KAFKA_LOGS_SENT.inc();
                Ok(buf.len())
            }
            Err((kafka_error, _)) => {
                // Increment dropped counter
                KAFKA_LOGS_DROPPED.inc();

                // Check if it's a queue full error
                if let KafkaError::MessageProduction(rdkafka::error::RDKafkaErrorCode::QueueFull) =
                    &kafka_error
                {
                    // Queue is full - increment counter and drop the log
                    DROPPED_LOGS.fetch_add(1, Ordering::Relaxed);
                    // Return success anyway - don't want logging to fail the app
                    Ok(buf.len())
                } else {
                    // For other errors, still drop but log the error type
                    DROPPED_LOGS.fetch_add(1, Ordering::Relaxed);
                    // Return success to prevent app failure
                    Ok(buf.len())
                }
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        // Flush the producer to ensure messages are sent
        self.producer
            .flush(rdkafka::util::Timeout::After(Duration::from_secs(5)))
            .map_err(|e: KafkaError| io::Error::other(format!("Kafka flush failed: {e}")))
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

/// Graceful shutdown - flush pending messages when dropping
impl Drop for KafkaWriter {
    fn drop(&mut self) {
        // Only flush if this is the last reference to the producer
        if Arc::strong_count(&self.producer) == 1 {
            // Try to flush pending messages with a 5 second timeout
            let _ = self
                .producer
                .flush(rdkafka::util::Timeout::After(Duration::from_secs(5)));
        }
    }
}
