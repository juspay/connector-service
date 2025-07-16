//! Kafka writer implementation for sending formatted log messages to Kafka.

use std::io::{self, Write};
use std::sync::Arc;
use std::time::Duration;

use rdkafka::{
    config::ClientConfig,
    error::KafkaError,
    producer::{BaseRecord, DefaultProducerContext, Producer, ThreadedProducer},
};

use crate::{
    KAFKA_DROPS_MSG_TOO_LARGE, KAFKA_DROPS_OTHER, KAFKA_DROPS_QUEUE_FULL, KAFKA_DROPS_TIMEOUT,
    KAFKA_LOGS_DROPPED, KAFKA_LOGS_SENT, KAFKA_QUEUE_SIZE,
};

/// Kafka writer that implements std::io::Write for seamless integration with tracing
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
        // config.set("queue.buffering.max.messages", "100000"); // Limit queue size
        // config.set("queue.buffering.max.kbytes", "1024000"); // 100MB max memory
        // config.set("socket.timeout.ms", "5000"); // 5 second socket timeout
        // config.set("message.timeout.ms", "30000"); // 30 second message timeout
        // config.set("request.timeout.ms", "10000"); // 10 second request timeout

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
        // Track queue depth for monitoring
        let queue_size = self.producer.in_flight_count();
        KAFKA_QUEUE_SIZE.set(queue_size as i64);

        // Warn when approaching queue limits (90% full)
        if queue_size > 90_000 {
            eprintln!("[KAFKA WARNING] Queue nearly full: {}/100000", queue_size);
        }

        // Kafka expects string payloads for JSON logs
        let message =
            std::str::from_utf8(buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        // Attach timestamp for event ordering in Kafka
        let record: BaseRecord<'_, (), str> =
            BaseRecord::to(&self.topic).payload(message).timestamp(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as i64)
                    .unwrap_or(0),
            );

        match self.producer.send(record) {
            Ok(_) => {
                KAFKA_LOGS_SENT.inc();
                Ok(buf.len())
            }
            Err((kafka_error, _)) => {
                KAFKA_LOGS_DROPPED.inc();

                // Track specific drop reasons for debugging
                match &kafka_error {
                    KafkaError::MessageProduction(rdkafka::error::RDKafkaErrorCode::QueueFull) => {
                        KAFKA_DROPS_QUEUE_FULL.inc();
                        eprintln!("[KAFKA DROP] Reason: Queue full (size: {})", queue_size);
                    }
                    KafkaError::MessageProduction(
                        rdkafka::error::RDKafkaErrorCode::MessageSizeTooLarge,
                    ) => {
                        KAFKA_DROPS_MSG_TOO_LARGE.inc();
                        eprintln!(
                            "[KAFKA DROP] Reason: Message too large (size: {} bytes)",
                            buf.len()
                        );
                    }
                    KafkaError::MessageProduction(
                        rdkafka::error::RDKafkaErrorCode::MessageTimedOut,
                    ) => {
                        KAFKA_DROPS_TIMEOUT.inc();
                        eprintln!("[KAFKA DROP] Reason: Message timed out");
                    }
                    _ => {
                        KAFKA_DROPS_OTHER.inc();
                        eprintln!("[KAFKA DROP] Reason: {:?}", kafka_error);
                    }
                }

                // Non-blocking: drop logs rather than block the app
                Ok(buf.len())
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
