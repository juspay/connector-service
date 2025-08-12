//! Kafka layer implementation that reuses log_utils formatting.

use std::collections::{HashMap, HashSet};

use log_utils::{
    AdditionalFieldsPlacement, JsonFormattingLayer, JsonFormattingLayerConfig, LoggerError,
};
use tracing::Subscriber;
use tracing_subscriber::Layer;

use crate::writer::{KafkaWriter, KafkaWriterError};

/// Tracing layer that sends JSON-formatted logs to Kafka
///
/// Wraps log_utils' JsonFormattingLayer
pub struct KafkaLayer {
    inner: JsonFormattingLayer<KafkaWriter, serde_json::ser::CompactFormatter>,
}

impl KafkaLayer {
    /// Creates a new builder for configuring a KafkaLayer.
    pub fn builder() -> super::builder::KafkaLayerBuilder {
        super::builder::KafkaLayerBuilder::new()
    }

    /// Creates a new KafkaLayer from a pre-configured KafkaWriter.
    /// This is primarily used internally by the builder.
    pub(crate) fn from_writer(
        kafka_writer: KafkaWriter,
        static_fields: HashMap<String, serde_json::Value>,
    ) -> Result<Self, KafkaLayerError> {
        let config = JsonFormattingLayerConfig {
            static_top_level_fields: static_fields,
            top_level_keys: HashSet::new(),
            log_span_lifecycles: true,
            additional_fields_placement: AdditionalFieldsPlacement::TopLevel,
        };

        let inner =
            JsonFormattingLayer::new(config, kafka_writer, serde_json::ser::CompactFormatter)?;

        Ok(Self { inner })
    }
}

impl<S> Layer<S> for KafkaLayer
where
    S: Subscriber + for<'lookup> tracing_subscriber::registry::LookupSpan<'lookup>,
{
    fn on_event(&self, event: &tracing::Event<'_>, ctx: tracing_subscriber::layer::Context<'_, S>) {
        self.inner.on_event(event, ctx);
    }

    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        id: &tracing::span::Id,
        ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        self.inner.on_new_span(attrs, id, ctx);
    }

    fn on_enter(&self, id: &tracing::span::Id, ctx: tracing_subscriber::layer::Context<'_, S>) {
        self.inner.on_enter(id, ctx);
    }

    fn on_exit(&self, id: &tracing::span::Id, ctx: tracing_subscriber::layer::Context<'_, S>) {
        self.inner.on_exit(id, ctx);
    }

    fn on_close(&self, id: tracing::span::Id, ctx: tracing_subscriber::layer::Context<'_, S>) {
        self.inner.on_close(id, ctx);
    }
}

impl KafkaLayer {
    /// Boxes the layer, making it easier to compose with other layers.
    pub fn boxed<S>(self) -> Box<dyn Layer<S> + Send + Sync + 'static>
    where
        Self: Layer<S> + Sized + Send + Sync + 'static,
        S: Subscriber + for<'span> tracing_subscriber::registry::LookupSpan<'span>,
    {
        Box::new(self)
    }
}

/// Errors that can occur when creating a KafkaLayer.
#[derive(Debug, thiserror::Error)]
pub enum KafkaLayerError {
    #[error("Kafka writer error: {0}")]
    Writer(#[from] KafkaWriterError),

    #[error("Logger configuration error: {0}")]
    Logger(#[from] LoggerError),

    #[error("Missing brokers configuration")]
    MissingBrokers,

    #[error("Missing topic configuration")]
    MissingTopic,
}
