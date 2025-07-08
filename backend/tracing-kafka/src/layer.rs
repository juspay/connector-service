//! Kafka layer implementation that reuses log_utils formatting.

use std::collections::{HashMap, HashSet};

use log_utils::{
    AdditionalFieldsPlacement, JsonFormattingLayer, JsonFormattingLayerConfig, LoggerError,
};
use serde_json::Value;
use tracing::Subscriber;
use tracing_subscriber::Layer;

use crate::writer::{KafkaWriter, KafkaWriterError};

/// A tracing layer that sends formatted logs to Kafka using the same formatting as log_utils.
pub struct KafkaLayer<S> {
    inner: JsonFormattingLayer<KafkaWriter, serde_json::ser::CompactFormatter>,
    _phantom: std::marker::PhantomData<S>,
}

impl<S> KafkaLayer<S>
where
    S: Subscriber,
{
    /// Creates a new KafkaLayer with basic configuration.
    pub fn new(brokers: Vec<String>, topic: String) -> Result<Self, KafkaLayerError> {
        Self::with_config(brokers, topic, HashMap::new())
    }

    /// Creates a new KafkaLayer with custom static fields.
    pub fn with_config(
        brokers: Vec<String>,
        topic: String,
        static_fields: HashMap<String, Value>,
    ) -> Result<Self, KafkaLayerError> {
        let kafka_writer: KafkaWriter = KafkaWriter::new(brokers, topic)?;

        let config = JsonFormattingLayerConfig {
            static_top_level_fields: static_fields,
            top_level_keys: HashSet::new(),
            log_span_lifecycles: true,
            additional_fields_placement: AdditionalFieldsPlacement::TopLevel,
        };

        let inner = JsonFormattingLayer::new(
            config,
            kafka_writer,
            serde_json::ser::CompactFormatter,
        )?;

        Ok(Self {
            inner,
            _phantom: std::marker::PhantomData,
        })
    }

    /// Creates a new KafkaLayer with full configuration control.
    pub fn with_full_config(
        brokers: Vec<String>,
        topic: String,
        config: JsonFormattingLayerConfig,
    ) -> Result<Self, KafkaLayerError> {
        let kafka_writer = KafkaWriter::new(brokers, topic)?;

        let inner: JsonFormattingLayer<KafkaWriter, serde_json::ser::CompactFormatter> = JsonFormattingLayer::new(
            config,
            kafka_writer,
            serde_json::ser::CompactFormatter,
        )?;

        Ok(Self {
            inner,
            _phantom: std::marker::PhantomData,
        })
    }
}

impl<S> Layer<S> for KafkaLayer<S>
where
    S: Subscriber + for<'lookup> tracing_subscriber::registry::LookupSpan<'lookup>,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
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

/// Errors that can occur when creating a KafkaLayer.
#[derive(Debug, thiserror::Error)]
pub enum KafkaLayerError {
    #[error("Kafka writer error: {0}")]
    Writer(#[from] KafkaWriterError),

    #[error("Logger configuration error: {0}")]
    Logger(#[from] LoggerError),
}
