//! A generic Kafka tracing subscriber that reuses log_utils formatting.
//!
//! This crate provides a simple way to send tracing logs to Kafka while maintaining
//! the exact same JSON format as your existing log_utils-based logging infrastructure.
//!
//! # Example
//!
//! ```rust
//! use std::collections::HashMap;
//! use serde_json::json;
//! use tracing_kafka::KafkaLayer;
//! use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
//!
//! // Basic usage
//! let kafka_layer = KafkaLayer::new(
//!     vec!["localhost:9092".to_string()],
//!     "application-logs".to_string(),
//! ).expect("Failed to create Kafka layer");
//!
//! // With custom static fields (like service name, version, etc.)
//! let static_fields = HashMap::from([
//!     ("service".to_string(), json!("my-service")),
//!     ("version".to_string(), json!("1.0.0")),
//! ]);
//!
//! let kafka_layer_with_config = KafkaLayer::with_config(
//!     vec!["localhost:9092".to_string()],
//!     "application-logs".to_string(),
//!     static_fields,
//! ).expect("Failed to create Kafka layer");
//!
//! // Set up tracing with both console and Kafka logging
//! tracing_subscriber::registry()
//!     .with(tracing_subscriber::fmt::layer()) // Console logging
//!     .with(kafka_layer)                      // Kafka logging
//!     .init();
//!
//! // Now all tracing calls will be sent to both console and Kafka
//! tracing::info!("Application started successfully");
//! tracing::error!(error = %err, "Failed to process request");
//! ```
//!
//! # Features
//!
//! - **Identical JSON format**: Uses the same `log_utils::JsonFormattingLayer` for consistent formatting
//! - **Simple API**: Just provide Kafka brokers and topic name
//! - **Generic**: Works with any application using tracing
//! - **Non-blocking**: Kafka failures won't block your application
//! - **Configurable**: Support for custom static fields and full configuration control

mod layer;
mod writer;

pub use layer::{KafkaLayer, KafkaLayerError};
pub use writer::{KafkaWriter, KafkaWriterError};

// Re-export useful types from log_utils for convenience
pub use log_utils::{
    AdditionalFieldsPlacement, JsonFormattingLayerConfig, Level, LoggerError,
};
