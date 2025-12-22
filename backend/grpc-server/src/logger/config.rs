//!
//! Logger-specific config.
//!

use serde::{Deserialize, Serialize};
use struct_patch::Patch;
/// Log config settings.
#[derive(Debug, Deserialize, Clone, Serialize, PartialEq, Patch)]
#[patch(attribute(derive(Debug, Default, Deserialize, Serialize)))]
#[patch(attribute(serde(default)))]
pub struct Log {
    /// Logging to a console.
    #[patch(nesting)]
    pub console: LogConsole,
    /// Logging to Kafka (optional).
    #[serde(default)]
    #[patch(name = "Option<LogKafkaPatch>")]
    pub kafka: Option<LogKafka>,
}

/// Logging to a console.
#[derive(Debug, Deserialize, Clone, Serialize, PartialEq, Eq, Patch)]
#[patch(attribute(derive(Debug, Default, Deserialize, Serialize)))]
#[patch(attribute(serde(default)))]
pub struct LogConsole {
    /// Whether you want to see log in your terminal.
    pub enabled: bool,
    /// What you see in your terminal.
    pub level: Level,
    /// Log format
    pub log_format: LogFormat,
    /// Directive which sets the log level for one or more crates/modules.
    pub filtering_directive: Option<String>,
}

/// Describes the level of verbosity of a span or event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Level(pub(super) tracing::Level);

impl Serialize for Level {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.0.as_str())
    }
}

impl Level {
    /// Returns the most verbose [`tracing::Level`]
    pub fn into_level(&self) -> tracing::Level {
        self.0
    }
}

impl Default for Level {
    fn default() -> Self {
        Self(tracing::Level::INFO)
    }
}

impl<'de> Deserialize<'de> for Level {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use std::str::FromStr as _;

        let s = String::deserialize(deserializer)?;
        tracing::Level::from_str(&s)
            .map(Level)
            .map_err(serde::de::Error::custom)
    }
}

/// Telemetry / tracing.
#[derive(Default, Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// Default pretty log format
    Default,
    /// JSON based structured logging
    #[default]
    Json,
}

/// Logging to Kafka.
#[derive(Debug, Deserialize, Clone, Serialize, PartialEq, Patch, Default)]
#[patch(attribute(derive(Debug, Default, Deserialize, Serialize)))]
#[patch(attribute(serde(default)))]
pub struct LogKafka {
    /// Whether Kafka logging is enabled.
    pub enabled: bool,
    /// Minimum log level for Kafka logging.
    pub level: Level,
    /// Directive which sets the log level for one or more crates/modules.
    pub filtering_directive: Option<String>,
    /// Kafka broker addresses.
    pub brokers: Vec<String>,
    /// Topic name for logs.
    pub topic: String,
    /// Batch size for Kafka messages (optional, defaults to Kafka default).
    #[serde(default)]
    pub batch_size: Option<usize>,
    /// Flush interval in milliseconds (optional, defaults to Kafka default).
    #[serde(default)]
    pub flush_interval_ms: Option<u64>,
    /// Buffer limit for Kafka messages (optional, defaults to Kafka default).
    #[serde(default)]
    pub buffer_limit: Option<usize>,
}
