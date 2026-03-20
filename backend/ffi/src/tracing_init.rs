//! One-shot initialization of the FFI streaming tracing subscriber.
//!
//! Reuses the same `JsonFormattingLayer` from `log_utils` that the server-side
//! `tracing-kafka` crate uses, but writes to stdout/stderr/file instead of Kafka.
//! Guarded by `OnceLock` so that the first call wins and subsequent calls are no-ops.

use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

use log_utils::{AdditionalFieldsPlacement, JsonFormattingLayer, JsonFormattingLayerConfig};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

use crate::tracing_writer::FfiWriter;

/// Guard ensuring the global tracing subscriber is installed at most once.
static INIT_GUARD: OnceLock<Result<(), String>> = OnceLock::new();

/// Initialize the FFI streaming tracing subscriber.
///
/// Installs a `JsonFormattingLayer<FfiWriter>` as the global default subscriber.
/// Uses `try_init()` to avoid panicking if another library has already set one.
///
/// Returns `Ok(())` on success or if already initialized.
/// Returns `Err(msg)` if subscriber installation fails for a non-idempotency reason.
pub fn init_ffi_tracing(writer: FfiWriter, level_filter: Option<&str>) -> Result<(), String> {
    INIT_GUARD
        .get_or_init(|| {
            let static_top_level_fields = HashMap::from_iter([(
                "source".to_string(),
                serde_json::json!("ffi-sdk"),
            )]);

            let config = JsonFormattingLayerConfig {
                static_top_level_fields,
                top_level_keys: HashSet::new(),
                log_span_lifecycles: true,
                additional_fields_placement: AdditionalFieldsPlacement::TopLevel,
            };

            let layer: JsonFormattingLayer<FfiWriter, serde_json::ser::CompactFormatter> =
                JsonFormattingLayer::new(config, writer, serde_json::ser::CompactFormatter)
                    .map_err(|e| format!("Failed to create JsonFormattingLayer: {e}"))?;

            let filter = EnvFilter::try_new(level_filter.unwrap_or("info"))
                .map_err(|e| format!("Invalid level_filter: {e}"))?;

            tracing_subscriber::registry()
                .with(layer.with_filter(filter))
                .try_init()
                .map_err(|e| format!("Failed to set global subscriber: {e}"))
        })
        .clone()
}
