//! Prometheus metrics for Kafka writer

use once_cell::sync::Lazy;
use prometheus::{register_int_counter, register_int_gauge, IntCounter, IntGauge};

/// Total number of logs successfully sent to Kafka
#[allow(clippy::expect_used)]
pub static KAFKA_LOGS_SENT: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "kafka_logs_sent_total",
        "Total number of logs successfully sent to Kafka"
    )
    .expect("Failed to register kafka_logs_sent_total metric")
});

/// Total number of logs dropped due to Kafka queue full or errors
#[allow(clippy::expect_used)]
pub static KAFKA_LOGS_DROPPED: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "kafka_logs_dropped_total",
        "Total number of logs dropped due to Kafka queue full or errors"
    )
    .expect("Failed to register kafka_logs_dropped_total metric")
});

/// Current size of Kafka producer queue
#[allow(clippy::expect_used)]
pub static KAFKA_QUEUE_SIZE: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "kafka_producer_queue_size",
        "Current size of Kafka producer queue"
    )
    .expect("Failed to register kafka_producer_queue_size metric")
});

/// Logs dropped due to queue full
#[allow(clippy::expect_used)]
pub static KAFKA_DROPS_QUEUE_FULL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "kafka_drops_queue_full_total",
        "Total number of logs dropped due to Kafka queue being full"
    )
    .expect("Failed to register kafka_drops_queue_full_total metric")
});

/// Logs dropped due to message too large
#[allow(clippy::expect_used)]
pub static KAFKA_DROPS_MSG_TOO_LARGE: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "kafka_drops_msg_too_large_total",
        "Total number of logs dropped due to message size exceeding limit"
    )
    .expect("Failed to register kafka_drops_msg_too_large_total metric")
});

/// Logs dropped due to timeout
#[allow(clippy::expect_used)]
pub static KAFKA_DROPS_TIMEOUT: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "kafka_drops_timeout_total",
        "Total number of logs dropped due to timeout"
    )
    .expect("Failed to register kafka_drops_timeout_total metric")
});

/// Logs dropped due to other errors
#[allow(clippy::expect_used)]
pub static KAFKA_DROPS_OTHER: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "kafka_drops_other_total",
        "Total number of logs dropped due to other errors"
    )
    .expect("Failed to register kafka_drops_other_total metric")
});

/// Total number of audit events successfully sent to Kafka
#[allow(clippy::expect_used)]
pub static KAFKA_AUDIT_EVENTS_SENT: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "kafka_audit_events_sent_total",
        "Total number of audit events successfully sent to Kafka"
    )
    .expect("Failed to register kafka_audit_events_sent_total metric")
});

/// Total number of audit events dropped due to Kafka queue full or errors
#[allow(clippy::expect_used)]
pub static KAFKA_AUDIT_EVENTS_DROPPED: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "kafka_audit_events_dropped_total",
        "Total number of audit events dropped due to Kafka queue full or errors"
    )
    .expect("Failed to register kafka_audit_events_dropped_total metric")
});

/// Current size of Kafka audit event producer queue
#[allow(clippy::expect_used)]
pub static KAFKA_AUDIT_EVENT_QUEUE_SIZE: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "kafka_audit_event_queue_size",
        "Current size of Kafka audit event producer queue"
    )
    .expect("Failed to register kafka_audit_event_queue_size metric")
});

/// Audit events dropped due to queue full
#[allow(clippy::expect_used)]
pub static KAFKA_AUDIT_DROPS_QUEUE_FULL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "kafka_audit_drops_queue_full_total",
        "Total number of audit events dropped due to Kafka queue being full"
    )
    .expect("Failed to register kafka_audit_drops_queue_full_total metric")
});

/// Audit events dropped due to message too large
#[allow(clippy::expect_used)]
pub static KAFKA_AUDIT_DROPS_MSG_TOO_LARGE: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "kafka_audit_drops_msg_too_large_total",
        "Total number of audit events dropped due to message size exceeding limit"
    )
    .expect("Failed to register kafka_audit_drops_msg_too_large_total metric")
});

/// Audit events dropped due to timeout
#[allow(clippy::expect_used)]
pub static KAFKA_AUDIT_DROPS_TIMEOUT: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "kafka_audit_drops_timeout_total",
        "Total number of audit events dropped due to timeout"
    )
    .expect("Failed to register kafka_audit_drops_timeout_total metric")
});

/// Audit events dropped due to other errors
#[allow(clippy::expect_used)]
pub static KAFKA_AUDIT_DROPS_OTHER: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "kafka_audit_drops_other_total",
        "Total number of audit events dropped due to other errors"
    )
    .expect("Failed to register kafka_audit_drops_other_total metric")
});
