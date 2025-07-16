use lazy_static::lazy_static;
use prometheus::{
    register_gauge, register_histogram, register_int_counter, register_int_gauge, Gauge, Histogram,
    IntCounter, IntGauge,
};

lazy_static! {
    // ===== TEST ENDPOINT METRICS =====

    /// Total number of test logging requests
    pub static ref TEST_LOGGING_REQUESTS: IntCounter = register_int_counter!(
        "test_logging_requests_total",
        "Total number of test logging requests"
    ).expect("Failed to register test_logging_requests_total");

    /// Total number of log events generated at tracing level (before filtering)
    pub static ref TRACING_EVENTS_GENERATED: IntCounter = register_int_counter!(
        "tracing_events_generated_total",
        "Total number of log events generated at tracing level (before filtering)"
    ).expect("Failed to register tracing_events_generated_total");

    /// Test logging request duration histogram
    pub static ref TEST_LOGGING_DURATION: Histogram = register_histogram!(
        "test_logging_duration_seconds",
        "Duration of test logging requests"
    ).expect("Failed to register test_logging_duration");

    /// Total logs generated in test
    pub static ref TEST_LOGS_GENERATED: IntCounter = register_int_counter!(
        "test_logs_generated_total",
        "Total number of logs generated in test"
    ).expect("Failed to register test_logs_generated_total");

    /// Total logs lost in test
    pub static ref TEST_LOGS_LOST: IntCounter = register_int_counter!(
        "test_logs_lost_total",
        "Total number of logs lost in test"
    ).expect("Failed to register test_logs_lost_total");

    /// Current log loss rate percentage
    pub static ref LOG_LOSS_RATE: Gauge = register_gauge!(
        "log_loss_rate_percent",
        "Current log loss rate as a percentage"
    ).expect("Failed to register log_loss_rate");

    /// Log throughput (logs per second)
    pub static ref LOG_THROUGHPUT: Gauge = register_gauge!(
        "log_throughput_per_second",
        "Current log throughput in logs per second"
    ).expect("Failed to register log_throughput");

    // ===== PERFORMANCE METRICS =====

    /// Log send duration histogram
    pub static ref LOG_SEND_DURATION: Histogram = register_histogram!(
        "log_send_duration_seconds",
        "Time taken to send individual logs"
    ).expect("Failed to register log_send_duration");

    // ===== KAFKA SPECIFIC METRICS =====

    /// Kafka connection status (1 = connected, 0 = disconnected)
    pub static ref KAFKA_CONNECTION_STATUS: IntGauge = register_int_gauge!(
        "kafka_connection_status",
        "Kafka connection status (1 = connected, 0 = disconnected)"
    ).expect("Failed to register kafka_connection_status");

    /// Kafka send errors counter
    pub static ref KAFKA_SEND_ERRORS: IntCounter = register_int_counter!(
        "kafka_send_errors_total",
        "Total number of Kafka send errors"
    ).expect("Failed to register kafka_send_errors");
}

/// Update log loss rate percentage based on generated and lost counts
pub fn update_log_loss_rate() {
    let generated = TEST_LOGS_GENERATED.get() as f64;
    let lost = TEST_LOGS_LOST.get() as f64;

    if generated > 0.0 {
        let loss_rate = (lost / generated) * 100.0;
        LOG_LOSS_RATE.set(loss_rate);
    }
}

/// Record a successful log send with duration
pub fn record_log_success(duration_secs: f64) {
    TEST_LOGS_GENERATED.inc();
    LOG_SEND_DURATION.observe(duration_secs);
}

/// Record a failed log send
pub fn record_log_failure() {
    TEST_LOGS_GENERATED.inc();
    TEST_LOGS_LOST.inc();
    KAFKA_SEND_ERRORS.inc();
    update_log_loss_rate();
}
