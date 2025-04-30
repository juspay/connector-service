use error_stack::ResultExt;
use lazy_static::lazy_static;
use prometheus::{self, Encoder, TextEncoder};

// const MICROS_500: f64 = 0.0001;

lazy_static! {
    // pub static ref SUCCESS_BASED_ROUTING_METRICS_REQUEST: IntCounter = register_int_counter!(
    //     "success_based_routing_metrics_request",
    //     "total success based routing request received"
    // )
    // .unwrap();
    // pub static ref SUCCESS_BASED_ROUTING_UPDATE_WINDOW_DECISION_REQUEST_TIME: Histogram =
    //     register_histogram!(
    //         "success_based_routing_update_window_decision_request_time",
    //         "Time taken to process success based routing update window request (in seconds)",
    //         #[allow(clippy::expect_used)]
    //         exponential_buckets(MICROS_500, 2.0, 10).expect("failed to create histogram")
    //     )
    //     .unwrap();
}

pub async fn metrics_handler() -> error_stack::Result<String, MetricsError> {
    let mut buffer = Vec::new();
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    encoder
        .encode(&metric_families, &mut buffer)
        .change_context(MetricsError::EncodingError)?;
    String::from_utf8(buffer).change_context(MetricsError::Utf8Error)
}

#[derive(Debug, thiserror::Error)]
pub enum MetricsError {
    #[error("Error encoding metrics")]
    EncodingError,
    #[error("Error converting metrics to utf8")]
    Utf8Error,
}
