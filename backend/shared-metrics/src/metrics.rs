use error_stack::ResultExt;
use lazy_static::lazy_static;
use prometheus::{
    self, Encoder, HistogramVec, IntCounterVec, TextEncoder, register_histogram_vec,
    register_int_counter_vec,
};
use std::future::Future;
use std::time::Instant;
use tonic::{Response, Status};

// Define latency buckets for histograms
const LATENCY_BUCKETS: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

lazy_static! {
    pub static ref GRPC_SERVER_REQUESTS_TOTAL: IntCounterVec = register_int_counter_vec!(
        "GRPC_SERVER_REQUESTS_TOTAL",
        "Total number of gRPC requests received",
        &["flow","connector"]
    )
        .unwrap();

    pub static ref GRPC_SERVER_REQUESTS_SUCCESSFUL: IntCounterVec = register_int_counter_vec!(
        "GRPC_SERVER_REQUESTS_SUCCESSFUL",
        "Total number of gRPC requests successful",
        &["flow","connector"]
    )
        .unwrap();

    pub static ref GRPC_SERVER_REQUEST_LATENCY: HistogramVec = register_histogram_vec!(
        "GRPC_SERVER_REQUEST_LATENCY_SECONDS",
        "Request latency in seconds",
        &["flow", "connector"],
        LATENCY_BUCKETS.to_vec()
    )
    .unwrap();

    pub static ref EXTERNAL_SERVICE_API_CALLS_LATENCY: HistogramVec = register_histogram_vec!(
        "EXTERNAL_SERVICE_API_CALLS_LATENCY_SECONDS",
        "Latency of external service API calls",
        &["endpoint", "method"],
        LATENCY_BUCKETS.to_vec()
    )
    .unwrap();

    pub static ref EXTERNAL_SERVICE_TOTAL_API_CALLS: IntCounterVec = register_int_counter_vec!(
        "EXTERNAL_SERVICE_TOTAL_API_CALLS",
        "Total number of external service API calls",
        &["endpoint", "method"]
    )
    .unwrap();

    pub static ref EXTERNAL_SERVICE_API_CALLS_ERRORS: IntCounterVec = register_int_counter_vec!(
        "EXTERNAL_SERVICE_API_CALLS_ERRORS",
        "Total number of errors in external service API calls",
        &["endpoint", "method", "error"]
    )
    .unwrap();

}

pub async fn with_metrics_and_connector<R, F, Fut>(
    method_name: &str,
    connector: &str,
    handler: F,
) -> Result<Response<R>, Status>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<Response<R>, Status>>,
{
    let start_time = Instant::now();

    // Increment total requests counter
    GRPC_SERVER_REQUESTS_TOTAL
        .with_label_values(&[method_name, connector])
        .inc();

    // Execute the handler
    let result = handler().await;

    // Record metrics based on result
    match &result {
        Ok(_) => {
            GRPC_SERVER_REQUESTS_SUCCESSFUL
                        .with_label_values(&[method_name, connector])
                        .inc();
        }
        Err(_) => {
            // Could add error metrics here if needed
        }
    }

    // Record latency
    let duration = start_time.elapsed().as_secs_f64();
    GRPC_SERVER_REQUEST_LATENCY
        .with_label_values(&[method_name, connector])
        .observe(duration);

    result
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
