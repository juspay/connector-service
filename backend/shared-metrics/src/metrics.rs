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
    pub static ref grpc_server_requests_total: IntCounterVec = register_int_counter_vec!(
        "grpc_server_requests_total",
        "Total number of gRPC requests received",
        &["method","connector"]
    )
        .unwrap();

    pub static ref grpc_server_requests_successful: IntCounterVec = register_int_counter_vec!(
        "grpc_server_requests_successful",
        "Total number of gRPC requests successful",
        &["method","connector"]
    )
        .unwrap();

    pub static ref grpc_server_request_latency: HistogramVec = register_histogram_vec!(
        "grpc_server_request_latency_seconds",
        "Request latency in seconds",
        &["method", "connector"],
        LATENCY_BUCKETS.to_vec()
    )
    .unwrap();

    pub static ref external_service_api_calls_latency: HistogramVec = register_histogram_vec!(
        "external_service_api_calls_latency_seconds",
        "Latency of external service API calls",
        &["endpoint", "method"],
        LATENCY_BUCKETS.to_vec()
    )
    .unwrap();

    pub static ref external_service_total_api_calls: IntCounterVec = register_int_counter_vec!(
        "external_service_total_api_calls",
        "Total number of external service API calls",
        &["endpoint", "method"]
    )
    .unwrap();

    pub static ref external_service_api_calls_errors: IntCounterVec = register_int_counter_vec!(
        "external_service_api_calls_errors",
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
    grpc_server_requests_total
        .with_label_values(&[method_name, connector])
        .inc();

    // Execute the handler
    let result = handler().await;

    // Record metrics based on result
    match &result {
        Ok(_) => {
            grpc_server_requests_successful
                .with_label_values(&[method_name, connector])
                .inc();
        }
        Err(_) => {
            // Could add error metrics here if needed
        }
    }

    // Record latency
    let duration = start_time.elapsed().as_secs_f64();
    grpc_server_request_latency
        .with_label_values(&[method_name, connector])
        .observe(duration);

    result
}

// Convenience macro for even easier usage
#[macro_export]
macro_rules! with_metrics {
    ($method:expr, $request:expr, $body:block) => {
        MetricsMiddleware::with_metrics($method, &$request, || async move $body).await
    };
    ($method:expr, $connector:expr, $body:block) => {
        MetricsMiddleware::with_metrics_and_connector($method, $connector, || async move $body).await
    };
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

// Ensure no manual implementation of std::fmt::Display exists for MetricsError to avoid conflicts with thiserror::Error derive macro
