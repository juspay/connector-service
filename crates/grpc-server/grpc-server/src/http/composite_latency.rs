use axum::{extract::Request, middleware::Next, response::Response};
use common_utils::{consts::X_OUTGOING_API_OVERHEAD, request_metrics::ConnectorLatencyTracker};

pub async fn track_composite_outgoing_latency(mut request: Request, next: Next) -> Response {
    if !request.uri().path().starts_with("/composite/") {
        return next.run(request).await;
    }

    let tracker = ConnectorLatencyTracker::default();
    request.extensions_mut().insert(tracker.clone());

    let mut response = next.run(request).await;
    if let Ok(value) = tracker.outgoing_latency_millis().to_string().parse() {
        response
            .headers_mut()
            .insert(X_OUTGOING_API_OVERHEAD, value);
    }
    response
}

#[cfg(test)]
mod tests {
    use axum::{
        extract::Extension,
        http::{HeaderValue, Request, StatusCode},
        middleware,
        routing::get,
        Router,
    };
    use common_utils::{consts::X_OUTGOING_API_OVERHEAD, request_metrics::ConnectorLatencyTracker};
    use tower::ServiceExt;

    use super::track_composite_outgoing_latency;

    async fn record_latency(tracker: Option<Extension<ConnectorLatencyTracker>>) -> StatusCode {
        if let Some(Extension(tracker)) = tracker {
            tracker.add_outgoing_latency_millis(1875);
            tracker.add_outgoing_latency_millis(1974);
        }
        StatusCode::BAD_GATEWAY
    }

    fn test_router() -> Router {
        Router::new()
            .route("/composite/test", get(record_latency))
            .route("/payments/test", get(record_latency))
            .layer(middleware::from_fn(track_composite_outgoing_latency))
    }

    #[tokio::test]
    async fn composite_http_response_contains_exact_sum_even_on_error() {
        let response = test_router()
            .oneshot(
                Request::builder()
                    .uri("/composite/test")
                    .body(axum::body::Body::empty())
                    .expect("request must be valid"),
            )
            .await
            .expect("router must respond");

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(
            response.headers().get(X_OUTGOING_API_OVERHEAD),
            Some(&HeaderValue::from_static("3849"))
        );
    }

    #[tokio::test]
    async fn non_composite_http_response_has_no_latency_header() {
        let response = test_router()
            .oneshot(
                Request::builder()
                    .uri("/payments/test")
                    .body(axum::body::Body::empty())
                    .expect("request must be valid"),
            )
            .await
            .expect("router must respond");

        assert!(!response.headers().contains_key(X_OUTGOING_API_OVERHEAD));
    }
}
