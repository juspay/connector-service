use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use common_utils::{consts::X_OUTGOING_API_OVERHEAD, request_metrics::ConnectorLatencyTracker};
use http::{Request, Response};
use tonic::body::Body;
use tower::{Layer, Service};

#[derive(Clone, Copy, Default)]
pub struct CompositeLatencyLayer;

impl<S> Layer<S> for CompositeLatencyLayer {
    type Service = CompositeLatencyService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        CompositeLatencyService { inner }
    }
}

#[derive(Clone)]
pub struct CompositeLatencyService<S> {
    inner: S,
}

impl<S> Service<Request<Body>> for CompositeLatencyService<S>
where
    S: Service<Request<Body>, Response = Response<Body>, Error = tonic::Status> + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request<Body>) -> Self::Future {
        if !is_composite_grpc_path(request.uri().path()) {
            let future = self.inner.call(request);
            return Box::pin(future);
        }

        let tracker = ConnectorLatencyTracker::default();
        request.extensions_mut().insert(tracker.clone());
        let future = self.inner.call(request);

        Box::pin(async move {
            let outgoing_latency_ms = tracker.outgoing_latency_millis().to_string();
            match future.await {
                Ok(mut response) => {
                    if let Ok(value) = outgoing_latency_ms.parse() {
                        response
                            .headers_mut()
                            .insert(X_OUTGOING_API_OVERHEAD, value);
                    }
                    Ok(response)
                }
                Err(mut status) => {
                    if let Ok(value) = outgoing_latency_ms.parse() {
                        status.metadata_mut().insert(X_OUTGOING_API_OVERHEAD, value);
                    }
                    Err(status)
                }
            }
        })
    }
}

fn is_composite_grpc_path(path: &str) -> bool {
    path.split('/')
        .nth(1)
        .and_then(|service| service.rsplit('.').next())
        .is_some_and(|service| service.starts_with("Composite"))
}

#[cfg(test)]
mod tests {
    use common_utils::{consts::X_OUTGOING_API_OVERHEAD, request_metrics::ConnectorLatencyTracker};
    use http::{Request, Response};
    use tonic::body::Body;
    use tower::{service_fn, ServiceExt};

    use super::{is_composite_grpc_path, CompositeLatencyService};

    #[test]
    fn identifies_only_composite_services() {
        assert!(is_composite_grpc_path(
            "/types.CompositePaymentService/Authorize"
        ));
        assert!(is_composite_grpc_path(
            "/types.CompositeFraudAndRiskManagementService/PreRiskCheck"
        ));
        assert!(!is_composite_grpc_path("/types.PaymentService/Authorize"));
    }

    #[tokio::test]
    async fn composite_response_contains_exact_outgoing_latency_sum() {
        let service = CompositeLatencyService {
            inner: service_fn(|request: Request<Body>| async move {
                let tracker = request
                    .extensions()
                    .get::<ConnectorLatencyTracker>()
                    .expect("composite requests must contain a latency tracker");
                tracker.add_outgoing_latency_millis(1875);
                tracker.add_outgoing_latency_millis(1974);
                Ok::<_, tonic::Status>(Response::new(Body::empty()))
            }),
        };

        let response = service
            .oneshot(
                Request::builder()
                    .uri("/types.CompositePaymentService/Authorize")
                    .body(Body::empty())
                    .expect("request must be valid"),
            )
            .await
            .expect("service must succeed");

        assert_eq!(
            response.headers().get(X_OUTGOING_API_OVERHEAD),
            Some(&http::HeaderValue::from_static("3849"))
        );
    }

    #[tokio::test]
    async fn non_composite_response_has_no_tracker_or_latency_header() {
        let service = CompositeLatencyService {
            inner: service_fn(|request: Request<Body>| async move {
                assert!(request
                    .extensions()
                    .get::<ConnectorLatencyTracker>()
                    .is_none());
                Ok::<_, tonic::Status>(Response::new(Body::empty()))
            }),
        };

        let response = service
            .oneshot(
                Request::builder()
                    .uri("/types.PaymentService/Authorize")
                    .body(Body::empty())
                    .expect("request must be valid"),
            )
            .await
            .expect("service must succeed");

        assert!(!response.headers().contains_key(X_OUTGOING_API_OVERHEAD));
    }

    #[tokio::test]
    async fn composite_error_contains_outgoing_latency_metadata() {
        let service = CompositeLatencyService {
            inner: service_fn(|request: Request<Body>| async move {
                request
                    .extensions()
                    .get::<ConnectorLatencyTracker>()
                    .expect("composite requests must contain a latency tracker")
                    .add_outgoing_latency_millis(1875);
                Err::<Response<Body>, _>(tonic::Status::internal("connector failed"))
            }),
        };

        let status = service
            .oneshot(
                Request::builder()
                    .uri("/types.CompositePaymentService/Authorize")
                    .body(Body::empty())
                    .expect("request must be valid"),
            )
            .await
            .expect_err("service must return its error");

        assert_eq!(
            status.metadata().get(X_OUTGOING_API_OVERHEAD),
            Some(&tonic::metadata::MetadataValue::from_static("1875"))
        );
    }
}
