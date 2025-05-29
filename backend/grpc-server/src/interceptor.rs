use std::{
    pin::Pin,
    task::{Context, Poll},
};

use futures::future::BoxFuture;
use tonic::{body::BoxBody, transport::Body};
use tower::{Layer, Service};
use uuid::Uuid;

use crate::logger;

#[derive(Clone)]
pub struct GrpcLoggingLayer;

impl<S> Layer<S> for GrpcLoggingLayer {
    type Service = GrpcLoggingService<S>;

    fn layer(&self, service: S) -> Self::Service {
        GrpcLoggingService { inner: service }
    }
}

#[derive(Clone)]
pub struct GrpcLoggingService<S> {
    inner: S,
}

impl<S> Service<hyper::Request<Body>> for GrpcLoggingService<S>
where
    S: Service<hyper::Request<Body>, Response = hyper::Response<BoxBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>> + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: hyper::Request<Body>) -> Self::Future {
        let mut inner = self.inner.clone();
        let start_time = std::time::Instant::now();

        Box::pin(async move {
            let request_id = Uuid::new_v4().to_string();
            let method = req.uri().path();
            let headers = req.headers().clone();

            logger::info!(
                request_id = %request_id,
                method = %method,
                user_agent = ?headers.get("user-agent"),
                content_type = ?headers.get("content-type"),
                "gRPC request received"
            );

            let response = inner.call(req).await;

            let duration = start_time.elapsed();

            match &response {
                Ok(res) => {
                    let status = res.status();
                    logger::info!(
                        request_id = %request_id,
                        method = %method,
                        status = %status,
                        duration_ms = %duration.as_millis(),
                        "gRPC request completed"
                    );
                }
                Err(_) => {
                    logger::error!(
                        request_id = %request_id,
                        method = %method,
                        duration_ms = %duration.as_millis(),
                        "gRPC request failed"
                    );
                }
            }

            response
        })
    }
}