use crate::{configs::Config, utils::config_from_metadata};
use http::{Request, Response};
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use tonic::body::Body;
use tower::{Layer, Service};

// Simple middleware layer for Tonic
#[derive(Clone)]
pub struct RequestExtensionsLayer;

#[allow(clippy::new_without_default)]
impl RequestExtensionsLayer {
    pub fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for RequestExtensionsLayer {
    type Service = TonicRequestExtensionsMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TonicRequestExtensionsMiddleware { inner }
    }
}

// Middleware service specifically for Tonic
#[derive(Clone)]
pub struct TonicRequestExtensionsMiddleware<S> {
    inner: S,
}

impl<S> Service<Request<Body>> for TonicRequestExtensionsMiddleware<S>
where
    S: Service<Request<Body>, Response = Response<Body>> + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    #[allow(clippy::expect_used)]
    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        let default_config = Config::new().expect("Failed to load default config");
        // Extract x-config-override header
        let config_override = req
            .headers()
            .get("x-config-override")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_string();

        let new_config = config_from_metadata(config_override, default_config.clone())
            .expect("Failed to create config from metadata");

        req.extensions_mut().insert(new_config);
        let future = self.inner.call(req);
        Box::pin(async move {
            let response = future.await?;
            Ok(response)
        })
    }
}
