use crate::{
    // configs::Config,
    utils::merge_config_with_override,
};
use axum::{body::Body, extract::Request, http::StatusCode, response::Response};
use common_crate::configs::Config;
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tower::{Layer, Service};

fn create_error_response(message: &str) -> Response<Body> {
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .body(Body::from(message.to_string()))
        .unwrap_or_else(|_| {
            // Single fallback - no nested unwrap needed
            let mut response = Response::new(Body::from("Internal server error"));
            *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            response
        })
}

// HTTP middleware layer for adding config to request extensions
#[derive(Clone)]
pub struct HttpRequestExtensionsLayer {
    base_config: Arc<Config>,
}

#[allow(clippy::new_without_default)]
impl HttpRequestExtensionsLayer {
    pub fn new(base_config: Arc<Config>) -> Self {
        Self { base_config }
    }
}

impl<S> Layer<S> for HttpRequestExtensionsLayer {
    type Service = HttpRequestExtensionsMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        HttpRequestExtensionsMiddleware {
            inner,
            base_config: self.base_config.clone(),
        }
    }
}

#[derive(Clone)]
pub struct HttpRequestExtensionsMiddleware<S> {
    inner: S,
    base_config: Arc<Config>,
}

impl<S> Service<Request<Body>> for HttpRequestExtensionsMiddleware<S>
where
    S: Service<Request<Body>, Response = Response, Error = std::convert::Infallible>
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        // Extract x-config-override header first
        let config_override = req
            .headers()
            .get("x-config-override")
            .and_then(|h| h.to_str().map(|s| s.to_owned()).ok());

        // Only process config if override header is present
        match config_override {
            Some(override_str) => {
                // Merge override with default
                let new_config =
                    match merge_config_with_override(override_str, (*self.base_config).clone()) {
                        Ok(cfg) => cfg,
                        Err(e) => {
                            let error_response = create_error_response(&format!(
                                "Failed to merge config with override config: {e:?}"
                            ));
                            let fut = async move { Ok(error_response) };
                            return Box::pin(fut);
                        }
                    };

                // Insert merged config into extensions
                req.extensions_mut().insert(new_config);
            }
            None => {
                // No override header - insert base config
                req.extensions_mut().insert(Arc::clone(&self.base_config));
            }
        }

        let future = self.inner.call(req);
        Box::pin(async move {
            let response = future.await?;
            Ok(response)
        })
    }
}
