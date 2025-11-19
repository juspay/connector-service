use crate::{configs::Config, utils::config_from_metadata};
use http::{Request, Response};
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tonic::body::Body;
use tower::{Layer, Service};

// Simple middleware layer for Tonic
#[derive(Clone)]
pub struct RequestExtensionsLayer {
    base_config: Config,
}

#[allow(clippy::new_without_default)]
impl RequestExtensionsLayer {
    pub fn new(base_config: Config) -> Self {
        Self { base_config }
    }
}

impl<S> Layer<S> for RequestExtensionsLayer {
    type Service = TonicRequestExtensionsMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TonicRequestExtensionsMiddleware {
            inner,
            base_config: self.base_config.clone(),
        }
    }
}
#[derive(Clone)]
pub struct TonicRequestExtensionsMiddleware<S> {
    inner: S,
    base_config: Config,
}

impl<S> Service<Request<Body>> for TonicRequestExtensionsMiddleware<S>
where
    S: Service<Request<Body>, Response = Response<Body>, Error = tonic::Status> + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = tonic::Status;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(|e| e)
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
                    match config_from_metadata(Some(override_str), self.base_config.clone()) {
                        Ok(cfg) => cfg,
                        Err(e) => {
                            let err = tonic::Status::internal(format!(
                                "Failed to create config from metadata: {e:?}"
                            ));
                            let fut = async move { Err(err) };
                            return Box::pin(fut);
                        }
                    };

                // Insert merged config into extensions
                req.extensions_mut().insert(new_config);
            }
            None => {
                // No override header - skip processing, service will use base config
                req.extensions_mut()
                    .insert(Arc::new(self.base_config.clone()));
            }
        }

        let future = self.inner.call(req);
        Box::pin(async move {
            let response = future.await?;
            Ok(response)
        })
    }
}
