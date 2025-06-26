use tower::{Layer, Service};
use std::{
    collections::HashMap, default, future::Future, pin::Pin, task::{Context, Poll}
};
use crate::{configs::Config, utils::config_from_metadata};
use http::{Request, Response};
use tonic::body::Body;
use domain_types::errors::{ApiError, ApplicationErrorResponse};
use error_stack::Report;
use serde_json::Value;

// Simple middleware layer for Tonic
#[derive(Clone)]
pub struct RequestExtensionsLayer;

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

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        let default_config = Config::new().expect("Failed to load configuration");
        // Extract x-config-override header
        let config_override = req.headers()
            .get("x-config-override")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_string();

        let new_config = config_from_metadata(config_override, default_config.clone())
            .expect("Failed to create config from metadata");
        // tracing::info!("new_config: {:?}", new_config);

    // let new_config_value = match serde_json::to_value(&new_config) {
    //     Ok(val) => val,
    //     Err(e) => {
    //         // You may want to log the error or handle it appropriately
    //         tracing::error!("Cannot serialize base config to JSON: {}", e);
    //         // Optionally, you can return an error response here, or handle as needed
    //         // For now, just return early with a default value or panic
    //         // panic!("Cannot serialize base config to JSON: {}", e);
    //         // Or return a default value:
    //         Value::Null
    //     }
    // };

        // // Create metadata map
        // let mut metadata = HashMap::new();
        // metadata.insert("x-config-override".to_string(), config_override);
        // metadata.insert("method".to_string(), req.method().to_string());
        // metadata.insert("path".to_string(), req.uri().path().to_string());
        
        // // Insert metadata into request extensions
        // req.extensions_mut().insert(metadata);
        // tracing::info!("config_override: {}", config_override);
        tracing::info!("New config value: {}", new_config);
        let config_extensions = get_config_extensions(new_config);

        req.extensions_mut().insert(config_extensions);
        let future = self.inner.call(req);
        Box::pin(async move {
            let response = future.await?;
            Ok(response)
        })
    }
}      
pub fn get_config_extensions(config: Value) -> HashMap<String, String> {
    let mut extensions = HashMap::new();
    extensions.insert("config".to_string(), config.to_string());
    // Add other config fields as needed
    extensions
}  