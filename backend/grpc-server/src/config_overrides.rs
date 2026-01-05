use crate::{configs::Config, utils::merge_config_with_override};
use http::{Request, Response};
use std::{
    future::Future,
    pin::Pin,
    str::FromStr,
    sync::Arc,
    task::{Context, Poll},
};
use tonic::body::Body;
use tower::{Layer, Service};

// Simple middleware layer for Tonic
#[derive(Clone)]
pub struct RequestExtensionsLayer {
    base_config: Arc<Config>,
}

#[allow(clippy::new_without_default)]
impl RequestExtensionsLayer {
    pub fn new(base_config: Arc<Config>) -> Self {
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
    base_config: Arc<Config>,
}

impl<S> TonicRequestExtensionsMiddleware<S> {
    /// Resolves config dynamically using Superposition with connector + environment dimensions
    fn resolve_dynamic_config(
        &self,
        connector_str: &str,
        environment_str: Option<&str>,
    ) -> Result<Config, String> {
        // Parse connector enum
        let connector = domain_types::connector_types::ConnectorEnum::from_str(connector_str)
            .map_err(|e| format!("Invalid connector '{}': {}", connector_str, e))?;

        // Determine environment: use header if present, otherwise use base config's environment
        let environment = if let Some(env_str) = environment_str {
            common_utils::consts::Env::from_str(env_str)
                .map_err(|e| format!("Invalid environment '{}': {}", env_str, e))?
        } else {
            self.base_config.common.environment.clone()
        };

        // Resolve Superposition config for this specific connector + environment
        let resolved = crate::superposition_config::resolve_connector_specific_config(
            &connector,
            &environment,
        )
        .map_err(|e| format!("Superposition resolution failed: {:?}", e))?;

        // Build TOML string from resolved values
        let toml_string = crate::superposition_config::build_config_toml(&resolved)
            .map_err(|e| format!("Failed to build config TOML: {:?}", e))?;

        // Parse into Config struct
        let config: Config = toml::from_str(&toml_string)
            .map_err(|e| format!("Failed to parse resolved config: {:?}", e))?;

        Ok(config)
    }
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
        // Extract per-request context headers
        let connector_header = req
            .headers()
            .get(common_utils::consts::X_CONNECTOR_NAME)
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_owned());

        let environment_header = req
            .headers()
            .get(common_utils::consts::X_ENVIRONMENT)
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_owned());

        let config_override = req
            .headers()
            .get("x-config-override")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_owned());

        // Determine which config to use: Superposition dynamic, override, or base
        let config = match (connector_header, environment_header) {
            (Some(connector_str), env_opt) => {
                // Per-request Superposition resolution with connector dimension
                match self.resolve_dynamic_config(&connector_str, env_opt.as_deref()) {
                    Ok(resolved_config) => {
                        // Apply x-config-override on top if present
                        if let Some(override_str) = config_override {
                            match merge_config_with_override(Some(override_str), resolved_config) {
                                Ok(cfg) => cfg,
                                Err(e) => {
                                    let err = tonic::Status::internal(format!(
                                        "Failed to merge config with override: {e:?}"
                                    ));
                                    let fut = async move { Err(err) };
                                    return Box::pin(fut);
                                }
                            }
                        } else {
                            Arc::new(resolved_config)
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to resolve dynamic Superposition config: {:?}. Falling back to base config.",
                            e
                        );
                        // Fall back to base config on resolution error
                        if let Some(override_str) = config_override {
                            match merge_config_with_override(
                                Some(override_str),
                                (*self.base_config).clone(),
                            ) {
                                Ok(cfg) => cfg,
                                Err(e) => {
                                    let err = tonic::Status::internal(format!(
                                        "Failed to merge config with override: {e:?}"
                                    ));
                                    let fut = async move { Err(err) };
                                    return Box::pin(fut);
                                }
                            }
                        } else {
                            Arc::clone(&self.base_config)
                        }
                    }
                }
            }
            (None, _) => {
                // No connector header - use base config with optional override
                if let Some(override_str) = config_override {
                    match merge_config_with_override(Some(override_str), (*self.base_config).clone())
                    {
                        Ok(cfg) => cfg,
                        Err(e) => {
                            let err = tonic::Status::internal(format!(
                                "Failed to merge config with override: {e:?}"
                            ));
                            let fut = async move { Err(err) };
                            return Box::pin(fut);
                        }
                    }
                } else {
                    Arc::clone(&self.base_config)
                }
            }
        };

        // Insert resolved config into extensions
        req.extensions_mut().insert(config);

        let future = self.inner.call(req);
        Box::pin(async move {
            let response = future.await?;
            Ok(response)
        })
    }
}
