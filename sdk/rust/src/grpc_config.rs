use std::{collections::HashMap, fmt};

/// A credential string that never leaks through `Debug` or `Display`.
///
/// Use [`Secret::new`] to wrap a credential value and [`Secret::expose`] (crate-internal)
/// to extract it only when writing headers.
#[derive(Clone)]
pub struct Secret(String);

impl Secret {
    /// Wrap a credential string.
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// Extract the inner value — only used internally when writing gRPC metadata.
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}

/// Configuration for connecting to the hosted connector-service gRPC server.
///
/// The typed fields map directly to the gRPC metadata headers the server
/// expects on every call. Set once at client init — headers are injected
/// automatically on every request via [`GrpcClient`].
///
/// | Field         | Header          | Required |
/// |---------------|-----------------|----------|
/// | `connector`   | `x-connector`   | always   |
/// | `auth_type`   | `x-auth`        | always   |
/// | `api_key`     | `x-api-key`     | always   |
/// | `api_secret`  | `x-api-secret`  | optional |
/// | `key1`        | `x-key1`        | optional |
/// | `merchant_id` | `x-merchant-id` | optional |
/// | `tenant_id`   | `x-tenant-id`   | optional |
///
/// [`GrpcClient`]: crate::GrpcClient
pub struct GrpcConfig {
    /// Server endpoint, e.g. `"http://localhost:8000"` (plain) or
    /// `"https://grpc.example.com"` (TLS).
    pub endpoint: String,
    /// Which payment connector to route to, e.g. `"stripe"`, `"worldpay"`.
    pub connector: String,
    /// Auth mechanism the connector expects, e.g. `"header-key"`, `"signature-key"`.
    pub auth_type: String,
    /// Primary API key / access token for the connector.
    pub api_key: Secret,
    /// API secret — required by some connectors, `None` for others.
    pub api_secret: Option<Secret>,
    /// Additional credential (`x-key1`) — connector-specific.
    pub key1: Option<Secret>,
    /// Merchant identifier — required by some connectors.
    pub merchant_id: Option<String>,
    /// Tenant identifier — required by multi-tenant deployments.
    pub tenant_id: Option<String>,
}

impl GrpcConfig {
    pub(crate) fn into_headers(self) -> HashMap<String, String> {
        let mut h = HashMap::new();
        h.insert("x-connector".into(), self.connector);
        h.insert("x-auth".into(), self.auth_type);
        h.insert("x-api-key".into(), self.api_key.expose().to_string());
        if let Some(v) = self.api_secret {
            h.insert("x-api-secret".into(), v.expose().to_string());
        }
        if let Some(v) = self.key1 {
            h.insert("x-key1".into(), v.expose().to_string());
        }
        if let Some(v) = self.merchant_id {
            h.insert("x-merchant-id".into(), v);
        }
        if let Some(v) = self.tenant_id {
            h.insert("x-tenant-id".into(), v);
        }
        h
    }
}
