use std::collections::HashMap;

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
    pub api_key: String,
    /// API secret — required by some connectors, `None` for others.
    pub api_secret: Option<String>,
    /// Additional credential (`x-key1`) — connector-specific.
    pub key1: Option<String>,
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
        h.insert("x-api-key".into(), self.api_key);
        if let Some(v) = self.api_secret  { h.insert("x-api-secret".into(), v); }
        if let Some(v) = self.key1        { h.insert("x-key1".into(), v); }
        if let Some(v) = self.merchant_id { h.insert("x-merchant-id".into(), v); }
        if let Some(v) = self.tenant_id   { h.insert("x-tenant-id".into(), v); }
        h
    }
}
