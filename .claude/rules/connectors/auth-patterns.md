---
paths:
  - backend/connector-integration/src/connectors/**/*.rs
---
# Authentication Patterns

Learned authentication patterns from successful connector integrations.

## Pattern: OAuth with CreateAccessToken

**When to Use**: API requires OAuth2 token authentication, mentions "access token", "bearer token", or "OAuth"

### Recognition Signals
- "Bearer" in Authorization header examples
- Token endpoint exists (e.g., `/oauth/token`, `/auth/token`)
- Client ID + Secret credential pairs

### Implementation
```rust
// 1. CreateAccessToken MUST be FIRST in api array
macros::create_all_prerequisites!(
    api: [
        (flow: CreateAccessToken, ...), // FIRST!
        (flow: Authorize, ...),
    ],
);

// 2. Auth type extracts OAuth credentials
pub struct ConnectorAuthType {
    pub client_id: Secret<String>,
    pub client_secret: Secret<String>,
}

// 3. Other flows use Bearer token
fn build_headers(&self, req: &...) -> Result<Vec<(String, String)>, ...> {
    let token = req.resource_common_data.get_access_token()?;
    Ok(vec![("Authorization", format!("Bearer {}", token))])
}
```

---

## Pattern: HeaderKey Authorization

**When to Use**: API uses static API key in request header, `Authorization: Bearer <key>` or `X-Api-Key: <key>`

### Implementation
```rust
pub struct ConnectorAuthType {
    pub api_key: Secret<String>,
}

fn get_headers(&self, req: &...) -> Result<Vec<(String, String)>, ...> {
    let auth = ConnectorAuthType::try_from(&req.access_token)?;
    Ok(vec![
        ("Authorization", format!("Bearer {}", auth.api_key.peek())),
        ("Content-Type", "application/json".to_string()),
    ])
}
```

---

## Pattern: BodyKey Authorization

**When to Use**: API requires credentials in request body (e.g., `merchantId`, `apiKey` in JSON payload)

### Implementation
```rust
#[derive(Serialize)]
pub struct ConnectorRequest {
    pub merchant_id: Secret<String>,
    pub api_key: Secret<String>,
    // ... payment fields
}

impl TryFrom<&RouterDataV2<...>> for ConnectorRequest {
    fn try_from(router_data: &RouterDataV2<...>) -> Result<Self, ...> {
        let auth = ConnectorAuthType::try_from(&router_data.access_token)?;
        Ok(Self {
            merchant_id: auth.merchant_id.clone(),
            api_key: auth.api_key.clone(),
            // ... other fields from router_data
        })
    }
}
```

---

## gRPC Transport: How Auth Reaches the Server

Connector credentials are passed via **gRPC metadata headers only** (not in the request payload).

### Typed path (preferred)
```
x-connector-auth: {"auth_type":{"Stripe":{"api_key":"sk_test_..."}}}
```
JSON-serialized `ConnectorAuth` proto message. Uses PascalCase variant names. Parsed by `extract_connector_auth_from_header()` in `utils.rs`.

### Legacy path (fallback)
```
x-auth: header-key
x-api-key: sk_test_...
```
Generic headers parsed by `auth_from_metadata()`. Used when `x-connector-auth` is absent.

Both paths produce `ConnectorSpecificAuth`, which connector code consumes via `TryFrom<&ConnectorSpecificAuth>`.

> **Note**: The `connector_auth` field was removed from all proto request messages. Auth is never in the payload.

---

## Quick Reference

| Auth Type | CreateAccessToken | Token in Header | Credentials Location |
|-----------|-------------------|-----------------|---------------------|
| OAuth | Yes (FIRST) | Bearer token | From AccessTokenResponseData |
| HeaderKey | No | API key | Directly from AccessToken |
| BodyKey | No | Often none | In request body |
| SignatureKey | No | Signature | Computed from secret |
