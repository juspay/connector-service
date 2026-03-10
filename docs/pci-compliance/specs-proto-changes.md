# Configuration Changes for Vault Integration

> Summary of configuration changes required to support PCI vault providers in UCS

---

## Overview

This document outlines the configuration changes needed to support two vault proxy patterns:
- **Network Proxy**: VGS, Evervault (transparent routing—UCS routes to proxy URL only)
- **Application Proxy**: Hyperswitch Vault, TokenEx, Basis Theory (UCS formats tokens for vault protocol)

**Important**: UCS uses **file-based configuration** (TOML), not protobuf-based configuration. Connectors are configured via the `Connectors` struct in `backend/domain_types/src/types.rs`.

---

## Global Vault Configuration

### Design Decision: Global Vault Mode

Instead of configuring vault settings per-connector, we use a **global vault configuration**. This simplifies the setup since merchants typically use one vault provider for all their payment processing.

```rust
// In backend/domain_types/src/types.rs - Add to Config struct
#[derive(Clone, Deserialize, Serialize, Debug, Default, PartialEq, config_patch_derive::Patch)]
pub struct Config {
    pub common: Common,
    pub server: Server,
    pub connectors: Connectors,
    // ... existing fields ...

    /// Global vault configuration (optional)
    /// When set, all connectors can use this vault for detokenization
    #[serde(default)]
    pub vault: Option<VaultConfig>,
}
```

---

## Vault Configuration Messages

### VaultConfig (Enum for Provider Selection)

```rust
// In backend/domain_types/src/types.rs
#[derive(Clone, Deserialize, Serialize, Debug, PartialEq, config_patch_derive::Patch)]
#[serde(tag = "provider", rename_all = "snake_case")]
pub enum VaultConfig {
    /// Network Proxy providers (zero code changes)
    Vgs(VgsConfig),
    Evervault(EvervaultConfig),

    /// Application Proxy providers (UCS formats tokens for vault protocol)
    HyperswitchVault(HyperswitchVaultConfig),
    TokenEx(TokenExConfig),
    BasisTheory(BasisTheoryConfig),
}
```

**Why enum with tag?**
- Ensures only one vault provider is active at a time
- Prevents misconfiguration (e.g., setting both VGS and TokenEx)
- Makes the configuration explicit and self-validating
- Serde's `tag = "provider"` creates clean TOML structure

---

## Network Proxy Configurations

### VgsConfig

```rust
// In backend/domain_types/src/types.rs
#[derive(Clone, Deserialize, Serialize, Debug, Default, PartialEq, config_patch_derive::Patch)]
pub struct VgsConfig {
    /// VGS tenant identifier
    /// Format: "tnt" + alphanumeric (e.g., "tntSANDBOX123")
    pub tenant_id: String,

    /// VGS environment
    /// Sandbox: Use for testing (tokens are non-production)
    /// Production: Use for live transactions
    pub environment: VgsEnvironment,

    /// Optional: CA certificate for TLS verification
    /// If not provided, UCS uses the default VGS CA cert
    pub ca_certificate: Option<String>,
}

#[derive(Clone, Copy, Deserialize, Serialize, Debug, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum VgsEnvironment {
    #[default]
    Sandbox,
    Production,
}
```

**TOML Configuration Example:**
```toml
[vault]
provider = "vgs"
tenant_id = "tntSANDBOX123"
environment = "sandbox"
```

**Key Fields Explained:**
- `tenant_id`: Your unique VGS tenant (found in VGS dashboard)
- `environment`: Sandbox for testing, Production for live
- `ca_certificate`: VGS uses a custom CA for sandbox; production uses standard CAs

---

### EvervaultConfig

```rust
// In backend/domain_types/src/types.rs
#[derive(Clone, Deserialize, Serialize, Debug, Default, PartialEq, config_patch_derive::Patch)]
pub struct EvervaultConfig {
    /// Evervault team identifier
    /// Format: "team_" + alphanumeric (e.g., "team_123abc")
    pub team_id: String,

    /// Evervault app identifier
    /// Format: "app_" + alphanumeric (e.g., "app_456def")
    pub app_id: String,

    /// Evervault API key for Relay authentication
    /// Keep this secret—treat like a password
    pub api_key: Secret<String>,
}
```

**TOML Configuration Example:**
```toml
[vault]
provider = "evervault"
team_id = "team_123abc"
app_id = "app_456def"
api_key = "${EVERVAULT_API_KEY}"  # Use environment variable
```

**Key Fields Explained:**
- `team_id`: Your Evervault team (top-level organization)
- `app_id`: Specific app within your team (isolated encryption boundary)
- `api_key`: Authenticates the Relay connection (different from client-side keys)

**Evervault vs VGS:**
- VGS uses **tokenization** (tokens stored in VGS vault)
- Evervault uses **client-side encryption** (data encrypted before reaching your server)

---

## Application Proxy Configurations

### HyperswitchVaultConfig

```rust
// In backend/domain_types/src/types.rs
#[derive(Clone, Deserialize, Serialize, Debug, Default, PartialEq, config_patch_derive::Patch)]
pub struct HyperswitchVaultConfig {
    /// Hyperswitch API key
    /// Format: "dev_xxx" (sandbox) or "prod_xxx" (production)
    pub api_key: Secret<String>,

    /// Hyperswitch Profile ID
    /// Identifies your merchant profile
    pub profile_id: String,

    /// Hyperswitch Proxy endpoint
    /// Default: "https://sandbox.hyperswitch.io/proxy" (sandbox)
    pub proxy_url: String,

    /// Environment
    pub environment: HyperswitchEnvironment,
}

#[derive(Clone, Copy, Deserialize, Serialize, Debug, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum HyperswitchEnvironment {
    #[default]
    Sandbox,
    Production,
}
```

**TOML Configuration Example:**
```toml
[vault]
provider = "hyperswitch_vault"
api_key = "${HYPERSWITCH_API_KEY}"
profile_id = "pro_xxxxxxxxxx"
proxy_url = "https://sandbox.hyperswitch.io/proxy"
environment = "sandbox"
```

**How it works:**
1. UCS constructs wrapped request with `destination_url`, `headers`, `request_body`
2. Request body contains `{{$variable}}` expressions (e.g., `{{$card_number}}`)
3. Hyperswitch Vault evaluates expressions and injects real card data
4. Forwarded to destination PSP with detokenized data
5. Response flows back through the same path

---

### TokenExConfig

```rust
// In backend/domain_types/src/types.rs
#[derive(Clone, Deserialize, Serialize, Debug, Default, PartialEq, config_patch_derive::Patch)]
pub struct TokenExConfig {
    /// TokenEx API key for TGAPI authentication
    pub api_key: Secret<String>,

    /// TokenEx ID (organization identifier)
    pub tokenex_id: String,

    /// TGAPI endpoint URL
    /// Sandbox: "https://tgapi-sandbox.tokenex.com"
    /// Production: "https://tgapi.tokenex.com"
    pub tgapi_url: String,

    /// Default token scheme
    #[serde(default)]
    pub default_token_scheme: TokenExTokenScheme,
}

#[derive(Clone, Copy, Deserialize, Serialize, Debug, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TokenExTokenScheme {
    #[default]
    TokenFour,    // 4242123456784242
    Guid,         // UUID
    SixTokenFour, // 424212xxxxxx4242
}
```

**TOML Configuration Example:**
```toml
[vault]
provider = "token_ex"
api_key = "${TOKENEX_API_KEY}"
tokenex_id = "your_tokenex_id"
tgapi_url = "https://tgapi-sandbox.tokenex.com"
default_token_scheme = "token_four"
```

**How it works:**
1. UCS sends request to `tgapi_url`
2. Headers: `TX-URL: {destination}`, `TX-Method: {method}`
3. Body contains `{token}` markers
4. TokenEx detokenizes and forwards to destination
5. Response flows back through TGAPI

---

### BasisTheoryConfig

```rust
// In backend/domain_types/src/types.rs
#[derive(Clone, Deserialize, Serialize, Debug, Default, PartialEq, config_patch_derive::Patch)]
pub struct BasisTheoryConfig {
    /// Basis Theory API key
    /// Permissions needed: token:read, proxy:read
    pub api_key: Secret<String>,

    /// Proxy endpoint URL
    /// Default: "https://api.basistheory.com/proxy"
    pub proxy_url: String,

    /// Optional: Default proxy ID
    /// If set, this proxy configuration is used for all requests
    pub proxy_id: Option<String>,
}
```

**TOML Configuration Example:**
```toml
[vault]
provider = "basis_theory"
api_key = "${BASISTHEORY_API_KEY}"
proxy_url = "https://api.basistheory.com/proxy"
# proxy_id = "optional_proxy_id"
```

**How it works:**
1. UCS sends request to `proxy_url` with `BT-PROXY-URL` header
2. Request body contains `{{ token.property }}` expressions
3. Basis Theory evaluates expressions and injects real values
4. Forwarded to destination with detokenized data

---

## Connector-Level Configuration

### ConnectorParams Updates

```rust
// In backend/domain_types/src/types.rs - Update ConnectorParams struct
#[derive(Clone, Deserialize, Serialize, Debug, Default, PartialEq, config_patch_derive::Patch)]
pub struct ConnectorParams {
    /// Base URL for the connector
    #[serde(default)]
    pub base_url: String,

    #[serde(default)]
    pub dispute_base_url: Option<String>,

    #[serde(default)]
    pub secondary_base_url: Option<String>,

    #[serde(default)]
    pub third_base_url: Option<String>,

    /// Use vault for this connector
    /// If true, UCS routes requests through the configured vault proxy
    /// If false (or unset), UCS sends tokens directly to the PSP
    #[serde(default)]
    pub use_vault: bool,

    /// Optional: Override vault configuration for this connector
    /// If set, this overrides the global vault config
    #[serde(default)]
    pub vault_override: Option<VaultConfig>,
}
```

**Why `use_vault`?**
- Allows gradual migration: some connectors use vault, others don't
- Backward compatible: existing configs work without changes (defaults to false)
- Explicit opt-in: merchant must consciously enable vault usage

**TOML Configuration Example:**
```toml
[connectors.stripe]
base_url = "https://api.stripe.com"
use_vault = true  # Enable vault for this connector

# Or with VGS Network Proxy, point base_url to VGS proxy:
[connectors.stripe]
base_url = "https://tntSANDBOX123.sandbox.verygoodproxy.com"
use_vault = true
```

---

## Application Proxy-Specific Configuration

### ApplicationProxyConfig

For Application Proxy providers, additional configuration may be needed to map token fields:

```rust
// In backend/domain_types/src/types.rs
#[derive(Clone, Deserialize, Serialize, Debug, Default, PartialEq, config_patch_derive::Patch)]
pub struct ApplicationProxyConfig {
    /// Token property mappings
    /// Maps standard fields to provider-specific token properties
    #[serde(default)]
    pub token_mappings: Vec<TokenPropertyMapping>,

    /// Profile ID (for Hyperswitch Vault)
    pub profile_id: Option<String>,
}

#[derive(Clone, Deserialize, Serialize, Debug, PartialEq, config_patch_derive::Patch)]
pub struct TokenPropertyMapping {
    /// Standard field name (used by UCS internally)
    /// e.g., "card_number", "exp_month", "exp_year", "cvv"
    pub standard_field: String,

    /// Provider-specific property path
    /// Hyperswitch Vault: "$card_number", "$card_exp_month"
    pub vault_property: String,
}
```

**TOML Configuration Example:**
```toml
[connectors.checkout]
base_url = "https://api.checkout.com"
use_vault = true

[connectors.checkout.application_proxy_config]
profile_id = "pro_xxxxxxxxxx"

[[connectors.checkout.application_proxy_config.token_mappings]]
standard_field = "card_number"
vault_property = "$card_number"

[[connectors.checkout.application_proxy_config.token_mappings]]
standard_field = "exp_month"
vault_property = "$card_exp_month"
```

**Why separate Application Proxy config?**
- Different providers use different property names and syntax
- Allows mapping UCS standard fields to provider-specific fields
- Enables multiple connectors with different token mappings

---

## Summary Table

| Provider | Proxy Pattern | Key Config Fields | Routing Method |
|----------|---------------|-------------------|----------------|
| **VGS** | Network | `tenant_id`, `environment` | URL-based proxy (UCS routes only) |
| **Evervault** | Network | `team_id`, `app_id`, `api_key` | HTTP CONNECT relay (UCS routes only) |
| **Hyperswitch Vault** | Application | `api_key`, `profile_id` | Wrapped request with `{{$variable}}` |
| **TokenEx** | Application | `api_key`, `tokenex_id` | Headers + `{token}` markers |
| **Basis Theory** | Application | `api_key`, `proxy_url` | `BT-PROXY-URL` header + `{{}}` expressions |

---

## Configuration Examples

Merchants can choose different combinations of PCI modes and vault providers based on their requirements. Below are the available options:

### Option 1: PCI-Enabled Mode (Direct PSP Connection)

Use this when you handle raw card data and have PCI DSS certification. No vault configuration required.

```toml
# config/development.toml
# No vault configuration - UCS connects directly to PSPs
[connectors.stripe]
base_url = "https://api.stripe.com"
# use_vault defaults to false

[connectors.adyen]
base_url = "https://api.adyen.com"
```

---

### Option 2: PCI-Disabled with Network Proxy (VGS)

Use VGS for zero-code transparent proxy. Point connector base_url to VGS proxy endpoint.

```toml
# config/development.toml
[vault]
provider = "vgs"
tenant_id = "tntSANDBOX123"
environment = "sandbox"

[connectors.stripe]
# Point to VGS proxy URL instead of Stripe directly
base_url = "https://tntSANDBOX123.sandbox.verygoodproxy.com"
use_vault = true

[connectors.checkout]
base_url = "https://tntSANDBOX123.sandbox.verygoodproxy.com"
use_vault = true
```

---

### Option 3: PCI-Disabled with Network Proxy (Evervault)

Use Evervault for client-side encryption with HTTP CONNECT relay.

```toml
# config/development.toml
[vault]
provider = "evervault"
team_id = "team_123abc"
app_id = "app_456def"
api_key = "${EVERVAULT_API_KEY}"

[connectors.stripe]
# Base URL remains the PSP's direct URL
base_url = "https://api.stripe.com"
use_vault = true
```

---

### Option 4: PCI-Disabled with Application Proxy (Hyperswitch Vault)

Use Hyperswitch Vault when you want UCS to construct wrapped requests with `{{$variable}}` expressions.

```toml
# config/development.toml
[vault]
provider = "hyperswitch_vault"
api_key = "${HYPERSWITCH_API_KEY}"
profile_id = "pro_xxxxxxxxxx"
proxy_url = "https://sandbox.hyperswitch.io/proxy"
environment = "sandbox"

[connectors.stripe]
base_url = "https://api.stripe.com"
use_vault = true

[connectors.checkout]
base_url = "https://api.checkout.com"
use_vault = true
```

---

### Option 5: PCI-Disabled with Application Proxy (TokenEx)

Use TokenEx for header-driven routing with `{token}` markers.

```toml
# config/development.toml
[vault]
provider = "token_ex"
api_key = "${TOKENEX_API_KEY}"
tokenex_id = "your_tokenex_id"
tgapi_url = "https://tgapi-sandbox.tokenex.com"
default_token_scheme = "token_four"

[connectors.stripe]
base_url = "https://api.stripe.com"
use_vault = true
```

---

### Option 6: PCI-Disabled with Application Proxy (Basis Theory)

Use Basis Theory for header-driven routing with `{{ token.property }}` expressions.

```toml
# config/development.toml
[vault]
provider = "basis_theory"
api_key = "${BASISTHEORY_API_KEY}"
proxy_url = "https://api.basistheory.com/proxy"

[connectors.stripe]
base_url = "https://api.stripe.com"
use_vault = true
```

---

### Option 7: Mixed Mode (Different Connectors, Different Modes)

Some connectors can use vault while others connect directly. Useful for gradual adoption or specific connector requirements.

```toml
# config/development.toml
[vault]
provider = "vgs"
tenant_id = "tntSANDBOX123"
environment = "sandbox"

# Stripe uses VGS vault
[connectors.stripe]
base_url = "https://tntSANDBOX123.sandbox.verygoodproxy.com"
use_vault = true

# Adyen connects directly (PCI-Enabled mode for this connector)
[connectors.adyen]
base_url = "https://api.adyen.com"
use_vault = false

# Checkout also uses VGS vault
[connectors.checkout]
base_url = "https://tntSANDBOX123.sandbox.verygoodproxy.com"
use_vault = true
```

---

## Security Considerations

### Sensitive Fields

All API keys and tokens use `Secret<String>` for masking:

```rust
// In backend/domain_types/src/types.rs
use hyperswitch_masking::Secret;

pub struct BasisTheoryConfig {
    /// Sensitive - authentication credential
    pub api_key: Secret<String>,

    /// Not sensitive - public URL
    pub proxy_url: String,
}
```

### Environment Variables

Sensitive values should use environment variable substitution:

```toml
[vault]
provider = "hyperswitch_vault"
api_key = "${HYPERSWITCH_API_KEY}"  # Loaded from env var
profile_id = "pro_xxxxxxxxxx"
```

The UCS configuration loader (in `ucs_env/src/configs.rs`) supports environment variables with the `CS__` prefix:

```bash
# Environment variable format (case-insensitive)
export CS__VAULT__PROVIDER="vgs"
export CS__VAULT__TENANT_ID="tntSANDBOX123"
export CS__VAULT__ENVIRONMENT="sandbox"
export CS__CONNECTORS__STRIPE__USE_VAULT="true"
```

---

## Implementation Checklist

- [ ] Add `VaultConfig` enum to `backend/domain_types/src/types.rs`
- [ ] Add vault provider configs (VgsConfig, EvervaultConfig, etc.)
- [ ] Update `ConnectorParams` with `use_vault` and `vault_override`
- [ ] Add `ApplicationProxyConfig` for token field mappings
- [ ] Update `Config` struct to include `vault: Option<VaultConfig>`
- [ ] Implement vault header extraction in request handling
- [ ] Add validation for vault configuration

---

## Related Files

- `backend/domain_types/src/types.rs` - Configuration structs
- `backend/ucs_env/src/configs.rs` - Configuration loading
- `backend/domain_types/src/connector_types.rs` - Connector-related types
- `docs/pci-compliance/network-proxy.md` - Network Proxy documentation
- `docs/pci-compliance/application-proxy.md` - Application Proxy documentation

---

_Questions? See the individual proxy pattern docs for provider-specific details._
