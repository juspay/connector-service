# Vault Configuration Implementation Spec

> Configuration changes to support PCI vault providers (VGS, Evervault, Hyperswitch Vault, TokenEx, Basis Theory)

---

## Overview

UCS uses **file-based configuration** (TOML). This spec defines the Rust types and implementation plan for vault support.

**Two Proxy Patterns:**
- **Network Proxy** (VGS, Evervault): UCS routes to proxy URL only
- **Application Proxy** (Hyperswitch Vault, TokenEx, Basis Theory): UCS formats tokens for vault protocol

---

## Required Type Changes

### 1. VaultConfig Enum (Global)

**File:** `backend/domain_types/src/types.rs`

```rust
#[derive(Clone, Deserialize, Serialize, Debug, PartialEq, config_patch_derive::Patch)]
#[serde(tag = "provider", rename_all = "snake_case")]
pub enum VaultConfig {
    Vgs(VgsConfig),
    Evervault(EvervaultConfig),
    HyperswitchVault(HyperswitchVaultConfig),
    TokenEx(TokenExConfig),
    BasisTheory(BasisTheoryConfig),
}
```

**Why:** Ensures only one vault provider is active at a time. Uses Serde's `tag = "provider"` for clean TOML syntax: `provider = "vgs"`. Follows existing UCS pattern for config enums.

---

### 2. Provider Config Structs

```rust
```rust
// VGS Network Proxy
#[derive(Clone, Deserialize, Serialize, Debug, Default, PartialEq, config_patch_derive::Patch)]
pub struct VgsConfig {
    pub tenant_id: String,          // VGS tenant identifier (tntXXX)
    pub environment: VgsEnvironment,// Sandbox vs Production
    pub ca_certificate: Option<String>, // Optional custom CA cert
}

#[derive(Clone, Copy, Deserialize, Serialize, Debug, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum VgsEnvironment { #[default] Sandbox, Production }

// Evervault Network Proxy
#[derive(Clone, Deserialize, Serialize, Debug, Default, PartialEq, config_patch_derive::Patch)]
pub struct EvervaultConfig {
    pub team_id: String,            // Evervault team identifier
    pub app_id: String,             // App identifier (isolated keys)
    pub api_key: Secret<String>,    // Relay authentication key
}

// Hyperswitch Vault Application Proxy
#[derive(Clone, Deserialize, Serialize, Debug, Default, PartialEq, config_patch_derive::Patch)]
pub struct HyperswitchVaultConfig {
    pub api_key: Secret<String>,
    pub profile_id: String,         // Merchant profile identifier
    pub proxy_url: String,          // Hyperswitch proxy endpoint
    pub environment: HyperswitchEnvironment,
}

#[derive(Clone, Copy, Deserialize, Serialize, Debug, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum HyperswitchEnvironment { #[default] Sandbox, Production }

// TokenEx Application Proxy
#[derive(Clone, Deserialize, Serialize, Debug, Default, PartialEq, config_patch_derive::Patch)]
pub struct TokenExConfig {
    pub api_key: Secret<String>,
    pub tokenex_id: String,         // Organization identifier
    pub tgapi_url: String,          // TGAPI endpoint
    #[serde(default)]
    pub default_token_scheme: TokenExTokenScheme,
}

#[derive(Clone, Copy, Deserialize, Serialize, Debug, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TokenExTokenScheme {
    #[default] TokenFour, Guid, SixTokenFour
}

// Basis Theory Application Proxy
#[derive(Clone, Deserialize, Serialize, Debug, Default, PartialEq, config_patch_derive::Patch)]
pub struct BasisTheoryConfig {
    pub api_key: Secret<String>,
    pub proxy_url: String,          // Basis Theory proxy endpoint
    pub proxy_id: Option<String>,   // Optional pre-configured proxy
}
```

**Why:** Each provider requires different auth credentials and endpoints. `Secret<String>` masks sensitive values in logs. `config_patch_derive::Patch` enables hot-reloading of config. Environments use `#[serde(default)]` for backward compatibility.

### 3. Update ConnectorParams

**File:** `backend/domain_types/src/types.rs`

```rust
#[derive(Clone, Deserialize, Serialize, Debug, Default, PartialEq, config_patch_derive::Patch)]
pub struct ConnectorParams {
    #[serde(default)]
    pub base_url: String,
    #[serde(default)]
    pub dispute_base_url: Option<String>,
    #[serde(default)]
    pub secondary_base_url: Option<String>,
    #[serde(default)]
    pub third_base_url: Option<String>,

    /// When true, routes requests through the global vault proxy
    #[serde(default)]
    pub enable_vault_proxy: bool,

    /// Optional: Use a different vault than the global one
    #[serde(default)]
    pub vault_proxy_override: Option<VaultConfig>,
}
```

**Why:** `enable_vault_proxy` (defaults to `false`) ensures backward compatibility—existing configs work without changes. `vault_proxy_override` allows per-connector vault customization (e.g., Stripe uses VGS, Checkout uses Hyperswitch Vault). Naming is explicit to avoid confusion with connector-specific vaults.

### 4. Update Main Config

**File:** `backend/ucs_env/src/configs.rs`

```rust
#[derive(Clone, Deserialize, Serialize, Debug, Default, PartialEq, config_patch_derive::Patch)]
pub struct Config {
    pub common: Common,
    pub server: Server,
    pub connectors: Connectors,
    #[serde(default)]
    pub vault: Option<VaultConfig>,  // NEW: Global vault config
    // ... existing fields ...
}
```

**Why:** `Option<VaultConfig>` makes vault optional—merchants without vault needs have no config changes. Uses `#[serde(default)]` so missing `[vault]` section doesn't error. Placed alongside `connectors` since vault is a cross-cutting concern for all connectors.

---

## Configuration Examples

### TOML: PCI-Enabled (No Vault)
```toml
[connectors.stripe]
base_url = "https://api.stripe.com"
# enable_vault_proxy defaults to false
```

### TOML: Network Proxy (VGS)
```toml
[vault]
provider = "vgs"
tenant_id = "tntSANDBOX123"
environment = "sandbox"

[connectors.stripe]
base_url = "https://tntSANDBOX123.sandbox.verygoodproxy.com"
enable_vault_proxy = true
```

### TOML: Application Proxy (Hyperswitch Vault)
```toml
[vault]
provider = "hyperswitch_vault"
api_key = "${HYPERSWITCH_API_KEY}"
profile_id = "pro_xxxxxxxxxx"
proxy_url = "https://sandbox.hyperswitch.io/proxy"

[connectors.stripe]
base_url = "https://api.stripe.com"
enable_vault_proxy = true
```

### TOML: Per-Connector Vault Override
```toml
[vault]
provider = "vgs"
tenant_id = "tntSANDBOX123"

[connectors.stripe]
base_url = "https://api.stripe.com"
enable_vault_proxy = true
vault_proxy_override = { provider = "hyperswitch_vault", api_key = "...", profile_id = "...", proxy_url = "...", environment = "sandbox" }
```

---

## Implementation Plan

### Phase 1: Core Types (2-3 hours)
**Files:** `backend/domain_types/src/types.rs`

1. Add `VaultConfig` enum with all provider variants
2. Add provider config structs (`VgsConfig`, `EvervaultConfig`, etc.)
3. Add environment enums (`VgsEnvironment`, `HyperswitchEnvironment`, `TokenExTokenScheme`)
4. Update `ConnectorParams` with `enable_vault_proxy` and `vault_proxy_override`

### Phase 2: Config Integration (30 min)
**Files:** `backend/ucs_env/src/configs.rs`

1. Add `vault: Option<VaultConfig>` to main `Config` struct
2. Ensure config validation handles optional vault

### Phase 3: Vault Resolution Logic (1-2 hours)
**Files:** `backend/domain_types/src/types.rs`

1. Add helper method to resolve vault for a connector:
   ```rust
   impl Connectors {
       pub fn resolve_vault(&self, connector_name: &str) -> Option<&VaultConfig> {
           // Check vault_proxy_override first, then fall back to global
       }
   }
   ```

### Phase 4: HTTP Client Integration (3-4 hours)
**Files:** TBD (likely `backend/connector_integration/` or `backend/external_services/`)

1. Create vault-aware HTTP client wrapper
2. For Network Proxy: Transform URLs (VGS) or use HTTP CONNECT (Evervault)
3. For Application Proxy: Transform request body/headers

### Phase 5: Validation & Tests (2-3 hours)
**Files:** Various

1. Add config validation on startup
2. Unit tests for config deserialization
3. Integration tests for vault routing

---

## Provider Summary

| Provider | Pattern | Key Fields | Routing |
|----------|---------|------------|---------|
| **VGS** | Network | `tenant_id`, `environment` | URL-based proxy |
| **Evervault** | Network | `team_id`, `app_id`, `api_key` | HTTP CONNECT relay |
| **Hyperswitch Vault** | Application | `api_key`, `profile_id` | Wrapped request with `{{$variable}}` |
| **TokenEx** | Application | `api_key`, `tokenex_id` | Headers + `{token}` markers |
| **Basis Theory** | Application | `api_key`, `proxy_url` | `BT-PROXY-URL` header + `{{}}` |

---

## Files to Update

| File | Change |
|------|--------|
| `backend/domain_types/src/types.rs` | Add `VaultConfig`, provider configs, update `ConnectorParams` |
| `backend/ucs_env/src/configs.rs` | Add `vault` field to main `Config` |
| `docs/pci-compliance/*.md` | Update all examples to use `enable_vault_proxy` |

---

## Checklist

- [ ] Phase 1: Core types added
- [ ] Phase 2: Config integration complete
- [ ] Phase 3: Vault resolution logic
- [ ] Phase 4: HTTP client integration
- [ ] Phase 5: Validation and tests
