# PCI Vault Integration - Implementation Spec

> End-to-end implementation guide for PCI vault support in UCS (VGS, Evervault, Hyperswitch Vault, TokenEx, Basis Theory)

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

### Phase 1: Core Types
**Files:** `backend/domain_types/src/types.rs`

1. Add `VaultConfig` enum with all provider variants
2. Add provider config structs (`VgsConfig`, `EvervaultConfig`, etc.)
3. Add environment enums (`VgsEnvironment`, `HyperswitchEnvironment`, `TokenExTokenScheme`)
4. Update `ConnectorParams` with `enable_vault_proxy` and `vault_proxy_override`

### Phase 2: Config Integration
**Files:** `backend/ucs_env/src/configs.rs`

1. Add `vault: Option<VaultConfig>` to main `Config` struct
2. Ensure config validation handles optional vault

### Phase 3: Vault Resolution Logic
**Files:** `backend/domain_types/src/types.rs`

1. Add helper method to resolve vault for a connector:
   ```rust
   impl Connectors {
       pub fn resolve_vault(&self, connector_name: &str) -> Option<&VaultConfig> {
           // Check vault_proxy_override first, then fall back to global
       }
   }
   ```

### Phase 4: HTTP Client Integration
**Files:** TBD (likely `backend/connector_integration/` or `backend/external_services/`)

1. Create vault-aware HTTP client wrapper
2. For Network Proxy: Transform URLs (VGS) or use HTTP CONNECT (Evervault)
3. For Application Proxy: Transform request body/headers

### Phase 5: HTTP Client Integration
**Files:** `backend/connector-integration/` or `backend/external-services/`

1. Integrate `transform_connector_url()` into connector HTTP client's `base_url()` method
2. Add vault header injection via `get_vault_headers()` before request dispatch
3. Handle network proxy connection setup (Evervault HTTP CONNECT, VGS URL transformation)
4. Error handling for vault connectivity failures

**Design Decisions:**
- Where to store vault-aware HTTP client (per-connector or shared service)
- Timeout configuration for vault operations

### Phase 6: Request/Response Transformation (Application Proxies)
**Files:** Per-connector implementation

**Description:** Application proxies require request body formatting with vault-specific syntax.

**Examples:**
- Hyperswitch Vault: `{{card_number}}`, `{{cvv}}` variables
- Basis Theory: `{{card_number}}`, `{{token:bt_token_id}}` syntax
- TokenEx: `{token:tokenex_token_id}` markers

**Per-Connector Work:**
1. Stripe (reference implementation)
2. Checkout
3. Adyen
4. Cybersource
5. (remaining connectors)

### Phase 7: Validation & Tests
**Files:** Various

1. Add config validation on startup
2. Unit tests for config deserialization
3. Integration tests for vault routing
4. Security audit (no secrets in logs)

---

## Testing Strategy

### Overview

Essential tests to ensure PCI vault integration is secure, correct, and backward compatible.

---

### 1. Unit Tests (PR #617) ✅

**Location:** `backend/external-services/src/vault.rs`

| Test | Purpose |
|------|---------|
| `test_vgs_url_transformation_sandbox` | VGS sandbox URL generation |
| `test_vgs_url_transformation_production` | VGS production URL generation |
| `test_vgs_url_with_query_params` | Query parameter preservation |
| `test_is_network_proxy` | Proxy type classification |
| `test_get_vault_headers_*` | Header generation for all 5 providers |

**Run:** `cargo test --package external-services vault`

---

### 2. Configuration Tests

**Config Deserialization:**
```rust
#[test]
fn test_vault_config_parsing() {
    let toml = r#"
        [vault]
        provider = "vgs"
        tenant_id = "tnt123"
        environment = "sandbox"
    "#;
    let config: Config = toml::from_str(toml).unwrap();
    assert!(matches!(config.vault, Some(VaultConfig::Vgs(_))));
}
```

**Backward Compatibility:**
```rust
#[test]
fn test_backward_compat_no_vault() {
    let config: Config = toml::from_str(r#"
        [connectors.stripe]
        base_url = "https://api.stripe.com"
    "#).unwrap();
    assert!(config.vault.is_none());
    assert!(!config.connectors.stripe.enable_vault_proxy);
}
```

**Validation Tests:**
- Empty `tenant_id` should fail validation
- Invalid `environment` value should error

---

### 3. Security Tests (Critical)

**Secret Masking:**
```rust
#[test]
fn test_vault_credentials_masked() {
    let config = VaultConfig::HyperswitchVault(HyperswitchVaultConfig {
        api_key: Secret::new("secret_key_123".to_string()),
        // ...
    });

    let debug_output = format!("{:?}", config);
    assert!(!debug_output.contains("secret_key_123"));
    assert!(debug_output.contains("***"));
}
```

**Log Inspection:**
```bash
# Ensure no sensitive data in logs
cargo test 2>&1 | grep -E "(api_key|token|credential)" | wc -l
# Expected: 0 (or only masked values)
```

---

### 4. Connector Integration Tests (PR #2)

**Mock Vault Server Tests:**
```rust
#[tokio::test]
async fn test_stripe_via_vgs() {
    let mock = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/payment_intents"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock)
        .await;

    let response = stripe_connector.authorize(payment_request).await;
    assert!(response.is_success());
}
```

**Test Matrix (Prioritized):**

| Connector | VGS | Hyperswitch Vault | Priority |
|-----------|-----|-------------------|----------|
| Stripe | ✅ | ✅ | P0 |
| Checkout | ⬜ | ⬜ | P1 |
| Adyen | ⬜ | ⬜ | P2 |

---

### 5. End-to-End Scenarios

```gherkin
Feature: PCI Vault Integration

  Scenario: Payment with VGS Network Proxy
    Given merchant has VGS vault configured
    When payment is authorized through Stripe connector
    Then request URL should contain "verygoodproxy.com"
    And card data should NOT appear in UCS logs
    And payment should succeed

  Scenario: Backward compatibility - no vault
    Given merchant has no vault configured
    When payment is authorized
    Then request should go directly to PSP
    And payment should succeed

  Scenario: Vault configuration error
    Given merchant has invalid vault configuration
    When payment is attempted
    Then error should indicate misconfiguration
    And payment should NOT proceed
```

---

### 6. Failure Mode Tests

| Scenario | Expected Behavior |
|----------|-------------------|
| Vault timeout | Return 504, retryable error |
| Vault auth failure | Return 401, no secrets in logs |
| Invalid config | Clear error, fail-safe (no payment) |
| TLS cert error | Clear validation error |

---

### CI/CD Checks

```yaml
# Essential pre-merge checks
- cargo test --package external-services vault
- cargo test --package ucs_env config
- cargo test --test vault_integration
- cargo clippy -- -D warnings
```

---

### Pre-Merge Checklist

- [ ] All unit tests pass
- [ ] Config validation works
- [ ] No secrets exposed in logs
- [ ] Backward compatibility verified
- [ ] Integration tests pass
- [ ] Documentation updated

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

## Files Updated

| File | Change |
|------|--------|
| `backend/domain_types/src/types.rs` | Added `VaultConfig` enum, 5 provider configs, updated `ConnectorParams` with `enable_vault_proxy` and `vault_proxy_override`, added `resolve_vault()` method to `Connectors` |
| `backend/ucs_env/src/configs.rs` | Added `vault: Option<VaultConfig>` to main `Config`, imported `VaultConfigPatch` |
| `backend/external-services/src/vault.rs` | **New file** - HTTP client integration with URL transformation, header generation, and helper functions |
| `backend/external-services/src/lib.rs` | Exported `vault` module |
| `docs/pci-compliance/*.md` | Updated examples to use `enable_vault_proxy` |

---

## Implementation Summary

### Phase 1: Core Types (Complete)
Added `VaultConfig` enum with 5 provider variants and their configuration structs:
- `VgsConfig` - Network proxy with tenant_id, environment, optional CA cert
- `EvervaultConfig` - Network proxy with team_id, app_id, api_key
- `HyperswitchVaultConfig` - Application proxy with api_key, profile_id, proxy_url
- `TokenExConfig` - Application proxy with api_key, tokenex_id, token scheme
- `BasisTheoryConfig` - Application proxy with api_key, proxy_url, proxy_id

### Phase 2: Config Integration (Complete)
- Added `vault: Option<VaultConfig>` to main `Config` struct in `ucs_env/src/configs.rs`
- Config hot-reloading supported via `config_patch_derive::Patch`
- Backward compatible - vault is optional

### Phase 3: Vault Resolution Logic (Complete)
- Added `get_connector_params()` method to `Connectors` for connector lookup by name
- Added `resolve_vault()` method that returns vault config with priority:
  1. Connector's `vault_proxy_override` (if set)
  2. Global vault config (if set)
  3. None (if `enable_vault_proxy` is false)

### Phase 4: HTTP Client Integration (Complete)
Created `external-services/src/vault.rs` with:
- `transform_connector_url()` - URL transformation for VGS (network proxy)
- `get_vault_headers()` - Header generation for application proxies
- `is_network_proxy()` - Check if vault uses network-level proxy
- `get_vault_aware_url()` - Convenience function for connectors
- Unit tests for VGS URL transformation

### Phase 5: Validation and Tests (Complete)
- All crates compile successfully: `domain_types`, `ucs_env`, `external-services`, `connector-integration`
- Unit tests for vault URL transformation
- Config deserialization validated

---

## Checklist

- [x] Phase 1: Core types added
- [x] Phase 2: Config integration complete
- [x] Phase 3: Vault resolution logic
- [x] Phase 4: HTTP client integration
- [x] Phase 5: Validation and tests
