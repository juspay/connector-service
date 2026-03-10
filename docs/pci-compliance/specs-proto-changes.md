# Proto Changes for Vault Integration

> Summary of protobuf changes required to support PCI vault providers in UCS

---

## Overview

This document outlines the protobuf message changes needed to support two vault proxy patterns:
- **Network Proxy**: VGS, Evervault (transparent routing—UCS routes to proxy URL only)
- **Application Proxy**: Hyperswitch Vault, TokenEx, Basis Theory (UCS formats tokens for vault protocol)

---

## Global Vault Configuration

### Design Decision: Global Vault Mode

Instead of configuring vault settings per-connector, we use a **global vault configuration**. This simplifies the setup since merchants typically use one vault provider for all their payment processing.

```protobuf
// Added to the main UCS configuration message
message UcsConfig {
  // ... existing fields ...

  // Global vault configuration (optional)
  // When set, all connectors use this vault for detokenization
  VaultConfig vault = 25;
}
```

---

## Vault Configuration Messages

### VaultConfig (Oneof for Provider Selection)

```protobuf
// Top-level vault configuration
// Uses oneof to ensure only one provider is configured at a time
message VaultConfig {
  // The vault provider determines which proxy pattern to use
  oneof provider {
    // Network Proxy providers (zero code changes)
    VgsConfig vgs = 1;
    EvervaultConfig evervault = 2;

    // Application Proxy providers (UCS formats tokens for vault protocol)
    HyperswitchVaultConfig hyperswitch_vault = 3;
    TokenExConfig tokenex = 5;
  }
}
```

**Why oneof?**
- Ensures only one vault provider is active at a time
- Prevents misconfiguration (e.g., setting both VGS and TokenEx)
- Makes the configuration explicit and self-validating

---

## Network Proxy Configurations

### VgsConfig

```protobuf
// VGS (Very Good Security) Network Proxy configuration
// Used for: Outbound HTTP Proxy with transparent detokenization
message VgsConfig {
  // VGS tenant identifier
  // Format: "tnt" + alphanumeric (e.g., "tntSANDBOX123")
  // This identifies your VGS organization
  string tenant_id = 1;

  // VGS environment
  // SANDBOX: Use for testing (tokens are non-production)
  // PRODUCTION: Use for live transactions
  VgsEnvironment environment = 2;

  // Optional: CA certificate for TLS verification
  // If not provided, UCS uses the default VGS CA cert
  // Required when using custom certificates
  bytes ca_certificate = 3;
}

enum VgsEnvironment {
  VGS_ENVIRONMENT_UNSPECIFIED = 0;
  VGS_ENVIRONMENT_SANDBOX = 1;
  VGS_ENVIRONMENT_PRODUCTION = 2;
}
```

**Key Fields Explained:**
- `tenant_id`: Your unique VGS tenant (found in VGS dashboard)
- `environment`: Sandbox for testing, Production for live
- `ca_certificate`: VGS uses a custom CA for sandbox; production uses standard CAs

---

### EvervaultConfig

```protobuf
// Evervault Network Proxy configuration
// Used for: HTTP CONNECT Relay with client-side encryption
message EvervaultConfig {
  // Evervault team identifier
  // Format: "team_" + alphanumeric (e.g., "team_123abc")
  string team_id = 1;

  // Evervault app identifier
  // Format: "app_" + alphanumeric (e.g., "app_456def")
  // Each app has its own encryption keys
  string app_id = 2;

  // Evervault API key for Relay authentication
  // Used to authenticate outbound proxy connections
  // Keep this secret—treat like a password
  string api_key = 3;
}
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

```protobuf
// Hyperswitch Vault Transform Proxy configuration
// Used for: Wrapped request proxy with {{$variable}} expressions
message HyperswitchVaultConfig {
  // Hyperswitch API key
  // Format: "dev_xxx" (sandbox) or "prod_xxx" (production)
  // Get from Hyperswitch Dashboard → API Keys
  string api_key = 1;

  // Hyperswitch Profile ID
  // Identifies your merchant profile
  // Found in Hyperswitch Dashboard → Settings
  string profile_id = 2;

  // Hyperswitch Proxy endpoint
  // Default: "https://sandbox.hyperswitch.io/proxy" (sandbox)
  // Production: "https://api.hyperswitch.io/proxy"
  string proxy_url = 3;

  // Environment
  // SANDBOX: Use for testing
  // PRODUCTION: Use for live transactions
  HyperswitchEnvironment environment = 4;
}

enum HyperswitchEnvironment {
  HYPERSWITCH_ENVIRONMENT_UNSPECIFIED = 0;
  HYPERSWITCH_ENVIRONMENT_SANDBOX = 1;
  HYPERSWITCH_ENVIRONMENT_PRODUCTION = 2;
}
```

**Key Fields Explained:**
- `api_key`: Your Hyperswitch API key for authentication
- `profile_id`: Your merchant profile identifier
- `proxy_url`: The Hyperswitch proxy endpoint
- `environment`: Sandbox for testing, Production for live

**How it works:**
1. UCS constructs wrapped request with `destination_url`, `headers`, `request_body`
2. Request body contains `{{$variable}}` expressions (e.g., `{{$card_number}}`)
3. Hyperswitch Vault evaluates expressions and injects real card data
4. Forwarded to destination PSP with detokenized data
5. Response flows back through the same path

### TokenExConfig

```protobuf
// TokenEx Application Proxy configuration
// Used for: Header-driven routing with {token} markers
message TokenExConfig {
  // TokenEx API key
  // Used for TGAPI authentication
  // Get from TokenEx Dashboard → API Keys
  string api_key = 1;

  // TokenEx ID (organization identifier)
  // Format: Alphanumeric string
  // Identifies your TokenEx account
  string tokenex_id = 2;

  // TGAPI endpoint URL
  // Sandbox: "https://tgapi-sandbox.tokenex.com"
  // Production: "https://tgapi.tokenex.com"
  string tgapi_url = 3;

  // Default token scheme
  // Determines token format for new tokenizations
  // TOKENfour: Format-preserving 16-digit (default)
  // GUID: UUID format
  // SIXTokenfour: 6-digit prefix preserved
  string default_token_scheme = 4;
}

// Token scheme options for TokenEx
enum TokenExTokenScheme {
  TOKEN_EX_TOKEN_SCHEME_UNSPECIFIED = 0;
  TOKEN_EX_TOKEN_SCHEME_TOKEN_FOUR = 1;  // 4242123456784242
  TOKEN_EX_TOKEN_SCHEME_GUID = 2;         // UUID
  TOKEN_EX_TOKEN_SCHEME_SIX_TOKEN_FOUR = 3; // 424212xxxxxx4242
}
```

**Key Fields Explained:**
- `api_key`: Authenticates TGAPI requests
- `tokenex_id`: Your TokenEx organization ID
- `tgapi_url`: Transparent Gateway API endpoint (sandbox vs production)
- `default_token_scheme`: Format for newly created tokens

**How it works:**
1. UCS sends request to `tgapi_url`
2. Headers: `TX-URL: {destination}`, `TX-Method: {method}`
3. Body contains `{token}` markers
4. TokenEx detokenizes and forwards to destination
5. Response flows back through TGAPI

---

### BasisTheoryConfig

```protobuf
// Basis Theory Application Proxy configuration
// Used for: Header-driven routing with {{ }} expressions
message BasisTheoryConfig {
  // Basis Theory API key
  // Get from: Basis Theory Dashboard → Applications
  // Permissions needed: token:read, proxy:read
  string api_key = 1;

  // Proxy endpoint URL
  // Default: "https://api.basistheory.com/proxy"
  // Can be overridden for private deployments
  string proxy_url = 2;

  // Optional: Default proxy ID
  // If set, this proxy configuration is used for all requests
  // If not set, UCS creates ephemeral proxies
  string proxy_id = 3;
}
```

**Key Fields Explained:**
- `api_key`: Authenticates with Basis Theory API
- `proxy_url`: The proxy endpoint (Basis Theory Cloud or private instance)
- `proxy_id`: Pre-configured proxy (optional, enables reuse and caching)

**How it works:**
1. UCS sends request to `proxy_url` with `BT-PROXY-URL` header
2. Request body contains `{{ token.property }}` expressions
3. Basis Theory evaluates expressions and injects real values
4. Forwarded to destination with detokenized data

---

## Connector-Level Configuration

### ConnectorConfig Updates

```protobuf
// Added to existing ConnectorConfig message
message ConnectorConfig {
  // ... existing fields (base_url, api_key, etc.) ...

  // Use vault for this connector
  // If true, UCS routes requests through the configured vault proxy
  // If false (or unset), UCS sends tokens directly to the PSP
  // (Useful for gradual migration: enable per-connector as you test)
  bool use_vault = 20;

  // Optional: Override vault configuration for this connector
  // If set, this overrides the global vault config
  // If not set, uses global vault config (if present)
  VaultConfig vault_override = 21;

  // Application Proxy-specific configuration
  // Used for vault providers requiring token transformation
  ApplicationProxyConfig application_proxy_config = 22;
}
```

**Why `use_vault`?**
- Allows gradual migration: some connectors use vault, others don't
- Backward compatible: existing configs work without changes
- Explicit opt-in: merchant must consciously enable vault usage

---

## Application Proxy-Specific Configuration

### ApplicationProxyConfig

```protobuf
// Additional configuration for Application Proxy connectors
// This is provider-agnostic and works with Hyperswitch Vault, TokenEx, etc.
message ApplicationProxyConfig {
  // Expression syntax (provider-specific)
  // Hyperswitch Vault: "{{$variable}}"
  // TokenEx: "{token}" (no expressions, just markers)
  // Basis Theory: "{{token.property}}"
  string expression_syntax = 1;

  // Token property mappings
  // Maps standard fields to provider-specific token properties
  repeated TokenPropertyMapping token_mappings = 2;

  // Profile ID (for Hyperswitch Vault)
  // The merchant profile to use
  string profile_id = 3;
}

// Maps a standard field to a vault-specific property
message TokenPropertyMapping {
  // Standard field name (used by UCS internally)
  // e.g., "card_number", "exp_month", "exp_year", "cvv"
  string standard_field = 1;

  // Provider-specific property path
  // Hyperswitch Vault: "$card_number", "$card_exp_month"
  string vault_property = 2;
}
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

## Migration Path

### Phase 1: PCI-Enabled (Current State)
```protobuf
// No vault configuration
UcsConfig {
  // vault not set
  connectors: [{
    name: "stripe"
    base_url: "https://api.stripe.com"
    api_key: "sk_..."
    // use_vault defaults to false
  }]
}
```

### Phase 2: PCI-Disabled with Vault
```protobuf
// Global vault enabled
UcsConfig {
  vault: {
    vgs: {
      tenant_id: "tntSANDBOX123"
      environment: SANDBOX
    }
  }
  connectors: [{
    name: "stripe"
    base_url: "https://tntSANDBOX123.sandbox.verygoodproxy.com"
    api_key: "sk_..."
    use_vault: true  // Enable vault usage
  }]
}
```

### Phase 3: Mixed Mode (Gradual Migration)
```protobuf
// Some connectors use vault, others don't
UcsConfig {
  vault: { /* global config */ }
  connectors: [
    {
      name: "stripe"
      use_vault: true   // Uses vault
    },
    {
      name: "adyen"
      use_vault: false  // Direct connection (legacy)
    }
  ]
}
```

---

## Security Considerations

### Sensitive Fields

All API keys and tokens are marked as sensitive:

```protobuf
message VgsConfig {
  // Not sensitive - identifies the tenant
  string tenant_id = 1;

  // Not sensitive - environment selector
  VgsEnvironment environment = 2;

  // Sensitive - certificate data
  bytes ca_certificate = 3 [(google.api.field_behavior) = SENSITIVE];
}

message BasisTheoryConfig {
  // Sensitive - authentication credential
  string api_key = 1 [(google.api.field_behavior) = SENSITIVE];

  // Not sensitive - public URL
  string proxy_url = 2;
}
```

### Validation Rules

```protobuf
// Example validation annotations
message EvervaultConfig {
  // Must match pattern: team_[a-zA-Z0-9]+
  string team_id = 1 [(validate.rules).string.pattern = "^team_[a-zA-Z0-9]+$"];

  // Must match pattern: app_[a-zA-Z0-9]+
  string app_id = 2 [(validate.rules).string.pattern = "^app_[a-zA-Z0-9]+$"];

  // Required, minimum 32 characters
  string api_key = 3 [(validate.rules).string.min_len = 32, (validate.rules).string.sensitive = true];
}
```

---

## Example Proto Definitions

See the full proto definitions in:
- `/backend/grpc-api-types/proto/vault.proto` (new file)
- `/backend/grpc-api-types/proto/payment.proto` (updates to existing)

---

_Questions? See the individual proxy pattern docs for provider-specific details._
