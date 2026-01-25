# UniFFI Evaluation for Connector Service FFI

## Executive Summary

**Recommendation: Adopt UniFFI for multi-language binding generation.**

[Mozilla UniFFI](https://github.com/mozilla/uniffi-rs) would eliminate manual type duplication across Python, JavaScript, and other languages, providing automatically generated, type-safe bindings from a single Rust source.

## Current State vs UniFFI

### Current Approach (Manual FFI)

```
┌─────────────────────────────────────────────────────────────────┐
│  Rust FFI (lib.rs)                                              │
│  - Manual C-compatible structs                                  │
│  - JSON serialization for complex types                         │
│  - Raw pointer handling                                         │
│  - ~1300 lines                                                  │
└─────────────────────────────────────────────────────────────────┘
          │                    │                    │
          ▼                    ▼                    ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│  Python         │  │  JavaScript     │  │  Java (TODO)    │
│  connector_     │  │  index.js       │  │                 │
│  client.py      │  │  index.d.ts     │  │                 │
│  ~600 lines     │  │  ~700 lines     │  │                 │
│                 │  │                 │  │                 │
│  DUPLICATED:    │  │  DUPLICATED:    │  │  WOULD NEED:    │
│  - PaymentMethod│  │  - PaymentMethod│  │  - PaymentMethod│
│  - PaymentResult│  │  - PaymentResult│  │  - PaymentResult│
│  - ConnectorInfo│  │  - ConnectorInfo│  │  - ConnectorInfo│
│  - Enums        │  │  - Enums        │  │  - Enums        │
└─────────────────┘  └─────────────────┘  └─────────────────┘
```

**Problems:**
- Types defined 3+ times (Rust, Python, JS, TypeScript)
- Manual synchronization required
- Type mismatches cause runtime errors
- Adding a field requires changes in all languages
- No compile-time guarantees across boundaries

### UniFFI Approach

```
┌─────────────────────────────────────────────────────────────────┐
│  Rust with UniFFI Macros (lib.rs)                               │
│  - #[derive(uniffi::Record)] for structs                        │
│  - #[derive(uniffi::Enum)] for enums                            │
│  - #[uniffi::export] for functions                              │
│  - Single source of truth                                       │
└─────────────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────┐
│  uniffi-bindgen (build step)                                    │
│  - Parses Rust types                                            │
│  - Generates language bindings                                  │
└─────────────────────────────────────────────────────────────────┘
          │
          ├──────────────┬──────────────┬──────────────┐
          ▼              ▼              ▼              ▼
┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│  Python      │  │  Kotlin      │  │  Swift       │  │  Ruby        │
│  AUTO-GEN    │  │  AUTO-GEN    │  │  AUTO-GEN    │  │  AUTO-GEN    │
│              │  │              │  │              │  │              │
│  Types match │  │  Types match │  │  Types match │  │  Types match │
│  100%        │  │  100%        │  │  100%        │  │  100%        │
└──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘
```

## Supported Languages

| Language | Support Level | Notes |
|----------|---------------|-------|
| **Python** | ✅ Built-in | Full support |
| **Kotlin** | ✅ Built-in | Android/JVM |
| **Swift** | ✅ Built-in | iOS/macOS |
| **Ruby** | ✅ Built-in | Full support |
| **JavaScript** | ⚡ 3rd party | Via uniffi-bindgen-js (WASM, React Native) |
| **Java** | ⚡ 3rd party | Via uniffi-bindgen-java |
| **C#/.NET** | ⚡ 3rd party | Via uniffi-bindgen-cs |
| **Go** | ⚡ 3rd party | Via uniffi-bindgen-go |

## What UniFFI Code Looks Like

### Current Manual Approach

```rust
// Current: Manual C-compatible FFI
#[repr(C)]
pub struct FfiPaymentResponse {
    pub status: *const c_char,
    pub transaction_id: *const c_char,
    pub amount: i64,
    // ... more fields
}

#[no_mangle]
pub unsafe extern "C" fn connector_transform_request_json(
    request_json: *const c_char,
) -> *const c_char {
    // Manual null checks
    if request_json.is_null() { ... }
    // Manual string conversion
    let input_str = CStr::from_ptr(request_json).to_str()?;
    // Manual JSON parsing
    let input: TransformRequestInput = serde_json::from_str(input_str)?;
    // ... process ...
    // Manual JSON serialization + C string conversion
    to_c_string(&result)
}
```

### UniFFI Approach

```rust
// UniFFI: Native Rust types with derive macros
use uniffi;

#[derive(uniffi::Enum)]
pub enum PaymentStatus {
    Succeeded,
    Authorized,
    Pending,
    Failed,
    Cancelled,
    RequiresAction,
}

#[derive(uniffi::Enum)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
}

#[derive(uniffi::Record)]
pub struct PaymentMethod {
    pub method_type: String,
    pub card: Option<CardData>,
    pub wallet: Option<WalletData>,
}

#[derive(uniffi::Record)]
pub struct CardData {
    pub number: String,
    pub exp_month: u32,
    pub exp_year: u32,
    pub cvc: String,
    pub holder_name: Option<String>,
}

#[derive(uniffi::Record)]
pub struct HttpRequest {
    pub url: String,
    pub method: HttpMethod,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub body_type: String,
}

#[derive(uniffi::Record)]
pub struct PaymentResult {
    pub success: bool,
    pub status: PaymentStatus,
    pub transaction_id: Option<String>,
    pub amount: Option<i64>,
    pub currency: Option<String>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
}

#[derive(uniffi::Record)]
pub struct ConnectorInfo {
    pub name: String,
    pub display_name: String,
    pub base_url: String,
    pub auth_type: String,
    pub auth_fields: Vec<String>,
    pub supported_flows: Vec<String>,
    pub supported_currencies: Vec<String>,
    pub body_format: String,
}

// Functions are exported with #[uniffi::export]
#[uniffi::export]
pub fn transform_request(
    connector: String,
    flow: String,
    auth: HashMap<String, String>,
    payment: HashMap<String, String>,
) -> Result<HttpRequest, ConnectorError> {
    // Pure Rust implementation - no manual FFI handling
    // ...
}

#[uniffi::export]
pub fn transform_response(
    connector: String,
    flow: String,
    status_code: u16,
    body: String,
) -> Result<PaymentResult, ConnectorError> {
    // Pure Rust implementation
    // ...
}

#[uniffi::export]
pub fn list_connectors() -> Vec<String> {
    vec!["stripe", "adyen", "forte", ...]
}

#[uniffi::export]
pub fn get_connector_info(connector: String) -> Option<ConnectorInfo> {
    // ...
}

// Custom error type
#[derive(Debug, uniffi::Error)]
pub enum ConnectorError {
    UnknownConnector { name: String },
    MissingAuthField { field: String },
    TransformError { message: String },
    ParseError { message: String },
}
```

### Generated Python (Automatic)

```python
# AUTO-GENERATED by uniffi-bindgen - DO NOT EDIT

from enum import Enum
from dataclasses import dataclass
from typing import Optional, Dict, List

class PaymentStatus(Enum):
    SUCCEEDED = "Succeeded"
    AUTHORIZED = "Authorized"
    PENDING = "Pending"
    FAILED = "Failed"
    CANCELLED = "Cancelled"
    REQUIRES_ACTION = "RequiresAction"

class HttpMethod(Enum):
    GET = "Get"
    POST = "Post"
    PUT = "Put"
    DELETE = "Delete"
    PATCH = "Patch"

@dataclass
class CardData:
    number: str
    exp_month: int
    exp_year: int
    cvc: str
    holder_name: Optional[str] = None

@dataclass
class PaymentMethod:
    method_type: str
    card: Optional[CardData] = None
    wallet: Optional[WalletData] = None

@dataclass
class HttpRequest:
    url: str
    method: HttpMethod
    headers: Dict[str, str]
    body: Optional[str]
    body_type: str

@dataclass
class PaymentResult:
    success: bool
    status: PaymentStatus
    transaction_id: Optional[str] = None
    amount: Optional[int] = None
    currency: Optional[str] = None
    error_code: Optional[str] = None
    error_message: Optional[str] = None

class ConnectorError(Exception):
    pass

class UnknownConnector(ConnectorError):
    def __init__(self, name: str):
        self.name = name

# Functions - automatically wrapped
def transform_request(
    connector: str,
    flow: str,
    auth: Dict[str, str],
    payment: Dict[str, str],
) -> HttpRequest:
    return _uniffi_lib.transform_request(connector, flow, auth, payment)

def transform_response(
    connector: str,
    flow: str,
    status_code: int,
    body: str,
) -> PaymentResult:
    return _uniffi_lib.transform_response(connector, flow, status_code, body)

def list_connectors() -> List[str]:
    return _uniffi_lib.list_connectors()

def get_connector_info(connector: str) -> Optional[ConnectorInfo]:
    return _uniffi_lib.get_connector_info(connector)
```

### Generated Kotlin (Automatic)

```kotlin
// AUTO-GENERATED by uniffi-bindgen - DO NOT EDIT

package io.juspay.connector

enum class PaymentStatus {
    SUCCEEDED,
    AUTHORIZED,
    PENDING,
    FAILED,
    CANCELLED,
    REQUIRES_ACTION
}

enum class HttpMethod {
    GET, POST, PUT, DELETE, PATCH
}

data class CardData(
    val number: String,
    val expMonth: UInt,
    val expYear: UInt,
    val cvc: String,
    val holderName: String? = null
)

data class HttpRequest(
    val url: String,
    val method: HttpMethod,
    val headers: Map<String, String>,
    val body: String?,
    val bodyType: String
)

data class PaymentResult(
    val success: Boolean,
    val status: PaymentStatus,
    val transactionId: String? = null,
    val amount: Long? = null,
    val currency: String? = null,
    val errorCode: String? = null,
    val errorMessage: String? = null
)

sealed class ConnectorError : Exception() {
    data class UnknownConnector(val name: String) : ConnectorError()
    data class MissingAuthField(val field: String) : ConnectorError()
    data class TransformError(val message: String) : ConnectorError()
}

object ConnectorFFI {
    fun transformRequest(
        connector: String,
        flow: String,
        auth: Map<String, String>,
        payment: Map<String, String>
    ): HttpRequest = // native call

    fun transformResponse(
        connector: String,
        flow: String,
        statusCode: UShort,
        body: String
    ): PaymentResult = // native call

    fun listConnectors(): List<String> = // native call

    fun getConnectorInfo(connector: String): ConnectorInfo? = // native call
}
```

## Migration Plan

### Phase 1: Setup UniFFI Infrastructure (1-2 days)

1. Add UniFFI dependencies to `Cargo.toml`:
```toml
[dependencies]
uniffi = "0.28"

[build-dependencies]
uniffi = { version = "0.28", features = ["build"] }
```

2. Create `uniffi.toml` configuration:
```toml
[bindings.python]
package_name = "connector_ffi"
cdylib_name = "connector_ffi"

[bindings.kotlin]
package_name = "io.juspay.connector"
cdylib_name = "connector_ffi"

[bindings.swift]
module_name = "ConnectorFFI"
cdylib_name = "connector_ffi"
```

3. Create build script for binding generation

### Phase 2: Convert Core Types (2-3 days)

1. Add UniFFI derives to existing types:
```rust
#[derive(uniffi::Record, Serialize, Deserialize)]
pub struct HttpRequest { ... }
```

2. Convert enums:
```rust
#[derive(uniffi::Enum)]
pub enum PaymentStatus { ... }
```

3. Create proper error types:
```rust
#[derive(uniffi::Error)]
pub enum ConnectorError { ... }
```

### Phase 3: Export Functions (1-2 days)

1. Mark public functions with `#[uniffi::export]`
2. Adjust function signatures for UniFFI compatibility
3. Remove manual JSON wrapping

### Phase 4: Generate Bindings (1 day)

1. Run `uniffi-bindgen generate`:
```bash
# Python
uniffi-bindgen generate --library target/release/libconnector_ffi.so \
    --language python --out-dir bindings/python

# Kotlin
uniffi-bindgen generate --library target/release/libconnector_ffi.so \
    --language kotlin --out-dir bindings/kotlin

# Swift
uniffi-bindgen generate --library target/release/libconnector_ffi.so \
    --language swift --out-dir bindings/swift
```

2. Package for distribution

### Phase 5: High-Level Wrappers (2-3 days)

Create thin wrappers for ergonomic APIs (optional, since generated code is already usable):

```python
# connector_client.py - Thin wrapper over generated bindings
from connector_ffi import (
    transform_request, transform_response,
    HttpRequest, PaymentResult, ConnectorInfo
)

class ConnectorClient:
    def __init__(self, connector: str, auth: dict):
        self.connector = connector
        self.auth = auth

    def authorize(self, amount: int, currency: str, ...) -> PaymentResult:
        # Call generated transform_request
        http_req = transform_request(self.connector, "authorize", self.auth, {...})
        # Execute HTTP
        response = self._http_client.request(...)
        # Call generated transform_response
        return transform_response(self.connector, "authorize", response.status, response.body)
```

## Comparison Table

| Aspect | Manual FFI | UniFFI |
|--------|------------|--------|
| **Type Safety** | Runtime JSON errors | Compile-time guarantees |
| **Code Duplication** | 3x (Rust + each lang) | 1x (Rust only) |
| **Adding New Type** | Change all languages | Change Rust only |
| **Language Support** | Manual per language | Auto-generated |
| **Maintenance** | High | Low |
| **Learning Curve** | Low (familiar patterns) | Medium (new tool) |
| **Build Complexity** | Simple | Extra build step |
| **Binary Size** | Smaller | Slightly larger |
| **Performance** | Manual optimization | Good (auto-optimized) |
| **Error Handling** | Manual mapping | Typed exceptions |

## Pros and Cons

### Pros of UniFFI

1. **Single Source of Truth**: Types defined once in Rust
2. **Type Safety**: Compile-time errors instead of runtime JSON parsing failures
3. **Multi-Language**: Python, Kotlin, Swift, Ruby built-in; JS, Java, C# via 3rd party
4. **Mozilla Backing**: Production-tested in Firefox
5. **Reduced Maintenance**: Add a field once, regenerate bindings
6. **Proper Error Types**: Rich exception handling across languages
7. **Documentation**: Generated docs match Rust docs

### Cons of UniFFI

1. **Build Complexity**: Extra generation step
2. **Learning Curve**: Team needs to learn UniFFI patterns
3. **Constraints**: Some Rust patterns don't translate well
4. **Third-Party JS**: JavaScript support isn't built-in
5. **Version Coupling**: Bindings tied to library version
6. **Debugging**: Harder to debug generated code

## Recommended Approach

### Short Term (Keep Current)
- Current implementation works
- Good for initial validation

### Medium Term (Adopt UniFFI)
1. Create new `backend/ffi-uniffi/` crate
2. Migrate types with UniFFI derives
3. Generate Python + Kotlin bindings
4. Keep JS as pure-JS implementation (works well)
5. Deprecate manual Python bindings

### Directory Structure

```
backend/
├── ffi/                          # Current (to be deprecated)
│   └── examples/
│       ├── python/
│       └── javascript/
│
└── ffi-uniffi/                   # New UniFFI-based
    ├── Cargo.toml
    ├── uniffi.toml
    ├── src/
    │   └── lib.rs                # Rust with UniFFI macros
    ├── bindings/                 # Auto-generated
    │   ├── python/
    │   │   └── connector_ffi/
    │   ├── kotlin/
    │   │   └── io/juspay/connector/
    │   ├── swift/
    │   │   └── ConnectorFFI/
    │   └── ruby/
    │       └── connector_ffi/
    └── wrappers/                 # High-level ergonomic APIs
        ├── python/
        │   └── connector_client.py
        └── kotlin/
            └── ConnectorClient.kt
```

## Next Steps

1. **Prototype**: Create minimal UniFFI example with 2-3 types
2. **Validate**: Test generated Python and Kotlin bindings
3. **Benchmark**: Compare performance with manual FFI
4. **Decide**: Full migration vs hybrid approach
5. **Implement**: Phased migration per plan above

## References

- [UniFFI GitHub Repository](https://github.com/mozilla/uniffi-rs)
- [UniFFI User Guide](https://mozilla.github.io/uniffi-rs/latest/)
- [Mozilla Blog: Autogenerating Rust-JS bindings](https://hacks.mozilla.org/2023/08/autogenerating-rust-js-bindings-with-uniffi/)
- [uniffi-bindgen-js for JavaScript](https://github.com/aspect-build/aspect-build-uniffi-bindgen-js)
- [uniffi-bindgen-java](https://github.com/nicegram/nicegram-android/tree/main/nicegram-features/nicegram-api-java)
