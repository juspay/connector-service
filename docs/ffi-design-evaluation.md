# FFI Design Evaluation: Connector Service as a Library

## Executive Summary

**Verdict: FFI exposure is feasible and recommended.**

The connector-service architecture already cleanly separates transformation logic from transport, making it well-suited for FFI exposure. This would allow connector-service to be used as a library in multiple languages (JavaScript, Java, Python, Go, etc.) while keeping the HTTP execution in the native language.

## Current Architecture Analysis

### Separation of Concerns (Already Exists)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Layer 1: gRPC/HTTP Service (grpc-server)                                    │
│ - Receives requests, routes to connectors                                   │
│ - NOT needed for FFI                                                        │
└─────────────────────────────────────────────────────────────────────────────┘
                                      ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│ Layer 2: HTTP Execution (external-services)                                 │
│ - Calls reqwest, handles proxies, retries                                   │
│ - REPLACED by native HTTP client in FFI model                               │
└─────────────────────────────────────────────────────────────────────────────┘
                                      ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│ Layer 3: Transformation Logic (connector-integration)     ← FFI BOUNDARY    │
│ - build_request_v2(): RouterDataV2 → Request (URL, headers, body)           │
│ - handle_response_v2(): Response bytes → RouterDataV2                       │
│ - PURE, SYNCHRONOUS, NO ASYNC                                               │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Key Trait: `ConnectorIntegrationV2`

Location: `backend/interfaces/src/connector_integration_v2.rs`

```rust
pub trait ConnectorIntegrationV2<Flow, ResourceCommonData, Req, Resp> {
    // Request building (FFI-exposable)
    fn get_url(&self, req: &RouterDataV2<...>) -> CustomResult<String>;
    fn get_headers(&self, req: &RouterDataV2<...>) -> CustomResult<Vec<(String, String)>>;
    fn get_http_method(&self) -> Method;  // GET, POST, PUT, DELETE, PATCH
    fn get_request_body(&self, req: &RouterDataV2<...>) -> CustomResult<Option<RequestContent>>;
    fn build_request_v2(&self, req: &RouterDataV2<...>) -> CustomResult<Option<Request>>;

    // Response handling (FFI-exposable)
    fn handle_response_v2(&self, data: &RouterDataV2<...>, res: Response) -> CustomResult<RouterDataV2<...>>;
    fn get_error_response_v2(&self, res: Response) -> CustomResult<ErrorResponse>;
}
```

### The `Request` Struct (Already FFI-Friendly)

Location: `backend/common_utils/src/request.rs`

```rust
pub struct Request {
    pub url: String,                    // FFI: char*
    pub headers: HashSet<(String, String)>,  // FFI: array of key-value pairs
    pub method: Method,                 // FFI: enum (GET=0, POST=1, etc.)
    pub body: Option<RequestContent>,   // FFI: serialized bytes + format tag
}
```

## Proposed FFI Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          Your Application (JS/Java/Python/Go)               │
├─────────────────────────────────────────────────────────────────────────────┤
│  1. Prepare payment data                                                    │
│  2. Call FFI: connector_transform_request()                                 │
│     → Returns: { url, method, headers, body }                               │
│  3. Execute HTTP with native client (fetch, HttpClient, requests, etc.)     │
│  4. Call FFI: connector_transform_response()                                │
│     → Returns: { status, transaction_id, amount, ... }                      │
└─────────────────────────────────────────────────────────────────────────────┘
                              │ FFI Calls │
                              ↓           ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│                          connector-ffi (Rust Library)                       │
├─────────────────────────────────────────────────────────────────────────────┤
│  connector_transform_request(connector, flow, auth, data)                   │
│    → Looks up connector by name                                             │
│    → Calls connector.build_request_v2()                                     │
│    → Returns HTTP request components                                        │
│                                                                             │
│  connector_transform_response(connector, flow, status, body)                │
│    → Looks up connector by name                                             │
│    → Calls connector.handle_response_v2()                                   │
│    → Returns standardized payment response                                  │
└─────────────────────────────────────────────────────────────────────────────┘
                              │ Calls │
                              ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│                    connector-integration (Existing Crate)                   │
│                    70+ connectors, pure transformation logic                │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Benefits

| Benefit | Description |
|---------|-------------|
| **Multi-language support** | JS, Java, Python, Go, Ruby, C#, etc. via single Rust library |
| **Native HTTP clients** | Use platform-optimized HTTP (fetch, HttpClient, requests) |
| **No async boundary** | Transformation is synchronous; async only in caller |
| **Smaller footprint** | No gRPC, no tokio runtime needed at FFI boundary |
| **Reuse existing code** | 70+ connector implementations work unchanged |
| **Type safety** | Rust ensures transformation correctness |
| **Performance** | Native code for CPU-intensive serialization/crypto |

## Challenges & Mitigations

### Challenge 1: Generic Type Parameters

**Problem**: Connectors use `PaymentMethodDataTypes<T>` for type-safe payment methods.

**Mitigation**: Use JSON serialization at the FFI boundary. The FFI layer deserializes JSON into concrete types before calling connector methods.

```rust
// FFI receives JSON
let payment_data: serde_json::Value = serde_json::from_str(request_json)?;

// Convert to concrete type based on payment method
let router_data = match payment_data["payment_method"]["type"].as_str() {
    Some("card") => build_card_router_data(payment_data)?,
    Some("wallet") => build_wallet_router_data(payment_data)?,
    // ...
};
```

### Challenge 2: Trait Objects vs. Static Dispatch

**Problem**: Connectors are selected at runtime by name.

**Mitigation**: Create a connector registry that maps names to trait implementations.

```rust
fn get_connector(name: &str) -> Option<Box<dyn ConnectorIntegrationV2<...>>> {
    match name {
        "stripe" => Some(Box::new(Stripe::default())),
        "adyen" => Some(Box::new(Adyen::default())),
        "phonepe" => Some(Box::new(Phonepe::default())),
        // ... 70+ connectors
        _ => None,
    }
}
```

### Challenge 3: Error Handling

**Problem**: Rust uses `error_stack` for rich error chains.

**Mitigation**: Flatten errors to JSON at the FFI boundary.

```rust
match result {
    Ok(response) => json!({ "success": true, "data": response }),
    Err(e) => json!({
        "success": false,
        "error": {
            "code": extract_error_code(&e),
            "message": e.to_string(),
            "chain": format_error_chain(&e)  // Optional: full error chain
        }
    })
}
```

### Challenge 4: Sensitive Data Handling

**Problem**: API keys and card numbers must be protected.

**Mitigation**:
- Use `Maskable<String>` for headers (already exists)
- Add `is_sensitive` flag to FFI header struct
- Caller is responsible for secure handling after FFI boundary

## Implementation Phases

### Phase 1: Core FFI Layer (Proof of Concept)
- Create `connector-ffi` crate
- Implement JSON-based API for simplicity
- Support 3-5 connectors (Stripe, Adyen, PhonePe)
- Support Authorize and Sync flows only
- Deliverable: Working Python/JS example

### Phase 2: Full Connector Support
- Add all 70+ connectors
- Support all flows (Authorize, Capture, Void, Refund, Sync, etc.)
- Add connector configuration loading
- Add comprehensive error handling

### Phase 3: Language Bindings
- Publish language-specific SDKs:
  - `@connector-service/node` (npm)
  - `connector-service-python` (PyPI)
  - `io.connector.service:ffi` (Maven)
  - `connector-service-go` (Go module)
- Auto-generate bindings using `uniffi` or `cbindgen`

### Phase 4: Production Hardening
- Memory safety audit
- Performance benchmarks
- Thread safety testing
- Documentation and examples

## API Design

### Option A: Raw C FFI (Maximum Compatibility)

```c
// C-compatible structs
typedef struct {
    const char* url;
    int method;  // 0=GET, 1=POST, etc.
    FfiHeader* headers;
    size_t headers_count;
    const char* body;
} FfiHttpRequest;

// Functions
FfiHttpRequest* connector_transform_request(
    const char* connector_name,
    const char* flow_name,
    const char* request_json,
    const char* auth_json
);

void ffi_free_request(FfiHttpRequest* req);
```

### Option B: JSON API (Simpler Integration)

```c
// Input/output are JSON strings
const char* connector_transform_request_json(const char* request_json);
const char* connector_transform_response_json(const char* response_json);
void ffi_string_free(char* s);
```

**Recommendation**: Implement both. JSON API for dynamic languages, raw FFI for performance-critical use cases.

## Comparison with Alternatives

| Approach | Pros | Cons |
|----------|------|------|
| **FFI (Proposed)** | Native perf, multi-language, no network | Memory mgmt complexity, build per platform |
| **gRPC Service** | Already exists, language-agnostic | Network latency, deployment complexity |
| **WASM** | Sandboxed, portable, web-friendly | Limited async, memory constraints |
| **Code Generation** | Native in each language | Maintenance burden, divergence risk |

## Conclusion

The connector-service codebase is well-architected for FFI exposure:

1. **Clean separation** between transformation (pure) and transport (async) layers
2. **Existing `Request` struct** is essentially FFI-ready
3. **70+ connectors** would work without modification
4. **No async at transformation boundary** simplifies FFI design

**Recommendation**: Proceed with FFI implementation starting with Phase 1 (proof of concept with 3-5 connectors).

## Files Created

- `backend/ffi/Cargo.toml` - FFI crate configuration
- `backend/ffi/src/lib.rs` - FFI interface definition (proof of concept)
- `backend/ffi/examples/usage.md` - Usage examples in Python, JS, Java, Go

## Next Steps

1. Review and approve this design
2. Add `connector-ffi` to workspace `Cargo.toml`
3. Implement Phase 1 with Stripe/Adyen/PhonePe
4. Create automated tests with mock connectors
5. Benchmark performance vs. gRPC service
