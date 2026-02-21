# UniFFI Protobuf Bindings Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add UniFFI bindings to the FFI crate so Python and Java callers can invoke `authorize_req` and `authorize_res` using protobuf-encoded bytes at the boundary, reusing their existing proto-generated stubs.

**Architecture:** The UniFFI boundary uses only `Vec<u8>` (protobuf-encoded `PaymentServiceAuthorizeRequest` / `PaymentServiceAuthorizeResponse`) and `HashMap<String, String>` (connector metadata/credentials) — both natively supported UniFFI types requiring zero custom annotation. `authorize_req` decodes the proto bytes, calls the existing `authorize_req_handler`, and returns the raw HTTP request JSON string that the caller sends to the connector. `authorize_res` takes the connector's HTTP response bytes plus the original proto request bytes and metadata, calls `authorize_res_handler`, and returns proto-encoded `PaymentServiceAuthorizeResponse` bytes. All business logic lives in the existing handlers; the UniFFI wrapper is a thin translation layer.

**Tech Stack:** Rust (uniffi 0.28), prost (protobuf encode/decode already in `grpc-api-types`), `backend/ffi` crate with `uniffi` feature flag, Python `cffi`/`uniffi-bindgen` for the example.

---

## Background: Codebase Map

Before touching any code, understand these files:

| File | Role |
|------|------|
| `backend/ffi/Cargo.toml` | Already has `uniffi = { version = "0.28", optional = true }` and `uniffi` feature flag |
| `backend/ffi/build.rs` | Runs `napi_build::setup()` for NAPI; needs equivalent for UniFFI |
| `backend/ffi/src/lib.rs` | Top-level module declarations |
| `backend/ffi/src/wrappers.rs` | Re-exports `mod napi`; needs `mod uniffi` added |
| `backend/ffi/src/wrappers/napi.rs` | Reference implementation — mirror its structure |
| `backend/ffi/src/handlers/payments.rs` | `authorize_req_handler` / `authorize_res_handler` — do NOT modify |
| `backend/ffi/src/types.rs` | `FFIRequestData<T>`, `FFIMetadataPayload`, `FFIApiResponse` |
| `backend/ffi/src/utils.rs` | `ffi_headers_to_masked_metadata(headers: &HashMap<String,String>)` — use this for metadata |
| `backend/grpc-api-types/src/lib.rs` | `pub mod payments { tonic::include_proto!("ucs.v2"); }` — proto types live here |
| `examples/example-py/` | Existing Python gRPC example — add a new `example-uniffi-py/` alongside it |

**Key types from `grpc_api_types::payments`:**
- `PaymentServiceAuthorizeRequest` — implements `prost::Message` (encode/decode)
- `PaymentServiceAuthorizeResponse` — implements `prost::Message` (encode/decode)

**Key functions from `backend/ffi/src/handlers/payments.rs`:**
```rust
pub fn authorize_req_handler(
    request: FFIRequestData<PaymentServiceAuthorizeRequest>,
) -> Result<Option<common_utils::request::Request>, PaymentAuthorizationError>

pub fn authorize_res_handler(
    request: FFIRequestData<PaymentServiceAuthorizeRequest>,
    response: domain_types::router_response_types::Response,
) -> Result<PaymentServiceAuthorizeResponse, PaymentServiceAuthorizeResponse>
```

**Key function from `backend/ffi/src/utils.rs`:**
```rust
pub fn ffi_headers_to_masked_metadata(headers: &HashMap<String, String>) -> MaskedMetadata
```

**`FFIMetadataPayload` (from `backend/ffi/src/types.rs`):**
```rust
pub struct FFIMetadataPayload {
    pub connector: ConnectorEnum,       // serde::Deserialize — parse from metadata HashMap
    pub connector_auth_type: ConnectorAuthType, // serde::Deserialize — parse from metadata HashMap
}
```
The metadata `HashMap<String, String>` must contain two keys: `"connector"` (JSON string of connector name) and `"connector_auth_type"` (JSON string of the auth struct). See how `napi.rs` does `serde_json::from_str(&extracted_metadata)` for the whole `FFIMetadataPayload` — we replicate that by JSON-encoding just the connector field from the map.

---

## Task 1: Enable UniFFI in `build.rs`

**Files:**
- Modify: `backend/ffi/build.rs`

**Context:** `build.rs` currently only calls `napi_build::setup()` when the `napi` feature is active. UniFFI's proc-macro mode (which we're using) does NOT require a build script step — it uses `uniffi::setup_scaffolding!()` at the crate root. But we need to confirm the build script doesn't need changes.

**Step 1: Verify the current build.rs**

Read `backend/ffi/build.rs`. It should contain only:
```rust
use std::env;
fn main() {
    if env::var("CARGO_FEATURE_NAPI").is_ok() {
        napi_build::setup();
    }
}
```
No changes needed for UniFFI proc-macro mode. UniFFI's scaffolding macro handles everything at compile time.

**Step 2: Verify Cargo.toml has correct uniffi deps**

Read `backend/ffi/Cargo.toml` and confirm:
```toml
uniffi = { version = "0.28", optional = true }

[build-dependencies]
uniffi = { version = "0.28", features = ["build"], optional = true }

[features]
uniffi = ["dep:uniffi"]
```
These should already be present. No changes needed.

**Step 3: Check that `prost` is accessible in the `ffi` crate**

Run:
```bash
grep -r "prost" backend/ffi/Cargo.toml
```
`prost` is NOT a direct dependency of `backend/ffi` — it's a dependency of `grpc-api-types`. We need it directly for `prost::Message::encode`/`decode`. Note it for Task 2.

---

## Task 2: Add `prost` to `backend/ffi/Cargo.toml`

**Files:**
- Modify: `backend/ffi/Cargo.toml`

**Step 1: Add prost dependency**

In `backend/ffi/Cargo.toml`, add under `[dependencies]`:
```toml
prost = "0.13"
bytes = "1"
```
`bytes` is needed because `prost::Message::encode_to_vec` returns `Vec<u8>` directly, but `prost::Message::decode` takes `impl Buf` — `bytes::Bytes::from(vec)` is the standard way.

Check if `bytes` is already present:
```bash
grep "bytes" backend/ffi/Cargo.toml
```
Only add it if missing.

**Step 2: Verify build still compiles (napi feature)**

```bash
cd backend/ffi && cargo build --features napi 2>&1 | tail -5
```
Expected: compiles without errors (we only added deps, no code changes yet).

**Step 3: Commit**

```bash
git add backend/ffi/Cargo.toml
git commit -m "chore(ffi): add prost and bytes deps for uniffi protobuf boundary"
```

---

## Task 3: Create `backend/ffi/src/wrappers/uniffi_bindings.rs`

**Files:**
- Create: `backend/ffi/src/wrappers/uniffi_bindings.rs`
- Modify: `backend/ffi/src/wrappers.rs`

**Context:** This is the core of the work. The file mirrors the structure of `napi.rs` but:
1. Uses `#[uniffi::export]` instead of `#[napi]`
2. Takes `Vec<u8>` (proto bytes) instead of JSON `String` for the request payload
3. Takes `HashMap<String, String>` instead of JSON `String` for metadata
4. Returns `Vec<u8>` (proto bytes) for the response, `String` for the connector request

**How metadata works:** The caller passes a flat `HashMap<String, String>` like:
```python
{
    "connector": "stripe",
    "connector_auth_type": '{"HeaderKey": {"api_key": "sk_test_..."}}'
}
```
We reconstruct `FFIMetadataPayload` by building a JSON object from the two keys and deserializing:
```rust
let metadata_json = format!(
    r#"{{"connector": {}, "connector_auth_type": {}}}"#,
    serde_json::to_string(metadata.get("connector"))?,
    metadata.get("connector_auth_type")?
);
let ffi_metadata: FFIMetadataPayload = serde_json::from_str(&metadata_json)?;
```

**Step 1: Create the file**

Create `backend/ffi/src/wrappers/uniffi_bindings.rs` with this content:

```rust
#[cfg(feature = "uniffi")]
mod uniffi_bindings {
    use crate::handlers::payments::{authorize_req_handler, authorize_res_handler};
    use crate::types::{FFIMetadataPayload, FFIRequestData};
    use crate::utils::ffi_headers_to_masked_metadata;
    use external_services;
    use grpc_api_types::payments::{
        PaymentServiceAuthorizeRequest, PaymentServiceAuthorizeResponse,
    };
    use prost::Message;
    use std::collections::HashMap;

    /// Error type exposed over the UniFFI boundary.
    /// UniFFI requires errors to be enums implementing `std::error::Error`.
    #[derive(Debug, thiserror::Error, uniffi::Error)]
    pub enum UniffiError {
        #[error("Failed to decode protobuf request: {msg}")]
        DecodeError { msg: String },
        #[error("Missing metadata key: {key}")]
        MissingMetadata { key: String },
        #[error("Failed to parse metadata: {msg}")]
        MetadataParseError { msg: String },
        #[error("Handler error: {msg}")]
        HandlerError { msg: String },
        #[error("Failed to encode protobuf response: {msg}")]
        EncodeError { msg: String },
        #[error("No connector request generated")]
        NoConnectorRequest,
    }

    /// Build an FFIMetadataPayload from the caller's flat HashMap.
    ///
    /// Expected keys:
    ///   "connector"           — connector name string, e.g. "stripe"
    ///   "connector_auth_type" — JSON-encoded ConnectorAuthType, e.g.
    ///                           '{"HeaderKey":{"api_key":"sk_test_..."}}'
    fn parse_metadata(
        metadata: &HashMap<String, String>,
    ) -> Result<FFIMetadataPayload, UniffiError> {
        let connector_val = metadata
            .get("connector")
            .ok_or_else(|| UniffiError::MissingMetadata {
                key: "connector".to_string(),
            })?;
        let auth_val =
            metadata
                .get("connector_auth_type")
                .ok_or_else(|| UniffiError::MissingMetadata {
                    key: "connector_auth_type".to_string(),
                })?;

        // connector is a plain string — wrap in quotes to make valid JSON
        let json = format!(
            r#"{{"connector": "{}", "connector_auth_type": {}}}"#,
            connector_val, auth_val
        );
        serde_json::from_str::<FFIMetadataPayload>(&json).map_err(|e| {
            UniffiError::MetadataParseError {
                msg: e.to_string(),
            }
        })
    }

    /// Build the connector HTTP request.
    ///
    /// # Arguments
    /// - `request_bytes`: protobuf-encoded `PaymentServiceAuthorizeRequest`
    /// - `metadata`: flat map with keys `connector` and `connector_auth_type`
    ///
    /// # Returns
    /// JSON string describing the HTTP request to send to the connector:
    /// `{"url": "...", "method": "POST", "headers": {...}, "body": {...}}`
    #[uniffi::export]
    pub fn authorize_req(
        request_bytes: Vec<u8>,
        metadata: HashMap<String, String>,
    ) -> Result<String, UniffiError> {
        // Decode protobuf bytes into typed request
        let payload = PaymentServiceAuthorizeRequest::decode(
            bytes::Bytes::from(request_bytes),
        )
        .map_err(|e| UniffiError::DecodeError { msg: e.to_string() })?;

        let ffi_metadata = parse_metadata(&metadata)?;
        let masked_metadata = ffi_headers_to_masked_metadata(&metadata);

        let request = FFIRequestData {
            payload,
            extracted_metadata: ffi_metadata,
            masked_metadata,
        };

        let result = authorize_req_handler(request)
            .map_err(|e| UniffiError::HandlerError {
                msg: format!("{:?}", e),
            })?;

        let connector_request =
            result.ok_or(UniffiError::NoConnectorRequest)?;

        Ok(external_services::service::extract_raw_connector_request(
            &connector_request,
        ))
    }

    /// Process the connector HTTP response and produce a structured response.
    ///
    /// # Arguments
    /// - `response_body`: raw bytes from the connector's HTTP response body
    /// - `status_code`: HTTP status code from the connector response
    /// - `response_headers`: HTTP response headers from the connector
    /// - `request_bytes`: the original protobuf-encoded `PaymentServiceAuthorizeRequest`
    ///   (the same bytes passed to `authorize_req`)
    /// - `metadata`: the original metadata map passed to `authorize_req`
    ///
    /// # Returns
    /// protobuf-encoded `PaymentServiceAuthorizeResponse` bytes
    #[uniffi::export]
    pub fn authorize_res(
        response_body: Vec<u8>,
        status_code: u16,
        response_headers: HashMap<String, String>,
        request_bytes: Vec<u8>,
        metadata: HashMap<String, String>,
    ) -> Result<Vec<u8>, UniffiError> {
        // Rebuild the Response struct from raw parts
        let mut header_map = http::HeaderMap::new();
        for (key, value) in &response_headers {
            if let (Ok(name), Ok(val)) = (
                http::header::HeaderName::from_bytes(key.as_bytes()),
                http::header::HeaderValue::from_str(value),
            ) {
                header_map.insert(name, val);
            }
        }

        let response = domain_types::router_response_types::Response {
            headers: if header_map.is_empty() {
                None
            } else {
                Some(header_map)
            },
            response: bytes::Bytes::from(response_body),
            status_code,
        };

        // Decode original request
        let payload = PaymentServiceAuthorizeRequest::decode(
            bytes::Bytes::from(request_bytes),
        )
        .map_err(|e| UniffiError::DecodeError { msg: e.to_string() })?;

        let ffi_metadata = parse_metadata(&metadata)?;
        let masked_metadata = ffi_headers_to_masked_metadata(&metadata);

        let request = FFIRequestData {
            payload,
            extracted_metadata: ffi_metadata,
            masked_metadata,
        };

        let proto_response = authorize_res_handler(request, response)
            .unwrap_or_else(|err_response| err_response); // error path also returns a valid response

        Ok(proto_response.encode_to_vec())
    }
}

#[cfg(feature = "uniffi")]
pub use uniffi_bindings::*;
```

**Step 2: Check if `thiserror` is a dependency of `backend/ffi`**

```bash
grep "thiserror" backend/ffi/Cargo.toml
```
If missing, add to `Cargo.toml`:
```toml
thiserror = "1"
```

**Step 3: Register module in `wrappers.rs`**

Edit `backend/ffi/src/wrappers.rs` to add:
```rust
pub mod napi;
pub mod uniffi_bindings;
```

**Step 4: Add `uniffi::setup_scaffolding!()` to `lib.rs`**

Edit `backend/ffi/src/lib.rs` to add at the top:
```rust
#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();
```

This macro generates the C-callable FFI entry points that the UniFFI scaffolding needs. It must appear at the crate root (not in a submodule).

**Step 5: Attempt to build with uniffi feature**

```bash
cd backend/ffi && cargo build --no-default-features --features uniffi 2>&1 | head -60
```

Expected: compile errors are likely here — work through them in Task 4.

---

## Task 4: Fix Compile Errors

**Files:**
- Modify: `backend/ffi/src/wrappers/uniffi_bindings.rs` (as needed)

**Context:** The most likely compile issues and how to fix each:

**Issue A — `bytes` crate not found:**
Add `bytes = "1"` to `backend/ffi/Cargo.toml` under `[dependencies]` (covered in Task 2 but double-check).

**Issue B — `http` version mismatch:**
`napi.rs` uses `http = "0.2"` (check `backend/ffi/Cargo.toml`). If the version is `0.2`, then `http::HeaderMap`, `http::header::HeaderName`, `http::header::HeaderValue` are the same API. If it shows version `1.x`, the import path is unchanged but note the crate version.

**Issue C — `domain_types::router_response_types::Response` field names:**
The `Response` struct in `napi.rs` uses `status_code: api_response.status` (a `u16`). Our `authorize_res` receives `status_code: u16` directly — this is fine. Verify the `Response` struct definition:
```bash
grep -n "pub struct Response" backend/domain_types/src/router_response_types.rs
```
Adjust field names if they differ.

**Issue D — `uniffi::Error` derive requires `thiserror`:**
UniFFI 0.28's `#[derive(uniffi::Error)]` works with `thiserror`. If not available, replace with a simpler error enum without `thiserror` and implement `std::fmt::Display` and `std::error::Error` manually.

**Issue E — `HashMap` not recognized in UniFFI export:**
UniFFI 0.28 supports `HashMap<String, String>` natively. If it complains, ensure the import is `use std::collections::HashMap;` (not `hashbrown`).

**Step 1: Run build and capture first error**

```bash
cd backend/ffi && cargo build --no-default-features --features uniffi 2>&1 | grep "^error" | head -10
```

**Step 2: Fix each error, re-run, repeat until clean**

```bash
cd backend/ffi && cargo build --no-default-features --features uniffi 2>&1 | tail -20
```
Expected final output: `Finished` line with no errors.

**Step 3: Also verify napi still builds**

```bash
cd backend/ffi && cargo build --features napi 2>&1 | tail -5
```
Expected: `Finished` with no errors. The `uniffi_bindings.rs` module is fully gated by `#[cfg(feature = "uniffi")]` so it must not break the napi build.

**Step 4: Commit**

```bash
git add backend/ffi/Cargo.toml backend/ffi/src/lib.rs backend/ffi/src/wrappers.rs backend/ffi/src/wrappers/uniffi_bindings.rs
git commit -m "feat(ffi): add uniffi bindings with protobuf boundary for authorize_req and authorize_res"
```

---

## Task 5: Generate UniFFI Bindings and Verify the Scaffold

**Files:**
- No source changes — verification only

**Context:** UniFFI generates language bindings (Python `.py`, Kotlin `.kt`, Swift `.swift`) by inspecting the compiled library. We verify the scaffolding is correct before building the example.

**Step 1: Install uniffi-bindgen if not present**

```bash
cargo install uniffi-bindgen --version 0.28 2>&1 | tail -3
```

**Step 2: Build the shared library**

```bash
cd backend/ffi && cargo build --no-default-features --features uniffi --release 2>&1 | tail -5
```
The `.dylib` (macOS) or `.so` (Linux) will be at:
`target/release/libconnector_service_ffi.dylib` (macOS)
`target/release/libconnector_service_ffi.so` (Linux)

**Step 3: Generate Python bindings to verify the UDL**

UniFFI proc-macro mode (our approach) doesn't require a `.udl` file — it generates one from the Rust source. Generate the Python scaffolding:

```bash
cd backend/ffi && \
  cargo run --no-default-features --features uniffi \
    --bin uniffi-bindgen -- \
    generate \
    --library target/release/libconnector_service_ffi.dylib \
    --language python \
    --out-dir /tmp/uniffi-check \
    2>&1
```

> **Note:** If `uniffi-bindgen` binary isn't a bin target in the crate, use the standalone tool:
> ```bash
> uniffi-bindgen generate \
>   --library backend/ffi/target/release/libconnector_service_ffi.dylib \
>   --language python \
>   --out-dir /tmp/uniffi-check
> ```

**Step 4: Inspect the generated Python**

```bash
ls /tmp/uniffi-check/
cat /tmp/uniffi-check/connector_service_ffi.py | head -60
```
Expected: a Python file containing `authorize_req` and `authorize_res` function definitions, and an `UniffiError` class.

**Step 5: Commit nothing** — this was verification only.

---

## Task 6: Create the Python Example

**Files:**
- Create: `examples/example-uniffi-py/` (new directory)
- Create: `examples/example-uniffi-py/Makefile`
- Create: `examples/example-uniffi-py/main.py`
- Create: `examples/example-uniffi-py/README.md`

**Context:** The example shows the full round-trip: build the proto request in Python, call `authorize_req` via UniFFI, get back the connector HTTP request JSON. It does NOT actually call the connector (no real HTTP call) — it demonstrates the FFI boundary is working correctly.

The example uses `payment_pb2` which the caller already knows how to generate (same proto files, same Makefile pattern as `examples/example-py/`).

**Step 1: Create directory**

```bash
mkdir -p examples/example-uniffi-py
```

**Step 2: Create the Makefile**

Create `examples/example-uniffi-py/Makefile`:

```makefile
.PHONY: build-lib generate-bindings install-deps run clean

# Path to the ffi crate
FFI_CRATE=../../backend/ffi
# Proto files
PROTO_DIR=../../backend/grpc-api-types/proto
PYTHON_OUT=./generated

# Build the Rust shared library with uniffi feature
build-lib:
	@echo "Building UniFFI shared library..."
	@cd $(FFI_CRATE) && cargo build --no-default-features --features uniffi --release
	@echo "Build complete."

# Generate UniFFI Python bindings from the compiled library
generate-bindings: build-lib
	@echo "Generating UniFFI Python bindings..."
	@mkdir -p $(PYTHON_OUT)
	@uniffi-bindgen generate \
		--library $(FFI_CRATE)/target/release/libconnector_service_ffi.dylib \
		--language python \
		--out-dir $(PYTHON_OUT)
	@echo "UniFFI bindings generated in $(PYTHON_OUT)/"

# Generate Python protobuf stubs (same as example-py)
generate-proto:
	@echo "Generating Python protobuf stubs..."
	@mkdir -p $(PYTHON_OUT)
	@python -m grpc_tools.protoc \
		-I $(PROTO_DIR) \
		--python_out=$(PYTHON_OUT) \
		--pyi_out=$(PYTHON_OUT) \
		$(PROTO_DIR)/payment.proto $(PROTO_DIR)/payment_methods.proto
	@touch $(PYTHON_OUT)/__init__.py
	@echo "Proto stubs generated."

# Install Python dependencies
install-deps:
	@echo "Installing Python dependencies..."
	@pip install grpcio grpcio-tools uniffi-python
	@echo "Done."

# Full setup: build lib, generate both bindings and proto stubs
setup: install-deps generate-proto generate-bindings

# Run the example
run:
	@python main.py

clean:
	@rm -rf $(PYTHON_OUT)
```

> **macOS vs Linux note:** Change `.dylib` to `.so` on Linux. The Makefile can be made cross-platform with:
> ```makefile
> UNAME := $(shell uname)
> ifeq ($(UNAME), Darwin)
>   LIB_EXT = dylib
> else
>   LIB_EXT = so
> endif
> ```

**Step 3: Create `main.py`**

Create `examples/example-uniffi-py/main.py`:

```python
"""
UniFFI FFI example: authorize_req

Demonstrates calling the connector FFI directly from Python using
protobuf-encoded bytes at the boundary, without going through gRPC.

Flow:
  1. Build PaymentServiceAuthorizeRequest as a Python protobuf object
  2. Serialize it to bytes
  3. Pass bytes + metadata to authorize_req via UniFFI
  4. Receive back the connector HTTP request JSON

Prerequisites (run `make setup` first):
  - generated/connector_service_ffi.py  (UniFFI bindings)
  - generated/payment_pb2.py            (protobuf stubs)
"""

import json
import os
import sys

sys.path.insert(0, "./generated")

# UniFFI-generated Python module
from connector_service_ffi import authorize_req, UniffiError

# Protobuf-generated stubs (same protos as the gRPC example)
from payment_pb2 import PaymentServiceAuthorizeRequest
from payment_methods_pb2 import (
    PaymentMethod,
    CardDetails,
)


def build_authorize_request() -> bytes:
    """Build a PaymentServiceAuthorizeRequest and serialize to protobuf bytes."""
    req = PaymentServiceAuthorizeRequest()
    req.amount = 1000
    req.minor_amount = 1000
    req.currency = 3  # USD — see Currency enum in payment.proto

    # Minimal card payment method
    card = req.payment_method.card
    # CardDetails fields — see payment_methods.proto
    # card_number is a CardNumberType (extern_path → cards::CardNumber)
    # In Python protobuf, it's just a string field on the wire
    card.card_exp_month = "03"
    card.card_exp_year = "2030"
    card.card_cvc = "737"

    req.auth_type = 1  # THREE_DS

    return req.SerializeToString()


def build_metadata() -> dict:
    """
    Build the metadata map that the FFI layer uses for connector routing and auth.

    Keys:
      connector           — connector name (matches ConnectorEnum variant, snake_case)
      connector_auth_type — JSON-encoded ConnectorAuthType variant
    """
    return {
        "connector": "stripe",
        "connector_auth_type": json.dumps({
            "HeaderKey": {
                "api_key": os.getenv("STRIPE_API_KEY", "sk_test_placeholder")
            }
        }),
    }


def main():
    print("=== UniFFI FFI authorize_req example ===\n")

    request_bytes = build_authorize_request()
    metadata = build_metadata()

    print(f"Request proto bytes: {len(request_bytes)} bytes")
    print(f"Connector: {metadata['connector']}\n")

    try:
        connector_request_json = authorize_req(request_bytes, metadata)
        connector_request = json.loads(connector_request_json)

        print("Connector HTTP request generated successfully:")
        print(f"  URL:    {connector_request.get('url', 'N/A')}")
        print(f"  Method: {connector_request.get('method', 'N/A')}")
        print(f"  Headers: {list(connector_request.get('headers', {}).keys())}")
        print(f"\nFull request JSON:\n{json.dumps(connector_request, indent=2)}")

    except UniffiError as e:
        print(f"FFI error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
```

**Step 4: Create README**

Create `examples/example-uniffi-py/README.md`:

```markdown
# UniFFI Python FFI Example

Calls the connector FFI layer directly from Python using protobuf-encoded bytes,
bypassing gRPC. Uses UniFFI-generated Python bindings.

## Setup

```bash
# 1. Install Python deps and build the Rust library
make setup

# 2. Run the example
STRIPE_API_KEY=sk_test_your_key make run
```

## How it works

1. `make build-lib` — builds `backend/ffi` with `--features uniffi`
2. `make generate-bindings` — runs `uniffi-bindgen` to produce `generated/connector_service_ffi.py`
3. `make generate-proto` — runs `grpc_tools.protoc` to produce `generated/payment_pb2.py`
4. `main.py` — builds a `PaymentServiceAuthorizeRequest`, serializes to proto bytes,
   calls `authorize_req(bytes, metadata)`, prints the connector HTTP request

## Difference from `example-py`

| | `example-py` | `example-uniffi-py` |
|--|--|--|
| Transport | gRPC | Direct FFI (in-process) |
| Serialization | Proto over gRPC | Proto bytes at FFI boundary |
| Server required | Yes | No |
```

**Step 5: Commit**

```bash
git add examples/example-uniffi-py/
git commit -m "feat(examples): add Python UniFFI FFI example for authorize_req"
```

---

## Task 7: Run the Example End-to-End

**Files:** None — execution only.

**Step 1: Install deps**

```bash
cd examples/example-uniffi-py && make install-deps
```
Expected: pip installs `grpcio grpcio-tools uniffi-python`.

**Step 2: Generate proto stubs**

```bash
cd examples/example-uniffi-py && make generate-proto
```
Expected: `generated/payment_pb2.py` and `generated/payment_methods_pb2.py` created.

**Step 3: Build the Rust lib**

```bash
cd examples/example-uniffi-py && make build-lib 2>&1 | tail -5
```
Expected: `Finished release [optimized]` line.

**Step 4: Generate UniFFI Python bindings**

```bash
cd examples/example-uniffi-py && make generate-bindings 2>&1
```
Expected: `generated/connector_service_ffi.py` created.

If this fails with "symbol not found" or "no exported symbols", the `uniffi::setup_scaffolding!()` call in `lib.rs` may be missing — go back to Task 3 Step 4.

**Step 5: Run**

```bash
cd examples/example-uniffi-py && STRIPE_API_KEY=sk_test_placeholder make run
```
Expected output:
```
=== UniFFI FFI authorize_req example ===

Request proto bytes: N bytes
Connector: stripe

Connector HTTP request generated successfully:
  URL:    https://api.stripe.com/v1/payment_intents
  Method: POST
  Headers: ['Authorization', 'Content-Type', ...]

Full request JSON:
{
  "url": "...",
  "method": "POST",
  ...
}
```

If you see a `HandlerError`, check that the `connector` value in metadata matches a `ConnectorEnum` variant exactly (e.g., `"stripe"` not `"Stripe"`).

**Step 6: Commit any fixes**

```bash
git add -p
git commit -m "fix(ffi/uniffi): correct any issues found during end-to-end run"
```

---

## Task 8: Clippy and Final Verification

**Files:** Fix any warnings in `backend/ffi/src/wrappers/uniffi_bindings.rs`.

**Step 1: Run clippy on the uniffi feature**

```bash
cd backend/ffi && cargo clippy --no-default-features --features uniffi 2>&1
```
Fix any warnings (unused imports, needless borrows, etc.).

**Step 2: Run clippy on napi feature to confirm no regression**

```bash
cd backend/ffi && cargo clippy --features napi 2>&1
```

**Step 3: Final commit**

```bash
git add backend/ffi/src/wrappers/uniffi_bindings.rs
git commit -m "chore(ffi): fix clippy warnings in uniffi bindings"
```

---

## Summary of All New/Modified Files

| Action | File |
|--------|------|
| Modify | `backend/ffi/Cargo.toml` — add `prost`, `bytes`, `thiserror` deps |
| Modify | `backend/ffi/src/lib.rs` — add `uniffi::setup_scaffolding!()` |
| Modify | `backend/ffi/src/wrappers.rs` — add `pub mod uniffi_bindings` |
| Create | `backend/ffi/src/wrappers/uniffi_bindings.rs` — UniFFI wrapper |
| Create | `examples/example-uniffi-py/Makefile` |
| Create | `examples/example-uniffi-py/main.py` |
| Create | `examples/example-uniffi-py/README.md` |

## Files NOT Modified

| File | Reason |
|------|--------|
| `backend/ffi/src/handlers/payments.rs` | All business logic stays here; UniFFI is a thin wrapper |
| `backend/ffi/src/wrappers/napi.rs` | NAPI bindings unchanged |
| `backend/grpc-api-types/` | Proto types already implement `prost::Message`; no changes needed |
| `backend/ffi/build.rs` | UniFFI proc-macro mode needs no build script changes |
