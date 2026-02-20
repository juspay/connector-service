# UniFFI Kotlin FFI Example

Calls the connector FFI layer directly from Kotlin/JVM using protobuf-encoded bytes,
bypassing gRPC. Uses UniFFI-generated Kotlin bindings with JNA.

## Prerequisites

- Rust toolchain (`cargo`)
- JDK 17+ (`java`, `javac`)
- `protoc` (Protocol Buffers compiler)

## Setup

```bash
# 1. Build Rust lib, generate UniFFI bindings and proto stubs
make setup

# 2. Run the example (low-level FFI demo only)
make run

# 3. Run with full round-trip (requires valid Stripe test key)
STRIPE_API_KEY=sk_test_your_key make run
```

## How it works

1. `make build-lib` — builds `backend/ffi` with `--features uniffi`
2. `make generate-bindings` — runs `uniffi-bindgen --language kotlin` to produce `generated/connector_service_ffi.kt`
3. `make generate-proto` — runs `protoc --java_out` to produce Java protobuf stubs (callable from Kotlin)
4. `./gradlew run` — two demos:
   - **Low-level FFI**: builds a `PaymentServiceAuthorizeRequest`, serializes to proto bytes,
     calls `authorizeReq(bytes, metadata)`, prints the connector HTTP request
   - **Full round-trip**: uses `ConnectorClient` to build request -> HTTP call -> parse response

## ConnectorClient

`ConnectorClient.kt` provides a high-level client that handles:
1. Serialize protobuf request to bytes
2. Call `authorizeReq` via FFI to get the connector HTTP request
3. Execute the HTTP request using OkHttp
4. Call `authorizeRes` via FFI to parse the connector response
5. Deserialize the protobuf response

## Difference from `example-py` / `example-uniffi-py`

| | `example-py` | `example-uniffi-py` | `example-uniffi-kt` |
|--|--|--|--|
| Language | Python | Python | Kotlin/JVM |
| Transport | gRPC | Direct FFI (in-process) | Direct FFI (in-process) |
| FFI mechanism | N/A | ctypes (UniFFI) | JNA (UniFFI) |
| HTTP client | N/A | requests | OkHttp |
| Build | pip + Makefile | pip + Makefile | Gradle + Makefile |
