# UniFFI Python FFI Example

Calls the connector FFI layer directly from Python using protobuf-encoded bytes,
bypassing gRPC. Uses UniFFI-generated Python bindings.

## Setup

```bash
# 1. Install Python deps and build the Rust library
make setup

# 2. Run the example (low-level FFI demo only)
make run

# 3. Run with full round-trip (requires valid Stripe test key)
STRIPE_API_KEY=sk_test_your_key make run
```

## How it works

1. `make build-lib` — builds `backend/ffi` with `--features uniffi`
2. `make generate-bindings` — runs `uniffi-bindgen` to produce `generated/connector_service_ffi.py`
3. `make generate-proto` — runs `grpc_tools.protoc` to produce `generated/payment_pb2.py`
4. `main.py` — two demos:
   - **Low-level FFI**: builds a `PaymentServiceAuthorizeRequest`, serializes to proto bytes,
     calls `authorize_req(bytes, metadata)`, prints the connector HTTP request
   - **Full round-trip**: uses `ConnectorClient` to build request → HTTP call → parse response

## ConnectorClient

`connector_client.py` provides a high-level `ConnectorClient` class that handles:
1. Serialize protobuf request to bytes
2. Call `authorize_req` via FFI to get the connector HTTP request
3. Execute the HTTP request using `requests`
4. Call `authorize_res` via FFI to parse the connector response
5. Deserialize the protobuf response

## Difference from `example-py`

| | `example-py` | `example-uniffi-py` |
|--|--|--|
| Transport | gRPC | Direct FFI (in-process) |
| Serialization | Proto over gRPC | Proto bytes at FFI boundary |
| Server required | Yes | No |
