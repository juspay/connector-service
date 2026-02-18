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
