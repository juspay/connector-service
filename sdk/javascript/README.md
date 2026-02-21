# UniFFI Node.js FFI Example

Calls the connector FFI layer directly from Node.js using the same UniFFI shared
library as the Python and Kotlin examples. Uses `koffi` to call the C ABI —
**no NAPI required**.

## Prerequisites

- Rust toolchain (`cargo`)
- Node.js 18+ (for built-in `fetch`)
- `npm`

## Setup

```bash
# 1. Install deps, build Rust lib, symlink .dylib
make setup

# 2. Run the example (low-level FFI demo only)
make example-run

# 3. Run with full round-trip (requires valid Stripe test key)
STRIPE_API_KEY=sk_test_your_key make example-run
```

## How it works

1. `make build-lib` — builds `backend/ffi` with `--features uniffi`
2. `make generate-bindings` — symlinks the `.dylib` into `generated/`
3. `npm install` — installs `koffi` (FFI) and `protobufjs` (proto encoding)
4. `node main.js` — two demos:
   - **Low-level FFI**: builds a protobuf request, calls `authorizeReq` via UniFFI C ABI
   - **Full round-trip**: uses `ConnectorClient` to build request -> HTTP call -> parse response

## Architecture

```
main.js                    — demo entry point, builds protobuf via protobufjs
connector_client.js        — high-level authorize() with HTTP round-trip
uniffi_client.js           — UniFFI C ABI wrapper using koffi (RustBuffer protocol)
generated/libconnector_service_ffi.dylib — same binary as Python/Kotlin use
```

No code generation needed for JS — `uniffi_client.js` manually implements the
UniFFI RustBuffer serialization protocol (~180 lines).
