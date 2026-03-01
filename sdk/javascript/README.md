# JavaScript Payments SDK

Calls the connector FFI layer directly from Node.js using the same UniFFI shared
library as the Python and Kotlin SDKs. Uses `koffi` to call the C ABI —
**no NAPI required**.

## Prerequisites

- Rust toolchain (`cargo`)
- Node.js 18+
- `npm`

## Setup

```bash
# Build Rust lib, generate bindings and proto stubs, build tarball
make pack
```

## Test

```bash
# Verify the packed tarball installs and the FFI layer works end-to-end
make test-pack

# With full round-trip (requires valid Stripe test key)
STRIPE_API_KEY=sk_test_your_key make test-pack
```

`test-pack` installs the tarball into an isolated temp directory and runs
`test_smoke.js`, which asserts the connector request URL and method, then
optionally exercises the full HTTP round-trip if `STRIPE_API_KEY` is set.

## Distribution

```bash
# Build tarball containing all available platform binaries (for CI / release)
make dist
# → artifacts/sdk-javascript/hyperswitch-payments-0.1.0.tgz
```

## How it works

1. `make build-lib` — builds `backend/ffi` with `--features uniffi`
2. `make generate-bindings` — symlinks the `.dylib`/`.so` into `generated/`
3. `make generate-proto` — runs `pbjs` to produce `generated/proto.js` and `proto.d.ts`
4. `make pack-archive` — runs `npm pack` to produce the installable `.tgz`

## Architecture

```
src/payments/connector_client.js   — high-level authorize() with HTTP round-trip
src/payments/uniffi_client.js      — UniFFI C ABI wrapper using koffi (RustBuffer protocol)
src/payments/generated/proto.js    — protobufjs static module (generated)
src/payments/generated/libconnector_service_ffi.*  — native shared library
```

No code generation needed for JS — `uniffi_client.js` manually implements the
UniFFI RustBuffer serialization protocol.
