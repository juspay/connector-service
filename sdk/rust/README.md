# Rust ConnectorClient Example

A Rust-native example that calls the connector service handler functions directly — no FFI serialization or gRPC overhead. This is the recommended approach for Rust consumers of the connector service library.

## How it works

Unlike the Python, Java, and JS examples (which serialize to protobuf bytes, call FFI, then deserialize), this example works with Rust types directly:

1. Build a `PaymentServiceAuthorizeRequest` (Rust proto struct)
2. Call `authorize_req_handler` → get a `Request` with URL, method, headers, body
3. Make the HTTP call with `reqwest`
4. Call `authorize_res_handler` → get a `PaymentServiceAuthorizeResponse`

No protobuf serialization/deserialization needed.

## Prerequisites

- Rust toolchain (rustup)
- For the full round-trip demo: a Stripe test API key

## Usage

### Build

```bash
# From the workspace root:
cargo build -p hyperswitch-payments-client

# Or from this directory:
make setup
```

### Run (low-level demo only)

```bash
cargo run -p hyperswitch-payments-client
```

This runs Demo 1 which shows the connector HTTP request JSON without making any external calls.

### Run with Stripe API key (full round-trip)

```bash
STRIPE_API_KEY=sk_test_xxx cargo run -p hyperswitch-payments-client
```

This runs both demos — Demo 1 shows the request, Demo 2 makes the actual HTTP call to Stripe.

## Project structure

```
sdk/rust/
├── Cargo.toml                 # Dependencies (internal crates + reqwest/tokio)
├── Makefile                   # Build and run targets
├── README.md                  # This file
└── src/
    ├── main.rs                # Two demos: low-level + full round-trip
    └── connector_client.rs    # ConnectorClient with async authorize()
```
