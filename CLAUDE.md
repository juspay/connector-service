# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Common Development Commands

### Building the Project

```bash
# Compile the project
cargo build

# Build with optimizations
cargo build --release
```

### Running the Server

```bash
# Run the server
cargo run

# Run with a specific config file
cargo run -- --config path/to/config.toml
```

### Testing

```bash
# Run all tests
cargo test

# Run tests for a specific module
cargo test <module_name>

# Test with feature flags
cargo hack test --each-feature
```

### Code Quality

```bash
# Format code using nightly rustfmt
cargo +nightly fmt --all

# Run clippy on each feature (no dev dependencies)
cargo hack clippy --each-feature --no-dev-deps

# Run clippy with warnings as errors (CI mode)
cargo hack clippy --each-feature --no-dev-deps -- -D warnings

# Run all quality checks (fmt, check, clippy, test)
make all

# Run CI-mode checks (warnings as errors)
make ci
```

### gRPC Testing

```bash
# Test a gRPC service endpoint (example)
grpcurl -plaintext -d '{
    "connector_request_reference_id": "YOUR_CONNECTOR_REFERENCE_ID",
    "connector": "ADYEN",
    "auth_creds": {
        "signature_key": {
            "api_key": "CONNECTOR_API_KEY",
            "key1": "CONNECTOR_KEY",
            "api_secret": "CONNECTOR_API_SECRET"
        }
    }
}' localhost:8000 ucs.payments.PaymentService/VoidPayment
```

## Architecture Overview

The connector service is a stateless, Rust-based gRPC service that provides a unified interface for payment operations across multiple payment processors. The architecture consists of the following key components:

### 1. gRPC Server (`backend/grpc-server`)

- Entry point for client requests
- Converts gRPC requests to domain types
- Delegates processing to connector integrations
- Returns responses to clients
- Implements server-side request handling

### 2. Connector Integration (`backend/connector-integration`)

- Contains payment processor-specific implementations
- Uses a trait-based system for connector implementations
- Converts domain types to connector-specific formats
- Handles HTTP communication with payment processors
- Processes responses from payment processors

### 3. Domain Types (`backend/domain_types`)

- Common data structures shared between components
- Defines connector-agnostic payment flows
- Contains error types and utilities
- Provides intermediate representations for data conversions

### 4. gRPC API Types (`backend/grpc-api-types`)

- Defines gRPC service interfaces via Protocol Buffers
- Contains auto-generated code from proto files
- Specifies request and response structures

### 5. SDK Clients (`sdk/`)

- Language-specific client implementations
- Provides easy integration for various programming languages
- Handles gRPC communication details

## Core Design Patterns

### 1. Trait-Based Connector Integration

Connectors implement the `ConnectorIntegration` trait for each payment flow they support:

```rust
trait ConnectorIntegration<Flow, ResourceCommonData, Req, Resp> {
  fn get_headers();
  fn get_content_type();
  fn get_http_method();
  fn get_url();
  fn get_request_body();
  fn build_request();
  fn handle_response();
  fn get_error_response();
}
```

### 2. Flow-Based Architecture

The system uses generic type parameters to represent different payment flows:
- `Authorize`: Authorize a payment
- `Capture`: Capture previously authorized funds
- `Void`: Cancel a previously authorized payment
- `Refund`: Refund previously captured funds
- `PSync`: Check payment status
- `RSync`: Check refund status
- `SetupMandate`: Set up a recurring payment mandate
- And others (disputes, order creation, etc.)

### 3. Macro Framework for Connector Implementation

A sophisticated macro system in `macros.rs` reduces boilerplate when implementing new connectors:

```rust
macros::create_all_prerequisites!(
    connector_name: ConnectorName,
    api: [
        (flow: FlowType, request_body: RequestStruct, response_body: ResponseStruct, router_data: RouterDataType)
        // ...more flows
    ],
    // ...
);

macros::macro_connector_implementation!(
    connector: ConnectorName,
    flow_name: FlowType,
    // ...other parameters
);
```

### 4. Router Data Pattern

The `RouterDataV2` struct encapsulates all data for a payment operation:
- Flow-specific type parameters
- Common resource data
- Connector authentication details
- Request and response data

## Adding a New Connector

To add a new payment processor connector:

1. Create a connector directory structure:
   ```
   backend/connector-integration/src/connectors/
   ├── <connector_name>/
   │   ├── transformers.rs    # Request/Response structs and TryFrom implementations
   │   └── test.rs            # Tests
   └── <connector_name>.rs    # Main connector logic
   ```

2. Define connector-specific request and response structs in `transformers.rs`

3. Implement `TryFrom` for converting between domain types and connector types

4. Set up the connector using the macro framework:
   ```rust
   macros::create_all_prerequisites!(/* ... */);
   macros::macro_connector_implementation!(/* ... */);
   ```

5. Implement the `ConnectorCommon` trait for common functionality

6. Implement flow-specific marker traits for supported operations

## Working with the Codebase

1. Use the macro framework documentation in `macro_framework.md` and `connector_integration_macros.md` when implementing new connectors

2. Understand the payment flows defined in `domain_types` before modifying connector integrations

3. Test new implementations with gRPC requests using `grpcurl` or the client SDKs

4. Ensure code follows Rust best practices and passes `clippy` and `fmt` checks

5. Reference existing connectors (like Adyen and Razorpay) as implementation examples