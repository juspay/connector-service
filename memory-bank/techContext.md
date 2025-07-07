# Technical Context: Connector Service

## Core Technologies

### Programming Languages

1. **Rust**: The primary implementation language for the Connector Service, chosen for its:
   - Memory safety without garbage collection
   - High performance for payment processing workloads
   - Strong type system ensuring correctness across 11 flow types
   - Excellent concurrency support for handling 6 production connectors
   - Robust error handling with error-stack integration

2. **Protocol Buffers**: Used for defining the three-service gRPC API contract, providing:
   - Language-agnostic interface definition for PaymentService, RefundService, DisputeService
   - Efficient binary serialization
   - Automatic code generation for multiple languages
   - Strong typing across service boundaries

### Frameworks & Libraries

1. **Tonic 0.13.0**: Rust implementation of gRPC, used for:
   - Building the three-service gRPC server (PaymentService, RefundService, DisputeService)
   - Handling request/response serialization across service boundaries
   - Managing connections and streaming
   - gRPC reflection support for development

2. **Tokio 1.44.2**: Asynchronous runtime for Rust, providing:
   - Non-blocking I/O for concurrent connector requests
   - Multi-threaded task scheduling
   - Concurrency primitives for payment processing
   - Signal handling for graceful shutdown

3. **Serde 1.0.189**: Serialization/deserialization framework for Rust, used for:
   - JSON processing for connector APIs
   - Data structure conversion between gRPC and domain types
   - Configuration handling (TOML files)
   - Derive macro support for automatic serialization

4. **error-stack 0.4.1**: Error handling library for Rust, used for:
   - Contextual error information across connector operations
   - Error chaining from gRPC to connector layers
   - Detailed error reporting for payment failures

### Communication Protocols

1. **gRPC**: Primary communication protocol between clients and the three services, offering:
   - Efficient binary serialization with Protocol Buffers
   - Strong typing across PaymentService, RefundService, DisputeService
   - HTTP/2 transport with multiplexing
   - Metadata-based authentication for connector selection

2. **HTTP/REST**: Used for communication with the 6 production payment processors:
   - HTTPS communication with Adyen, Razorpay, Checkout.com, Fiserv, Elavon, Xendit
   - JSON request/response handling
   - Webhook processing for real-time events

## Development Environment

### Prerequisites

1. **Rust and Cargo**: Required for building and running the service
   ```shell
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

2. **grpcurl**: Command-line tool for interacting with gRPC services
   ```shell
   # MacOS
   brew install grpcurl
   
   # Linux
   curl -sLO https://github.com/fullstorydev/grpcurl/releases/latest/download/grpcurl_$(uname -s)_$(uname -m).tar.gz
   tar -xzf grpcurl_$(uname -s)_$(uname -m).tar.gz
   sudo mv grpcurl /usr/local/bin/
   ```

### Build System

The project uses Cargo, Rust's package manager and build system:

1. **Building**:
   ```shell
   cargo build --release
   ```

2. **Running the gRPC server**:
   ```shell
   cargo run --bin grpc-server
   ```

3. **Testing** (includes integration tests for 6 connectors):
   ```shell
   cargo test
   ```

4. **Linting**:
   ```shell
   cargo clippy --all-targets --all-features
   ```

5. **Formatting**:
   ```shell
   cargo fmt --all
   ```

6. **Workspace operations** (multi-crate project):
   ```shell
   cargo build --workspace
   cargo test --workspace
   ```

### Project Structure

The project follows a modular workspace structure with separate crates for different components:

1. **backend/connector-integration**: Contains 6 production connector implementations (Adyen, Razorpay, Checkout.com, Fiserv, Elavon, Xendit)
2. **backend/domain_types**: Common data structures, flow definitions, and type conversions
3. **backend/grpc-api-types**: gRPC API definitions for three services (PaymentService, RefundService, DisputeService)
4. **backend/grpc-server**: Three-service gRPC server implementation
5. **backend/interfaces**: ConnectorIntegrationV2 trait and authentication interfaces
6. **backend/external-services**: HTTP client and external service interactions
7. **backend/common_utils**: Shared utilities, request handling, and error management
8. **backend/common_enums**: Shared enumerations (AttemptStatus, PaymentMethod, etc.)
9. **backend/cards**: Card validation and processing utilities
10. **sdk**: Client SDKs for different languages

### Configuration

The service uses TOML configuration files located in the `config/` directory:

- **development.toml**: Configuration for development environment including:
  - gRPC server settings (host: 127.0.0.1, port: 8000)
  - Metrics endpoint (port: 8080)
  - Logging configuration (TRACE level)
  - All 6 production connector base URLs (Adyen, Razorpay, Fiserv, Elavon, Xendit, Checkout.com)
  - Proxy settings and timeout configurations
- Additional environment-specific configurations can be added

## Dependencies

### External Libraries

1. **tonic 0.13.0**: gRPC implementation for Rust with reflection support
2. **tokio 1.44.2**: Asynchronous runtime with multi-threading and signal handling
3. **serde 1.0.189**: Serialization/deserialization framework with derive macros
4. **error-stack 0.4.1**: Contextual error handling library
5. **tracing 0.1.40**: Logging and distributed tracing
6. **config 0.14.0**: Configuration file handling (TOML)
7. **axum 0.8.3**: HTTP server framework for metrics and health endpoints
8. **prometheus 0.13.4**: Metrics collection and exposition
9. **tower-http 0.6.2**: HTTP middleware for tracing and request IDs
10. **hyper 1.6.0**: HTTP implementation
11. **base64 0.21.2**: Base64 encoding for authentication
12. **log_utils**: Juspay framework logging utilities
13. **build_info**: Build information and versioning

### Internal Dependencies

1. **connector-integration** depends on:
   - domain_types (flow definitions and data structures)
   - interfaces (ConnectorIntegrationV2 trait)
   - common_utils (HTTP client and utilities)
   - common_enums (status enums and payment types)

2. **grpc-server** depends on:
   - connector-integration (connector implementations)
   - domain_types (shared data structures)
   - grpc-api-types (protobuf generated types)
   - external-services (HTTP service layer)
   - interfaces (trait definitions)
   - common_utils (error handling and utilities)

3. **domain_types** depends on:
   - grpc-api-types (protobuf message types)
   - common_enums (shared enumerations)
   - common_utils (type conversion utilities)

## Deployment Considerations

### Containerization

The service can be containerized using Docker:

```dockerfile
# Dockerfile is provided in the root directory
```

### Scaling

As a stateless service, the Connector Service can be horizontally scaled by:
- Running multiple instances behind a load balancer
- Deploying in a Kubernetes cluster with independent scaling of the three services
- Using auto-scaling based on payment processing load metrics
- Service-specific scaling (PaymentService, RefundService, DisputeService can scale independently)

### Monitoring

The service includes comprehensive observability:
- **Logging**: Structured logging using tracing library with TRACE level support
- **Metrics**: Prometheus metrics exposed on port 8080 for monitoring payment flows
- **Health Checks**: Built-in health check endpoints for service monitoring
- **Request Tracing**: Request ID tracking and distributed tracing support
- **Build Information**: Version and build metadata for deployment tracking

## Testing

### Testing Approach

1. **Unit Tests**: Test individual components in isolation (ConnectorIntegrationV2 implementations)
2. **Integration Tests**: Test interactions between gRPC services and connector integrations
3. **Connector Tests**: Comprehensive test coverage for all 6 production connectors
4. **Flow Tests**: End-to-end testing of all 11 payment flow types
5. **Webhook Tests**: Verification of IncomingWebhook trait implementations

### Test Tools

1. **cargo test**: Run Rust unit and integration tests across workspace
2. **grpcurl**: Test all three gRPC services manually (PaymentService, RefundService, DisputeService)
3. **Example clients**: Test with provided multi-language SDK implementations
4. **Connector Test Suites**: Individual test files for each connector (Adyen, Razorpay, etc.)
5. **Development Test Files**: Located in backend/grpc-server/tests/ for service-specific testing

## Security Considerations

### Data Protection

1. **Sensitive Data Masking**: Payment card data and other sensitive information is masked in logs using masking utilities
2. **No Persistent Storage**: The stateless service does not store sensitive payment data
3. **Base64 Encoding**: Secure handling of authentication credentials with base64 encoding

### Authentication

1. **gRPC Metadata Authentication**: Connector selection and authentication passed through gRPC metadata headers:
   - `x-connector`: Connector name (adyen, razorpay, etc.)
   - `x-auth`: Authentication type (header-key, signature-key, etc.)
   - `x-api-key`: API credentials
2. **Connector-Specific Auth**: Support for different authentication methods per connector
3. **API Security**: Service designed for deployment behind appropriate authentication mechanisms

### Transport Security

1. **TLS**: gRPC connections secured with TLS in production environments
2. **HTTPS**: All communication with 6 production payment processors uses HTTPS
3. **Webhook Verification**: Built-in webhook source verification for secure event processing

## Performance Characteristics

### Resource Requirements

1. **CPU**: Moderate usage, primarily for request processing and data transformation
2. **Memory**: Low to moderate, depending on concurrent request volume
3. **Network**: Moderate, for handling client requests and payment processor communication

### Scalability

1. **Horizontal Scaling**: Add more instances to handle increased load
2. **Vertical Scaling**: Increase resources for individual instances if needed

### Latency Considerations

1. **Request Processing**: Typically low latency for request transformation
2. **External Calls**: Payment processor API calls dominate the overall latency
3. **Response Handling**: Minimal latency for response transformation

## Constraints and Limitations

1. **Connector Support**: Currently limited to 6 production connectors (Adyen, Razorpay, Checkout.com, Fiserv, Elavon, Xendit) with framework support for 90+ potential connectors
2. **Payment Methods**: Support varies by connector implementation, currently focusing on card and token-based payments
3. **Statelessness**: No built-in state management for multi-step payment flows - external state management required
4. **Authentication**: No built-in authentication mechanism for client requests - designed for deployment behind auth layer
5. **Rate Limiting**: No built-in rate limiting for payment processor APIs - handled at infrastructure level
6. **Flow Completeness**: Some operations return placeholder responses (PaymentService.Dispute, DisputeService.Get)

## Development Workflow

### Adding a New Connector

1. Create a new module in `backend/connector-integration/src/connectors/`
2. Implement the `ConnectorIntegrationV2` trait for all 11 supported flow types:
   - Authorize, PSync, Void, Capture, Refund, RSync, SetupMandate, Accept, SubmitEvidence, DefendDispute, CreateOrder
3. Implement the `IncomingWebhook` trait for webhook handling across all three service domains
4. Add the connector to the connector registry in `connectors.rs`
5. Add comprehensive tests following the pattern of existing connector tests
6. Add connector configuration to `config/development.toml`

### Modifying the API

1. Update the Protocol Buffer definitions in `backend/grpc-api-types/proto/`:
   - `services.proto` for service method changes
   - `payment.proto` for message type changes
2. Regenerate the gRPC code using build scripts
3. Update the corresponding handlers in `backend/grpc-server/src/server/`:
   - `payments.rs` for PaymentService changes
   - `refunds.rs` for RefundService changes
   - `disputes.rs` for DisputeService changes
4. Update domain type conversions in `backend/domain_types/src/`
5. Update all client SDKs to reflect the API changes across three services

### Release Process

1. **Testing**: Run comprehensive tests across workspace
   ```shell
   cargo test --workspace
   ```
2. **Linting**: Ensure code quality with clippy and formatting
   ```shell
   cargo clippy --all-targets --all-features
   cargo fmt --all
   ```
3. **Integration Testing**: Verify all 6 connector integrations
4. **Version Management**: Update version numbers in workspace Cargo.toml files
5. **Release Build**: Create optimized release build
   ```shell
   cargo build --release --workspace
   ```
6. **Service Verification**: Test all three gRPC services (PaymentService, RefundService, DisputeService)
7. **Deployment**: Deploy the new version with appropriate configuration
