# Technical Context: Connector Service

## Core Technologies

### Programming Languages

1. **Rust**: The primary implementation language for the Connector Service, chosen for its:
   - Memory safety without garbage collection
   - High performance
   - Strong type system
   - Excellent concurrency support
   - Robust error handling

2. **Protocol Buffers**: Used for defining the gRPC API contract, providing:
   - Language-agnostic interface definition
   - Efficient binary serialization
   - Automatic code generation for multiple languages

### Frameworks & Libraries

1. **Tonic**: Rust implementation of gRPC, used for:
   - Building the gRPC server
   - Handling request/response serialization
   - Managing connections and streaming

2. **Tokio**: Asynchronous runtime for Rust, providing:
   - Non-blocking I/O
   - Task scheduling
   - Concurrency primitives

3. **Serde**: Serialization/deserialization framework for Rust, used for:
   - JSON processing
   - Data structure conversion
   - Configuration handling

4. **error-stack**: Error handling library for Rust, used for:
   - Contextual error information
   - Error chaining
   - Detailed error reporting

### Communication Protocols

1. **gRPC**: Primary communication protocol between clients and the service, offering:
   - Efficient binary serialization
   - Strong typing
   - Bidirectional streaming
   - HTTP/2 transport

2. **HTTP/REST**: Used for communication with payment processors, as most provide REST APIs.

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

1. **Compilation**:
   ```shell
   cargo compile
   ```

2. **Building**:
   ```shell
   cargo build
   ```

3. **Running**:
   ```shell
   cargo run
   ```

4. **Testing**:
   ```shell
   cargo test
   ```

5. **Linting**:
   ```shell
   cargo clippy
   ```

6. **Formatting**:
   ```shell
   cargo +nightly fmt --all
   ```

### Project Structure

The project follows a modular structure with separate crates for different components:

1. **backend/connector-integration**: Contains connector implementations
2. **backend/domain-types**: Common data structures and type conversions
3. **backend/grpc-api-types**: gRPC API definitions
4. **backend/grpc-server**: gRPC server implementation
5. **sdk**: Client SDKs for different languages

### Configuration

The service uses TOML configuration files located in the `config/` directory:

- **development.toml**: Configuration for development environment
- Additional environment-specific configurations can be added

## Dependencies

### External Libraries

1. **hyperswitch-common-utils**: Utility functions and common types
2. **hyperswitch-domain-models**: Domain model definitions
3. **hyperswitch-interfaces**: Interface definitions for connectors
4. **hyperswitch-masking**: Data masking utilities for sensitive information
5. **error-stack**: Error handling library
6. **tonic**: gRPC implementation for Rust
7. **prost**: Protocol Buffers implementation for Rust
8. **tokio**: Asynchronous runtime
9. **serde**: Serialization/deserialization framework
10. **tracing**: Logging and tracing

### Internal Dependencies

1. **connector-integration** depends on:
   - domain-types
   - hyperswitch-interfaces
   - hyperswitch-domain-models

2. **grpc-server** depends on:
   - connector-integration
   - domain-types
   - grpc-api-types
   - external-services

3. **domain-types** depends on:
   - grpc-api-types
   - hyperswitch-domain-models

## Deployment Considerations

### Containerization

The service can be containerized using Docker:

```dockerfile
# Dockerfile is provided in the root directory
```

### Scaling

As a stateless service, the Connector Service can be horizontally scaled by:
- Running multiple instances behind a load balancer
- Deploying in a Kubernetes cluster
- Using auto-scaling based on load metrics

### Monitoring

The service includes:
- Logging using the tracing library
- Metrics collection points
- Health check endpoints

## Testing

### Testing Approach

1. **Unit Tests**: Test individual components in isolation
2. **Integration Tests**: Test interactions between components
3. **End-to-End Tests**: Test complete payment flows

### Test Tools

1. **cargo test**: Run Rust tests
2. **grpcurl**: Test gRPC endpoints manually
3. **Example clients**: Test with provided example implementations

## Security Considerations

### Data Protection

1. **Sensitive Data Masking**: Payment card data and other sensitive information is masked in logs
2. **No Persistent Storage**: The service does not store sensitive payment data

### Authentication

1. **Connector Authentication**: Authentication details for payment processors are passed through metadata
2. **API Security**: The service should be deployed behind appropriate authentication mechanisms

### Transport Security

1. **TLS**: gRPC connections should be secured with TLS in production
2. **Secure Communication**: All communication with payment processors uses HTTPS

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

1. **Connector Support**: Limited to implemented payment processors
2. **Payment Methods**: Support varies by connector implementation
3. **Statelessness**: No built-in state management for multi-step payment flows
4. **Authentication**: No built-in authentication mechanism for client requests
5. **Rate Limiting**: No built-in rate limiting for payment processor APIs

## Development Workflow

### Adding a New Connector

1. Create a new module in `backend/connector-integration/src/connectors/`
2. Implement the `ConnectorIntegration` trait for each supported payment flow
3. Implement the `IncomingWebhook` trait for webhook handling
4. Add the connector to the connector registry
5. Add tests for the connector implementation

### Modifying the API

1. Update the Protocol Buffer definitions in `backend/grpc-api-types/proto/`
2. Regenerate the gRPC code
3. Update the corresponding handler in `backend/grpc-server/src/server/`
4. Update the domain type conversions in `backend/domain-types/src/`
5. Update client SDKs to reflect the API changes

### Release Process

1. Run tests to ensure functionality
2. Run linting to ensure code quality
3. Update version numbers
4. Create a release build
5. Deploy the new version
