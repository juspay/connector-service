# System Patterns: Connector Service Architecture

## High-Level Architecture

The Connector Service comprises two major runtime components:

1. **gRPC Service**: Offers a unified interface for all merchant payment operations supported by different payment processors around the world.

2. **Client SDKs**: Language-specific clients that integrate into applications to invoke the gRPC service.

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│                 │     │                 │     │                 │
│  Client App     │────▶│  Client SDK     │────▶│  gRPC Service   │────▶ Payment Processors
│  (User Code)    │     │  (Lang-specific)│     │  (Rust)         │     (Adyen, Razorpay, etc.)
│                 │     │                 │     │                 │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

## Component Structure

The codebase is organized into the following key components:

```
connector-service/
├── backend/
│   ├── connector-integration/  # Payment processor integrations
│   ├── domain-types/           # Common data structures
│   ├── grpc-api-types/         # gRPC interface definitions
│   │   └── proto/              # Protocol buffer definitions
│   ├── grpc-server/            # gRPC server implementation
│   └── external-services/      # External service interactions
├── sdk/                        # Client SDKs
│   ├── node-grpc-client/       # Node.js client
│   ├── python-grpc-client/     # Python client
│   └── rust-grpc-client/       # Rust client
└── examples/                   # Example implementations
```

### Key Components

1. **grpc-server**: Implements the gRPC server that receives requests via defined gRPC interfaces, performs flow-type conversions, interacts with connector-integration to generate connector-specific requests, sends the request to the connector, and constructs the appropriate response.

2. **connector-integration**: Contains payment processor specific transformations and logic for each flow. It is responsible for converting generic flow data into payment processor specific formats and generating the corresponding HTTP requests.

3. **grpc-api-types**: Auto-generated gRPC API types and interface definitions, generated from .proto files. These types are used for communication between services and clients.

4. **domain-types**: Common intermediate representation for the `grpc-server` and the `connector-integration` components to operate on.

5. **sdk**: Provides client SDKs for different languages to interact with the gRPC server, allowing users to integrate easily with their system.

## Key Design Patterns

### 1. Trait-Based Connector Integration

The `connector-integration` component uses Rust's trait mechanism to allow each payment processor to define its implementation for a particular payment operation. This enables a plugin-like architecture where new connectors can be added without modifying the core system.

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

Each payment processor implements this trait for each supported payment flow (Authorize, Capture, Refund, etc.), allowing the system to handle different processors in a uniform way.

### 2. Webhook Processing Pattern

For handling incoming webhooks from payment processors, a similar trait-based approach is used:

```rust
trait IncomingWebhook {
   fn verify_webhook_source();
   fn get_event_type();
   fn process_payment_webhook();
   fn process_refund_webhook();
}
```

This allows standardized processing of webhooks from different payment processors, converting them to a common representation.

### 3. Router Data Pattern

The system uses a `RouterDataV2` struct to encapsulate all the data needed for a payment operation, including:

- Flow-specific type parameters
- Common resource data
- Connector authentication details
- Request data
- Response data

This pattern allows for type-safe processing of different payment flows while maintaining a consistent structure.

### 4. Foreign Type Conversion

The system uses `ForeignTryFrom` and `ForeignFrom` traits to handle conversions between different data representations:

- gRPC API types to domain types
- Domain types to connector-specific types
- Connector responses to domain types
- Domain types to gRPC API responses

This pattern ensures clean separation between the external API contract and internal implementations.

## Data Flow

### Forward Payment Flow

```
┌─────────┐     ┌─────────────┐     ┌────────────────────┐     ┌─────────────┐
│         │     │             │     │                    │     │             │
│ Client  │────▶│ gRPC Server │────▶│ Connector          │────▶│ Payment     │
│         │     │             │     │ Integration        │     │ Processor   │
│         │     │             │     │                    │     │             │
└─────────┘     └─────────────┘     └────────────────────┘     └─────────────┘
     ▲                                                               │
     │                                                               │
     └───────────────────────────────────────────────────────────────┘
                            Response Flow
```

1. Client sends a payment request to the gRPC server
2. Server converts the request to domain types
3. Connector integration transforms domain types to connector-specific format
4. Request is sent to the payment processor
5. Response is received from the payment processor
6. Connector integration transforms the response to domain types
7. Server converts domain types to gRPC response
8. Response is sent back to the client

### Webhook Flow

```
┌─────────────┐     ┌─────────────┐     ┌────────────────────┐     ┌─────────────┐
│             │     │             │     │                    │     │             │
│ Payment     │────▶│ Client      │────▶│ gRPC Server       │────▶│ Connector   │
│ Processor   │     │ Webhook     │     │ (IncomingWebhook) │     │ Integration │
│             │     │ Endpoint    │     │                    │     │             │
└─────────────┘     └─────────────┘     └────────────────────┘     └─────────────┘
                                                                         │
                                                                         │
                          Normalized Webhook Event                       │
                                   ▲                                     │
                                   └─────────────────────────────────────┘
```

1. Payment processor sends a webhook to the client's webhook endpoint
2. Client forwards the webhook to the gRPC server
3. Server identifies the connector and passes the webhook to the appropriate connector integration
4. Connector integration verifies the webhook source and processes it
5. Webhook is normalized to a standard format and returned to the client

## Key Technical Decisions

### 1. Rust for Core Implementation

The core service is implemented in Rust, providing:
- Memory safety without garbage collection
- High performance
- Strong type system for ensuring correctness
- Excellent concurrency support

### 2. gRPC for Communication

gRPC was chosen as the communication protocol for:
- Efficient binary serialization (Protocol Buffers)
- Strong typing and contract definition
- Support for streaming and bidirectional communication
- Excellent cross-language support

### 3. Stateless Architecture

The service is designed to be stateless, which:
- Simplifies scaling and deployment
- Improves reliability
- Reduces operational complexity

### 4. Trait-Based Extensibility

Using Rust's trait system for connector integration:
- Provides a clear interface for implementing new connectors
- Ensures consistent behavior across connectors
- Enables compile-time verification of connector implementations

### 5. Multi-Language SDK Support

Providing SDKs in multiple languages:
- Reduces integration effort for clients
- Ensures consistent usage patterns
- Handles gRPC complexities transparently

## Component Relationships

### gRPC Server and Connector Integration

The gRPC server depends on the connector integration component but is agnostic to the specific connectors implemented. It:
1. Receives gRPC requests
2. Converts them to domain types
3. Delegates to the appropriate connector integration
4. Converts responses back to gRPC types

### Connector Integration and Domain Types

Connector integration components depend on domain types for:
1. Common data structures
2. Type conversions
3. Error handling

### gRPC API Types and Client SDKs

Client SDKs depend on gRPC API types to:
1. Generate client code
2. Define request and response structures
3. Handle serialization and deserialization

## Extension Points

The system is designed to be extended in several ways:

1. **New Connectors**: Adding support for new payment processors by implementing the ConnectorIntegration trait.

2. **New Payment Flows**: Supporting new payment operations by defining new flow types and implementing connector support.

3. **New Client SDKs**: Creating clients for additional programming languages.

4. **Enhanced Webhook Processing**: Adding support for new webhook types and events.
