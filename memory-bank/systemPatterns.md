# System Patterns: Connector Service Architecture

## High-Level Architecture

The Connector Service comprises two major runtime components:

1. **Three-Service gRPC Architecture**: Offers a unified interface for all merchant payment operations through specialized services (PaymentService, RefundService, DisputeService) supported by different payment processors around the world.

2. **Client SDKs**: Language-specific clients that integrate into applications to invoke the gRPC services.

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│                 │     │                 │     │                 │
│  Client App     │────▶│  Client SDK     │────▶│  gRPC Services  │────▶ Payment Processors
│  (User Code)    │     │  (Lang-specific)│     │  (3 Services)   │     (6 Production Connectors)
│                 │     │                 │     │                 │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                                                       │
                                                       ├── PaymentService
                                                       ├── RefundService
                                                       └── DisputeService
```

## Three-Service Architecture

The gRPC API is organized into three specialized services for better separation of concerns:

1. **PaymentService**: Core payment operations (authorize, capture, void, refund, mandate setup)
2. **RefundService**: Dedicated refund management and status tracking
3. **DisputeService**: Comprehensive dispute handling (evidence submission, defense, acceptance)

## Component Structure

The codebase is organized into the following key components:

```
connector-service/
├── backend/
│   ├── connector-integration/  # Payment processor integrations (6 production connectors)
│   ├── domain_types/           # Common data structures and flow definitions
│   ├── grpc-api-types/         # gRPC interface definitions
│   │   └── proto/              # Protocol buffer definitions (services.proto, payment.proto)
│   ├── grpc-server/            # Three-service gRPC server implementation
│   ├── interfaces/             # Connector integration traits and authentication
│   ├── external-services/      # External service interactions
│   └── common_utils/           # Shared utilities and error handling
├── sdk/                        # Client SDKs
│   ├── node-grpc-client/       # Node.js client
│   ├── python-grpc-client/     # Python client
│   └── rust-grpc-client/       # Rust client
└── examples/                   # Example implementations
```

### Key Components

1. **grpc-server**: Implements the three-service gRPC server (PaymentService, RefundService, DisputeService) that receives requests via defined gRPC interfaces, performs flow-type conversions, interacts with connector-integration to generate connector-specific requests, sends the request to the connector, and constructs the appropriate response.

2. **connector-integration**: Contains payment processor specific transformations and logic for each flow. Currently supports 6 production connectors (Adyen, Razorpay, Checkout.com, Fiserv, Elavon, Xendit). It is responsible for converting generic flow data into payment processor specific formats and generating the corresponding HTTP requests.

3. **grpc-api-types**: Auto-generated gRPC API types and interface definitions, generated from .proto files (services.proto, payment.proto, payment_methods.proto). These types are used for communication between services and clients.

4. **domain_types**: Common intermediate representation for the `grpc-server` and the `connector-integration` components to operate on. Contains flow definitions, connector types, and router data structures.

5. **interfaces**: Defines the ConnectorIntegrationV2 trait and other interfaces for connector implementations, authentication, and webhook processing.

6. **sdk**: Provides client SDKs for different languages to interact with the gRPC services, allowing users to integrate easily with their system.

## Key Design Patterns

### 1. Trait-Based Connector Integration

The `connector-integration` component uses Rust's trait mechanism to allow each payment processor to define its implementation for a particular payment operation. This enables a plugin-like architecture where new connectors can be added without modifying the core system.

```rust
pub trait ConnectorIntegrationV2<Flow, ResourceCommonData, Req, Resp>:
    ConnectorIntegrationAnyV2<Flow, ResourceCommonData, Req, Resp> + Sync + api::ConnectorCommon
{
    fn get_headers(&self, req: &RouterDataV2<Flow, ResourceCommonData, Req, Resp>) 
        -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError>;
    fn get_content_type(&self) -> &'static str;
    fn get_http_method(&self) -> Method;
    fn get_url(&self, req: &RouterDataV2<Flow, ResourceCommonData, Req, Resp>) 
        -> CustomResult<String, ConnectorError>;
    fn get_request_body(&self, req: &RouterDataV2<Flow, ResourceCommonData, Req, Resp>) 
        -> CustomResult<Option<RequestContent>, ConnectorError>;
    fn build_request_v2(&self, req: &RouterDataV2<Flow, ResourceCommonData, Req, Resp>) 
        -> CustomResult<Option<Request>, ConnectorError>;
    fn handle_response_v2(&self, data: &RouterDataV2<Flow, ResourceCommonData, Req, Resp>, 
        event_builder: Option<&mut ConnectorEvent>, res: Response) 
        -> CustomResult<RouterDataV2<Flow, ResourceCommonData, Req, Resp>, ConnectorError>;
    fn get_error_response_v2(&self, res: Response, event_builder: Option<&mut ConnectorEvent>) 
        -> CustomResult<ErrorResponse, ConnectorError>;
}
```

Each payment processor implements this trait for each supported payment flow (Authorize, Capture, Refund, etc.), allowing the system to handle different processors in a uniform way. The current implementation supports 11 distinct flow types: Authorize, PSync, Void, Capture, Refund, RSync, SetupMandate, Accept, SubmitEvidence, DefendDispute, and CreateOrder.

### 2. Webhook Processing Pattern

For handling incoming webhooks from payment processors, the IncomingWebhook trait provides standardized webhook processing:

```rust
pub trait IncomingWebhook {
    fn verify_webhook_source(&self, request: RequestDetails, 
        connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        connector_account_details: Option<ConnectorAuthType>) 
        -> Result<bool, ConnectorError>;
    
    fn get_event_type(&self, request: RequestDetails,
        connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        connector_account_details: Option<ConnectorAuthType>)
        -> Result<EventType, ConnectorError>;
    
    fn process_payment_webhook(&self, request: RequestDetails,
        connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        connector_account_details: Option<ConnectorAuthType>)
        -> Result<WebhookDetailsResponse, ConnectorError>;
    
    fn process_refund_webhook(&self, request: RequestDetails,
        connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        connector_account_details: Option<ConnectorAuthType>)
        -> Result<RefundWebhookDetailsResponse, ConnectorError>;
    
    fn process_dispute_webhook(&self, request: RequestDetails,
        connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        connector_account_details: Option<ConnectorAuthType>)
        -> Result<DisputeWebhookDetailsResponse, ConnectorError>;
}
```

This allows standardized processing of webhooks from different payment processors across three service domains (payments, refunds, disputes), converting them to a common representation with source verification.

### 3. Router Data Pattern

The system uses a `RouterDataV2` struct to encapsulate all the data needed for a payment operation, including:

- Flow-specific type parameters (Authorize, Capture, Refund, etc.)
- Resource common data (PaymentFlowData, RefundFlowData, DisputeFlowData)
- Connector authentication details
- Request data (flow-specific request types)
- Response data (flow-specific response types)

```rust
pub struct RouterDataV2<Flow, ResourceCommonData, Request, Response> {
    pub flow: PhantomData<Flow>,
    pub resource_common_data: ResourceCommonData,
    pub connector_auth_type: ConnectorAuthType,
    pub request: Request,
    pub response: Result<Response, ErrorResponse>,
}
```

This pattern allows for type-safe processing of different payment flows while maintaining a consistent structure across all three gRPC services.

### 4. Service-Specific Type Conversion

The system uses pattern-based conversions to handle transformations between different data representations:

- gRPC API types (PaymentServiceAuthorizeRequest, RefundServiceGetRequest, etc.) to domain types
- Domain types to connector-specific types
- Connector responses to domain types
- Domain types to gRPC API responses (PaymentServiceAuthorizeResponse, DisputeResponse, etc.)

This pattern ensures clean separation between the external three-service API contract and internal implementations, with each service handling its own specific conversion patterns while sharing common domain types.

## Data Flow

### Forward Payment Flow

```
┌─────────┐     ┌─────────────────┐     ┌────────────────────┐     ┌─────────────┐
│         │     │                 │     │                    │     │             │
│ Client  │────▶│ gRPC Services   │────▶│ Connector          │────▶│ Payment     │
│         │     │ (Payment/       │     │ Integration        │     │ Processor   │
│         │     │  Refund/        │     │ (6 Connectors)     │     │ (Adyen,     │
│         │     │  Dispute)       │     │                    │     │  Razorpay,  │
│         │     │                 │     │                    │     │  etc.)      │
└─────────┘     └─────────────────┘     └────────────────────┘     └─────────────┘
     ▲                                                                     │
     │                                                                     │
     └─────────────────────────────────────────────────────────────────────┘
                                Response Flow
```

1. Client sends a request to one of the three gRPC services (PaymentService, RefundService, or DisputeService)
2. Service extracts connector metadata from gRPC headers
3. Service converts the request to appropriate domain types
4. Connector integration transforms domain types to connector-specific format
5. Request is sent to the payment processor
6. Response is received from the payment processor
7. Connector integration transforms the response to domain types
8. Service converts domain types to appropriate gRPC response
9. Response is sent back to the client

### Webhook Flow

```
┌─────────────┐     ┌─────────────┐     ┌────────────────────┐     ┌─────────────┐
│             │     │             │     │ gRPC Services      │     │             │
│ Payment     │────▶│ Client      │────▶│ Transform Methods  │────▶│ Connector   │
│ Processor   │     │ Webhook     │     │ (Payment/Refund/   │     │ Integration │
│             │     │ Endpoint    │     │  Dispute)          │     │ (Webhook    │
│             │     │             │     │                    │     │  Processing)│
└─────────────┘     └─────────────┘     └────────────────────┘     └─────────────┘
                                                                         │
                                                                         │
                          Service-Specific Webhook Response              │
                                   ▲                                     │
                                   └─────────────────────────────────────┘
```

1. Payment processor sends a webhook to the client's webhook endpoint
2. Client forwards the webhook to the appropriate gRPC service Transform method:
   - PaymentService.Transform for payment events
   - RefundService.Transform for refund events  
   - DisputeService.Transform for dispute events
3. Service identifies the connector and passes the webhook to the appropriate connector integration
4. Connector integration verifies the webhook source and processes it using IncomingWebhook trait
5. Webhook is normalized to service-specific format and returned to the client

## Key Technical Decisions

### 1. Rust for Core Implementation

The core service is implemented in Rust, providing:
- Memory safety without garbage collection
- High performance for payment processing workloads
- Strong type system for ensuring correctness across 11 flow types
- Excellent concurrency support for handling multiple connectors

### 2. Three-Service gRPC Architecture

Three specialized gRPC services were chosen for:
- Separation of concerns (payments, refunds, disputes)
- Independent service scaling and evolution
- Clear API boundaries and specialized response types
- Efficient binary serialization (Protocol Buffers)
- Strong typing and contract definition

### 3. Stateless Architecture

The service is designed to be stateless, which:
- Simplifies scaling and deployment across multiple instances
- Improves reliability for high-throughput payment processing
- Reduces operational complexity
- Enables horizontal scaling of individual services

### 4. Trait-Based Extensibility

Using Rust's trait system for connector integration:
- Provides a clear interface for implementing new connectors (currently 6 production, 90+ potential)
- Ensures consistent behavior across all payment processors
- Enables compile-time verification of connector implementations
- Supports comprehensive flow coverage (11 distinct flow types)

### 5. Multi-Language SDK Support

Providing SDKs in multiple languages:
- Reduces integration effort for clients using different technology stacks
- Ensures consistent usage patterns across all three services
- Handles gRPC complexities and metadata management transparently
- Abstracts service selection and authentication details

## Component Relationships

### gRPC Services and Connector Integration

The three gRPC services depend on the connector integration component but are agnostic to the specific connectors implemented. Each service:
1. Receives service-specific gRPC requests (PaymentService, RefundService, DisputeService)
2. Extracts connector metadata from gRPC headers
3. Converts requests to appropriate domain types
4. Delegates to the appropriate connector integration using RouterDataV2
5. Converts responses back to service-specific gRPC types

### Connector Integration and Domain Types

Connector integration components depend on domain_types for:
1. Common data structures (PaymentFlowData, RefundFlowData, DisputeFlowData)
2. Flow type definitions (Authorize, Capture, Refund, etc.)
3. Type conversions between gRPC and connector-specific formats
4. Centralized error handling and response patterns

### gRPC API Types and Client SDKs

Client SDKs depend on gRPC API types to:
1. Generate service-specific client code (PaymentServiceClient, RefundServiceClient, DisputeServiceClient)
2. Define request and response structures for all three services
3. Handle serialization and deserialization across service boundaries
4. Manage authentication metadata and service routing

## Extension Points

The system is designed to be extended in several ways:

1. **New Connectors**: Adding support for new payment processors by implementing the ConnectorIntegrationV2 trait for all 11 flow types. Framework currently supports 6 production connectors with potential for 90+ more.

2. **New Payment Flows**: Supporting new payment operations by:
   - Defining new flow types in domain_types/connector_flow.rs
   - Adding corresponding gRPC service methods
   - Implementing connector support across all relevant connectors

3. **New Client SDKs**: Creating clients for additional programming languages that support all three gRPC services (PaymentService, RefundService, DisputeService).

4. **Enhanced Webhook Processing**: Adding support for new webhook types and events by:
   - Extending the IncomingWebhook trait methods
   - Adding new event types to the EventType enum
   - Implementing service-specific Transform method handling

5. **Service Extensions**: Adding new specialized services following the three-service pattern while maintaining shared domain types and connector integration patterns.
