# Architecture Overview

##

<!-- 
title: Architecture Overview
description: How Prism library is architected for multi-language SDKs and unified payment processing
last_updated: 2026-03-03
generated_from: N/A
auto_generated: false
reviewed_by: engineering
reviewed_at: 2026-03-03
approved: true 
-->

---



## Architecture Components

As at 10,000 feet overview, the Prism library can be broken into a three layered architecture, each solving a unique purpose.

| Component | Why It Exists | Problem It Solves | Technologies |
|-----------|---------------|-------------------|--------------|
| **Interface layer** | Enabled developers to think in their language's patterns whicle using the unified payments grammar provided by the library | You use `client.payments.authorize()` with idiomatic types in your codebase | Node.js, Python, Java, .NET, Go, Haskell |
| **Binding Layer** | Every language SDK needs native-performance gRPC to trigger API calls | Seamless transport without language bridges; handles serialization, HTTP/2, streaming | tonic, grpcio, grpc-dotnet, go-grpc |
| **Core** | Single source of truth for payment logic. Also includes the API transformations into the | One implementation of payment services serves all languages; unified errors, routing, types | Rust, tonic, protocol buffers |

The architecture prioritizes four important pillars

1. **Consistency**: The protobuf ensures same domain types, patterns, and errors shall be used across all connectors. It ensure the glue between the gRPC Client and the SDK interface.
2. **Extensibility**: Being able to add more connectors without any having to change the Interface of the library.
3. **Near zero overhead**: The gRPC interface was chosen to provide significant advantage compared REST APIs for high volume payment processing. If the library is chosen to be used as a microservice the gRPC interface enable with 10x smaller payloads, faster serialization/ deserialization hops, reduced bandwidth consumption and optimized for concurrent requests on a single connection
4. **Developer Experience**: Idiomatic payments interface with multi language SDKs 



```
┌─────────────────────────────────────────────────────────────────────────────┐
│                  UNIFIED CONNECTOR LIBRARY - INTERFACE                      │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐      │
│  │  Node.js  │ │  Python   │ │   Java    │ │   .NET    │ │    Go     │ ...  │
│  │    SDK    │ │    SDK    │ │    SDK    │ │    SDK    │ │    SDK    │      │
│  └─────┬─────┘ └─────┬─────┘ └─────┬─────┘ └─────┬─────┘ └─────┬─────┘      │
└────────┼─────────────┼─────────────┼─────────────┼─────────────┼────────────┘
         │             │             │             │             │
         ▼             ▼             ▼             ▼             ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                   UNIFIED CONNECTOR LIBRARY - BINDING LAYER                  │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │  Native gRPC Clients (tonic, grpcio, grpc-dotnet, go-grpc, etc.)       │  │
│  │                                                                        │  │
│  │  • Protobuf serialization/deserialization                              │  │
│  │  • HTTP/2 connection management                                        │  │
│  │  • Streaming support                                                   │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────────┐
│                   UNIFIED CONNECTOR LIBRARY - CORE                         │
│  ┌────────────────────────────────────┐    ┌────────────────────────────┐  │
│  │           gRPC Server              │    │    Connector Adapters      │  │
│  │                                    │    │    (100+ connectors)       │  │
│  │  ┌─────────┐ ┌─────────┐           │    │                            │  │
│  │  │ Payment │ │ Refund  │           │───▶│  ┌─────────┐  ┌─────────┐  │  │
│  │  │ Service │ │ Service │           │    │  │ Stripe  │  │  Adyen  │  │  │
│  │  └─────────┘ └─────────┘           │    │  │ Adapter │  │ Adapter │  │  │
│  │                                    │    │  └─────────┘  └─────────┘  │  │
│  │  ┌─────────┐ ┌─────────┐           │    │                            │  │
│  │  │ Dispute │ │  Event  │           │    │  ┌─────────┐  ┌─────────┐  │  │
│  │  │ Service │ │ Service │           │    │  │ PayPal  │  │   +     │  │  │
│  │  └─────────┘ └─────────┘           │    │  │ Adapter │  │  more   │  │  │
│  │                                    │    │  └─────────┘  └─────────┘  │  │
│  │  • Unified protobuf types          │    │                            │  │
│  │  • Request routing                 │    └──────────────┼─────────────┘  │
│  │  • Error normalization             │                   │                │
│  └────────────────────────────────────┘                   ▼                │
│                                                ┌─────────┐ ┌─────────┐     │
│                                                │ Stripe  │ │  Adyen  │     │
│                                                │   API   │ │   API   │     │
│                                                └─────────┘ └─────────┘     │
│                                                ┌─────────┐ ┌─────────┐     │
│                                                │ Stripe  │ │    +    │     │
│                                                │   API   │ │   more  │     │
│                                                └─────────┘ └─────────┘     │
└────────────────────────────────────────────────────────────────────────────┘
```

### Component Descriptions

## Data Flow

```mermaid
sequenceDiagram
    participant SDK as SDK Interface
    participant FFI as FFI / Binding Layer
    participant Server as gRPC Server
    participant Adapter as Connector Adapters
    participant Stripe as Stripe API
    participant Adyen as Adyen API

    SDK->>FFI: Serialize to protobuf
    FFI->>Server: gRPC call (HTTP/2)
    Server->>Server: Route to connector adapter
    Server->>Adapter: Transform request

    alt Stripe Connector
        Adapter->>Stripe: POST /v1/payment_intents
        Stripe-->>Adapter: PaymentIntent response
    else Adyen Connector
        Adapter->>Adyen: POST /payments
        Adyen-->>Adapter: Payment response
    end

    Adapter->>Adapter: Transform to unified format
    Adapter-->>Server: Return unified response
    Server-->>Server: Normalize errors
    Server-->>FFI: gRPC response
    FFI-->>SDK: Deserialize from protobuf
```

### Connector Transformation

Prism transforms unified requests to connector-specific formats.

**Authorization Mapping:**

| Unified Field                     | Stripe                         | Adyen                   |
| --------------------------------- | ------------------------------ | ----------------------- |
| `amount.currency`                 | `currency`                     | `amount.currency`       |
| `amount.amount`                   | `amount` (cents)               | `value` (cents)         |
| `payment_method.card.card_number` | `payment_method[card][number]` | `paymentMethod[number]` |
| `connector_metadata`              | `metadata`                     | `additionalData`        |

This transformation happens server-side, so the multi-language SDKs of Prism remain unchanged when adding new connectors.

### Connector Adapter Pattern

Each connector implements a standard interface:

```rust
trait ConnectorAdapter {
    async fn authorize(&self, request: AuthorizeRequest) -> Result<AuthorizeResponse>;
    async fn capture(&self, request: CaptureRequest) -> Result<CaptureResponse>;
    async fn void(&self, request: VoidRequest) -> Result<VoidResponse>;
    async fn refund(&self, request: RefundRequest) -> Result<RefundResponse>;
    // ... 20+ operations
}
```

Adding new connectors only need an adapter implementation. SDKs require zero changes.

## Summary

The architecture prioritizes:

1. **Consistency**: Same types, patterns, and errors across all connectors
2. **Extensibility**: Being able to add more connectors without any SDK side changes
3. **Performance**: gRPC interface provides significant advantage over REST APIs for high volume payment processing. The library could also be used as microservice with 10x smaller payloads, faster serialization/ deserialization hops, reduced bandwidth consumption and optimized for concurrent requests on a single connection
4. **Developer Experience**: Idiomatic payments interface with multi language SDKs 

For developers integrating multiple payment providers, this means weeks of integration work becomes hours, and maintenance burden drops from O(N connectors) to O(1).
