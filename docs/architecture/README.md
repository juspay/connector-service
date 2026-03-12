## The Problem

If you've integrated multiple payment providers, you know the pain:
- Stripe uses PaymentIntents
- Adyen uses payments
- PayPal uses orders

All of them do the same job, but each has different field names, different status enums, different error formats.

This problem exists in other domains too, but solved with well maintained developer centric libraries, open source and free from vendor lock-in.

| Domain | Unified Interface | What It Solves |
|--------|-------------------|----------------|
| **LLMs** | [LiteLLM](https://github.com/BerriAI/litellm) | One interface for OpenAI, Anthropic, Google, etc. |
| **Databases** | [Prisma](https://www.prisma.io/) | One ORM for PostgreSQL, MySQL, MongoDB, etc. |
| **Cloud Storage** | [Rclone](https://rclone.org/) | One CLI for S3, GCS, Azure Blob, etc. |

**But for payments, no such equivalent exists for developers.**

Connector Service is the unified abstraction layer for payment processors—giving you one API, one set of types, and one mental model for 100+ payment connectors.

## Architecture Components

The Connector Service supports a three layered architecture, each solving a purpose 

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           SDK INTERFACE LAYER                               │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐      │
│  │  Node.js  │ │  Python   │ │   Java    │ │   .NET    │ │    Go     │ ...  │
│  │    SDK    │ │    SDK    │ │    SDK    │ │    SDK    │ │    SDK    │      │
│  └─────┬─────┘ └─────┬─────┘ └─────┬─────┘ └─────┬─────┘ └─────┬─────┘      │
└────────┼─────────────┼─────────────┼─────────────┼─────────────┼────────────┘
         │             │             │             │             │
         ▼             ▼             ▼             ▼             ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                          FFI / BINDING LAYER                                 │
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
│                                  CORE                                      │
│                                                                            │
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

| Component | Why It Exists | Problem It Solves | Technologies |
|-----------|---------------|-------------------|--------------|
| **SDK Interface** | Developers can think in their language's patterns whicle using the unified payments grammar provided by the library | You use `client.payments.authorize()` with idiomatic types in your codebase | Node.js, Python, Java, .NET, Go, Haskell |
| **FFI / Binding Layer** | Each language needs native-performance gRPC | Seamless transport without language bridges; handles serialization, HTTP/2, streaming | tonic, grpcio, grpc-dotnet, go-grpc |
| **gRPC Server** | Single source of truth for payment logic. Also offers freedom to use connector service as a separate microservice | One implementation of payment services serves all languages; unified errors, routing, types | Rust, tonic, protocol buffers |
| **Connector Adapters** | Each connector has unique APIs and formats | You use one `AuthorizeRequest`; the library maps to Stripe's `PaymentIntent` or Adyen's `payments` | Rust, 100+ connector implementations |

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

## Connector Transformation

The core value: Connector Service transforms unified requests to connector-specific formats.

**Authorization Mapping:**

| Unified Field | Stripe | Adyen |
|---------------|--------|-------|
| `amount.currency` | `currency` | `amount.currency` |
| `amount.amount` | `amount` (cents) | `value` (cents) |
| `payment_method.card.card_number` | `payment_method[card][number]` | `paymentMethod[number]` |
| `connector_metadata` | `metadata` | `additionalData` |

This transformation happens server-side, so SDKs remain unchanged when adding new connectors.

## Connector Adapter Pattern

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
2. **Extensibility**: Add connectors without SDK changes
3. **Performance**: gRPC interface provides significant advantage over REST APIs for high volume payment processing. The lirabry could also be used as microservice with 10x smaller paylos, faster serialization/ deserialization hops, reduced bannwidth consumption and optimized for concurrent requests on a single connection
4. **Developer Experience**: Idiomatic payments interface with multi language SDKs 

For developers integrating multiple payment providers, this means weeks of integration work becomes hours, and maintenance burden drops from O(N connectors) to O(1).

