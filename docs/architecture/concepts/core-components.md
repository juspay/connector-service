# Core Components

Prism breaks down into four components that each solve a specific integration pain point. Understanding them helps you decide how to deploy and extend the system.

```
┌─────────────────────────────────────────────────────────────┐
│                     YOUR APPLICATION                        │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  SDK LAYER (Node.js, Python, Java, Go, Rust)                │
│  • Idiomatic language bindings                               │
│  • Type-safe requests and responses                          │
│  • Error handling in your language's conventions             │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  TRANSPORT LAYER (FFI or gRPC)                              │
│  • FFI: In-process shared library calls                      │
│  • gRPC: HTTP/2 service calls                                │
│  • Protobuf serialization                                    │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  CORE SERVICE LAYER                                         │
│  • PaymentService, RefundService, DisputeService            │
│  • Request routing and validation                            │
│  • Unified error handling                                    │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  CONNECTOR ADAPTER LAYER                                    │
│  • Stripe adapter, Adyen adapter, 50+ more                   │
│  • Request/response transformation                           │
│  • Authentication and error mapping                          │
└─────────────────────────────────────────────────────────────┘
```

## Component 1: SDK Layer

**What it does:** Gives you type-safe, idiomatic payment methods in your language of choice.

**Why it matters:** You write `client.payments.authorize()` in Node.js, Python, Java, or Go. Same method signature, same behavior, native patterns. A Python developer uses async/await. A Java developer uses CompletableFuture. Both call the same underlying operation.

**Impact on your code:**
- Compile-time type checking catches integration errors
- IDE autocomplete shows available methods and fields
- Error handling follows your language's conventions (exceptions, Result types, error returns)

## Component 2: Transport Layer

**What it does:** Moves requests between your application and the core service.

**Why it matters:** You choose the integration pattern that fits your architecture. FFI bindings load the Rust core as a shared library in your process. gRPC bindings connect to the core as a separate service.

| Transport | Latency | Use Case |
|-----------|---------|----------|
| FFI | < 1ms | High-throughput, single-process applications |
| gRPC | 5-20ms | Microservices, containerized deployments, shared core |

**Impact on your code:** Same SDK methods work with either transport. Change one configuration line to switch modes.

## Component 3: Core Service Layer

**What it does:** Implements payment logic once, serves all languages.

**Why it matters:** Payment operations (authorize, capture, refund, void) contain complex business rules. Validating amounts, checking status transitions, handling retries—this logic lives in one place. The Core Service layer executes these operations regardless of which SDK or transport you use.

The layer exposes services:
- **PaymentService**: Authorize, capture, void, sync, incremental authorization
- **RefundService**: Refund, sync
- **DisputeService**: Accept, defend, submit evidence
- **EventService**: Webhook handling

**Impact on your code:** You call `capture()` the same way whether you're capturing a Stripe payment or an Adyen payment. The core handles the differences.

## Component 4: Connector Adapter Layer

**What it does:** Translates unified requests into Stripe format, Adyen format, PayPal format, and back.

**Why it matters:** Each payment processor speaks a different API dialect. Stripe uses PaymentIntents. Adyen uses payments. PayPal uses orders. The adapter layer maps Prism's unified types to each provider's native format.

```rust
// Unified request (your code)
AuthorizeRequest {
    amount: Money { minor_amount: 1000, currency: "USD" },
    payment_method: PaymentMethod::Card { ... }
}

// Stripe adapter transforms to:
{
    "amount": 1000,
    "currency": "usd",
    "payment_method[data][card][number]": "4242424242424242"
}

// Adyen adapter transforms to:
{
    "amount": { "value": 1000, "currency": "USD" },
    "paymentMethod": { "number": "4242424242424242" }
}
```

**Impact on your code:** Zero. You never see connector-specific formats. The adapter layer handles authentication, request transformation, response parsing, and error mapping.

## How Components Connect

A typical payment flow shows the relationship:

```
Your App → SDK (Node.js) → FFI → Core Service → Stripe Adapter → Stripe API
     ↑                                                    │
     └────────────────────────────────────────────────────┘
                    (response flows back)
```

Each component adds value:
1. **SDK**: Type safety and idiomatic patterns
2. **FFI**: Fast, in-process communication
3. **Core Service**: Unified payment logic
4. **Adapter**: Connector-specific translation

## Extending the System

Adding a new connector? You only touch Component 4. Write an adapter that implements the connector trait, map the types, handle authentication. The SDK, transport, and core service require zero changes.

Adding a new language SDK? You touch Component 1. Generate bindings from protobuf, add idiomatic wrappers. The core and adapters work unchanged.

This separation keeps the system maintainable at 50+ connectors and growing.
