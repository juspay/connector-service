<!--
@doc-guidance
────────────────────────────────────────────────────
PAGE INTENT: A high level breakdown of the connector service into 3-5 core components, What is the siginifcance of the component and how it impacts external integration or developer experience has to be explained.
AUDIENCE: Payment developers and architects
TONE: Direct, conversational, opinionated. Write like explaining to a colleague over coffee.
PRIOR READING: [What pages should the reader have seen before this one? Link them.]
LEADS INTO: [What page comes next?]
────────────────────────────────────────────────────
LENGTH: 1.5–2 pages max (~600–800 words prose, tables and code blocks don't count toward this).
         If you need more space, the page is doing too much — split it.

WRITING RULES:
1. FIRST SENTENCE RULE — Open with what the reader gains, not what the thing is.
   Bad:  "The Prism SDK provides a unified interface..."
   Good: "You call one method. It works with Stripe, Adyen, or any of 50+ processors."

2. NO HEDGING — Delete: "can be", "may", "it is possible to", "in some cases", "typically".
   Say what IS. If something is conditional, state the condition.

3. VERB OVER NOUN — "lets you configure" not "provides configuration capabilities".
   "transforms the request" not "performs request transformation".

4. ONE IDEA PER SECTION — If a section has more than one takeaway, split it.

5. SHOW THEN TELL — Code example or diagram first, explanation after.
   The reader should see what it looks like before reading why.

6. EARN EVERY SENCE — If removing a sentence doesn't lose information, remove it.
   No "In this section, we will discuss..." No "As mentioned earlier..."
   No "It is important to note that..."

7. SPECIFICS OVER CLAIMS — Never say "supports many payment methods".
   Say "supports cards, wallets (Apple Pay, Google Pay), bank transfers, BNPL, and UPI".

8. ERRORS ARE FEATURES — When documenting a flow, show what goes wrong too.
   Include at least one error scenario with the actual error message.

9. NAME THE PRODUCT "Prism" — Not "UCS", not "the service", not "our platform".

10. TABLES FOR COMPARISON, PROSE FOR NARRATIVE — Don't put a story in a table.
    Don't write paragraphs when a 3-row table would be clearer.

CODE EXAMPLE RULES:
- Every code block must be runnable or clearly marked as pseudocode
- Use test credentials: Stripe key as $STRIPE_API_KEY, card 4242424242424242
- Show the output, not just the input
- If the example needs setup, show the setup

ANTI-PATTERNS TO REJECT:
- "Comprehensive", "robust", "seamless", "leverage", "utilize", "facilitate"
- Starting paragraphs with "Additionally", "Furthermore", "Moreover"
- Any sentence that describes the documentation itself ("This guide covers...")
- Repeating the heading as the first sentence of a section
────────────────────────────────────────────────────
-->

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
