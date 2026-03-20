<!--
@doc-guidance
────────────────────────────────────────────────────
PAGE INTENT:The connector service can be used as a (i) Library (ii) As a GRPC micro service. Explain the advanatages and the additional responsibilities for devleoeprs whil choosing each mode. SDK is meant to be easy to use and manage, language agnostic, easy to augment ith exisitng sdetup. Even dsingle payment procesor users can use the SDK, so that future expansiion to newer payment processors will only be a few line changes. Micro service is good for large scale deployments where service isolation. Emphasise on deserialization speed benefits, payload size benefits on the GRPC service. 

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

6. EARN EVERY SENTENCE — If removing a sentence doesn't lose information, remove it.
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

# Library Modes of Usage

Prism fits into your architecture two ways: as an embedded library or as a standalone microservice. The choice depends on your scale, team structure, and how you want to manage payment logic.

## Mode Comparison

| Factor | Library (SDK) | Microservice (gRPC) |
|--------|---------------|---------------------|
| **Latency** | < 1ms | 5-20ms |
| **Deployment** | Embedded in your app | Separate container/service |
| **Language support** | Node.js, Python, Java, Go, Rust | Any gRPC client |
| **Scaling** | Scale with your app | Independent scaling |
| **Team ownership** | Your team manages everything | Platform team owns payments |
| **Resource isolation** | Shared resources | Dedicated resources |
| **Upgrade cycle** | Tied to your app releases | Independent deployments |

## Library Mode (SDK)

Use the SDK when you want payment logic in your application process.

```javascript
// Your application code
const { ConnectorClient } = require('@juspay/connector-service-node');

const client = new ConnectorClient({
    connectors: {
        stripe: { apiKey: process.env.STRIPE_API_KEY }
    }
});

// Direct function call—no network hop
const payment = await client.payments.authorize({
    amount: { minorAmount: 1000, currency: 'USD' },
    paymentMethod: { card: { cardNumber: '4242424242424242', ... } }
});
```

**Architecture:**

```
Your App Process
├── Your Business Logic
├── Prism SDK (loaded via FFI)
│   ├── Type definitions
│   ├── Request serialization
│   └── FFI bindings
├── Prism Core (Rust shared library)
│   ├── Payment logic
│   └── Connector adapters
└── HTTP client (for connector calls)
```

**Advantages:**

- **Speed**: FFI calls are sub-millisecond. No network overhead.
- **Simplicity**: Single deployable unit. No service mesh complexity.
- **Type safety**: Full type checking at compile time.
- **Debugging**: Step through payment logic in your debugger.

**Your Responsibilities:**

- Manage Prism version upgrades with your app releases
- Handle library dependencies in your deployment
- Monitor resource usage (the core runs in your process)
- Configure TLS and connection pooling for connector calls

**Best for:**

- Startups and small teams
- Single-payment-processor use cases (easy to add more later)
- Latency-sensitive applications
- Monolithic architectures

## Microservice Mode (gRPC)

Run Prism as a standalone service when you need separation of concerns.

```javascript
// Your application code
const { ConnectorServiceClient } = require('@juspay/connector-service-grpc');

const client = new ConnectorServiceClient('connector-service.internal:8080');

// gRPC call to the microservice
const payment = await client.authorize({
    amount: { minorAmount: 1000, currency: 'USD' },
    paymentMethod: { card: { cardNumber: '4242424242424242', ... } }
});
```

**Architecture:**

```
Your App Container          Prism Container
┌─────────────────┐         ┌──────────────────────────┐
│ Your App        │         │ Prism        │
│ ├─ Business     │──gRPC──▶│ ├─ gRPC server           │
│ └─ gRPC client  │         │ ├─ Payment logic         │
└─────────────────┘         │ └─ Connector adapters    │
                            └──────────┬───────────────┘
                                       │ HTTP
                                       ▼
                            ┌──────────────────────────┐
                            │   Stripe / Adyen / etc.  │
                            └──────────────────────────┘
```

**Advantages:**

- **Performance**: gRPC uses Protocol Buffers—binary serialization is 5-10x faster than JSON and produces 50-80% smaller payloads
- **Isolation**: Payment logic failures don't crash your app
- **Independent scaling**: Scale payment processing separately from your API servers
- **Team separation**: Platform team owns payments, product teams consume them
- **Protocol efficiency**: HTTP/2 multiplexing handles concurrent requests on a single connection
- **Polyglot support**: Any language with gRPC can call the service

**Your Responsibilities:**

- Deploy and operate the Prism container
- Manage service discovery and load balancing
- Monitor inter-service latency and error rates
- Handle gRPC connection lifecycle (health checking, reconnection)

**Best for:**

- Large organizations with platform teams
- Multi-service architectures
- High-throughput payment processing
- Regulated environments requiring service isolation

## Why gRPC Over REST

Prism uses gRPC for the microservice mode because:

| Aspect | gRPC | REST/JSON |
|--------|------|-----------|
| **Serialization** | Binary (Protobuf) | Text (JSON) |
| **Payload size** | ~60% smaller | Larger |
| **Deserialization** | ~10x faster | Slower |
| **Schema** | Strict (proto files) | Loose |
| **Streaming** | Bidirectional | Limited |
| **Code generation** | Automatic | Manual |

For high-volume payment processing, these differences matter. A payment gateway handling 10,000 TPS saves significant bandwidth and CPU with gRPC.

## Switching Between Modes

The SDK abstracts the transport. Changing from library to microservice mode is one configuration change:

```javascript
// Library mode
const client = new ConnectorClient({
    mode: 'ffi',  // Or omit—FFI is default
    connectors: { ... }
});

// Microservice mode—same API, different transport
const client = new ConnectorClient({
    mode: 'grpc',
    endpoint: 'connector-service.internal:8080'
});
```

Your business logic stays identical.

## Single Processor Today, Many Tomorrow

Even if you only use Stripe today, using Prism SDK positions you for expansion:

```javascript
// Today: Just Stripe
const response = await client.payments.authorize({
    connector: Connector.STRIPE,
    amount: { ... }
});

// Tomorrow: Add Adyen with one line change
const response = await client.payments.authorize({
    connector: Connector.ADYEN,  // ← Only change
    amount: { ... }              // Everything else identical
});
```

No rewriting integration code. No retesting payment flows. Just swap the connector enum.

## Choosing Your Mode

**Choose Library Mode if:**
- You want the fastest possible payment calls
- You're a small team managing your own infrastructure
- You're starting with one processor and might add more
- You prefer simplicity over separation

**Choose Microservice Mode if:**
- You have a platform team managing shared services
- You process high payment volumes (1000+ TPS)
- You need independent scaling or deployment
- You're in a regulated environment requiring service boundaries

Both modes give you the same unified API. The difference is where the code runs.
