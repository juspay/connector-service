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
