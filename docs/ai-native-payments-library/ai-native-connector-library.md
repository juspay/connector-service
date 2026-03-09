# UCS: The AI-Native Connector Library for Payments

> What if integrating Stripe, Adyen, or Worldpay was as simple as `redis.get()` or `db.query()`?

---

## Introduction

Every developer has experienced this: you're building a feature, everything's going smoothly, and then you need to integrate payments. Suddenly you're drowning in API documentation, webhook signatures, idempotency keys, and connector-specific quirks. The cognitive load explodes.

Now multiply this problem across every AI-assisted coding session. As developers increasingly rely on LLMs to write code, traditional payment APIs become a bottleneck. They're inconsistently documented, use different patterns for each provider, and require deep domain knowledge to use correctly. AI assistants hallucinate field names, guess at error handling, and can't reason about connector-specific quirks.

What if payment integrations felt like using PostgreSQL?

```python
# PostgreSQL - familiar and predictable
db.execute("SELECT * FROM orders WHERE status = %s", ("pending",))

# Redis - simple and reliable
redis.setex("session:123", 3600, "active")

# UCS - why can't payments be this straightforward?
payments.authorize(PaymentRequest(amount=1000, currency="USD", connector="stripe"))
```

**UCS (Unified Connector Service)** is built on a simple premise: payments are infrastructure, not integration. By treating connectors as first-class libraries with strongly-typed interfaces, we make payment integrations predictable, type-safe, and—most importantly—AI-friendly.

In an era where AI writes more code than ever, UCS provides the structured, protocol-first foundation that LLMs need to generate correct payment code on the first try.

---

## AI-Native Design Principles

### Protocol Buffers: The Universal Interface

Traditional payment APIs force you to navigate JSON schemas, HTTP headers, and authentication dances. UCS uses **Protocol Buffers** as the single source of truth:

```protobuf
// A payment request is unambiguous
message PaymentRequest {
  Money amount = 1;                    // Strongly-typed money (not just a number!)
  string currency = 2;                 // ISO 4217 standard
  string connector = 3;                // Which PSP to route to
  PaymentMethod payment_method = 4;    // Card, wallet, BNPL, etc.
  IdempotencyKey idempotency_key = 5;  // Built-in retry safety
}

// The response tells you exactly what happened
message PaymentResponse {
  PaymentStatus status = 1;            // AUTHORIZED, CAPTURED, FAILED, etc.
  string connector_transaction_id = 2; // PSP-specific reference
  Error error = 3;                     // Structured error info
  Money amount_authorized = 4;         // What actually got approved
}
```

**Why this matters for AI:**
- LLMs understand proto definitions natively
- No guessing field types or valid values
- Self-documenting through strong typing
- Code generation eliminates hallucinated field names

### Industry-Standard Terminology

We've banished payment-industry jargon in favor of standard developer concepts:

| Legacy Term | UCS Term | Why |
|-------------|----------|-----|
| "Authorization" | `authorize()` | HTTP verb + resource |
| "Capture" | `capture()` | Clear action |
| "PaymentIntent" (Stripe) | `PaymentRequest` | Generic, not vendor-specific |
| "Merchant Account" | `connector_config` | Infrastructure as configuration |
| "Webhook" | `WebhookEvent` | Event-driven architecture standard |

This consistency means an AI assistant trained on one connector can help with any connector.

---

## The Developer Experience

### Two Personas, One Library

UCS is designed for two distinct personas:

| Persona | Goal | How UCS Helps |
|---------|------|---------------|
| **Architect** | Assess capabilities & customize integrations | Deep control over connectors, routing logic, and transformations |
| **Developer** | Integrate with minimal code | No-code/low-code options with smart defaults |

**For Architects:** UCS provides the building blocks to design payment infrastructure—custom routing rules, multiple connector fallbacks, vault integrations, and granular control over every request.

**For Developers:** UCS feels like any other library import. Add a dependency, initialize the client, and you're processing payments in minutes—not days.

### Five Lines to Production

```python
# Python SDK
def process_payment(order):
    client = ucs.PaymentClient(api_key=os.getenv("UCS_API_KEY"))

    response = client.payments.authorize(
        amount=ucs.Money(minor_units=1000, currency="USD"),
        connector="stripe",
        payment_method=ucs.CardToken(token=order.card_token)
    )

    return response.status == ucs.PaymentStatus.AUTHORIZED
```

```go
// Go SDK
func processPayment(order Order) (bool, error) {
    client := ucs.NewPaymentClient(os.Getenv("UCS_API_KEY"))

    resp, err := client.Payments.Authorize(ctx, &ucsv2.PaymentRequest{
        Amount: &ucsv2.Money{MinorUnits: 1000, Currency: "USD"},
        Connector: "stripe",
        PaymentMethod: &ucsv2.PaymentMethod{
            Type: ucsv2.PaymentMethodType_CARD,
            Card: &ucsv2.CardPayment{Token: order.CardToken},
        },
    })

    return resp.Status == ucsv2.PaymentStatus_AUTHORIZED, err
}
```

```rust
// Rust SDK
async fn process_payment(order: &Order) -> Result<bool, ucs::Error> {
    let client = ucs::PaymentClient::new(env::var("UCS_API_KEY")?);

    let response = client.payments()
        .authorize(PaymentRequest {
            amount: Some(Money { minor_units: 1000, currency: "USD".to_string() }),
            connector: "stripe".to_string(),
            payment_method: Some(PaymentMethod {
                r#type: PaymentMethodType::Card as i32,
                card: Some(CardPayment { token: order.card_token.clone() }),
                ..Default::default()
            }),
            ..Default::default()
        })
        .await?;

    Ok(response.status == PaymentStatus::Authorized as i32)
}
```

**Notice the pattern:**
- Same concepts, idiomatic to each language
- Type safety catches errors at compile time
- IDE autocomplete knows all available fields
- No hand-rolled HTTP clients or JSON parsing

### Priority Language Support

UCS SDKs are built with framework-native integration in mind:

| Language | Frameworks | Package |
|----------|------------|---------|
| **Rust** | Actix, Axum, Tokio | `cargo add ucs-sdk` |
| **Node.js** | Express, NestJS, Fastify | `npm install @juspay/ucs` |
| **Python** | FastAPI, Django, Flask | `pip install ucs-sdk` |
| **Java** | Spring Boot, Quarkus | Maven: `com.juspay:ucs-java` |

These SDK patterns power **33+ connectors** including Stripe, Adyen, Worldpay, Checkout, and Cybersource.

---

## Proto Interface Design Philosophy

### Resource-Oriented Messages

Our proto definitions follow HTTP semantics that developers already understand:

```protobuf
// Collections have List operations
rpc ListPayments(ListPaymentsRequest) returns (ListPaymentsResponse);

// Resources have Get operations
rpc GetPayment(GetPaymentRequest) returns (Payment);

// Actions use standard verbs
rpc Authorize(PaymentRequest) returns (PaymentResponse);
rpc Capture(CaptureRequest) returns (CaptureResponse);
rpc Refund(RefundRequest) returns (RefundResponse);
```

### Consistent Field Patterns

Every message follows predictable conventions:

```protobuf
// Amounts are always Money messages (no ambiguity)
message Money {
  int64 minor_units = 1;  // 1000 = $10.00 USD
  string currency = 2;    // ISO 4217: USD, EUR, GBP
}

// Status enums are explicit and exhaustive
enum PaymentStatus {
  PAYMENT_STATUS_UNSPECIFIED = 0;  // Proto3 requires this
  PAYMENT_STATUS_REQUIRES_ACTION = 1;  // 3DS, authentication needed
  PAYMENT_STATUS_AUTHORIZED = 2;       // Funds reserved
  PAYMENT_STATUS_CAPTURED = 3;         // Funds transferred
  PAYMENT_STATUS_FAILED = 4;           // Declined, error, etc.
}

// Timestamps use google.protobuf.Timestamp
import "google/protobuf/timestamp.proto";
message Payment {
  google.protobuf.Timestamp created_at = 1;
  google.protobuf.Timestamp expires_at = 2;
}
```

---

## Language SDKs & Integration

### The Code Generation Pipeline

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   payment.proto │────▶│  protoc + plugins │────▶│  Language SDKs  │
│   (source of    │     │  - prost (Rust)   │     │  - Rust         │
│    truth)       │     │  - tonic (gRPC)   │     │  - Node.js      │
└─────────────────┘     │  - grpclib (Py)   │     │  - Python       │
                        └─────────────────┘     │  - Java         │
                                                └─────────────────┘
```

### Type Safety Across Languages

The proto definition ensures consistency:

```protobuf
message CardPayment {
  string token = 1 [(validate.rules).string.min_len = 10];
  string network = 2;  // visa, mastercard, amex
  string last_four = 3 [(validate.rules).string.len = 4];
}
```

Generated in each language:

```python
# Python: dataclass with validation
@dataclass
class CardPayment:
    token: str  # Min length enforced at runtime
    network: str
    last_four: str  # Exactly 4 characters
```

```rust
// Rust: struct with builders
pub struct CardPayment {
    pub token: String,      // Generated code enforces min length
    pub network: String,
    pub last_four: String,  // Exactly 4 chars
}
```

```java
// Java: immutable value objects
public record CardPayment(
    @MinLength(10) String token,
    String network,
    @Length(4) String lastFour
) {}
```

### Error Handling That's Consistent

```protobuf
message Error {
  ErrorType type = 1;           // CONNECTOR_ERROR, VALIDATION_ERROR, etc.
  string code = 2;              // Machine-readable (e.g., "card_declined")
  string message = 3;           // Human-readable
  repeated ErrorDetail details = 4;  // Field-specific errors
}
```

Every SDK exposes the same error structure—catch `ConnectorError` and handle by code, regardless of which PSP or language you're using.

---

## AI-Native Architectural Frameworks

UCS adopts several proven frameworks to deliver an AI-native developer experience:

### 1. Protocol-First API Design

By defining APIs in Protocol Buffers before writing any implementation code, UCS ensures:
- **Single source of truth** across all languages
- **Self-documenting contracts** that AI can parse
- **Type safety by default** without runtime validation overhead
- **Version compatibility** through field number reservations

### 2. Resource-Oriented Architecture

Following RESTful principles at the proto level:
- Resources have consistent CRUD operations
- Actions use standard HTTP verbs (`authorize`, `capture`, `refund`)
- Relationships are explicit (`Payment` → `Refund`)
- State transitions are well-defined and documented

### 3. Documentation as Interface

In UCS, documentation is not an afterthought—it's part of the code:
- Proto comments generate SDK documentation
- Field descriptions become IDE tooltips
- Examples are embedded in the schema itself
- AI assistants read the same docs developers do

### 4. Generated Code over Handwritten SDKs

Traditional SDKs drift from the API over time. UCS generates SDKs from protos:
- Zero drift between API and SDK
- Consistent patterns across all languages
- Updates are automatic when protos change
- AI-generated code stays correct

**Connector implementations use declarative macros** that generate structs, traits, and type bridges from a single definition:

```rust
macros::create_all_prerequisites!(
    connector_name: Adyen,
    api: [
        (flow: Authorize, request_body: AdyenPaymentRequest, ...),
        (flow: Capture, request_body: AdyenCaptureRequest, ...),
    ],
);
```

---

## Vault Compatibility & PCI Modes

UCS supports three vault integration patterns, each based on different tokenization flows and integration mechanisms:

| Pattern | How It Works | Example Providers |
|---------|--------------|-------------------|
| **Network Proxy** | Route requests through vault's proxy endpoint; detokenization happens transparently | VGS, Evervault |
| **Transform Proxy** | Use template expressions (`{{token}}`) for explicit detokenization control | Basis Theory, Skyflow |
| **Relay Proxy** | Header-driven routing with token markers (`{token}`) | TokenEx |

### PCI Integration Modes

**PCI-Disabled Mode (Tokenized)**
Your application never handles raw card data. Tokens from your vault provider flow through UCS to the PSP.

```python
# Send vault tokens—UCS routes through your configured proxy
response = client.payments.authorize(
    PaymentRequest(
        amount=Money(minor_units=1000, currency="USD"),
        connector="stripe",
        payment_method=PaymentMethod(
            card=CardPayment(token="tok_sandbox_4242xxxx")
        )
    )
)
```

**PCI-Enabled Mode (Raw Card Data)**
For PCI-compliant merchants who handle raw card data, UCS accepts card numbers directly and routes to the PSP without vault intermediaries.

---

## Configurability at Every Layer

UCS provides extensive configuration options for production deployments:

### Environment & Endpoint Configuration

```yaml
# UCS supports environment-specific configs
environments:
  sandbox:
    base_url: https://sandbox.api.ucs.io
    timeout_ms: 30000
  production:
    base_url: https://api.ucs.io
    timeout_ms: 10000
    retry_policy: exponential_backoff
```

### Credential Management

| Credential Type | How UCS Handles It |
|-----------------|-------------------|
| **PSP API Keys** | Accepts standard processor API keys |
| **Standard API Key** | Single UCS API key authenticates all requests |
| **Vault Credentials** | Encrypted at rest, injected at runtime |

### Operational Controls

- **Timeout Management**: Per-connector timeouts with automatic retries
- **Proxy Configuration**: Route through corporate proxies or vault proxies
- **Circuit Breakers**: Fail fast when PSPs are degraded
- **Request Tracing**: Full observability across the payment flow

---

## Build, Release & Testing

### Multi-Architecture Binaries

UCS provides pre-built binaries for common platforms:

| Platform | Architecture | Binary |
|----------|--------------|--------|
| Linux | x86_64, ARM64 | `ucs-server-linux-{arch}` |
| macOS | x86_64, Apple Silicon | `ucs-server-darwin-{arch}` |
| Windows | x86_64 | `ucs-server-windows-x64.exe` |

Docker images are available for all major container platforms:
```bash
docker pull juspay/ucs-server:latest
docker pull juspay/ucs-server:1.2.3-alpine
```

### Test Artifact Publishing

Every UCS release includes:
- **Unit Test Reports**: JUnit XML for CI integration
- **Coverage Reports**: Codecov-compatible coverage data
- **Performance Benchmarks**: Latency percentiles by connector
- **Compatibility Matrices**: Tested PSP versions

### Regression Testing Suite

UCS maintains a comprehensive test suite:

| Test Type | Coverage |
|-----------|----------|
| **Unit Tests** | Core logic, transformers, validators |
| **Integration Tests** | Real PSP sandboxes (Stripe, Adyen, etc.) |
| **Contract Tests** | Proto compatibility verification |
| **Performance Tests** | Load testing at 1000+ TPS |
| **Security Tests** | Credential handling, PCI compliance |

All tests run on every commit. Releases are blocked if any test fails.

---

## AI-Assisted Development

### Smart Code Generation

UCS is designed for an AI-assisted development workflow. Our code generation pipeline goes beyond simple stubs:

| Feature | What You Get |
|---------|--------------|
| **IDE Integration** | Auto-complete, inline docs, type hints |
| **AI Context** | Proto definitions as context for LLMs |
| **Smart Defaults** | Sensible configurations out of the box |
| **Pattern Recognition** | Common payment flows as reusable templates |

**From natural language to working code:**

```
Developer: "Create a checkout endpoint that authorizes on Stripe
           and captures after 24 hours"

AI generates:
1. Route handler in your language/framework
2. UCS client initialization with proper config
3. Orchestrated payment flow (authorize → schedule capture)
4. Webhook handler for async events
5. Error handling for common failure modes
```

### LLMs Understand Proto Definitions

Because UCS uses Protocol Buffers, AI assistants can:

1. **Generate correct code from descriptions:**
   > "Authorize a $50 payment on Stripe using a card token"

   ```python
   response = client.payments.authorize(
       PaymentRequest(
           amount=Money(minor_units=5000, currency="USD"),
           connector="stripe",
           payment_method=PaymentMethod(
               card=CardPayment(token="tok_visa_4242")
           )
       )
   )
   ```

2. **Auto-complete with full context:**
   - Type `PaymentRequest(` and get all required fields
   - No hallucinated field names or incorrect types
   - Inline documentation from proto comments

3. **Debug with structured understanding:**
   > "Why did this payment fail?"

   The AI can parse the structured error response and suggest fixes based on the `code` and `details` fields.

---

## Comparison: Traditional vs UCS Approach

### The Old Way: Custom HTTP Integration

```python
import requests
import hmac
import json

def authorize_payment_stripe(amount, currency, card_token):
    # Auth setup
    headers = {"Authorization": f"Bearer {STRIPE_KEY}"}

    # Payload construction (easy to get wrong)
    payload = {
        "amount": amount * 100,  # Convert to cents manually
        "currency": currency.lower(),  # Wrong case = failure
        "payment_method_data": {
            "type": "card",
            "card": {"token": card_token}
        }
    }

    # Raw HTTP call
    resp = requests.post(
        "https://api.stripe.com/v1/payment_intents",
        headers=headers,
        data=payload  # x-www-form-urlencoded, not JSON!
    )

    # Error handling ( Stripe-specific )
    data = resp.json()
    if data.get("error"):
        raise PaymentError(data["error"]["message"])

    # Status parsing ( Stripe-specific values )
    status_map = {
        "requires_confirmation": "pending",
        "succeeded": "authorized"
    }

    return {
        "id": data["id"],
        "status": status_map.get(data["status"], "unknown"),
        "amount": data["amount"] / 100  # Convert back
    }
```

**Problems:**
- Type errors at runtime
- Connector-specific logic
- Documentation hunting
- Different for Stripe vs Adyen vs Worldpay

### The UCS Way: Library Integration

```python
import ucs

client = ucs.Client(api_key=UCS_API_KEY)

def authorize_payment(amount, currency, card_token, connector):
    response = client.payments.authorize(
        PaymentRequest(
            amount=Money(minor_units=amount * 100, currency=currency),
            connector=connector,
            payment_method=PaymentMethod(
                card=CardPayment(token=card_token)
            )
        )
    )

    # Same interface regardless of connector
    return response.status == PaymentStatus.AUTHORIZED
```

**Benefits:**
- Type checking catches errors before runtime
- Same code for Stripe, Adyen, Worldpay
- IDE autocomplete
- AI understands the interface

---

## Time to First Payment

| Approach | Time |
|----------|------|
| Raw HTTP + JSON | 2-3 days |
| Vendor SDK | 1 day |
| **UCS** | **30 minutes** |

The difference: UCS abstracts the connector complexity while maintaining full control.

---

## Conclusion

UCS brings payment integrations into the modern developer experience:

1. **Strongly-typed interfaces** that AI can understand
2. **Multi-language SDKs** generated from a single source of truth
3. **Industry-standard terminology** instead of vendor-specific jargon
4. **Infrastructure-as-code** support for DevOps workflows
5. **Framework-native integrations** that feel idiomatic in your stack

The result? Payment integrations that feel like using any other infrastructure service—predictable, type-safe, and delightful.

---

**Get Started:**

Choose your stack and get started in minutes:

| Language | Quick Start |
|----------|-------------|
| Rust (Actix/Axum) | `cargo add ucs-sdk` |
| Node.js (Express/NestJS) | `npm install @juspay/ucs` |
| Python (FastAPI/Django) | `pip install ucs-sdk` |
| Java (Spring) | `mvn com.juspay:ucs-java` |

- GitHub: [github.com/juspay/connector-service](https://github.com/juspay/connector-service)
- Documentation: [docs.ucs.io](https://docs.ucs.io)

---

_Think of UCS as the **ORM for payment processors**—one interface, any PSP._
