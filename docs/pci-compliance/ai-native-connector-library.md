# UCS: The AI-Native Connector Library for Payments

> What if integrating Stripe, Adyen, or Worldpay was as simple as `redis.get()` or `db.query()`?

---

## Introduction

Every developer has experienced this: you're building a feature, everything's going smoothly, and then you need to integrate payments. Suddenly you're drowning in API documentation, webhook signatures, idempotency keys, and connector-specific quirks. The cognitive load explodes.

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

### Clear Request/Response Flows

```protobuf
// Request includes everything needed for the operation
message CaptureRequest {
  // What to capture
  string payment_id = 1;

  // Optional partial capture
  Money amount = 2;  // If unset, captures full authorized amount

  // Connector-specific overrides
  map<string, string> connector_metadata = 3;
}

// Response tells you what happened
message CaptureResponse {
  string capture_id = 1;              // New transaction reference
  PaymentStatus status = 2;           // CAPTURED or FAILED
  Money amount_captured = 3;          // Actual amount moved
  google.protobuf.Timestamp captured_at = 4;
}
```

---

## Language SDKs & Integration

### The Code Generation Pipeline

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   payment.proto │────▶│  protoc + plugins │────▶│  Language SDKs  │
│   (source of    │     │  - prost (Rust)   │     │  - Go           │
│    truth)       │     │  - tonic (gRPC)   │     │  - Python       │
└─────────────────┘     │  - grpclib (Py)   │     │  - Rust         │
                        └─────────────────┘     │  - Java         │
                                                │  - Node.js      │
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

```go
// Go: struct with tags
type CardPayment struct {
    Token    string `protobuf:"bytes,1,opt,name=token" validate:"min=10"`
    Network  string `protobuf:"bytes,2,opt,name=network"`
    LastFour string `protobuf:"bytes,3,opt,name=last_four" validate:"len=4"`
}
```

```rust
// Rust: struct with builders
pub struct CardPayment {
    pub token: String,      // Generated code enforces min length
    pub network: String,
    pub last_four: String,  // Exactly 4 chars
}
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

Every SDK exposes the same error structure:

```python
try:
    response = client.payments.authorize(request)
except ucs.ConnectorError as e:
    if e.code == "card_declined":
        return {"error": "Please try a different card"}
    raise
```

```go
resp, err := client.Payments.Authorize(ctx, req)
if err != nil {
    if ucsErr, ok := err.(*ucs.ConnectorError); ok {
        if ucsErr.Code == "card_declined" {
            return map[string]string{"error": "Please try a different card"}
        }
    }
}
```

---

## AI-Assisted Development

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

### Documentation That Makes Sense

```protobuf
// A payment represents a monetary transaction between a customer
// and a merchant. Payments go through a lifecycle: created →
// authorized → captured (or voided/refunded).
message Payment {
  // Unique identifier for this payment (UCS-generated)
  string payment_id = 1;

  // The amount the customer authorized. This may differ from
  // the capture amount in partial capture scenarios.
  Money amount_authorized = 2;

  // Current status in the payment lifecycle
  PaymentStatus status = 3;

  // The connector (PSP) that processed this payment
  string connector = 4;
}
```

Proto comments become:
- IDE tooltips
- Generated documentation
- AI context for code generation

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

## The Future: Infrastructure as Code

### Terraform-Style Configuration

```hcl
# connectors.tf
resource "ucs_connector" "stripe" {
  name = "stripe"
  base_url = "https://api.stripe.com"
  api_key = var.stripe_api_key
}

resource "ucs_connector" "adyen" {
  name = "adyen"
  base_url = "https://api.adyen.com"
  api_key = var.adyen_api_key
  merchant_account = var.adyen_merchant
}

# Enable VGS vault for PCI compliance
resource "ucs_vault" "vgs" {
  provider = "vgs"
  tenant_id = var.vgs_tenant
  environment = "production"
}
```

### Declarative Payment Flows

```yaml
# payment-flow.yaml
apiVersion: ucs.io/v1
kind: PaymentFlow
metadata:
  name: checkout-flow
spec:
  steps:
    - name: authorize
      action: authorize
      connector: stripe
      amount: "${order.total}"

    - name: fraud-check
      action: webhook
      url: https://api.example.com/fraud-check
      condition: "amount > 10000"

    - name: capture
      action: capture
      delay: 24h  # Capture after fulfillment
```

---

## Conclusion

UCS brings payment integrations into the modern developer experience:

1. **Strongly-typed interfaces** that AI can understand
2. **Multi-language SDKs** generated from a single source of truth
3. **Industry-standard terminology** instead of vendor-specific jargon
4. **Infrastructure-as-code** support for DevOps workflows

The result? Payment integrations that feel like using any other infrastructure service—predictable, type-safe, and delightful.

---

**Get Started:**
- GitHub: [github.com/juspay/connector-service](https://github.com/juspay/connector-service)
- Documentation: [docs.ucs.io](https://docs.ucs.io)
- SDKs: `pip install ucs`, `go get github.com/juspay/ucs-go`, `cargo add ucs`

---

_Think of UCS as the "PostgreSQL of payments"—a reliable, well-documented, type-safe interface that just works, regardless of what language you're using or which PSP you're connecting to._
