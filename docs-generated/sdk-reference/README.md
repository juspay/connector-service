# SDK Reference

Complete reference for Prism SDKs in Node.js, Python, Java/Kotlin, and JavaScript.

Prism provides native SDKs that embed directly into your application via FFI (Foreign Function Interface). Each SDK offers type-safe clients for all payment services with automatic connection pooling, error handling, and request/response serialization.

## Service Clients

Each SDK provides specialized clients for different payment operations:

| Service | Purpose | Key Methods | SDK Reference |
|---------|---------|-------------|---------------|
| PaymentService | Core payment lifecycle | `authorize()`, `capture()`, `refund()`, `void()`, `createOrder()` | [Node.js](https://github.com/juspay/hyperswitch-prism/tree/main/sdk/javascript/src/payments/_generated_connector_client_flows.ts) · [Python](https://github.com/juspay/hyperswitch-prism/tree/main/sdk/python/src/payments/_generated_service_clients.py) · [Java](https://github.com/juspay/hyperswitch-prism/tree/main/sdk/java/src/main/kotlin/GeneratedFlows.kt) |
| RefundService | Refund operations | `get()` | [Node.js](https://github.com/juspay/hyperswitch-prism/tree/main/sdk/javascript/src/payments/_generated_connector_client_flows.ts) · [Python](https://github.com/juspay/hyperswitch-prism/tree/main/sdk/python/src/payments/_generated_service_clients.py) · [Java](https://github.com/juspay/hyperswitch-prism/tree/main/sdk/java/src/main/kotlin/GeneratedFlows.kt) |
| RecurringPaymentService | Subscription billing | `charge()`, `revoke()` | [Node.js](https://github.com/juspay/hyperswitch-prism/tree/main/sdk/javascript/src/payments/_generated_connector_client_flows.ts) · [Python](https://github.com/juspay/hyperswitch-prism/tree/main/sdk/python/src/payments/_generated_service_clients.py) · [Java](https://github.com/juspay/hyperswitch-prism/tree/main/sdk/java/src/main/kotlin/GeneratedFlows.kt) |
| DisputeService | Chargeback handling | `accept()`, `defend()`, `submitEvidence()` | [Node.js](https://github.com/juspay/hyperswitch-prism/tree/main/sdk/javascript/src/payments/_generated_connector_client_flows.ts) · [Python](https://github.com/juspay/hyperswitch-prism/tree/main/sdk/python/src/payments/_generated_service_clients.py) · [Java](https://github.com/juspay/hyperswitch-prism/tree/main/sdk/java/src/main/kotlin/GeneratedFlows.kt) |
| EventService | Webhook processing | `handle()` | [Node.js](https://github.com/juspay/hyperswitch-prism/tree/main/sdk/javascript/src/payments/_generated_connector_client_flows.ts) · [Python](https://github.com/juspay/hyperswitch-prism/tree/main/sdk/python/src/payments/_generated_service_clients.py) · [Java](https://github.com/juspay/hyperswitch-prism/tree/main/sdk/java/src/main/kotlin/GeneratedFlows.kt) |
| CustomerService | Customer management | `create()` | [Node.js](https://github.com/juspay/hyperswitch-prism/tree/main/sdk/javascript/src/payments/_generated_connector_client_flows.ts) · [Python](https://github.com/juspay/hyperswitch-prism/tree/main/sdk/python/src/payments/_generated_service_clients.py) · [Java](https://github.com/juspay/hyperswitch-prism/tree/main/sdk/java/src/main/kotlin/GeneratedFlows.kt) |
| PaymentMethodService | Payment method storage | `tokenize()` | [Node.js](https://github.com/juspay/hyperswitch-prism/tree/main/sdk/javascript/src/payments/_generated_connector_client_flows.ts) · [Python](https://github.com/juspay/hyperswitch-prism/tree/main/sdk/python/src/payments/_generated_service_clients.py) · [Java](https://github.com/juspay/hyperswitch-prism/tree/main/sdk/java/src/main/kotlin/GeneratedFlows.kt) |
| PaymentMethodAuthenticationService | 3DS authentication | `preAuthenticate()`, `authenticate()`, `postAuthenticate()` | [Node.js](https://github.com/juspay/hyperswitch-prism/tree/main/sdk/javascript/src/payments/_generated_connector_client_flows.ts) · [Python](https://github.com/juspay/hyperswitch-prism/tree/main/sdk/python/src/payments/_generated_service_clients.py) · [Java](https://github.com/juspay/hyperswitch-prism/tree/main/sdk/java/src/main/kotlin/GeneratedFlows.kt) |
| MerchantAuthenticationService | Session management | `createAccessToken()`, `createSessionToken()`, `createSdkSessionToken()` | [Node.js](https://github.com/juspay/hyperswitch-prism/tree/main/sdk/javascript/src/payments/_generated_connector_client_flows.ts) · [Python](https://github.com/juspay/hyperswitch-prism/tree/main/sdk/python/src/payments/_generated_service_clients.py) · [Java](https://github.com/juspay/hyperswitch-prism/tree/main/sdk/java/src/main/kotlin/GeneratedFlows.kt) |

## SDK Clients by Language

The table above shows service names. Below is the mapping to SDK-specific client class names:

| Service | Node.js Client | Python Client | Java/Kotlin Client |
|---------|---------------|---------------|-------------------|
| PaymentService | `PaymentClient` | `PaymentClient` | `PaymentClient` |
| RefundService | `RefundClient` | `RefundClient` | `RefundClient` |
| RecurringPaymentService | `RecurringPaymentClient` | `RecurringPaymentClient` | `RecurringPaymentClient` |
| DisputeService | `DisputeClient` | `DisputeClient` | `DisputeClient` |
| EventService | `EventClient` | `EventClient` | `EventClient` |
| CustomerService | `CustomerClient` | `CustomerClient` | `CustomerClient` |
| PaymentMethodService | `PaymentMethodClient` | `PaymentMethodClient` | `PaymentMethodClient` |
| PaymentMethodAuthenticationService | `PaymentMethodAuthenticationClient` | `PaymentMethodAuthenticationClient` | `PaymentMethodAuthenticationClient` |
| MerchantAuthenticationService | `MerchantAuthenticationClient` | `MerchantAuthenticationClient` | `MerchantAuthenticationClient` |

## Quick Start

### Node.js

```typescript
import { PaymentClient, types } from 'hs-playlib';

const { ConnectorConfig, Connector, Environment, Currency, CaptureMethod } = types;

const config = ConnectorConfig.create({
  connector: Connector.STRIPE,
  auth: {
    stripe: {
      apiKey: { value: 'sk_test_your_key' }
    }
  },
  environment: Environment.SANDBOX,
});

const client = new PaymentClient(config);

const request = PaymentServiceAuthorizeRequest.create({
  merchantTransactionId: 'txn_001',
  amount: {
    minorAmount: 1000,
    currency: Currency.USD,
  },
  captureMethod: CaptureMethod.AUTOMATIC,
  paymentMethod: {
    card: {
      cardNumber: { value: '4111111111111111' },
      cardExpMonth: { value: '12' },
      cardExpYear: { value: '2027' },
      cardCvc: { value: '123' },
    }
  },
  testMode: true,
});

const response = await client.authorize(request);
console.log('Status:', response.status);
```

### Python

```python
from payments import PaymentClient, PaymentServiceAuthorizeRequest

metadata = {
    "connector": "Stripe",
    "connector_auth_type": {
        "auth_type": "HeaderKey",
        "api_key": "sk_test_your_key"
    }
}

client = PaymentClient(metadata)

request = PaymentServiceAuthorizeRequest(
    merchant_transaction_id="txn_001",
    amount={"minor_amount": 1000, "currency": "USD"},
    payment_method={
        "card": {
            "card_number": "4111111111111111",
            "expiry_month": "12",
            "expiry_year": "2027",
            "card_cvc": "123"
        }
    },
    test_mode=True
)

response = await client.authorize(request)
print(f"Status: {response.status}")
```

### Java/Kotlin

```kotlin
import payments.PaymentClient
import payments.PaymentServiceAuthorizeRequest

val metadata = ConnectorMetadata(
    connector = "Stripe",
    connectorAuthType = AuthType.HeaderKey(apiKey = "sk_test_your_key")
)

val client = PaymentClient(metadata)

val request = PaymentServiceAuthorizeRequest.newBuilder()
    .setMerchantTransactionId("txn_001")
    .setAmount(Money.newBuilder()
        .setMinorAmount(1000)
        .setCurrency("USD")
        .build())
    .setPaymentMethod(PaymentMethod.newBuilder()
        .setCard(Card.newBuilder()
            .setCardNumber("4111111111111111")
            .setExpiryMonth("12")
            .setExpiryYear("2027")
            .build())
        .build())
    .setTestMode(true)
    .build()

val response = client.authorize(request)
println("Status: ${response.status}")
```

## SDK Architecture

All SDKs follow the same layered architecture:

```
Your Application
       ↓
   Service Client (typed API)
       ↓
   ConnectorClient (FFI bindings)
       ↓
   UniFFI FFI Layer
       ↓
   Rust Core (Prism)
       ↓
   Payment Processor API (Stripe, Adyen, etc.)
```

## Configuration

### Connector Configuration

| Field | Type | Description |
|-------|------|-------------|
| `connector` | `Connector` | The payment processor (Stripe, PayPal, Adyen, etc.) |
| `auth` | `AuthConfig` | Authentication credentials (API keys, secrets) |
| `environment` | `Environment` | `SANDBOX` or `PRODUCTION` |

### Request Configuration

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `timeout` | `int` | 30000 | Request timeout in milliseconds |
| `proxy` | `string` | None | HTTP proxy URL |
| `retry` | `int` | 0 | Number of retry attempts |

## Error Handling

All SDKs throw structured errors with consistent fields:

| Field | Description |
|-------|-------------|
| `errorCode` | Machine-readable error code |
| `message` | Human-readable error description |
| `statusCode` | HTTP status code (if applicable) |

Common error codes:

| Code | Description |
|------|-------------|
| `CONNECT_TIMEOUT` | Failed to establish connection |
| `RESPONSE_TIMEOUT` | No response received from gateway |
| `INVALID_CONFIGURATION` | Configuration error |
| `NETWORK_FAILURE` | General network error |

## Building from Source

### Prerequisites

- Rust toolchain (`cargo`)
- `protoc` (Protocol Buffers compiler)
- Language-specific toolchain (Node.js 18+, Python 3.9+, JDK 17+)

### Build Commands

```bash
# Node.js
make -C sdk/javascript pack

# Python
make -C sdk/python pack

# Java/Kotlin
make -C sdk/java pack
```

## Additional Resources

- [API Reference](../api-reference/) - Detailed service operation documentation
- [Connectors](../connectors/) - Supported payment processors
- [Architecture](../../architecture/concepts/library-modes-of-usage.md) - Library vs Microservice modes
