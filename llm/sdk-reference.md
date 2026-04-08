# Hyperswitch Prism SDK

**One integration. Any payment processor. Zero lock-in.**

[![npm](https://badge.fury.io/js/hyperswitch-prism.svg)](https://www.npmjs.com/package/hyperswitch-prism)
[![PyPI](https://badge.fury.io/py/hyperswitch-prism.svg)](https://pypi.org/project/hyperswitch-prism/)
[![Maven](https://img.shields.io/maven-central/v/com.hyperswitch/hyperswitch-prism.svg)](https://central.sonatype.com/artifact/com.hyperswitch/hyperswitch-prism)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A unified, type-safe SDK for payment processing. Connect to 70+ payment processors (Stripe, Adyen, PayPal, and more) through a single API.

---

## For Humans

### Quick Start (5 minutes)

**Install:**

```bash
# Node.js
npm install hyperswitch-prism

# Python
pip install hyperswitch-prism

# Java/Kotlin (Maven)
<dependency>
    <groupId>com.hyperswitch</groupId>
    <artifactId>hyperswitch-prism</artifactId>
    <version>0.0.1</version>
</dependency>

# PHP
composer require hyperswitch-prism
```

**Process a payment (Node.js):**

```typescript
const { PaymentClient, types } = require('hyperswitch-prism');

const client = new PaymentClient({
  connectorConfig: {
    stripe: { apiKey: { value: process.env.STRIPE_API_KEY } }
  }
});

const result = await client.authorize({
  merchantTransactionId: 'txn_001',
  amount: { minorAmount: 1000, currency: types.Currency.USD },
  captureMethod: types.CaptureMethod.AUTOMATIC,
  paymentMethod: {
    card: {
      cardNumber: { value: '4111111111111111' },
      cardExpMonth: { value: '12' },
      cardExpYear: { value: '2027' },
      cardCvc: { value: '123' }
    }
  },
  testMode: true
});

console.log('Status:', result.status === 8 ? 'CHARGED' : 'FAILED');
```

That's it! Switch to Adyen by changing one line:

```typescript
const client = new PaymentClient({
  connectorConfig: {
    adyen: {
      apiKey: { value: process.env.ADYEN_API_KEY },
      merchantAccount: { value: process.env.ADYEN_MERCHANT_ACCOUNT }
    }
  }
});
```

---

## For AI Assistants

### What This SDK Does

Hyperswitch Prism is a **unified connector library** that abstracts 70+ payment processors behind a single API.

1. **Request Transformation**: Converts unified payment requests to connector-specific formats
   - Input: `{ amount: { minorAmount: 1000, currency: "USD" }, ... }`
   - Output (Stripe): `{ amount: 1000, currency: "usd", ... }`
   - Output (Adyen): `{ amount: { value: 1000, currency: "USD" }, ... }`

2. **Response Normalization**: Transforms connector responses back to unified schema
   - Stripe `succeeded` → Prism `CHARGED (8)`
   - Adyen `authorised` → Prism `CHARGED (8)`

3. **Error Handling**: Provides consistent error types regardless of connector
   - `IntegrationError` - Request construction errors (bad config, missing fields)
   - `ConnectorError` - Response transformation errors
   - `NetworkError` - Network/timeout errors

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Your App (Node.js / Python / Java / PHP)                  │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│  Service Clients (PaymentClient, CustomerClient, etc.)      │
│  - PaymentClient.authorize(), capture(), refund(), void()  │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│  ConnectorClient (HTTP execution + connection pooling)      │
│  - undici (Node), httpx (Python), OkHttp (Java)            │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│  FFI Bindings (koffi/UniFFI → Rust core)                   │
│  - connector-service-ffi.{node,so,dll}                     │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│  Rust Core (transformation logic)                          │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Connector Adapters (Stripe, Adyen, PayPal, +68)   │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
         Payment Processor APIs (Stripe, Adyen, etc.)
```

### Key Files

| Language | File | Purpose |
|----------|------|---------|
| Node.js | `src/index.ts` | Public API exports |
| Node.js | `src/connector-client.ts` | HTTP execution |
| Node.js | `src/ffi/connector-service-ffi.ts` | koffi FFI bindings |
| Python | `src/payments/__init__.py` | Public API |
| Python | `src/payments/connector_client.py` | httpx execution |
| Java | `src/main/kotlin/.../payments/` | Public API |

---

## Installation & Configuration

### Node.js (v18+)

```bash
npm install hyperswitch-prism
```

```typescript
import { PaymentClient, types } from 'hyperswitch-prism';

const config: types.ConnectorConfig = {
  connectorConfig: {
    stripe: { apiKey: { value: process.env.STRIPE_API_KEY! } }
  }
};
const client = new PaymentClient(config);
```

### Python (3.9+)

```bash
pip install hyperswitch-prism
```

```python
from payments import PaymentClient
from payments.generated import sdk_config_pb2, payment_pb2
from payments import SecretString
import os

cfg = sdk_config_pb2.ConnectorConfig(
    options=sdk_config_pb2.SdkOptions(environment=sdk_config_pb2.Environment.SANDBOX)
)
cfg.connector_config.CopyFrom(payment_pb2.ConnectorSpecificConfig(
    stripe=payment_pb2.StripeConfig(
        api_key=SecretString(value=os.environ["STRIPE_API_KEY"])
    )
))
client = PaymentClient(cfg)
```

### Java/Kotlin (JDK 17+)

```xml
<dependency>
  <groupId>com.hyperswitch</groupId>
  <artifactId>hyperswitch-prism</artifactId>
  <version>0.0.1</version>
</dependency>
```

```kotlin
import com.hyperswitch.payments.*

val stripeConfig = ConnectorConfig(
    connectorConfig = ConnectorConfig.ConnectorConfigOneOf.Stripe(
        StripeConfig(apiKey = SecretString(value = System.getenv("STRIPE_API_KEY")))
    )
)
val client = PaymentClient(stripeConfig)
```

### PHP (8.0+)

```bash
composer require hyperswitch-prism
```

```php
$config = [
    'connectorConfig' => [
        'stripe' => ['apiKey' => ['value' => $_ENV['STRIPE_API_KEY']]]
    ]
];
$client = new PaymentClient($config);
```

---

## Connector Authentication

### Stripe (HeaderKey)
```typescript
{ connectorConfig: { stripe: { apiKey: { value: 'sk_test_xxx' } } } }
```

### Adyen (HeaderKey + MerchantAccount)
```typescript
{
  connectorConfig: {
    adyen: {
      apiKey: { value: 'xxx' },
      merchantAccount: { value: 'MerchantAccount' }
    }
  }
}
```

### PayPal (SignatureKey)
```typescript
{
  connectorConfig: {
    paypal: {
      clientId: { value: 'xxx' },
      clientSecret: { value: 'xxx' }
    }
  }
}
```

### 70+ More Connectors
- Bank of America, Braintree, Cashfree, Cybersource, Fiserv, Globalpay, Helcim, NMI, Nuvei, Rapyd, Revolut, Shift4, Stax, WorldPay, Xendit, and more...

---

## Payment Operations

### Authorize (Hold Funds)

```typescript
const auth = await client.authorize({
  merchantTransactionId: 'txn_001',
  amount: { minorAmount: 1000, currency: types.Currency.USD },
  captureMethod: types.CaptureMethod.MANUAL,  // MANUAL or AUTOMATIC
  paymentMethod: {
    card: {
      cardNumber: { value: '4111111111111111' },
      cardExpMonth: { value: '12' },
      cardExpYear: { value: '2027' },
      cardCvc: { value: '123' },
      cardHolderName: { value: 'John Doe' }
    }
  },
  address: { billingAddress: {} },
  authType: types.AuthenticationType.NO_THREE_DS,
  testMode: true
});

// auth.status === 6 (AUTHORIZED) - funds held
```

### Capture (Capture Held Funds)

```typescript
const capture = await client.capture({
  merchantCaptureId: 'cap_001',
  connectorTransactionId: auth.connectorTransactionId!,
  amountToCapture: { minorAmount: 1000, currency: types.Currency.USD },
  testMode: true
});

// capture.status === 8 (CHARGED)
```

### Refund

```typescript
const refund = await client.refund({
  merchantRefundId: 'ref_001',
  connectorTransactionId: auth.connectorTransactionId!,
  refundAmount: { minorAmount: 500, currency: types.Currency.USD },
  reason: 'RETURN',  // Use: OTHER, RETURN, DUPLICATE, FRAUD
  testMode: true
});

// refund.status === 4 (REFUND_SUCCESS) or 3 (REFUND_PENDING)
```

### Void (Cancel Authorization)

```typescript
const voidResult = await client.void({
  merchantVoidId: 'void_001',
  connectorTransactionId: auth.connectorTransactionId!,
  cancellationReason: 'Customer cancelled',
  testMode: true
});

// voidResult.status === 11 (VOIDED)
```

---

## Error Handling

### Error Types

| Error Type | When | Example |
|------------|------|---------|
| `IntegrationError` | Bad config, missing field, serialization | Missing `browserInfo` for Adyen |
| `ConnectorError` | Response transform failed | Invalid refund reason for connector |
| `NetworkError` | Timeout, DNS, connection refused | Connector timeout |

### Handling

```typescript
import { IntegrationError, ConnectorError, NetworkError, types } from 'hyperswitch-prism';

try {
  const response = await client.authorize(request);

  // Soft declines come as status, NOT exceptions
  if (response.status === types.PaymentStatus.FAILURE) {
    console.error('Declined:', response.error?.message);
    return;
  }

} catch (error) {
  if (error instanceof IntegrationError) {
    console.error('Integration error:', error.errorCode, error.message);
  } else if (error instanceof ConnectorError) {
    console.error('Connector error:', error.errorCode, error.message);
  } else if (error instanceof NetworkError) {
    console.error('Network error:', error.message);
  }
}
```

### Common Error Codes

| Code | Type | Fix |
|------|------|-----|
| `MISSING_REQUIRED_FIELD: browser_info` | IntegrationError | Add `browserInfo` for Adyen |
| `INVALID_CONFIGURATION` | IntegrationError | Check connector config |
| `CONNECT_TIMEOUT` | NetworkError | Check network/proxy |
| `TOTAL_TIMEOUT` | NetworkError | Increase `totalTimeoutMs` |

---

## Status Codes (CRITICAL)

**Always use numeric enums, NOT strings:**

```typescript
// ❌ WRONG - response.status is a number
if (response.status === 'CHARGED') { }  // Always false!

// ✅ CORRECT - use numeric enum
if (response.status === types.PaymentStatus.CHARGED) { }  // === 8
if (response.status === 8) { }  // Equivalent
```

### PaymentStatus

| Value | Name | Meaning |
|-------|------|---------|
| 0 | UNSPECIFIED | Unknown |
| 1 | STARTED | Payment initiated |
| 4 | AUTHENTICATION_PENDING | Awaiting 3DS |
| 5 | AUTHENTICATION_SUCCESSFUL | 3DS passed |
| 6 | AUTHORIZED | Auth succeeded, not captured |
| 7 | AUTHORIZATION_FAILED | Declined |
| 8 | CHARGED | Captured / auto-capture success |
| 11 | VOIDED | Authorization cancelled |
| 20 | PENDING | Processing (async connectors) |
| 21 | FAILURE | Soft decline - check error |

### RefundStatus (DIFFERENT enum!)

| Value | Name | Meaning |
|-------|------|---------|
| 1 | REFUND_FAILURE | Refund failed |
| 2 | REFUND_MANUAL_REVIEW | Pending review |
| 3 | REFUND_PENDING | Processing (normal for Adyen) |
| 4 | REFUND_SUCCESS | Completed |

⚠️ **CRITICAL**: PaymentStatus and RefundStatus share overlapping values!
- Value `4` = `AUTHENTICATION_PENDING` (PaymentStatus)
- Value `4` = `REFUND_SUCCESS` (RefundStatus)

Always use `types.PaymentStatus` for authorize/capture/void responses and `types.RefundStatus` for refund responses.

---

## Connector-Specific Requirements

### browserInfo (Required for Some Connectors)

| Connector | When Required |
|-----------|---------------|
| Adyen | Always for card payments |
| Cybersource | 3DS flows |
| Any connector | When `authType: THREE_DS` |

```typescript
browserInfo: {
  colorDepth: 24,
  screenHeight: 900,
  screenWidth: 1440,
  javaEnabled: false,
  javaScriptEnabled: true,
  language: 'en-US',
  timeZoneOffsetMinutes: 0,
  acceptHeader: 'text/html,*/*;q=0.8',
  userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)'
}
```

### Test Cards (Sandbox)

| Connector | Card Number | CVC | Expiry |
|-----------|-------------|-----|--------|
| Stripe | 4111111111111111 | 123 | Any |
| Adyen | 4111111111111111 | 737 | 03/2030 |
| PayPal | 4111111111111111 | 123 | Any |
| Braintree | 4111111111111111 | 123 | Any |

### Refund Reasons (Connector Constraints)

| Connector | Accepted Values |
|-----------|----------------|
| Adyen | OTHER, RETURN, DUPLICATE, FRAUD, CUSTOMER REQUEST |
| Stripe | Any free-text string |

---

## Advanced Configuration

### Timeouts

```typescript
const client = new PaymentClient(config, {
  http: {
    totalTimeoutMs: 30000,
    connectTimeoutMs: 10000,
    responseTimeoutMs: 25000
  }
});
```

### Proxy

```typescript
const client = new PaymentClient(config, {
  http: {
    proxy: {
      httpsUrl: 'https://proxy.company.com:8443',
      bypassUrls: ['http://localhost']
    }
  }
});
```

### Per-Request Override

```typescript
const response = await client.authorize(request, {
  http: { totalTimeoutMs: 60000 }
});
```

---

## Field Probe (Connector Discovery)

Prism includes a **field-probe** tool that discovers required fields and sample payloads for every connector × flow × payment-method combination WITHOUT making HTTP calls.

### How Field Probe Works

1. Builds a maximally-populated proto request with all standard fields
2. Calls the FFI `req_transformer` directly (no HTTP)
3. Records the transformed request (URL, method, headers, body)

### Field Probe Output

Each connector generates a JSON file showing supported flows and payment methods:

```json
{
  "connector": "stripe",
  "flows": {
    "authorize": {
      "Card": {
        "status": "supported",
        "proto_request": { "merchant_transaction_id": "probe_txn_001", ... },
        "sample": {
          "url": "https://api.stripe.com/v1/payment_intents",
          "method": "POST",
          "headers": { "authorization": "Bearer probe_key", ... },
          "body": "amount=1000&currency=USD&..."
        }
      },
      "PayPal": { "status": "supported", ... },
      "Klarna": { "status": "supported", ... }
    }
  }
}
```

### Using Field Probe Data

Field probe outputs are used to generate:
- **Connector Documentation**: `docs-generated/connectors/{connector}.md`
- **SDK Examples**: `examples/{connector}/{connector}.{ts,py,kt,rs}`

### Available Connectors (70+)

Field probe has generated data for: stripe, adyen, paypal, braintree, cybersource, checkout, worldpay, authorize.net, bluesnap, airwallex, cashfree, razorpay, mollie, nuvei, rapyd, globalpay, fiserv, bankofamerica, and 50+ more.

---

## Connector Examples

Complete, runnable examples for each connector in all 4 languages:

### Stripe

```
examples/stripe/
├── stripe.ts    # Node.js
├── stripe.py    # Python
├── stripe.kt    # Kotlin
└── stripe.rs    # Rust
```

**Available scenarios:**
- `processCheckoutAutocapture` - One-step payment
- `processCheckoutCard` - Two-step (authorize + capture)
- `processRefund` - Refund a payment
- `processVoidPayment` - Cancel authorization
- `processGetPayment` - Check payment status
- `authorize`, `capture`, `refund`, `void` - Individual flows

### Adyen

```
examples/adyen/
├── adyen.ts
├── adyen.py
├── adyen.kt
└── adyen.rs
```

### PayPal

```
examples/paypal/
├── paypal.ts
├── paypal.py
├── paypal.kt
└── paypal.rs
```

### More Connectors

Full list in `examples/` directory:
- aci, adyen, authorizedotnet, bambora, bankofamerica, braintree, checkout, cybersource, datatrans, dlocal, fiserv, globalpay, helcim, mollie, novalnet, nuvei, paypal, paytm, razorpay, stripe, trustly, worldpay, xendit, and many more...

---

## API Reference (Per Connector)

Each connector has auto-generated docs at `docs-generated/connectors/{connector}.md` showing:

### SDK Configuration
```typescript
// Stripe
const client = new PaymentClient({
  connectorConfig: {
    stripe: { apiKey: { value: 'YOUR_API_KEY' } }
  }
});

// Adyen
const client = new PaymentClient({
  connectorConfig: {
    adyen: {
      apiKey: { value: 'YOUR_API_KEY' },
      merchantAccount: { value: 'YOUR_MERCHANT_ACCOUNT' }
    }
  }
});
```

### Supported Payment Methods

| Payment Method | Stripe | Adyen | PayPal |
|----------------|:------:|:-----:|:------:|
| Card | ✓ | ✓ | - |
| Apple Pay | ✓ | ✓ | - |
| Google Pay | ✓ | ✓ | - |
| PayPal | ✓ | ✓ | ✓ |
| Klarna | ✓ | ✓ | - |
| iDEAL | ✓ | ✓ | - |
| ... | | | |

### Integration Scenarios

Each connector doc shows:
- One-step payment (authorize + capture)
- Two-step payment (authorize, then capture)
- Refund flow
- Void flow
- Get payment status

---

## Development

### Build from Source

```bash
# Clone
git clone https://github.com/juspay/hyperswitch-prism.git
cd hyperswitch-prism/sdk/javascript

# Build
make pack

# Test with live credentials
STRIPE_API_KEY=sk_test_xxx make test-pack
```

### Platform Support

| Platform | Architectures |
|----------|---------------|
| macOS | x86_64, arm64 |
| Linux | x86_64, aarch64 |
| Windows | x86_64 |

---

## Service Clients

| Client | Methods |
|--------|---------|
| `PaymentClient` | authorize, capture, refund, void, get, sync |
| `CustomerClient` | create |
| `PaymentMethodClient` | tokenize |
| `MerchantAuthenticationClient` | createServerAuthenticationToken, createClientAuthenticationToken |
| `PaymentMethodAuthenticationClient` | preAuthenticate, authenticate, postAuthenticate |
| `RecurringPaymentClient` | setup, charge, revoke |
| `EventClient` | handleEvent (webhooks) |
| `RefundClient` | get, createRefund, updateRefund |
| `DisputeClient` | accept, defend, submitEvidence, get |

---

## What's Next

- [Full API Reference](./api-reference/)
- [Architecture Documentation](./architecture/)
- [Connector Examples](https://github.com/juspay/hyperswitch-prism/tree/main/examples)
- [Field Probe Data](https://github.com/juspay/hyperswitch-prism/tree/main/data/field_probe)
- [Report Issues](https://github.com/juspay/hyperswitch-prism/issues)
