# Hyperswitch Prism SDK

[![npm](https://badge.fury.io/js/hyperswitch-prism.svg)](https://www.npmjs.com/package/hyperswitch-prism)
[![PyPI](https://badge.fury.io/py/hyperswitch-prism.svg)](https://pypi.org/project/hyperswitch-prism/)
[![Maven](https://img.shields.io/maven-central/v/com.hyperswitch/hyperswitch-prism.svg)](https://central.sonatype.com/artifact/com.hyperswitch/hyperswitch-prism)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

**One integration. Any payment processor. Zero lock-in.**  
A unified, type-safe SDK for 70+ payment processors (Stripe, Adyen, PayPal, and more) through a single API.

---

## SECTION 0 — AI AGENT PROTOCOL (Read This First, Always)

> **If you are an AI assistant generating integration code, this section is your entry point. Do NOT skip to quick-start examples.**

### Mandatory Decision Tree

```
START HERE
    │
    ▼
Are you writing ANY payment integration code?
    │
    YES
    │
    ▼
STEP 1 ──► Run Field Probe (Section 1) for your connector × flow × payment-method
    │         Command: npx hyperswitch-prism probe --connector <name> --flow <flow>
    │         This reveals REQUIRED fields. TypeScript types alone are NOT sufficient.
    │
    ▼
STEP 2 ──► Read the inline Connector Example (Section 2) for your connector
    │         Use exact field names, structures, and patterns from the example.
    │         Do NOT invent field names from TypeScript types.
    │
    ▼
STEP 3 ──► Apply the Integration Rules (Section 3)
    │         Status codes, error handling, enum usage.
    │
    ▼
STEP 4 ──► Only now write code
```

### Why This Order Is Non-Negotiable

| If you skip... | You will get... |
|----------------|----------------|
| Field Probe | `IntegrationError: MISSING_REQUIRED_FIELD` at runtime |
| Connector Examples | Type mismatches, wrong config format, silent failures |
| Integration Rules | Status comparisons that always return `false` |

### System Prompt Snippet (for developers using AI assistants)

Paste this into your AI assistant's system prompt when working with this SDK:

```
When integrating Hyperswitch Prism:
1. Always run `npx hyperswitch-prism probe --connector <name> --flow <flow>` before writing code.
2. Use the inline connector examples in Section 2 as the source of truth for request structure.
3. Never compare response.status to a string. Always use numeric values (e.g., status === 8).
4. Do not assume TypeScript types match runtime requirements. Field Probe output overrides types.
```

---

## SECTION 1 — Field Probe (Run Before Writing Code)

The field-probe tool discovers required fields, types, and sample payloads for every connector × flow × payment-method combination **without making any HTTP calls**.

### How to Run Field Probe

```bash
# Discover fields for a specific connector + flow + payment method
npx hyperswitch-prism probe --connector stripe --flow authorize --payment-method card

# Discover all flows for a connector
npx hyperswitch-prism probe --connector adyen --all-flows

# Output as JSON (for programmatic use)
npx hyperswitch-prism probe --connector stripe --flow authorize --payment-method card --json
```

### How to Read Field Probe Output

```json
{
  "connector": "stripe",
  "flow": "authorize",
  "paymentMethod": "Card",
  "status": "supported",
  "fieldsprops": {
    "merchant_transaction_id":  { "required": true,  "type": "string" },
    "amount.minor_amount":      { "required": true,  "type": "int64" },
    "amount.currency":          { "required": true,  "type": "Currency enum" },
    "capture_method":           { "required": true,  "type": "CaptureMethod enum" },
    "payment_method.card.card_number":   { "required": true,  "type": "SecretString" },
    "payment_method.card.card_exp_month":{ "required": true,  "type": "SecretString" },
    "payment_method.card.card_exp_year": { "required": true,  "type": "SecretString" },
    "payment_method.card.card_cvc":      { "required": true,  "type": "SecretString" },
    "browser_info":             { "required": false, "type": "BrowserInfo object" },
    "auth_type":                { "required": false, "type": "AuthenticationType enum" }
  },
  "sample": {
    "url": "https://api.stripe.com/v1/payment_intents",
    "method": "POST",
    "body": "amount=1000&currency=usd&..."
  }
}
```

### Field Probe: Connector × Flow × Required Fields (Quick Reference)

This table summarizes the most commonly missed required fields. **Field Probe output is authoritative — use it to confirm.**

```
┌─────────────┬───────────┬─────────────────────────────────────────────────────┐
│ Connector   │ Flow      │ Fields Required BEYOND the common base              │
├─────────────┼───────────┼─────────────────────────────────────────────────────┤
│ stripe      │ authorize │ (no extras for card)                                │
│ stripe      │ capture   │ connectorTransactionId                              │
│ stripe      │ refund    │ connectorTransactionId, refundAmount, reason        │
│ stripe      │ void      │ connectorTransactionId                              │
├─────────────┼───────────┼─────────────────────────────────────────────────────┤
│ adyen       │ authorize │ browserInfo (ALWAYS required for card)              │
│             │           │ merchantAccount (in config)                         │
│ adyen       │ refund    │ reason must be one of: OTHER, RETURN, DUPLICATE,   │
│             │           │   FRAUD, CUSTOMER_REQUEST (not free-text)           │
├─────────────┼───────────┼─────────────────────────────────────────────────────┤
│ paypal      │ authorize │ clientId + clientSecret (SignatureKey config)       │
│ braintree   │ authorize │ (no extras for card)                                │
│ cybersource │ authorize │ browserInfo required for 3DS flows                 │
└─────────────┴───────────┴─────────────────────────────────────────────────────┘
```

---

## SECTION 2 — Connector Examples (Use As Source of Truth)

> **Copy these patterns exactly.** Do not invent field names from TypeScript types. These examples are tested and verified.

### 2.1 — Stripe

#### Node.js — Full Authorize + Capture + Refund + Void

```typescript
import { PaymentClient, IntegrationError, ConnectorError, NetworkError, types } from 'hyperswitch-prism';

// ── CONFIG ──────────────────────────────────────────────────────────────────
const client = new PaymentClient({
  connectorConfig: {
    stripe: { apiKey: { value: process.env.STRIPE_API_KEY! } }
  }
});

// ── AUTHORIZE (hold funds, manual capture) ──────────────────────────────────
const authResult = await client.authorize({
  merchantTransactionId: 'txn_001',
  amount: { minorAmount: 1000, currency: types.Currency.USD },
  captureMethod: types.CaptureMethod.MANUAL,
  paymentMethod: {
    card: {
      cardNumber:    { value: '4111111111111111' },
      cardExpMonth:  { value: '12' },
      cardExpYear:   { value: '2027' },
      cardCvc:       { value: '123' },
      cardHolderName:{ value: 'Jane Doe' }
    }
  },
  address: { billingAddress: {} },
  authType: types.AuthenticationType.NO_THREE_DS,
  testMode: true
});

// ⚠️ status is a NUMBER — never compare to a string
if (authResult.status === 6) {
  console.log('Authorized. connectorTransactionId:', authResult.connectorTransactionId);
}

// ── CAPTURE ─────────────────────────────────────────────────────────────────
const captureResult = await client.capture({
  merchantCaptureId: 'cap_001',
  connectorTransactionId: authResult.connectorTransactionId ?? '',
  amountToCapture: { minorAmount: 1000, currency: types.Currency.USD },
  testMode: true
});
// captureResult.status === 8 → CHARGED

// ── REFUND ──────────────────────────────────────────────────────────────────
const refundResult = await client.refund({
  merchantRefundId: 'ref_001',
  connectorTransactionId: authResult.connectorTransactionId ?? '',
  refundAmount: { minorAmount: 500, currency: types.Currency.USD },
  reason: 'RETURN',        // Stripe: any free-text string is accepted
  testMode: true
});
// refundResult.status === 4 → REFUND_SUCCESS  (RefundStatus enum, NOT PaymentStatus)

// ── VOID ────────────────────────────────────────────────────────────────────
const voidResult = await client.void({
  merchantVoidId: 'void_001',
  connectorTransactionId: authResult.connectorTransactionId ?? '',
  cancellationReason: 'Customer cancelled',
  testMode: true
});
// voidResult.status === 11 → VOIDED

// ── ONE-STEP (auto-capture) ──────────────────────────────────────────────────
const autoResult = await client.authorize({
  merchantTransactionId: 'txn_002',
  amount: { minorAmount: 2000, currency: types.Currency.USD },
  captureMethod: types.CaptureMethod.AUTOMATIC,    // ← key difference
  paymentMethod: {
    card: {
      cardNumber:   { value: '4111111111111111' },
      cardExpMonth: { value: '12' },
      cardExpYear:  { value: '2027' },
      cardCvc:      { value: '123' }
    }
  },
  testMode: true
});
// autoResult.status === 8 → CHARGED immediately
```

#### Python — Stripe Authorize

```python
from payments import PaymentClient, SecretString
from payments.generated import sdk_config_pb2, payment_pb2
import os

cfg = sdk_config_pb2.ConnectorConfig()
cfg.connector_config.CopyFrom(payment_pb2.ConnectorSpecificConfig(
    stripe=payment_pb2.StripeConfig(
        api_key=SecretString(value=os.environ["STRIPE_API_KEY"])
    )
))
client = PaymentClient(cfg)

request = payment_pb2.PaymentAuthorizeRequest(
    merchant_transaction_id="txn_001",
    amount=payment_pb2.MinorUnit(minor_amount=1000, currency=payment_pb2.Currency.USD),
    capture_method=payment_pb2.CaptureMethod.AUTOMATIC,
    payment_method=payment_pb2.PaymentMethodData(
        card=payment_pb2.Card(
            card_number=SecretString(value="4111111111111111"),
            card_exp_month=SecretString(value="12"),
            card_exp_year=SecretString(value="2027"),
            card_cvc=SecretString(value="123"),
        )
    ),
    test_mode=True,
)

result = client.authorize(request)
# result.status == 8 → CHARGED
```

---

### 2.2 — Adyen

> ⚠️ **Adyen requires `browserInfo` for ALL card payments. Omitting it throws `IntegrationError: MISSING_REQUIRED_FIELD: browser_info`.**

#### Node.js — Adyen Authorize (with required browserInfo)

```typescript
import { PaymentClient, types } from 'hyperswitch-prism';

// ── CONFIG — note: requires merchantAccount in addition to apiKey ────────────
const client = new PaymentClient({
  connectorConfig: {
    adyen: {
      apiKey:          { value: process.env.ADYEN_API_KEY! },
      merchantAccount: { value: process.env.ADYEN_MERCHANT_ACCOUNT! }
    }
  }
});

// ── AUTHORIZE ────────────────────────────────────────────────────────────────
const authResult = await client.authorize({
  merchantTransactionId: 'txn_adyen_001',
  amount: { minorAmount: 1000, currency: types.Currency.USD },
  captureMethod: types.CaptureMethod.MANUAL,
  paymentMethod: {
    card: {
      cardNumber:    { value: '4111111111111111' },
      cardExpMonth:  { value: '03' },
      cardExpYear:   { value: '2030' },
      cardCvc:       { value: '737' },         // ← Adyen sandbox CVC is 737
      cardHolderName:{ value: 'Jane Doe' }
    }
  },
  // ⚠️ REQUIRED for Adyen — do not omit
  browserInfo: {
    colorDepth:           24,
    screenHeight:         900,
    screenWidth:          1440,
    javaEnabled:          false,
    javaScriptEnabled:    true,
    language:             'en-US',
    timeZoneOffsetMinutes:0,
    acceptHeader:         'text/html,*/*;q=0.8',
    userAgent:            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)'
  },
  address: { billingAddress: {} },
  authType: types.AuthenticationType.NO_THREE_DS,
  testMode: true
});

// ── REFUND — reason must be an accepted enum value, NOT free-text ─────────────
const refundResult = await client.refund({
  merchantRefundId: 'ref_adyen_001',
  connectorTransactionId: authResult.connectorTransactionId ?? '',
  refundAmount: { minorAmount: 500, currency: types.Currency.USD },
  reason: 'RETURN',   // ✅ Valid: OTHER | RETURN | DUPLICATE | FRAUD | CUSTOMER_REQUEST
  // reason: 'my custom text'  ← ❌ Will throw ConnectorError for Adyen
  testMode: true
});
```

---

### 2.3 — PayPal

```typescript
import { PaymentClient, types } from 'hyperswitch-prism';

// ── CONFIG — SignatureKey (clientId + clientSecret, NOT apiKey) ───────────────
const client = new PaymentClient({
  connectorConfig: {
    paypal: {
      clientId:     { value: process.env.PAYPAL_CLIENT_ID! },
      clientSecret: { value: process.env.PAYPAL_CLIENT_SECRET! }
    }
  }
});

const result = await client.authorize({
  merchantTransactionId: 'txn_paypal_001',
  amount: { minorAmount: 1000, currency: types.Currency.USD },
  captureMethod: types.CaptureMethod.AUTOMATIC,
  paymentMethod: {
    card: {
      cardNumber:   { value: '4111111111111111' },
      cardExpMonth: { value: '12' },
      cardExpYear:  { value: '2027' },
      cardCvc:      { value: '123' }
    }
  },
  testMode: true
});
```

---

### 2.4 — Error Handling Template (Use in All Integrations)

```typescript
import { IntegrationError, ConnectorError, NetworkError, types } from 'hyperswitch-prism';

async function safeAuthorize(client: PaymentClient, request: types.PaymentAuthorizeRequest) {
  try {
    const response = await client.authorize(request);

    // Soft declines are status values, NOT exceptions
    if (response.status === 21) {   // 21 = FAILURE
      console.error('Soft decline:', response.error?.message);
      return null;
    }

    if (response.status === 7) {    // 7 = AUTHORIZATION_FAILED
      console.error('Auth failed:', response.error?.message);
      return null;
    }

    return response;

  } catch (error) {
    if (error instanceof IntegrationError) {
      // Bad config, missing required field, serialization error
      // → Fix your request structure. Do NOT retry.
      console.error('[IntegrationError]', error.errorCode, error.message);
    } else if (error instanceof ConnectorError) {
      // Response transformation failed
      // → Log and investigate. Do NOT retry automatically.
      console.error('[ConnectorError]', error.errorCode, error.message);
    } else if (error instanceof NetworkError) {
      // Timeout, DNS failure, connection refused
      // → Safe to retry with backoff.
      console.error('[NetworkError]', error.message);
    }
    return null;
  }
}
```

---

## SECTION 3 — Integration Rules (Non-Negotiable)

### Rule 1: Status Codes Are Numbers, Never Strings

```typescript
// ❌ ALWAYS FALSE — response.status is a number at runtime
if (response.status === 'CHARGED') { }
if (response.status === 'AUTHORIZED') { }

// ✅ CORRECT
if (response.status === 8) { }                         // literal
if (response.status === types.PaymentStatus.CHARGED) { } // enum (equals 8)
```

### Rule 2: PaymentStatus vs RefundStatus Are Different Enums (Overlapping Values!)

```
Value 4 means TWO DIFFERENT things depending on context:
  PaymentStatus 4 = AUTHENTICATION_PENDING   ← for authorize/capture/void responses
  RefundStatus  4 = REFUND_SUCCESS           ← for refund responses ONLY
```

```typescript
// ✅ Always use the correct enum for the correct operation
const auth   = await client.authorize(...);
const refund = await client.refund(...);

if (auth.status   === types.PaymentStatus.AUTHORIZED)     { } // === 6
if (refund.status === types.RefundStatus.REFUND_SUCCESS)  { } // === 4
```

### Rule 3: Handle Optional Fields with Fallbacks

```typescript
// connectorTransactionId can be undefined on failure — always guard it
const txId = authResult.connectorTransactionId ?? '';

// error object may be undefined on success — guard before accessing
const errMsg = response.error?.message ?? 'Unknown error';
```

### Rule 4: Connector Config Format Varies by Connector

```typescript
// Stripe  → HeaderKey  → apiKey only
{ stripe: { apiKey: { value: '...' } } }

// Adyen   → HeaderKey + MerchantAccount → apiKey + merchantAccount
{ adyen: { apiKey: { value: '...' }, merchantAccount: { value: '...' } } }

// PayPal  → SignatureKey → clientId + clientSecret (NOT apiKey)
{ paypal: { clientId: { value: '...' }, clientSecret: { value: '...' } } }
```

### Rule 5: Enum Values Quick Reference

**PaymentStatus (for authorize / capture / void)**

| Number | Name | Meaning |
|--------|------|---------|
| 0 | UNSPECIFIED | Unknown |
| 1 | STARTED | Payment initiated |
| 4 | AUTHENTICATION_PENDING | Awaiting 3DS |
| 5 | AUTHENTICATION_SUCCESSFUL | 3DS passed |
| 6 | AUTHORIZED | Held, not captured |
| 7 | AUTHORIZATION_FAILED | Declined |
| 8 | CHARGED | Captured / auto-capture success |
| 11 | VOIDED | Authorization cancelled |
| 20 | PENDING | Processing (async connectors) |
| 21 | FAILURE | Soft decline — check error field |

**RefundStatus (for refund ONLY)**

| Number | Name | Meaning |
|--------|------|---------|
| 1 | REFUND_FAILURE | Failed |
| 2 | REFUND_MANUAL_REVIEW | Pending review |
| 3 | REFUND_PENDING | Processing (normal for Adyen) |
| 4 | REFUND_SUCCESS | Completed |

---

## SECTION 4 — Installation & Configuration

### Node.js (v18+)

```bash
npm install hyperswitch-prism
```

### Python (3.9+)

```bash
pip install hyperswitch-prism
```

### Java/Kotlin (JDK 17+)

```xml
<dependency>
  <groupId>com.hyperswitch</groupId>
  <artifactId>hyperswitch-prism</artifactId>
  <version>0.0.1</version>
</dependency>
```

### PHP (8.0+)

```bash
composer require hyperswitch-prism
```

---

## SECTION 5 — Advanced Configuration

### Timeouts

```typescript
const client = new PaymentClient(config, {
  http: {
    totalTimeoutMs:    30000,
    connectTimeoutMs:  10000,
    responseTimeoutMs: 25000
  }
});
```

### Proxy

```typescript
const client = new PaymentClient(config, {
  http: {
    proxy: {
      httpsUrl:   'https://proxy.company.com:8443',
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

## SECTION 6 — Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Your App (Node.js / Python / Java / PHP)                   │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│  Service Clients (PaymentClient, CustomerClient, etc.)      │
│  - PaymentClient.authorize(), capture(), refund(), void()   │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│  ConnectorClient (HTTP + connection pooling)                │
│  - undici (Node), httpx (Python), OkHttp (Java)            │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│  FFI Bindings (koffi/UniFFI → Rust core)                   │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│  Rust Core → Connector Adapters (Stripe, Adyen, +68 more)  │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
         Payment Processor APIs (Stripe, Adyen, etc.)
```

---

## SECTION 7 — All Service Clients

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

## SECTION 8 — Platform Support

| Platform | Architectures |
|----------|---------------|
| macOS | x86_64, arm64 |
| Linux | x86_64, aarch64 |
| Windows | x86_64 |

---

## SECTION 9 — Pre-Deployment Checklist

- [ ] Ran Field Probe (`npx hyperswitch-prism probe`) for every connector × flow × payment-method in use
- [ ] Used inline connector examples (Section 2) as source of truth — not TypeScript types alone
- [ ] All `response.status` comparisons use numeric values, not strings
- [ ] Using `types.PaymentStatus` for auth/capture/void and `types.RefundStatus` for refund (not interchanged)
- [ ] `connectorTransactionId` accessed with `?? ''` fallback
- [ ] `response.error?.message` accessed with optional chaining
- [ ] `IntegrationError` → not retried (fix the request)
- [ ] `NetworkError` → retried with backoff
- [ ] Tested with sandbox credentials before production

---

## Useful Links

- [Full API Reference](./api-reference/)
- [Architecture Documentation](./architecture/)
- [Connector Examples (full repo)](https://github.com/juspay/hyperswitch-prism/tree/main/examples)
- [Field Probe Data](https://github.com/juspay/hyperswitch-prism/tree/main/data/field_probe)
- [Report Issues](https://github.com/juspay/hyperswitch-prism/issues)
