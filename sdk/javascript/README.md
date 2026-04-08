# hs-paylib

**Universal Connector Service — Node.js SDK**

A high-performance, type-safe Node.js SDK for payment processing through the Universal Connector Service. Connect to 70+ payment processors (Stripe, Adyen, PayPal, Cybersource, and more) through a single, unified API.

[![npm version](https://badge.fury.io/js/hs-paylib.svg)](https://www.npmjs.com/package/hs-paylib)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

---

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Connector Authentication](#connector-authentication)
- [Connector-Specific Requirements](#connector-specific-requirements)
- [All Service Clients](#all-service-clients)
- [Payment Flows](#payment-flows)
- [Status Codes Reference](#status-codes-reference)
- [Error Handling](#error-handling)
- [Advanced Configuration](#advanced-configuration)
- [Building from Source](#building-from-source)

---

## 🤖 AI Assistant Context

This SDK is part of **Hyperswitch Prism** — a unified connector library for payment processors.

### What This SDK Does

1. **Request Transformation**: Converts unified payment requests to connector-specific formats (Stripe, Adyen, PayPal, etc.)
2. **Response Normalization**: Transforms connector responses back to a unified schema
3. **Error Handling**: Provides consistent error types (`IntegrationError`, `ConnectorError`, `NetworkError`) regardless of connector

### Architecture

```
Your Node.js App
       │
       ▼
┌──────────────────────────────────────────────────────────────┐
│  Service Clients (PaymentClient, CustomerClient, etc.)       │
└───────────────────────────┬──────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────┐
│  ConnectorClient (undici connection pool + HTTP execution)   │
└───────────────────────────┬──────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────┐
│  koffi FFI Bindings (connector-service-ffi.node)             │
└───────────────────────────┬──────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────┐
│  Rust Core (connector transformation logic)                  │
└───────────────────────────┬──────────────────────────────────┘
                            │
                            ▼
              Payment Processor APIs (Stripe, Adyen, etc.)
```

### Key Files

| File | Purpose |
|------|---------|
| `src/index.ts` | Public API exports (clients, types, errors) |
| `src/connector-client.ts` | HTTP execution layer with undici |
| `src/ffi/connector-service-ffi.ts` | koffi FFI bindings |
| `src/proto/payment_pb.ts` | Protobuf message definitions |

### Package & Import

- **Package Name**: `hyperswitch-prism`
- **Installation**: `npm install hyperswitch-prism`
- **Import**: `import { PaymentClient, types } from 'hyperswitch-prism'`

---

## Installation

```bash
npm install hs-paylib
```

> **Important:** The package name on npm is `hs-paylib`. All imports must use `hs-paylib`, not `hyperswitch-prism`.

**Requirements:**
- Node.js 18+ (LTS recommended)
- macOS (x64, arm64), Linux (x64, arm64), or Windows (x64)

---

## Quick Start

```typescript
import { PaymentClient, types } from 'hs-paylib';

const config: types.ConnectorConfig = {
  connectorConfig: {
    stripe: {
      apiKey: { value: process.env.STRIPE_API_KEY! }
    }
  }
};

const client = new PaymentClient(config);

const response = await client.authorize({
  merchantTransactionId: 'txn_001',
  amount: { minorAmount: 1000, currency: types.Currency.USD },
  captureMethod: types.CaptureMethod.AUTOMATIC,
  paymentMethod: {
    card: {
      cardNumber: { value: '4111111111111111' },
      cardExpMonth: { value: '12' },
      cardExpYear: { value: '2027' },
      cardCvc: { value: '123' },
      cardHolderName: { value: 'John Doe' },
    }
  },
  address: { billingAddress: {} },
  authType: types.AuthenticationType.NO_THREE_DS,
  returnUrl: 'https://example.com/return',
  orderDetails: [],
  testMode: true,
});

console.log('Status:', response.status);          // e.g. 8 = CHARGED
console.log('Transaction ID:', response.connectorTransactionId);
```

---

## Connector Authentication

Each connector uses a different authentication scheme. Below are the config shapes for common connectors. All configs are set inside `connectorConfig` as a single key matching the connector name.

### Single API Key

```typescript
// Stripe
{ connectorConfig: { stripe: { apiKey: { value: '...' } } } }

// Xendit
{ connectorConfig: { xendit: { apiKey: { value: '...' } } } }

// Shift4
{ connectorConfig: { shift4: { apiKey: { value: '...' } } } }

// Helcim
{ connectorConfig: { helcim: { apiKey: { value: '...' } } } }

// Stax
{ connectorConfig: { stax: { apiKey: { value: '...' } } } }

// NMI
{ connectorConfig: { nmi: { apiKey: { value: '...' }, publicKey: { value: '...' } } } }

// Multisafepay
{ connectorConfig: { multisafepay: { apiKey: { value: '...' } } } }

// Revolut
{ connectorConfig: { revolut: { secretApiKey: { value: '...' }, signingSecret: { value: '...' } } } }
```

### API Key + Merchant Account

```typescript
// Adyen
{
  connectorConfig: {
    adyen: {
      apiKey: { value: '...' },
      merchantAccount: { value: '...' },
      // optional: reviewKey, endpointPrefix for regional endpoints
    }
  }
}

// Cybersource
{
  connectorConfig: {
    cybersource: {
      apiKey: { value: '...' },
      merchantAccount: { value: '...' },
      apiSecret: { value: '...' }
    }
  }
}

// Bank of America
{
  connectorConfig: {
    bankofamerica: {
      apiKey: { value: '...' },
      merchantAccount: { value: '...' },
      apiSecret: { value: '...' }
    }
  }
}

// Wells Fargo
{
  connectorConfig: {
    wellsfargo: {
      apiKey: { value: '...' },
      merchantAccount: { value: '...' },
      apiSecret: { value: '...' }
    }
  }
}

// Fiserv
{
  connectorConfig: {
    fiserv: {
      apiKey: { value: '...' },
      merchantAccount: { value: '...' },
      apiSecret: { value: '...' },
      terminalId: { value: '...' }
    }
  }
}
```

### Client ID + Secret (OAuth-style)

```typescript
// PayPal
{
  connectorConfig: {
    paypal: {
      clientId: { value: '...' },
      clientSecret: { value: '...' },
      payerId: { value: '...' }  // optional
    }
  }
}

// Airwallex
{
  connectorConfig: {
    airwallex: {
      apiKey: { value: '...' },
      clientId: { value: '...' }
    }
  }
}

// Volt
{
  connectorConfig: {
    volt: {
      username: { value: '...' },
      password: { value: '...' },
      clientId: { value: '...' },
      clientSecret: { value: '...' }
    }
  }
}

// Globalpay
{
  connectorConfig: {
    globalpay: {
      appId: { value: '...' },
      appKey: { value: '...' }
    }
  }
}
```

### Username + Password

```typescript
// Bluesnap
{ connectorConfig: { bluesnap: { username: { value: '...' }, password: { value: '...' } } } }

// Datatrans
{
  connectorConfig: {
    datatrans: {
      merchantId: { value: '...' },
      password: { value: '...' }
    }
  }
}

// WorldPay
{
  connectorConfig: {
    worldpay: {
      username: { value: '...' },
      password: { value: '...' },
      entityId: { value: '...' },
      merchantName: { value: '...' }
    }
  }
}

// Authorize.net
{
  connectorConfig: {
    authorizedotnet: {
      name: { value: '...' },
      transactionKey: { value: '...' }
    }
  }
}
```

### Other Authentication Patterns

```typescript
// Nuvei (Merchant ID + Site ID + Secret)
{
  connectorConfig: {
    nuvei: {
      merchantId: { value: '...' },
      merchantSiteId: { value: '...' },
      merchantSecret: { value: '...' }
    }
  }
}

// Rapyd (Access Key + Secret Key)
{
  connectorConfig: {
    rapyd: {
      accessKey: { value: '...' },
      secretKey: { value: '...' }
    }
  }
}

// Novalnet (Product Activation Key + Payment Access Key + Tariff ID)
{
  connectorConfig: {
    novalnet: {
      productActivationKey: { value: '...' },
      paymentAccessKey: { value: '...' },
      tariffId: { value: '...' }
    }
  }
}

// Braintree (Public Key + Private Key + Merchant Account ID)
{
  connectorConfig: {
    braintree: {
      publicKey: { value: '...' },
      privateKey: { value: '...' },
      merchantAccountId: { value: '...' },
      merchantConfigCurrency: { value: 'USD' }
    }
  }
}

// Cashfree (App ID + Secret Key)
{
  connectorConfig: {
    cashfree: {
      appId: { value: '...' },
      secretKey: { value: '...' }
    }
  }
}
```

---

## Connector-Specific Requirements

This section documents known per-connector requirements and sandbox quirks that are **not enforced by the SDK type system** but will cause failures at runtime if missing.

### `browserInfo` — When It Is Required

The `browserInfo` field on authorize, capture, refund, and void requests is optional in the type definition, but **required at runtime** for certain connectors and flows:

| Connector | When required |
|-----------|--------------|
| Adyen | Always required for card payments (including NO_THREE_DS) |
| Cybersource | Required for 3DS flows |
| NMI | Required for 3DS flows |
| Braintree | Required for device data / fraud checks |
| Any connector | Required when `authType: THREE_DS` |

**Minimal `browserInfo` for Adyen (satisfies sandbox):**

```typescript
browserInfo: {
  colorDepth: 24,
  screenHeight: 900,
  screenWidth: 1440,
  javaEnabled: false,
  javaScriptEnabled: true,
  language: 'en-US',
  timeZoneOffsetMinutes: 0,
  acceptHeader: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
  userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
}
```

> **Rule of thumb:** Always include `browserInfo` when targeting Adyen, Cybersource, or any 3DS flow. For other connectors, it is safe to include it — it will be ignored if not needed.

---

### Sandbox Test Cards

Different connectors require different test card numbers and CVCs in sandbox mode:

| Connector | Card Number | CVC | Expiry | Notes |
|-----------|-------------|-----|--------|-------|
| Stripe | `4111111111111111` | `123` | Any future | Standard Visa test card |
| Stripe | `4000000000009995` | `123` | Any future | Triggers decline |
| Adyen | `4111111111111111` | `737` | `03/2030` | CVC `737` is required for Adyen sandbox |
| Adyen | `5500000000000004` | `737` | `03/2030` | Mastercard test card |
| Cybersource | `4111111111111111` | `123` | Any future | Standard |
| Braintree | `4111111111111111` | `123` | Any future | Standard |
| Authorize.net | `4111111111111111` | `900` | Any future | |
| Bluesnap | `4111111111111111` | `111` | `12/2026` | |
| NMI | `4111111111111111` | `999` | Any future | |
| WorldPay | `4444333322221111` | `123` | Any future | |
| Checkout.com | `4242424242424242` | `100` | Any future | |
| Globalpay | `4263970000005262` | `123` | `12/2025` | |

> **Note:** Always check the connector's own sandbox documentation for the definitive test card list. The table above reflects known-working values at time of writing.

---

### Refund Reason — Connector Constraints

The `reason` field in refund requests is typed as `string`, but some connectors only accept specific enum values:

| Connector | Accepted values |
|-----------|----------------|
| Adyen | `OTHER`, `RETURN`, `DUPLICATE`, `FRAUD`, `CUSTOMER REQUEST` |
| Stripe | Any free-text string |
| Braintree | Any free-text string |
| Most others | Free-text string (connector may truncate or ignore) |

**Cross-connector safe pattern** — use standard enum values to avoid failures across all connectors:

```typescript
// Safe across all connectors
const REFUND_REASONS = ['OTHER', 'RETURN', 'DUPLICATE', 'FRAUD', 'CUSTOMER REQUEST'] as const;

await client.refund({
  merchantRefundId: 'ref_001',
  connectorTransactionId: response.connectorTransactionId!,
  refundAmount: { minorAmount: 1000, currency: types.Currency.USD },
  paymentAmount: 1000,
  reason: 'RETURN',  // Use enum values, not free text
  testMode: true,
});
```

---

### Capture Status by Connector

After a **manual capture**, the returned `status` varies by connector:

| Status | Numeric | Connectors |
|--------|---------|------------|
| `CHARGED` | 8 | Stripe, Cybersource, most |
| `PENDING` | 20 | Adyen (capture is asynchronous) |
| `CAPTURE_INITIATED` | 13 | Some async connectors |

Always accept both `CHARGED` and `PENDING` as success after capture for cross-connector compatibility.

---

### 3DS (Three Domain Secure) Flows

For 3DS authentication, set `authType: THREE_DS` and always include `browserInfo`. The authorize response will contain `redirectionData` instead of a final status:

```typescript
const response = await client.authorize({
  // ...
  authType: types.AuthenticationType.THREE_DS,
  browserInfo: { /* required — see above */ },
  returnUrl: 'https://example.com/3ds-return',
  completeAuthorizeUrl: 'https://example.com/3ds-complete',
});

if (response.redirectionData) {
  // Redirect the user to complete 3DS authentication
  // response.status will be AUTHENTICATION_PENDING (4)
}
```

---

## All Service Clients

```typescript
import {
  PaymentClient,
  CustomerClient,
  PaymentMethodClient,
  MerchantAuthenticationClient,
  PaymentMethodAuthenticationClient,
  RecurringPaymentClient,
  RefundClient,
  DisputeClient,
  PayoutClient,
  EventClient,
  // gRPC variants:
  GrpcPaymentClient,
  GrpcCustomerClient,
  // ...
  types,
  IntegrationError,
  ConnectorError,
  NetworkError,
} from 'hs-paylib';
```

| Client | Methods |
|--------|---------|
| `PaymentClient` | `authorize()`, `capture()`, `refund()`, `void()`, `createOrder()`, `get()`, `sync()`, `incrementalAuthorization()` |
| `RefundClient` | `get()`, `createRefund()`, `updateRefund()` |
| `CustomerClient` | `create()` |
| `PaymentMethodClient` | `tokenize()` |
| `MerchantAuthenticationClient` | `createServerAuthenticationToken()`, `createClientAuthenticationToken()`, `createServerSessionAuthenticationToken()` |
| `PaymentMethodAuthenticationClient` | `preAuthenticate()`, `authenticate()`, `postAuthenticate()` |
| `RecurringPaymentClient` | `setup()`, `charge()`, `revoke()` |
| `DisputeClient` | `accept()`, `defend()`, `submitEvidence()`, `get()` |
| `PayoutClient` | Payout operations |
| `EventClient` | `handleEvent()` (webhook processing) |

---

## Payment Flows

### Authorize with Auto Capture

```typescript
const client = new PaymentClient(config);

const response = await client.authorize({
  merchantTransactionId: 'txn_001',
  amount: { minorAmount: 1000, currency: types.Currency.USD },
  captureMethod: types.CaptureMethod.AUTOMATIC,
  paymentMethod: {
    card: {
      cardNumber: { value: '4111111111111111' },
      cardExpMonth: { value: '12' },
      cardExpYear: { value: '2027' },
      cardCvc: { value: '123' },
      cardHolderName: { value: 'John Doe' },
    }
  },
  address: { billingAddress: {} },
  authType: types.AuthenticationType.NO_THREE_DS,
  returnUrl: 'https://example.com/return',
  orderDetails: [],
  testMode: true,
});
// response.status === 8 (CHARGED) on success
```

### Authorize + Manual Capture

```typescript
// Step 1: Authorize only
const authResponse = await client.authorize({
  // ...
  captureMethod: types.CaptureMethod.MANUAL,
});
// authResponse.status === 6 (AUTHORIZED)

// Step 2: Capture later
const captureResponse = await client.capture({
  merchantCaptureId: 'cap_001',
  connectorTransactionId: authResponse.connectorTransactionId!,
  amountToCapture: { minorAmount: 1000, currency: types.Currency.USD },
  testMode: true,
});
// captureResponse.status === 8 (CHARGED) or 20 (PENDING) — both are success
```

### Refund

```typescript
const refundResponse = await client.refund({
  merchantRefundId: 'ref_001',
  connectorTransactionId: authResponse.connectorTransactionId!,
  refundAmount: { minorAmount: 500, currency: types.Currency.USD },
  paymentAmount: 1000,
  reason: 'RETURN',  // Use enum values for cross-connector safety
  testMode: true,
});
// refundResponse.status === 4 (REFUND_SUCCESS) or 3 (REFUND_PENDING) — both are success
```

### Void (Cancel Authorization)

```typescript
const voidResponse = await client.void({
  merchantVoidId: 'void_001',
  connectorTransactionId: authResponse.connectorTransactionId!,
  cancellationReason: 'Customer cancelled',
  testMode: true,
});
// voidResponse.status === 11 (VOIDED)
```

### Currency-Based Connector Routing

```typescript
import { PaymentClient, types } from 'hs-paylib';

const stripeClient = new PaymentClient({
  connectorConfig: { stripe: { apiKey: { value: process.env.STRIPE_API_KEY! } } }
});

const adyenClient = new PaymentClient({
  connectorConfig: {
    adyen: {
      apiKey: { value: process.env.ADYEN_API_KEY! },
      merchantAccount: { value: process.env.ADYEN_MERCHANT_ACCOUNT! },
    }
  }
});

function getClient(currency: string): PaymentClient {
  switch (currency) {
    case 'EUR': return adyenClient;
    case 'USD':
    default:    return stripeClient;
  }
}

function getCurrencyEnum(currency: string): types.Currency {
  const value = (types.Currency as Record<string, number>)[currency];
  if (value === undefined) throw new Error(`Unsupported currency: ${currency}`);
  return value;
}

// Route USD to Stripe, EUR to Adyen
async function pay(currency: string, amountMinor: number) {
  const client = getClient(currency);
  return client.authorize({
    merchantTransactionId: `txn_${Date.now()}`,
    amount: { minorAmount: amountMinor, currency: getCurrencyEnum(currency) },
    captureMethod: types.CaptureMethod.AUTOMATIC,
    paymentMethod: {
      card: {
        cardNumber: { value: '4111111111111111' },
        cardExpMonth: { value: '12' },
        cardExpYear: { value: '2027' },
        // Adyen sandbox requires CVC 737; for multi-connector use connector-specific cards
        cardCvc: { value: currency === 'EUR' ? '737' : '123' },
        cardHolderName: { value: 'Jane Doe' },
      }
    },
    address: { billingAddress: {} },
    authType: types.AuthenticationType.NO_THREE_DS,
    returnUrl: 'https://example.com/return',
    orderDetails: [],
    // Adyen always requires browserInfo
    browserInfo: currency === 'EUR' ? {
      colorDepth: 24, screenHeight: 900, screenWidth: 1440,
      javaEnabled: false, javaScriptEnabled: true,
      language: 'en-US', timeZoneOffsetMinutes: 0,
      acceptHeader: 'text/html,*/*;q=0.8',
      userAgent: 'Mozilla/5.0',
    } : undefined,
    testMode: true,
  });
}
```

### PayPal (Access Token Flow)

```typescript
import { PaymentClient, MerchantAuthenticationClient, types } from 'hs-paylib';

const paypalConfig: types.ConnectorConfig = {
  connectorConfig: {
    paypal: {
      clientId: { value: process.env.PAYPAL_CLIENT_ID! },
      clientSecret: { value: process.env.PAYPAL_CLIENT_SECRET! },
    }
  }
};

// Step 1: Get access token
const authClient = new MerchantAuthenticationClient(paypalConfig);
const tokenResponse = await authClient.createServerAuthenticationToken({
  merchantAccessTokenId: 'token_001',
  connector: types.Connector.PAYPAL,
  testMode: true,
});

// Step 2: Authorize with access token injected in state
const paymentClient = new PaymentClient(paypalConfig);
const response = await paymentClient.authorize({
  merchantTransactionId: 'txn_001',
  amount: { minorAmount: 1000, currency: types.Currency.USD },
  captureMethod: types.CaptureMethod.AUTOMATIC,
  paymentMethod: {
    card: {
      cardNumber: { value: '4111111111111111' },
      cardExpMonth: { value: '12' },
      cardExpYear: { value: '2027' },
      cardCvc: { value: '123' },
    }
  },
  address: { billingAddress: {} },
  authType: types.AuthenticationType.NO_THREE_DS,
  returnUrl: 'https://example.com/return',
  orderDetails: [],
  state: {
    accessToken: {
      token: { value: tokenResponse.accessToken.value },
      tokenType: 'Bearer',
      expiresInSeconds: tokenResponse.expiresInSeconds,
    },
  },
  testMode: true,
});
```

---

## Status Codes Reference

### PaymentStatus

The `response.status` field is a numeric enum. **Important: a `FAILURE` status is returned in the response body — it does NOT throw an exception.** Always check `response.status` explicitly.

| Name | Value | Meaning |
|------|-------|---------|
| `PAYMENT_STATUS_UNSPECIFIED` | 0 | Unknown |
| `STARTED` | 1 | Payment initiated |
| `AUTHENTICATION_PENDING` | 4 | Awaiting 3DS redirect |
| `AUTHENTICATION_SUCCESSFUL` | 5 | 3DS passed |
| `AUTHENTICATION_FAILED` | 2 | 3DS failed |
| `AUTHORIZED` | 6 | Auth succeeded, not yet captured |
| `AUTHORIZATION_FAILED` | 7 | Auth declined |
| `CHARGED` | 8 | Captured / auto-captured successfully |
| `PARTIAL_CHARGED` | 17 | Partially captured |
| `CAPTURE_INITIATED` | 13 | Async capture in progress |
| `CAPTURE_FAILED` | 14 | Capture failed |
| `VOIDED` | 11 | Authorization voided/cancelled |
| `VOID_INITIATED` | 12 | Async void in progress |
| `VOID_FAILED` | 15 | Void failed |
| `PENDING` | 20 | Processing / async (common for Adyen capture) |
| `FAILURE` | 21 | Soft decline — check `response.error` |
| `ROUTER_DECLINED` | 3 | Declined by routing layer |
| `EXPIRED` | 26 | Payment expired |
| `PARTIALLY_AUTHORIZED` | 25 | Partial authorization |
| `UNRESOLVED` | 19 | Requires manual review |

**Checking status safely:**

```typescript
import { types } from 'hs-paylib';

const response = await client.authorize(request);

// Soft declines arrive as status, NOT exceptions
if (response.status === types.PaymentStatus.FAILURE) {
  console.error('Declined:', response.error?.message, response.error?.code);
} else if (response.status === types.PaymentStatus.CHARGED ||
           response.status === types.PaymentStatus.AUTHORIZED) {
  console.log('Success:', response.connectorTransactionId);
} else if (response.status === types.PaymentStatus.AUTHENTICATION_PENDING) {
  // Redirect user for 3DS
  console.log('Redirect to:', response.redirectionData);
}
```

### RefundStatus

| Name | Value | Meaning |
|------|-------|---------|
| `REFUND_STATUS_UNSPECIFIED` | 0 | Unknown |
| `REFUND_FAILURE` | 1 | Refund failed |
| `REFUND_MANUAL_REVIEW` | 2 | Pending manual review |
| `REFUND_PENDING` | 3 | Processing (normal for Adyen, async connectors) |
| `REFUND_SUCCESS` | 4 | Completed |
| `REFUND_TRANSACTION_FAILURE` | 5 | Transaction-level failure |

> `REFUND_PENDING` is a normal success state for many connectors (Adyen, Braintree). Treat both `REFUND_PENDING` and `REFUND_SUCCESS` as successful outcomes.

---

## Error Handling

The SDK raises exceptions **only for hard failures** (network errors, invalid configuration, serialization errors). Soft payment declines come back as an in-band `status: FAILURE` in the response body.

```typescript
import { IntegrationError, ConnectorError, NetworkError, types } from 'hs-paylib';

try {
  const response = await client.authorize(request);

  // Always check status — soft declines do NOT throw
  if (response.status === types.PaymentStatus.FAILURE) {
    console.error('Payment declined:', response.error?.message);
    return;
  }

} catch (error) {
  if (error instanceof IntegrationError) {
    // Request-phase error: bad config, missing required field, serialization failure
    // e.g. "MISSING_REQUIRED_FIELD: browser_info" for Adyen without browserInfo
    console.error('Integration error:', error.errorCode, error.message);

  } else if (error instanceof ConnectorError) {
    // Response-phase error: connector returned unexpected format, transform failed
    // e.g. invalid refund reason enum for Adyen
    console.error('Connector error:', error.errorCode, error.message);

  } else if (error instanceof NetworkError) {
    // Network-level: timeout, connection refused, DNS failure
    console.error('Network error:', error.message);
  }
}
```

### Common Error Codes

| Code | Type | Cause | Fix |
|------|------|-------|-----|
| `MISSING_REQUIRED_FIELD: browser_info` | `IntegrationError` | Adyen requires `browserInfo` | Add `browserInfo` to request |
| `INVALID_CONFIGURATION` | `IntegrationError` | Wrong credentials or missing required config field | Check connector config fields |
| `CLIENT_INITIALIZATION` | `IntegrationError` | SDK failed to initialize native library | Check platform compatibility |
| `CONNECT_TIMEOUT` | `NetworkError` | Could not reach connector | Check network / proxy config |
| `RESPONSE_TIMEOUT` | `NetworkError` | Connector took too long | Increase `totalTimeoutMs` |
| `TOTAL_TIMEOUT` | `NetworkError` | Request exceeded total timeout | Increase `totalTimeoutMs` |

---

## Advanced Configuration

### Timeouts

```typescript
const client = new PaymentClient(config, {
  http: {
    totalTimeoutMs: 30000,      // Total request timeout
    connectTimeoutMs: 10000,    // TCP connect timeout
    responseTimeoutMs: 25000,   // Time waiting for response headers
    keepAliveTimeoutMs: 60000,  // Keep-alive connection lifetime
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

### Per-Request Overrides

```typescript
const response = await client.authorize(request, {
  http: { totalTimeoutMs: 60000 }  // Override for this request only
});
```

### Connection Pooling

Create the client once and reuse it — each instance manages its own connection pool:

```typescript
// Good: create once, reuse
const client = new PaymentClient(config);
for (const payment of payments) {
  await client.authorize(payment);
}

// Bad: creating a new client per request destroys connection pool benefits
```

### CA Certificate Pinning

```typescript
const client = new PaymentClient(config, {
  http: {
    caCert: fs.readFileSync('ca.pem', 'utf8')  // PEM or DER format
  }
});
```

---

## Building from Source

```bash
# Clone the repository
git clone https://github.com/juspay/hyperswitch-prism.git
cd hyperswitch-prism/sdk/javascript

# Build native library, generate bindings, and pack
make pack

# Run tests
make test-pack

# With live API credentials
STRIPE_API_KEY=sk_test_xxx make test-pack
```
