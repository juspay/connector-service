# Node.js SDK Reference

---
description: Complete reference for integrating payments using the hs-playlib Node.js SDK with the Connector Service.
last_updated: 2026-03-11
---

## Overview

Use **hs-playlib** (also published as `hyperswitch-payments`) to integrate payments into your Node.js applications. This SDK connects your application to the Universal Connector Service (UCS) and enables payment processing across 50+ connectors through a unified API.

## Installation

Install the SDK with npm:

```bash
npm install hs-playlib
```

### Prerequisites

- **Node.js** 18+ (LTS recommended)
- **Rust toolchain** (for building native bindings)
- **npm** 9+ or **yarn** 1.22+

### Platform Support

| Platform | Architecture | Status |
|----------|--------------|--------|
| macOS | x64, arm64 | ✅ Supported |
| Linux | x64, arm64 | ✅ Supported |
| Windows | x64 | ✅ Supported |

## Quick Start

### 1. Configure Your Connector

Create a configuration object with your connector credentials:

```typescript
import { PaymentClient, types } from 'hs-playlib';

const { ConnectorConfig, RequestConfig, Environment, Connector } = types;

// Set up connector identity and authentication
const config = ConnectorConfig.create({
  connector: Connector.STRIPE,
  auth: {
    stripe: {
      apiKey: { value: 'sk_test_your_stripe_key' }
    }
  },
  environment: Environment.SANDBOX,
});

// Optional: Set request defaults (timeouts, proxy, etc.)
const defaults = RequestConfig.create({
  http: {
    totalTimeoutMs: 30000,
    connectTimeoutMs: 10000,
  }
});
```

### 2. Authorize a Payment

Create a client and authorize a payment:

```typescript
const client = new PaymentClient(config, defaults);

const { PaymentServiceAuthorizeRequest, Currency, CaptureMethod } = types;

const request = PaymentServiceAuthorizeRequest.create({
  merchantTransactionId: 'txn_order_001',
  amount: {
    minorAmount: 1000,  // $10.00
    currency: Currency.USD,
  },
  captureMethod: CaptureMethod.AUTOMATIC,
  paymentMethod: {
    card: {
      cardNumber: { value: '4111111111111111' },
      cardExpMonth: { value: '12' },
      cardExpYear: { value: '2027' },
      cardCvc: { value: '123' },
      cardHolderName: { value: 'John Doe' },
    }
  },
  customer: {
    email: { value: 'customer@example.com' },
    name: 'John Doe',
  },
  testMode: true,
});

const response = await client.authorize(request);
console.log('Payment status:', response.status);
console.log('Transaction ID:', response.connectorTransactionId);
```

## Service Clients

The SDK exports specialized clients for each service domain:

### PaymentClient

Use `PaymentClient` to execute core payment operations:

```typescript
import { PaymentClient } from 'hs-playlib';

const client = new PaymentClient(config, defaults);

// Execute payment operations
await client.authorize(request);           // Reserve funds
await client.capture(request);             // Finalize payment
await client.void(request);                // Cancel authorization
await client.refund(request);              // Return funds
await client.reverse(request);             // Reverse captured payment
await client.get(request);                 // Query payment status
await client.createOrder(request);         // Initialize order
await client.setupRecurring(request);      // Setup subscription
```

### CustomerClient

Use `CustomerClient` to manage customer records:

```typescript
import { CustomerClient } from 'hs-playlib';

const client = new CustomerClient(config, defaults);

const response = await client.create({
  merchantCustomerId: 'cust_123',
  email: { value: 'customer@example.com' },
  name: 'John Doe',
});
```

### MerchantAuthenticationClient

Use `MerchantAuthenticationClient` to handle connector authentication flows:

```typescript
import { MerchantAuthenticationClient } from 'hs-playlib';

const client = new MerchantAuthenticationClient(config, defaults);

// Create access token for OAuth connectors (e.g., PayPal)
const tokenResponse = await client.createAccessToken({
  merchantAccessTokenId: 'token_001',
  connector: Connector.PAYPAL,
  testMode: true,
});

// Extract token for subsequent requests
const accessToken = tokenResponse.accessToken.value;
```

### PaymentMethodClient

Use `PaymentMethodClient` to tokenize payment methods:

```typescript
import { PaymentMethodClient } from 'hs-playlib';

const client = new PaymentMethodClient(config, defaults);

const response = await client.tokenize({
  merchantPaymentMethodId: 'pm_123',
  paymentMethod: {
    card: {
      cardNumber: { value: '4111111111111111' },
      cardExpMonth: { value: '12' },
      cardExpYear: { value: '2027' },
    }
  }
});
```

### EventClient

Use `EventClient` to process webhooks and async events:

```typescript
import { EventClient } from 'hs-playlib';

const client = new EventClient(config, defaults);

// Process incoming webhook (no HTTP round-trip)
const response = await client.handleEvent({
  merchantEventId: 'evt_123',
  eventData: webhookPayload,
});
```

### RecurringPaymentClient

Use `RecurringPaymentClient` to charge stored payment methods:

```typescript
import { RecurringPaymentClient } from 'hs-playlib';

const client = new RecurringPaymentClient(config, defaults);

const response = await client.charge({
  merchantChargeId: 'charge_001',
  connectorTransactionId: 'original_txn_123',
  amount: {
    minorAmount: 5000,
    currency: Currency.USD,
  },
});
```

## Configuration Reference

### ConnectorConfig

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `connector` | `Connector` | ✅ | Connector enum (STRIPE, PAYPAL, ADYEN, etc.) |
| `auth` | `ConnectorAuth` | ✅ | Authentication credentials |
| `environment` | `Environment` | ✅ | SANDBOX or PRODUCTION |

### Auth Types

#### HeaderKey (Stripe)

```typescript
auth: {
  stripe: {
    apiKey: { value: 'sk_test_xxx' }
  }
}
```

#### BodyKey

```typescript
auth: {
  connectorName: {
    apiKey: { value: 'key_xxx' },
    key1: 'additional_field'
  }
}
```

#### SignatureKey (PayPal)

```typescript
auth: {
  paypal: {
    clientId: { value: 'client_id' },
    clientSecret: { value: 'client_secret' }
  }
}
```

### RequestConfig

Set optional defaults for all requests:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `http.totalTimeoutMs` | `number` | 30000 | Total request timeout |
| `http.connectTimeoutMs` | `number` | 10000 | Connection establishment timeout |
| `http.responseTimeoutMs` | `number` | 30000 | Response read timeout |
| `http.keepAliveTimeoutMs` | `number` | 60000 | Keep-alive connection timeout |
| `http.proxy` | `ProxyOptions` | - | HTTP/HTTPS proxy settings |

## Flow Execution Methods

### `_executeFlow()`

Call `_executeFlow()` to execute standard payment operations with HTTP round-trips:

```typescript
const response = await client._executeFlow(
  'authorize',
  requestMsg,
  options,           // Optional RequestConfig override
  'PaymentServiceAuthorizeRequest',
  'PaymentServiceAuthorizeResponse'
);
```

This method performs these steps:
1. Serializes the protobuf request
2. Builds the HTTP request via FFI
3. Executes HTTP with connection pooling
4. Parses the response via FFI
5. Deserializes the protobuf response

### `_executeDirect()`

Call `_executeDirect()` for inbound flows that do not need external HTTP calls (e.g., webhooks):

```typescript
const response = await client._executeDirect(
  'handle_event',
  requestMsg,
  options,
  'EventServiceHandleRequest',
  'EventServiceHandleResponse'
);
```

This method performs these steps:
1. Serializes the request
2. Calls the transformer directly via FFI
3. Deserializes the response

## Error Handling

Catch and handle errors using the `ConnectorError` class:

```typescript
import { ConnectorError } from 'hs-playlib';

try {
  const response = await client.authorize(request);
} catch (error) {
  if (error instanceof ConnectorError) {
    console.error('Error Code:', error.errorCode);
    console.error('Status Code:', error.statusCode);
    console.error('Message:', error.message);
    console.error('Response Body:', error.body);
  } else {
    console.error('Unexpected error:', error);
  }
}
```

### Error Codes

| Code | Description |
|------|-------------|
| `CONNECT_TIMEOUT` | Failed to establish connection |
| `RESPONSE_TIMEOUT` | Connection made but no response received |
| `TOTAL_TIMEOUT` | Overall request timeout exceeded |
| `NETWORK_FAILURE` | General network error |
| `INVALID_CONFIGURATION` | Client configuration error |
| `CLIENT_INITIALIZATION` | Failed to initialize SDK |

## Advanced Usage

### Per-Request Overrides

Override defaults for individual requests:

```typescript
const response = await client.authorize(request, {
  http: {
    totalTimeoutMs: 60000,  // Longer timeout for this request
  }
});
```

### Connection Pooling

Create each client instance once and reuse it for optimal performance. Each client maintains its own connection pool:

```typescript
// ✅ Good: Reuse client
const client = new PaymentClient(config, defaults);
for (const payment of payments) {
  await client.authorize(payment);
}

// ❌ Avoid: Creating client per request
for (const payment of payments) {
  const client = new PaymentClient(config, defaults);
  await client.authorize(payment);
}
```

### Custom Library Path

Specify a custom UniFFI library path for specialized deployments:

```typescript
const client = new PaymentClient(
  config,
  defaults,
  '/path/to/libconnector_service_ffi.dylib'
);
```

### Proxy Configuration

Configure proxy settings for all requests:

```typescript
const defaults = RequestConfig.create({
  http: {
    proxy: {
      httpUrl: 'http://proxy.company.com:8080',
      httpsUrl: 'https://proxy.company.com:8443',
      bypassUrls: ['http://localhost', 'http://internal.api']
    }
  }
});
```

## Complete Example: PayPal Access Token Flow

This example demonstrates fetching an access token and using it for payment authorization:

```typescript
import {
  PaymentClient,
  MerchantAuthenticationClient,
  types
} from 'hs-playlib';

const {
  ConnectorConfig, RequestConfig, Environment,
  Connector, Currency, CaptureMethod, SecretString,
  AccessToken, ConnectorState
} = types;

// Configuration
const config = ConnectorConfig.create({
  connector: Connector.PAYPAL,
  auth: {
    paypal: {
      clientId: { value: 'YOUR_CLIENT_ID' },
      clientSecret: { value: 'YOUR_CLIENT_SECRET' }
    }
  },
  environment: Environment.SANDBOX,
});

const defaults = RequestConfig.create({});

// Step 1: Get Access Token
const authClient = new MerchantAuthenticationClient(config, defaults);
const tokenResponse = await authClient.createAccessToken({
  merchantAccessTokenId: 'token_001',
  connector: Connector.PAYPAL,
  testMode: true,
});

// Step 2: Use Token for Payment
const paymentClient = new PaymentClient(config, defaults);
const paymentResponse = await paymentClient.authorize({
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
  state: ConnectorState.create({
    accessToken: AccessToken.create({
      token: SecretString.create({ value: tokenResponse.accessToken.value }),
      tokenType: 'Bearer',
      expiresInSeconds: tokenResponse.expiresInSeconds,
    }),
  }),
  testMode: true,
});

console.log('Payment status:', paymentResponse.status);
```

## Testing

### Smoke Test

Run the basic smoke test (no real API calls):

```bash
npm test
```

Run the full round-trip test with valid credentials:

```bash
STRIPE_API_KEY=sk_test_xxx npm test
```

### Manual Testing

Create a test file:

```typescript
// test_manual.ts
import { PaymentClient, types } from 'hs-playlib';

async function test() {
  // Your test code here
}

test().catch(console.error);
```

## Troubleshooting

### Common Issues

**Issue**: `Error: Cannot find module './generated/proto'`

**Solution**: Build the project:

```bash
npm run build
```

**Issue**: `Dynamic library loading failed`

**Solution**: Verify the native library exists:

```bash
# macOS/Linux
ls dist/src/payments/generated/*.dylib

# Linux
ls dist/src/payments/generated/*.so
```

**Issue**: `PROTOCOL_TIMEOUT` errors

**Solution**: Increase timeout configuration:

```typescript
const defaults = RequestConfig.create({
  http: {
    totalTimeoutMs: 60000,
    connectTimeoutMs: 20000,
  }
});
```

## API Reference

See the complete API reference documentation:

- [Payment Service](/api-reference/services/payment-service/)
- [Customer Service](/api-reference/services/customer-service/)
- [Event Service](/api-reference/services/event-service/)
- [Merchant Authentication Service](/api-reference/services/merchant-authentication-service/)
- [Payment Method Service](/api-reference/services/payment-method-service/)
- [Recurring Payment Service](/api-reference/services/recurring-payment-service/)

## TypeScript Support

Import types from the SDK for type-safe development:

```typescript
import { PaymentClient, types } from 'hs-playlib';

// Access types under the types namespace
const request: types.IPaymentServiceAuthorizeRequest = {
  // ...
};

// Use enums for type-safe values
const currency: types.Currency = types.Currency.USD;
const captureMethod: types.CaptureMethod = types.CaptureMethod.AUTOMATIC;
```

## Contributing

For SDK development and contributions, see the [JavaScript SDK source](https://github.com/juspay/connector-service/tree/main/sdk/javascript).

## License

MIT License - See LICENSE file for details.
