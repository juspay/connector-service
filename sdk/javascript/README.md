# hyperswitch-prism

[![npm version](https://badge.fury.io/js/hyperswitch-prism.svg)](https://www.npmjs.com/package/hyperswitch-prism)

Universal payment connector SDK for Node.js. Connect to 100+ payment processors through a single, unified API.

## Installation

```bash
npm install hyperswitch-prism
```

## Quick Start

```typescript
import { PaymentClient, types } from 'hyperswitch-prism';

// Configure your connector
const config: types.ConnectorConfig = {
  connectorConfig: {
    stripe: {
      apiKey: { value: 'sk_test_your_key' }
    }
  }
};

const client = new PaymentClient(config);

// Authorize a payment
const request: types.PaymentServiceAuthorizeRequest = {
  merchantTransactionId: 'txn_001',
  amount: {
    minorAmount: 1000,  // $10.00
    currency: types.Currency.USD,
  },
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
  authType: types.AuthenticationType.NO_THREE_DS,
  address: {},
  orderDetails: [],
};

const response = await client.authorize(request);
console.log('Status:', response.status);
```

## Features

- 100+ payment connectors (Stripe, PayPal, Adyen, and more)
- TypeScript native with full type definitions
- Rust core with native bindings for high performance
- Connection pooling for optimal throughput
- Stateless design - no payment data stored

## Requirements

- Node.js 18+
- macOS (x64, arm64) / Linux (x64, arm64) / Windows (x64)

## License

Apache-2.0
