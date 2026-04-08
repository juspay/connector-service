# Connector Settings and Overrides

Prism provides three configurable settings per connector: **Proxy**, **Timeout**, and **Retry**. 

It offers the flexibility to enable the setting could be enabled at a connector level or overridden per request.

| Setting | Description | Default |
|---------|-------------|---------|
| **Proxy** | HTTP proxy URL for routing requests to a target endpoint. You may leverage this when you choose to outsource PCI compliance to a compliant third party endpoint | None |
| **Timeout** | Request timeout from API call in milliseconds. You may tweak this for processor which are slower to respond. | 30000ms |
| **Retry** | Number of API retry attempts on failure, incase of network failures | 0 |

## Configuration at Connector Level

The below example is a connector level configuration of the API keys. Timeout and proxy settings are configured per-request using RequestConfig.

```javascript
const { PaymentClient } = require('hyperswitch-prism');

const config = {
    connectorConfig: {
        stripe: {
            apiKey: { value: process.env.STRIPE_API_KEY }
        },
    }
};
const paymentClient = new PaymentClient(config);
```

## Override at a Request Level

This is an example of overriding the settings for a single request for timeout and proxy using RequestConfig.

```javascript
const { PaymentClient } = require('hyperswitch-prism');
const types = require('hyperswitch-prism').types;

const config = {
    connectorConfig: {
        stripe: { apiKey: { value: process.env.STRIPE_API_KEY } }
    }
};
const paymentClient = new PaymentClient(config);

// Longer timeout for 3D Secure flows - use RequestConfig
const response = await paymentClient.authorize({
    merchantTransactionId: 'order-001',
    amount: { minorAmount: 1000, currency: types.Currency.USD },
    paymentMethod: { card: { /* card details */ } },
    captureMethod: types.CaptureMethod.MANUAL,
    address: { billingAddress: {} },
    authType: types.AuthenticationType.THREE_DS,
    returnUrl: "https://example.com/return"
}, {
    http: {
        totalTimeoutMs: 120000,   // 2 minute timeout for this request
        proxy: {
            httpUrl: "http://proxy.example.com:8080"
        }
    }
});
```
