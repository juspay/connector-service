# Connector Settings and Overrides

Sometimes you need to adjust behavior for a specific connector without changing your core integration logic. Prism gives you fine-grained control through settings and overrides that apply per-connector, per-request, or per-environment.

## Why You Need Control

Different payment processors have different quirks:
- Stripe supports idempotency keys. Adyen supports idempotency keys with different semantics.
- Some connectors require custom headers for specific features.
- You might want different retry policies for different providers.
- Certain connectors need webhook signature verification. Others don't.

Without overrides, you'd need connector-specific code paths. With overrides, you configure behavior declaratively.

## Setting Levels

Settings apply at three levels with increasing specificity:

```
Global Defaults
    ↓ (overridden by)
Connector Configuration
    ↓ (overridden by)
Request-Level Overrides
```

| Level | Scope | Use Case |
|-------|-------|----------|
| **Global** | All connectors | Default timeouts, retry policies |
| **Connector** | Specific connector | API keys, endpoint URLs, feature flags |
| **Request** | Single operation | Idempotency keys, custom metadata |

## Global Settings

Global settings define defaults across all connectors:

```javascript
const client = new ConnectorServiceClient({
    globalSettings: {
        timeoutMs: 30000,           // 30 second default timeout
        maxRetries: 3,              // Retry failed requests 3 times
        retryBackoffMs: 1000        // Wait 1 second between retries
    }
});
```

These apply unless a connector-specific setting overrides them.

## Connector Configuration

Each connector has its own configuration block:

```javascript
const client = new ConnectorServiceClient({
    connectors: {
        stripe: {
            apiKey: process.env.STRIPE_API_KEY,
            apiVersion: '2023-10-16',
            idempotencyKeyStrategy: 'per-request'
        },
        adyen: {
            apiKey: process.env.ADYEN_API_KEY,
            merchantAccount: 'YourMerchantAccount',
            environment: 'test',        // or 'live'
            timeoutMs: 60000            // Override global timeout for Adyen
        }
    }
});
```

Connector settings include:
- **Authentication**: API keys, certificates, OAuth tokens
- **Endpoints**: Sandbox vs. production URLs
- **Features**: Enable/disable connector-specific capabilities
- **Timeouts**: Override global defaults per connector

## Request-Level Overrides

Override settings for a single request:

```javascript
const response = await client.payments.authorize({
    amount: { minorAmount: 1000, currency: 'USD' },
    paymentMethod: { card: { ... } },
    connector: Connector.STRIPE,
    // Request-level override
    connectorSettings: {
        stripe: {
            idempotencyKey: `order-${orderId}-auth`,
            metadata: {
                internalOrderId: orderId,
                customerSegment: 'premium'
            }
        }
    }
});
```

Request overrides are useful for:
- Idempotency keys tied to your internal IDs
- Custom metadata for reconciliation
- Feature flags for specific transactions
- One-off timeout adjustments

## Common Override Patterns

### Idempotency Keys

Prevent duplicate charges by providing your own idempotency key:

```javascript
// Use your internal order ID as the idempotency key
const response = await client.payments.authorize({
    amount: { ... },
    connectorSettings: {
        stripe: { idempotencyKey: `order-${orderId}` }
    }
});
```

If the request fails and you retry, Stripe recognizes the duplicate key and returns the original response instead of charging twice.

### Custom Metadata

Attach your internal identifiers for reconciliation:

```javascript
const response = await client.payments.authorize({
    amount: { ... },
    connectorSettings: {
        stripe: {
            metadata: {
                orderId: 'order-123',
                customerId: 'cust-456',
                campaign: 'summer-sale'
            }
        }
    }
});
```

This data appears in Stripe dashboards and webhook events.

### Timeout Overrides

Some operations need more time:

```javascript
// 3D Secure authentication might take longer
const response = await client.payments.authenticate({
    paymentId: 'pay_123',
    connectorSettings: {
        adyen: { timeoutMs: 120000 }  // 2 minute timeout
    }
});
```

### Feature Flags

Enable connector-specific features:

```javascript
const response = await client.payments.authorize({
    amount: { ... },
    connectorSettings: {
        adyen: {
            enableNetworkTokenization: true,
            splitSettlement: {
                primary: 800,    // 80% to primary account
                secondary: 200   // 20% to marketplace account
            }
        }
    }
});
```

## Settings in Practice

A typical configuration combines all three levels:

```javascript
const client = new ConnectorServiceClient({
    // Global defaults
    globalSettings: {
        timeoutMs: 30000,
        maxRetries: 3
    },
    
    // Connector-specific configuration
    connectors: {
        stripe: {
            apiKey: process.env.STRIPE_API_KEY,
            webhookSecret: process.env.STRIPE_WEBHOOK_SECRET
        },
        adyen: {
            apiKey: process.env.ADYEN_API_KEY,
            merchantAccount: process.env.ADYEN_MERCHANT_ACCOUNT,
            timeoutMs: 45000  // Adyen needs more time
        }
    }
});

// Request with overrides
const response = await client.payments.authorize({
    amount: { minorAmount: 1000, currency: 'USD' },
    paymentMethod: { card: { ... } },
    connector: Connector.STRIPE,
    connectorSettings: {
        stripe: {
            idempotencyKey: `auth-${orderId}`,
            metadata: { orderId, customerId }
        }
    }
});
```

## Validation

Prism validates settings at initialization and request time:

- Missing required settings throw errors on client creation
- Invalid setting combinations are caught before API calls
- Unknown settings are logged as warnings (to catch typos)

This catches configuration errors early, before they cause failed payments.
