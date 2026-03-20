<!--
@doc-guidance
────────────────────────────────────────────────────
PAGE INTENT: The connector service has setting and overrides to provide control to developers. Explain the needs for such control and how connector serv ice provives it.
AUDIENCE: Payment developers and architects
TONE: Direct, conversational, opinionated. Write like explaining to a colleague over coffee.
PRIOR READING: [What pages should the reader have seen before this one? Link them.]
LEADS INTO: [What page comes next?]
────────────────────────────────────────────────────
LENGTH: 1.5–2 pages max (~600–800 words prose, tables and code blocks don't count toward this).
         If you need more space, the page is doing too much — split it.

WRITING RULES:
1. FIRST SENTENCE RULE — Open with what the reader gains, not what the thing is.
   Bad:  "The Prism SDK provides a unified interface..."
   Good: "You call one method. It works with Stripe, Adyen, or any of 50+ processors."

2. NO HEDGING — Delete: "can be", "may", "it is possible to", "in some cases", "typically".
   Say what IS. If something is conditional, state the condition.

3. VERB OVER NOUN — "lets you configure" not "provides configuration capabilities".
   "transforms the request" not "performs request transformation".

4. ONE IDEA PER SECTION — If a section has more than one takeaway, split it.

5. SHOW THEN TELL — Code example or diagram first, explanation after.
   The reader should see what it looks like before reading why.

6. EARN EVERY SENTENCE — If removing a sentence doesn't lose information, remove it.
   No "In this section, we will discuss..." No "As mentioned earlier..."
   No "It is important to note that..."

7. SPECIFICS OVER CLAIMS — Never say "supports many payment methods".
   Say "supports cards, wallets (Apple Pay, Google Pay), bank transfers, BNPL, and UPI".

8. ERRORS ARE FEATURES — When documenting a flow, show what goes wrong too.
   Include at least one error scenario with the actual error message.

9. NAME THE PRODUCT "Prism" — Not "UCS", not "the service", not "our platform".

10. TABLES FOR COMPARISON, PROSE FOR NARRATIVE — Don't put a story in a table.
    Don't write paragraphs when a 3-row table would be clearer.

CODE EXAMPLE RULES:
- Every code block must be runnable or clearly marked as pseudocode
- Use test credentials: Stripe key as $STRIPE_API_KEY, card 4242424242424242
- Show the output, not just the input
- If the example needs setup, show the setup

ANTI-PATTERNS TO REJECT:
- "Comprehensive", "robust", "seamless", "leverage", "utilize", "facilitate"
- Starting paragraphs with "Additionally", "Furthermore", "Moreover"
- Any sentence that describes the documentation itself ("This guide covers...")
- Repeating the heading as the first sentence of a section
────────────────────────────────────────────────────
-->

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
