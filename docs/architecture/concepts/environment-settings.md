<!--
@doc-guidance
────────────────────────────────────────────────────
PAGE INTENT: Why would develpers need environemnt setting control. How to confuigure it in the connrector service has to be explain with examples.
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

# Environment Settings

Your code behaves differently in development, staging, and production. Prism lets you configure environments explicitly so test transactions don't hit live payment processors and production keys don't leak into debug logs.

## Why Environment Control Matters

Payment integrations have three distinct modes:

| Environment | Use Case | Risk Level |
|-------------|----------|------------|
| **Development** | Local testing, feature work | Zero—fake data only |
| **Sandbox/Staging** | Integration testing, QA | Low—test credentials, fake money |
| **Production** | Real customer transactions | High—real money, real consequences |

Without explicit environment configuration, you might accidentally charge a real card during testing. Or worse, use production credentials in a debug session that gets logged.

## Environment Configuration

Configure environments at the connector level:

```javascript
const client = new ConnectorServiceClient({
    connectors: {
        stripe: {
            // Use sandbox for development
            apiKey: process.env.STRIPE_TEST_API_KEY,
            environment: 'test'  // or 'live'
        },
        adyen: {
            // Different endpoints for different environments
            apiKey: process.env.ADYEN_TEST_API_KEY,
            merchantAccount: process.env.ADYEN_TEST_MERCHANT,
            environment: 'test'  // or 'live'
        }
    }
});
```

## Common Environment Patterns

### Development Environment

Use fake data and mock responses:

```javascript
// .env.development
CONNECTOR_SERVICE_MODE=mock
STRIPE_API_KEY=sk_test_dummy

// client initialization
const client = new ConnectorServiceClient({
    mode: 'mock',  // Returns success responses without API calls
    connectors: {
        stripe: { apiKey: 'sk_test_dummy' }
    }
});
```

Mock mode is useful for:
- Unit testing without network calls
- Frontend development before backend is ready
- CI/CD pipelines that shouldn't make external requests

### Sandbox Environment

Use real sandbox credentials:

```javascript
// .env.staging
STRIPE_API_KEY=sk_test_abc123...
STRIPE_WEBHOOK_SECRET=whsec_xyz789...

// client initialization
const client = new ConnectorServiceClient({
    connectors: {
        stripe: {
            apiKey: process.env.STRIPE_API_KEY,
            webhookSecret: process.env.STRIPE_WEBHOOK_SECRET,
            environment: 'test'
        }
    }
});
```

Sandbox environments:
- Accept test card numbers (4242424242424242)
- Don't move real money
- Mirror production API behavior
- Support webhook testing

### Production Environment

Use live credentials with extra safeguards:

```javascript
// .env.production
STRIPE_API_KEY=sk_live_abc123...
STRIPE_WEBHOOK_SECRET=whsec_xyz789...

// client initialization with production safeguards
const client = new ConnectorServiceClient({
    connectors: {
        stripe: {
            apiKey: process.env.STRIPE_API_KEY,
            webhookSecret: process.env.STRIPE_WEBHOOK_SECRET,
            environment: 'live',
            // Extra safeguards for production
            validateIdempotencyKeys: true,
            logLevel: 'error'  // Don't log request/response bodies
        }
    },
    // Global production settings
    globalSettings: {
        timeoutMs: 45000,  // Longer timeouts for reliability
        maxRetries: 5
    }
});
```

## Environment Detection

Prism can detect environments automatically:

```javascript
// Auto-detect from NODE_ENV
const client = new ConnectorServiceClient({
    environment: process.env.NODE_ENV,  // 'development', 'staging', 'production'
    connectors: {
        stripe: {
            // Keys selected based on environment
            testApiKey: process.env.STRIPE_TEST_API_KEY,
            liveApiKey: process.env.STRIPE_LIVE_API_KEY
        }
    }
});
```

The client selects the appropriate credentials based on the environment:

| NODE_ENV | Stripe API Key Used | Adyen Environment |
|----------|--------------------|--------------------|
| development | testApiKey | test |
| staging | testApiKey | test |
| production | liveApiKey | live |

## Environment-Specific Features

Some features only work in specific environments:

```javascript
const client = new ConnectorServiceClient({
    connectors: {
        stripe: {
            apiKey: process.env.STRIPE_API_KEY,
            environment: 'test',
            // Sandbox-only features
            enableRequestLogging: true,  // Log all requests in test
            simulateErrors: ['card_declined', 'insufficient_funds']  // Test error handling
        }
    }
});
```

## Best Practices

### 1. Separate Credential Files

Never commit credentials to version control:

```bash
# .gitignore
.env
.env.local
.env.production
```

### 2. Validate Environment on Startup

```javascript
const requiredEnvVars = {
    development: ['STRIPE_TEST_API_KEY'],
    staging: ['STRIPE_TEST_API_KEY', 'STRIPE_WEBHOOK_SECRET'],
    production: ['STRIPE_LIVE_API_KEY', 'STRIPE_LIVE_WEBHOOK_SECRET']
};

const env = process.env.NODE_ENV || 'development';
const missing = requiredEnvVars[env].filter(key => !process.env[key]);

if (missing.length > 0) {
    throw new Error(`Missing required env vars for ${env}: ${missing.join(', ')}`);
}
```

### 3. Use Different Webhook Endpoints

```javascript
// Development: localhost webhook tunnel
const webhookConfig = {
    development: { endpoint: 'https://webhook.site/unique-id' },
    staging: { endpoint: 'https://staging.yoursite.com/webhooks' },
    production: { endpoint: 'https://yoursite.com/webhooks' }
};
```

### 4. Log Environment on Initialization

```javascript
const client = new ConnectorServiceClient(config);
console.log(`Prism initialized: environment=${env}, mode=${config.mode}`);
// Logs: Prism initialized: environment=production, mode=live
```

This prevents "why are test cards failing?" debugging sessions when you're accidentally in live mode.

## Complete Environment Setup

```javascript
// config.js
const environments = {
    development: {
        mode: 'mock',
        connectors: {
            stripe: { apiKey: 'sk_test_dummy' }
        }
    },
    staging: {
        mode: 'live',
        connectors: {
            stripe: {
                apiKey: process.env.STRIPE_TEST_API_KEY,
                environment: 'test',
                enableRequestLogging: true
            }
        }
    },
    production: {
        mode: 'live',
        connectors: {
            stripe: {
                apiKey: process.env.STRIPE_LIVE_API_KEY,
                environment: 'live',
                logLevel: 'error'
            }
        }
    }
};

const env = process.env.NODE_ENV || 'development';
module.exports = environments[env];
```

Environment configuration prevents costly mistakes and makes your integration behavior predictable across dev, staging, and production.
