<!--
@doc-guidance
────────────────────────────────────────────────────
PAGE INTENT:How does the connector service handle errors whicle conencting to external processor. In case of run time errors how does it informat the develoopers with errror and instuctions to rectify. explain with example.
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

# Error Handling

Payment failures happen. Cards get declined. Networks timeout. Prism gives you structured error information that tells you exactly what went wrong and how to fix it, regardless of which payment processor generated the error.

## The Error Object

Every error follows the same structure:

```javascript
{
    error: {
        code: "PAYMENT_DECLINED",
        message: "Your card was declined.",
        category: "PAYMENT_ERROR",
        connector_code: "card_declined",
        connector_message: "Your card was declined.",
        request_id: "req_8f3a2b1c",
        retryable: false,
        suggested_action: "Ask customer to use different payment method"
    }
}
```

| Field | Purpose |
|-------|---------|
| `code` | Unified error code you handle in your code |
| `message` | Human-readable explanation |
| `category` | Error type (PAYMENT_ERROR, NETWORK_ERROR, CONFIGURATION_ERROR) |
| `connector_code` | Original error from the payment processor |
| `connector_message` | Original message from the payment processor |
| `request_id` | Unique ID for support/debugging |
| `retryable` | Whether retrying might succeed |
| `suggested_action` | Recommended next step |

## Error Categories

Errors fall into four categories based on root cause:

| Category | Description | Example | Retryable? |
|----------|-------------|---------|------------|
| **PAYMENT_ERROR** | Customer's payment method failed | Declined card, expired card | No |
| **NETWORK_ERROR** | Connectivity issues | Timeout, connection refused | Yes |
| **CONFIGURATION_ERROR** | Setup problems | Invalid API key, wrong credentials | No |
| **VALIDATION_ERROR** | Request issues | Invalid amount, missing field | No |

## Handling Errors in Code

```javascript
try {
    const response = await client.payments.authorize({
        amount: { minorAmount: 1000, currency: 'USD' },
        paymentMethod: { card: { cardNumber: '4000000000000002' } }  // Decline test card
    });
} catch (error) {
    // error.code is the unified error code
    switch (error.code) {
        case 'PAYMENT_DECLINED':
            // Show customer-friendly message
            showError('Your payment was declined. Please try a different card.');
            break;
            
        case 'EXPIRED_CARD':
            showError('Your card has expired. Please check the expiration date.');
            break;
            
        case 'INSUFFICIENT_FUNDS':
            showError('Insufficient funds. Please try a different payment method.');
            break;
            
        case 'NETWORK_TIMEOUT':
            // Retry logic for network errors
            if (error.retryable) {
                await retryWithBackoff(() => client.payments.authorize(request));
            }
            break;
            
        case 'INVALID_API_KEY':
            // Log for ops team—this is a configuration issue
            logger.error('Invalid Stripe API key', { requestId: error.request_id });
            showError('Payment service temporarily unavailable.');
            break;
            
        default:
            // Unknown error—log details and show generic message
            logger.error('Unexpected payment error', { error });
            showError('Something went wrong. Please try again.');
    }
}
```

## Real Error Examples

### Declined Card (Stripe)

**Stripe's raw response:**
```json
{
    "error": {
        "code": "card_declined",
        "decline_code": "insufficient_funds",
        "message": "Your card was declined."
    }
}
```

**Prism unified error:**
```json
{
    "error": {
        "code": "INSUFFICIENT_FUNDS",
        "message": "Your card has insufficient funds.",
        "category": "PAYMENT_ERROR",
        "connector_code": "card_declined",
        "connector_message": "Your card was declined.",
        "retryable": false,
        "suggested_action": "Ask customer to use different payment method"
    }
}
```

### Invalid API Key (Adyen)

**Adyen's raw response:**
```json
{
    "status": 401,
    "errorCode": "000",
    "message": "HTTP Status Response - Unauthorized",
    "errorType": "security"
}
```

**Prism unified error:**
```json
{
    "error": {
        "code": "INVALID_API_KEY",
        "message": "Invalid API credentials for Adyen",
        "category": "CONFIGURATION_ERROR",
        "connector_code": "000",
        "connector_message": "HTTP Status Response - Unauthorized",
        "retryable": false,
        "suggested_action": "Check Adyen API key and merchant account configuration"
    }
}
```

### Network Timeout

```json
{
    "error": {
        "code": "NETWORK_TIMEOUT",
        "message": "Request to payment processor timed out after 30 seconds",
        "category": "NETWORK_ERROR",
        "retryable": true,
        "suggested_action": "Retry the request with exponential backoff"
    }
}
```

## Retry Strategies

Some errors warrant retry. Prism tells you which:

```javascript
async function authorizeWithRetry(request, maxRetries = 3) {
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
        try {
            return await client.payments.authorize(request);
        } catch (error) {
            // Only retry if error is retryable and we haven't exhausted retries
            if (!error.retryable || attempt === maxRetries) {
                throw error;
            }
            
            // Exponential backoff: 1s, 2s, 4s
            const delay = Math.pow(2, attempt - 1) * 1000;
            await sleep(delay);
        }
    }
}
```

**Retryable errors:**
- `NETWORK_TIMEOUT`
- `RATE_LIMIT_EXCEEDED`
- `SERVICE_UNAVAILABLE`

**Non-retryable errors:**
- `PAYMENT_DECLINED`
- `EXPIRED_CARD`
- `INVALID_API_KEY`
- `VALIDATION_ERROR`

## Logging and Debugging

Always log the `request_id` for support:

```javascript
catch (error) {
    logger.error('Payment failed', {
        requestId: error.request_id,
        code: error.code,
        connector: 'stripe',
        amount: request.amount
    });
    
    // Customer sees generic message
    showError('Payment failed. Reference: ' + error.request_id);
}
```

Support teams can use `request_id` to trace the exact request in logs and diagnose issues.

## Best Practices

1. **Handle specific error codes** before falling back to generic handling
2. **Show customer-friendly messages**, not raw error codes
3. **Log full error details** for debugging
4. **Only retry retryable errors** with exponential backoff
5. **Use `request_id`** in customer-facing error messages for support
6. **Monitor error rates** by category to detect issues early

## Error Monitoring

Track errors to catch problems:

```javascript
// Track error rates
catch (error) {
    metrics.increment(`payment_error.${error.category}.${error.code}`);
    
    // Alert on configuration errors
    if (error.category === 'CONFIGURATION_ERROR') {
        pagerDuty.alert('Payment configuration error', { error });
    }
}
```

Configuration errors hitting production indicate a deployment or credential issue that needs immediate attention.
