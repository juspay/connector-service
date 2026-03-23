# Integrity and Source Verification

Every payload from a payment processor carries two risks: tampering (someone modified the data in transit) and impersonation (someone forged the sender's identity). Hyperswitch Prism provides the tools to eliminate both risks:

| Verification Type | What It Checks | Attack Prevented |
|-------------------|----------------|------------------|
| **Integrity** | Amount, currency, and transaction ID match your records | Data tampering |
| **Source** | Cryptographic signature using shared secrets | Impersonation, forged webhooks |

Before trusting any webhook or redirect response, Prism helps you verify both.

---

## 1. Why Integration Checks and Source Verification is Important?

Every payment processor webhook or redirect response that enters your system is a potential attack vector. Without proper verification, attackers can exploit your system in two critical ways:

### Data Tampering (Integrity Risk)

An attacker intercepting a webhook can modify the payload before it reaches your server:
- Change a failed payment status to "succeeded" → You ship unpaid orders
- Modify the amount from $100 to $1 → Customer pays less
- Change currency from USD to a cheaper one → Arbitrage attack

### Impersonation (Source Risk)

Attackers can forge webhooks that appear to come from payment processors:
- Send fake "payment succeeded" webhooks → Ship products for free
- Mimic refund notifications → Manipulate your accounting
- Fake 3D Secure callbacks → Bypass authentication

**Real-world impact:** A forged webhook could mark a failed payment as successful, causing you to ship product for unpaid orders. The financial and reputational damage can be severe.

Prism provides built-in verification for both risks, but you must enable and use these features to benefit from them.

---

## 2. Recommendations - Recommended Integrity Checks

Prism performs several integrity checks automatically. Here's what you should verify and how Prism helps:

### Amount and Currency Verification

Webhooks include amounts. Prism verifies these match your records.

```json
{
  "event_type": "PAYMENT_INTENT_SUCCESS",
  "amount": {
    "minor_amount": 5999,
    "currency": "USD"
  },
  "expected_amount": {
    "minor_amount": 5999,
    "currency": "USD"
  }
}
```

If amounts mismatch, Prism flags the discrepancy:

```json
{
  "error": {
    "code": "AMOUNT_MISMATCH",
    "message": "Webhook amount does not match expected amount",
    "webhook_amount": 4999,
    "expected_amount": 5999,
    "currency": "USD"
  }
}
```

**Why it matters:** This prevents attacks where an attacker modifies the webhook payload to show a lower amount than actually charged.

### Transaction ID Verification

Prism tracks transaction IDs across the lifecycle. When a webhook arrives, it verifies the ID matches an in-flight transaction.

| Check | Failure Mode |
|-------|--------------|
| ID exists in system | Reject unknown transaction IDs |
| Status transition valid | Reject invalid state changes (e.g., SUCCEEDED → PENDING) |
| Amount matches | Reject amount tampering |
| Currency matches | Reject currency switching attacks |

### Error: Amount Mismatch

```json
{
  "error": {
    "code": "AMOUNT_MISMATCH",
    "message": "Webhook amount does not match expected amount",
    "webhook_amount": 4999,
    "expected_amount": 5999,
    "currency": "USD"
  }
}
```

### Error: Replay Attack Detected

```json
{
  "error": {
    "code": "DUPLICATE_EVENT",
    "message": "Event ID already processed",
    "event_id": "evt_1234567890",
    "processed_at": "2026-03-19T10:30:00Z"
  }
}
```

Prism tracks event IDs to prevent replay attacks. An attacker cannot resend an old webhook to trigger duplicate actions.

### Configuration

Configure secrets per connector:

```javascript
const client = new ConnectorServiceClient({
  connector: 'stripe',
  webhookSecrets: {
    secret: process.env.STRIPE_WEBHOOK_SECRET,
    // Some connectors use additional secrets
    additionalSecret: process.env.STRIPE_ADDITIONAL_SECRET
  }
});
```

**Secret Rotation:**
- Generate new secret in processor dashboard
- Update Prism configuration
- Old secret continues working during transition
- Remove old secret after 24 hours

---

## 3. Signature Verification - How It Works

Typically Payment processors sign webhooks with a shared secret. You verify the signature before trusting the payload. Prism handles this for every supported processor.

### Supported Algorithms

| Algorithm | Processors Using It | Security Level |
|-----------|---------------------|----------------|
| HMAC-SHA256 | Stripe, Adyen, Checkout.com | Recommended |
| HMAC-SHA1 | Legacy systems | Acceptable |
| HMAC-SHA512 | High-security connectors | Maximum |

### Verification Code Example

```javascript
// Incoming webhook from Stripe
const payload = req.body;
const signature = req.headers['stripe-signature'];

// Prism verifies the signature
const result = await client.events.handle({
  payload: payload,
  signature: signature,
  connector: 'stripe',
  webhookSecrets: {
    secret: process.env.STRIPE_WEBHOOK_SECRET
  }
});

// result.source_verified tells you if the webhook is authentic
console.log(result.sourceVerified); // true or false
```

### The Complete Verification Flow

```javascript
// 1. Receive webhook
app.post('/webhooks/stripe', async (req, res) => {
  const payload = req.body;
  const signature = req.headers['stripe-signature'];

  // 2. Verify before processing
  const result = await client.events.handle({
    payload: payload,
    signature: signature,
    connector: 'stripe',
    webhookSecrets: { secret: process.env.STRIPE_WEBHOOK_SECRET }
  });

  // 3. Check verification result
  if (!result.sourceVerified) {
    // Reject forged webhooks immediately
    return res.status(401).json({ error: 'Invalid signature' });
  }

  // 4. Process verified event
  await processPaymentEvent(result.eventResponse);
  res.json({ received: true });
});
```

**Never process unverified webhooks.**

### Error: Signature Verification Failed

```json
{
  "error": {
    "code": "SIGNATURE_VERIFICATION_FAILED",
    "message": "Webhook signature does not match payload",
    "connector": "stripe",
    "suggestion": "Check your webhook secret is correct and the payload was not modified"
  }
}
```

**Common causes:**
- Wrong webhook secret configured
- Payload modified in transit (proxy, middleware)
- Signature header missing or malformed

---

## Testing Webhook Verification

Test with forged signatures to verify your rejection logic:

```bash
# Send webhook with invalid signature
curl -X POST http://localhost:8080/webhooks/stripe \
  -H "Content-Type: application/json" \
  -H "Stripe-Signature: forged_signature" \
  -d '{"type":"payment_intent.succeeded","id":"evt_test"}'

# Expected: 401 Unauthorized
```

## Best Practices

1. **Verify before processing** — Never trust webhooks without signature verification
2. **Use HTTPS** — Webhooks over HTTP expose secrets to interception
3. **Log verification failures** — Repeated failures indicate attack attempts
4. **Implement idempotency** — Handle duplicate webhooks gracefully even with verification
5. **Rotate secrets quarterly** — Limit exposure window if a secret leaks

## Next Steps

- [Source Verification](./source-verification.md) — Verify redirect responses and 3DS callbacks
- [Error Handling](../architecture/error-handling.md) — Handle verification failures in your application
