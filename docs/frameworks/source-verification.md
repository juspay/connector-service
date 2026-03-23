# Source Verification

A customer returns from a 3D Secure challenge. The URL shows `status=success`. Do you ship the order? Not yet. That URL could be forged. Prism verifies the source before you fulfill a single order.

## The Risk: Forged Redirects

Redirect-based payments (3DS, bank authentication, wallet callbacks) are vulnerable to tampering:

- **URL parameter manipulation** — Changing `?status=failed` to `?status=success`
- **Replay attacks** — Reusing a successful callback URL for a different order
- **Forged callbacks** — Creating fake redirect responses that look legitimate

Without verification, you ship product for payments that never completed.

## How Source Verification Works

Prism cryptographically verifies redirect responses:

1. **Extract signature** — Pulls the signature from headers, query params, or body
2. **Recompute hash** — Generates expected signature using shared secrets
3. **Compare** — Validates the signatures match
4. **Return result** — `source_verified: true` only when verification passes

```javascript
// Customer returns from 3DS redirect
app.get('/payment/redirect', async (req, res) => {
  const { payment_intent, payment_intent_client_secret } = req.query;

  // Verify the redirect is authentic
  const result = await client.payments.verifyRedirectResponse({
    merchantOrderId: 'order_001',
    requestDetails: {
      queryParams: [
        { key: 'payment_intent', value: payment_intent },
        { key: 'payment_intent_client_secret', value: payment_intent_client_secret }
      ],
      headers: [
        { key: 'Content-Type', value: 'application/x-www-form-urlencoded' }
      ]
    }
  });

  if (!result.sourceVerified) {
    return res.status(400).json({ error: 'Redirect verification failed' });
  }

  // Safe to fulfill order
  await fulfillOrder(result.merchantOrderId);
  res.json({ status: 'success', orderId: result.merchantOrderId });
});
```

## Verification Methods by Connector

| Connector | Signature Location | Algorithm |
|-----------|-------------------|-----------|
| Stripe | `Stripe-Signature` header | HMAC-SHA256 |
| Adyen | `Authorization` header | HMAC-SHA256 |
| Checkout.com | Signature in body | HMAC-SHA256 |
| PayPal | Certificate-based | RSA-SHA256 |
| Worldpay | `MAC` query parameter | HMAC-SHA256 |

Prism abstracts these differences. You call one method. It handles all verification schemes.

## Response Structure

```json
{
  "source_verified": true,
  "connector_transaction_id": "pi_3Oxxx...",
  "response_amount": {
    "minor_amount": 1000,
    "currency": "USD"
  },
  "merchant_order_id": "order_001",
  "status": "AUTHORIZED"
}
```

| Field | Meaning |
|-------|---------|
| `source_verified` | Boolean. `true` only if cryptographically verified. |
| `status` | Payment status after verification. Can be `AUTHORIZED`, `FAILED`, or `PENDING`. |
| `response_amount` | Amount from the verified response. Check this matches your order total. |

## Error: Verification Failed

```json
{
  "error": {
    "code": "SOURCE_VERIFICATION_FAILED",
    "message": "Redirect response signature does not match expected value",
    "connector": "stripe",
    "suggestion": "Do not fulfill order. Check redirect parameters were not modified."
  }
}
```

**When this happens:**
- Customer modified URL parameters manually
- Redirect was intercepted and tampered with
- Wrong secrets configured
- Request replayed from different session

**Action:** Reject the payment. Do not fulfill the order.

## Error: Amount Mismatch

```json
{
  "error": {
    "code": "AMOUNT_VERIFICATION_FAILED",
    "message": "Response amount does not match expected order amount",
    "expected_amount": 1000,
    "response_amount": 500,
    "currency": "USD"
  }
}
```

This indicates tampering. The customer attempted to pay less than the order total.

## Complete 3DS Flow with Verification

```javascript
// 1. Initiate payment with 3DS
const auth = await client.payments.authorize({
  merchantTransactionId: 'txn_001',
  amount: { minorAmount: 1000, currency: 'USD' },
  paymentMethod: { card: {...} },
  authenticationType: 'THREE_DS'  // Triggers 3DS
});

// 2. Redirect customer to 3DS challenge
if (auth.status === 'PENDING' && auth.redirectForm) {
  res.redirect(auth.redirectForm.endpoint);
}

// 3. Customer returns from 3DS
app.get('/payment/return', async (req, res) => {
  // 4. Verify redirect before trusting it
  const verification = await client.payments.verifyRedirectResponse({
    merchantOrderId: 'txn_001',
    requestDetails: {
      queryParams: Object.entries(req.query).map(([k, v]) => ({ key: k, value: v })),
      headers: [{ key: 'Content-Type', value: 'application/x-www-form-urlencoded' }]
    }
  });

  // 5. Only proceed if verified
  if (!verification.sourceVerified) {
    return res.status(400).json({ error: 'Verification failed' });
  }

  // 6. Capture the verified payment
  const capture = await client.payments.capture({
    merchantTransactionId: 'txn_001',
    connectorTransactionId: verification.connectorTransactionId,
    amount: { minorAmount: 1000, currency: 'USD' }
  });

  res.json({ status: capture.status });
});
```

## Security Checklist

1. **Always verify redirects** — Never trust URL parameters without verification
2. **Check `source_verified`** — This must be `true`, not just present
3. **Validate amount** — Compare `response_amount` to your order total
4. **Verify transaction ID** — Ensure `connector_transaction_id` matches your records
5. **Handle failures** — Reject orders when verification fails

## Next Steps

- [Integrity](./integrity.md) — Webhook signature verification
- [Error Handling](../architecture/error-handling.md) — Handle verification errors
