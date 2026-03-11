# Stripe

<!--
---
title: Stripe
description: Stripe integration guide for Connector Service - payments, refunds, webhooks, and more
last_updated: 2026-03-03
generated_from: backend/connector-integration/src/connectors/stripe/
auto_generated: false
reviewed_by: engineering
reviewed_at: 2026-03-03
approved: true
---
-->

## Overview

Stripe is a global payment processor supporting 135+ currencies and extensive payment methods. This guide covers integration with Connector Service.

| Attribute | Value |
|-----------|-------|
| Connector ID | `STRIPE` |
| Regions | Global (46+ countries) |
| Currencies | 135+ |
| PCI Compliance | PCI DSS Level 1 |

## Prerequisites

### Stripe Account Setup

1. Sign up at [Stripe Dashboard](https://dashboard.stripe.com/register)
2. Complete business verification (if processing live payments)
3. Enable required payment methods in Dashboard > Settings > Payment Methods
4. Generate API keys in Dashboard > Developers > API Keys

### Required Credentials

| Credential | Location | Purpose |
|------------|----------|---------|
| `api_key` | Dashboard > Developers > API Keys | Authentication |
| `webhook_secret` | Dashboard > Developers > Webhooks | Webhook verification |

## Configuration

### Credential Setup

Configure credentials in Connector Service:

```bash
curl -X POST https://api.juspay.in/v2/merchants/{merchant_id}/connectors \
  -H "Authorization: Bearer {ucs_api_key}" \
  -H "Content-Type: application/json" \
  -d '{
    "connector": "STRIPE",
    "connector_account_details": {
      "api_key": "sk_test_...",
      "api_secret": "whsec_..."
    },
    "test_mode": true
  }'
```

### PCI Mode

Stripe supports multiple PCI compliance modes:
- **PCI DSS Level 1**: Direct card handling with SAQ D
- **Stripe Elements**: PCI SAQ A (recommended)
- **Stripe Checkout**: Hosted payment page (lowest PCI scope)

## Feature Matrix

| Feature | Support | Notes |
|---------|---------|-------|
| Card Payments | SUPPORTED | Visa, Mastercard, Amex, Discover, JCB |
| 3D Secure | SUPPORTED | Automatic 3DS2 with fallback to 3DS1 |
| Apple Pay | SUPPORTED | Requires Apple Developer account |
| Google Pay | SUPPORTED | Requires Google Pay business account |
| Link | SUPPORTED | Stripe's one-click checkout |
| SEPA Direct Debit | SUPPORTED | EUR only |
| ACH | SUPPORTED | USD only |
| Refunds | SUPPORTED | Full and partial |
| Webhooks | SUPPORTED | All event types |

## Testing

### Test Credentials

| Environment | API Endpoint | Dashboard URL |
|-------------|--------------|---------------|
| Sandbox | `https://api.stripe.com/v1/` | [Dashboard](https://dashboard.stripe.com/test) |
| Production | `https://api.stripe.com/v1/` | [Dashboard](https://dashboard.stripe.com) |

### Test Cards

| Card Number | Brand | Result |
|-------------|-------|--------|
| `4242424242424242` | Visa | Success |
| `4000000000000002` | Visa | Generic decline |
| `4000000000000127` | Visa | Incorrect CVC |
| `4000000000000069` | Visa | Expired card |
| `4000000000003220` | Visa | 3DS2 frictionless |
| `4000002500003155` | Visa | 3DS2 challenge |

## Common Errors

| Error Code | Cause | Resolution |
|------------|-------|------------|
| `card_declined` | Issuer declined | Use different card or contact bank |
| `insufficient_funds` | Card has no funds | Use different card |
| `expired_card` | Card expired | Use different card |
| `incorrect_cvc` | CVC check failed | Retry with correct CVC |
| `processing_error` | Stripe processing error | Retry with idempotency key |

## Example: Authorization

### Request

```bash
grpcurl -H "Authorization: Bearer $UCS_API_KEY" \
  -d '{
    "amount": {"currency": "USD", "amount": 1000},
    "payment_method": {
      "card": {
        "card_number": "4242424242424242",
        "expiry_month": "12",
        "expiry_year": "2027",
        "card_holder_name": "John Doe",
        "cvc": "123"
      }
    },
    "connector": "STRIPE",
    "merchant_order_reference_id": "order-001"
  }' \
  api.juspay.in:443 ucs.v2.PaymentService/Authorize
```

### Response

```json
{
  "payment": {
    "id": "pay_abc123xyz",
    "status": "AUTHORIZED",
    "amount": {
      "currency": "USD",
      "amount": 1000
    },
    "connector": "STRIPE",
    "connector_transaction_id": "pi_3Oxxx..."
  }
}
```

## Webhook Configuration

1. Go to [Stripe Dashboard > Webhooks](https://dashboard.stripe.com/webhooks)
2. Click "Add endpoint"
3. Endpoint URL: `https://api.juspay.in/v2/webhooks/{merchant_id}`
4. Select events:
   - `payment_intent.succeeded`
   - `payment_intent.payment_failed`
   - `charge.refunded`
   - `charge.dispute.created`
5. Copy the webhook signing secret (`whsec_...`)
6. Configure the secret in Connector Service

## Support

- **Stripe Support**: [support.stripe.com](https://support.stripe.com)
- **Stripe Documentation**: [stripe.com/docs](https://stripe.com/docs)
- **Connector Service Support**: support@juspay.in
