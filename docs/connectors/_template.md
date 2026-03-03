# {Connector Name}

<!--
---
title: {Connector Name}
description: {Connector Name} integration guide for Connector Service
last_updated: {YYYY-MM-DD}
generated_from: backend/connector-integration/src/connectors/{connector_id}/
auto_generated: false
reviewed_by: engineering
reviewed_at: {YYYY-MM-DD}
approved: true
---
-->

## Overview

{Connector Name} is a {regional_scope} payment processor supporting {payment_methods}. This guide covers integration with Connector Service.

| Attribute | Value |
|-----------|-------|
| Connector ID | `{CONNECTOR_ID}` |
| Regions | {regions} |
| Currencies | {supported_currencies} |
| PCI Compliance | {PCI_MODE} |

## Prerequisites

### {Connector Name} Account Setup

1. Sign up at [{connector_portal}]({signup_url})
2. Complete business verification
3. Enable required payment methods
4. Generate API credentials

### Required Credentials

| Credential | Location | Purpose |
|------------|----------|---------|
| `{API_KEY_NAME}` | Dashboard > Settings > API Keys | Authentication |
| `{MERCHANT_ID_NAME}` | Dashboard > Account | Merchant identification |
| `{WEBHOOK_SECRET_NAME}` | Dashboard > Webhooks | Webhook verification |

## Configuration

### Credential Setup

Configure credentials in Connector Service:

```bash
curl -X POST https://api.juspay.in/v2/merchants/{merchant_id}/connectors \
  -H "Authorization: Bearer {api_key}" \
  -H "Content-Type: application/json" \
  -d '{
    "connector": "{CONNECTOR_ID}",
    "connector_account_details": {
      "api_key": "your_{connector_id}_api_key",
      "api_secret": "your_{connector_id}_api_secret"
    },
    "test_mode": true
  }'
```

### PCI Mode

{Connector Name} supports:
- **PCI DSS Level 1**: Direct card handling
- **Tokenization**: Use {Connector Name} tokens
- **Hosted Fields**: iFrame-based card input

## Feature Matrix

| Feature | Support | Notes |
|---------|---------|-------|
| Card Payments | {SUPPORTED/PARTIAL/NOT_SUPPORTED} | {notes} |
| 3D Secure | {SUPPORTED/PARTIAL/NOT_SUPPORTED} | {notes} |
| Apple Pay | {SUPPORTED/PARTIAL/NOT_SUPPORTED} | {notes} |
| Google Pay | {SUPPORTED/PARTIAL/NOT_SUPPORTED} | {notes} |
| Refunds | {SUPPORTED/PARTIAL/NOT_SUPPORTED} | {notes} |
| Partial Refunds | {SUPPORTED/PARTIAL/NOT_SUPPORTED} | {notes} |
| Webhooks | {SUPPORTED/PARTIAL/NOT_SUPPORTED} | {notes} |

## Testing

### Test Credentials

| Environment | API Endpoint | Dashboard URL |
|-------------|--------------|---------------|
| Sandbox | `{sandbox_api_url}` | `{sandbox_dashboard}` |
| Production | `{production_api_url}` | `{production_dashboard}` |

### Test Cards

| Card Number | Brand | Result |
|-------------|-------|--------|
| `{test_card_success}` | Visa | Success |
| `{test_card_decline}` | Visa | Decline |
| `{test_card_3ds}` | Visa | 3DS Challenge |

## Common Errors

| Error Code | Cause | Resolution |
|------------|-------|------------|
| `{ERROR_CODE_1}` | {description} | {resolution} |
| `{ERROR_CODE_2}` | {description} | {resolution} |

## Example: Authorization

### Request

```bash
grpcurl -H "Authorization: Bearer $UCS_API_KEY" \
  -d '{
    "amount": {"currency": "USD", "amount": 1000},
    "payment_method": {
      "card": {
        "card_number": "{test_card_success}",
        "expiry_month": "12",
        "expiry_year": "2027",
        "cvc": "123"
      }
    },
    "connector": "{CONNECTOR_ID}"
  }' \
  api.juspay.in:443 ucs.v2.PaymentService/Authorize
```

### Response

```json
{
  "payment": {
    "id": "pay_xxx",
    "status": "AUTHORIZED",
    "connector": "{CONNECTOR_ID}"
  }
}
```

## Webhook Configuration

1. Go to {Connector Name} Dashboard > Webhooks
2. Add endpoint: `https://api.juspay.in/v2/webhooks/{merchant_id}`
3. Select events: `payment_intent.succeeded`, `payment_intent.payment_failed`, etc.
4. Copy webhook secret and configure in Connector Service

## Support

- **{Connector Name} Support**: {support_url}
- **Connector Service Support**: support@juspay.in
