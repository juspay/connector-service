# Adyen

<!--
---
title: Adyen
description: Adyen integration guide for Connector Service - global payments, 3DS, and local methods
last_updated: 2026-03-03
generated_from: backend/connector-integration/src/connectors/adyen/
auto_generated: false
reviewed_by: engineering
reviewed_at: 2026-03-03
approved: true
---
-->

## Overview

Adyen is a global payment platform supporting local payment methods across 200+ countries. This guide covers integration with Connector Service.

| Attribute | Value |
|-----------|-------|
| Connector ID | `ADYEN` |
| Regions | Global (200+ countries) |
| Currencies | 150+ |
| PCI Compliance | PCI DSS Level 1 |

## Prerequisites

### Adyen Account Setup

1. Sign up at [Adyen Customer Area](https://www.adyen.com/signup)
2. Complete merchant onboarding and KYC
3. Request API credentials from Adyen Support
4. Configure merchant accounts for each region

### Required Credentials

| Credential | Location | Purpose |
|------------|----------|---------|
| `api_key` | Customer Area > Account > API credentials | Authentication |
| `merchant_account` | Customer Area > Account | Merchant identification |
| `client_key` | Customer Area > Developers | Client-side encryption |
| `hmac_key` | Customer Area > Developers > Webhooks | Webhook verification |

## Configuration

### Credential Setup

Configure credentials in Connector Service:

```bash
curl -X POST https://api.juspay.in/v2/merchants/{merchant_id}/connectors \
  -H "Authorization: Bearer {ucs_api_key}" \
  -H "Content-Type: application/json" \
  -d '{
    "connector": "ADYEN",
    "connector_account_details": {
      "api_key": "AQExhmfx...",
      "api_secret": "your_merchant_account",
      "client_key": "test_..."
    },
    "test_mode": true
  }'
```

### PCI Mode

Adyen supports multiple PCI compliance modes:
- **Direct API**: PCI SAQ D (requires full compliance)
- **Secured Fields**: PCI SAQ A-EP (iFrame-based)
- **Drop-in/Components**: PCI SAQ A (lowest scope)

## Feature Matrix

| Feature | Support | Notes |
|---------|---------|-------|
| Card Payments | SUPPORTED | Visa, Mastercard, Amex, JCB, Diners, Discover |
| 3D Secure | SUPPORTED | Native 3DS2 with fallback to 3DS1 |
| Apple Pay | SUPPORTED | Requires Apple Developer account |
| Google Pay | SUPPORTED | Requires Google Pay business account |
| iDEAL | SUPPORTED | Netherlands only |
| Bancontact | SUPPORTED | Belgium only |
| Giropay | SUPPORTED | Germany only |
| Sofort | SUPPORTED | EUR countries |
| SEPA Direct Debit | SUPPORTED | EUR only |
| Refunds | SUPPORTED | Full and partial, with Modification API |
| Webhooks | SUPPORTED | Standard webhooks |

## Testing

### Test Credentials

| Environment | API Endpoint | Customer Area URL |
|-------------|--------------|-------------------|
| Sandbox | `https://pal-test.adyen.com/` | [Test CA](https://ca-test.adyen.com) |
| Production | `https://pal-live.adyen.com/` | [Live CA](https://ca-live.adyen.com) |

### Test Cards

| Card Number | Brand | Result |
|-------------|-------|--------|
| `4111111111111111` | Visa | Success (frictionless 3DS) |
| `4035501000000008` | Visa | 3DS2 challenge |
| `5201281500001005` | Mastercard | Success |
| `5201281500001013` | Mastercard | 3DS2 challenge |

## Common Errors

| Error Code | Cause | Resolution |
|------------|-------|------------|
| `Refused` | Issuer declined | Check refusal reason code |
| `InsufficientFunds` | No funds available | Use different card |
| `ExpiredCard` | Card expired | Use different card |
| `InvalidCardNumber` | Invalid card | Check card number |
| `AcquirerError` | Acquirer technical error | Retry with idempotency key |

## Example: Authorization

### Request

```bash
grpcurl -H "Authorization: Bearer $UCS_API_KEY" \
  -d '{
    "amount": {"currency": "EUR", "amount": 1000},
    "payment_method": {
      "card": {
        "card_number": "4111111111111111",
        "expiry_month": "03",
        "expiry_year": "2030",
        "card_holder_name": "John Doe",
        "cvc": "737"
      }
    },
    "connector": "ADYEN",
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
      "currency": "EUR",
      "amount": 1000
    },
    "connector": "ADYEN",
    "connector_transaction_id": "883628383618832G"
  }
}
```

## Webhook Configuration

1. Go to [Adyen Customer Area > Developers > Webhooks](https://ca-test.adyen.com/ca/ca/config/showws.shtml)
2. Click "Add webhook" > "Standard webhook"
3. Server configuration:
   - URL: `https://api.juspay.in/v2/webhooks/{merchant_id}`
   - Method: JSON
   - HMAC Key: Generate and save
4. Select events:
   - `AUTHORISATION`
   - `CAPTURE`
   - `REFUND`
   - `CHARGEBACK`
5. Save the HMAC key and configure in Connector Service

## Support

- **Adyen Support**: [adyen.help](https://www.adyen.help)
- **Adyen Documentation**: [docs.adyen.com](https://docs.adyen.com)
- **Connector Service Support**: support@juspay.in
