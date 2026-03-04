# Authorize RPC

<!--
---
title: Authorize
description: Authorize a payment amount on a payment method - reserves funds without capturing
last_updated: 2026-03-03
generated_from: backend/grpc-api-types/proto/services.proto
auto_generated: false
reviewed_by: engineering
reviewed_at: 2026-03-03
approved: true
---
-->

## Overview

The `Authorize` RPC reserves funds on a customer's payment method without transferring them. This is the first step in a two-step payment flow (authorize + capture).

## Purpose

- Reserve funds for later capture
- Verify payment method validity
- Reduce fraud risk by verifying funds availability
- Enable delayed capture for order fulfillment workflows

## Request: PaymentServiceAuthorizeRequest

```protobuf
message PaymentServiceAuthorizeRequest {
  // Required fields
  Money amount = 1;
  PaymentMethod payment_method = 2;
  Connector connector = 3;

  // Optional fields
  string merchant_order_reference_id = 4;
  string description = 5;
  Address billing_address = 6;
  Address shipping_address = 7;
  Metadata metadata = 8;
  SetupMandateDetails mandate_data = 9;
  string idempotency_key = 10;
  AuthenticationData authentication_data = 11;
  CaptureMethod capture_method = 12;  // MANUAL (default) or AUTOMATIC
}
```

### Request Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `amount` | Money | Yes | Amount to authorize (currency + amount in minor units) |
| `payment_method` | PaymentMethod | Yes | Card, wallet, or other payment method |
| `connector` | Connector | Yes | Target payment processor (STRIPE, ADYEN, etc.) |
| `merchant_order_reference_id` | string | No | Your internal order reference ID |
| `description` | string | No | Payment description shown to customer |
| `billing_address` | Address | No | Customer billing address for fraud checks |
| `shipping_address` | Address | No | Customer shipping/delivery address |
| `metadata` | Metadata | No | Custom key-value pairs (max 20 keys) |
| `mandate_data` | SetupMandateDetails | No | For setting up recurring payments |
| `idempotency_key` | string | No | Unique key for safe retries (max 36 chars) |
| `authentication_data` | AuthenticationData | No | 3DS authentication data |
| `capture_method` | CaptureMethod | No | MANUAL (default) or AUTOMATIC |

## Response: PaymentServiceAuthorizeResponse

```protobuf
message PaymentServiceAuthorizeResponse {
  Payment payment = 1;
  ConnectorResponseData connector_response = 2;
  RedirectionResponse redirection_response = 3;  // If redirect required
}
```

### Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `payment` | Payment | Created payment with ID, status, and amount |
| `connector_response` | ConnectorResponseData | Raw connector response for debugging |
| `redirection_response` | RedirectionResponse | Redirect URL if 3DS or redirect-based payment needed |

## Example

### Request (grpcurl)

```bash
grpcurl -H "Authorization: Bearer $UCS_API_KEY" \
  -d '{
    "amount": {
      "currency": "USD",
      "amount": 1000
    },
    "payment_method": {
      "card": {
        "card_number": "4111111111111111",
        "expiry_month": "12",
        "expiry_year": "2027",
        "card_holder_name": "John Doe",
        "cvc": "123"
      }
    },
    "connector": "STRIPE",
    "merchant_order_reference_id": "order-001",
    "capture_method": "MANUAL"
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
    "connector": "STRIPE"
  }
}
```

## Error Cases

| Error Code | Cause | Resolution |
|------------|-------|------------|
| `CARD_DECLINED` | Issuer declined | Use different payment method |
| `INSUFFICIENT_FUNDS` | Card has no funds | Use different payment method |
| `INVALID_CARD_NUMBER` | Card number invalid | Check card number format |
| `EXPIRED_CARD` | Card expired | Use different card |

## Next Steps

- [Capture](./capture.md) - Capture the authorized payment
- [Void](./void.md) - Cancel the authorization
- [Get](./get.md) - Check payment status
