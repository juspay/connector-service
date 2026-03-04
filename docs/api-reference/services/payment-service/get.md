# Get RPC

---
title: Get
description: Retrieve current payment status from the payment processor - enables state synchronization
last_updated: 2026-03-03
generated_from: backend/grpc-api-types/proto/services.proto
auto_generated: false
reviewed_by: engineering
reviewed_at: 2026-03-03
approved: true
---

## Overview

The `Get` RPC retrieves the current status of a payment from the payment processor, enabling synchronization between your system and Connector Service.

## Purpose

- Check payment status after async operations
- Synchronize payment state with your database
- Poll for status updates when webhooks are unavailable
- Verify payment details before subsequent operations

## Request: PaymentServiceGetRequest

```protobuf
message PaymentServiceGetRequest {
  string payment_id = 1;           // Required: Payment ID to retrieve
  Connector connector = 2;         // Optional: Force specific connector lookup
}
```

### Key Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `payment_id` | string | Yes | Payment ID from authorization |
| `connector` | Connector | No | Specific connector to query |

## Response: PaymentServiceGetResponse

```protobuf
message PaymentServiceGetResponse {
  Payment payment = 1;
  repeated Capture captures = 2;   // All captures for this payment
  repeated Refund refunds = 3;     // All refunds for this payment
}
```

### Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `payment` | Payment | Current payment status and details |
| `captures` | Capture[] | List of all captures for this payment |
| `refunds` | Refund[] | List of all refunds for this payment |

## Example

### Request

```json
{
  "payment_id": "pay_abc123xyz"
}
```

### Response

```json
{
  "payment": {
    "id": "pay_abc123xyz",
    "status": "CAPTURED",
    "amount": {
      "currency": "USD",
      "amount": 1000
    },
    "connector": "STRIPE",
    "created_at": "2026-03-03T10:30:00Z"
  },
  "captures": [
    {
      "id": "cap_def456uvw",
      "status": "SUCCESS",
      "amount": {
        "currency": "USD",
        "amount": 1000
      }
    }
  ],
  "refunds": []
}
```

## Payment Statuses

| Status | Description |
|--------|-------------|
| `PENDING` | Payment is being processed |
| `AUTHORIZED` | Funds reserved, awaiting capture |
| `CAPTURED` | Funds transferred to merchant |
| `VOIDED` | Authorization cancelled |
| `FAILED` | Payment failed |
| `REFUNDED` | Fully refunded |
| `PARTIALLY_REFUNDED` | Partially refunded |

## Polling Strategy

```
Attempt 1: Immediately after authorize
Attempt 2: + 5 seconds
Attempt 3: + 10 seconds
Attempt 4: + 30 seconds
Maximum: Stop after 5 minutes, rely on webhooks
```

## Error Cases

| Error Code | Cause | Resolution |
|------------|-------|------------|
| `PAYMENT_NOT_FOUND` | Invalid payment ID | Check payment ID |
| `CONNECTOR_ERROR` | Connector API failure | Retry with backoff |

## Related RPCs

- [Authorize](./authorize.md) - Creates the payment to retrieve
- [Capture](./capture.md) - Changes payment status to CAPTURED
