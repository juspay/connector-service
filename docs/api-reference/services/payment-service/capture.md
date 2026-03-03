# Capture RPC

---
title: Capture
description: Finalize an authorized payment transaction - transfers reserved funds to merchant account
last_updated: 2026-03-03
generated_from: backend/grpc-api-types/proto/services.proto
auto_generated: false
reviewed_by: engineering
reviewed_at: 2026-03-03
approved: true
---

## Overview

The `Capture` RPC finalizes an authorized payment by transferring the reserved funds from the customer's account to the merchant's account.

## Purpose

- Complete the payment lifecycle after authorization
- Transfer funds from customer to merchant
- Support partial captures (capture less than authorized amount)
- Enable order fulfillment workflows

## Request: PaymentServiceCaptureRequest

```protobuf
message PaymentServiceCaptureRequest {
  string payment_id = 1;           // Required: Payment ID from authorize
  Money amount = 2;                // Required: Amount to capture (can be partial)
  string reason = 3;               // Optional: Reason for capture
  string idempotency_key = 4;      // Optional: For safe retries
}
```

### Key Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `payment_id` | string | Yes | Payment ID from authorization response |
| `amount` | Money | Yes | Amount to capture (can be ≤ authorized amount) |
| `reason` | string | No | Reason for capture (e.g., "Order fulfillment") |
| `idempotency_key` | string | No | Unique key for safe retries |

## Response: PaymentServiceCaptureResponse

```protobuf
message PaymentServiceCaptureResponse {
  Capture capture = 1;
  Payment payment = 2;
}
```

### Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `capture` | Capture | Capture details including ID and status |
| `payment` | Payment | Updated payment with new status |

## Example

### Request

```json
{
  "payment_id": "pay_abc123xyz",
  "amount": {
    "currency": "USD",
    "amount": 1000
  },
  "reason": "Order fulfillment"
}
```

### Response

```json
{
  "capture": {
    "id": "cap_def456uvw",
    "status": "SUCCESS",
    "amount": {
      "currency": "USD",
      "amount": 1000
    }
  },
  "payment": {
    "id": "pay_abc123xyz",
    "status": "CAPTURED"
  }
}
```

## Partial Capture

Capture less than the authorized amount:

```json
{
  "payment_id": "pay_abc123xyz",
  "amount": {
    "currency": "USD",
    "amount": 800  // $8.00 of $10.00 authorized
  },
  "reason": "Partial fulfillment"
}
```

Remaining authorized amount can be captured later or voided.

## Error Cases

| Error Code | Cause | Resolution |
|------------|-------|------------|
| `PAYMENT_NOT_FOUND` | Invalid payment ID | Check payment ID |
| `PAYMENT_NOT_AUTHORIZED` | Payment not in authorized state | Check payment status |
| `CAPTURE_AMOUNT_EXCEEDED` | Capture > authorized amount | Reduce capture amount |
| `AUTHORIZATION_EXPIRED` | Auth too old | Re-authorize payment |

## Related RPCs

- [Authorize](./authorize.md) - First step: authorize payment
- [Void](./void.md) - Cancel authorization instead of capturing
- [Reverse](./reverse.md) - Reverse after capture (pre-settlement)
