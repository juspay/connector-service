# Void RPC

---
title: Void
description: Cancel an authorized payment before capture - releases held funds back to customer
last_updated: 2026-03-03
generated_from: backend/grpc-api-types/proto/services.proto
auto_generated: false
reviewed_by: engineering
reviewed_at: 2026-03-03
approved: true
---

## Overview

The `Void` RPC cancels an authorized payment that has not yet been captured, releasing the held funds back to the customer's payment method.

## Purpose

- Cancel an order before fulfillment
- Release held funds when customer cancels
- Reverse an authorization without capturing
- Clean up abandoned transactions

## Request: PaymentServiceVoidRequest

```protobuf
message PaymentServiceVoidRequest {
  string payment_id = 1;           // Required: Payment ID to void
  string reason = 2;               // Optional: Reason for void
  string idempotency_key = 3;      // Optional: For safe retries
}
```

### Key Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `payment_id` | string | Yes | Payment ID from authorization |
| `reason` | string | No | Reason for void (e.g., "Customer cancelled") |
| `idempotency_key` | string | No | Unique key for safe retries |

## Response: PaymentServiceVoidResponse

```protobuf
message PaymentServiceVoidResponse {
  Void void = 1;
  Payment payment = 2;
}
```

### Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `void` | Void | Void details including ID and status |
| `payment` | Payment | Updated payment with VOIDED status |

## Example

### Request

```json
{
  "payment_id": "pay_abc123xyz",
  "reason": "Customer cancelled order"
}
```

### Response

```json
{
  "void": {
    "id": "void_ghi789rst",
    "status": "SUCCESS",
    "reason": "Customer cancelled order"
  },
  "payment": {
    "id": "pay_abc123xyz",
    "status": "VOIDED"
  }
}
```

## When to Use Void vs Reverse vs Refund

| RPC | When to Use | Funds State |
|-----|-------------|-------------|
| **Void** | Before capture | Releases authorization hold |
| **Reverse** | After capture, before settlement | Reverses captured funds |
| **Refund** | After settlement | Returns settled funds |

## Error Cases

| Error Code | Cause | Resolution |
|------------|-------|------------|
| `PAYMENT_NOT_FOUND` | Invalid payment ID | Check payment ID |
| `PAYMENT_NOT_AUTHORIZED` | Already captured/refunded | Check payment status |
| `VOID_NOT_SUPPORTED` | Connector doesn't support void | Use refund instead |

## Related RPCs

- [Authorize](./authorize.md) - Creates the authorization to void
- [Capture](./capture.md) - Alternative to void (completes payment)
- [Reverse](./reverse.md) - Use after capture, before settlement
