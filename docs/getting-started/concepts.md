# Core Concepts

---
title: Core Concepts
description: Essential abstractions and concepts for understanding Connector Service
last_updated: 2026-03-03
generated_from: N/A
auto_generated: false
reviewed_by: tech-writer
reviewed_at: 2026-03-03
approved: true
---

## Overview

This guide explains the core concepts and abstractions that power Connector Service. Understanding these will help you design robust payment integrations.

## Connector Abstraction

### What is a Connector?

A **connector** is a payment processor integrated into Connector Service. Examples include Stripe, Adyen, PayPal, and 100+ others.

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────┐
│  Your App   │────▶│  UCS (Abstract)  │────▶│  Connector  │
│             │◀────│  One API         │◀────│  (Concrete) │
└─────────────┘     └──────────────────┘     └─────────────┘
```

### Unified Data Model

Instead of learning each connector's API, you use Connector Service's unified types:

| Connector Service | Stripe Equivalent | Adyen Equivalent |
|-------------------|-------------------|------------------|
| `payment.id` | `payment_intent.id` | `pspReference` |
| `payment.status` | `status` | `resultCode` |
| `amount.currency` | `currency` | `currency` |

### Connector Selection

Specify the connector in your requests:

```javascript
{
  "connector": "STRIPE",  // or "ADYEN", "PAYPAL", etc.
  // ... rest of request
}
```

## Payment Lifecycle

### Standard Flow (Authorization + Capture)

```
         ┌─────────────┐
         │    START    │
         └──────┬──────┘
                │
                ▼
         ┌─────────────┐
         │  AUTHORIZE  │◀── Reserves funds
         └──────┬──────┘
                │
        ┌───────┴───────┐
        │               │
        ▼               ▼
   ┌─────────┐     ┌─────────┐
   │  VOID   │     │ CAPTURE │◀── Transfers funds
   └─────────┘     └────┬────┘
                        │
                        ▼
                   ┌─────────┐
                   │ REFUND  │◀── Returns funds
                   └─────────┘
```

### One-Step Flow (Automatic Capture)

Some use cases require immediate capture:

```javascript
{
  "capture_method": "AUTOMATIC",  // vs "MANUAL"
  // Authorization automatically captures
}
```

### Payment Statuses

| Status | Meaning | Next Actions |
|--------|---------|--------------|
| `PENDING` | Awaiting connector response | Wait for webhook or poll |
| `AUTHORIZED` | Funds reserved | Capture, Void, or wait |
| `CAPTURED` | Funds transferred | Refund available |
| `VOIDED` | Authorization cancelled | None |
| `FAILED` | Payment failed | Retry with different method |

## 3D Secure (3DS) Authentication

### What is 3DS?

3D Secure adds an extra authentication layer for card payments, reducing fraud liability.

### Frictionless vs Challenge

| Type | User Experience | When Used |
|------|-----------------|-----------|
| Frictionless | No interaction | Low-risk transactions |
| Challenge | OTP/password required | High-risk transactions |

### 3DS Flow

```
1. PRE_AUTHENTICATE ──▶ Get 3DS requirements
         │
         ▼
2. AUTHENTICATE ──────▶ Present challenge (if needed)
         │
         ▼
3. POST_AUTHENTICATE ─▶ Validate result
         │
         ▼
4. AUTHORIZE ─────────▶ Proceed with payment
```

## Recurring Payments (Mandates)

### Mandate Types

| Type | Description | Use Case |
|------|-------------|----------|
| `ON_DEMAND` | Charge anytime with consent | Ride-sharing, rentals |
| `SCHEDULED` | Fixed schedule charges | Subscriptions, utilities |

### Mandate Lifecycle

```
SETUP ──▶ ACTIVE ──▶ CHARGED ──▶ REVOKED
   │         │          │
   ▼         ▼          ▼
Consent  Stored     Payment   Cancellation
```

## Webhooks

### Purpose

Webhooks provide real-time notifications of payment state changes without polling.

### Webhook Types

| Event Type | Trigger | Payload |
|------------|---------|---------|
| `payment.authorized` | Authorization completes | Payment details |
| `payment.captured` | Capture completes | Capture details |
| `refund.succeeded` | Refund processed | Refund details |
| `dispute.created` | Chargeback filed | Dispute details |

### Webhook Security

```
┌─────────────────┐     ┌─────────────────┐
│  Connector      │────▶│  Your Webhook   │
│  Service        │     │  Endpoint       │
│                 │     │                 │
│  + Signature    │     │  Verify Sig     │
│  + Timestamp    │     │  Process Event  │
└─────────────────┘     └─────────────────┘
```

Always verify webhook signatures to ensure authenticity.

## Error Handling

### Error Categories

| Category | HTTP Code | Resolution |
|----------|-----------|------------|
| Validation | 400 | Fix request payload |
| Authentication | 401 | Check API credentials |
| Authorization | 403 | Verify permissions |
| Not Found | 404 | Check resource IDs |
| Connector Error | 422 | Check connector-specific error |

### Idempotency

Use idempotency keys to safely retry requests:

```javascript
{
  "idempotency_key": "unique-key-123",
  // ... request payload
}
```

## Next Steps

- [SDKs](../sdks/) - Language-specific implementation guides
- [API Reference](../api-reference/) - Complete API documentation
- [Guides](../guides/) - Step-by-step how-to articles
