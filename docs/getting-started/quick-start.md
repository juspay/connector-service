# Quick Start

---
title: Quick Start
description: 5-minute integration guide - process your first payment with Connector Service
last_updated: 2026-03-03
generated_from: N/A
auto_generated: false
reviewed_by: tech-writer
reviewed_at: 2026-03-03
approved: true
---

## Overview

This guide walks you through processing your first payment in under 5 minutes. You'll authorize, capture, and refund a test payment.

## Prerequisites

- [SDK installed](./installation.md) and configured
- Test credentials from your target connector (Stripe, Adyen, etc.)
- Environment variables set (`UCS_API_KEY`, `UCS_MERCHANT_ID`)

## Step 1: Authorize a Payment

Authorization reserves funds on the customer's payment method without capturing them.

```javascript
const { PaymentClient } = require('@juspay/connector-service-sdk');

const client = new PaymentClient({
  apiKey: process.env.UCS_API_KEY,
  merchantId: process.env.UCS_MERCHANT_ID
});

async function authorizePayment() {
  const response = await client.payments.authorize({
    amount: {
      currency: "USD",
      amount: 1000  // $10.00 (amount in cents)
    },
    payment_method: {
      card: {
        card_number: "4111111111111111",  // Test card
        expiry_month: "12",
        expiry_year: "2027",
        card_holder_name: "John Doe",
        cvc: "123"
      }
    },
    connector: "STRIPE",  // Or your target connector
    merchant_order_reference_id: "order-001",
    description: "Test payment"
  });

  console.log('Authorization ID:', response.payment.id);
  console.log('Status:', response.payment.status);  // AUTHORIZED

  return response.payment.id;
}
```

## Step 2: Capture the Payment

Capture finalizes the transaction and transfers funds.

```javascript
async function capturePayment(paymentId) {
  const response = await client.payments.capture({
    payment_id: paymentId,
    amount: {
      currency: "USD",
      amount: 1000  // Full capture (can be partial)
    },
    reason: "Order fulfillment"
  });

  console.log('Capture ID:', response.capture.id);
  console.log('Status:', response.capture.status);  // SUCCESS
}
```

## Step 3: Refund the Payment

Refund returns funds to the customer.

```javascript
async function refundPayment(paymentId) {
  const response = await client.payments.refund({
    payment_id: paymentId,
    refund_amount: {
      currency: "USD",
      amount: 1000  // Full refund
    },
    reason: "Customer request"
  });

  console.log('Refund ID:', response.refund.id);
  console.log('Status:', response.refund.status);  // SUCCESS
}
```

## Complete Example

```javascript
async function runQuickStart() {
  try {
    console.log('🚀 Starting quick start demo...\n');

    // Step 1: Authorize
    console.log('Step 1: Authorizing payment...');
    const paymentId = await authorizePayment();
    console.log('✅ Payment authorized\n');

    // Step 2: Capture
    console.log('Step 2: Capturing payment...');
    await capturePayment(paymentId);
    console.log('✅ Payment captured\n');

    // Step 3: Refund
    console.log('Step 3: Refunding payment...');
    await refundPayment(paymentId);
    console.log('✅ Payment refunded\n');

    console.log('🎉 Quick start complete!');
  } catch (error) {
    console.error('❌ Error:', error.message);
  }
}

runQuickStart();
```

## Expected Output

```
🚀 Starting quick start demo...

Step 1: Authorizing payment...
Authorization ID: pay_abc123xyz
Status: AUTHORIZED
✅ Payment authorized

Step 2: Capturing payment...
Capture ID: cap_def456uvw
Status: SUCCESS
✅ Payment captured

Step 3: Refunding payment...
Refund ID: ref_ghi789rst
Status: SUCCESS
✅ Payment refunded

🎉 Quick start complete!
```

## Payment Lifecycle

```
AUTHORIZE → CAPTURE → REFUND
    │          │         │
    ▼          ▼         ▼
 Funds    Funds      Funds
 Reserved Captured   Returned
```

## Test Cards

| Card Number | Brand | Result |
|-------------|-------|--------|
| 4111111111111111 | Visa | Success |
| 4000000000000002 | Visa | Decline |
| 5555555555554444 | Mastercard | Success |

## Next Steps

- [Core Concepts](./concepts.md) - Understand the full payment lifecycle
- [API Reference](../api-reference/) - Explore all available operations
- [Connectors](../connectors/) - Configure specific payment processors
