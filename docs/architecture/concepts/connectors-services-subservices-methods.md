# Services and Methods

Prism organizes payment operations into services that reflect how payments actually work in the real world. Some operations are independent. Others are follow-on actions that only make sense after a payment exists.

## Service Hierarchy

```
PaymentService (core)
├── authorize() — Start a payment, hold funds
├── capture() — Complete the payment, transfer funds
├── void() — Cancel an authorized payment
├── refund() — Return captured funds (calls RefundService)
└── sync() — Get latest status from processor

RefundService (sub-service)
├── refund() — Create a refund for a captured payment
└── sync() — Check refund status

RecurringPaymentService (sub-service)
├── charge() — Charge a stored payment method
└── revoke() — Cancel a recurring authorization

DisputeService (sub-service)
├── accept() — Accept a chargeback
├── defend() — Challenge a dispute
└── submit_evidence() — Upload dispute evidence
```

## Why Sub-Services Exist

A refund isn't a standalone operation. It requires a payment that was already captured. A recurring charge requires a payment method setup. A dispute arises from an existing transaction.

Prism models this dependency explicitly:

| Operation | Requires | Provided By |
|-----------|----------|-------------|
| `RefundService.refund()` | A captured payment | `PaymentService.capture()` |
| `RecurringPaymentService.charge()` | A stored payment method | `PaymentService.setup_mandate()` |
| `DisputeService.accept()` | A disputed transaction | Payment processor notification |

This hierarchy prevents invalid state transitions. You can't refund a payment that was never captured. The service structure enforces this at the API level.

## PaymentService: The Core

PaymentService handles the primary payment lifecycle:

```javascript
// 1. Authorize - hold funds
const auth = await client.payments.authorize({
    amount: { minorAmount: 1000, currency: 'USD' },
    paymentMethod: { card: { cardNumber: '4242424242424242', ... } },
    captureMethod: CaptureMethod.MANUAL  // Don't capture yet
});
// Returns: payment_id, status: AUTHORIZED

// 2. Capture - complete the payment
const capture = await client.payments.capture({
    paymentId: auth.paymentId,
    amount: { minorAmount: 1000, currency: 'USD' }
});
// Returns: status: CAPTURED

// 3. Refund - return funds (delegates to RefundService)
const refund = await client.payments.refund({
    paymentId: capture.paymentId,
    amount: { minorAmount: 1000, currency: 'USD' }
});
// Returns: refund_id, status: PENDING
```

## RefundService: Follow-On Operations

RefundService operates on captured payments. You can call it directly or through PaymentService.refund():

```javascript
// Option 1: Through PaymentService (convenience)
const refund = await client.payments.refund({ paymentId: 'pay_123', ... });

// Option 2: Direct RefundService call
const refund = await client.refunds.create({
    paymentId: 'pay_123',
    amount: { minorAmount: 500, currency: 'USD' }
});
```

Both approaches create the same refund. The PaymentService method is a convenience wrapper.

RefundService also handles sync operations to check refund status:

```javascript
const status = await client.refunds.sync({ refundId: 'ref_456' });
// Returns: status (SUCCEEDED, FAILED, PENDING)
```

## RecurringPaymentService: Stored Payment Operations

RecurringPaymentService manages operations on stored payment methods:

```javascript
// First, set up a mandate (stores the payment method)
const mandate = await client.payments.setupMandate({
    paymentMethod: { card: { ... } },
    customerId: 'cus_789'
});

// Later, charge the stored method
const charge = await client.recurringPayments.charge({
    mandateId: mandate.mandateId,
    amount: { minorAmount: 500, currency: 'USD' }
});

// When done, revoke the mandate
await client.recurringPayments.revoke({
    mandateId: mandate.mandateId
});
```

## DisputeService: Chargeback Management

DisputeService handles chargebacks and disputes:

```javascript
// Accept the dispute (refund the customer)
await client.disputes.accept({ disputeId: 'disp_abc' });

// Or defend the dispute
await client.disputes.defend({ disputeId: 'disp_abc' });

// Submit evidence
await client.disputes.submitEvidence({
    disputeId: 'disp_abc',
    evidence: { shippingReceipt: '...', customerCommunication: '...' }
});
```

## Service Reference

| Service | Primary Operations | Documentation |
|---------|-------------------|---------------|
| PaymentService | authorize, capture, void, refund, sync | [Payment Service](../../api-reference/services/payment-service/) |
| RefundService | refund, sync | [Refund Service](../../api-reference/services/refund-service/) |
| RecurringPaymentService | charge, revoke | [Recurring Payment Service](../../api-reference/services/recurring-payment-service/) |
| DisputeService | accept, defend, submit_evidence | [Dispute Service](../../api-reference/services/dispute-service/) |
| EventService | handle | [Event Service](../../api-reference/services/event-service/) |
| CustomerService | create | [Customer Service](../../api-reference/services/customer-service/) |

## Method Naming Conventions

Methods follow verb-noun patterns that describe the action:

- **authorize**: Start authorization, hold funds
- **capture**: Complete authorization, transfer funds
- **void**: Cancel authorization, release funds
- **refund**: Return captured funds
- **sync**: Synchronize status with processor
- **setup_mandate**: Create recurring payment authorization
- **charge**: Execute payment using stored method

This naming is consistent across all connectors. Stripe calls it "capture." Adyen calls it "capture." Prism calls it `capture()` everywhere.
