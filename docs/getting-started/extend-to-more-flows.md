# Extending to More Flows

YOu have implemmented the basic plumbing for routing payment processor agnostic APIs. All methods work the same way with the single interface regardless of which payment processor you use. That's the power you get with the library.

Beyond the basic authorization and capture, the library handles complex payment scenarios in a processor agnostic manner. This includes recurring payments, incremental authorization, void, reverse, refund and more.

## Payment Flows Overview

Below are some sample use cases to try out quickly, followed by some real world scenarios.

| Flow | Use Case | Key Operations |
|------|----------|----------------|
| **Authorize + Capture** | Standard e-commerce | [`authorize`](../../api-reference/services/payment-service/authorize.md), [`capture`](../../api-reference/services/payment-service/capture.md) |
| **Authorize + Void** | Cancel pending order | [`authorize`](../../api-reference/services/payment-service/authorize.md), [`void`](../../api-reference/services/payment-service/void.md) |
| **Automatic Capture** | Digital goods, immediate charge | [`authorize`](../../api-reference/services/payment-service/authorize.md) with `AUTOMATIC` |
| **Incremental Authorization** | Hotel check-in, car rental | [`authorize`](../../api-reference/services/payment-service/authorize.md), [`incrementalAuthorization`](../../api-reference/services/payment-service/incremental-authorization.md) |
| **Partial Capture** | Multi-shipment orders | [`capture`](../../api-reference/services/payment-service/capture.md) with partial amount |
| **Refunds** | Customer returns | [`refund`](../../api-reference/services/payment-service/refund.md) |
| **Reucrring Payments** | SaaS billing and rer | [`setupMandate`](../../api-reference/services/payment-service/setup-recurring.md), [`charge`](../../api-reference/services/recurring-payment-service/charge.md) |


## Incremental Authorization

Hotels and car rentals need to increase authorization amounts after the initial charge:

```javascript
// 1. Initial authorization: $100 hold
const auth = await client.payments.authorize({
    amount: { minorAmount: 10000, currency: Currency.USD },
    captureMethod: CaptureMethod.MANUAL
});

// 2. Customer adds room service: increase hold to $150
const incremental = await client.payments.incrementalAuthorization({
    paymentId: auth.paymentId,
    additionalAmount: { minorAmount: 5000, currency: Currency.USD }
});

// 3. At checkout: capture final amount
await client.payments.capture({
    paymentId: auth.paymentId,
    amount: { minorAmount: 14750, currency: Currency.USD }  // Actual amount
});
```

See: [`incrementalAuthorization` API Reference](../../api-reference/services/payment-service/incremental-authorization.md)

## Subscription / Recurring Payments

Store a payment method and charge it later:

```javascript
// 1. Set up mandate (store payment method)
const mandate = await client.payments.setupMandate({
    customerId: 'cus_xyz789',
    paymentMethod: { card: { ... } }
});

// 2. Charge the stored method monthly
const charge = await client.recurringPayments.charge({
    mandateId: mandate.mandateId,
    amount: { minorAmount: 2900, currency: Currency.USD }
});


See: [`setupMandate`](../../api-reference/services/payment-service/setup-recurring.md), [`charge`](../../api-reference/services/recurring-payment-service/charge.md), [`revoke`](../../api-reference/services/recurring-payment-service/revoke.md)


## Partial Capture

Capture less than authorized amount (multi-shipment orders):

```javascript
// Authorized $100
const auth = await client.payments.authorize({
    amount: { minorAmount: 10000, currency: Currency.USD },
    captureMethod: CaptureMethod.MANUAL
});

// First shipment: capture $40
await client.payments.capture({
    paymentId: auth.paymentId,
    amount: { minorAmount: 4000, currency: Currency.USD }  // Partial
});

// Second shipment: capture remaining $60
await client.payments.capture({
    paymentId: auth.paymentId,
    amount: { minorAmount: 6000, currency: Currency.USD }
});
```

See: [`capture`](../../api-reference/services/payment-service/capture.md)

## Void (Cancel Authorization)

Release held funds without charging:

```javascript
// Customer cancels order before shipment
await client.payments.void({
    paymentId: auth.paymentId,
    reason: 'Customer cancelled'
});
// Funds released immediately
```

See: [`void`](../../api-reference/services/payment-service/void.md)

## Reverse (Refund Without Reference)

Refund when you only have the connector transaction ID:

```javascript
await client.payments.reverse({
    connectorTransactionId: 'pi_3MqSCR2eZvKYlo2C1',
    amount: { minorAmount: 10000, currency: Currency.USD }
});
```

See: [`reverse`](../../api-reference/services/payment-service/reverse.md)

## Webhook Handling

Process events from payment processors:

```javascript
// Express route for webhooks
app.post('/webhooks', async (req, res) => {
    const event = await client.events.handle({
        payload: req.body,
        signature: req.headers['stripe-signature'],
        connector: Connector.STRIPE
    });
    
    switch (event.type) {
        case 'payment.captured':
            await fulfillOrder(event.paymentId);
            break;
        case 'payment.failed':
            await notifyCustomer(event.paymentId);
            break;
        case 'refund.completed':
            await updateInventory(event.refundId);
            break;
    }
    
    res.sendStatus(200);
});
```

See: [`handle`](../../api-reference/services/event-service/handle.md)

## Dispute Handling

When customers dispute charges:

```javascript
// Accept the dispute (refund immediately)
await client.disputes.accept({
    disputeId: 'dp_xyz789'
});

// Or defend with evidence
await client.disputes.defend({
    disputeId: 'dp_xyz789'
});

await client.disputes.submitEvidence({
    disputeId: 'dp_xyz789',
    evidence: {
        productDescription: 'Premium Widget',
        customerCommunication: emailThread,
        shippingReceipt: trackingNumber
    }
});
```

See: [`accept`](../../api-reference/services/dispute-service/accept.md), [`defend`](../../api-reference/services/dispute-service/defend.md), [`submitEvidence`](../../api-reference/services/dispute-service/submit-evidence.md)


## Next Steps

- Browse the full [API Reference](../../api-reference/)
- Jump to [SDK-specific guides](../../sdks/)