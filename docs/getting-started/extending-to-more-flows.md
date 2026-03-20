# Extending to More Flows

After completing your [first payment](./first-payment.md), this guide shows you how to implement additional payment flows and capabilities.

## Supported Payment Flows

UCS supports a comprehensive set of payment operations:

| Flow | Description | Use Case |
|------|-------------|----------|
| **Authorize** | Reserve funds on customer's card | Immediate authorization |
| **Capture** | Collect authorized funds | Complete the transaction |
| **Authorize + Capture** | Single-step payment | Standard one-time payment |
| **Void** | Cancel authorized but not captured payment | Order cancellation |
| **Refund** | Return funds to customer | Post-purchase returns |
| **Incremental Authorization** | Increase authorized amount | Tips, add-ons |
| **Recurring** | Stored credential payments | Subscriptions |
| **Verify** | Validate card without charging | Account verification |

## Refund Flow

Process a refund for a completed payment:

```rust
use ucs::prelude::*;

async fn refund_payment(
    client: &UcsClient,
    payment_id: String
) -> Result<Refund, UcsError> {
    let refund = client
        .refund_service()
        .create(CreateRefundRequest {
            payment_id,
            amount: Amount {
                value: 1000,
                currency: Currency::USD,
            },
            reason: Some("Customer request".to_string()),
            ..Default::default()
        })
        .await?;

    println!("Refund created: {} - {:?}", refund.id, refund.status);
    Ok(refund)
}
```

### Partial Refunds

Refund a portion of the original amount:

```rust
let partial_refund = client
    .refund_service()
    .create(CreateRefundRequest {
        payment_id: "pay_123".to_string(),
        amount: Amount {
            value: 500,  // Refund $5.00 of $10.00
            currency: Currency::USD,
        },
        ..Default::default()
    })
    .await?;
```

## Void Flow

Cancel an authorized but not yet captured payment:

```rust
async fn void_payment(
    client: &UcsClient,
    payment_id: String
) -> Result<VoidResponse, UcsError> {
    let void_response = client
        .payment_service()
        .void(VoidRequest {
            payment_id,
            reason: Some("Order cancelled by customer".to_string()),
            ..Default::default()
        })
        .await?;

    println!("Payment voided: {:?}", void_response.status);
    Ok(void_response)
}
```

## Incremental Authorization

Increase the authorized amount (useful for tips, add-ons):

```rust
async fn add_tip(
    client: &UcsClient,
    payment_id: String
) -> Result<Authorization, UcsError> {
    let incremental = client
        .payment_service()
        .incremental_authorization(IncrementalAuthorizationRequest {
            payment_id,
            additional_amount: Amount {
                value: 200,  // Add $2.00 tip
                currency: Currency::USD,
            },
            reason: Some("Gratuity".to_string()),
            ..Default::default()
        })
        .await?;

    println!("New authorized amount: {}", incremental.authorized_amount);
    Ok(incremental)
}
```

## Recurring Payments

Set up and process recurring payments:

### Step 1: Setup Recurring

```rust
async fn setup_recurring(
    client: &UcsClient,
    payment_method_id: String
) -> Result<RecurringSetup, UcsError> {
    let setup = client
        .recurring_payment_service()
        .setup_recurring(SetupRecurringRequest {
            payment_method_id,
            merchant_reference: "subscription-001".to_string(),
            recurring_type: RecurringType::Unscheduled,
            ..Default::default()
        })
        .await?;

    println!("Recurring setup: {}", setup.id);
    Ok(setup)
}
```

### Step 2: Charge Recurring

```rust
async fn charge_recurring(
    client: &UcsClient,
    recurring_id: String
) -> Result<Payment, UcsError> {
    let payment = client
        .recurring_payment_service()
        .charge(ChargeRecurringRequest {
            recurring_id,
            amount: Amount {
                value: 999,  // $9.99 monthly charge
                currency: Currency::USD,
            },
            merchant_reference: "charge-001".to_string(),
            ..Default::default()
        })
        .await?;

    println!("Recurring charge: {} - {:?}", payment.id, payment.status);
    Ok(payment)
}
```

### Step 3: Revoke Recurring

```rust
async fn revoke_recurring(
    client: &UcsClient,
    recurring_id: String
) -> Result<(), UcsError> {
    client
        .recurring_payment_service()
        .revoke(RevokeRecurringRequest {
            recurring_id,
            reason: Some("Customer cancelled subscription".to_string()),
            ..Default::default()
        })
        .await?;

    println!("Recurring authorization revoked");
    Ok(())
}
```

## 3D Secure Authentication

Handle 3D Secure authentication flows:

```rust
async fn authenticate_with_3ds(
    client: &UcsClient,
    order_id: String,
    card: Card
) -> Result<AuthenticationResponse, UcsError> {
    // Step 1: Pre-authenticate
    let pre_auth = client
        .payment_method_authentication_service()
        .pre_authenticate(PreAuthenticateRequest {
            order_id: order_id.clone(),
            payment_method: PaymentMethod::Card(card),
            ..Default::default()
        })
        .await?;

    if pre_auth.requires_redirect {
        // Redirect customer to 3DS page
        println!("Redirect to: {}", pre_auth.redirect_url.unwrap());
        // ... handle redirect flow ...

        // Step 2: Post-authenticate after redirect
        let post_auth = client
            .payment_method_authentication_service()
            .post_authenticate(PostAuthenticateRequest {
                authentication_id: pre_auth.id,
                redirect_response: RedirectResponse {
                    // ... parse from return URL
                },
                ..Default::default()
            })
            .await?;

        Ok(post_auth)
    } else {
        // Frictionless flow - no redirect needed
        Ok(AuthenticationResponse {
            status: AuthenticationStatus::Success,
            ..pre_auth
        })
    }
}
```

## Dispute Handling

Handle chargebacks and disputes:

```rust
async fn handle_dispute(
    client: &UcsClient,
    dispute_id: String
) -> Result<(), UcsError> {
    // Get dispute details
    let dispute = client
        .dispute_service()
        .get(GetDisputeRequest {
            dispute_id: dispute_id.clone(),
            ..Default::default()
        })
        .await?;

    match dispute.status {
        DisputeStatus::NeedsResponse => {
            // Submit evidence
            client
                .dispute_service()
                .submit_evidence(SubmitEvidenceRequest {
                    dispute_id,
                    evidence: Evidence {
                        customer_communication: Some("email_thread.pdf".to_string()),
                        delivery_confirmation: Some("tracking_12345".to_string()),
                        ..Default::default()
                    },
                    ..Default::default()
                })
                .await?;
        }
        DisputeStatus::Won => {
            println!("Dispute won!");
        }
        DisputeStatus::Lost => {
            println!("Dispute lost - funds debited");
        }
        _ => {}
    }

    Ok(())
}
```

## Webhook Handling

Process webhooks for asynchronous events:

```rust
use ucs::webhook::WebhookVerifier;

async fn handle_webhook(
    payload: &[u8],
    signature: &str,
    secret: &str
) -> Result<(), UcsError> {
    // Verify webhook signature
    let verifier = WebhookVerifier::new(secret);
    verifier.verify(payload, signature)?;

    // Parse the event
    let event: UcsEvent = serde_json::from_slice(payload)?;

    match event.event_type {
        EventType::PaymentAuthorized { payment_id, .. } => {
            println!("Payment authorized: {}", payment_id);
            // Update order status
        }
        EventType::PaymentCaptured { payment_id, .. } => {
            println!("Payment captured: {}", payment_id);
            // Fulfill order
        }
        EventType::RefundCompleted { refund_id, .. } => {
            println!("Refund completed: {}", refund_id);
            // Update inventory
        }
        EventType::DisputeOpened { dispute_id, .. } => {
            println!("Dispute opened: {}", dispute_id);
            // Alert support team
        }
        _ => {}
    }

    Ok(())
}
```

## Flow Comparison

```
Standard Payment:
  Create Order → Authorize → Capture

Two-Step (Hold & Charge Later):
  Create Order → Authorize → (delay) → Capture

With Cancellation:
  Create Order → Authorize → Void

Refund:
  Create Order → Authorize → Capture → Refund

Recurring:
  Setup Recurring → (schedule) → Charge → Charge → Revoke
```

## Next Steps

- Explore the [API Reference](../api-reference/services/payment-service/README.md)
- Learn about [error handling](../architecture/error-handling.md)
- Read the [architecture overview](../architecture/overview.md)
- Review [connector-specific guides](../connectors/README.md)
