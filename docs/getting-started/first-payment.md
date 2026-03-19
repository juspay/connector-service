# First Payment

This guide walks you through making your first payment using the Universal Connector Service (UCS).

## Prerequisites

Before you begin, ensure you have:

- Completed the [installation](./installation.md)
- Set up your connector credentials (Stripe, Adyen, etc.)
- Understanding of basic UCS [concepts](./concepts.md)

## Overview

In this tutorial, you will:

1. Create a payment order
2. Authorize the payment
3. Handle potential errors with user-friendly messages
4. Capture the payment

## Step 1: Create a Payment Order

First, create a payment order that represents the transaction:

```rust
use ucs::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the UCS client
    let client = UcsClient::new(Config::from_env()?)?;

    // Create a payment order
    let order = client
        .payment_service()
        .create_order(CreateOrderRequest {
            amount: Amount {
                value: 1000,  // $10.00 in cents
                currency: Currency::USD,
            },
            merchant_reference: "order-12345".to_string(),
            description: Some("Test payment".to_string()),
            ..Default::default()
        })
        .await?;

    println!("Created order: {}", order.id);
    Ok(())
}
```

## Step 2: Authorize the Payment

Authorize the payment using a test card:

```rust
use ucs::types::payment_method::{Card, CardBrand};

let authorize_response = client
    .payment_service()
    .authorize(AuthorizeRequest {
        order_id: order.id.clone(),
        payment_method: PaymentMethod::Card(Card {
            number: "4242424242424242".to_string(), // Test card
            expiry_month: 12,
            expiry_year: 2027,
            cvv: "123".to_string(),
            brand: Some(CardBrand::Visa),
            ..Default::default()
        }),
        ..Default::default()
    })
    .await?;

println!("Authorization status: {:?}", authorize_response.status);
```

## Step 3: Error Handling

UCS provides detailed, actionable error messages. Here's how to handle common errors:

```rust
match client.payment_service().authorize(request).await {
    Ok(response) => {
        println!("Payment authorized: {}", response.id);
    }
    Err(UcsError::ValidationError { field, message, suggestion }) => {
        eprintln!("Validation error in '{}': {}", field, message);
        eprintln!("Suggestion: {}", suggestion);
        // Handle validation error (e.g., invalid card number)
    }
    Err(UcsError::ConnectorError { connector, code, message, connector_docs }) => {
        eprintln!("{} error ({}): {}", connector, code, message);
        eprintln!("See: {}", connector_docs);
        // Handle connector-specific error
    }
    Err(UcsError::PaymentDeclined { reason, retryable }) => {
        eprintln!("Payment declined: {}", reason);
        if retryable {
            eprintln!("You may retry with different payment method");
        }
        // Handle declined payment
    }
    Err(e) => {
        eprintln!("Unexpected error: {}", e);
    }
}
```

### Common Error Scenarios

#### Invalid Card Number

```
Error: Validation failed for field 'card.number'
Message: Card number failed Luhn check
Suggestion: Verify the card number is entered correctly. Test with 4242424242424242 for Visa.
Stripe docs: https://stripe.com/docs/testing#cards
```

#### Expired Card

```
Error: Payment declined
Message: Your card has expired
Suggestion: Check the expiry date or use a different card
Retryable: true
```

#### Insufficient Funds

```
Error: Payment declined
Message: Insufficient funds
Suggestion: Use a different payment method or contact your bank
Retryable: true
```

## Step 4: Capture the Payment

Once authorized, capture the payment to complete the transaction:

```rust
let capture_response = client
    .payment_service()
    .capture(CaptureRequest {
        payment_id: authorize_response.id,
        amount: Some(Amount {
            value: 1000,
            currency: Currency::USD,
        }), // Partial capture supported
        ..Default::default()
    })
    .await?;

println!("Captured: {:?}", capture_response.status);
```

## Complete Example

Here's the complete flow in one example:

```rust
use ucs::prelude::*;

async fn process_payment() -> Result<Payment, UcsError> {
    let client = UcsClient::new(Config::from_env()?)?;

    // 1. Create order
    let order = client
        .payment_service()
        .create_order(CreateOrderRequest {
            amount: Amount {
                value: 1000,
                currency: Currency::USD,
            },
            merchant_reference: "order-12345".to_string(),
            ..Default::default()
        })
        .await?;

    // 2. Authorize
    let auth = client
        .payment_service()
        .authorize(AuthorizeRequest {
            order_id: order.id,
            payment_method: PaymentMethod::Card(Card {
                number: "4242424242424242".to_string(),
                expiry_month: 12,
                expiry_year: 2027,
                cvv: "123".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        })
        .await?;

    // 3. Capture
    let payment = client
        .payment_service()
        .capture(CaptureRequest {
            payment_id: auth.id,
            ..Default::default()
        })
        .await?;

    Ok(payment)
}
```

## Next Steps

- Learn about [extending to more flows](./extending-to-more-flows.md)
- Explore [refund operations](../api-reference/services/refund-service/README.md)
- Set up [recurring payments](../api-reference/services/recurring-payment-service/README.md)
- Read about [error handling](../architecture/error-handling.md) in depth

## Language Examples

### Node.js

```typescript
import { UcsClient } from '@juspay/ucs-node';

const client = new UcsClient({
  apiKey: process.env.UCS_API_KEY,
  environment: 'sandbox'
});

const order = await client.payments.createOrder({
  amount: { value: 1000, currency: 'USD' },
  merchantReference: 'order-12345'
});

const payment = await client.payments.authorize({
  orderId: order.id,
  paymentMethod: {
    type: 'card',
    card: {
      number: '4242424242424242',
      expiryMonth: 12,
      expiryYear: 2027,
      cvv: '123'
    }
  }
});
```

### Python

```python
from ucs import UcsClient

client = UcsClient(api_key=os.getenv("UCS_API_KEY"))

order = client.payments.create_order(
    amount={"value": 1000, "currency": "USD"},
    merchant_reference="order-12345"
)

payment = client.payments.authorize(
    order_id=order.id,
    payment_method={
        "type": "card",
        "card": {
            "number": "4242424242424242",
            "expiry_month": 12,
            "expiry_year": 2027,
            "cvv": "123"
        }
    }
)
```
