# Quick Start

Now that the library is installed, let's create your first payment order (different payment processor's use different terminology - order, intent, transaction and so on). Conceptually, it represents the user's intent to start a payment session. 

Once you implement this basic plumbing, you will be able to switch the request to any other payment processot, by changing one-line of code. 

- **If you depend on your Payment processor/ PCI vault for PCI compliance:** Lets start by creating a payment intent (order) with Stripe, which you can then use to complete the payment with Stripe.js on your frontend to collect payment details - if you are not PCI compliant.

- **If you are managing PCI compliance on your own:** You should be able to collect card data from the user and directly pass it to the payment processor. Ignore this section and directly jump to [First Payment](./first-payment.md).

## Prerequisites

- Library ([installation](./installation.md))
- Stripe test API key (get one at [stripe.com](https://stripe.com))

## Create a Payment Order

Create an order to get a `session_token` (client secret) from Stripe.

{% tabs %}

{% tab title="Node.js" %}

```javascript
const { ConnectorClient, Currency } = require('@juspay/connector-service-node');

async function main() {
    const client = new ConnectorClient({
        connectors: {
            stripe: { apiKey: process.env.STRIPE_API_KEY }
        }
    });

    const order = await client.payments.createOrder({
        amount: {
            minorAmount: 1000,  // $10.00
            currency: Currency.USD
        },
        merchantOrderId: 'order-123'
    });

    console.log('Order ID:', order.connectorOrderId);
    console.log('Client Secret:', order.sessionToken.clientSecret);
}

main().catch(console.error);
```

{% endtab %}

{% tab title="Python" %}

```python
import os
from connector_service import ConnectorClient, Currency

client = ConnectorClient(
    connectors={
        "stripe": {"api_key": os.environ["STRIPE_API_KEY"]}
    }
)

order = client.payments.create_order(
    amount={"minor_amount": 1000, "currency": Currency.USD},
    merchant_order_id="order-123"
)

print(f"Order ID: {order.connector_order_id}")
print(f"Client Secret: {order.session_token.client_secret}")
```

{% endtab %}

{% tab title="Java" %}

```java
import com.juspay.connectorservice.*;

public class QuickStart {
    public static void main(String[] args) {
        ConnectorClient client = ConnectorClient.builder()
            .connector("stripe", StripeConfig.builder()
                .apiKey(System.getenv("STRIPE_API_KEY"))
                .build())
            .build();

        CreateOrderResponse order = client.payments().createOrder(
            CreateOrderRequest.builder()
                .amount(Amount.of(1000, Currency.USD))
                .merchantOrderId("order-123")
                .build()
        );

        System.out.println("Order ID: " + order.getConnectorOrderId());
        System.out.println("Client Secret: " + order.getSessionToken().getClientSecret());
    }
}
```

{% endtab %}

{% tab title="PHP" %}

```php
<?php
require_once 'vendor/autoload.php';

use ConnectorService\ConnectorClient;
use ConnectorService\Enum\Currency;

$client = new ConnectorClient([
    'connectors' => [
        'stripe' => ['api_key' => $_ENV['STRIPE_API_KEY']]
    ]
]);

$order = $client->payments()->createOrder([
    'amount' => ['minor_amount' => 1000, 'currency' => Currency::USD],
    'merchant_order_id' => 'order-123'
]);

echo "Order ID: " . $order->getConnectorOrderId() . "\n";
echo "Client Secret: " . $order->getSessionToken()->getClientSecret() . "\n";
```

{% endtab %}

{% endtabs %}

## What Just Happened

The library helped you create a PaymentIntent on Stripe. You will recieve a `client_secret` in the response.

The order is in `STARTED` state, ready for payment.

```json
{
    "connectorOrderId": "pi_3Oxxx...",
    "status": "STARTED",
    "merchantOrderId": "order-123",
    "sessionToken": {
        "clientSecret": "pi_3Oxxx..._secret_xxx"
    }
}
```

## Using the Client Secret with Stripe.js

Now, pass the `clientSecret` to your frontend and use it to initiate Stripe.js for PCI compliance card element. The users will be able to key in the card details on the Stripe Element and you will get `payment_method_id` in the response.

```html
<script src="https://js.stripe.com/v3/"></script>
<script>
const stripe = Stripe('pk_test_xxx'); // Your Stripe publishable key

// Client secret from your backend
const clientSecret = 'pi_3Oxxx..._secret_xxx';

// Mount Stripe Elements
const elements = stripe.elements({ clientSecret });
const paymentElement = elements.create('payment');
paymentElement.mount('#payment-element');

// When customer submits
const { error, paymentIntent } = await stripe.confirmPayment({
    elements,
    confirmParams: {
        return_url: 'https://your-site.com/payment/complete',
    },
});
</script>
```

You can proceed to the making the [first payment](./first-payment.md)

## Next Steps

- Learn about [authorizing payments](./first-payment.md) after CreateOrder
- Explore [error handling](./first-payment.md#error-handling)
- See [all payment flows](./extending-to-more-flows.md)
