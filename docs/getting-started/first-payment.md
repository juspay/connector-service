# First Payment

In the next few steps you will authorize the payment, handle errors, capture funds, and process refunds. And then you will be ready to send payment to any payment processor, without writing specialized code for each.

You will have a `payment_method_id` if you depend on your processor for PCI compliance. Use this to [Authorize with Payment Method ID](#authorize-with-payment-method-id).

Alternatively if your Payment processor API keys are enabled to accept PCI compliant raw card data, that will suffice to make the first payment. Jump to [Authorize with Raw Card Details](#authorize-with-raw-card-details-pci-compliant).

## Authorize with Payment Method ID

Use the `payment_method_id` from [Quick Start](./quick-start.md) to authorize the payment:

{% tabs %}

{% tab title="Node.js" %}

```javascript
const { PaymentClient } = require('hyperswitch-prism');
const types = require('hyperswitch-prism').types;

async function authorizePayment(paymentMethodId) {
    const config = {
        connectorConfig: {
            stripe: { apiKey: { value: process.env.STRIPE_API_KEY } }
        }
    };
    const paymentClient = new PaymentClient(config);

    try {
        // Authorize using the payment_method_id from Stripe or Adyen
        const auth = await paymentClient.authorize({
            merchantTransactionId: 'order-456',
            amount: { minorAmount: 1000, currency: types.Currency.USD },
            paymentMethod: {
                token: { token: paymentMethodId }  // e.g., 'pm_1234...'
            },
            captureMethod: types.CaptureMethod.MANUAL,
            address: { billingAddress: {} },
            authType: types.AuthenticationType.NO_THREE_DS,
            returnUrl: "https://example.com/return"
        });

        if (auth.status === 'FAILED') {
            throw new Error(`Payment failed: ${auth.error?.unifiedDetails?.message}`);
        }
        console.log('Authorized:', auth.connectorTransactionId, auth.status);
        return auth;

    } catch (error) {
        handlePaymentError(error);
    }
}

function handlePaymentError(error) {
    console.error('Payment failed:', error.message);
}
```

{% endtab %}

{% tab title="Python" %}

```python
import os
from hyperswitch_prism import PaymentClient
from hyperswitch_prism.generated import payment_pb2

config = {
    "connectorConfig": {
        "stripe": {"apiKey": {"value": os.environ["STRIPE_API_KEY"]}}
    }
}
payment_client = PaymentClient(config)

def authorize_payment(payment_method_id):
    try:
        auth = payment_client.authorize({
            "merchantTransactionId": "order-456",
            "amount": {"minorAmount": 1000, "currency": payment_pb2.Currency.USD},
            "paymentMethod": {
                "token": {"token": payment_method_id}
            },
            "captureMethod": payment_pb2.CaptureMethod.MANUAL,
            "address": {"billingAddress": {}},
            "authType": payment_pb2.AuthenticationType.NO_THREE_DS,
            "returnUrl": "https://example.com/return"
        })
        
        if auth.status == 'FAILED':
            raise Exception(f"Payment failed: {auth.error.unified_details.message}")
        print(f"Authorized: {auth.connector_transaction_id}, {auth.status}")
        return auth

    except Exception as e:
        print(f"Payment failed: {e}")
```

{% endtab %}

{% tab title="Java" %}

```java
import com.juspay.hyperswitch.prism.PaymentClient;
import com.juspay.hyperswitch.prism.types.*;

public class FirstPayment {
    private PaymentClient paymentClient;
    
    public FirstPayment() {
        ConnectorConfig config = ConnectorConfig.builder()
            .connectorConfig(ConnectorSpecificConfig.builder()
                .stripe(StripeConfig.builder()
                    .apiKey(SecretString.of(System.getenv("STRIPE_API_KEY")))
                    .build())
                .build())
            .build();
        this.paymentClient = new PaymentClient(config);
    }

    public void authorizePayment(String paymentMethodId) {
        try {
            AuthorizeResponse auth = paymentClient.authorize(
                AuthorizeRequest.builder()
                    .merchantTransactionId("order-456")
                    .amount(Amount.of(1000, Currency.USD))
                    .paymentMethod(PaymentMethod.byToken(paymentMethodId))
                    .captureMethod(CaptureMethod.MANUAL)
                    .address(Address.builder().billingAddress(BillingAddress.builder().build()).build())
                    .authType(AuthenticationType.NO_THREE_DS)
                    .returnUrl("https://example.com/return")
                    .build()
            );
            
            if (auth.getStatus() == Status.FAILED) {
                throw new RuntimeException("Payment failed: " + auth.getError().getUnifiedDetails().getMessage());
            }
            System.out.println("Authorized: " + auth.getConnectorTransactionId());

        } catch (Exception e) {
            System.err.println("Payment failed: " + e.getMessage());
        }
    }
}
```

{% endtab %}

{% tab title="PHP" %}

```php
<?php
use HyperswitchPrism\PaymentClient;
use HyperswitchPrism\Types\Currency;
use HyperswitchPrism\Types\CaptureMethod;
use HyperswitchPrism\Types\AuthenticationType;

$config = [
    'connectorConfig' => [
        'stripe' => ['apiKey' => ['value' => $_ENV['STRIPE_API_KEY']]]
    ]
];
$paymentClient = new PaymentClient($config);

function authorizePayment($paymentMethodId) use ($paymentClient) {
    try {
        $auth = $paymentClient->authorize([
            'merchantTransactionId' => 'order-456',
            'amount' => ['minorAmount' => 1000, 'currency' => Currency::USD],
            'paymentMethod' => [
                'token' => ['token' => $paymentMethodId]
            ],
            'captureMethod' => CaptureMethod::MANUAL,
            'address' => ['billingAddress' => []],
            'authType' => AuthenticationType::NO_THREE_DS,
            'returnUrl' => 'https://example.com/return'
        ]);
        
        if ($auth->status === 'FAILED') {
            throw new Exception("Payment failed: " . $auth->error->unifiedDetails->message);
        }
        echo "Authorized: " . $auth->connectorTransactionId . "\n";
        return $auth;

    } catch (Exception $e) {
        echo "Payment failed: " . $e->getMessage() . "\n";
    }
}
```

{% endtab %}

{% endtabs %}

## Authorize with Raw Card Details (PCI Compliant)

If you're PCI compliant and collect card details directly:

{% tabs %}

{% tab title="Node.js" %}

```javascript
const { PaymentClient } = require('hyperswitch-prism');
const types = require('hyperswitch-prism').types;

const config = {
    connectorConfig: {
        stripe: { apiKey: { value: process.env.STRIPE_API_KEY } }
    }
};
const paymentClient = new PaymentClient(config);

const auth = await paymentClient.authorize({
    merchantTransactionId: 'order-456',
    amount: { minorAmount: 1000, currency: types.Currency.USD },
    paymentMethod: {
        card: {
            cardNumber: { value: '4242424242424242' },
            cardExpMonth: { value: '12' },
            cardExpYear: { value: '2027' },
            cardCvc: { value: '123' },
            cardHolderName: { value: 'Jane Doe' }
        }
    },
    captureMethod: types.CaptureMethod.AUTOMATIC,  // Charge immediately
    address: { billingAddress: {} },
    authType: types.AuthenticationType.NO_THREE_DS,
    returnUrl: "https://example.com/return"
});
```

{% endtab %}

{% tab title="Python" %}

```python
import os
from hyperswitch_prism import PaymentClient
from hyperswitch_prism.generated import payment_pb2

config = {
    "connectorConfig": {
        "stripe": {"apiKey": {"value": os.environ["STRIPE_API_KEY"]}}
    }
}
payment_client = PaymentClient(config)

auth = payment_client.authorize({
    "merchantTransactionId": "order-456",
    "amount": {"minorAmount": 1000, "currency": payment_pb2.Currency.USD},
    "paymentMethod": {
        "card": {
            "cardNumber": {"value": "4242424242424242"},
            "cardExpMonth": {"value": "12"},
            "cardExpYear": {"value": "2027"},
            "cardCvc": {"value": "123"},
            "cardHolderName": {"value": "Jane Doe"}
        }
    },
    "captureMethod": payment_pb2.CaptureMethod.AUTOMATIC,
    "address": {"billingAddress": {}},
    "authType": payment_pb2.AuthenticationType.NO_THREE_DS,
    "returnUrl": "https://example.com/return"
})
```

{% endtab %}

{% tab title="Java" %}

```java
import com.juspay.hyperswitch.prism.PaymentClient;
import com.juspay.hyperswitch.prism.types.*;

ConnectorConfig config = ConnectorConfig.builder()
    .connectorConfig(ConnectorSpecificConfig.builder()
        .stripe(StripeConfig.builder()
            .apiKey(SecretString.of(System.getenv("STRIPE_API_KEY")))
            .build())
        .build())
    .build();
PaymentClient paymentClient = new PaymentClient(config);

AuthorizeResponse auth = paymentClient.authorize(
    AuthorizeRequest.builder()
        .merchantTransactionId("order-456")
        .amount(Amount.of(1000, Currency.USD))
        .paymentMethod(PaymentMethod.card(
            SecretString.of("4242424242424242"),
            SecretString.of("12"),
            SecretString.of("2027"),
            SecretString.of("123"),
            "Jane Doe"))
        .captureMethod(CaptureMethod.AUTOMATIC)
        .address(Address.builder().billingAddress(BillingAddress.builder().build()).build())
        .authType(AuthenticationType.NO_THREE_DS)
        .returnUrl("https://example.com/return")
        .build()
);
```

{% endtab %}

{% tab title="PHP" %}

```php
<?php
use HyperswitchPrism\PaymentClient;
use HyperswitchPrism\Types\Currency;
use HyperswitchPrism\Types\CaptureMethod;
use HyperswitchPrism\Types\AuthenticationType;

$config = [
    'connectorConfig' => [
        'stripe' => ['apiKey' => ['value' => $_ENV['STRIPE_API_KEY']]]
    ]
];
$paymentClient = new PaymentClient($config);

$auth = $paymentClient->authorize([
    'merchantTransactionId' => 'order-456',
    'amount' => ['minorAmount' => 1000, 'currency' => Currency::USD],
    'paymentMethod' => [
        'card' => [
            'cardNumber' => ['value' => '4242424242424242'],
            'cardExpMonth' => ['value' => '12'],
            'cardExpYear' => ['value' => '2027'],
            'cardCvc' => ['value' => '123'],
            'cardHolderName' => ['value' => 'Jane Doe']
        ]
    ],
    'captureMethod' => CaptureMethod::AUTOMATIC,
    'address' => ['billingAddress' => []],
    'authType' => AuthenticationType::NO_THREE_DS,
    'returnUrl' => 'https://example.com/return'
]);
```

{% endtab %}

{% endtabs %}

## Complete Payment Flow

After authorization, capture funds and handle refunds:

{% tabs %}

{% tab title="Node.js" %}

```javascript
// 1. Check payment status
const status = await paymentClient.get({
    merchantTransactionId: 'order-456',
    connectorTransactionId: auth.connectorTransactionId,
    amount: { minorAmount: 1000, currency: types.Currency.USD }
});
console.log('Current status:', status.status);

// 2. Capture the funds (when order ships)
const capture = await paymentClient.capture({
    merchantCaptureId: 'capture-001',
    connectorTransactionId: auth.connectorTransactionId,
    amountToCapture: { minorAmount: 1000, currency: types.Currency.USD }
});
console.log('Captured:', capture.status);  // CAPTURED

// 3. Process a partial refund (customer returns item)
const refund = await paymentClient.refund({
    merchantRefundId: 'refund-001',
    connectorTransactionId: auth.connectorTransactionId,
    paymentAmount: 1000,
    refundAmount: { minorAmount: 500, currency: types.Currency.USD },  // Refund $5
    reason: 'customer_request'
});
console.log('Refund ID:', refund.connectorRefundId);
```

{% endtab %}

{% tab title="Python" %}

```python
# 1. Check payment status
status = payment_client.get(
    merchant_transaction_id="order-456",
    connector_transaction_id=auth.connector_transaction_id,
    amount={"minorAmount": 1000, "currency": payment_pb2.Currency.USD}
)
print(f"Current status: {status.status}")

# 2. Capture the funds
capture = payment_client.capture({
    "merchantCaptureId": "capture-001",
    "connectorTransactionId": auth.connector_transaction_id,
    "amountToCapture": {"minorAmount": 1000, "currency": payment_pb2.Currency.USD}
})
print(f"Captured: {capture.status}")

# 3. Process a partial refund
refund = payment_client.refund({
    "merchantRefundId": "refund-001",
    "connectorTransactionId": auth.connector_transaction_id,
    "paymentAmount": 1000,
    "refundAmount": {"minorAmount": 500, "currency": payment_pb2.Currency.USD},
    "reason": "customer_request"
})
print(f"Refund ID: {refund.connector_refund_id}")
```

{% endtab %}

{% tab title="Java" %}

```java
// 1. Check payment status
PaymentServiceGetResponse status = paymentClient.get(
    PaymentServiceGetRequest.builder()
        .merchantTransactionId("order-456")
        .connectorTransactionId(auth.getConnectorTransactionId())
        .amount(Amount.of(1000, Currency.USD))
        .build()
);
System.out.println("Status: " + status.getStatus());

// 2. Capture the funds
PaymentServiceCaptureResponse capture = paymentClient.capture(
    PaymentServiceCaptureRequest.builder()
        .merchantCaptureId("capture-001")
        .connectorTransactionId(auth.getConnectorTransactionId())
        .amountToCapture(Amount.of(1000, Currency.USD))
        .build()
);
System.out.println("Captured: " + capture.getStatus());

// 3. Process a partial refund
PaymentServiceRefundResponse refund = paymentClient.refund(
    PaymentServiceRefundRequest.builder()
        .merchantRefundId("refund-001")
        .connectorTransactionId(auth.getConnectorTransactionId())
        .paymentAmount(1000)
        .refundAmount(Amount.of(500, Currency.USD))
        .reason("customer_request")
        .build()
);
System.out.println("Refund ID: " + refund.getConnectorRefundId());
```

{% endtab %}

{% tab title="PHP" %}

```php
// 1. Check payment status
$status = $paymentClient->get([
    'merchantTransactionId' => 'order-456',
    'connectorTransactionId' => $auth->connectorTransactionId,
    'amount' => ['minorAmount' => 1000, 'currency' => Currency::USD]
]);
echo "Status: " . $status->status . "\n";

// 2. Capture the funds
$capture = $paymentClient->capture([
    'merchantCaptureId' => 'capture-001',
    'connectorTransactionId' => $auth->connectorTransactionId,
    'amountToCapture' => ['minorAmount' => 1000, 'currency' => Currency::USD]
]);
echo "Captured: " . $capture->status . "\n";

// 3. Process a partial refund
$refund = $paymentClient->refund([
    'merchantRefundId' => 'refund-001',
    'connectorTransactionId' => $auth->connectorTransactionId,
    'paymentAmount' => 1000,
    'refundAmount' => ['minorAmount' => 500, 'currency' => Currency::USD],
    'reason' => 'customer_request'
]);
echo "Refund ID: " . $refund->connectorRefundId . "\n";
```

{% endtab %}

{% endtabs %}

## Error Scenarios

### Declined Card

```javascript
// Card declined - check response.status and response.error
const auth = await paymentClient.authorize({
    merchantTransactionId: 'order-456',
    amount: { minorAmount: 1000, currency: types.Currency.USD },
    paymentMethod: { token: { token: 'pm_declined' } },
    captureMethod: types.CaptureMethod.MANUAL,
    address: { billingAddress: {} },
    authType: types.AuthenticationType.NO_THREE_DS,
    returnUrl: "https://example.com/return"
});

if (auth.status === 'FAILED') {
    console.error('Payment declined:', auth.error?.unifiedDetails?.message);
}
```

### Network Timeout

```javascript
const { NetworkError } = require('hyperswitch-prism');

try {
    const auth = await paymentClient.authorize({...});
} catch (error) {
    if (error instanceof NetworkError) {
        // Network error - do NOT retry blindly
        // The request may have been sent to the connector
        console.error('Network error:', error.errorCode);
    }
}
```

## Business Use Cases

### E-commerce: Two-Step Flow

Authorize at checkout. Capture when you ship.

```javascript
// Checkout: authorize only
const auth = await paymentClient.authorize({
    merchantTransactionId: 'order-456',
    amount: { minorAmount: 9999, currency: types.Currency.USD },
    paymentMethod: { card: { /* card details */ } },
    captureMethod: types.CaptureMethod.MANUAL,
    address: { billingAddress: {} },
    authType: types.AuthenticationType.NO_THREE_DS,
    returnUrl: "https://example.com/return"
});

// Later: when order ships
await paymentClient.capture({
    merchantCaptureId: 'capture-001',
    connectorTransactionId: auth.connectorTransactionId,
    amountToCapture: { minorAmount: 9999, currency: types.Currency.USD }
});
```

### SaaS: Immediate Capture

For digital goods, capture immediately.

```javascript
const payment = await paymentClient.authorize({
    merchantTransactionId: 'order-456',
    amount: { minorAmount: 2900, currency: types.Currency.USD },
    paymentMethod: { card: { /* card details */ } },
    captureMethod: types.CaptureMethod.AUTOMATIC,
    address: { billingAddress: {} },
    authType: types.AuthenticationType.NO_THREE_DS,
    returnUrl: "https://example.com/return"
});
// Status: CAPTURED (auto-captured)
```

### Marketplace: Partial Refund

Customer returns one item from a multi-item order.

```javascript
await paymentClient.refund({
    merchantRefundId: 'refund-001',
    connectorTransactionId: 'conn_txn_abc123',
    paymentAmount: 10000,
    refundAmount: { minorAmount: 2500, currency: types.Currency.USD },
    reason: 'customer_request'
});
```

## Key Takeaways

- **One error handler** works for all connectors
- **Unified error codes** tell you exactly what happened
- **connectorTransactionId** is the key identifier for all operations
- **Same code** works for Stripe, Adyen, PayPal, and 50+ more

See [extending payment flows](./extend-to-more-flows.md) for subscriptions, 3D Secure, and more.