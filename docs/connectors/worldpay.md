# Worldpay

<!--
This file is auto-generated. Do not edit by hand.
Source: data/field_probe/worldpay.json
Regenerate: python3 scripts/generate-connector-docs.py worldpay
-->

## SDK Configuration

Use this config for all flows in this connector. Replace `YOUR_API_KEY` with your actual credentials.

<table>
<tr><td><b>Python</b></td><td><b>JavaScript</b></td><td><b>Kotlin</b></td><td><b>Rust</b></td></tr>
<tr>
<td valign="top">

<details><summary>Python</summary>

```python
from payments.generated import sdk_config_pb2, payment_pb2

config = sdk_config_pb2.ConnectorConfig(
    connector=payment_pb2.Connector.WORLDPAY,
    environment=sdk_config_pb2.Environment.SANDBOX,
)
# Set credentials before running (field names depend on connector auth type):
# config.auth.worldpay.api_key.value = "YOUR_API_KEY"

```

</details>

</td>
<td valign="top">

<details><summary>JavaScript</summary>

```javascript
const { ConnectorClient } = require('connector-service-node-ffi');

// Reuse this client for all flows
const client = new ConnectorClient({
    connector: 'Worldpay',
    environment: 'sandbox',
    connector_auth_type: {
        header_key: { api_key: 'YOUR_API_KEY' },
    },
});
```

</details>

</td>
<td valign="top">

<details><summary>Kotlin</summary>

```kotlin
val config = ConnectorConfig.newBuilder()
    .setConnector("Worldpay")
    .setEnvironment(Environment.SANDBOX)
    .setAuth(
        ConnectorAuthType.newBuilder()
            .setHeaderKey(HeaderKey.newBuilder().setApiKey("YOUR_API_KEY"))
    )
    .build()
```

</details>

</td>
<td valign="top">

<details><summary>Rust</summary>

```rust
use connector_service_sdk::{ConnectorClient, ConnectorConfig};

let config = ConnectorConfig {
    connector: "Worldpay".to_string(),
    environment: Environment::Sandbox,
    auth: ConnectorAuth::HeaderKey { api_key: "YOUR_API_KEY".into() },
    ..Default::default()
};
```

</details>

</td>
</tr>
</table>

## Integration Scenarios

Complete, runnable examples for common integration patterns. Each example shows the full flow with status handling. Copy-paste into your app and replace placeholder values.

### Card Payment (Authorize + Capture)

Reserve funds with Authorize, then settle with a separate Capture call. Use for physical goods or delayed fulfillment where capture happens later.

**Response status handling:**

| Status | Recommended action |
|--------|-------------------|
| `AUTHORIZED` | Funds reserved — proceed to Capture to settle |
| `PENDING` | Awaiting async confirmation — wait for webhook before capturing |
| `FAILED` | Payment declined — surface error to customer, do not retry without new details |

**Examples:** [Python](../../examples/worldpay/python/worldpay.py#L23) · [JavaScript](../../examples/worldpay/javascript/worldpay.js#L22) · [Kotlin](../../examples/worldpay/kotlin/worldpay.kt#L36) · [Rust](../../examples/worldpay/rust/worldpay.rs#L26)

### Card Payment (Automatic Capture)

Authorize and capture in one call using `capture_method=AUTOMATIC`. Use for digital goods or immediate fulfillment.

**Response status handling:**

| Status | Recommended action |
|--------|-------------------|
| `AUTHORIZED` | Payment authorized and captured — funds will be settled automatically |
| `PENDING` | Payment processing — await webhook for final status before fulfilling |
| `FAILED` | Payment declined — surface error to customer, do not retry without new details |

**Examples:** [Python](../../examples/worldpay/python/worldpay.py#L127) · [JavaScript](../../examples/worldpay/javascript/worldpay.js#L121) · [Kotlin](../../examples/worldpay/kotlin/worldpay.kt#L131) · [Rust](../../examples/worldpay/rust/worldpay.rs#L123)

### Wallet Payment (Google Pay / Apple Pay)

Wallet payments pass an encrypted token from the browser/device SDK. Pass the token blob directly — do not decrypt client-side.

**Response status handling:**

| Status | Recommended action |
|--------|-------------------|
| `AUTHORIZED` | Payment authorized and captured — funds will be settled automatically |
| `PENDING` | Payment processing — await webhook for final status before fulfilling |
| `FAILED` | Payment declined — surface error to customer, do not retry without new details |

**Examples:** [Python](../../examples/worldpay/python/worldpay.py#L215) · [JavaScript](../../examples/worldpay/javascript/worldpay.js#L206) · [Kotlin](../../examples/worldpay/kotlin/worldpay.kt#L213) · [Rust](../../examples/worldpay/rust/worldpay.rs#L206)

### Refund a Payment

Authorize with automatic capture, then refund the captured amount. `connector_transaction_id` from the Authorize response is reused for the Refund call.

**Examples:** [Python](../../examples/worldpay/python/worldpay.py#L310) · [JavaScript](../../examples/worldpay/javascript/worldpay.js#L298) · [Kotlin](../../examples/worldpay/kotlin/worldpay.kt#L302) · [Rust](../../examples/worldpay/rust/worldpay.rs#L296)

### Void a Payment

Authorize funds with a manual capture flag, then cancel the authorization with Void before any capture occurs. Releases the hold on the customer's funds.

**Examples:** [Python](../../examples/worldpay/python/worldpay.py#L416) · [JavaScript](../../examples/worldpay/javascript/worldpay.js#L399) · [Kotlin](../../examples/worldpay/kotlin/worldpay.kt#L399) · [Rust](../../examples/worldpay/rust/worldpay.rs#L395)

### Get Payment Status

Authorize a payment, then poll the connector for its current status using Get. Use this to sync payment state when webhooks are unavailable or delayed.

**Examples:** [Python](../../examples/worldpay/python/worldpay.py#L513) · [JavaScript](../../examples/worldpay/javascript/worldpay.js#L490) · [Kotlin](../../examples/worldpay/kotlin/worldpay.kt#L487) · [Rust](../../examples/worldpay/rust/worldpay.rs#L484)

## API Reference

| Flow (Service.RPC) | Category | gRPC Request Message |
|--------------------|----------|----------------------|
| [PaymentService.Authorize](#paymentserviceauthorize) | Payments | `PaymentServiceAuthorizeRequest` |
| [PaymentService.Capture](#paymentservicecapture) | Payments | `PaymentServiceCaptureRequest` |
| [PaymentService.Get](#paymentserviceget) | Payments | `PaymentServiceGetRequest` |
| [RecurringPaymentService.Charge](#recurringpaymentservicecharge) | Mandates | `RecurringPaymentServiceChargeRequest` |
| [PaymentService.Refund](#paymentservicerefund) | Payments | `PaymentServiceRefundRequest` |
| [PaymentService.Void](#paymentservicevoid) | Payments | `PaymentServiceVoidRequest` |

### Payments

#### PaymentService.Authorize

Authorize a payment amount on a payment method. This reserves funds without capturing them, essential for verifying availability before finalizing.

| | Message |
|---|---------|
| **Request** | `PaymentServiceAuthorizeRequest` |
| **Response** | `PaymentServiceAuthorizeResponse` |

**Supported payment method types:**

| Payment Method | Supported |
|----------------|:---------:|
| Card | ✓ |
| Google Pay | ✓ |
| Apple Pay | ✓ |
| Samsung Pay | — |

**Payment method objects** — use these in the `payment_method` field of the Authorize request.

##### Card (Raw PAN)

```python
"payment_method": {
    "card": {  # Generic card payment
        "card_number": {"value": "4111111111111111"},  # Card Identification
        "card_exp_month": {"value": "03"},
        "card_exp_year": {"value": "2030"},
        "card_cvc": {"value": "737"},
        "card_holder_name": {"value": "John Doe"}  # Cardholder Information
    }
}
```

##### Google Pay

```python
"payment_method": {
    "google_pay": {  # Google Pay
        "type": "CARD",  # Type of payment method
        "description": "Visa 1111",  # User-facing description of the payment method
        "info": {
            "card_network": "VISA",  # Card network name
            "card_details": "1111"  # Card details (usually last 4 digits)
        },
        "tokenization_data": {
            "encrypted_data": {  # Encrypted Google Pay payment data
                "token": "{\"version\":\"ECv2\",\"signature\":\"<sig>\",\"intermediateSigningKey\":{\"signedKey\":\"<signed_key>\",\"signatures\":[\"<sig>\"]},\"signedMessage\":\"<signed_message>\"}",  # Token generated for the wallet
                "token_type": "PAYMENT_GATEWAY"  # The type of the token
            }
        }
    }
}
```

##### Apple Pay

```python
"payment_method": {
    "apple_pay": {  # Apple Pay
        "payment_data": {
            "encrypted_data": "<base64_encoded_apple_pay_payment_token>"  # Encrypted Apple Pay payment data as string
        },
        "payment_method": {
            "display_name": "Visa 1111",
            "network": "Visa",
            "type": "debit"
        },
        "transaction_identifier": "<apple_pay_transaction_identifier>"  # Transaction identifier
    }
}
```

**Examples:** [Python](../../examples/worldpay/python/worldpay.py#L613) · [JavaScript](../../examples/worldpay/javascript/worldpay.js#L583) · [Kotlin](../../examples/worldpay/kotlin/worldpay.kt#L577) · [Rust](../../examples/worldpay/rust/worldpay.rs#L575)

#### PaymentService.Capture

Finalize an authorized payment transaction. Transfers reserved funds from customer to merchant account, completing the payment lifecycle.

| | Message |
|---|---------|
| **Request** | `PaymentServiceCaptureRequest` |
| **Response** | `PaymentServiceCaptureResponse` |

**Examples:** [Python](../../examples/worldpay/python/worldpay.py#L698) · [JavaScript](../../examples/worldpay/javascript/worldpay.js#L665) · [Kotlin](../../examples/worldpay/kotlin/worldpay.kt#L655) · [Rust](../../examples/worldpay/rust/worldpay.rs#L654)

#### PaymentService.Get

Retrieve current payment status from the payment processor. Enables synchronization between your system and payment processors for accurate state tracking.

| | Message |
|---|---------|
| **Request** | `PaymentServiceGetRequest` |
| **Response** | `PaymentServiceGetResponse` |

**Examples:** [Python](../../examples/worldpay/python/worldpay.py#L721) · [JavaScript](../../examples/worldpay/javascript/worldpay.js#L684) · [Kotlin](../../examples/worldpay/kotlin/worldpay.kt#L672) · [Rust](../../examples/worldpay/rust/worldpay.rs#L667)

#### PaymentService.Refund

Initiate a refund to customer's payment method. Returns funds for returns, cancellations, or service adjustments after original payment.

| | Message |
|---|---------|
| **Request** | `PaymentServiceRefundRequest` |
| **Response** | `RefundResponse` |

**Examples:** [Python](../../examples/worldpay/python/worldpay.py) · [JavaScript](../../examples/worldpay/javascript/worldpay.js) · [Kotlin](../../examples/worldpay/kotlin/worldpay.kt#L715) · [Rust](../../examples/worldpay/rust/worldpay.rs#L704)

#### PaymentService.Void

Cancel an authorized payment before capture. Releases held funds back to customer, typically used when orders are cancelled or abandoned.

| | Message |
|---|---------|
| **Request** | `PaymentServiceVoidRequest` |
| **Response** | `PaymentServiceVoidResponse` |

**Examples:** [Python](../../examples/worldpay/python/worldpay.py#L773) · [JavaScript](../../examples/worldpay/javascript/worldpay.js) · [Kotlin](../../examples/worldpay/kotlin/worldpay.kt#L734) · [Rust](../../examples/worldpay/rust/worldpay.rs#L719)

### Mandates

#### RecurringPaymentService.Charge

Charge using an existing stored recurring payment instruction. Processes repeat payments for subscriptions or recurring billing without collecting payment details.

| | Message |
|---|---------|
| **Request** | `RecurringPaymentServiceChargeRequest` |
| **Response** | `RecurringPaymentServiceChargeResponse` |

**Examples:** [Python](../../examples/worldpay/python/worldpay.py#L740) · [JavaScript](../../examples/worldpay/javascript/worldpay.js#L698) · [Kotlin](../../examples/worldpay/kotlin/worldpay.kt) · [Rust](../../examples/worldpay/rust/worldpay.rs#L679)
