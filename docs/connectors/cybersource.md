# CyberSource

<!--
This file is auto-generated. Do not edit by hand.
Source: data/field_probe/cybersource.json
Regenerate: python3 scripts/generate-connector-docs.py cybersource
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
    connector=payment_pb2.Connector.CYBERSOURCE,
    environment=sdk_config_pb2.Environment.SANDBOX,
)
# Set credentials before running (field names depend on connector auth type):
# config.auth.cybersource.api_key.value = "YOUR_API_KEY"

```

</details>

</td>
<td valign="top">

<details><summary>JavaScript</summary>

```javascript
const { ConnectorClient } = require('connector-service-node-ffi');

// Reuse this client for all flows
const client = new ConnectorClient({
    connector: 'Cybersource',
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
    .setConnector("Cybersource")
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
    connector: "Cybersource".to_string(),
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

**Examples:** [Python](../../examples/cybersource/python/cybersource.py#L23) · [JavaScript](../../examples/cybersource/javascript/cybersource.js#L22) · [Kotlin](../../examples/cybersource/kotlin/cybersource.kt#L39) · [Rust](../../examples/cybersource/rust/cybersource.rs#L26)

### Card Payment (Automatic Capture)

Authorize and capture in one call using `capture_method=AUTOMATIC`. Use for digital goods or immediate fulfillment.

**Response status handling:**

| Status | Recommended action |
|--------|-------------------|
| `AUTHORIZED` | Payment authorized and captured — funds will be settled automatically |
| `PENDING` | Payment processing — await webhook for final status before fulfilling |
| `FAILED` | Payment declined — surface error to customer, do not retry without new details |

**Examples:** [Python](../../examples/cybersource/python/cybersource.py#L127) · [JavaScript](../../examples/cybersource/javascript/cybersource.js#L121) · [Kotlin](../../examples/cybersource/kotlin/cybersource.kt#L134) · [Rust](../../examples/cybersource/rust/cybersource.rs#L123)

### Wallet Payment (Google Pay / Apple Pay)

Wallet payments pass an encrypted token from the browser/device SDK. Pass the token blob directly — do not decrypt client-side.

**Response status handling:**

| Status | Recommended action |
|--------|-------------------|
| `AUTHORIZED` | Payment authorized and captured — funds will be settled automatically |
| `PENDING` | Payment processing — await webhook for final status before fulfilling |
| `FAILED` | Payment declined — surface error to customer, do not retry without new details |

**Examples:** [Python](../../examples/cybersource/python/cybersource.py#L215) · [JavaScript](../../examples/cybersource/javascript/cybersource.js#L206) · [Kotlin](../../examples/cybersource/kotlin/cybersource.kt#L216) · [Rust](../../examples/cybersource/rust/cybersource.rs#L206)

### Refund a Payment

Authorize with automatic capture, then refund the captured amount. `connector_transaction_id` from the Authorize response is reused for the Refund call.

**Examples:** [Python](../../examples/cybersource/python/cybersource.py#L310) · [JavaScript](../../examples/cybersource/javascript/cybersource.js#L298) · [Kotlin](../../examples/cybersource/kotlin/cybersource.kt#L305) · [Rust](../../examples/cybersource/rust/cybersource.rs#L296)

### Recurring / Mandate Payments

Store a payment mandate with SetupRecurring, then charge it repeatedly with RecurringPaymentService.Charge without requiring customer action.

**Response status handling:**

| Status | Recommended action |
|--------|-------------------|
| `PENDING` | Mandate stored — save connector_transaction_id for future RecurringPaymentService.Charge calls |
| `FAILED` | Setup failed — customer must re-enter payment details |

**Examples:** [Python](../../examples/cybersource/python/cybersource.py#L416) · [JavaScript](../../examples/cybersource/javascript/cybersource.js#L399) · [Kotlin](../../examples/cybersource/kotlin/cybersource.kt#L402) · [Rust](../../examples/cybersource/rust/cybersource.rs#L395)

### Void a Payment

Authorize funds with a manual capture flag, then cancel the authorization with Void before any capture occurs. Releases the hold on the customer's funds.

**Examples:** [Python](../../examples/cybersource/python/cybersource.py#L515) · [JavaScript](../../examples/cybersource/javascript/cybersource.js#L489) · [Kotlin](../../examples/cybersource/kotlin/cybersource.kt#L494) · [Rust](../../examples/cybersource/rust/cybersource.rs#L484)

### Get Payment Status

Authorize a payment, then poll the connector for its current status using Get. Use this to sync payment state when webhooks are unavailable or delayed.

**Examples:** [Python](../../examples/cybersource/python/cybersource.py#L617) · [JavaScript](../../examples/cybersource/javascript/cybersource.js#L585) · [Kotlin](../../examples/cybersource/kotlin/cybersource.kt#L587) · [Rust](../../examples/cybersource/rust/cybersource.rs#L578)

## API Reference

| Flow (Service.RPC) | Category | gRPC Request Message |
|--------------------|----------|----------------------|
| [PaymentService.Authorize](#paymentserviceauthorize) | Payments | `PaymentServiceAuthorizeRequest` |
| [PaymentService.Capture](#paymentservicecapture) | Payments | `PaymentServiceCaptureRequest` |
| [PaymentService.Get](#paymentserviceget) | Payments | `PaymentServiceGetRequest` |
| [RecurringPaymentService.Charge](#recurringpaymentservicecharge) | Mandates | `RecurringPaymentServiceChargeRequest` |
| [PaymentService.Refund](#paymentservicerefund) | Payments | `PaymentServiceRefundRequest` |
| [PaymentService.SetupRecurring](#paymentservicesetuprecurring) | Payments | `PaymentServiceSetupRecurringRequest` |
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

**Examples:** [Python](../../examples/cybersource/python/cybersource.py#L717) · [JavaScript](../../examples/cybersource/javascript/cybersource.js#L678) · [Kotlin](../../examples/cybersource/kotlin/cybersource.kt#L677) · [Rust](../../examples/cybersource/rust/cybersource.rs#L669)

#### PaymentService.Capture

Finalize an authorized payment transaction. Transfers reserved funds from customer to merchant account, completing the payment lifecycle.

| | Message |
|---|---------|
| **Request** | `PaymentServiceCaptureRequest` |
| **Response** | `PaymentServiceCaptureResponse` |

**Examples:** [Python](../../examples/cybersource/python/cybersource.py#L802) · [JavaScript](../../examples/cybersource/javascript/cybersource.js#L760) · [Kotlin](../../examples/cybersource/kotlin/cybersource.kt#L755) · [Rust](../../examples/cybersource/rust/cybersource.rs#L748)

#### PaymentService.Get

Retrieve current payment status from the payment processor. Enables synchronization between your system and payment processors for accurate state tracking.

| | Message |
|---|---------|
| **Request** | `PaymentServiceGetRequest` |
| **Response** | `PaymentServiceGetResponse` |

**Examples:** [Python](../../examples/cybersource/python/cybersource.py#L825) · [JavaScript](../../examples/cybersource/javascript/cybersource.js#L779) · [Kotlin](../../examples/cybersource/kotlin/cybersource.kt#L772) · [Rust](../../examples/cybersource/rust/cybersource.rs#L761)

#### PaymentService.Refund

Initiate a refund to customer's payment method. Returns funds for returns, cancellations, or service adjustments after original payment.

| | Message |
|---|---------|
| **Request** | `PaymentServiceRefundRequest` |
| **Response** | `RefundResponse` |

**Examples:** [Python](../../examples/cybersource/python/cybersource.py) · [JavaScript](../../examples/cybersource/javascript/cybersource.js) · [Kotlin](../../examples/cybersource/kotlin/cybersource.kt#L815) · [Rust](../../examples/cybersource/rust/cybersource.rs#L798)

#### PaymentService.SetupRecurring

Setup a recurring payment instruction for future payments/ debits. This could be for SaaS subscriptions, monthly bill payments, insurance payments and similar use cases.

| | Message |
|---|---------|
| **Request** | `PaymentServiceSetupRecurringRequest` |
| **Response** | `PaymentServiceSetupRecurringResponse` |

**Examples:** [Python](../../examples/cybersource/python/cybersource.py#L877) · [JavaScript](../../examples/cybersource/javascript/cybersource.js#L822) · [Kotlin](../../examples/cybersource/kotlin/cybersource.kt) · [Rust](../../examples/cybersource/rust/cybersource.rs#L813)

#### PaymentService.Void

Cancel an authorized payment before capture. Releases held funds back to customer, typically used when orders are cancelled or abandoned.

| | Message |
|---|---------|
| **Request** | `PaymentServiceVoidRequest` |
| **Response** | `PaymentServiceVoidResponse` |

**Examples:** [Python](../../examples/cybersource/python/cybersource.py#L955) · [JavaScript](../../examples/cybersource/javascript/cybersource.js) · [Kotlin](../../examples/cybersource/kotlin/cybersource.kt#L904) · [Rust](../../examples/cybersource/rust/cybersource.rs#L883)

### Mandates

#### RecurringPaymentService.Charge

Charge using an existing stored recurring payment instruction. Processes repeat payments for subscriptions or recurring billing without collecting payment details.

| | Message |
|---|---------|
| **Request** | `RecurringPaymentServiceChargeRequest` |
| **Response** | `RecurringPaymentServiceChargeResponse` |

**Examples:** [Python](../../examples/cybersource/python/cybersource.py#L844) · [JavaScript](../../examples/cybersource/javascript/cybersource.js#L793) · [Kotlin](../../examples/cybersource/kotlin/cybersource.kt) · [Rust](../../examples/cybersource/rust/cybersource.rs#L773)
