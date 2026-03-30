# Fiuu

<!--
This file is auto-generated. Do not edit by hand.
Source: data/field_probe/fiuu.json
Regenerate: python3 scripts/generators/docs/generate.py fiuu
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
    options=sdk_config_pb2.SdkOptions(environment=sdk_config_pb2.Environment.SANDBOX),
)
# Set credentials before running (field names depend on connector auth type):
# config.connector_config.CopyFrom(payment_pb2.ConnectorSpecificConfig(
#     fiuu=payment_pb2.FiuuConfig(api_key=...),
# ))

```

</details>

</td>
<td valign="top">

<details><summary>JavaScript</summary>

```javascript
const { ConnectorClient } = require('connector-service-node-ffi');

// Reuse this client for all flows
const client = new ConnectorClient({
    connector: 'Fiuu',
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
    .setConnector("Fiuu")
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
    connector: "Fiuu".to_string(),
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

**Examples:** [Python](../../examples/fiuu/python/fiuu.py#L138) · [JavaScript](../../examples/fiuu/javascript/fiuu.js#L126) · [Kotlin](../../examples/fiuu/kotlin/fiuu.kt#L105) · [Rust](../../examples/fiuu/rust/fiuu.rs#L134)

### Card Payment (Automatic Capture)

Authorize and capture in one call using `capture_method=AUTOMATIC`. Use for digital goods or immediate fulfillment.

**Response status handling:**

| Status | Recommended action |
|--------|-------------------|
| `AUTHORIZED` | Payment authorized and captured — funds will be settled automatically |
| `PENDING` | Payment processing — await webhook for final status before fulfilling |
| `FAILED` | Payment declined — surface error to customer, do not retry without new details |

**Examples:** [Python](../../examples/fiuu/python/fiuu.py#L163) · [JavaScript](../../examples/fiuu/javascript/fiuu.js#L152) · [Kotlin](../../examples/fiuu/kotlin/fiuu.kt#L127) · [Rust](../../examples/fiuu/rust/fiuu.rs#L157)

### Wallet Payment (Google Pay / Apple Pay)

Wallet payments pass an encrypted token from the browser/device SDK. Pass the token blob directly — do not decrypt client-side.

**Response status handling:**

| Status | Recommended action |
|--------|-------------------|
| `AUTHORIZED` | Payment authorized and captured — funds will be settled automatically |
| `PENDING` | Payment processing — await webhook for final status before fulfilling |
| `FAILED` | Payment declined — surface error to customer, do not retry without new details |

**Examples:** [Python](../../examples/fiuu/python/fiuu.py#L182) · [JavaScript](../../examples/fiuu/javascript/fiuu.js#L171) · [Kotlin](../../examples/fiuu/kotlin/fiuu.kt#L143) · [Rust](../../examples/fiuu/rust/fiuu.rs#L173)

### Refund a Payment

Authorize with automatic capture, then refund the captured amount. `connector_transaction_id` from the Authorize response is reused for the Refund call.

**Examples:** [Python](../../examples/fiuu/python/fiuu.py#L234) · [JavaScript](../../examples/fiuu/javascript/fiuu.js#L220) · [Kotlin](../../examples/fiuu/kotlin/fiuu.kt#L189) · [Rust](../../examples/fiuu/rust/fiuu.rs#L222)

### Void a Payment

Authorize funds with a manual capture flag, then cancel the authorization with Void before any capture occurs. Releases the hold on the customer's funds.

**Examples:** [Python](../../examples/fiuu/python/fiuu.py#L259) · [JavaScript](../../examples/fiuu/javascript/fiuu.js#L246) · [Kotlin](../../examples/fiuu/kotlin/fiuu.kt#L211) · [Rust](../../examples/fiuu/rust/fiuu.rs#L245)

### Get Payment Status

Authorize a payment, then poll the connector for its current status using Get. Use this to sync payment state when webhooks are unavailable or delayed.

**Examples:** [Python](../../examples/fiuu/python/fiuu.py#L281) · [JavaScript](../../examples/fiuu/javascript/fiuu.js#L268) · [Kotlin](../../examples/fiuu/kotlin/fiuu.kt#L230) · [Rust](../../examples/fiuu/rust/fiuu.rs#L264)

## API Reference

| Flow (Service.RPC) | Category | gRPC Request Message |
|--------------------|----------|----------------------|
| [PaymentService.Authorize](#paymentserviceauthorize) | Payments | `PaymentServiceAuthorizeRequest` |
| [PaymentService.Capture](#paymentservicecapture) | Payments | `PaymentServiceCaptureRequest` |
| [PaymentService.Get](#paymentserviceget) | Payments | `PaymentServiceGetRequest` |
| [proxy_authorize](#proxy_authorize) | Other | `—` |
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
| Apple Pay | ⚠ |
| SEPA | ⚠ |
| BACS | ⚠ |
| ACH | ⚠ |
| BECS | ⚠ |
| iDEAL | ⚠ |
| PayPal | ⚠ |
| BLIK | ⚠ |
| Klarna | ⚠ |
| Afterpay | ⚠ |
| UPI | ⚠ |
| Affirm | ⚠ |
| Samsung Pay | ⚠ |

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
                "token_type": "PAYMENT_GATEWAY",  # The type of the token
                "token": "{\"id\":\"tok_probe_gpay\",\"object\":\"token\",\"type\":\"card\"}"  # Token generated for the wallet
            }
        }
    }
}
```

**Examples:** [Python](../../examples/fiuu/python/fiuu.py#L303) · [JavaScript](../../examples/fiuu/javascript/fiuu.js#L289) · [Kotlin](../../examples/fiuu/kotlin/fiuu.kt#L248) · [Rust](../../examples/fiuu/rust/fiuu.rs#L282)

#### PaymentService.Capture

Finalize an authorized payment by transferring funds. Captures the authorized amount to complete the transaction and move funds to your merchant account.

| | Message |
|---|---------|
| **Request** | `PaymentServiceCaptureRequest` |
| **Response** | `PaymentServiceCaptureResponse` |

**Examples:** [Python](../../examples/fiuu/python/fiuu.py#L312) · [JavaScript](../../examples/fiuu/javascript/fiuu.js#L298) · [Kotlin](../../examples/fiuu/kotlin/fiuu.kt#L260) · [Rust](../../examples/fiuu/rust/fiuu.rs#L294)

#### PaymentService.Get

Retrieve current payment status from the payment processor. Enables synchronization between your system and payment processors for accurate state tracking.

| | Message |
|---|---------|
| **Request** | `PaymentServiceGetRequest` |
| **Response** | `PaymentServiceGetResponse` |

**Examples:** [Python](../../examples/fiuu/python/fiuu.py#L321) · [JavaScript](../../examples/fiuu/javascript/fiuu.js#L307) · [Kotlin](../../examples/fiuu/kotlin/fiuu.kt#L270) · [Rust](../../examples/fiuu/rust/fiuu.rs#L301)

#### PaymentService.Refund

Process a partial or full refund for a captured payment. Returns funds to the customer when goods are returned or services are cancelled.

| | Message |
|---|---------|
| **Request** | `PaymentServiceRefundRequest` |
| **Response** | `RefundResponse` |

**Examples:** [Python](../../examples/fiuu/python/fiuu.py#L372) · [JavaScript](../../examples/fiuu/javascript/fiuu.js#L354) · [Kotlin](../../examples/fiuu/kotlin/fiuu.kt#L330) · [Rust](../../examples/fiuu/rust/fiuu.rs#L343)

#### PaymentService.Void

Cancel an authorized payment that has not been captured. Releases held funds back to the customer's payment method when a transaction cannot be completed.

| | Message |
|---|---------|
| **Request** | `PaymentServiceVoidRequest` |
| **Response** | `PaymentServiceVoidResponse` |

**Examples:** [Python](../../examples/fiuu/python/fiuu.py#L381) · [JavaScript](../../examples/fiuu/javascript/fiuu.js#L363) · [Kotlin](../../examples/fiuu/kotlin/fiuu.kt#L340) · [Rust](../../examples/fiuu/rust/fiuu.rs#L350)

### Mandates

#### RecurringPaymentService.Charge

Charge using an existing stored recurring payment instruction. Processes repeat payments for subscriptions or recurring billing without collecting payment details.

| | Message |
|---|---------|
| **Request** | `RecurringPaymentServiceChargeRequest` |
| **Response** | `RecurringPaymentServiceChargeResponse` |

**Examples:** [Python](../../examples/fiuu/python/fiuu.py#L363) · [JavaScript](../../examples/fiuu/javascript/fiuu.js#L345) · [Kotlin](../../examples/fiuu/kotlin/fiuu.kt#L299) · [Rust](../../examples/fiuu/rust/fiuu.rs#L336)

### Other

#### proxy_authorize

**Examples:** [Python](../../examples/fiuu/python/fiuu.py#L330) · [JavaScript](../../examples/fiuu/javascript/fiuu.js#L316) · [Kotlin](../../examples/fiuu/kotlin/fiuu.kt#L278) · [Rust](../../examples/fiuu/rust/fiuu.rs#L308)
