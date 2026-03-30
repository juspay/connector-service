# Worldpayvantiv

<!--
This file is auto-generated. Do not edit by hand.
Source: data/field_probe/worldpayvantiv.json
Regenerate: python3 scripts/generators/docs/generate.py worldpayvantiv
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
#     worldpayvantiv=payment_pb2.WorldpayvantivConfig(api_key=...),
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
    connector: 'Worldpayvantiv',
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
    .setConnector("Worldpayvantiv")
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
    connector: "Worldpayvantiv".to_string(),
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

**Examples:** [Python](../../examples/worldpayvantiv/python/worldpayvantiv.py#L111) · [JavaScript](../../examples/worldpayvantiv/javascript/worldpayvantiv.js#L100) · [Kotlin](../../examples/worldpayvantiv/kotlin/worldpayvantiv.kt#L101) · [Rust](../../examples/worldpayvantiv/rust/worldpayvantiv.rs#L106)

### Card Payment (Automatic Capture)

Authorize and capture in one call using `capture_method=AUTOMATIC`. Use for digital goods or immediate fulfillment.

**Response status handling:**

| Status | Recommended action |
|--------|-------------------|
| `AUTHORIZED` | Payment authorized and captured — funds will be settled automatically |
| `PENDING` | Payment processing — await webhook for final status before fulfilling |
| `FAILED` | Payment declined — surface error to customer, do not retry without new details |

**Examples:** [Python](../../examples/worldpayvantiv/python/worldpayvantiv.py#L136) · [JavaScript](../../examples/worldpayvantiv/javascript/worldpayvantiv.js#L126) · [Kotlin](../../examples/worldpayvantiv/kotlin/worldpayvantiv.kt#L123) · [Rust](../../examples/worldpayvantiv/rust/worldpayvantiv.rs#L129)

### Refund a Payment

Authorize with automatic capture, then refund the captured amount. `connector_transaction_id` from the Authorize response is reused for the Refund call.

**Examples:** [Python](../../examples/worldpayvantiv/python/worldpayvantiv.py#L155) · [JavaScript](../../examples/worldpayvantiv/javascript/worldpayvantiv.js#L145) · [Kotlin](../../examples/worldpayvantiv/kotlin/worldpayvantiv.kt#L139) · [Rust](../../examples/worldpayvantiv/rust/worldpayvantiv.rs#L145)

### Void a Payment

Authorize funds with a manual capture flag, then cancel the authorization with Void before any capture occurs. Releases the hold on the customer's funds.

**Examples:** [Python](../../examples/worldpayvantiv/python/worldpayvantiv.py#L180) · [JavaScript](../../examples/worldpayvantiv/javascript/worldpayvantiv.js#L171) · [Kotlin](../../examples/worldpayvantiv/kotlin/worldpayvantiv.kt#L161) · [Rust](../../examples/worldpayvantiv/rust/worldpayvantiv.rs#L168)

### Get Payment Status

Authorize a payment, then poll the connector for its current status using Get. Use this to sync payment state when webhooks are unavailable or delayed.

**Examples:** [Python](../../examples/worldpayvantiv/python/worldpayvantiv.py#L202) · [JavaScript](../../examples/worldpayvantiv/javascript/worldpayvantiv.js#L193) · [Kotlin](../../examples/worldpayvantiv/kotlin/worldpayvantiv.kt#L180) · [Rust](../../examples/worldpayvantiv/rust/worldpayvantiv.rs#L187)

## API Reference

| Flow (Service.RPC) | Category | gRPC Request Message |
|--------------------|----------|----------------------|
| [PaymentService.Authorize](#paymentserviceauthorize) | Payments | `PaymentServiceAuthorizeRequest` |
| [PaymentService.Capture](#paymentservicecapture) | Payments | `PaymentServiceCaptureRequest` |
| [PaymentService.Get](#paymentserviceget) | Payments | `PaymentServiceGetRequest` |
| [proxy_authorize](#proxy_authorize) | Other | `—` |
| [PaymentService.Refund](#paymentservicerefund) | Payments | `PaymentServiceRefundRequest` |
| [PaymentService.Reverse](#paymentservicereverse) | Payments | `PaymentServiceReverseRequest` |
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
| Google Pay | x |
| Apple Pay | x |
| SEPA | x |
| BACS | x |
| ACH | x |
| BECS | x |
| iDEAL | x |
| PayPal | x |
| BLIK | x |
| Klarna | x |
| Afterpay | x |
| UPI | x |
| Affirm | x |
| Samsung Pay | x |

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

**Examples:** [Python](../../examples/worldpayvantiv/python/worldpayvantiv.py#L224) · [JavaScript](../../examples/worldpayvantiv/javascript/worldpayvantiv.js#L214) · [Kotlin](../../examples/worldpayvantiv/kotlin/worldpayvantiv.kt#L198) · [Rust](../../examples/worldpayvantiv/rust/worldpayvantiv.rs#L205)

#### PaymentService.Capture

Finalize an authorized payment by transferring funds. Captures the authorized amount to complete the transaction and move funds to your merchant account.

| | Message |
|---|---------|
| **Request** | `PaymentServiceCaptureRequest` |
| **Response** | `PaymentServiceCaptureResponse` |

**Examples:** [Python](../../examples/worldpayvantiv/python/worldpayvantiv.py#L233) · [JavaScript](../../examples/worldpayvantiv/javascript/worldpayvantiv.js#L223) · [Kotlin](../../examples/worldpayvantiv/kotlin/worldpayvantiv.kt#L210) · [Rust](../../examples/worldpayvantiv/rust/worldpayvantiv.rs#L217)

#### PaymentService.Get

Retrieve current payment status from the payment processor. Enables synchronization between your system and payment processors for accurate state tracking.

| | Message |
|---|---------|
| **Request** | `PaymentServiceGetRequest` |
| **Response** | `PaymentServiceGetResponse` |

**Examples:** [Python](../../examples/worldpayvantiv/python/worldpayvantiv.py#L242) · [JavaScript](../../examples/worldpayvantiv/javascript/worldpayvantiv.js#L232) · [Kotlin](../../examples/worldpayvantiv/kotlin/worldpayvantiv.kt#L220) · [Rust](../../examples/worldpayvantiv/rust/worldpayvantiv.rs#L224)

#### PaymentService.Refund

Process a partial or full refund for a captured payment. Returns funds to the customer when goods are returned or services are cancelled.

| | Message |
|---|---------|
| **Request** | `PaymentServiceRefundRequest` |
| **Response** | `RefundResponse` |

**Examples:** [Python](../../examples/worldpayvantiv/python/worldpayvantiv.py#L283) · [JavaScript](../../examples/worldpayvantiv/javascript/worldpayvantiv.js#L269) · [Kotlin](../../examples/worldpayvantiv/kotlin/worldpayvantiv.kt#L248) · [Rust](../../examples/worldpayvantiv/rust/worldpayvantiv.rs#L258)

#### PaymentService.Reverse

Reverse a captured payment in full. Initiates a complete refund when you need to cancel a settled transaction rather than just an authorization.

| | Message |
|---|---------|
| **Request** | `PaymentServiceReverseRequest` |
| **Response** | `PaymentServiceReverseResponse` |

**Examples:** [Python](../../examples/worldpayvantiv/python/worldpayvantiv.py#L292) · [JavaScript](../../examples/worldpayvantiv/javascript/worldpayvantiv.js#L278) · [Kotlin](../../examples/worldpayvantiv/kotlin/worldpayvantiv.kt#L258) · [Rust](../../examples/worldpayvantiv/rust/worldpayvantiv.rs#L265)

#### PaymentService.Void

Cancel an authorized payment that has not been captured. Releases held funds back to the customer's payment method when a transaction cannot be completed.

| | Message |
|---|---------|
| **Request** | `PaymentServiceVoidRequest` |
| **Response** | `PaymentServiceVoidResponse` |

**Examples:** [Python](../../examples/worldpayvantiv/python/worldpayvantiv.py#L301) · [JavaScript](../../examples/worldpayvantiv/javascript/worldpayvantiv.js#L287) · [Kotlin](../../examples/worldpayvantiv/kotlin/worldpayvantiv.kt#L269) · [Rust](../../examples/worldpayvantiv/rust/worldpayvantiv.rs#L272)

### Other

#### proxy_authorize

**Examples:** [Python](../../examples/worldpayvantiv/python/worldpayvantiv.py#L251) · [JavaScript](../../examples/worldpayvantiv/javascript/worldpayvantiv.js#L241) · [Kotlin](../../examples/worldpayvantiv/kotlin/worldpayvantiv.kt#L228) · [Rust](../../examples/worldpayvantiv/rust/worldpayvantiv.rs#L231)
