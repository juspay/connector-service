# Powertranz

<!--
This file is auto-generated. Do not edit by hand.
Source: data/field_probe/powertranz.json
Regenerate: python3 scripts/generate-connector-docs.py powertranz
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
    connector=payment_pb2.Connector.POWERTRANZ,
    environment=sdk_config_pb2.Environment.SANDBOX,
)
# Set credentials before running (field names depend on connector auth type):
# config.auth.powertranz.api_key.value = "YOUR_API_KEY"

```

</details>

</td>
<td valign="top">

<details><summary>JavaScript</summary>

```javascript
const { ConnectorClient } = require('connector-service-node-ffi');

// Reuse this client for all flows
const client = new ConnectorClient({
    connector: 'Powertranz',
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
    .setConnector("Powertranz")
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
    connector: "Powertranz".to_string(),
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

**Examples:** [Python](../../examples/powertranz/python/powertranz.py#L22) · [JavaScript](../../examples/powertranz/javascript/powertranz.js#L22) · [Kotlin](../../examples/powertranz/kotlin/powertranz.kt#L33) · [Rust](../../examples/powertranz/rust/powertranz.rs#L26)

### Card Payment (Automatic Capture)

Authorize and capture in one call using `capture_method=AUTOMATIC`. Use for digital goods or immediate fulfillment.

**Response status handling:**

| Status | Recommended action |
|--------|-------------------|
| `AUTHORIZED` | Payment authorized and captured — funds will be settled automatically |
| `PENDING` | Payment processing — await webhook for final status before fulfilling |
| `FAILED` | Payment declined — surface error to customer, do not retry without new details |

**Examples:** [Python](../../examples/powertranz/python/powertranz.py#L126) · [JavaScript](../../examples/powertranz/javascript/powertranz.js#L121) · [Kotlin](../../examples/powertranz/kotlin/powertranz.kt#L128) · [Rust](../../examples/powertranz/rust/powertranz.rs#L123)

### Refund a Payment

Authorize with automatic capture, then refund the captured amount. `connector_transaction_id` from the Authorize response is reused for the Refund call.

**Examples:** [Python](../../examples/powertranz/python/powertranz.py#L214) · [JavaScript](../../examples/powertranz/javascript/powertranz.js#L206) · [Kotlin](../../examples/powertranz/kotlin/powertranz.kt#L210) · [Rust](../../examples/powertranz/rust/powertranz.rs#L206)

### Void a Payment

Authorize funds with a manual capture flag, then cancel the authorization with Void before any capture occurs. Releases the hold on the customer's funds.

**Examples:** [Python](../../examples/powertranz/python/powertranz.py#L320) · [JavaScript](../../examples/powertranz/javascript/powertranz.js#L307) · [Kotlin](../../examples/powertranz/kotlin/powertranz.kt#L307) · [Rust](../../examples/powertranz/rust/powertranz.rs#L305)

### Get Payment Status

Authorize a payment, then poll the connector for its current status using Get. Use this to sync payment state when webhooks are unavailable or delayed.

**Examples:** [Python](../../examples/powertranz/python/powertranz.py#L417) · [JavaScript](../../examples/powertranz/javascript/powertranz.js#L398) · [Kotlin](../../examples/powertranz/kotlin/powertranz.kt#L395) · [Rust](../../examples/powertranz/rust/powertranz.rs#L394)

## API Reference

| Flow (Service.RPC) | Category | gRPC Request Message |
|--------------------|----------|----------------------|
| [PaymentService.Authorize](#paymentserviceauthorize) | Payments | `PaymentServiceAuthorizeRequest` |
| [PaymentService.Capture](#paymentservicecapture) | Payments | `PaymentServiceCaptureRequest` |
| [PaymentService.Get](#paymentserviceget) | Payments | `PaymentServiceGetRequest` |
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

**Examples:** [Python](../../examples/powertranz/python/powertranz.py#L517) · [JavaScript](../../examples/powertranz/javascript/powertranz.js#L491) · [Kotlin](../../examples/powertranz/kotlin/powertranz.kt#L485) · [Rust](../../examples/powertranz/rust/powertranz.rs#L485)

#### PaymentService.Capture

Finalize an authorized payment transaction. Transfers reserved funds from customer to merchant account, completing the payment lifecycle.

| | Message |
|---|---------|
| **Request** | `PaymentServiceCaptureRequest` |
| **Response** | `PaymentServiceCaptureResponse` |

**Examples:** [Python](../../examples/powertranz/python/powertranz.py#L602) · [JavaScript](../../examples/powertranz/javascript/powertranz.js#L573) · [Kotlin](../../examples/powertranz/kotlin/powertranz.kt#L563) · [Rust](../../examples/powertranz/rust/powertranz.rs#L564)

#### PaymentService.Get

Retrieve current payment status from the payment processor. Enables synchronization between your system and payment processors for accurate state tracking.

| | Message |
|---|---------|
| **Request** | `PaymentServiceGetRequest` |
| **Response** | `PaymentServiceGetResponse` |

**Examples:** [Python](../../examples/powertranz/python/powertranz.py#L625) · [JavaScript](../../examples/powertranz/javascript/powertranz.js#L592) · [Kotlin](../../examples/powertranz/kotlin/powertranz.kt#L580) · [Rust](../../examples/powertranz/rust/powertranz.rs#L577)

#### PaymentService.Refund

Initiate a refund to customer's payment method. Returns funds for returns, cancellations, or service adjustments after original payment.

| | Message |
|---|---------|
| **Request** | `PaymentServiceRefundRequest` |
| **Response** | `RefundResponse` |

**Examples:** [Python](../../examples/powertranz/python/powertranz.py) · [JavaScript](../../examples/powertranz/javascript/powertranz.js) · [Kotlin](../../examples/powertranz/kotlin/powertranz.kt#L594) · [Rust](../../examples/powertranz/rust/powertranz.rs#L589)

#### PaymentService.Void

Cancel an authorized payment before capture. Releases held funds back to customer, typically used when orders are cancelled or abandoned.

| | Message |
|---|---------|
| **Request** | `PaymentServiceVoidRequest` |
| **Response** | `PaymentServiceVoidResponse` |

**Examples:** [Python](../../examples/powertranz/python/powertranz.py#L644) · [JavaScript](../../examples/powertranz/javascript/powertranz.js) · [Kotlin](../../examples/powertranz/kotlin/powertranz.kt#L613) · [Rust](../../examples/powertranz/rust/powertranz.rs#L604)
