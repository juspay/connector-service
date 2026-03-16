# Trustpayments

<!--
This file is auto-generated. Do not edit by hand.
Source: data/field_probe/trustpayments.json
Regenerate: python3 scripts/generate-connector-docs.py trustpayments
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
#     trustpayments=payment_pb2.TrustpaymentsConfig(api_key=...),
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
    connector: 'Trustpayments',
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
    .setConnector("Trustpayments")
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
    connector: "Trustpayments".to_string(),
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

**Examples:** [Python](../../examples/trustpayments/python/trustpayments.py#L85) · [JavaScript](../../examples/trustpayments/javascript/trustpayments.js#L76) · [Kotlin](../../examples/trustpayments/kotlin/trustpayments.kt#L98) · [Rust](../../examples/trustpayments/rust/trustpayments.rs#L95)

### Card Payment (Automatic Capture)

Authorize and capture in one call using `capture_method=AUTOMATIC`. Use for digital goods or immediate fulfillment.

**Response status handling:**

| Status | Recommended action |
|--------|-------------------|
| `AUTHORIZED` | Payment authorized and captured — funds will be settled automatically |
| `PENDING` | Payment processing — await webhook for final status before fulfilling |
| `FAILED` | Payment declined — surface error to customer, do not retry without new details |

**Examples:** [Python](../../examples/trustpayments/python/trustpayments.py#L110) · [JavaScript](../../examples/trustpayments/javascript/trustpayments.js#L102) · [Kotlin](../../examples/trustpayments/kotlin/trustpayments.kt#L120) · [Rust](../../examples/trustpayments/rust/trustpayments.rs#L117)

### Refund a Payment

Authorize with automatic capture, then refund the captured amount. `connector_transaction_id` from the Authorize response is reused for the Refund call.

**Examples:** [Python](../../examples/trustpayments/python/trustpayments.py#L129) · [JavaScript](../../examples/trustpayments/javascript/trustpayments.js#L121) · [Kotlin](../../examples/trustpayments/kotlin/trustpayments.kt#L136) · [Rust](../../examples/trustpayments/rust/trustpayments.rs#L132)

### Void a Payment

Authorize funds with a manual capture flag, then cancel the authorization with Void before any capture occurs. Releases the hold on the customer's funds.

**Examples:** [Python](../../examples/trustpayments/python/trustpayments.py#L166) · [JavaScript](../../examples/trustpayments/javascript/trustpayments.js#L156) · [Kotlin](../../examples/trustpayments/kotlin/trustpayments.kt#L158) · [Rust](../../examples/trustpayments/rust/trustpayments.rs#L154)

### Get Payment Status

Authorize a payment, then poll the connector for its current status using Get. Use this to sync payment state when webhooks are unavailable or delayed.

**Examples:** [Python](../../examples/trustpayments/python/trustpayments.py#L188) · [JavaScript](../../examples/trustpayments/javascript/trustpayments.js#L178) · [Kotlin](../../examples/trustpayments/kotlin/trustpayments.kt#L177) · [Rust](../../examples/trustpayments/rust/trustpayments.rs#L172)

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
| Google Pay | ⚠ |
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

**Examples:** [Python](../../examples/trustpayments/python/trustpayments.py#L210) · [JavaScript](../../examples/trustpayments/javascript/trustpayments.js#L199) · [Kotlin](../../examples/trustpayments/kotlin/trustpayments.kt#L195) · [Rust](../../examples/trustpayments/rust/trustpayments.rs#L189)

#### PaymentService.Capture

Finalize an authorized payment transaction. Transfers reserved funds from customer to merchant account, completing the payment lifecycle.

| | Message |
|---|---------|
| **Request** | `PaymentServiceCaptureRequest` |
| **Response** | `PaymentServiceCaptureResponse` |

**Examples:** [Python](../../examples/trustpayments/python/trustpayments.py#L219) · [JavaScript](../../examples/trustpayments/javascript/trustpayments.js#L208) · [Kotlin](../../examples/trustpayments/kotlin/trustpayments.kt#L207) · [Rust](../../examples/trustpayments/rust/trustpayments.rs#L200)

#### PaymentService.Get

Retrieve current payment status from the payment processor. Enables synchronization between your system and payment processors for accurate state tracking.

| | Message |
|---|---------|
| **Request** | `PaymentServiceGetRequest` |
| **Response** | `PaymentServiceGetResponse` |

**Examples:** [Python](../../examples/trustpayments/python/trustpayments.py#L228) · [JavaScript](../../examples/trustpayments/javascript/trustpayments.js#L217) · [Kotlin](../../examples/trustpayments/kotlin/trustpayments.kt#L217) · [Rust](../../examples/trustpayments/rust/trustpayments.rs#L206)

#### PaymentService.Refund

Initiate a refund to customer's payment method. Returns funds for returns, cancellations, or service adjustments after original payment.

| | Message |
|---|---------|
| **Request** | `PaymentServiceRefundRequest` |
| **Response** | `RefundResponse` |

**Examples:** [Python](../../examples/trustpayments/python/trustpayments.py#L129) · [JavaScript](../../examples/trustpayments/javascript/trustpayments.js#L121) · [Kotlin](../../examples/trustpayments/kotlin/trustpayments.kt#L225) · [Rust](../../examples/trustpayments/rust/trustpayments.rs#L212)

#### PaymentService.Void

Cancel an authorized payment before capture. Releases held funds back to customer, typically used when orders are cancelled or abandoned.

| | Message |
|---|---------|
| **Request** | `PaymentServiceVoidRequest` |
| **Response** | `PaymentServiceVoidResponse` |

**Examples:** [Python](../../examples/trustpayments/python/trustpayments.py#L237) · [JavaScript](../../examples/trustpayments/javascript/trustpayments.js#L226) · [Kotlin](../../examples/trustpayments/kotlin/trustpayments.kt#L235) · [Rust](../../examples/trustpayments/rust/trustpayments.rs#L218)
