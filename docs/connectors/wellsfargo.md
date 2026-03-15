# Wellsfargo

<!--
This file is auto-generated. Do not edit by hand.
Source: data/field_probe/wellsfargo.json
Regenerate: python3 scripts/generate-connector-docs.py wellsfargo
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
#     wellsfargo=payment_pb2.WellsfargoConfig(api_key=...),
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
    connector: 'Wellsfargo',
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
    .setConnector("Wellsfargo")
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
    connector: "Wellsfargo".to_string(),
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

**Examples:** [Python](../../examples/wellsfargo/python/wellsfargo.py#L134) · [JavaScript](../../examples/wellsfargo/javascript/wellsfargo.js#L125) · [Kotlin](../../examples/wellsfargo/kotlin/wellsfargo.kt#L151) · [Rust](../../examples/wellsfargo/rust/wellsfargo.rs#L144)

### Card Payment (Automatic Capture)

Authorize and capture in one call using `capture_method=AUTOMATIC`. Use for digital goods or immediate fulfillment.

**Response status handling:**

| Status | Recommended action |
|--------|-------------------|
| `AUTHORIZED` | Payment authorized and captured — funds will be settled automatically |
| `PENDING` | Payment processing — await webhook for final status before fulfilling |
| `FAILED` | Payment declined — surface error to customer, do not retry without new details |

**Examples:** [Python](../../examples/wellsfargo/python/wellsfargo.py#L159) · [JavaScript](../../examples/wellsfargo/javascript/wellsfargo.js#L151) · [Kotlin](../../examples/wellsfargo/kotlin/wellsfargo.kt#L173) · [Rust](../../examples/wellsfargo/rust/wellsfargo.rs#L166)

### Refund a Payment

Authorize with automatic capture, then refund the captured amount. `connector_transaction_id` from the Authorize response is reused for the Refund call.

**Examples:** [Python](../../examples/wellsfargo/python/wellsfargo.py#L178) · [JavaScript](../../examples/wellsfargo/javascript/wellsfargo.js#L170) · [Kotlin](../../examples/wellsfargo/kotlin/wellsfargo.kt#L189) · [Rust](../../examples/wellsfargo/rust/wellsfargo.rs#L181)

### Void a Payment

Authorize funds with a manual capture flag, then cancel the authorization with Void before any capture occurs. Releases the hold on the customer's funds.

**Examples:** [Python](../../examples/wellsfargo/python/wellsfargo.py#L215) · [JavaScript](../../examples/wellsfargo/javascript/wellsfargo.js#L205) · [Kotlin](../../examples/wellsfargo/kotlin/wellsfargo.kt#L211) · [Rust](../../examples/wellsfargo/rust/wellsfargo.rs#L203)

### Get Payment Status

Authorize a payment, then poll the connector for its current status using Get. Use this to sync payment state when webhooks are unavailable or delayed.

**Examples:** [Python](../../examples/wellsfargo/python/wellsfargo.py#L237) · [JavaScript](../../examples/wellsfargo/javascript/wellsfargo.js#L227) · [Kotlin](../../examples/wellsfargo/kotlin/wellsfargo.kt#L230) · [Rust](../../examples/wellsfargo/rust/wellsfargo.rs#L221)

## API Reference

| Flow (Service.RPC) | Category | gRPC Request Message |
|--------------------|----------|----------------------|
| [PaymentService.Authorize](#paymentserviceauthorize) | Payments | `PaymentServiceAuthorizeRequest` |
| [PaymentService.Capture](#paymentservicecapture) | Payments | `PaymentServiceCaptureRequest` |
| [PaymentService.Get](#paymentserviceget) | Payments | `PaymentServiceGetRequest` |
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

**Examples:** [Python](../../examples/wellsfargo/python/wellsfargo.py#L259) · [JavaScript](../../examples/wellsfargo/javascript/wellsfargo.js#L248) · [Kotlin](../../examples/wellsfargo/kotlin/wellsfargo.kt#L248) · [Rust](../../examples/wellsfargo/rust/wellsfargo.rs#L238)

#### PaymentService.Capture

Finalize an authorized payment transaction. Transfers reserved funds from customer to merchant account, completing the payment lifecycle.

| | Message |
|---|---------|
| **Request** | `PaymentServiceCaptureRequest` |
| **Response** | `PaymentServiceCaptureResponse` |

**Examples:** [Python](../../examples/wellsfargo/python/wellsfargo.py#L268) · [JavaScript](../../examples/wellsfargo/javascript/wellsfargo.js#L257) · [Kotlin](../../examples/wellsfargo/kotlin/wellsfargo.kt#L260) · [Rust](../../examples/wellsfargo/rust/wellsfargo.rs#L249)

#### PaymentService.Get

Retrieve current payment status from the payment processor. Enables synchronization between your system and payment processors for accurate state tracking.

| | Message |
|---|---------|
| **Request** | `PaymentServiceGetRequest` |
| **Response** | `PaymentServiceGetResponse` |

**Examples:** [Python](../../examples/wellsfargo/python/wellsfargo.py#L277) · [JavaScript](../../examples/wellsfargo/javascript/wellsfargo.js#L266) · [Kotlin](../../examples/wellsfargo/kotlin/wellsfargo.kt#L270) · [Rust](../../examples/wellsfargo/rust/wellsfargo.rs#L255)

#### PaymentService.Refund

Initiate a refund to customer's payment method. Returns funds for returns, cancellations, or service adjustments after original payment.

| | Message |
|---|---------|
| **Request** | `PaymentServiceRefundRequest` |
| **Response** | `RefundResponse` |

**Examples:** [Python](../../examples/wellsfargo/python/wellsfargo.py#L178) · [JavaScript](../../examples/wellsfargo/javascript/wellsfargo.js#L170) · [Kotlin](../../examples/wellsfargo/kotlin/wellsfargo.kt#L278) · [Rust](../../examples/wellsfargo/rust/wellsfargo.rs#L261)

#### PaymentService.SetupRecurring

Setup a recurring payment instruction for future payments/ debits. This could be for SaaS subscriptions, monthly bill payments, insurance payments and similar use cases.

| | Message |
|---|---------|
| **Request** | `PaymentServiceSetupRecurringRequest` |
| **Response** | `PaymentServiceSetupRecurringResponse` |

**Examples:** [Python](../../examples/wellsfargo/python/wellsfargo.py#L286) · [JavaScript](../../examples/wellsfargo/javascript/wellsfargo.js#L275) · [Kotlin](../../examples/wellsfargo/kotlin/wellsfargo.kt#L288) · [Rust](../../examples/wellsfargo/rust/wellsfargo.rs#L267)

#### PaymentService.Void

Cancel an authorized payment before capture. Releases held funds back to customer, typically used when orders are cancelled or abandoned.

| | Message |
|---|---------|
| **Request** | `PaymentServiceVoidRequest` |
| **Response** | `PaymentServiceVoidResponse` |

**Examples:** [Python](../../examples/wellsfargo/python/wellsfargo.py#L363) · [JavaScript](../../examples/wellsfargo/javascript/wellsfargo.js#L345) · [Kotlin](../../examples/wellsfargo/kotlin/wellsfargo.kt#L357) · [Rust](../../examples/wellsfargo/rust/wellsfargo.rs#L336)
