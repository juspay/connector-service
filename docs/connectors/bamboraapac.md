# Bamboraapac

<!--
This file is auto-generated. Do not edit by hand.
Source: data/field_probe/bamboraapac.json
Regenerate: python3 scripts/generate-connector-docs.py bamboraapac
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
#     bamboraapac=payment_pb2.BamboraapacConfig(api_key=...),
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
    connector: 'Bamboraapac',
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
    .setConnector("Bamboraapac")
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
    connector: "Bamboraapac".to_string(),
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

**Examples:** [Python](../../examples/bamboraapac/python/bamboraapac.py#L122) · [JavaScript](../../examples/bamboraapac/javascript/bamboraapac.js#L114) · [Kotlin](../../examples/bamboraapac/kotlin/bamboraapac.kt#L142) · [Rust](../../examples/bamboraapac/rust/bamboraapac.rs#L133)

### Card Payment (Automatic Capture)

Authorize and capture in one call using `capture_method=AUTOMATIC`. Use for digital goods or immediate fulfillment.

**Response status handling:**

| Status | Recommended action |
|--------|-------------------|
| `AUTHORIZED` | Payment authorized and captured — funds will be settled automatically |
| `PENDING` | Payment processing — await webhook for final status before fulfilling |
| `FAILED` | Payment declined — surface error to customer, do not retry without new details |

**Examples:** [Python](../../examples/bamboraapac/python/bamboraapac.py#L147) · [JavaScript](../../examples/bamboraapac/javascript/bamboraapac.js#L140) · [Kotlin](../../examples/bamboraapac/kotlin/bamboraapac.kt#L164) · [Rust](../../examples/bamboraapac/rust/bamboraapac.rs#L155)

### Refund a Payment

Authorize with automatic capture, then refund the captured amount. `connector_transaction_id` from the Authorize response is reused for the Refund call.

**Examples:** [Python](../../examples/bamboraapac/python/bamboraapac.py#L166) · [JavaScript](../../examples/bamboraapac/javascript/bamboraapac.js#L159) · [Kotlin](../../examples/bamboraapac/kotlin/bamboraapac.kt#L180) · [Rust](../../examples/bamboraapac/rust/bamboraapac.rs#L170)

### Recurring / Mandate Payments

Store a payment mandate with SetupRecurring, then charge it repeatedly with RecurringPaymentService.Charge without requiring customer action.

**Response status handling:**

| Status | Recommended action |
|--------|-------------------|
| `PENDING` | Mandate stored — save connector_transaction_id for future RecurringPaymentService.Charge calls |
| `FAILED` | Setup failed — customer must re-enter payment details |

**Examples:** [Python](../../examples/bamboraapac/python/bamboraapac.py#L203) · [JavaScript](../../examples/bamboraapac/javascript/bamboraapac.js#L194) · [Kotlin](../../examples/bamboraapac/kotlin/bamboraapac.kt#L202) · [Rust](../../examples/bamboraapac/rust/bamboraapac.rs#L192)

### Get Payment Status

Authorize a payment, then poll the connector for its current status using Get. Use this to sync payment state when webhooks are unavailable or delayed.

**Examples:** [Python](../../examples/bamboraapac/python/bamboraapac.py#L301) · [JavaScript](../../examples/bamboraapac/javascript/bamboraapac.js#L283) · [Kotlin](../../examples/bamboraapac/kotlin/bamboraapac.kt#L293) · [Rust](../../examples/bamboraapac/rust/bamboraapac.rs#L280)

## API Reference

| Flow (Service.RPC) | Category | gRPC Request Message |
|--------------------|----------|----------------------|
| [PaymentService.Authorize](#paymentserviceauthorize) | Payments | `PaymentServiceAuthorizeRequest` |
| [PaymentService.Capture](#paymentservicecapture) | Payments | `PaymentServiceCaptureRequest` |
| [PaymentService.Get](#paymentserviceget) | Payments | `PaymentServiceGetRequest` |
| [RecurringPaymentService.Charge](#recurringpaymentservicecharge) | Mandates | `RecurringPaymentServiceChargeRequest` |
| [PaymentService.Refund](#paymentservicerefund) | Payments | `PaymentServiceRefundRequest` |
| [PaymentService.SetupRecurring](#paymentservicesetuprecurring) | Payments | `PaymentServiceSetupRecurringRequest` |

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

**Examples:** [Python](../../examples/bamboraapac/python/bamboraapac.py#L323) · [JavaScript](../../examples/bamboraapac/javascript/bamboraapac.js#L304) · [Kotlin](../../examples/bamboraapac/kotlin/bamboraapac.kt#L311) · [Rust](../../examples/bamboraapac/rust/bamboraapac.rs#L297)

#### PaymentService.Capture

Finalize an authorized payment transaction. Transfers reserved funds from customer to merchant account, completing the payment lifecycle.

| | Message |
|---|---------|
| **Request** | `PaymentServiceCaptureRequest` |
| **Response** | `PaymentServiceCaptureResponse` |

**Examples:** [Python](../../examples/bamboraapac/python/bamboraapac.py#L332) · [JavaScript](../../examples/bamboraapac/javascript/bamboraapac.js#L313) · [Kotlin](../../examples/bamboraapac/kotlin/bamboraapac.kt#L323) · [Rust](../../examples/bamboraapac/rust/bamboraapac.rs#L308)

#### PaymentService.Get

Retrieve current payment status from the payment processor. Enables synchronization between your system and payment processors for accurate state tracking.

| | Message |
|---|---------|
| **Request** | `PaymentServiceGetRequest` |
| **Response** | `PaymentServiceGetResponse` |

**Examples:** [Python](../../examples/bamboraapac/python/bamboraapac.py#L341) · [JavaScript](../../examples/bamboraapac/javascript/bamboraapac.js#L322) · [Kotlin](../../examples/bamboraapac/kotlin/bamboraapac.kt#L333) · [Rust](../../examples/bamboraapac/rust/bamboraapac.rs#L314)

#### PaymentService.Refund

Initiate a refund to customer's payment method. Returns funds for returns, cancellations, or service adjustments after original payment.

| | Message |
|---|---------|
| **Request** | `PaymentServiceRefundRequest` |
| **Response** | `RefundResponse` |

**Examples:** [Python](../../examples/bamboraapac/python/bamboraapac.py#L166) · [JavaScript](../../examples/bamboraapac/javascript/bamboraapac.js#L159) · [Kotlin](../../examples/bamboraapac/kotlin/bamboraapac.kt#L370) · [Rust](../../examples/bamboraapac/rust/bamboraapac.rs#L345)

#### PaymentService.SetupRecurring

Setup a recurring payment instruction for future payments/ debits. This could be for SaaS subscriptions, monthly bill payments, insurance payments and similar use cases.

| | Message |
|---|---------|
| **Request** | `PaymentServiceSetupRecurringRequest` |
| **Response** | `PaymentServiceSetupRecurringResponse` |

**Examples:** [Python](../../examples/bamboraapac/python/bamboraapac.py#L383) · [JavaScript](../../examples/bamboraapac/javascript/bamboraapac.js#L360) · [Kotlin](../../examples/bamboraapac/kotlin/bamboraapac.kt#L380) · [Rust](../../examples/bamboraapac/rust/bamboraapac.rs#L351)

### Mandates

#### RecurringPaymentService.Charge

Charge using an existing stored recurring payment instruction. Processes repeat payments for subscriptions or recurring billing without collecting payment details.

| | Message |
|---|---------|
| **Request** | `RecurringPaymentServiceChargeRequest` |
| **Response** | `RecurringPaymentServiceChargeResponse` |

**Examples:** [Python](../../examples/bamboraapac/python/bamboraapac.py#L350) · [JavaScript](../../examples/bamboraapac/javascript/bamboraapac.js#L331) · [Kotlin](../../examples/bamboraapac/kotlin/bamboraapac.kt#L341) · [Rust](../../examples/bamboraapac/rust/bamboraapac.rs#L320)
