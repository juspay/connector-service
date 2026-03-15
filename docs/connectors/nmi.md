# Nmi

<!--
This file is auto-generated. Do not edit by hand.
Source: data/field_probe/nmi.json
Regenerate: python3 scripts/generate-connector-docs.py nmi
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
#     nmi=payment_pb2.NmiConfig(api_key=...),
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
    connector: 'Nmi',
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
    .setConnector("Nmi")
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
    connector: "Nmi".to_string(),
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

**Examples:** [Python](../../examples/nmi/python/nmi.py#L130) · [JavaScript](../../examples/nmi/javascript/nmi.js#L121) · [Kotlin](../../examples/nmi/kotlin/nmi.kt#L144) · [Rust](../../examples/nmi/rust/nmi.rs#L140)

### Card Payment (Automatic Capture)

Authorize and capture in one call using `capture_method=AUTOMATIC`. Use for digital goods or immediate fulfillment.

**Response status handling:**

| Status | Recommended action |
|--------|-------------------|
| `AUTHORIZED` | Payment authorized and captured — funds will be settled automatically |
| `PENDING` | Payment processing — await webhook for final status before fulfilling |
| `FAILED` | Payment declined — surface error to customer, do not retry without new details |

**Examples:** [Python](../../examples/nmi/python/nmi.py#L155) · [JavaScript](../../examples/nmi/javascript/nmi.js#L147) · [Kotlin](../../examples/nmi/kotlin/nmi.kt#L166) · [Rust](../../examples/nmi/rust/nmi.rs#L162)

### Bank Transfer (SEPA / ACH / BACS)

Direct bank debit (Ach). Bank transfers typically use `capture_method=AUTOMATIC`.

**Response status handling:**

| Status | Recommended action |
|--------|-------------------|
| `AUTHORIZED` | Payment authorized and captured — funds will be settled automatically |
| `PENDING` | Payment processing — await webhook for final status before fulfilling |
| `FAILED` | Payment declined — surface error to customer, do not retry without new details |

**Examples:** [Python](../../examples/nmi/python/nmi.py#L174) · [JavaScript](../../examples/nmi/javascript/nmi.js#L166) · [Kotlin](../../examples/nmi/kotlin/nmi.kt#L182) · [Rust](../../examples/nmi/rust/nmi.rs#L177)

### Refund a Payment

Authorize with automatic capture, then refund the captured amount. `connector_transaction_id` from the Authorize response is reused for the Refund call.

**Examples:** [Python](../../examples/nmi/python/nmi.py#L260) · [JavaScript](../../examples/nmi/javascript/nmi.js#L249) · [Kotlin](../../examples/nmi/kotlin/nmi.kt#L262) · [Rust](../../examples/nmi/rust/nmi.rs#L258)

### Void a Payment

Authorize funds with a manual capture flag, then cancel the authorization with Void before any capture occurs. Releases the hold on the customer's funds.

**Examples:** [Python](../../examples/nmi/python/nmi.py#L297) · [JavaScript](../../examples/nmi/javascript/nmi.js#L284) · [Kotlin](../../examples/nmi/kotlin/nmi.kt#L284) · [Rust](../../examples/nmi/rust/nmi.rs#L280)

### Get Payment Status

Authorize a payment, then poll the connector for its current status using Get. Use this to sync payment state when webhooks are unavailable or delayed.

**Examples:** [Python](../../examples/nmi/python/nmi.py#L319) · [JavaScript](../../examples/nmi/javascript/nmi.js#L306) · [Kotlin](../../examples/nmi/kotlin/nmi.kt#L303) · [Rust](../../examples/nmi/rust/nmi.rs#L298)

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
| ACH | ✓ |
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

##### ACH Direct Debit

```python
"payment_method": {
    "ach": {  # Ach - Automated Clearing House
        "account_number": {"value": "000123456789"},  # Account number for ach bank debit payment
        "routing_number": {"value": "110000000"},  # Routing number for ach bank debit payment
        "bank_account_holder_name": {"value": "John Doe"}  # Bank account holder name
    }
}
```

**Examples:** [Python](../../examples/nmi/python/nmi.py#L341) · [JavaScript](../../examples/nmi/javascript/nmi.js#L327) · [Kotlin](../../examples/nmi/kotlin/nmi.kt#L321) · [Rust](../../examples/nmi/rust/nmi.rs#L315)

#### PaymentService.Capture

Finalize an authorized payment transaction. Transfers reserved funds from customer to merchant account, completing the payment lifecycle.

| | Message |
|---|---------|
| **Request** | `PaymentServiceCaptureRequest` |
| **Response** | `PaymentServiceCaptureResponse` |

**Examples:** [Python](../../examples/nmi/python/nmi.py#L350) · [JavaScript](../../examples/nmi/javascript/nmi.js#L336) · [Kotlin](../../examples/nmi/kotlin/nmi.kt#L333) · [Rust](../../examples/nmi/rust/nmi.rs#L326)

#### PaymentService.Get

Retrieve current payment status from the payment processor. Enables synchronization between your system and payment processors for accurate state tracking.

| | Message |
|---|---------|
| **Request** | `PaymentServiceGetRequest` |
| **Response** | `PaymentServiceGetResponse` |

**Examples:** [Python](../../examples/nmi/python/nmi.py#L359) · [JavaScript](../../examples/nmi/javascript/nmi.js#L345) · [Kotlin](../../examples/nmi/kotlin/nmi.kt#L343) · [Rust](../../examples/nmi/rust/nmi.rs#L332)

#### PaymentService.Refund

Initiate a refund to customer's payment method. Returns funds for returns, cancellations, or service adjustments after original payment.

| | Message |
|---|---------|
| **Request** | `PaymentServiceRefundRequest` |
| **Response** | `RefundResponse` |

**Examples:** [Python](../../examples/nmi/python/nmi.py#L260) · [JavaScript](../../examples/nmi/javascript/nmi.js#L249) · [Kotlin](../../examples/nmi/kotlin/nmi.kt#L351) · [Rust](../../examples/nmi/rust/nmi.rs#L338)

#### PaymentService.Void

Cancel an authorized payment before capture. Releases held funds back to customer, typically used when orders are cancelled or abandoned.

| | Message |
|---|---------|
| **Request** | `PaymentServiceVoidRequest` |
| **Response** | `PaymentServiceVoidResponse` |

**Examples:** [Python](../../examples/nmi/python/nmi.py#L368) · [JavaScript](../../examples/nmi/javascript/nmi.js#L354) · [Kotlin](../../examples/nmi/kotlin/nmi.kt#L361) · [Rust](../../examples/nmi/rust/nmi.rs#L344)
