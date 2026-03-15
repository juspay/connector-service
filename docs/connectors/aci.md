# ACI

<!--
This file is auto-generated. Do not edit by hand.
Source: data/field_probe/aci.json
Regenerate: python3 scripts/generate-connector-docs.py aci
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
    connector=payment_pb2.Connector.ACI,
    environment=sdk_config_pb2.Environment.SANDBOX,
)
# Set credentials before running (field names depend on connector auth type):
# config.auth.aci.api_key.value = "YOUR_API_KEY"

```

</details>

</td>
<td valign="top">

<details><summary>JavaScript</summary>

```javascript
const { ConnectorClient } = require('connector-service-node-ffi');

// Reuse this client for all flows
const client = new ConnectorClient({
    connector: 'Aci',
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
    .setConnector("Aci")
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
    connector: "Aci".to_string(),
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

**Examples:** [Python](../../examples/aci/python/aci.py#L23) · [JavaScript](../../examples/aci/javascript/aci.js#L22) · [Kotlin](../../examples/aci/kotlin/aci.kt#L39) · [Rust](../../examples/aci/rust/aci.rs#L26)

### Card Payment (Automatic Capture)

Authorize and capture in one call using `capture_method=AUTOMATIC`. Use for digital goods or immediate fulfillment.

**Response status handling:**

| Status | Recommended action |
|--------|-------------------|
| `AUTHORIZED` | Payment authorized and captured — funds will be settled automatically |
| `PENDING` | Payment processing — await webhook for final status before fulfilling |
| `FAILED` | Payment declined — surface error to customer, do not retry without new details |

**Examples:** [Python](../../examples/aci/python/aci.py#L127) · [JavaScript](../../examples/aci/javascript/aci.js#L121) · [Kotlin](../../examples/aci/kotlin/aci.kt#L134) · [Rust](../../examples/aci/rust/aci.rs#L123)

### Refund a Payment

Authorize with automatic capture, then refund the captured amount. `connector_transaction_id` from the Authorize response is reused for the Refund call.

**Examples:** [Python](../../examples/aci/python/aci.py#L215) · [JavaScript](../../examples/aci/javascript/aci.js#L206) · [Kotlin](../../examples/aci/kotlin/aci.kt#L216) · [Rust](../../examples/aci/rust/aci.rs#L206)

### Recurring / Mandate Payments

Store a payment mandate with SetupRecurring, then charge it repeatedly with RecurringPaymentService.Charge without requiring customer action.

**Response status handling:**

| Status | Recommended action |
|--------|-------------------|
| `PENDING` | Mandate stored — save connector_transaction_id for future RecurringPaymentService.Charge calls |
| `FAILED` | Setup failed — customer must re-enter payment details |

**Examples:** [Python](../../examples/aci/python/aci.py#L321) · [JavaScript](../../examples/aci/javascript/aci.js#L307) · [Kotlin](../../examples/aci/kotlin/aci.kt#L313) · [Rust](../../examples/aci/rust/aci.rs#L305)

### Void a Payment

Authorize funds with a manual capture flag, then cancel the authorization with Void before any capture occurs. Releases the hold on the customer's funds.

**Examples:** [Python](../../examples/aci/python/aci.py#L419) · [JavaScript](../../examples/aci/javascript/aci.js#L396) · [Kotlin](../../examples/aci/kotlin/aci.kt#L404) · [Rust](../../examples/aci/rust/aci.rs#L393)

### Get Payment Status

Authorize a payment, then poll the connector for its current status using Get. Use this to sync payment state when webhooks are unavailable or delayed.

**Examples:** [Python](../../examples/aci/python/aci.py#L516) · [JavaScript](../../examples/aci/javascript/aci.js#L487) · [Kotlin](../../examples/aci/kotlin/aci.kt#L492) · [Rust](../../examples/aci/rust/aci.rs#L482)

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
| iDEAL | ✓ |
| Klarna | ✓ |
| Afterpay | ✓ |
| Affirm | ✓ |
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

##### iDEAL

```python
"payment_method": {
    "ideal": {
        "bank_name": "Ing"  # The bank name for ideal
    }
}
```

##### Klarna

```python
"payment_method": {
    "klarna": {  # Klarna - Swedish BNPL service
    }
}
```

##### Afterpay / Clearpay

```python
"payment_method": {
    "afterpay_clearpay": {  # Afterpay/Clearpay - BNPL service
    }
}
```

##### Affirm

```python
"payment_method": {
    "affirm": {  # Affirm - US BNPL service
    }
}
```

**Examples:** [Python](../../examples/aci/python/aci.py#L616) · [JavaScript](../../examples/aci/javascript/aci.js#L580) · [Kotlin](../../examples/aci/kotlin/aci.kt#L582) · [Rust](../../examples/aci/rust/aci.rs#L573)

#### PaymentService.Capture

Finalize an authorized payment transaction. Transfers reserved funds from customer to merchant account, completing the payment lifecycle.

| | Message |
|---|---------|
| **Request** | `PaymentServiceCaptureRequest` |
| **Response** | `PaymentServiceCaptureResponse` |

**Examples:** [Python](../../examples/aci/python/aci.py#L701) · [JavaScript](../../examples/aci/javascript/aci.js#L662) · [Kotlin](../../examples/aci/kotlin/aci.kt#L660) · [Rust](../../examples/aci/rust/aci.rs#L652)

#### PaymentService.Get

Retrieve current payment status from the payment processor. Enables synchronization between your system and payment processors for accurate state tracking.

| | Message |
|---|---------|
| **Request** | `PaymentServiceGetRequest` |
| **Response** | `PaymentServiceGetResponse` |

**Examples:** [Python](../../examples/aci/python/aci.py#L724) · [JavaScript](../../examples/aci/javascript/aci.js#L681) · [Kotlin](../../examples/aci/kotlin/aci.kt#L677) · [Rust](../../examples/aci/rust/aci.rs#L665)

#### PaymentService.Refund

Initiate a refund to customer's payment method. Returns funds for returns, cancellations, or service adjustments after original payment.

| | Message |
|---|---------|
| **Request** | `PaymentServiceRefundRequest` |
| **Response** | `RefundResponse` |

**Examples:** [Python](../../examples/aci/python/aci.py) · [JavaScript](../../examples/aci/javascript/aci.js) · [Kotlin](../../examples/aci/kotlin/aci.kt#L720) · [Rust](../../examples/aci/rust/aci.rs#L702)

#### PaymentService.SetupRecurring

Setup a recurring payment instruction for future payments/ debits. This could be for SaaS subscriptions, monthly bill payments, insurance payments and similar use cases.

| | Message |
|---|---------|
| **Request** | `PaymentServiceSetupRecurringRequest` |
| **Response** | `PaymentServiceSetupRecurringResponse` |

**Examples:** [Python](../../examples/aci/python/aci.py#L776) · [JavaScript](../../examples/aci/javascript/aci.js#L724) · [Kotlin](../../examples/aci/kotlin/aci.kt) · [Rust](../../examples/aci/rust/aci.rs#L717)

#### PaymentService.Void

Cancel an authorized payment before capture. Releases held funds back to customer, typically used when orders are cancelled or abandoned.

| | Message |
|---|---------|
| **Request** | `PaymentServiceVoidRequest` |
| **Response** | `PaymentServiceVoidResponse` |

**Examples:** [Python](../../examples/aci/python/aci.py#L853) · [JavaScript](../../examples/aci/javascript/aci.js) · [Kotlin](../../examples/aci/kotlin/aci.kt#L808) · [Rust](../../examples/aci/rust/aci.rs#L786)

### Mandates

#### RecurringPaymentService.Charge

Charge using an existing stored recurring payment instruction. Processes repeat payments for subscriptions or recurring billing without collecting payment details.

| | Message |
|---|---------|
| **Request** | `RecurringPaymentServiceChargeRequest` |
| **Response** | `RecurringPaymentServiceChargeResponse` |

**Examples:** [Python](../../examples/aci/python/aci.py#L743) · [JavaScript](../../examples/aci/javascript/aci.js#L695) · [Kotlin](../../examples/aci/kotlin/aci.kt) · [Rust](../../examples/aci/rust/aci.rs#L677)
