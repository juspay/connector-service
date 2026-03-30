# Bamboraapac

<!--
This file is auto-generated. Do not edit by hand.
Source: data/field_probe/bamboraapac.json
Regenerate: python3 scripts/generators/docs/generate.py bamboraapac
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

**Examples:** [Python](../../examples/bamboraapac/python/bamboraapac.py#L155) · [JavaScript](../../examples/bamboraapac/javascript/bamboraapac.js#L143) · [Kotlin](../../examples/bamboraapac/kotlin/bamboraapac.kt#L96) · [Rust](../../examples/bamboraapac/rust/bamboraapac.rs#L153)

### Card Payment (Automatic Capture)

Authorize and capture in one call using `capture_method=AUTOMATIC`. Use for digital goods or immediate fulfillment.

**Response status handling:**

| Status | Recommended action |
|--------|-------------------|
| `AUTHORIZED` | Payment authorized and captured — funds will be settled automatically |
| `PENDING` | Payment processing — await webhook for final status before fulfilling |
| `FAILED` | Payment declined — surface error to customer, do not retry without new details |

**Examples:** [Python](../../examples/bamboraapac/python/bamboraapac.py#L180) · [JavaScript](../../examples/bamboraapac/javascript/bamboraapac.js#L169) · [Kotlin](../../examples/bamboraapac/kotlin/bamboraapac.kt#L118) · [Rust](../../examples/bamboraapac/rust/bamboraapac.rs#L176)

### Refund a Payment

Authorize with automatic capture, then refund the captured amount. `connector_transaction_id` from the Authorize response is reused for the Refund call.

**Examples:** [Python](../../examples/bamboraapac/python/bamboraapac.py#L199) · [JavaScript](../../examples/bamboraapac/javascript/bamboraapac.js#L188) · [Kotlin](../../examples/bamboraapac/kotlin/bamboraapac.kt#L134) · [Rust](../../examples/bamboraapac/rust/bamboraapac.rs#L192)

### Recurring / Mandate Payments

Store a payment mandate with SetupRecurring, then charge it repeatedly with RecurringPaymentService.Charge without requiring customer action.

**Response status handling:**

| Status | Recommended action |
|--------|-------------------|
| `PENDING` | Mandate stored — save connector_transaction_id for future RecurringPaymentService.Charge calls |
| `FAILED` | Setup failed — customer must re-enter payment details |

**Examples:** [Python](../../examples/bamboraapac/python/bamboraapac.py#L224) · [JavaScript](../../examples/bamboraapac/javascript/bamboraapac.js#L214) · [Kotlin](../../examples/bamboraapac/kotlin/bamboraapac.kt#L156) · [Rust](../../examples/bamboraapac/rust/bamboraapac.rs#L215)

### Get Payment Status

Authorize a payment, then poll the connector for its current status using Get. Use this to sync payment state when webhooks are unavailable or delayed.

**Examples:** [Python](../../examples/bamboraapac/python/bamboraapac.py#L293) · [JavaScript](../../examples/bamboraapac/javascript/bamboraapac.js#L274) · [Kotlin](../../examples/bamboraapac/kotlin/bamboraapac.kt#L216) · [Rust](../../examples/bamboraapac/rust/bamboraapac.rs#L275)

## API Reference

| Flow (Service.RPC) | Category | gRPC Request Message |
|--------------------|----------|----------------------|
| [PaymentService.Authorize](#paymentserviceauthorize) | Payments | `PaymentServiceAuthorizeRequest` |
| [PaymentService.Capture](#paymentservicecapture) | Payments | `PaymentServiceCaptureRequest` |
| [PaymentService.Get](#paymentserviceget) | Payments | `PaymentServiceGetRequest` |
| [proxy_authorize](#proxy_authorize) | Other | `—` |
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

**Examples:** [Python](../../examples/bamboraapac/python/bamboraapac.py#L315) · [JavaScript](../../examples/bamboraapac/javascript/bamboraapac.js#L295) · [Kotlin](../../examples/bamboraapac/kotlin/bamboraapac.kt#L234) · [Rust](../../examples/bamboraapac/rust/bamboraapac.rs#L293)

#### PaymentService.Capture

Finalize an authorized payment by transferring funds. Captures the authorized amount to complete the transaction and move funds to your merchant account.

| | Message |
|---|---------|
| **Request** | `PaymentServiceCaptureRequest` |
| **Response** | `PaymentServiceCaptureResponse` |

**Examples:** [Python](../../examples/bamboraapac/python/bamboraapac.py#L324) · [JavaScript](../../examples/bamboraapac/javascript/bamboraapac.js#L304) · [Kotlin](../../examples/bamboraapac/kotlin/bamboraapac.kt#L246) · [Rust](../../examples/bamboraapac/rust/bamboraapac.rs#L305)

#### PaymentService.Get

Retrieve current payment status from the payment processor. Enables synchronization between your system and payment processors for accurate state tracking.

| | Message |
|---|---------|
| **Request** | `PaymentServiceGetRequest` |
| **Response** | `PaymentServiceGetResponse` |

**Examples:** [Python](../../examples/bamboraapac/python/bamboraapac.py#L333) · [JavaScript](../../examples/bamboraapac/javascript/bamboraapac.js#L313) · [Kotlin](../../examples/bamboraapac/kotlin/bamboraapac.kt#L256) · [Rust](../../examples/bamboraapac/rust/bamboraapac.rs#L312)

#### PaymentService.Refund

Process a partial or full refund for a captured payment. Returns funds to the customer when goods are returned or services are cancelled.

| | Message |
|---|---------|
| **Request** | `PaymentServiceRefundRequest` |
| **Response** | `RefundResponse` |

**Examples:** [Python](../../examples/bamboraapac/python/bamboraapac.py#L383) · [JavaScript](../../examples/bamboraapac/javascript/bamboraapac.js#L359) · [Kotlin](../../examples/bamboraapac/kotlin/bamboraapac.kt#L309) · [Rust](../../examples/bamboraapac/rust/bamboraapac.rs#L353)

#### PaymentService.SetupRecurring

Configure a payment method for recurring billing. Sets up the mandate and payment details needed for future automated charges.

| | Message |
|---|---------|
| **Request** | `PaymentServiceSetupRecurringRequest` |
| **Response** | `PaymentServiceSetupRecurringResponse` |

**Examples:** [Python](../../examples/bamboraapac/python/bamboraapac.py#L392) · [JavaScript](../../examples/bamboraapac/javascript/bamboraapac.js#L368) · [Kotlin](../../examples/bamboraapac/kotlin/bamboraapac.kt#L319) · [Rust](../../examples/bamboraapac/rust/bamboraapac.rs#L360)

### Mandates

#### RecurringPaymentService.Charge

Charge using an existing stored recurring payment instruction. Processes repeat payments for subscriptions or recurring billing without collecting payment details.

| | Message |
|---|---------|
| **Request** | `RecurringPaymentServiceChargeRequest` |
| **Response** | `RecurringPaymentServiceChargeResponse` |

**Examples:** [Python](../../examples/bamboraapac/python/bamboraapac.py#L374) · [JavaScript](../../examples/bamboraapac/javascript/bamboraapac.js#L350) · [Kotlin](../../examples/bamboraapac/kotlin/bamboraapac.kt#L284) · [Rust](../../examples/bamboraapac/rust/bamboraapac.rs#L346)

### Other

#### proxy_authorize

**Examples:** [Python](../../examples/bamboraapac/python/bamboraapac.py#L342) · [JavaScript](../../examples/bamboraapac/javascript/bamboraapac.js#L322) · [Kotlin](../../examples/bamboraapac/kotlin/bamboraapac.kt#L264) · [Rust](../../examples/bamboraapac/rust/bamboraapac.rs#L319)
