# Hipay

<!--
This file is auto-generated. Do not edit by hand.
Source: data/field_probe/hipay.json
Regenerate: python3 scripts/generators/docs/generate.py hipay
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
#     hipay=payment_pb2.HipayConfig(api_key=...),
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
    connector: 'Hipay',
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
    .setConnector("Hipay")
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
    connector: "Hipay".to_string(),
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

**Examples:** [Python](../../examples/hipay/python/hipay.py#L127) · [JavaScript](../../examples/hipay/javascript/hipay.js#L115) · [Kotlin](../../examples/hipay/kotlin/hipay.kt#L102) · [Rust](../../examples/hipay/rust/hipay.rs#L123)

### Card Payment (Automatic Capture)

Authorize and capture in one call using `capture_method=AUTOMATIC`. Use for digital goods or immediate fulfillment.

**Response status handling:**

| Status | Recommended action |
|--------|-------------------|
| `AUTHORIZED` | Payment authorized and captured — funds will be settled automatically |
| `PENDING` | Payment processing — await webhook for final status before fulfilling |
| `FAILED` | Payment declined — surface error to customer, do not retry without new details |

**Examples:** [Python](../../examples/hipay/python/hipay.py#L152) · [JavaScript](../../examples/hipay/javascript/hipay.js#L141) · [Kotlin](../../examples/hipay/kotlin/hipay.kt#L124) · [Rust](../../examples/hipay/rust/hipay.rs#L146)

### Refund a Payment

Authorize with automatic capture, then refund the captured amount. `connector_transaction_id` from the Authorize response is reused for the Refund call.

**Examples:** [Python](../../examples/hipay/python/hipay.py#L171) · [JavaScript](../../examples/hipay/javascript/hipay.js#L160) · [Kotlin](../../examples/hipay/kotlin/hipay.kt#L140) · [Rust](../../examples/hipay/rust/hipay.rs#L162)

### Void a Payment

Authorize funds with a manual capture flag, then cancel the authorization with Void before any capture occurs. Releases the hold on the customer's funds.

**Examples:** [Python](../../examples/hipay/python/hipay.py#L196) · [JavaScript](../../examples/hipay/javascript/hipay.js#L186) · [Kotlin](../../examples/hipay/kotlin/hipay.kt#L162) · [Rust](../../examples/hipay/rust/hipay.rs#L185)

### Get Payment Status

Authorize a payment, then poll the connector for its current status using Get. Use this to sync payment state when webhooks are unavailable or delayed.

**Examples:** [Python](../../examples/hipay/python/hipay.py#L218) · [JavaScript](../../examples/hipay/javascript/hipay.js#L208) · [Kotlin](../../examples/hipay/kotlin/hipay.kt#L181) · [Rust](../../examples/hipay/rust/hipay.rs#L204)

### Tokenize Payment Method

Store card details in the connector's vault and receive a reusable payment token. Use the returned token for one-click payments and recurring billing without re-collecting card data.

**Examples:** [Python](../../examples/hipay/python/hipay.py#L240) · [JavaScript](../../examples/hipay/javascript/hipay.js#L230) · [Kotlin](../../examples/hipay/kotlin/hipay.kt#L200) · [Rust](../../examples/hipay/rust/hipay.rs#L223)

## API Reference

| Flow (Service.RPC) | Category | gRPC Request Message |
|--------------------|----------|----------------------|
| [PaymentService.Authorize](#paymentserviceauthorize) | Payments | `PaymentServiceAuthorizeRequest` |
| [PaymentService.Capture](#paymentservicecapture) | Payments | `PaymentServiceCaptureRequest` |
| [PaymentService.Get](#paymentserviceget) | Payments | `PaymentServiceGetRequest` |
| [proxy_authorize](#proxy_authorize) | Other | `—` |
| [PaymentService.Refund](#paymentservicerefund) | Payments | `PaymentServiceRefundRequest` |
| [token_authorize](#token_authorize) | Other | `—` |
| [PaymentMethodService.Tokenize](#paymentmethodservicetokenize) | Payments | `PaymentMethodServiceTokenizeRequest` |
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

**Examples:** [Python](../../examples/hipay/python/hipay.py#L274) · [JavaScript](../../examples/hipay/javascript/hipay.js#L258) · [Kotlin](../../examples/hipay/kotlin/hipay.kt#L228) · [Rust](../../examples/hipay/rust/hipay.rs#L252)

#### PaymentService.Capture

Finalize an authorized payment by transferring funds. Captures the authorized amount to complete the transaction and move funds to your merchant account.

| | Message |
|---|---------|
| **Request** | `PaymentServiceCaptureRequest` |
| **Response** | `PaymentServiceCaptureResponse` |

**Examples:** [Python](../../examples/hipay/python/hipay.py#L283) · [JavaScript](../../examples/hipay/javascript/hipay.js#L267) · [Kotlin](../../examples/hipay/kotlin/hipay.kt#L240) · [Rust](../../examples/hipay/rust/hipay.rs#L264)

#### PaymentService.Get

Retrieve current payment status from the payment processor. Enables synchronization between your system and payment processors for accurate state tracking.

| | Message |
|---|---------|
| **Request** | `PaymentServiceGetRequest` |
| **Response** | `PaymentServiceGetResponse` |

**Examples:** [Python](../../examples/hipay/python/hipay.py#L292) · [JavaScript](../../examples/hipay/javascript/hipay.js#L276) · [Kotlin](../../examples/hipay/kotlin/hipay.kt#L250) · [Rust](../../examples/hipay/rust/hipay.rs#L271)

#### PaymentService.Refund

Process a partial or full refund for a captured payment. Returns funds to the customer when goods are returned or services are cancelled.

| | Message |
|---|---------|
| **Request** | `PaymentServiceRefundRequest` |
| **Response** | `RefundResponse` |

**Examples:** [Python](../../examples/hipay/python/hipay.py#L333) · [JavaScript](../../examples/hipay/javascript/hipay.js#L313) · [Kotlin](../../examples/hipay/kotlin/hipay.kt#L278) · [Rust](../../examples/hipay/rust/hipay.rs#L305)

#### PaymentMethodService.Tokenize

Tokenize payment method for secure storage. Replaces raw card details with secure token for one-click payments and recurring billing.

| | Message |
|---|---------|
| **Request** | `PaymentMethodServiceTokenizeRequest` |
| **Response** | `PaymentMethodServiceTokenizeResponse` |

**Examples:** [Python](../../examples/hipay/python/hipay.py#L367) · [JavaScript](../../examples/hipay/javascript/hipay.js#L343) · [Kotlin](../../examples/hipay/kotlin/hipay.kt#L303) · [Rust](../../examples/hipay/rust/hipay.rs#L332)

#### PaymentService.Void

Cancel an authorized payment that has not been captured. Releases held funds back to the customer's payment method when a transaction cannot be completed.

| | Message |
|---|---------|
| **Request** | `PaymentServiceVoidRequest` |
| **Response** | `PaymentServiceVoidResponse` |

**Examples:** [Python](../../examples/hipay/python/hipay.py#L376) · [JavaScript](../../examples/hipay/javascript/hipay.js#L352) · [Kotlin](../../examples/hipay/kotlin/hipay.kt#L329) · [Rust](../../examples/hipay/rust/hipay.rs#L339)

### Other

#### proxy_authorize

**Examples:** [Python](../../examples/hipay/python/hipay.py#L301) · [JavaScript](../../examples/hipay/javascript/hipay.js#L285) · [Kotlin](../../examples/hipay/kotlin/hipay.kt#L258) · [Rust](../../examples/hipay/rust/hipay.rs#L278)

#### token_authorize

**Examples:** [Python](../../examples/hipay/python/hipay.py#L342) · [JavaScript](../../examples/hipay/javascript/hipay.js#L322) · [Kotlin](../../examples/hipay/kotlin/hipay.kt#L288) · [Rust](../../examples/hipay/rust/hipay.rs#L312)
