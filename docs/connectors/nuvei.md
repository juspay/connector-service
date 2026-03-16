# Nuvei

<!--
This file is auto-generated. Do not edit by hand.
Source: data/field_probe/nuvei.json
Regenerate: python3 scripts/generate-connector-docs.py nuvei
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
#     nuvei=payment_pb2.NuveiConfig(api_key=...),
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
    connector: 'Nuvei',
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
    .setConnector("Nuvei")
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
    connector: "Nuvei".to_string(),
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

**Examples:** [Python](../../examples/nuvei/python/nuvei.py#L108) · [JavaScript](../../examples/nuvei/javascript/nuvei.js#L98) · [Kotlin](../../examples/nuvei/kotlin/nuvei.kt#L123) · [Rust](../../examples/nuvei/rust/nuvei.rs#L117)

### Card Payment (Automatic Capture)

Authorize and capture in one call using `capture_method=AUTOMATIC`. Use for digital goods or immediate fulfillment.

**Response status handling:**

| Status | Recommended action |
|--------|-------------------|
| `AUTHORIZED` | Payment authorized and captured — funds will be settled automatically |
| `PENDING` | Payment processing — await webhook for final status before fulfilling |
| `FAILED` | Payment declined — surface error to customer, do not retry without new details |

**Examples:** [Python](../../examples/nuvei/python/nuvei.py#L133) · [JavaScript](../../examples/nuvei/javascript/nuvei.js#L124) · [Kotlin](../../examples/nuvei/kotlin/nuvei.kt#L145) · [Rust](../../examples/nuvei/rust/nuvei.rs#L139)

### Refund a Payment

Authorize with automatic capture, then refund the captured amount. `connector_transaction_id` from the Authorize response is reused for the Refund call.

**Examples:** [Python](../../examples/nuvei/python/nuvei.py#L152) · [JavaScript](../../examples/nuvei/javascript/nuvei.js#L143) · [Kotlin](../../examples/nuvei/kotlin/nuvei.kt#L161) · [Rust](../../examples/nuvei/rust/nuvei.rs#L154)

### Void a Payment

Authorize funds with a manual capture flag, then cancel the authorization with Void before any capture occurs. Releases the hold on the customer's funds.

**Examples:** [Python](../../examples/nuvei/python/nuvei.py#L189) · [JavaScript](../../examples/nuvei/javascript/nuvei.js#L178) · [Kotlin](../../examples/nuvei/kotlin/nuvei.kt#L183) · [Rust](../../examples/nuvei/rust/nuvei.rs#L176)

### Get Payment Status

Authorize a payment, then poll the connector for its current status using Get. Use this to sync payment state when webhooks are unavailable or delayed.

**Examples:** [Python](../../examples/nuvei/python/nuvei.py#L211) · [JavaScript](../../examples/nuvei/javascript/nuvei.js#L200) · [Kotlin](../../examples/nuvei/kotlin/nuvei.kt#L202) · [Rust](../../examples/nuvei/rust/nuvei.rs#L194)

## API Reference

| Flow (Service.RPC) | Category | gRPC Request Message |
|--------------------|----------|----------------------|
| [PaymentService.Authorize](#paymentserviceauthorize) | Payments | `PaymentServiceAuthorizeRequest` |
| [PaymentService.Capture](#paymentservicecapture) | Payments | `PaymentServiceCaptureRequest` |
| [MerchantAuthenticationService.CreateSessionToken](#merchantauthenticationservicecreatesessiontoken) | Authentication | `MerchantAuthenticationServiceCreateSessionTokenRequest` |
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

**Examples:** [Python](../../examples/nuvei/python/nuvei.py#L233) · [JavaScript](../../examples/nuvei/javascript/nuvei.js#L221) · [Kotlin](../../examples/nuvei/kotlin/nuvei.kt#L220) · [Rust](../../examples/nuvei/rust/nuvei.rs#L211)

#### PaymentService.Capture

Finalize an authorized payment transaction. Transfers reserved funds from customer to merchant account, completing the payment lifecycle.

| | Message |
|---|---------|
| **Request** | `PaymentServiceCaptureRequest` |
| **Response** | `PaymentServiceCaptureResponse` |

**Examples:** [Python](../../examples/nuvei/python/nuvei.py#L242) · [JavaScript](../../examples/nuvei/javascript/nuvei.js#L230) · [Kotlin](../../examples/nuvei/kotlin/nuvei.kt#L232) · [Rust](../../examples/nuvei/rust/nuvei.rs#L222)

#### PaymentService.Get

Retrieve current payment status from the payment processor. Enables synchronization between your system and payment processors for accurate state tracking.

| | Message |
|---|---------|
| **Request** | `PaymentServiceGetRequest` |
| **Response** | `PaymentServiceGetResponse` |

**Examples:** [Python](../../examples/nuvei/python/nuvei.py#L269) · [JavaScript](../../examples/nuvei/javascript/nuvei.js#L252) · [Kotlin](../../examples/nuvei/kotlin/nuvei.kt#L255) · [Rust](../../examples/nuvei/rust/nuvei.rs#L239)

#### PaymentService.Refund

Initiate a refund to customer's payment method. Returns funds for returns, cancellations, or service adjustments after original payment.

| | Message |
|---|---------|
| **Request** | `PaymentServiceRefundRequest` |
| **Response** | `RefundResponse` |

**Examples:** [Python](../../examples/nuvei/python/nuvei.py#L152) · [JavaScript](../../examples/nuvei/javascript/nuvei.js#L143) · [Kotlin](../../examples/nuvei/kotlin/nuvei.kt#L263) · [Rust](../../examples/nuvei/rust/nuvei.rs#L245)

#### PaymentService.Void

Cancel an authorized payment before capture. Releases held funds back to customer, typically used when orders are cancelled or abandoned.

| | Message |
|---|---------|
| **Request** | `PaymentServiceVoidRequest` |
| **Response** | `PaymentServiceVoidResponse` |

**Examples:** [Python](../../examples/nuvei/python/nuvei.py#L278) · [JavaScript](../../examples/nuvei/javascript/nuvei.js#L261) · [Kotlin](../../examples/nuvei/kotlin/nuvei.kt#L273) · [Rust](../../examples/nuvei/rust/nuvei.rs#L251)

### Authentication

#### MerchantAuthenticationService.CreateSessionToken

Create session token for payment processing. Maintains session state across multiple payment operations for improved security and tracking.

| | Message |
|---|---------|
| **Request** | `MerchantAuthenticationServiceCreateSessionTokenRequest` |
| **Response** | `MerchantAuthenticationServiceCreateSessionTokenResponse` |

**Examples:** [Python](../../examples/nuvei/python/nuvei.py#L251) · [JavaScript](../../examples/nuvei/javascript/nuvei.js#L239) · [Kotlin](../../examples/nuvei/kotlin/nuvei.kt#L242) · [Rust](../../examples/nuvei/rust/nuvei.rs#L228)
