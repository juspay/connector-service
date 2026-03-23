# Airwallex

<!--
This file is auto-generated. Do not edit by hand.
Source: data/field_probe/airwallex.json
Regenerate: python3 scripts/generators/docs/generate.py airwallex
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
#     airwallex=payment_pb2.AirwallexConfig(api_key=...),
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
    connector: 'Airwallex',
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
    .setConnector("Airwallex")
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
    connector: "Airwallex".to_string(),
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

**Examples:** [Python](../../examples/airwallex/python/airwallex.py#L165) · [JavaScript](../../examples/airwallex/javascript/airwallex.js#L151) · [Kotlin](../../examples/airwallex/kotlin/airwallex.kt#L139) · [Rust](../../examples/airwallex/rust/airwallex.rs#L158)

### Card Payment (Automatic Capture)

Authorize and capture in one call using `capture_method=AUTOMATIC`. Use for digital goods or immediate fulfillment.

**Response status handling:**

| Status | Recommended action |
|--------|-------------------|
| `AUTHORIZED` | Payment authorized and captured — funds will be settled automatically |
| `PENDING` | Payment processing — await webhook for final status before fulfilling |
| `FAILED` | Payment declined — surface error to customer, do not retry without new details |

**Examples:** [Python](../../examples/airwallex/python/airwallex.py#L190) · [JavaScript](../../examples/airwallex/javascript/airwallex.js#L177) · [Kotlin](../../examples/airwallex/kotlin/airwallex.kt#L161) · [Rust](../../examples/airwallex/rust/airwallex.rs#L181)

### Refund a Payment

Authorize with automatic capture, then refund the captured amount. `connector_transaction_id` from the Authorize response is reused for the Refund call.

**Examples:** [Python](../../examples/airwallex/python/airwallex.py#L209) · [JavaScript](../../examples/airwallex/javascript/airwallex.js#L196) · [Kotlin](../../examples/airwallex/kotlin/airwallex.kt#L177) · [Rust](../../examples/airwallex/rust/airwallex.rs#L197)

### Void a Payment

Authorize funds with a manual capture flag, then cancel the authorization with Void before any capture occurs. Releases the hold on the customer's funds.

**Examples:** [Python](../../examples/airwallex/python/airwallex.py#L234) · [JavaScript](../../examples/airwallex/javascript/airwallex.js#L222) · [Kotlin](../../examples/airwallex/kotlin/airwallex.kt#L199) · [Rust](../../examples/airwallex/rust/airwallex.rs#L220)

### Get Payment Status

Authorize a payment, then poll the connector for its current status using Get. Use this to sync payment state when webhooks are unavailable or delayed.

**Examples:** [Python](../../examples/airwallex/python/airwallex.py#L256) · [JavaScript](../../examples/airwallex/javascript/airwallex.js#L244) · [Kotlin](../../examples/airwallex/kotlin/airwallex.kt#L218) · [Rust](../../examples/airwallex/rust/airwallex.rs#L239)

## API Reference

| Flow (Service.RPC) | Category | gRPC Request Message |
|--------------------|----------|----------------------|
| [PaymentService.Authorize](#paymentserviceauthorize) | Payments | `PaymentServiceAuthorizeRequest` |
| [PaymentService.Capture](#paymentservicecapture) | Payments | `PaymentServiceCaptureRequest` |
| [MerchantAuthenticationService.CreateAccessToken](#merchantauthenticationservicecreateaccesstoken) | Authentication | `MerchantAuthenticationServiceCreateAccessTokenRequest` |
| [PaymentService.CreateOrder](#paymentservicecreateorder) | Payments | `PaymentServiceCreateOrderRequest` |
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
| Google Pay | x |
| Apple Pay | x |
| SEPA | x |
| BACS | x |
| ACH | x |
| BECS | x |
| iDEAL | ✓ |
| PayPal | x |
| BLIK | ✓ |
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

##### iDEAL

```python
"payment_method": {
    "ideal": {
    }
}
```

##### BLIK

```python
"payment_method": {
    "blik": {
        "blik_code": "777124"
    }
}
```

**Examples:** [Python](../../examples/airwallex/python/airwallex.py#L278) · [JavaScript](../../examples/airwallex/javascript/airwallex.js#L265) · [Kotlin](../../examples/airwallex/kotlin/airwallex.kt#L236) · [Rust](../../examples/airwallex/rust/airwallex.rs#L257)

#### PaymentService.Capture

Finalize an authorized payment transaction. Transfers reserved funds from customer to merchant account, completing the payment lifecycle.

| | Message |
|---|---------|
| **Request** | `PaymentServiceCaptureRequest` |
| **Response** | `PaymentServiceCaptureResponse` |

**Examples:** [Python](../../examples/airwallex/python/airwallex.py#L287) · [JavaScript](../../examples/airwallex/javascript/airwallex.js#L274) · [Kotlin](../../examples/airwallex/kotlin/airwallex.kt#L248) · [Rust](../../examples/airwallex/rust/airwallex.rs#L269)

#### PaymentService.CreateOrder

Initialize an order in the payment processor system. Sets up payment context before customer enters card details for improved authorization rates.

| | Message |
|---|---------|
| **Request** | `PaymentServiceCreateOrderRequest` |
| **Response** | `PaymentServiceCreateOrderResponse` |

**Examples:** [Python](../../examples/airwallex/python/airwallex.py#L305) · [JavaScript](../../examples/airwallex/javascript/airwallex.js#L292) · [Kotlin](../../examples/airwallex/kotlin/airwallex.kt#L268) · [Rust](../../examples/airwallex/rust/airwallex.rs#L283)

#### PaymentService.Get

Retrieve current payment status from the payment processor. Enables synchronization between your system and payment processors for accurate state tracking.

| | Message |
|---|---------|
| **Request** | `PaymentServiceGetRequest` |
| **Response** | `PaymentServiceGetResponse` |

**Examples:** [Python](../../examples/airwallex/python/airwallex.py#L314) · [JavaScript](../../examples/airwallex/javascript/airwallex.js#L301) · [Kotlin](../../examples/airwallex/kotlin/airwallex.kt#L289) · [Rust](../../examples/airwallex/rust/airwallex.rs#L290)

#### PaymentService.Refund

Initiate a refund to customer's payment method. Returns funds for returns, cancellations, or service adjustments after original payment.

| | Message |
|---|---------|
| **Request** | `PaymentServiceRefundRequest` |
| **Response** | `RefundResponse` |

**Examples:** [Python](../../examples/airwallex/python/airwallex.py#L323) · [JavaScript](../../examples/airwallex/javascript/airwallex.js#L310) · [Kotlin](../../examples/airwallex/kotlin/airwallex.kt#L297) · [Rust](../../examples/airwallex/rust/airwallex.rs#L297)

#### PaymentService.Void

Cancel an authorized payment before capture. Releases held funds back to customer, typically used when orders are cancelled or abandoned.

| | Message |
|---|---------|
| **Request** | `PaymentServiceVoidRequest` |
| **Response** | `PaymentServiceVoidResponse` |

**Examples:** [Python](../../examples/airwallex/python/airwallex.py#L332) · [JavaScript](../../examples/airwallex/javascript/airwallex.js#L319) · [Kotlin](../../examples/airwallex/kotlin/airwallex.kt#L307) · [Rust](../../examples/airwallex/rust/airwallex.rs#L304)

### Authentication

#### MerchantAuthenticationService.CreateAccessToken

Generate short-lived connector authentication token. Provides secure credentials for connector API access without storing secrets client-side.

| | Message |
|---|---------|
| **Request** | `MerchantAuthenticationServiceCreateAccessTokenRequest` |
| **Response** | `MerchantAuthenticationServiceCreateAccessTokenResponse` |

**Examples:** [Python](../../examples/airwallex/python/airwallex.py#L296) · [JavaScript](../../examples/airwallex/javascript/airwallex.js#L283) · [Kotlin](../../examples/airwallex/kotlin/airwallex.kt#L258) · [Rust](../../examples/airwallex/rust/airwallex.rs#L276)
