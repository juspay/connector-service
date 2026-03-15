# Paypal

<!--
This file is auto-generated. Do not edit by hand.
Source: data/field_probe/paypal.json
Regenerate: python3 scripts/generate-connector-docs.py paypal
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
    connector=payment_pb2.Connector.PAYPAL,
    environment=sdk_config_pb2.Environment.SANDBOX,
)
# Set credentials before running (field names depend on connector auth type):
# config.auth.paypal.api_key.value = "YOUR_API_KEY"

```

</details>

</td>
<td valign="top">

<details><summary>JavaScript</summary>

```javascript
const { ConnectorClient } = require('connector-service-node-ffi');

// Reuse this client for all flows
const client = new ConnectorClient({
    connector: 'Paypal',
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
    .setConnector("Paypal")
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
    connector: "Paypal".to_string(),
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

**Examples:** [Python](../../examples/paypal/python/paypal.py#L24) · [JavaScript](../../examples/paypal/javascript/paypal.js#L22) · [Kotlin](../../examples/paypal/kotlin/paypal.kt#L41) · [Rust](../../examples/paypal/rust/paypal.rs#L26)

### Card Payment (Automatic Capture)

Authorize and capture in one call using `capture_method=AUTOMATIC`. Use for digital goods or immediate fulfillment.

**Response status handling:**

| Status | Recommended action |
|--------|-------------------|
| `AUTHORIZED` | Payment authorized and captured — funds will be settled automatically |
| `PENDING` | Payment processing — await webhook for final status before fulfilling |
| `FAILED` | Payment declined — surface error to customer, do not retry without new details |

**Examples:** [Python](../../examples/paypal/python/paypal.py#L142) · [JavaScript](../../examples/paypal/javascript/paypal.js#L135) · [Kotlin](../../examples/paypal/kotlin/paypal.kt#L150) · [Rust](../../examples/paypal/rust/paypal.rs#L137)

### Refund a Payment

Authorize with automatic capture, then refund the captured amount. `connector_transaction_id` from the Authorize response is reused for the Refund call.

**Examples:** [Python](../../examples/paypal/python/paypal.py#L237) · [JavaScript](../../examples/paypal/javascript/paypal.js#L227) · [Kotlin](../../examples/paypal/kotlin/paypal.kt#L239) · [Rust](../../examples/paypal/rust/paypal.rs#L227)

### Recurring / Mandate Payments

Store a payment mandate with SetupRecurring, then charge it repeatedly with RecurringPaymentService.Charge without requiring customer action.

**Response status handling:**

| Status | Recommended action |
|--------|-------------------|
| `PENDING` | Mandate stored — save connector_transaction_id for future RecurringPaymentService.Charge calls |
| `FAILED` | Setup failed — customer must re-enter payment details |

**Examples:** [Python](../../examples/paypal/python/paypal.py#L357) · [JavaScript](../../examples/paypal/javascript/paypal.js#L342) · [Kotlin](../../examples/paypal/kotlin/paypal.kt#L350) · [Rust](../../examples/paypal/rust/paypal.rs#L340)

### Void a Payment

Authorize funds with a manual capture flag, then cancel the authorization with Void before any capture occurs. Releases the hold on the customer's funds.

**Examples:** [Python](../../examples/paypal/python/paypal.py#L469) · [JavaScript](../../examples/paypal/javascript/paypal.js#L445) · [Kotlin](../../examples/paypal/kotlin/paypal.kt#L455) · [Rust](../../examples/paypal/rust/paypal.rs#L442)

### Get Payment Status

Authorize a payment, then poll the connector for its current status using Get. Use this to sync payment state when webhooks are unavailable or delayed.

**Examples:** [Python](../../examples/paypal/python/paypal.py#L580) · [JavaScript](../../examples/paypal/javascript/paypal.js#L550) · [Kotlin](../../examples/paypal/kotlin/paypal.kt#L557) · [Rust](../../examples/paypal/rust/paypal.rs#L545)

## API Reference

| Flow (Service.RPC) | Category | gRPC Request Message |
|--------------------|----------|----------------------|
| [PaymentService.Authorize](#paymentserviceauthorize) | Payments | `PaymentServiceAuthorizeRequest` |
| [PaymentService.Capture](#paymentservicecapture) | Payments | `PaymentServiceCaptureRequest` |
| [MerchantAuthenticationService.CreateAccessToken](#merchantauthenticationservicecreateaccesstoken) | Authentication | `MerchantAuthenticationServiceCreateAccessTokenRequest` |
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
| PayPal | ✓ |
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
    }
}
```

##### PayPal Redirect

```python
"payment_method": {
    "paypal_redirect": {  # PayPal
        "email": {"value": "test@example.com"}  # PayPal's email address
    }
}
```

**Examples:** [Python](../../examples/paypal/python/paypal.py#L694) · [JavaScript](../../examples/paypal/javascript/paypal.js#L657) · [Kotlin](../../examples/paypal/kotlin/paypal.kt#L661) · [Rust](../../examples/paypal/rust/paypal.rs#L650)

#### PaymentService.Capture

Finalize an authorized payment transaction. Transfers reserved funds from customer to merchant account, completing the payment lifecycle.

| | Message |
|---|---------|
| **Request** | `PaymentServiceCaptureRequest` |
| **Response** | `PaymentServiceCaptureResponse` |

**Examples:** [Python](../../examples/paypal/python/paypal.py#L786) · [JavaScript](../../examples/paypal/javascript/paypal.js#L746) · [Kotlin](../../examples/paypal/kotlin/paypal.kt#L746) · [Rust](../../examples/paypal/rust/paypal.rs#L736)

#### PaymentService.Get

Retrieve current payment status from the payment processor. Enables synchronization between your system and payment processors for accurate state tracking.

| | Message |
|---|---------|
| **Request** | `PaymentServiceGetRequest` |
| **Response** | `PaymentServiceGetResponse` |

**Examples:** [Python](../../examples/paypal/python/paypal.py#L831) · [JavaScript](../../examples/paypal/javascript/paypal.js#L782) · [Kotlin](../../examples/paypal/kotlin/paypal.kt#L780) · [Rust](../../examples/paypal/rust/paypal.rs#L764)

#### PaymentService.Refund

Initiate a refund to customer's payment method. Returns funds for returns, cancellations, or service adjustments after original payment.

| | Message |
|---|---------|
| **Request** | `PaymentServiceRefundRequest` |
| **Response** | `RefundResponse` |

**Examples:** [Python](../../examples/paypal/python/paypal.py) · [JavaScript](../../examples/paypal/javascript/paypal.js) · [Kotlin](../../examples/paypal/kotlin/paypal.kt#L837) · [Rust](../../examples/paypal/rust/paypal.rs#L815)

#### PaymentService.SetupRecurring

Setup a recurring payment instruction for future payments/ debits. This could be for SaaS subscriptions, monthly bill payments, insurance payments and similar use cases.

| | Message |
|---|---------|
| **Request** | `PaymentServiceSetupRecurringRequest` |
| **Response** | `PaymentServiceSetupRecurringResponse` |

**Examples:** [Python](../../examples/paypal/python/paypal.py#L897) · [JavaScript](../../examples/paypal/javascript/paypal.js#L839) · [Kotlin](../../examples/paypal/kotlin/paypal.kt) · [Rust](../../examples/paypal/rust/paypal.rs#L837)

#### PaymentService.Void

Cancel an authorized payment before capture. Releases held funds back to customer, typically used when orders are cancelled or abandoned.

| | Message |
|---|---------|
| **Request** | `PaymentServiceVoidRequest` |
| **Response** | `PaymentServiceVoidResponse` |

**Examples:** [Python](../../examples/paypal/python/paypal.py#L981) · [JavaScript](../../examples/paypal/javascript/paypal.js) · [Kotlin](../../examples/paypal/kotlin/paypal.kt#L939) · [Rust](../../examples/paypal/rust/paypal.rs#L913)

### Mandates

#### RecurringPaymentService.Charge

Charge using an existing stored recurring payment instruction. Processes repeat payments for subscriptions or recurring billing without collecting payment details.

| | Message |
|---|---------|
| **Request** | `RecurringPaymentServiceChargeRequest` |
| **Response** | `RecurringPaymentServiceChargeResponse` |

**Examples:** [Python](../../examples/paypal/python/paypal.py#L857) · [JavaScript](../../examples/paypal/javascript/paypal.js#L803) · [Kotlin](../../examples/paypal/kotlin/paypal.kt) · [Rust](../../examples/paypal/rust/paypal.rs#L783)

### Authentication

#### MerchantAuthenticationService.CreateAccessToken

Generate short-lived connector authentication token. Provides secure credentials for connector API access without storing secrets client-side.

| | Message |
|---|---------|
| **Request** | `MerchantAuthenticationServiceCreateAccessTokenRequest` |
| **Response** | `MerchantAuthenticationServiceCreateAccessTokenResponse` |

**Examples:** [Python](../../examples/paypal/python/paypal.py#L816) · [JavaScript](../../examples/paypal/javascript/paypal.js#L772) · [Kotlin](../../examples/paypal/kotlin/paypal.kt) · [Rust](../../examples/paypal/rust/paypal.rs#L756)
