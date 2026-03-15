# Bluesnap

<!--
This file is auto-generated. Do not edit by hand.
Source: data/field_probe/bluesnap.json
Regenerate: python3 scripts/generate-connector-docs.py bluesnap
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
#     bluesnap=payment_pb2.BluesnapConfig(api_key=...),
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
    connector: 'Bluesnap',
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
    .setConnector("Bluesnap")
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
    connector: "Bluesnap".to_string(),
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

**Examples:** [Python](../../examples/bluesnap/python/bluesnap.py#L130) · [JavaScript](../../examples/bluesnap/javascript/bluesnap.js#L121) · [Kotlin](../../examples/bluesnap/kotlin/bluesnap.kt#L144) · [Rust](../../examples/bluesnap/rust/bluesnap.rs#L140)

### Card Payment (Automatic Capture)

Authorize and capture in one call using `capture_method=AUTOMATIC`. Use for digital goods or immediate fulfillment.

**Response status handling:**

| Status | Recommended action |
|--------|-------------------|
| `AUTHORIZED` | Payment authorized and captured — funds will be settled automatically |
| `PENDING` | Payment processing — await webhook for final status before fulfilling |
| `FAILED` | Payment declined — surface error to customer, do not retry without new details |

**Examples:** [Python](../../examples/bluesnap/python/bluesnap.py#L155) · [JavaScript](../../examples/bluesnap/javascript/bluesnap.js#L147) · [Kotlin](../../examples/bluesnap/kotlin/bluesnap.kt#L166) · [Rust](../../examples/bluesnap/rust/bluesnap.rs#L162)

### Wallet Payment (Google Pay / Apple Pay)

Wallet payments pass an encrypted token from the browser/device SDK. Pass the token blob directly — do not decrypt client-side.

**Response status handling:**

| Status | Recommended action |
|--------|-------------------|
| `AUTHORIZED` | Payment authorized and captured — funds will be settled automatically |
| `PENDING` | Payment processing — await webhook for final status before fulfilling |
| `FAILED` | Payment declined — surface error to customer, do not retry without new details |

**Examples:** [Python](../../examples/bluesnap/python/bluesnap.py#L174) · [JavaScript](../../examples/bluesnap/javascript/bluesnap.js#L166) · [Kotlin](../../examples/bluesnap/kotlin/bluesnap.kt#L182) · [Rust](../../examples/bluesnap/rust/bluesnap.rs#L177)

### Bank Transfer (SEPA / ACH / BACS)

Direct bank debit (Ach). Bank transfers typically use `capture_method=AUTOMATIC`.

**Response status handling:**

| Status | Recommended action |
|--------|-------------------|
| `AUTHORIZED` | Payment authorized and captured — funds will be settled automatically |
| `PENDING` | Payment processing — await webhook for final status before fulfilling |
| `FAILED` | Payment declined — surface error to customer, do not retry without new details |

**Examples:** [Python](../../examples/bluesnap/python/bluesnap.py#L269) · [JavaScript](../../examples/bluesnap/javascript/bluesnap.js#L258) · [Kotlin](../../examples/bluesnap/kotlin/bluesnap.kt#L271) · [Rust](../../examples/bluesnap/rust/bluesnap.rs#L267)

### Refund a Payment

Authorize with automatic capture, then refund the captured amount. `connector_transaction_id` from the Authorize response is reused for the Refund call.

**Examples:** [Python](../../examples/bluesnap/python/bluesnap.py#L355) · [JavaScript](../../examples/bluesnap/javascript/bluesnap.js#L341) · [Kotlin](../../examples/bluesnap/kotlin/bluesnap.kt#L351) · [Rust](../../examples/bluesnap/rust/bluesnap.rs#L348)

### Void a Payment

Authorize funds with a manual capture flag, then cancel the authorization with Void before any capture occurs. Releases the hold on the customer's funds.

**Examples:** [Python](../../examples/bluesnap/python/bluesnap.py#L392) · [JavaScript](../../examples/bluesnap/javascript/bluesnap.js#L376) · [Kotlin](../../examples/bluesnap/kotlin/bluesnap.kt#L373) · [Rust](../../examples/bluesnap/rust/bluesnap.rs#L370)

### Get Payment Status

Authorize a payment, then poll the connector for its current status using Get. Use this to sync payment state when webhooks are unavailable or delayed.

**Examples:** [Python](../../examples/bluesnap/python/bluesnap.py#L414) · [JavaScript](../../examples/bluesnap/javascript/bluesnap.js#L398) · [Kotlin](../../examples/bluesnap/kotlin/bluesnap.kt#L392) · [Rust](../../examples/bluesnap/rust/bluesnap.rs#L388)

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
| Google Pay | ✓ |
| Apple Pay | ✓ |
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

##### Google Pay

```python
"payment_method": {
    "google_pay": {  # Google Pay
        "type": "CARD",  # Type of payment method
        "description": "Visa 1111",  # User-facing description of the payment method
        "info": {
            "card_network": "VISA",  # Card network name
            "card_details": "1111"  # Card details (usually last 4 digits)
        },
        "tokenization_data": {
            "encrypted_data": {  # Encrypted Google Pay payment data
                "token": "{\"version\":\"ECv2\",\"signature\":\"<sig>\",\"intermediateSigningKey\":{\"signedKey\":\"<signed_key>\",\"signatures\":[\"<sig>\"]},\"signedMessage\":\"<signed_message>\"}",  # Token generated for the wallet
                "token_type": "PAYMENT_GATEWAY"  # The type of the token
            }
        }
    }
}
```

##### Apple Pay

```python
"payment_method": {
    "apple_pay": {  # Apple Pay
        "payment_data": {
            "encrypted_data": "<base64_encoded_apple_pay_payment_token>"  # Encrypted Apple Pay payment data as string
        },
        "payment_method": {
            "display_name": "Visa 1111",
            "network": "Visa",
            "type": "debit"
        },
        "transaction_identifier": "<apple_pay_transaction_identifier>"  # Transaction identifier
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

**Examples:** [Python](../../examples/bluesnap/python/bluesnap.py#L436) · [JavaScript](../../examples/bluesnap/javascript/bluesnap.js#L419) · [Kotlin](../../examples/bluesnap/kotlin/bluesnap.kt#L410) · [Rust](../../examples/bluesnap/rust/bluesnap.rs#L405)

#### PaymentService.Capture

Finalize an authorized payment transaction. Transfers reserved funds from customer to merchant account, completing the payment lifecycle.

| | Message |
|---|---------|
| **Request** | `PaymentServiceCaptureRequest` |
| **Response** | `PaymentServiceCaptureResponse` |

**Examples:** [Python](../../examples/bluesnap/python/bluesnap.py#L445) · [JavaScript](../../examples/bluesnap/javascript/bluesnap.js#L428) · [Kotlin](../../examples/bluesnap/kotlin/bluesnap.kt#L422) · [Rust](../../examples/bluesnap/rust/bluesnap.rs#L416)

#### PaymentService.Get

Retrieve current payment status from the payment processor. Enables synchronization between your system and payment processors for accurate state tracking.

| | Message |
|---|---------|
| **Request** | `PaymentServiceGetRequest` |
| **Response** | `PaymentServiceGetResponse` |

**Examples:** [Python](../../examples/bluesnap/python/bluesnap.py#L454) · [JavaScript](../../examples/bluesnap/javascript/bluesnap.js#L437) · [Kotlin](../../examples/bluesnap/kotlin/bluesnap.kt#L432) · [Rust](../../examples/bluesnap/rust/bluesnap.rs#L422)

#### PaymentService.Refund

Initiate a refund to customer's payment method. Returns funds for returns, cancellations, or service adjustments after original payment.

| | Message |
|---|---------|
| **Request** | `PaymentServiceRefundRequest` |
| **Response** | `RefundResponse` |

**Examples:** [Python](../../examples/bluesnap/python/bluesnap.py#L355) · [JavaScript](../../examples/bluesnap/javascript/bluesnap.js#L341) · [Kotlin](../../examples/bluesnap/kotlin/bluesnap.kt#L440) · [Rust](../../examples/bluesnap/rust/bluesnap.rs#L428)

#### PaymentService.Void

Cancel an authorized payment before capture. Releases held funds back to customer, typically used when orders are cancelled or abandoned.

| | Message |
|---|---------|
| **Request** | `PaymentServiceVoidRequest` |
| **Response** | `PaymentServiceVoidResponse` |

**Examples:** [Python](../../examples/bluesnap/python/bluesnap.py#L463) · [JavaScript](../../examples/bluesnap/javascript/bluesnap.js#L446) · [Kotlin](../../examples/bluesnap/kotlin/bluesnap.kt#L450) · [Rust](../../examples/bluesnap/rust/bluesnap.rs#L434)
