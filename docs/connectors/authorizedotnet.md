# Authorize.net

<!--
This file is auto-generated. Do not edit by hand.
Source: data/field_probe/authorizedotnet.json
Regenerate: python3 scripts/generate-connector-docs.py authorizedotnet
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
#     authorizedotnet=payment_pb2.AuthorizedotnetConfig(api_key=...),
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
    connector: 'Authorizedotnet',
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
    .setConnector("Authorizedotnet")
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
    connector: "Authorizedotnet".to_string(),
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

**Examples:** [Python](../../examples/authorizedotnet/python/authorizedotnet.py#L131) · [JavaScript](../../examples/authorizedotnet/javascript/authorizedotnet.js#L121) · [Kotlin](../../examples/authorizedotnet/kotlin/authorizedotnet.kt#L146) · [Rust](../../examples/authorizedotnet/rust/authorizedotnet.rs#L140)

### Card Payment (Automatic Capture)

Authorize and capture in one call using `capture_method=AUTOMATIC`. Use for digital goods or immediate fulfillment.

**Response status handling:**

| Status | Recommended action |
|--------|-------------------|
| `AUTHORIZED` | Payment authorized and captured — funds will be settled automatically |
| `PENDING` | Payment processing — await webhook for final status before fulfilling |
| `FAILED` | Payment declined — surface error to customer, do not retry without new details |

**Examples:** [Python](../../examples/authorizedotnet/python/authorizedotnet.py#L156) · [JavaScript](../../examples/authorizedotnet/javascript/authorizedotnet.js#L147) · [Kotlin](../../examples/authorizedotnet/kotlin/authorizedotnet.kt#L168) · [Rust](../../examples/authorizedotnet/rust/authorizedotnet.rs#L162)

### Bank Transfer (SEPA / ACH / BACS)

Direct bank debit (Ach). Bank transfers typically use `capture_method=AUTOMATIC`.

**Response status handling:**

| Status | Recommended action |
|--------|-------------------|
| `AUTHORIZED` | Payment authorized and captured — funds will be settled automatically |
| `PENDING` | Payment processing — await webhook for final status before fulfilling |
| `FAILED` | Payment declined — surface error to customer, do not retry without new details |

**Examples:** [Python](../../examples/authorizedotnet/python/authorizedotnet.py#L175) · [JavaScript](../../examples/authorizedotnet/javascript/authorizedotnet.js#L166) · [Kotlin](../../examples/authorizedotnet/kotlin/authorizedotnet.kt#L184) · [Rust](../../examples/authorizedotnet/rust/authorizedotnet.rs#L177)

### Refund a Payment

Authorize with automatic capture, then refund the captured amount. `connector_transaction_id` from the Authorize response is reused for the Refund call.

**Examples:** [Python](../../examples/authorizedotnet/python/authorizedotnet.py#L261) · [JavaScript](../../examples/authorizedotnet/javascript/authorizedotnet.js#L249) · [Kotlin](../../examples/authorizedotnet/kotlin/authorizedotnet.kt#L264) · [Rust](../../examples/authorizedotnet/rust/authorizedotnet.rs#L258)

### Void a Payment

Authorize funds with a manual capture flag, then cancel the authorization with Void before any capture occurs. Releases the hold on the customer's funds.

**Examples:** [Python](../../examples/authorizedotnet/python/authorizedotnet.py#L298) · [JavaScript](../../examples/authorizedotnet/javascript/authorizedotnet.js#L284) · [Kotlin](../../examples/authorizedotnet/kotlin/authorizedotnet.kt#L286) · [Rust](../../examples/authorizedotnet/rust/authorizedotnet.rs#L280)

### Get Payment Status

Authorize a payment, then poll the connector for its current status using Get. Use this to sync payment state when webhooks are unavailable or delayed.

**Examples:** [Python](../../examples/authorizedotnet/python/authorizedotnet.py#L320) · [JavaScript](../../examples/authorizedotnet/javascript/authorizedotnet.js#L306) · [Kotlin](../../examples/authorizedotnet/kotlin/authorizedotnet.kt#L305) · [Rust](../../examples/authorizedotnet/rust/authorizedotnet.rs#L298)

### Create Customer

Register a customer record in the connector system. Returns a connector_customer_id that can be reused for recurring payments and tokenized card storage.

**Examples:** [Python](../../examples/authorizedotnet/python/authorizedotnet.py#L342) · [JavaScript](../../examples/authorizedotnet/javascript/authorizedotnet.js#L328) · [Kotlin](../../examples/authorizedotnet/kotlin/authorizedotnet.kt#L324) · [Rust](../../examples/authorizedotnet/rust/authorizedotnet.rs#L316)

## API Reference

| Flow (Service.RPC) | Category | gRPC Request Message |
|--------------------|----------|----------------------|
| [PaymentService.Authorize](#paymentserviceauthorize) | Payments | `PaymentServiceAuthorizeRequest` |
| [PaymentService.Capture](#paymentservicecapture) | Payments | `PaymentServiceCaptureRequest` |
| [CustomerService.Create](#customerservicecreate) | Customers | `CustomerServiceCreateRequest` |
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
| Google Pay | — |
| Apple Pay | — |
| ACH | ✓ |
| iDEAL | — |
| PayPal | — |
| BLIK | — |
| Klarna | — |
| Afterpay | — |
| UPI | — |
| Affirm | — |
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

**Examples:** [Python](../../examples/authorizedotnet/python/authorizedotnet.py#L376) · [JavaScript](../../examples/authorizedotnet/javascript/authorizedotnet.js#L356) · [Kotlin](../../examples/authorizedotnet/kotlin/authorizedotnet.kt#L352) · [Rust](../../examples/authorizedotnet/rust/authorizedotnet.rs#L342)

#### PaymentService.Capture

Finalize an authorized payment transaction. Transfers reserved funds from customer to merchant account, completing the payment lifecycle.

| | Message |
|---|---------|
| **Request** | `PaymentServiceCaptureRequest` |
| **Response** | `PaymentServiceCaptureResponse` |

**Examples:** [Python](../../examples/authorizedotnet/python/authorizedotnet.py#L385) · [JavaScript](../../examples/authorizedotnet/javascript/authorizedotnet.js#L365) · [Kotlin](../../examples/authorizedotnet/kotlin/authorizedotnet.kt#L364) · [Rust](../../examples/authorizedotnet/rust/authorizedotnet.rs#L353)

#### PaymentService.Get

Retrieve current payment status from the payment processor. Enables synchronization between your system and payment processors for accurate state tracking.

| | Message |
|---|---------|
| **Request** | `PaymentServiceGetRequest` |
| **Response** | `PaymentServiceGetResponse` |

**Examples:** [Python](../../examples/authorizedotnet/python/authorizedotnet.py#L394) · [JavaScript](../../examples/authorizedotnet/javascript/authorizedotnet.js#L374) · [Kotlin](../../examples/authorizedotnet/kotlin/authorizedotnet.kt#L400) · [Rust](../../examples/authorizedotnet/rust/authorizedotnet.rs#L383)

#### PaymentService.Refund

Initiate a refund to customer's payment method. Returns funds for returns, cancellations, or service adjustments after original payment.

| | Message |
|---|---------|
| **Request** | `PaymentServiceRefundRequest` |
| **Response** | `RefundResponse` |

**Examples:** [Python](../../examples/authorizedotnet/python/authorizedotnet.py#L261) · [JavaScript](../../examples/authorizedotnet/javascript/authorizedotnet.js#L249) · [Kotlin](../../examples/authorizedotnet/kotlin/authorizedotnet.kt#L408) · [Rust](../../examples/authorizedotnet/rust/authorizedotnet.rs#L389)

#### PaymentService.Void

Cancel an authorized payment before capture. Releases held funds back to customer, typically used when orders are cancelled or abandoned.

| | Message |
|---|---------|
| **Request** | `PaymentServiceVoidRequest` |
| **Response** | `PaymentServiceVoidResponse` |

**Examples:** [Python](../../examples/authorizedotnet/python/authorizedotnet.py#L403) · [JavaScript](../../examples/authorizedotnet/javascript/authorizedotnet.js#L383) · [Kotlin](../../examples/authorizedotnet/kotlin/authorizedotnet.kt#L418) · [Rust](../../examples/authorizedotnet/rust/authorizedotnet.rs#L395)

### Customers

#### CustomerService.Create

Create customer record in the payment processor system. Stores customer details for future payment operations without re-sending personal information.

| | Message |
|---|---------|
| **Request** | `CustomerServiceCreateRequest` |
| **Response** | `CustomerServiceCreateResponse` |

**Examples:** [Python](../../examples/authorizedotnet/python/authorizedotnet.py#L342) · [JavaScript](../../examples/authorizedotnet/javascript/authorizedotnet.js#L328) · [Kotlin](../../examples/authorizedotnet/kotlin/authorizedotnet.kt#L374) · [Rust](../../examples/authorizedotnet/rust/authorizedotnet.rs#L359)
