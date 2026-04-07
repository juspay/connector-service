# Peachpayments

<!--
This file is auto-generated. Do not edit by hand.
Source: data/field_probe/peachpayments.json
Regenerate: python3 scripts/generators/docs/generate.py peachpayments
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
#     peachpayments=payment_pb2.PeachpaymentsConfig(api_key=...),
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
    connector: 'Peachpayments',
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
    .setConnector("Peachpayments")
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
    connector: "Peachpayments".to_string(),
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

### One-step Payment (Authorize + Capture)

Simple payment that authorizes and captures in one call. Use for immediate charges.

**Response status handling:**

| Status | Recommended action |
|--------|-------------------|
| `AUTHORIZED` | Payment authorized and captured — funds will be settled automatically |
| `PENDING` | Payment processing — await webhook for final status before fulfilling |
| `FAILED` | Payment declined — surface error to customer, do not retry without new details |

**Examples:** [Python](../../examples/peachpayments/peachpayments.py#L23) · [JavaScript](../../examples/peachpayments/peachpayments.js) · [Kotlin](../../examples/peachpayments/peachpayments.kt#L23) · [Rust](../../examples/peachpayments/peachpayments.rs#L27)

### Card Payment (Authorize + Capture)

Two-step card payment. First authorize, then capture. Use when you need to verify funds before finalizing.

**Response status handling:**

| Status | Recommended action |
|--------|-------------------|
| `AUTHORIZED` | Funds reserved — proceed to Capture to settle |
| `PENDING` | Awaiting async confirmation — wait for webhook before capturing |
| `FAILED` | Payment declined — surface error to customer, do not retry without new details |

**Examples:** [Python](../../examples/peachpayments/peachpayments.py#L62) · [JavaScript](../../examples/peachpayments/peachpayments.js) · [Kotlin](../../examples/peachpayments/peachpayments.kt#L51) · [Rust](../../examples/peachpayments/peachpayments.rs#L65)

### Refund

Return funds to the customer for a completed payment.

**Examples:** [Python](../../examples/peachpayments/peachpayments.py#L116) · [JavaScript](../../examples/peachpayments/peachpayments.js) · [Kotlin](../../examples/peachpayments/peachpayments.kt#L90) · [Rust](../../examples/peachpayments/peachpayments.rs#L117)

### Void Payment

Cancel an authorized but not-yet-captured payment.

**Examples:** [Python](../../examples/peachpayments/peachpayments.py#L172) · [JavaScript](../../examples/peachpayments/peachpayments.js) · [Kotlin](../../examples/peachpayments/peachpayments.kt#L131) · [Rust](../../examples/peachpayments/peachpayments.rs#L171)

### Get Payment Status

Retrieve current payment status from the connector.

**Examples:** [Python](../../examples/peachpayments/peachpayments.py#L223) · [JavaScript](../../examples/peachpayments/peachpayments.js) · [Kotlin](../../examples/peachpayments/peachpayments.kt#L167) · [Rust](../../examples/peachpayments/peachpayments.rs#L219)

## API Reference

| Flow (Service.RPC) | Category | gRPC Request Message |
|--------------------|----------|----------------------|
| [authorize](#authorize) | Other | `—` |
| [capture](#capture) | Other | `—` |
| [get](#get) | Other | `—` |
| [handle_event](#handle_event) | Other | `—` |
| [proxy_authorize](#proxy_authorize) | Other | `—` |
| [refund](#refund) | Other | `—` |
| [refund_get](#refund_get) | Other | `—` |
| [void](#void) | Other | `—` |

### Other

#### authorize

**Supported payment method types:**

| Payment Method | Supported |
|----------------|:---------:|
| Card | ✓ |
| Bancontact | x |
| Apple Pay | x |
| Apple Pay Dec | x |
| Apple Pay SDK | x |
| Google Pay | x |
| Google Pay Dec | x |
| Google Pay SDK | x |
| PayPal SDK | x |
| Amazon Pay | x |
| Cash App | x |
| PayPal | x |
| WeChat Pay | x |
| Alipay | x |
| Revolut Pay | x |
| MiFinity | x |
| Bluecode | x |
| Paze | x |
| Samsung Pay | x |
| MB Way | x |
| Satispay | x |
| Wero | x |
| Affirm | x |
| Afterpay | x |
| Klarna | x |
| UPI Collect | x |
| UPI Intent | x |
| UPI QR | x |
| Thailand | x |
| Czech | x |
| Finland | x |
| FPX | x |
| Poland | x |
| Slovakia | x |
| UK | x |
| PIS | x |
| Generic | x |
| Local | x |
| iDEAL | x |
| Sofort | x |
| Trustly | x |
| Giropay | x |
| EPS | x |
| Przelewy24 | x |
| PSE | x |
| BLIK | x |
| Interac | x |
| Bizum | x |
| EFT | x |
| DuitNow | x |
| ACH | x |
| SEPA | x |
| BACS | x |
| Multibanco | x |
| Instant | x |
| Instant FI | x |
| Instant PL | x |
| Pix | x |
| Permata | x |
| BCA | x |
| BNI VA | x |
| BRI VA | x |
| CIMB VA | x |
| Danamon VA | x |
| Mandiri VA | x |
| Local | x |
| Indonesian | x |
| ACH | x |
| SEPA | x |
| BACS | x |
| BECS | x |
| SEPA Guaranteed | x |
| Crypto | x |
| Reward | x |
| Givex | x |
| PaySafeCard | x |
| E-Voucher | x |
| Boleto | x |
| Efecty | x |
| Pago Efectivo | x |
| Red Compra | x |
| Red Pagos | x |
| Alfamart | x |
| Indomaret | x |
| Oxxo | x |
| 7-Eleven | x |
| Lawson | x |
| Mini Stop | x |
| Family Mart | x |
| Seicomart | x |
| Pay Easy | x |

**Payment method objects** — use these in the `payment_method` field of the Authorize request.

##### Card (Raw PAN)

```python
"payment_method": {
    "card_number": "4111111111111111",
    "card_exp_month": "03",
    "card_exp_year": "2030",
    "card_cvc": "737",
    "card_holder_name": "John Doe"
}
```

**Examples:** [Python](../../examples/peachpayments/peachpayments.py#L274) · [TypeScript](../../examples/peachpayments/peachpayments.ts#L259) · [Kotlin](../../examples/peachpayments/peachpayments.kt) · [Rust](../../examples/peachpayments/peachpayments.rs#L266)

#### capture

**Examples:** [Python](../../examples/peachpayments/peachpayments.py#L310) · [TypeScript](../../examples/peachpayments/peachpayments.ts#L293) · [Kotlin](../../examples/peachpayments/peachpayments.kt) · [Rust](../../examples/peachpayments/peachpayments.rs#L300)

#### get

**Examples:** [Python](../../examples/peachpayments/peachpayments.py#L332) · [TypeScript](../../examples/peachpayments/peachpayments.ts#L312) · [Kotlin](../../examples/peachpayments/peachpayments.kt) · [Rust](../../examples/peachpayments/peachpayments.rs#L314)

#### handle_event

**Examples:** [Python](../../examples/peachpayments/peachpayments.py#L351) · [TypeScript](../../examples/peachpayments/peachpayments.ts#L327) · [Kotlin](../../examples/peachpayments/peachpayments.kt) · [Rust](../../examples/peachpayments/peachpayments.rs#L328)

#### proxy_authorize

**Examples:** [Python](../../examples/peachpayments/peachpayments.py#L365) · [TypeScript](../../examples/peachpayments/peachpayments.ts#L337) · [Kotlin](../../examples/peachpayments/peachpayments.kt) · [Rust](../../examples/peachpayments/peachpayments.rs#L337)

#### refund

**Examples:** [Python](../../examples/peachpayments/peachpayments.py#L395) · [TypeScript](../../examples/peachpayments/peachpayments.ts#L363) · [Kotlin](../../examples/peachpayments/peachpayments.kt) · [Rust](../../examples/peachpayments/peachpayments.rs#L364)

#### refund_get

**Examples:** [Python](../../examples/peachpayments/peachpayments.py#L419) · [TypeScript](../../examples/peachpayments/peachpayments.ts#L384) · [Kotlin](../../examples/peachpayments/peachpayments.kt) · [Rust](../../examples/peachpayments/peachpayments.rs#L380)

#### void

**Examples:** [Python](../../examples/peachpayments/peachpayments.py#L435) · [TypeScript](../../examples/peachpayments/peachpayments.ts) · [Kotlin](../../examples/peachpayments/peachpayments.kt) · [Rust](../../examples/peachpayments/peachpayments.rs#L391)
