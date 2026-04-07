# Zift

<!--
This file is auto-generated. Do not edit by hand.
Source: data/field_probe/zift.json
Regenerate: python3 scripts/generators/docs/generate.py zift
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
#     zift=payment_pb2.ZiftConfig(api_key=...),
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
    connector: 'Zift',
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
    .setConnector("Zift")
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
    connector: "Zift".to_string(),
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

**Examples:** [Python](../../examples/zift/zift.py#L23) · [JavaScript](../../examples/zift/zift.js) · [Kotlin](../../examples/zift/zift.kt#L23) · [Rust](../../examples/zift/zift.rs#L27)

### Card Payment (Authorize + Capture)

Two-step card payment. First authorize, then capture. Use when you need to verify funds before finalizing.

**Response status handling:**

| Status | Recommended action |
|--------|-------------------|
| `AUTHORIZED` | Funds reserved — proceed to Capture to settle |
| `PENDING` | Awaiting async confirmation — wait for webhook before capturing |
| `FAILED` | Payment declined — surface error to customer, do not retry without new details |

**Examples:** [Python](../../examples/zift/zift.py#L63) · [JavaScript](../../examples/zift/zift.js) · [Kotlin](../../examples/zift/zift.kt#L52) · [Rust](../../examples/zift/zift.rs#L66)

### Refund

Return funds to the customer for a completed payment.

**Examples:** [Python](../../examples/zift/zift.py#L118) · [JavaScript](../../examples/zift/zift.js) · [Kotlin](../../examples/zift/zift.kt#L92) · [Rust](../../examples/zift/zift.rs#L119)

### Void Payment

Cancel an authorized but not-yet-captured payment.

**Examples:** [Python](../../examples/zift/zift.py#L175) · [JavaScript](../../examples/zift/zift.js) · [Kotlin](../../examples/zift/zift.kt#L134) · [Rust](../../examples/zift/zift.rs#L174)

### Get Payment Status

Retrieve current payment status from the connector.

**Examples:** [Python](../../examples/zift/zift.py#L223) · [JavaScript](../../examples/zift/zift.js) · [Kotlin](../../examples/zift/zift.kt#L169) · [Rust](../../examples/zift/zift.rs#L219)

## API Reference

| Flow (Service.RPC) | Category | gRPC Request Message |
|--------------------|----------|----------------------|
| [authorize](#authorize) | Other | `—` |
| [capture](#capture) | Other | `—` |
| [get](#get) | Other | `—` |
| [proxy_authorize](#proxy_authorize) | Other | `—` |
| [proxy_setup_recurring](#proxy_setup_recurring) | Other | `—` |
| [refund](#refund) | Other | `—` |
| [setup_recurring](#setup_recurring) | Other | `—` |
| [void](#void) | Other | `—` |

### Other

#### authorize

**Supported payment method types:**

| Payment Method | Supported |
|----------------|:---------:|
| Card | ✓ |
| Bancontact | ⚠ |
| Apple Pay | ⚠ |
| Apple Pay Dec | ⚠ |
| Apple Pay SDK | ⚠ |
| Google Pay | ⚠ |
| Google Pay Dec | ⚠ |
| Google Pay SDK | ⚠ |
| PayPal SDK | ⚠ |
| Amazon Pay | ⚠ |
| Cash App | ⚠ |
| PayPal | ⚠ |
| WeChat Pay | ⚠ |
| Alipay | ⚠ |
| Revolut Pay | ⚠ |
| MiFinity | ⚠ |
| Bluecode | ⚠ |
| Paze | x |
| Samsung Pay | ⚠ |
| MB Way | ⚠ |
| Satispay | ⚠ |
| Wero | ⚠ |
| Affirm | ⚠ |
| Afterpay | ⚠ |
| Klarna | ⚠ |
| UPI Collect | ⚠ |
| UPI Intent | ⚠ |
| UPI QR | ⚠ |
| Thailand | ⚠ |
| Czech | ⚠ |
| Finland | ⚠ |
| FPX | ⚠ |
| Poland | ⚠ |
| Slovakia | ⚠ |
| UK | ⚠ |
| PIS | x |
| Generic | ⚠ |
| Local | ⚠ |
| iDEAL | ⚠ |
| Sofort | ⚠ |
| Trustly | ⚠ |
| Giropay | ⚠ |
| EPS | ⚠ |
| Przelewy24 | ⚠ |
| PSE | ⚠ |
| BLIK | ⚠ |
| Interac | ⚠ |
| Bizum | ⚠ |
| EFT | ⚠ |
| DuitNow | x |
| ACH | ⚠ |
| SEPA | ⚠ |
| BACS | ⚠ |
| Multibanco | ⚠ |
| Instant | ⚠ |
| Instant FI | ⚠ |
| Instant PL | ⚠ |
| Pix | ⚠ |
| Permata | ⚠ |
| BCA | ⚠ |
| BNI VA | ⚠ |
| BRI VA | ⚠ |
| CIMB VA | ⚠ |
| Danamon VA | ⚠ |
| Mandiri VA | ⚠ |
| Local | ⚠ |
| Indonesian | ⚠ |
| ACH | ⚠ |
| SEPA | ⚠ |
| BACS | ⚠ |
| BECS | ⚠ |
| SEPA Guaranteed | ⚠ |
| Crypto | x |
| Reward | ⚠ |
| Givex | x |
| PaySafeCard | x |
| E-Voucher | ⚠ |
| Boleto | ⚠ |
| Efecty | ⚠ |
| Pago Efectivo | ⚠ |
| Red Compra | ⚠ |
| Red Pagos | ⚠ |
| Alfamart | ⚠ |
| Indomaret | ⚠ |
| Oxxo | ⚠ |
| 7-Eleven | ⚠ |
| Lawson | ⚠ |
| Mini Stop | ⚠ |
| Family Mart | ⚠ |
| Seicomart | ⚠ |
| Pay Easy | ⚠ |

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

**Examples:** [Python](../../examples/zift/zift.py#L275) · [TypeScript](../../examples/zift/zift.ts#L260) · [Kotlin](../../examples/zift/zift.kt) · [Rust](../../examples/zift/zift.rs#L267)

#### capture

**Examples:** [Python](../../examples/zift/zift.py#L312) · [TypeScript](../../examples/zift/zift.ts#L295) · [Kotlin](../../examples/zift/zift.kt) · [Rust](../../examples/zift/zift.rs#L302)

#### get

**Examples:** [Python](../../examples/zift/zift.py#L334) · [TypeScript](../../examples/zift/zift.ts#L314) · [Kotlin](../../examples/zift/zift.kt) · [Rust](../../examples/zift/zift.rs#L316)

#### proxy_authorize

**Examples:** [Python](../../examples/zift/zift.py#L353) · [TypeScript](../../examples/zift/zift.ts#L329) · [Kotlin](../../examples/zift/zift.kt) · [Rust](../../examples/zift/zift.rs#L330)

#### proxy_setup_recurring

**Examples:** [Python](../../examples/zift/zift.py#L384) · [TypeScript](../../examples/zift/zift.ts#L356) · [Kotlin](../../examples/zift/zift.kt) · [Rust](../../examples/zift/zift.rs#L358)

#### refund

**Examples:** [Python](../../examples/zift/zift.py#L418) · [TypeScript](../../examples/zift/zift.ts#L386) · [Kotlin](../../examples/zift/zift.kt) · [Rust](../../examples/zift/zift.rs#L389)

#### setup_recurring

**Examples:** [Python](../../examples/zift/zift.py#L442) · [TypeScript](../../examples/zift/zift.ts#L407) · [Kotlin](../../examples/zift/zift.kt) · [Rust](../../examples/zift/zift.rs#L405)

#### void

**Examples:** [Python](../../examples/zift/zift.py#L485) · [TypeScript](../../examples/zift/zift.ts) · [Kotlin](../../examples/zift/zift.kt) · [Rust](../../examples/zift/zift.rs#L444)
