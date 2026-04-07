# Mollie

<!--
This file is auto-generated. Do not edit by hand.
Source: data/field_probe/mollie.json
Regenerate: python3 scripts/generators/docs/generate.py mollie
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
#     mollie=payment_pb2.MollieConfig(api_key=...),
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
    connector: 'Mollie',
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
    .setConnector("Mollie")
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
    connector: "Mollie".to_string(),
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

**Examples:** [Python](../../examples/mollie/mollie.py#L23) · [JavaScript](../../examples/mollie/mollie.js) · [Kotlin](../../examples/mollie/mollie.kt#L23) · [Rust](../../examples/mollie/mollie.rs#L27)

### Refund

Return funds to the customer for a completed payment.

**Examples:** [Python](../../examples/mollie/mollie.py#L63) · [JavaScript](../../examples/mollie/mollie.js) · [Kotlin](../../examples/mollie/mollie.kt#L52) · [Rust](../../examples/mollie/mollie.rs#L66)

### Void Payment

Cancel an authorized but not-yet-captured payment.

**Examples:** [Python](../../examples/mollie/mollie.py#L120) · [JavaScript](../../examples/mollie/mollie.js) · [Kotlin](../../examples/mollie/mollie.kt#L94) · [Rust](../../examples/mollie/mollie.rs#L121)

### Get Payment Status

Retrieve current payment status from the connector.

**Examples:** [Python](../../examples/mollie/mollie.py#L168) · [JavaScript](../../examples/mollie/mollie.js) · [Kotlin](../../examples/mollie/mollie.kt#L129) · [Rust](../../examples/mollie/mollie.rs#L166)

## API Reference

| Flow (Service.RPC) | Category | gRPC Request Message |
|--------------------|----------|----------------------|
| [authorize](#authorize) | Other | `—` |
| [get](#get) | Other | `—` |
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

**Examples:** [Python](../../examples/mollie/mollie.py#L220) · [TypeScript](../../examples/mollie/mollie.ts#L208) · [Kotlin](../../examples/mollie/mollie.kt) · [Rust](../../examples/mollie/mollie.rs#L214)

#### get

**Examples:** [Python](../../examples/mollie/mollie.py#L257) · [TypeScript](../../examples/mollie/mollie.ts#L243) · [Kotlin](../../examples/mollie/mollie.kt) · [Rust](../../examples/mollie/mollie.rs#L249)

#### proxy_authorize

**Examples:** [Python](../../examples/mollie/mollie.py#L276) · [TypeScript](../../examples/mollie/mollie.ts#L258) · [Kotlin](../../examples/mollie/mollie.kt) · [Rust](../../examples/mollie/mollie.rs#L263)

#### refund

**Examples:** [Python](../../examples/mollie/mollie.py#L307) · [TypeScript](../../examples/mollie/mollie.ts#L285) · [Kotlin](../../examples/mollie/mollie.kt) · [Rust](../../examples/mollie/mollie.rs#L291)

#### refund_get

**Examples:** [Python](../../examples/mollie/mollie.py#L331) · [TypeScript](../../examples/mollie/mollie.ts#L306) · [Kotlin](../../examples/mollie/mollie.kt) · [Rust](../../examples/mollie/mollie.rs#L307)

#### void

**Examples:** [Python](../../examples/mollie/mollie.py#L347) · [TypeScript](../../examples/mollie/mollie.ts) · [Kotlin](../../examples/mollie/mollie.kt) · [Rust](../../examples/mollie/mollie.rs#L318)
