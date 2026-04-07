# Hyperpg

<!--
This file is auto-generated. Do not edit by hand.
Source: data/field_probe/hyperpg.json
Regenerate: python3 scripts/generators/docs/generate.py hyperpg
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
#     hyperpg=payment_pb2.HyperpgConfig(api_key=...),
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
    connector: 'Hyperpg',
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
    .setConnector("Hyperpg")
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
    connector: "Hyperpg".to_string(),
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

**Examples:** [Python](../../examples/hyperpg/hyperpg.py#L23) · [JavaScript](../../examples/hyperpg/hyperpg.js) · [Kotlin](../../examples/hyperpg/hyperpg.kt#L23) · [Rust](../../examples/hyperpg/hyperpg.rs#L27)

### Refund

Return funds to the customer for a completed payment.

**Examples:** [Python](../../examples/hyperpg/hyperpg.py#L62) · [JavaScript](../../examples/hyperpg/hyperpg.js) · [Kotlin](../../examples/hyperpg/hyperpg.kt#L51) · [Rust](../../examples/hyperpg/hyperpg.rs#L65)

### Get Payment Status

Retrieve current payment status from the connector.

**Examples:** [Python](../../examples/hyperpg/hyperpg.py#L118) · [JavaScript](../../examples/hyperpg/hyperpg.js) · [Kotlin](../../examples/hyperpg/hyperpg.kt#L92) · [Rust](../../examples/hyperpg/hyperpg.rs#L119)

## API Reference

| Flow (Service.RPC) | Category | gRPC Request Message |
|--------------------|----------|----------------------|
| [authorize](#authorize) | Other | `—` |
| [get](#get) | Other | `—` |
| [proxy_authorize](#proxy_authorize) | Other | `—` |
| [refund](#refund) | Other | `—` |
| [refund_get](#refund_get) | Other | `—` |

### Other

#### authorize

**Supported payment method types:**

| Payment Method | Supported |
|----------------|:---------:|
| Card | ✓ |
| Bancontact | ⚠ |
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

**Examples:** [Python](../../examples/hyperpg/hyperpg.py#L170) · [TypeScript](../../examples/hyperpg/hyperpg.ts#L162) · [Kotlin](../../examples/hyperpg/hyperpg.kt) · [Rust](../../examples/hyperpg/hyperpg.rs#L167)

#### get

**Examples:** [Python](../../examples/hyperpg/hyperpg.py#L206) · [TypeScript](../../examples/hyperpg/hyperpg.ts#L196) · [Kotlin](../../examples/hyperpg/hyperpg.kt) · [Rust](../../examples/hyperpg/hyperpg.rs#L201)

#### proxy_authorize

**Examples:** [Python](../../examples/hyperpg/hyperpg.py#L226) · [TypeScript](../../examples/hyperpg/hyperpg.ts#L212) · [Kotlin](../../examples/hyperpg/hyperpg.kt) · [Rust](../../examples/hyperpg/hyperpg.rs#L216)

#### refund

**Examples:** [Python](../../examples/hyperpg/hyperpg.py#L256) · [TypeScript](../../examples/hyperpg/hyperpg.ts#L238) · [Kotlin](../../examples/hyperpg/hyperpg.kt) · [Rust](../../examples/hyperpg/hyperpg.rs#L243)

#### refund_get

**Examples:** [Python](../../examples/hyperpg/hyperpg.py#L280) · [TypeScript](../../examples/hyperpg/hyperpg.ts#L259) · [Kotlin](../../examples/hyperpg/hyperpg.kt) · [Rust](../../examples/hyperpg/hyperpg.rs#L259)
