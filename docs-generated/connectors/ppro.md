# Ppro

<!--
This file is auto-generated. Do not edit by hand.
Source: data/field_probe/ppro.json
Regenerate: python3 scripts/generators/docs/generate.py ppro
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
#     ppro=payment_pb2.PproConfig(api_key=...),
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
    connector: 'Ppro',
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
    .setConnector("Ppro")
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
    connector: "Ppro".to_string(),
    environment: Environment::Sandbox,
    auth: ConnectorAuth::HeaderKey { api_key: "YOUR_API_KEY".into() },
    ..Default::default()
};
```

</details>

</td>
</tr>
</table>

## API Reference

| Flow (Service.RPC) | Category | gRPC Request Message |
|--------------------|----------|----------------------|
| [authorize](#authorize) | Other | `—` |
| [capture](#capture) | Other | `—` |
| [get](#get) | Other | `—` |
| [handle_event](#handle_event) | Other | `—` |
| [recurring_charge](#recurring_charge) | Other | `—` |
| [refund](#refund) | Other | `—` |
| [refund_get](#refund_get) | Other | `—` |
| [void](#void) | Other | `—` |

### Other

#### authorize

**Supported payment method types:**

| Payment Method | Supported |
|----------------|:---------:|
| Card | x |
| Bancontact | ✓ |
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
| WeChat Pay | ✓ |
| Alipay | ✓ |
| Revolut Pay | x |
| MiFinity | x |
| Bluecode | x |
| Paze | x |
| Samsung Pay | x |
| MB Way | ✓ |
| Satispay | ✓ |
| Wero | ✓ |
| Affirm | x |
| Afterpay | x |
| Klarna | x |
| UPI Collect | x |
| UPI Intent | ✓ |
| UPI QR | ✓ |
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
| iDEAL | ✓ |
| Sofort | x |
| Trustly | ✓ |
| Giropay | x |
| EPS | x |
| Przelewy24 | x |
| PSE | x |
| BLIK | ✓ |
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

##### iDEAL

```python
"payment_method": {
}
```

##### BLIK

```python
"payment_method": {
    "blik_code": "777124"
}
```

**Examples:** [Python](../../examples/ppro/ppro.py#L23) · [TypeScript](../../examples/ppro/ppro.ts#L24) · [Kotlin](../../examples/ppro/ppro.kt) · [Rust](../../examples/ppro/ppro.rs#L26)

#### capture

**Examples:** [Python](../../examples/ppro/ppro.py#L54) · [TypeScript](../../examples/ppro/ppro.ts#L53) · [Kotlin](../../examples/ppro/ppro.kt) · [Rust](../../examples/ppro/ppro.rs#L55)

#### get

**Examples:** [Python](../../examples/ppro/ppro.py#L76) · [TypeScript](../../examples/ppro/ppro.ts#L72) · [Kotlin](../../examples/ppro/ppro.kt) · [Rust](../../examples/ppro/ppro.rs#L69)

#### handle_event

**Examples:** [Python](../../examples/ppro/ppro.py#L95) · [TypeScript](../../examples/ppro/ppro.ts#L87) · [Kotlin](../../examples/ppro/ppro.kt) · [Rust](../../examples/ppro/ppro.rs#L83)

#### recurring_charge

**Examples:** [Python](../../examples/ppro/ppro.py#L109) · [TypeScript](../../examples/ppro/ppro.ts#L97) · [Kotlin](../../examples/ppro/ppro.kt) · [Rust](../../examples/ppro/ppro.rs#L92)

#### refund

**Examples:** [Python](../../examples/ppro/ppro.py#L139) · [TypeScript](../../examples/ppro/ppro.ts#L124) · [Kotlin](../../examples/ppro/ppro.kt) · [Rust](../../examples/ppro/ppro.rs#L120)

#### refund_get

**Examples:** [Python](../../examples/ppro/ppro.py#L163) · [TypeScript](../../examples/ppro/ppro.ts#L145) · [Kotlin](../../examples/ppro/ppro.kt) · [Rust](../../examples/ppro/ppro.rs#L136)

#### void

**Examples:** [Python](../../examples/ppro/ppro.py#L179) · [TypeScript](../../examples/ppro/ppro.ts) · [Kotlin](../../examples/ppro/ppro.kt) · [Rust](../../examples/ppro/ppro.rs#L147)
