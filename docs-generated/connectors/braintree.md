# Braintree

<!--
This file is auto-generated. Do not edit by hand.
Source: data/field_probe/braintree.json
Regenerate: python3 scripts/generators/docs/generate.py braintree
-->

## SDK Configuration

Use this config for all flows in this connector. Replace `YOUR_API_KEY` with your actual credentials.

<table>
<tr><td><b>Python</b></td><td><b>JavaScript</b></td><td><b>Kotlin</b></td><td><b>Rust</b></td></tr>
<tr>
<td valign="top">

<details><summary>Python</summary>

```python
from payments.generated import sdk_config_pb2, payment_pb2, payment_methods_pb2

config = sdk_config_pb2.ConnectorConfig(
    options=sdk_config_pb2.SdkOptions(environment=sdk_config_pb2.Environment.SANDBOX),
)
# Set credentials before running (field names depend on connector auth type):
# config.connector_config.CopyFrom(payment_pb2.ConnectorSpecificConfig(
#     braintree=payment_pb2.BraintreeConfig(api_key=...),
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
    connector: 'Braintree',
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
    .setConnector("Braintree")
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
    connector: "Braintree".to_string(),
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
| [create_client_authentication_token](#create_client_authentication_token) | Other | `—` |
| [get](#get) | Other | `—` |
| [refund](#refund) | Other | `—` |
| [refund_get](#refund_get) | Other | `—` |
| [tokenize](#tokenize) | Other | `—` |
| [void](#void) | Other | `—` |

### Other

#### authorize

**Supported payment method types:**

| Payment Method | Supported |
|----------------|:---------:|
| Card | ? |
| Bancontact | ⚠ |
| Apple Pay | ⚠ |
| Apple Pay Dec | ⚠ |
| Apple Pay SDK | ✓ |
| Google Pay | ⚠ |
| Google Pay Dec | ⚠ |
| Google Pay SDK | ✓ |
| PayPal SDK | ✓ |
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

**Examples:** [Python](../../examples/braintree/braintree.py) · [TypeScript](../../examples/braintree/braintree.ts) · [Kotlin](../../examples/braintree/braintree.kt) · [Rust](../../examples/braintree/braintree.rs)

#### capture

**Examples:** [Python](../../examples/braintree/braintree.py#L23) · [TypeScript](../../examples/braintree/braintree.ts#L24) · [Kotlin](../../examples/braintree/braintree.kt) · [Rust](../../examples/braintree/braintree.rs#L26)

#### create_client_authentication_token

**Examples:** [Python](../../examples/braintree/braintree.py#L45) · [TypeScript](../../examples/braintree/braintree.ts#L43) · [Kotlin](../../examples/braintree/braintree.kt) · [Rust](../../examples/braintree/braintree.rs#L40)

#### get

**Examples:** [Python](../../examples/braintree/braintree.py#L63) · [TypeScript](../../examples/braintree/braintree.ts#L57) · [Kotlin](../../examples/braintree/braintree.kt) · [Rust](../../examples/braintree/braintree.rs#L57)

#### refund

**Examples:** [Python](../../examples/braintree/braintree.py#L82) · [TypeScript](../../examples/braintree/braintree.ts#L72) · [Kotlin](../../examples/braintree/braintree.kt) · [Rust](../../examples/braintree/braintree.rs#L71)

#### refund_get

**Examples:** [Python](../../examples/braintree/braintree.py#L106) · [TypeScript](../../examples/braintree/braintree.ts#L93) · [Kotlin](../../examples/braintree/braintree.kt) · [Rust](../../examples/braintree/braintree.rs#L87)

#### tokenize

**Examples:** [Python](../../examples/braintree/braintree.py#L123) · [TypeScript](../../examples/braintree/braintree.ts#L106) · [Kotlin](../../examples/braintree/braintree.kt) · [Rust](../../examples/braintree/braintree.rs#L99)

#### void

**Examples:** [Python](../../examples/braintree/braintree.py#L149) · [TypeScript](../../examples/braintree/braintree.ts) · [Kotlin](../../examples/braintree/braintree.kt) · [Rust](../../examples/braintree/braintree.rs#L124)
