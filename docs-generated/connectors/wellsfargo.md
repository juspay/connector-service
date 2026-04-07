# Wellsfargo

<!--
This file is auto-generated. Do not edit by hand.
Source: data/field_probe/wellsfargo.json
Regenerate: python3 scripts/generators/docs/generate.py wellsfargo
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
#     wellsfargo=payment_pb2.WellsfargoConfig(api_key=...),
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
    connector: 'Wellsfargo',
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
    .setConnector("Wellsfargo")
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
    connector: "Wellsfargo".to_string(),
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

**Examples:** [Python](../../examples/wellsfargo/wellsfargo.py#L23) · [JavaScript](../../examples/wellsfargo/wellsfargo.js) · [Kotlin](../../examples/wellsfargo/wellsfargo.kt#L23) · [Rust](../../examples/wellsfargo/wellsfargo.rs#L27)

### Card Payment (Authorize + Capture)

Two-step card payment. First authorize, then capture. Use when you need to verify funds before finalizing.

**Response status handling:**

| Status | Recommended action |
|--------|-------------------|
| `AUTHORIZED` | Funds reserved — proceed to Capture to settle |
| `PENDING` | Awaiting async confirmation — wait for webhook before capturing |
| `FAILED` | Payment declined — surface error to customer, do not retry without new details |

**Examples:** [Python](../../examples/wellsfargo/wellsfargo.py#L65) · [JavaScript](../../examples/wellsfargo/wellsfargo.js) · [Kotlin](../../examples/wellsfargo/wellsfargo.kt#L52) · [Rust](../../examples/wellsfargo/wellsfargo.rs#L68)

### Refund

Return funds to the customer for a completed payment.

**Examples:** [Python](../../examples/wellsfargo/wellsfargo.py#L122) · [JavaScript](../../examples/wellsfargo/wellsfargo.js) · [Kotlin](../../examples/wellsfargo/wellsfargo.kt#L92) · [Rust](../../examples/wellsfargo/wellsfargo.rs#L123)

### Void Payment

Cancel an authorized but not-yet-captured payment.

**Examples:** [Python](../../examples/wellsfargo/wellsfargo.py#L181) · [JavaScript](../../examples/wellsfargo/wellsfargo.js) · [Kotlin](../../examples/wellsfargo/wellsfargo.kt#L134) · [Rust](../../examples/wellsfargo/wellsfargo.rs#L180)

### Get Payment Status

Retrieve current payment status from the connector.

**Examples:** [Python](../../examples/wellsfargo/wellsfargo.py#L235) · [JavaScript](../../examples/wellsfargo/wellsfargo.js) · [Kotlin](../../examples/wellsfargo/wellsfargo.kt#L171) · [Rust](../../examples/wellsfargo/wellsfargo.rs#L231)

## API Reference

| Flow (Service.RPC) | Category | gRPC Request Message |
|--------------------|----------|----------------------|
| [authorize](#authorize) | Other | `—` |
| [capture](#capture) | Other | `—` |
| [get](#get) | Other | `—` |
| [proxy_authorize](#proxy_authorize) | Other | `—` |
| [proxy_setup_recurring](#proxy_setup_recurring) | Other | `—` |
| [refund](#refund) | Other | `—` |
| [refund_get](#refund_get) | Other | `—` |
| [setup_recurring](#setup_recurring) | Other | `—` |
| [void](#void) | Other | `—` |

### Other

#### authorize

**Supported payment method types:**

| Payment Method | Supported |
|----------------|:---------:|
| Card | ✓ |
| Bancontact | x |
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

**Examples:** [Python](../../examples/wellsfargo/wellsfargo.py#L289) · [TypeScript](../../examples/wellsfargo/wellsfargo.ts#L274) · [Kotlin](../../examples/wellsfargo/wellsfargo.kt) · [Rust](../../examples/wellsfargo/wellsfargo.rs#L281)

#### capture

**Examples:** [Python](../../examples/wellsfargo/wellsfargo.py#L328) · [TypeScript](../../examples/wellsfargo/wellsfargo.ts#L311) · [Kotlin](../../examples/wellsfargo/wellsfargo.kt) · [Rust](../../examples/wellsfargo/wellsfargo.rs#L318)

#### get

**Examples:** [Python](../../examples/wellsfargo/wellsfargo.py#L350) · [TypeScript](../../examples/wellsfargo/wellsfargo.ts#L330) · [Kotlin](../../examples/wellsfargo/wellsfargo.kt) · [Rust](../../examples/wellsfargo/wellsfargo.rs#L332)

#### proxy_authorize

**Examples:** [Python](../../examples/wellsfargo/wellsfargo.py#L369) · [TypeScript](../../examples/wellsfargo/wellsfargo.ts#L345) · [Kotlin](../../examples/wellsfargo/wellsfargo.kt) · [Rust](../../examples/wellsfargo/wellsfargo.rs#L346)

#### proxy_setup_recurring

**Examples:** [Python](../../examples/wellsfargo/wellsfargo.py#L402) · [TypeScript](../../examples/wellsfargo/wellsfargo.ts#L374) · [Kotlin](../../examples/wellsfargo/wellsfargo.kt) · [Rust](../../examples/wellsfargo/wellsfargo.rs#L376)

#### refund

**Examples:** [Python](../../examples/wellsfargo/wellsfargo.py#L438) · [TypeScript](../../examples/wellsfargo/wellsfargo.ts#L406) · [Kotlin](../../examples/wellsfargo/wellsfargo.kt) · [Rust](../../examples/wellsfargo/wellsfargo.rs#L409)

#### refund_get

**Examples:** [Python](../../examples/wellsfargo/wellsfargo.py#L462) · [TypeScript](../../examples/wellsfargo/wellsfargo.ts#L427) · [Kotlin](../../examples/wellsfargo/wellsfargo.kt) · [Rust](../../examples/wellsfargo/wellsfargo.rs#L425)

#### setup_recurring

**Examples:** [Python](../../examples/wellsfargo/wellsfargo.py#L478) · [TypeScript](../../examples/wellsfargo/wellsfargo.ts#L439) · [Kotlin](../../examples/wellsfargo/wellsfargo.kt) · [Rust](../../examples/wellsfargo/wellsfargo.rs#L436)

#### void

**Examples:** [Python](../../examples/wellsfargo/wellsfargo.py#L523) · [TypeScript](../../examples/wellsfargo/wellsfargo.ts) · [Kotlin](../../examples/wellsfargo/wellsfargo.kt) · [Rust](../../examples/wellsfargo/wellsfargo.rs#L477)
