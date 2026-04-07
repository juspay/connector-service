# Shift4

<!--
This file is auto-generated. Do not edit by hand.
Source: data/field_probe/shift4.json
Regenerate: python3 scripts/generators/docs/generate.py shift4
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
#     shift4=payment_pb2.Shift4Config(api_key=...),
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
    connector: 'Shift4',
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
    .setConnector("Shift4")
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
    connector: "Shift4".to_string(),
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

**Examples:** [Python](../../examples/shift4/shift4.py#L23) · [JavaScript](../../examples/shift4/shift4.js) · [Kotlin](../../examples/shift4/shift4.kt#L23) · [Rust](../../examples/shift4/shift4.rs#L27)

### Card Payment (Authorize + Capture)

Two-step card payment. First authorize, then capture. Use when you need to verify funds before finalizing.

**Response status handling:**

| Status | Recommended action |
|--------|-------------------|
| `AUTHORIZED` | Funds reserved — proceed to Capture to settle |
| `PENDING` | Awaiting async confirmation — wait for webhook before capturing |
| `FAILED` | Payment declined — surface error to customer, do not retry without new details |

**Examples:** [Python](../../examples/shift4/shift4.py#L63) · [JavaScript](../../examples/shift4/shift4.js) · [Kotlin](../../examples/shift4/shift4.kt#L52) · [Rust](../../examples/shift4/shift4.rs#L66)

### Refund

Return funds to the customer for a completed payment.

**Examples:** [Python](../../examples/shift4/shift4.py#L118) · [JavaScript](../../examples/shift4/shift4.js) · [Kotlin](../../examples/shift4/shift4.kt#L92) · [Rust](../../examples/shift4/shift4.rs#L119)

### Get Payment Status

Retrieve current payment status from the connector.

**Examples:** [Python](../../examples/shift4/shift4.py#L175) · [JavaScript](../../examples/shift4/shift4.js) · [Kotlin](../../examples/shift4/shift4.kt#L134) · [Rust](../../examples/shift4/shift4.rs#L174)

## API Reference

| Flow (Service.RPC) | Category | gRPC Request Message |
|--------------------|----------|----------------------|
| [authorize](#authorize) | Other | `—` |
| [capture](#capture) | Other | `—` |
| [create_customer](#create_customer) | Other | `—` |
| [get](#get) | Other | `—` |
| [proxy_authorize](#proxy_authorize) | Other | `—` |
| [recurring_charge](#recurring_charge) | Other | `—` |
| [refund](#refund) | Other | `—` |
| [refund_get](#refund_get) | Other | `—` |

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
| iDEAL | ✓ |
| Sofort | x |
| Trustly | x |
| Giropay | x |
| EPS | ✓ |
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

##### iDEAL

```python
"payment_method": {
}
```

**Examples:** [Python](../../examples/shift4/shift4.py#L227) · [TypeScript](../../examples/shift4/shift4.ts#L216) · [Kotlin](../../examples/shift4/shift4.kt) · [Rust](../../examples/shift4/shift4.rs#L222)

#### capture

**Examples:** [Python](../../examples/shift4/shift4.py#L264) · [TypeScript](../../examples/shift4/shift4.ts#L251) · [Kotlin](../../examples/shift4/shift4.kt) · [Rust](../../examples/shift4/shift4.rs#L257)

#### create_customer

**Examples:** [Python](../../examples/shift4/shift4.py#L286) · [TypeScript](../../examples/shift4/shift4.ts#L270) · [Kotlin](../../examples/shift4/shift4.kt) · [Rust](../../examples/shift4/shift4.rs#L271)

#### get

**Examples:** [Python](../../examples/shift4/shift4.py#L303) · [TypeScript](../../examples/shift4/shift4.ts#L283) · [Kotlin](../../examples/shift4/shift4.kt) · [Rust](../../examples/shift4/shift4.rs#L283)

#### proxy_authorize

**Examples:** [Python](../../examples/shift4/shift4.py#L322) · [TypeScript](../../examples/shift4/shift4.ts#L298) · [Kotlin](../../examples/shift4/shift4.kt) · [Rust](../../examples/shift4/shift4.rs#L297)

#### recurring_charge

**Examples:** [Python](../../examples/shift4/shift4.py#L353) · [TypeScript](../../examples/shift4/shift4.ts#L325) · [Kotlin](../../examples/shift4/shift4.kt) · [Rust](../../examples/shift4/shift4.rs#L325)

#### refund

**Examples:** [Python](../../examples/shift4/shift4.py#L383) · [TypeScript](../../examples/shift4/shift4.ts#L352) · [Kotlin](../../examples/shift4/shift4.kt) · [Rust](../../examples/shift4/shift4.rs#L353)

#### refund_get

**Examples:** [Python](../../examples/shift4/shift4.py#L407) · [TypeScript](../../examples/shift4/shift4.ts#L373) · [Kotlin](../../examples/shift4/shift4.kt) · [Rust](../../examples/shift4/shift4.rs#L369)
