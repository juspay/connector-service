# ACI

<!--
This file is auto-generated. Do not edit by hand.
Source: data/field_probe/aci.json
Regenerate: python3 scripts/generators/docs/generate.py aci
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
#     aci=payment_pb2.AciConfig(api_key=...),
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
    connector: 'Aci',
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
    .setConnector("Aci")
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
    connector: "Aci".to_string(),
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

**Examples:** [Python](../../examples/aci/aci.py#L23) · [JavaScript](../../examples/aci/aci.js) · [Kotlin](../../examples/aci/aci.kt#L23) · [Rust](../../examples/aci/aci.rs#L27)

### Card Payment (Authorize + Capture)

Two-step card payment. First authorize, then capture. Use when you need to verify funds before finalizing.

**Response status handling:**

| Status | Recommended action |
|--------|-------------------|
| `AUTHORIZED` | Funds reserved — proceed to Capture to settle |
| `PENDING` | Awaiting async confirmation — wait for webhook before capturing |
| `FAILED` | Payment declined — surface error to customer, do not retry without new details |

**Examples:** [Python](../../examples/aci/aci.py#L63) · [JavaScript](../../examples/aci/aci.js) · [Kotlin](../../examples/aci/aci.kt#L52) · [Rust](../../examples/aci/aci.rs#L66)

### Refund

Return funds to the customer for a completed payment.

**Examples:** [Python](../../examples/aci/aci.py#L118) · [JavaScript](../../examples/aci/aci.js) · [Kotlin](../../examples/aci/aci.kt#L92) · [Rust](../../examples/aci/aci.rs#L119)

### Void Payment

Cancel an authorized but not-yet-captured payment.

**Examples:** [Python](../../examples/aci/aci.py#L175) · [JavaScript](../../examples/aci/aci.js) · [Kotlin](../../examples/aci/aci.kt#L134) · [Rust](../../examples/aci/aci.rs#L174)

### Get Payment Status

Retrieve current payment status from the connector.

**Examples:** [Python](../../examples/aci/aci.py#L223) · [JavaScript](../../examples/aci/aci.js) · [Kotlin](../../examples/aci/aci.kt#L169) · [Rust](../../examples/aci/aci.rs#L219)

## API Reference

| Flow (Service.RPC) | Category | gRPC Request Message |
|--------------------|----------|----------------------|
| [authorize](#authorize) | Other | `—` |
| [capture](#capture) | Other | `—` |
| [get](#get) | Other | `—` |
| [proxy_authorize](#proxy_authorize) | Other | `—` |
| [proxy_setup_recurring](#proxy_setup_recurring) | Other | `—` |
| [recurring_charge](#recurring_charge) | Other | `—` |
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
| Alipay | ✓ |
| Revolut Pay | ⚠ |
| MiFinity | ⚠ |
| Bluecode | ⚠ |
| Paze | x |
| Samsung Pay | ⚠ |
| MB Way | ⚠ |
| Satispay | ⚠ |
| Wero | ⚠ |
| Affirm | ✓ |
| Afterpay | ✓ |
| Klarna | ✓ |
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
| iDEAL | ✓ |
| Sofort | ✓ |
| Trustly | ✓ |
| Giropay | ✓ |
| EPS | ✓ |
| Przelewy24 | ✓ |
| PSE | ⚠ |
| BLIK | ⚠ |
| Interac | ✓ |
| Bizum | ⚠ |
| EFT | ✓ |
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

##### iDEAL

```python
"payment_method": {
    "bank_name": "Ing"
}
```

##### Klarna

```python
"payment_method": {
}
```

##### Afterpay / Clearpay

```python
"payment_method": {
}
```

##### Affirm

```python
"payment_method": {
}
```

**Examples:** [Python](../../examples/aci/aci.py#L275) · [TypeScript](../../examples/aci/aci.ts#L260) · [Kotlin](../../examples/aci/aci.kt) · [Rust](../../examples/aci/aci.rs#L267)

#### capture

**Examples:** [Python](../../examples/aci/aci.py#L312) · [TypeScript](../../examples/aci/aci.ts#L295) · [Kotlin](../../examples/aci/aci.kt) · [Rust](../../examples/aci/aci.rs#L302)

#### get

**Examples:** [Python](../../examples/aci/aci.py#L334) · [TypeScript](../../examples/aci/aci.ts#L314) · [Kotlin](../../examples/aci/aci.kt) · [Rust](../../examples/aci/aci.rs#L316)

#### proxy_authorize

**Examples:** [Python](../../examples/aci/aci.py#L353) · [TypeScript](../../examples/aci/aci.ts#L329) · [Kotlin](../../examples/aci/aci.kt) · [Rust](../../examples/aci/aci.rs#L330)

#### proxy_setup_recurring

**Examples:** [Python](../../examples/aci/aci.py#L384) · [TypeScript](../../examples/aci/aci.ts#L356) · [Kotlin](../../examples/aci/aci.kt) · [Rust](../../examples/aci/aci.rs#L358)

#### recurring_charge

**Examples:** [Python](../../examples/aci/aci.py#L417) · [TypeScript](../../examples/aci/aci.ts#L385) · [Kotlin](../../examples/aci/aci.kt) · [Rust](../../examples/aci/aci.rs#L388)

#### refund

**Examples:** [Python](../../examples/aci/aci.py#L447) · [TypeScript](../../examples/aci/aci.ts#L412) · [Kotlin](../../examples/aci/aci.kt) · [Rust](../../examples/aci/aci.rs#L416)

#### setup_recurring

**Examples:** [Python](../../examples/aci/aci.py#L471) · [TypeScript](../../examples/aci/aci.ts#L433) · [Kotlin](../../examples/aci/aci.kt) · [Rust](../../examples/aci/aci.rs#L432)

#### void

**Examples:** [Python](../../examples/aci/aci.py#L513) · [TypeScript](../../examples/aci/aci.ts) · [Kotlin](../../examples/aci/aci.kt) · [Rust](../../examples/aci/aci.rs#L470)
