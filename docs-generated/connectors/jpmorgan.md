# Jpmorgan

<!--
This file is auto-generated. Do not edit by hand.
Source: data/field_probe/jpmorgan.json
Regenerate: python3 scripts/generators/docs/generate.py jpmorgan
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
#     jpmorgan=payment_pb2.JpmorganConfig(api_key=...),
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
    connector: 'Jpmorgan',
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
    .setConnector("Jpmorgan")
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
    connector: "Jpmorgan".to_string(),
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

**Examples:** [Python](../../examples/jpmorgan/jpmorgan.py#L23) · [JavaScript](../../examples/jpmorgan/jpmorgan.js) · [Kotlin](../../examples/jpmorgan/jpmorgan.kt#L23) · [Rust](../../examples/jpmorgan/jpmorgan.rs#L27)

### Card Payment (Authorize + Capture)

Two-step card payment. First authorize, then capture. Use when you need to verify funds before finalizing.

**Response status handling:**

| Status | Recommended action |
|--------|-------------------|
| `AUTHORIZED` | Funds reserved — proceed to Capture to settle |
| `PENDING` | Awaiting async confirmation — wait for webhook before capturing |
| `FAILED` | Payment declined — surface error to customer, do not retry without new details |

**Examples:** [Python](../../examples/jpmorgan/jpmorgan.py#L67) · [JavaScript](../../examples/jpmorgan/jpmorgan.js) · [Kotlin](../../examples/jpmorgan/jpmorgan.kt#L54) · [Rust](../../examples/jpmorgan/jpmorgan.rs#L72)

### Refund

Return funds to the customer for a completed payment.

**Examples:** [Python](../../examples/jpmorgan/jpmorgan.py#L131) · [JavaScript](../../examples/jpmorgan/jpmorgan.js) · [Kotlin](../../examples/jpmorgan/jpmorgan.kt#L99) · [Rust](../../examples/jpmorgan/jpmorgan.rs#L138)

### Void Payment

Cancel an authorized but not-yet-captured payment.

**Examples:** [Python](../../examples/jpmorgan/jpmorgan.py#L197) · [JavaScript](../../examples/jpmorgan/jpmorgan.js) · [Kotlin](../../examples/jpmorgan/jpmorgan.kt#L146) · [Rust](../../examples/jpmorgan/jpmorgan.rs#L206)

### Get Payment Status

Retrieve current payment status from the connector.

**Examples:** [Python](../../examples/jpmorgan/jpmorgan.py#L254) · [JavaScript](../../examples/jpmorgan/jpmorgan.js) · [Kotlin](../../examples/jpmorgan/jpmorgan.kt#L186) · [Rust](../../examples/jpmorgan/jpmorgan.rs#L264)

## API Reference

| Flow (Service.RPC) | Category | gRPC Request Message |
|--------------------|----------|----------------------|
| [authorize](#authorize) | Other | `—` |
| [capture](#capture) | Other | `—` |
| [create_server_authentication_token](#create_server_authentication_token) | Other | `—` |
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
| ACH | ✓ |
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

##### ACH Direct Debit

```python
"payment_method": {
    "account_number": "000123456789",
    "routing_number": "110000000",
    "bank_account_holder_name": "John Doe"
}
```

**Examples:** [Python](../../examples/jpmorgan/jpmorgan.py#L315) · [TypeScript](../../examples/jpmorgan/jpmorgan.ts#L300) · [Kotlin](../../examples/jpmorgan/jpmorgan.kt) · [Rust](../../examples/jpmorgan/jpmorgan.rs#L325)

#### capture

**Examples:** [Python](../../examples/jpmorgan/jpmorgan.py#L356) · [TypeScript](../../examples/jpmorgan/jpmorgan.ts#L339) · [Kotlin](../../examples/jpmorgan/jpmorgan.kt) · [Rust](../../examples/jpmorgan/jpmorgan.rs#L366)

#### create_server_authentication_token

**Examples:** [Python](../../examples/jpmorgan/jpmorgan.py#L383) · [TypeScript](../../examples/jpmorgan/jpmorgan.ts#L363) · [Kotlin](../../examples/jpmorgan/jpmorgan.kt) · [Rust](../../examples/jpmorgan/jpmorgan.rs#L387)

#### get

**Examples:** [Python](../../examples/jpmorgan/jpmorgan.py#L397) · [TypeScript](../../examples/jpmorgan/jpmorgan.ts#L373) · [Kotlin](../../examples/jpmorgan/jpmorgan.kt) · [Rust](../../examples/jpmorgan/jpmorgan.rs#L396)

#### proxy_authorize

**Examples:** [Python](../../examples/jpmorgan/jpmorgan.py#L421) · [TypeScript](../../examples/jpmorgan/jpmorgan.ts#L393) · [Kotlin](../../examples/jpmorgan/jpmorgan.kt) · [Rust](../../examples/jpmorgan/jpmorgan.rs#L417)

#### refund

**Examples:** [Python](../../examples/jpmorgan/jpmorgan.py#L456) · [TypeScript](../../examples/jpmorgan/jpmorgan.ts#L424) · [Kotlin](../../examples/jpmorgan/jpmorgan.kt) · [Rust](../../examples/jpmorgan/jpmorgan.rs#L451)

#### refund_get

**Examples:** [Python](../../examples/jpmorgan/jpmorgan.py#L485) · [TypeScript](../../examples/jpmorgan/jpmorgan.ts#L450) · [Kotlin](../../examples/jpmorgan/jpmorgan.kt) · [Rust](../../examples/jpmorgan/jpmorgan.rs#L474)

#### void

**Examples:** [Python](../../examples/jpmorgan/jpmorgan.py#L506) · [TypeScript](../../examples/jpmorgan/jpmorgan.ts) · [Kotlin](../../examples/jpmorgan/jpmorgan.kt) · [Rust](../../examples/jpmorgan/jpmorgan.rs#L492)
