# Payload

<!--
This file is auto-generated. Do not edit by hand.
Source: data/field_probe/payload.json
Regenerate: python3 scripts/generators/docs/generate.py payload
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
#     payload=payment_pb2.PayloadConfig(api_key=...),
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
    connector: 'Payload',
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
    .setConnector("Payload")
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
    connector: "Payload".to_string(),
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

**Examples:** [Python](../../examples/payload/payload.py#L23) · [JavaScript](../../examples/payload/payload.js) · [Kotlin](../../examples/payload/payload.kt#L23) · [Rust](../../examples/payload/payload.rs#L27)

### Card Payment (Authorize + Capture)

Two-step card payment. First authorize, then capture. Use when you need to verify funds before finalizing.

**Response status handling:**

| Status | Recommended action |
|--------|-------------------|
| `AUTHORIZED` | Funds reserved — proceed to Capture to settle |
| `PENDING` | Awaiting async confirmation — wait for webhook before capturing |
| `FAILED` | Payment declined — surface error to customer, do not retry without new details |

**Examples:** [Python](../../examples/payload/payload.py#L72) · [JavaScript](../../examples/payload/payload.js) · [Kotlin](../../examples/payload/payload.kt#L59) · [Rust](../../examples/payload/payload.rs#L77)

### Refund

Return funds to the customer for a completed payment.

**Examples:** [Python](../../examples/payload/payload.py#L141) · [JavaScript](../../examples/payload/payload.js) · [Kotlin](../../examples/payload/payload.kt#L109) · [Rust](../../examples/payload/payload.rs#L148)

### Void Payment

Cancel an authorized but not-yet-captured payment.

**Examples:** [Python](../../examples/payload/payload.py#L212) · [JavaScript](../../examples/payload/payload.js) · [Kotlin](../../examples/payload/payload.kt#L161) · [Rust](../../examples/payload/payload.rs#L221)

### Get Payment Status

Retrieve current payment status from the connector.

**Examples:** [Python](../../examples/payload/payload.py#L274) · [JavaScript](../../examples/payload/payload.js) · [Kotlin](../../examples/payload/payload.kt#L206) · [Rust](../../examples/payload/payload.rs#L284)

## API Reference

| Flow (Service.RPC) | Category | gRPC Request Message |
|--------------------|----------|----------------------|
| [authorize](#authorize) | Other | `—` |
| [capture](#capture) | Other | `—` |
| [get](#get) | Other | `—` |
| [handle_event](#handle_event) | Other | `—` |
| [proxy_authorize](#proxy_authorize) | Other | `—` |
| [proxy_setup_recurring](#proxy_setup_recurring) | Other | `—` |
| [recurring_charge](#recurring_charge) | Other | `—` |
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
| Apple Pay SDK | x |
| Google Pay | ⚠ |
| Google Pay Dec | ⚠ |
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
| ACH | ✓ |
| SEPA | ⚠ |
| BACS | ⚠ |
| BECS | ⚠ |
| SEPA Guaranteed | ⚠ |
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

##### ACH Direct Debit

```python
"payment_method": {
    "account_number": "000123456789",
    "routing_number": "110000000",
    "bank_account_holder_name": "John Doe"
}
```

**Examples:** [Python](../../examples/payload/payload.py#L340) · [TypeScript](../../examples/payload/payload.ts#L325) · [Kotlin](../../examples/payload/payload.kt) · [Rust](../../examples/payload/payload.rs#L350)

#### capture

**Examples:** [Python](../../examples/payload/payload.py#L386) · [TypeScript](../../examples/payload/payload.ts#L369) · [Kotlin](../../examples/payload/payload.kt) · [Rust](../../examples/payload/payload.rs#L396)

#### get

**Examples:** [Python](../../examples/payload/payload.py#L413) · [TypeScript](../../examples/payload/payload.ts#L393) · [Kotlin](../../examples/payload/payload.kt) · [Rust](../../examples/payload/payload.rs#L417)

#### handle_event

**Examples:** [Python](../../examples/payload/payload.py#L437) · [TypeScript](../../examples/payload/payload.ts#L413) · [Kotlin](../../examples/payload/payload.kt) · [Rust](../../examples/payload/payload.rs#L438)

#### proxy_authorize

**Examples:** [Python](../../examples/payload/payload.py#L451) · [TypeScript](../../examples/payload/payload.ts#L423) · [Kotlin](../../examples/payload/payload.kt) · [Rust](../../examples/payload/payload.rs#L447)

#### proxy_setup_recurring

**Examples:** [Python](../../examples/payload/payload.py#L491) · [TypeScript](../../examples/payload/payload.ts#L459) · [Kotlin](../../examples/payload/payload.kt) · [Rust](../../examples/payload/payload.rs#L486)

#### recurring_charge

**Examples:** [Python](../../examples/payload/payload.py#L534) · [TypeScript](../../examples/payload/payload.ts#L498) · [Kotlin](../../examples/payload/payload.kt) · [Rust](../../examples/payload/payload.rs#L528)

#### refund

**Examples:** [Python](../../examples/payload/payload.py#L569) · [TypeScript](../../examples/payload/payload.ts#L530) · [Kotlin](../../examples/payload/payload.kt) · [Rust](../../examples/payload/payload.rs#L563)

#### refund_get

**Examples:** [Python](../../examples/payload/payload.py#L598) · [TypeScript](../../examples/payload/payload.ts#L556) · [Kotlin](../../examples/payload/payload.kt) · [Rust](../../examples/payload/payload.rs#L586)

#### setup_recurring

**Examples:** [Python](../../examples/payload/payload.py#L619) · [TypeScript](../../examples/payload/payload.ts#L573) · [Kotlin](../../examples/payload/payload.kt) · [Rust](../../examples/payload/payload.rs#L604)

#### void

**Examples:** [Python](../../examples/payload/payload.py#L671) · [TypeScript](../../examples/payload/payload.ts) · [Kotlin](../../examples/payload/payload.kt) · [Rust](../../examples/payload/payload.rs#L654)
