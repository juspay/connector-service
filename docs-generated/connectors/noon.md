# Noon

<!--
This file is auto-generated. Do not edit by hand.
Source: data/field_probe/noon.json
Regenerate: python3 scripts/generators/docs/generate.py noon
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
#     noon=payment_pb2.NoonConfig(api_key=...),
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
    connector: 'Noon',
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
    .setConnector("Noon")
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
    connector: "Noon".to_string(),
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

**Examples:** [Python](../../examples/noon/noon.py#L23) · [JavaScript](../../examples/noon/noon.js) · [Kotlin](../../examples/noon/noon.kt#L23) · [Rust](../../examples/noon/noon.rs#L27)

### Card Payment (Authorize + Capture)

Two-step card payment. First authorize, then capture. Use when you need to verify funds before finalizing.

**Response status handling:**

| Status | Recommended action |
|--------|-------------------|
| `AUTHORIZED` | Funds reserved — proceed to Capture to settle |
| `PENDING` | Awaiting async confirmation — wait for webhook before capturing |
| `FAILED` | Payment declined — surface error to customer, do not retry without new details |

**Examples:** [Python](../../examples/noon/noon.py#L64) · [JavaScript](../../examples/noon/noon.js) · [Kotlin](../../examples/noon/noon.kt#L53) · [Rust](../../examples/noon/noon.rs#L67)

### Refund

Return funds to the customer for a completed payment.

**Examples:** [Python](../../examples/noon/noon.py#L120) · [JavaScript](../../examples/noon/noon.js) · [Kotlin](../../examples/noon/noon.kt#L94) · [Rust](../../examples/noon/noon.rs#L121)

### Void Payment

Cancel an authorized but not-yet-captured payment.

**Examples:** [Python](../../examples/noon/noon.py#L178) · [JavaScript](../../examples/noon/noon.js) · [Kotlin](../../examples/noon/noon.kt#L137) · [Rust](../../examples/noon/noon.rs#L177)

### Get Payment Status

Retrieve current payment status from the connector.

**Examples:** [Python](../../examples/noon/noon.py#L227) · [JavaScript](../../examples/noon/noon.js) · [Kotlin](../../examples/noon/noon.kt#L173) · [Rust](../../examples/noon/noon.rs#L223)

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
| [recurring_revoke](#recurring_revoke) | Other | `—` |
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
| Apple Pay | ? |
| Apple Pay Dec | ? |
| Apple Pay SDK | ⚠ |
| Google Pay | ✓ |
| Google Pay Dec | ✓ |
| Google Pay SDK | ⚠ |
| PayPal SDK | ⚠ |
| Amazon Pay | ⚠ |
| Cash App | ⚠ |
| PayPal | ✓ |
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

##### Google Pay

```python
"payment_method": {
    "type": "CARD",
    "description": "Visa 1111",
    "card_network": "VISA",
    "card_details": "1111"
    "token_type": "PAYMENT_GATEWAY",
    "token": "{\"id\":\"tok_probe_gpay\",\"object\":\"token\",\"type\":\"card\"}"
}
```

##### PayPal Redirect

```python
"payment_method": {
    "email": "test@example.com"
}
```

**Examples:** [Python](../../examples/noon/noon.py#L280) · [TypeScript](../../examples/noon/noon.ts#L265) · [Kotlin](../../examples/noon/noon.kt) · [Rust](../../examples/noon/noon.rs#L272)

#### capture

**Examples:** [Python](../../examples/noon/noon.py#L318) · [TypeScript](../../examples/noon/noon.ts#L301) · [Kotlin](../../examples/noon/noon.kt) · [Rust](../../examples/noon/noon.rs#L308)

#### get

**Examples:** [Python](../../examples/noon/noon.py#L340) · [TypeScript](../../examples/noon/noon.ts#L320) · [Kotlin](../../examples/noon/noon.kt) · [Rust](../../examples/noon/noon.rs#L322)

#### handle_event

**Examples:** [Python](../../examples/noon/noon.py#L359) · [TypeScript](../../examples/noon/noon.ts#L335) · [Kotlin](../../examples/noon/noon.kt) · [Rust](../../examples/noon/noon.rs#L336)

#### proxy_authorize

**Examples:** [Python](../../examples/noon/noon.py#L373) · [TypeScript](../../examples/noon/noon.ts#L345) · [Kotlin](../../examples/noon/noon.kt) · [Rust](../../examples/noon/noon.rs#L345)

#### proxy_setup_recurring

**Examples:** [Python](../../examples/noon/noon.py#L405) · [TypeScript](../../examples/noon/noon.ts#L373) · [Kotlin](../../examples/noon/noon.kt) · [Rust](../../examples/noon/noon.rs#L374)

#### recurring_charge

**Examples:** [Python](../../examples/noon/noon.py#L439) · [TypeScript](../../examples/noon/noon.ts#L403) · [Kotlin](../../examples/noon/noon.kt) · [Rust](../../examples/noon/noon.rs#L405)

#### recurring_revoke

**Examples:** [Python](../../examples/noon/noon.py#L470) · [TypeScript](../../examples/noon/noon.ts#L431) · [Kotlin](../../examples/noon/noon.kt) · [Rust](../../examples/noon/noon.rs#L434)

#### refund

**Examples:** [Python](../../examples/noon/noon.py#L486) · [TypeScript](../../examples/noon/noon.ts#L443) · [Kotlin](../../examples/noon/noon.kt) · [Rust](../../examples/noon/noon.rs#L445)

#### refund_get

**Examples:** [Python](../../examples/noon/noon.py#L510) · [TypeScript](../../examples/noon/noon.ts#L464) · [Kotlin](../../examples/noon/noon.kt) · [Rust](../../examples/noon/noon.rs#L461)

#### void

**Examples:** [Python](../../examples/noon/noon.py#L526) · [TypeScript](../../examples/noon/noon.ts) · [Kotlin](../../examples/noon/noon.kt) · [Rust](../../examples/noon/noon.rs#L472)
