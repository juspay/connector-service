# CyberSource

<!--
This file is auto-generated. Do not edit by hand.
Source: data/field_probe/cybersource.json
Regenerate: python3 scripts/generators/docs/generate.py cybersource
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
#     cybersource=payment_pb2.CybersourceConfig(api_key=...),
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
    connector: 'Cybersource',
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
    .setConnector("Cybersource")
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
    connector: "Cybersource".to_string(),
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

**Examples:** [Python](../../examples/cybersource/cybersource.py#L23) · [JavaScript](../../examples/cybersource/cybersource.js) · [Kotlin](../../examples/cybersource/cybersource.kt#L23) · [Rust](../../examples/cybersource/cybersource.rs#L27)

### Card Payment (Authorize + Capture)

Two-step card payment. First authorize, then capture. Use when you need to verify funds before finalizing.

**Response status handling:**

| Status | Recommended action |
|--------|-------------------|
| `AUTHORIZED` | Funds reserved — proceed to Capture to settle |
| `PENDING` | Awaiting async confirmation — wait for webhook before capturing |
| `FAILED` | Payment declined — surface error to customer, do not retry without new details |

**Examples:** [Python](../../examples/cybersource/cybersource.py#L65) · [JavaScript](../../examples/cybersource/cybersource.js) · [Kotlin](../../examples/cybersource/cybersource.kt#L52) · [Rust](../../examples/cybersource/cybersource.rs#L68)

### Refund

Return funds to the customer for a completed payment.

**Examples:** [Python](../../examples/cybersource/cybersource.py#L122) · [JavaScript](../../examples/cybersource/cybersource.js) · [Kotlin](../../examples/cybersource/cybersource.kt#L92) · [Rust](../../examples/cybersource/cybersource.rs#L123)

### Void Payment

Cancel an authorized but not-yet-captured payment.

**Examples:** [Python](../../examples/cybersource/cybersource.py#L181) · [JavaScript](../../examples/cybersource/cybersource.js) · [Kotlin](../../examples/cybersource/cybersource.kt#L134) · [Rust](../../examples/cybersource/cybersource.rs#L180)

### Get Payment Status

Retrieve current payment status from the connector.

**Examples:** [Python](../../examples/cybersource/cybersource.py#L236) · [JavaScript](../../examples/cybersource/cybersource.js) · [Kotlin](../../examples/cybersource/cybersource.kt#L172) · [Rust](../../examples/cybersource/cybersource.rs#L232)

## API Reference

| Flow (Service.RPC) | Category | gRPC Request Message |
|--------------------|----------|----------------------|
| [authenticate](#authenticate) | Other | `—` |
| [authorize](#authorize) | Other | `—` |
| [capture](#capture) | Other | `—` |
| [get](#get) | Other | `—` |
| [post_authenticate](#post_authenticate) | Other | `—` |
| [pre_authenticate](#pre_authenticate) | Other | `—` |
| [proxy_authorize](#proxy_authorize) | Other | `—` |
| [recurring_charge](#recurring_charge) | Other | `—` |
| [recurring_revoke](#recurring_revoke) | Other | `—` |
| [refund](#refund) | Other | `—` |
| [refund_get](#refund_get) | Other | `—` |
| [void](#void) | Other | `—` |

### Other

#### authenticate

**Examples:** [Python](../../examples/cybersource/cybersource.py#L290) · [TypeScript](../../examples/cybersource/cybersource.ts#L275) · [Kotlin](../../examples/cybersource/cybersource.kt) · [Rust](../../examples/cybersource/cybersource.rs#L282)

#### authorize

**Supported payment method types:**

| Payment Method | Supported |
|----------------|:---------:|
| Card | ✓ |
| Bancontact | ⚠ |
| Apple Pay | ✓ |
| Apple Pay Dec | ✓ |
| Apple Pay SDK | ⚠ |
| Google Pay | ✓ |
| Google Pay Dec | ✓ |
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
| Samsung Pay | ✓ |
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

##### Apple Pay

```python
"payment_method": {
    "encrypted_data": "eyJ2ZXJzaW9uIjoiRUNfdjEiLCJkYXRhIjoicHJvYmUiLCJzaWduYXR1cmUiOiJwcm9iZSJ9"
    "display_name": "Visa 1111",
    "network": "Visa",
    "type": "debit"
    "transaction_identifier": "probe_txn_id"
}
```

##### Samsung Pay

```python
"payment_method": {
    "method": "3DS",
    "recurring_payment": False,
    "card_brand": "VISA",
    "card_last_four_digits": "1234",
    "type": "S",
    "version": "100",
    "data": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InNhbXN1bmdfcHJvYmVfa2V5XzEyMyJ9.eyJwYXltZW50TWV0aG9kVG9rZW4iOiJwcm9iZV9zYW1zdW5nX3Rva2VuIn0.ZHVtbXlfc2lnbmF0dXJl"
}
```

**Examples:** [Python](../../examples/cybersource/cybersource.py#L325) · [TypeScript](../../examples/cybersource/cybersource.ts#L306) · [Kotlin](../../examples/cybersource/cybersource.kt) · [Rust](../../examples/cybersource/cybersource.rs#L318)

#### capture

**Examples:** [Python](../../examples/cybersource/cybersource.py#L364) · [TypeScript](../../examples/cybersource/cybersource.ts#L343) · [Kotlin](../../examples/cybersource/cybersource.kt) · [Rust](../../examples/cybersource/cybersource.rs#L355)

#### get

**Examples:** [Python](../../examples/cybersource/cybersource.py#L386) · [TypeScript](../../examples/cybersource/cybersource.ts#L362) · [Kotlin](../../examples/cybersource/cybersource.kt) · [Rust](../../examples/cybersource/cybersource.rs#L369)

#### post_authenticate

**Examples:** [Python](../../examples/cybersource/cybersource.py#L405) · [TypeScript](../../examples/cybersource/cybersource.ts#L377) · [Kotlin](../../examples/cybersource/cybersource.kt) · [Rust](../../examples/cybersource/cybersource.rs#L383)

#### pre_authenticate

**Examples:** [Python](../../examples/cybersource/cybersource.py#L435) · [TypeScript](../../examples/cybersource/cybersource.ts#L403) · [Kotlin](../../examples/cybersource/cybersource.kt) · [Rust](../../examples/cybersource/cybersource.rs#L414)

#### proxy_authorize

**Examples:** [Python](../../examples/cybersource/cybersource.py#L463) · [TypeScript](../../examples/cybersource/cybersource.ts#L427) · [Kotlin](../../examples/cybersource/cybersource.kt) · [Rust](../../examples/cybersource/cybersource.rs#L441)

#### recurring_charge

**Examples:** [Python](../../examples/cybersource/cybersource.py#L496) · [TypeScript](../../examples/cybersource/cybersource.ts#L456) · [Kotlin](../../examples/cybersource/cybersource.kt) · [Rust](../../examples/cybersource/cybersource.rs#L471)

#### recurring_revoke

**Examples:** [Python](../../examples/cybersource/cybersource.py#L526) · [TypeScript](../../examples/cybersource/cybersource.ts#L483) · [Kotlin](../../examples/cybersource/cybersource.kt) · [Rust](../../examples/cybersource/cybersource.rs#L499)

#### refund

**Examples:** [Python](../../examples/cybersource/cybersource.py#L542) · [TypeScript](../../examples/cybersource/cybersource.ts#L495) · [Kotlin](../../examples/cybersource/cybersource.kt) · [Rust](../../examples/cybersource/cybersource.rs#L510)

#### refund_get

**Examples:** [Python](../../examples/cybersource/cybersource.py#L566) · [TypeScript](../../examples/cybersource/cybersource.ts#L516) · [Kotlin](../../examples/cybersource/cybersource.kt) · [Rust](../../examples/cybersource/cybersource.rs#L526)

#### void

**Examples:** [Python](../../examples/cybersource/cybersource.py#L582) · [TypeScript](../../examples/cybersource/cybersource.ts) · [Kotlin](../../examples/cybersource/cybersource.kt) · [Rust](../../examples/cybersource/cybersource.rs#L537)
