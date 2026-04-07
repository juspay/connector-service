# Stax

<!--
This file is auto-generated. Do not edit by hand.
Source: data/field_probe/stax.json
Regenerate: python3 scripts/generators/docs/generate.py stax
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
#     stax=payment_pb2.StaxConfig(api_key=...),
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
    connector: 'Stax',
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
    .setConnector("Stax")
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
    connector: "Stax".to_string(),
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

**Examples:** [Python](../../examples/stax/stax.py#L23) · [JavaScript](../../examples/stax/stax.js) · [Kotlin](../../examples/stax/stax.kt#L23) · [Rust](../../examples/stax/stax.rs#L27)

### Card Payment (Authorize + Capture)

Two-step card payment. First authorize, then capture. Use when you need to verify funds before finalizing.

**Response status handling:**

| Status | Recommended action |
|--------|-------------------|
| `AUTHORIZED` | Funds reserved — proceed to Capture to settle |
| `PENDING` | Awaiting async confirmation — wait for webhook before capturing |
| `FAILED` | Payment declined — surface error to customer, do not retry without new details |

**Examples:** [Python](../../examples/stax/stax.py#L63) · [JavaScript](../../examples/stax/stax.js) · [Kotlin](../../examples/stax/stax.kt#L52) · [Rust](../../examples/stax/stax.rs#L66)

### Refund

Return funds to the customer for a completed payment.

**Examples:** [Python](../../examples/stax/stax.py#L118) · [JavaScript](../../examples/stax/stax.js) · [Kotlin](../../examples/stax/stax.kt#L92) · [Rust](../../examples/stax/stax.rs#L119)

### Void Payment

Cancel an authorized but not-yet-captured payment.

**Examples:** [Python](../../examples/stax/stax.py#L175) · [JavaScript](../../examples/stax/stax.js) · [Kotlin](../../examples/stax/stax.kt#L134) · [Rust](../../examples/stax/stax.rs#L174)

### Get Payment Status

Retrieve current payment status from the connector.

**Examples:** [Python](../../examples/stax/stax.py#L223) · [JavaScript](../../examples/stax/stax.js) · [Kotlin](../../examples/stax/stax.kt#L169) · [Rust](../../examples/stax/stax.rs#L219)

## API Reference

| Flow (Service.RPC) | Category | gRPC Request Message |
|--------------------|----------|----------------------|
| [authorize](#authorize) | Other | `—` |
| [capture](#capture) | Other | `—` |
| [create_customer](#create_customer) | Other | `—` |
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
| SEPA | ✓ |
| BACS | ✓ |
| BECS | ✓ |
| SEPA Guaranteed | ✓ |
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

##### SEPA Direct Debit

```python
"payment_method": {
    "iban": "DE89370400440532013000",
    "bank_account_holder_name": "John Doe"
}
```

##### BACS Direct Debit

```python
"payment_method": {
    "account_number": "55779911",
    "sort_code": "200000",
    "bank_account_holder_name": "John Doe"
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

##### BECS Direct Debit

```python
"payment_method": {
    "account_number": "000123456",
    "bsb_number": "000000",
    "bank_account_holder_name": "John Doe"
}
```

**Examples:** [Python](../../examples/stax/stax.py#L275) · [TypeScript](../../examples/stax/stax.ts#L260) · [Kotlin](../../examples/stax/stax.kt) · [Rust](../../examples/stax/stax.rs#L267)

#### capture

**Examples:** [Python](../../examples/stax/stax.py#L312) · [TypeScript](../../examples/stax/stax.ts#L295) · [Kotlin](../../examples/stax/stax.kt) · [Rust](../../examples/stax/stax.rs#L302)

#### create_customer

**Examples:** [Python](../../examples/stax/stax.py#L334) · [TypeScript](../../examples/stax/stax.ts#L314) · [Kotlin](../../examples/stax/stax.kt) · [Rust](../../examples/stax/stax.rs#L316)

#### get

**Examples:** [Python](../../examples/stax/stax.py#L351) · [TypeScript](../../examples/stax/stax.ts#L327) · [Kotlin](../../examples/stax/stax.kt) · [Rust](../../examples/stax/stax.rs#L328)

#### refund

**Examples:** [Python](../../examples/stax/stax.py#L370) · [TypeScript](../../examples/stax/stax.ts#L342) · [Kotlin](../../examples/stax/stax.kt) · [Rust](../../examples/stax/stax.rs#L342)

#### refund_get

**Examples:** [Python](../../examples/stax/stax.py#L394) · [TypeScript](../../examples/stax/stax.ts#L363) · [Kotlin](../../examples/stax/stax.kt) · [Rust](../../examples/stax/stax.rs#L358)

#### tokenize

**Examples:** [Python](../../examples/stax/stax.py#L410) · [TypeScript](../../examples/stax/stax.ts#L375) · [Kotlin](../../examples/stax/stax.kt) · [Rust](../../examples/stax/stax.rs#L369)

#### void

**Examples:** [Python](../../examples/stax/stax.py#L439) · [TypeScript](../../examples/stax/stax.ts) · [Kotlin](../../examples/stax/stax.kt) · [Rust](../../examples/stax/stax.rs#L397)
