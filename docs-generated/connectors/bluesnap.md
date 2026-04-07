# Bluesnap

<!--
This file is auto-generated. Do not edit by hand.
Source: data/field_probe/bluesnap.json
Regenerate: python3 scripts/generators/docs/generate.py bluesnap
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
#     bluesnap=payment_pb2.BluesnapConfig(api_key=...),
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
    connector: 'Bluesnap',
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
    .setConnector("Bluesnap")
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
    connector: "Bluesnap".to_string(),
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

**Examples:** [Python](../../examples/bluesnap/bluesnap.py#L23) · [JavaScript](../../examples/bluesnap/bluesnap.js) · [Kotlin](../../examples/bluesnap/bluesnap.kt#L23) · [Rust](../../examples/bluesnap/bluesnap.rs#L27)

### Card Payment (Authorize + Capture)

Two-step card payment. First authorize, then capture. Use when you need to verify funds before finalizing.

**Response status handling:**

| Status | Recommended action |
|--------|-------------------|
| `AUTHORIZED` | Funds reserved — proceed to Capture to settle |
| `PENDING` | Awaiting async confirmation — wait for webhook before capturing |
| `FAILED` | Payment declined — surface error to customer, do not retry without new details |

**Examples:** [Python](../../examples/bluesnap/bluesnap.py#L62) · [JavaScript](../../examples/bluesnap/bluesnap.js) · [Kotlin](../../examples/bluesnap/bluesnap.kt#L51) · [Rust](../../examples/bluesnap/bluesnap.rs#L65)

### Refund

Return funds to the customer for a completed payment.

**Examples:** [Python](../../examples/bluesnap/bluesnap.py#L116) · [JavaScript](../../examples/bluesnap/bluesnap.js) · [Kotlin](../../examples/bluesnap/bluesnap.kt#L90) · [Rust](../../examples/bluesnap/bluesnap.rs#L117)

### Void Payment

Cancel an authorized but not-yet-captured payment.

**Examples:** [Python](../../examples/bluesnap/bluesnap.py#L172) · [JavaScript](../../examples/bluesnap/bluesnap.js) · [Kotlin](../../examples/bluesnap/bluesnap.kt#L131) · [Rust](../../examples/bluesnap/bluesnap.rs#L171)

### Get Payment Status

Retrieve current payment status from the connector.

**Examples:** [Python](../../examples/bluesnap/bluesnap.py#L219) · [JavaScript](../../examples/bluesnap/bluesnap.js) · [Kotlin](../../examples/bluesnap/bluesnap.kt#L165) · [Rust](../../examples/bluesnap/bluesnap.rs#L215)

## API Reference

| Flow (Service.RPC) | Category | gRPC Request Message |
|--------------------|----------|----------------------|
| [authorize](#authorize) | Other | `—` |
| [capture](#capture) | Other | `—` |
| [get](#get) | Other | `—` |
| [handle_event](#handle_event) | Other | `—` |
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

##### SEPA Direct Debit

```python
"payment_method": {
    "iban": "DE89370400440532013000",
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

**Examples:** [Python](../../examples/bluesnap/bluesnap.py#L270) · [TypeScript](../../examples/bluesnap/bluesnap.ts#L255) · [Kotlin](../../examples/bluesnap/bluesnap.kt) · [Rust](../../examples/bluesnap/bluesnap.rs#L262)

#### capture

**Examples:** [Python](../../examples/bluesnap/bluesnap.py#L306) · [TypeScript](../../examples/bluesnap/bluesnap.ts#L289) · [Kotlin](../../examples/bluesnap/bluesnap.kt) · [Rust](../../examples/bluesnap/bluesnap.rs#L296)

#### get

**Examples:** [Python](../../examples/bluesnap/bluesnap.py#L328) · [TypeScript](../../examples/bluesnap/bluesnap.ts#L308) · [Kotlin](../../examples/bluesnap/bluesnap.kt) · [Rust](../../examples/bluesnap/bluesnap.rs#L310)

#### handle_event

**Examples:** [Python](../../examples/bluesnap/bluesnap.py#L347) · [TypeScript](../../examples/bluesnap/bluesnap.ts#L323) · [Kotlin](../../examples/bluesnap/bluesnap.kt) · [Rust](../../examples/bluesnap/bluesnap.rs#L324)

#### proxy_authorize

**Examples:** [Python](../../examples/bluesnap/bluesnap.py#L361) · [TypeScript](../../examples/bluesnap/bluesnap.ts#L333) · [Kotlin](../../examples/bluesnap/bluesnap.kt) · [Rust](../../examples/bluesnap/bluesnap.rs#L333)

#### refund

**Examples:** [Python](../../examples/bluesnap/bluesnap.py#L391) · [TypeScript](../../examples/bluesnap/bluesnap.ts#L359) · [Kotlin](../../examples/bluesnap/bluesnap.kt) · [Rust](../../examples/bluesnap/bluesnap.rs#L360)

#### refund_get

**Examples:** [Python](../../examples/bluesnap/bluesnap.py#L415) · [TypeScript](../../examples/bluesnap/bluesnap.ts#L380) · [Kotlin](../../examples/bluesnap/bluesnap.kt) · [Rust](../../examples/bluesnap/bluesnap.rs#L376)

#### void

**Examples:** [Python](../../examples/bluesnap/bluesnap.py#L431) · [TypeScript](../../examples/bluesnap/bluesnap.ts) · [Kotlin](../../examples/bluesnap/bluesnap.kt) · [Rust](../../examples/bluesnap/bluesnap.rs#L387)
