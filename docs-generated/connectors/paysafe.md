# Paysafe

<!--
This file is auto-generated. Do not edit by hand.
Source: data/field_probe/paysafe.json
Regenerate: python3 scripts/generators/docs/generate.py paysafe
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
#     paysafe=payment_pb2.PaysafeConfig(api_key=...),
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
    connector: 'Paysafe',
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
    .setConnector("Paysafe")
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
    connector: "Paysafe".to_string(),
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

**Examples:** [Python](../../examples/paysafe/paysafe.py#L23) · [JavaScript](../../examples/paysafe/paysafe.js) · [Kotlin](../../examples/paysafe/paysafe.kt#L23) · [Rust](../../examples/paysafe/paysafe.rs#L27)

### Card Payment (Authorize + Capture)

Two-step card payment. First authorize, then capture. Use when you need to verify funds before finalizing.

**Response status handling:**

| Status | Recommended action |
|--------|-------------------|
| `AUTHORIZED` | Funds reserved — proceed to Capture to settle |
| `PENDING` | Awaiting async confirmation — wait for webhook before capturing |
| `FAILED` | Payment declined — surface error to customer, do not retry without new details |

**Examples:** [Python](../../examples/paysafe/paysafe.py#L63) · [JavaScript](../../examples/paysafe/paysafe.js) · [Kotlin](../../examples/paysafe/paysafe.kt#L52) · [Rust](../../examples/paysafe/paysafe.rs#L66)

### Refund

Return funds to the customer for a completed payment.

**Examples:** [Python](../../examples/paysafe/paysafe.py#L118) · [JavaScript](../../examples/paysafe/paysafe.js) · [Kotlin](../../examples/paysafe/paysafe.kt#L92) · [Rust](../../examples/paysafe/paysafe.rs#L119)

### Void Payment

Cancel an authorized but not-yet-captured payment.

**Examples:** [Python](../../examples/paysafe/paysafe.py#L175) · [JavaScript](../../examples/paysafe/paysafe.js) · [Kotlin](../../examples/paysafe/paysafe.kt#L134) · [Rust](../../examples/paysafe/paysafe.rs#L174)

### Get Payment Status

Retrieve current payment status from the connector.

**Examples:** [Python](../../examples/paysafe/paysafe.py#L227) · [JavaScript](../../examples/paysafe/paysafe.js) · [Kotlin](../../examples/paysafe/paysafe.kt#L171) · [Rust](../../examples/paysafe/paysafe.rs#L223)

## API Reference

| Flow (Service.RPC) | Category | gRPC Request Message |
|--------------------|----------|----------------------|
| [authorize](#authorize) | Other | `—` |
| [capture](#capture) | Other | `—` |
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
| Bancontact | ✓ |
| Apple Pay | ✓ |
| Apple Pay Dec | ✓ |
| Apple Pay SDK | ✓ |
| Google Pay | ✓ |
| Google Pay Dec | ✓ |
| Google Pay SDK | ✓ |
| PayPal SDK | ✓ |
| Amazon Pay | ✓ |
| Cash App | ✓ |
| PayPal | ✓ |
| WeChat Pay | ✓ |
| Alipay | ✓ |
| Revolut Pay | ✓ |
| MiFinity | ✓ |
| Bluecode | ✓ |
| Paze | x |
| Samsung Pay | ✓ |
| MB Way | ✓ |
| Satispay | ✓ |
| Wero | ✓ |
| Affirm | ✓ |
| Afterpay | ✓ |
| Klarna | ✓ |
| UPI Collect | ✓ |
| UPI Intent | ✓ |
| UPI QR | ✓ |
| Thailand | ✓ |
| Czech | ✓ |
| Finland | ✓ |
| FPX | ✓ |
| Poland | ✓ |
| Slovakia | ✓ |
| UK | ✓ |
| PIS | x |
| Generic | ✓ |
| Local | ✓ |
| iDEAL | ✓ |
| Sofort | ✓ |
| Trustly | ✓ |
| Giropay | ✓ |
| EPS | ✓ |
| Przelewy24 | ✓ |
| PSE | ✓ |
| BLIK | ✓ |
| Interac | ✓ |
| Bizum | ✓ |
| EFT | ✓ |
| DuitNow | x |
| ACH | ✓ |
| SEPA | ✓ |
| BACS | ✓ |
| Multibanco | ✓ |
| Instant | ✓ |
| Instant FI | ✓ |
| Instant PL | ✓ |
| Pix | ✓ |
| Permata | ✓ |
| BCA | ✓ |
| BNI VA | ✓ |
| BRI VA | ✓ |
| CIMB VA | ✓ |
| Danamon VA | ✓ |
| Mandiri VA | ✓ |
| Local | ✓ |
| Indonesian | ✓ |
| ACH | ✓ |
| SEPA | ✓ |
| BACS | ✓ |
| BECS | ✓ |
| SEPA Guaranteed | ✓ |
| Crypto | x |
| Reward | ✓ |
| Givex | x |
| PaySafeCard | x |
| E-Voucher | ✓ |
| Boleto | ✓ |
| Efecty | ✓ |
| Pago Efectivo | ✓ |
| Red Compra | ✓ |
| Red Pagos | ✓ |
| Alfamart | ✓ |
| Indomaret | ✓ |
| Oxxo | ✓ |
| 7-Eleven | ✓ |
| Lawson | ✓ |
| Mini Stop | ✓ |
| Family Mart | ✓ |
| Seicomart | ✓ |
| Pay Easy | ✓ |

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

##### iDEAL

```python
"payment_method": {
}
```

##### PayPal Redirect

```python
"payment_method": {
    "email": "test@example.com"
}
```

##### BLIK

```python
"payment_method": {
    "blik_code": "777124"
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

##### UPI Collect

```python
"payment_method": {
    "vpa_id": "test@upi"
}
```

##### Affirm

```python
"payment_method": {
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

**Examples:** [Python](../../examples/paysafe/paysafe.py#L279) · [TypeScript](../../examples/paysafe/paysafe.ts#L264) · [Kotlin](../../examples/paysafe/paysafe.kt) · [Rust](../../examples/paysafe/paysafe.rs#L271)

#### capture

**Examples:** [Python](../../examples/paysafe/paysafe.py#L316) · [TypeScript](../../examples/paysafe/paysafe.ts#L299) · [Kotlin](../../examples/paysafe/paysafe.kt) · [Rust](../../examples/paysafe/paysafe.rs#L306)

#### get

**Examples:** [Python](../../examples/paysafe/paysafe.py#L338) · [TypeScript](../../examples/paysafe/paysafe.ts#L318) · [Kotlin](../../examples/paysafe/paysafe.kt) · [Rust](../../examples/paysafe/paysafe.rs#L320)

#### refund

**Examples:** [Python](../../examples/paysafe/paysafe.py#L357) · [TypeScript](../../examples/paysafe/paysafe.ts#L333) · [Kotlin](../../examples/paysafe/paysafe.kt) · [Rust](../../examples/paysafe/paysafe.rs#L334)

#### refund_get

**Examples:** [Python](../../examples/paysafe/paysafe.py#L381) · [TypeScript](../../examples/paysafe/paysafe.ts#L354) · [Kotlin](../../examples/paysafe/paysafe.kt) · [Rust](../../examples/paysafe/paysafe.rs#L350)

#### tokenize

**Examples:** [Python](../../examples/paysafe/paysafe.py#L397) · [TypeScript](../../examples/paysafe/paysafe.ts#L366) · [Kotlin](../../examples/paysafe/paysafe.kt) · [Rust](../../examples/paysafe/paysafe.rs#L361)

#### void

**Examples:** [Python](../../examples/paysafe/paysafe.py#L424) · [TypeScript](../../examples/paysafe/paysafe.ts) · [Kotlin](../../examples/paysafe/paysafe.kt) · [Rust](../../examples/paysafe/paysafe.rs#L387)
