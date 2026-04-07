# Revolut

<!--
This file is auto-generated. Do not edit by hand.
Source: data/field_probe/revolut.json
Regenerate: python3 scripts/generators/docs/generate.py revolut
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
#     revolut=payment_pb2.RevolutConfig(api_key=...),
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
    connector: 'Revolut',
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
    .setConnector("Revolut")
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
    connector: "Revolut".to_string(),
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

**Examples:** [Python](../../examples/revolut/revolut.py#L23) · [JavaScript](../../examples/revolut/revolut.js) · [Kotlin](../../examples/revolut/revolut.kt#L23) · [Rust](../../examples/revolut/revolut.rs#L27)

### Card Payment (Authorize + Capture)

Two-step card payment. First authorize, then capture. Use when you need to verify funds before finalizing.

**Response status handling:**

| Status | Recommended action |
|--------|-------------------|
| `AUTHORIZED` | Funds reserved — proceed to Capture to settle |
| `PENDING` | Awaiting async confirmation — wait for webhook before capturing |
| `FAILED` | Payment declined — surface error to customer, do not retry without new details |

**Examples:** [Python](../../examples/revolut/revolut.py#L62) · [JavaScript](../../examples/revolut/revolut.js) · [Kotlin](../../examples/revolut/revolut.kt#L51) · [Rust](../../examples/revolut/revolut.rs#L65)

### Refund

Return funds to the customer for a completed payment.

**Examples:** [Python](../../examples/revolut/revolut.py#L116) · [JavaScript](../../examples/revolut/revolut.js) · [Kotlin](../../examples/revolut/revolut.kt#L90) · [Rust](../../examples/revolut/revolut.rs#L117)

### Get Payment Status

Retrieve current payment status from the connector.

**Examples:** [Python](../../examples/revolut/revolut.py#L172) · [JavaScript](../../examples/revolut/revolut.js) · [Kotlin](../../examples/revolut/revolut.kt#L131) · [Rust](../../examples/revolut/revolut.rs#L171)

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
| [token_authorize](#token_authorize) | Other | `—` |
| [verify_redirect](#verify_redirect) | Other | `—` |

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

**Examples:** [Python](../../examples/revolut/revolut.py#L223) · [TypeScript](../../examples/revolut/revolut.ts#L212) · [Kotlin](../../examples/revolut/revolut.kt) · [Rust](../../examples/revolut/revolut.rs#L218)

#### capture

**Examples:** [Python](../../examples/revolut/revolut.py#L259) · [TypeScript](../../examples/revolut/revolut.ts#L246) · [Kotlin](../../examples/revolut/revolut.kt) · [Rust](../../examples/revolut/revolut.rs#L252)

#### get

**Examples:** [Python](../../examples/revolut/revolut.py#L281) · [TypeScript](../../examples/revolut/revolut.ts#L265) · [Kotlin](../../examples/revolut/revolut.kt) · [Rust](../../examples/revolut/revolut.rs#L266)

#### handle_event

**Examples:** [Python](../../examples/revolut/revolut.py#L300) · [TypeScript](../../examples/revolut/revolut.ts#L280) · [Kotlin](../../examples/revolut/revolut.kt) · [Rust](../../examples/revolut/revolut.rs#L280)

#### proxy_authorize

**Examples:** [Python](../../examples/revolut/revolut.py#L314) · [TypeScript](../../examples/revolut/revolut.ts#L290) · [Kotlin](../../examples/revolut/revolut.kt) · [Rust](../../examples/revolut/revolut.rs#L289)

#### refund

**Examples:** [Python](../../examples/revolut/revolut.py#L344) · [TypeScript](../../examples/revolut/revolut.ts#L316) · [Kotlin](../../examples/revolut/revolut.kt) · [Rust](../../examples/revolut/revolut.rs#L316)

#### refund_get

**Examples:** [Python](../../examples/revolut/revolut.py#L368) · [TypeScript](../../examples/revolut/revolut.ts#L337) · [Kotlin](../../examples/revolut/revolut.kt) · [Rust](../../examples/revolut/revolut.rs#L332)

#### token_authorize

**Examples:** [Python](../../examples/revolut/revolut.py#L384) · [TypeScript](../../examples/revolut/revolut.ts#L349) · [Kotlin](../../examples/revolut/revolut.kt) · [Rust](../../examples/revolut/revolut.rs#L343)

#### verify_redirect

**Examples:** [Python](../../examples/revolut/revolut.py#L407) · [TypeScript](../../examples/revolut/revolut.ts#L368) · [Kotlin](../../examples/revolut/revolut.kt) · [Rust](../../examples/revolut/revolut.rs#L363)
