# Adyen

<!--
This file is auto-generated. Do not edit by hand.
Source: data/field_probe/adyen.json
Regenerate: python3 scripts/generators/docs/generate.py adyen
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
#     adyen=payment_pb2.AdyenConfig(api_key=...),
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
    connector: 'Adyen',
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
    .setConnector("Adyen")
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
    connector: "Adyen".to_string(),
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

**Examples:** [Python](../../examples/adyen/adyen.py#L23) · [JavaScript](../../examples/adyen/adyen.js) · [Kotlin](../../examples/adyen/adyen.kt#L23) · [Rust](../../examples/adyen/adyen.rs#L27)

### Card Payment (Authorize + Capture)

Two-step card payment. First authorize, then capture. Use when you need to verify funds before finalizing.

**Response status handling:**

| Status | Recommended action |
|--------|-------------------|
| `AUTHORIZED` | Funds reserved — proceed to Capture to settle |
| `PENDING` | Awaiting async confirmation — wait for webhook before capturing |
| `FAILED` | Payment declined — surface error to customer, do not retry without new details |

**Examples:** [Python](../../examples/adyen/adyen.py#L75) · [JavaScript](../../examples/adyen/adyen.js) · [Kotlin](../../examples/adyen/adyen.kt#L62) · [Rust](../../examples/adyen/adyen.rs#L78)

### Refund

Return funds to the customer for a completed payment.

**Examples:** [Python](../../examples/adyen/adyen.py#L142) · [JavaScript](../../examples/adyen/adyen.js) · [Kotlin](../../examples/adyen/adyen.kt#L112) · [Rust](../../examples/adyen/adyen.rs#L143)

### Void Payment

Cancel an authorized but not-yet-captured payment.

**Examples:** [Python](../../examples/adyen/adyen.py#L211) · [JavaScript](../../examples/adyen/adyen.js) · [Kotlin](../../examples/adyen/adyen.kt#L164) · [Rust](../../examples/adyen/adyen.rs#L210)

## API Reference

| Flow (Service.RPC) | Category | gRPC Request Message |
|--------------------|----------|----------------------|
| [authorize](#authorize) | Other | `—` |
| [capture](#capture) | Other | `—` |
| [dispute_accept](#dispute_accept) | Other | `—` |
| [dispute_defend](#dispute_defend) | Other | `—` |
| [dispute_submit_evidence](#dispute_submit_evidence) | Other | `—` |
| [handle_event](#handle_event) | Other | `—` |
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
| Bancontact | ✓ |
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
| Affirm | ✓ |
| Afterpay | ✓ |
| Klarna | ✓ |
| UPI Collect | ⚠ |
| UPI Intent | ⚠ |
| UPI QR | ⚠ |
| Thailand | ✓ |
| Czech | ✓ |
| Finland | ✓ |
| FPX | ✓ |
| Poland | ⚠ |
| Slovakia | ✓ |
| UK | ✓ |
| PIS | x |
| Generic | ⚠ |
| Local | ⚠ |
| iDEAL | ✓ |
| Sofort | ⚠ |
| Trustly | ✓ |
| Giropay | ⚠ |
| EPS | ✓ |
| Przelewy24 | ⚠ |
| PSE | ⚠ |
| BLIK | ✓ |
| Interac | ⚠ |
| Bizum | ✓ |
| EFT | ⚠ |
| DuitNow | x |
| ACH | ⚠ |
| SEPA | ⚠ |
| BACS | ⚠ |
| Multibanco | ⚠ |
| Instant | ⚠ |
| Instant FI | ⚠ |
| Instant PL | ⚠ |
| Pix | ✓ |
| Permata | ✓ |
| BCA | ✓ |
| BNI VA | ✓ |
| BRI VA | ✓ |
| CIMB VA | ✓ |
| Danamon VA | ✓ |
| Mandiri VA | ✓ |
| Local | ⚠ |
| Indonesian | ⚠ |
| ACH | ✓ |
| SEPA | ✓ |
| BACS | ✓ |
| BECS | ⚠ |
| SEPA Guaranteed | ⚠ |
| Crypto | x |
| Reward | ⚠ |
| Givex | x |
| PaySafeCard | x |
| E-Voucher | ⚠ |
| Boleto | ✓ |
| Efecty | ⚠ |
| Pago Efectivo | ⚠ |
| Red Compra | ⚠ |
| Red Pagos | ⚠ |
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

##### iDEAL

```python
"payment_method": {
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

##### Affirm

```python
"payment_method": {
}
```

**Examples:** [Python](../../examples/adyen/adyen.py#L271) · [TypeScript](../../examples/adyen/adyen.ts#L260) · [Kotlin](../../examples/adyen/adyen.kt) · [Rust](../../examples/adyen/adyen.rs#L266)

#### capture

**Examples:** [Python](../../examples/adyen/adyen.py#L320) · [TypeScript](../../examples/adyen/adyen.ts#L307) · [Kotlin](../../examples/adyen/adyen.kt) · [Rust](../../examples/adyen/adyen.rs#L313)

#### dispute_accept

**Examples:** [Python](../../examples/adyen/adyen.py#L342) · [TypeScript](../../examples/adyen/adyen.ts#L326) · [Kotlin](../../examples/adyen/adyen.kt) · [Rust](../../examples/adyen/adyen.rs#L327)

#### dispute_defend

**Examples:** [Python](../../examples/adyen/adyen.py#L358) · [TypeScript](../../examples/adyen/adyen.ts#L338) · [Kotlin](../../examples/adyen/adyen.kt) · [Rust](../../examples/adyen/adyen.rs#L338)

#### dispute_submit_evidence

**Examples:** [Python](../../examples/adyen/adyen.py#L375) · [TypeScript](../../examples/adyen/adyen.ts#L351) · [Kotlin](../../examples/adyen/adyen.kt) · [Rust](../../examples/adyen/adyen.rs#L350)

#### handle_event

**Examples:** [Python](../../examples/adyen/adyen.py#L392) · [TypeScript](../../examples/adyen/adyen.ts#L364) · [Kotlin](../../examples/adyen/adyen.kt) · [Rust](../../examples/adyen/adyen.rs#L362)

#### proxy_authorize

**Examples:** [Python](../../examples/adyen/adyen.py#L406) · [TypeScript](../../examples/adyen/adyen.ts#L374) · [Kotlin](../../examples/adyen/adyen.kt) · [Rust](../../examples/adyen/adyen.rs#L371)

#### proxy_setup_recurring

**Examples:** [Python](../../examples/adyen/adyen.py#L449) · [TypeScript](../../examples/adyen/adyen.ts#L413) · [Kotlin](../../examples/adyen/adyen.kt) · [Rust](../../examples/adyen/adyen.rs#L411)

#### recurring_charge

**Examples:** [Python](../../examples/adyen/adyen.py#L499) · [TypeScript](../../examples/adyen/adyen.ts#L459) · [Kotlin](../../examples/adyen/adyen.kt) · [Rust](../../examples/adyen/adyen.rs#L458)

#### refund

**Examples:** [Python](../../examples/adyen/adyen.py#L529) · [TypeScript](../../examples/adyen/adyen.ts#L486) · [Kotlin](../../examples/adyen/adyen.kt) · [Rust](../../examples/adyen/adyen.rs#L486)

#### setup_recurring

**Examples:** [Python](../../examples/adyen/adyen.py#L553) · [TypeScript](../../examples/adyen/adyen.ts#L507) · [Kotlin](../../examples/adyen/adyen.kt) · [Rust](../../examples/adyen/adyen.rs#L502)

#### void

**Examples:** [Python](../../examples/adyen/adyen.py#L611) · [TypeScript](../../examples/adyen/adyen.ts) · [Kotlin](../../examples/adyen/adyen.kt) · [Rust](../../examples/adyen/adyen.rs#L556)
