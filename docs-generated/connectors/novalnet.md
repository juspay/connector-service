# Novalnet

<!--
This file is auto-generated. Do not edit by hand.
Source: data/field_probe/novalnet.json
Regenerate: python3 scripts/generators/docs/generate.py novalnet
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
#     novalnet=payment_pb2.NovalnetConfig(api_key=...),
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
    connector: 'Novalnet',
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
    .setConnector("Novalnet")
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
    connector: "Novalnet".to_string(),
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

**Examples:** [Python](../../examples/novalnet/novalnet.py#L23) · [JavaScript](../../examples/novalnet/novalnet.js) · [Kotlin](../../examples/novalnet/novalnet.kt#L23) · [Rust](../../examples/novalnet/novalnet.rs#L27)

### Card Payment (Authorize + Capture)

Two-step card payment. First authorize, then capture. Use when you need to verify funds before finalizing.

**Response status handling:**

| Status | Recommended action |
|--------|-------------------|
| `AUTHORIZED` | Funds reserved — proceed to Capture to settle |
| `PENDING` | Awaiting async confirmation — wait for webhook before capturing |
| `FAILED` | Payment declined — surface error to customer, do not retry without new details |

**Examples:** [Python](../../examples/novalnet/novalnet.py#L67) · [JavaScript](../../examples/novalnet/novalnet.js) · [Kotlin](../../examples/novalnet/novalnet.kt#L54) · [Rust](../../examples/novalnet/novalnet.rs#L70)

### Refund

Return funds to the customer for a completed payment.

**Examples:** [Python](../../examples/novalnet/novalnet.py#L126) · [JavaScript](../../examples/novalnet/novalnet.js) · [Kotlin](../../examples/novalnet/novalnet.kt#L96) · [Rust](../../examples/novalnet/novalnet.rs#L127)

### Void Payment

Cancel an authorized but not-yet-captured payment.

**Examples:** [Python](../../examples/novalnet/novalnet.py#L187) · [JavaScript](../../examples/novalnet/novalnet.js) · [Kotlin](../../examples/novalnet/novalnet.kt#L140) · [Rust](../../examples/novalnet/novalnet.rs#L186)

### Get Payment Status

Retrieve current payment status from the connector.

**Examples:** [Python](../../examples/novalnet/novalnet.py#L239) · [JavaScript](../../examples/novalnet/novalnet.js) · [Kotlin](../../examples/novalnet/novalnet.kt#L177) · [Rust](../../examples/novalnet/novalnet.rs#L235)

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
| Bancontact | ⚠ |
| Apple Pay | ✓ |
| Apple Pay Dec | ? |
| Apple Pay SDK | ⚠ |
| Google Pay | ✓ |
| Google Pay Dec | ? |
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

##### PayPal Redirect

```python
"payment_method": {
    "email": "test@example.com"
}
```

**Examples:** [Python](../../examples/novalnet/novalnet.py#L295) · [TypeScript](../../examples/novalnet/novalnet.ts#L280) · [Kotlin](../../examples/novalnet/novalnet.kt) · [Rust](../../examples/novalnet/novalnet.rs#L287)

#### capture

**Examples:** [Python](../../examples/novalnet/novalnet.py#L336) · [TypeScript](../../examples/novalnet/novalnet.ts#L319) · [Kotlin](../../examples/novalnet/novalnet.kt) · [Rust](../../examples/novalnet/novalnet.rs#L326)

#### get

**Examples:** [Python](../../examples/novalnet/novalnet.py#L358) · [TypeScript](../../examples/novalnet/novalnet.ts#L338) · [Kotlin](../../examples/novalnet/novalnet.kt) · [Rust](../../examples/novalnet/novalnet.rs#L340)

#### handle_event

**Examples:** [Python](../../examples/novalnet/novalnet.py#L377) · [TypeScript](../../examples/novalnet/novalnet.ts#L353) · [Kotlin](../../examples/novalnet/novalnet.kt) · [Rust](../../examples/novalnet/novalnet.rs#L354)

#### proxy_authorize

**Examples:** [Python](../../examples/novalnet/novalnet.py#L391) · [TypeScript](../../examples/novalnet/novalnet.ts#L363) · [Kotlin](../../examples/novalnet/novalnet.kt) · [Rust](../../examples/novalnet/novalnet.rs#L363)

#### proxy_setup_recurring

**Examples:** [Python](../../examples/novalnet/novalnet.py#L426) · [TypeScript](../../examples/novalnet/novalnet.ts#L394) · [Kotlin](../../examples/novalnet/novalnet.kt) · [Rust](../../examples/novalnet/novalnet.rs#L395)

#### recurring_charge

**Examples:** [Python](../../examples/novalnet/novalnet.py#L465) · [TypeScript](../../examples/novalnet/novalnet.ts#L429) · [Kotlin](../../examples/novalnet/novalnet.kt) · [Rust](../../examples/novalnet/novalnet.rs#L431)

#### refund

**Examples:** [Python](../../examples/novalnet/novalnet.py#L497) · [TypeScript](../../examples/novalnet/novalnet.ts#L458) · [Kotlin](../../examples/novalnet/novalnet.kt) · [Rust](../../examples/novalnet/novalnet.rs#L461)

#### refund_get

**Examples:** [Python](../../examples/novalnet/novalnet.py#L521) · [TypeScript](../../examples/novalnet/novalnet.ts#L479) · [Kotlin](../../examples/novalnet/novalnet.kt) · [Rust](../../examples/novalnet/novalnet.rs#L477)

#### setup_recurring

**Examples:** [Python](../../examples/novalnet/novalnet.py#L537) · [TypeScript](../../examples/novalnet/novalnet.ts#L491) · [Kotlin](../../examples/novalnet/novalnet.kt) · [Rust](../../examples/novalnet/novalnet.rs#L488)

#### void

**Examples:** [Python](../../examples/novalnet/novalnet.py#L584) · [TypeScript](../../examples/novalnet/novalnet.ts) · [Kotlin](../../examples/novalnet/novalnet.kt) · [Rust](../../examples/novalnet/novalnet.rs#L531)
