# TrustPay

<!--
This file is auto-generated. Do not edit by hand.
Source: data/field_probe/trustpay.json
Regenerate: python3 scripts/generators/docs/generate.py trustpay
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
#     trustpay=payment_pb2.TrustpayConfig(api_key=...),
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
    connector: 'Trustpay',
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
    .setConnector("Trustpay")
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
    connector: "Trustpay".to_string(),
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

**Examples:** [Python](../../examples/trustpay/trustpay.py#L23) · [JavaScript](../../examples/trustpay/trustpay.js) · [Kotlin](../../examples/trustpay/trustpay.kt#L23) · [Rust](../../examples/trustpay/trustpay.rs#L27)

### Refund

Return funds to the customer for a completed payment.

**Examples:** [Python](../../examples/trustpay/trustpay.py#L79) · [JavaScript](../../examples/trustpay/trustpay.js) · [Kotlin](../../examples/trustpay/trustpay.kt#L62) · [Rust](../../examples/trustpay/trustpay.rs#L84)

### Get Payment Status

Retrieve current payment status from the connector.

**Examples:** [Python](../../examples/trustpay/trustpay.py#L157) · [JavaScript](../../examples/trustpay/trustpay.js) · [Kotlin](../../examples/trustpay/trustpay.kt#L117) · [Rust](../../examples/trustpay/trustpay.rs#L164)

## API Reference

| Flow (Service.RPC) | Category | gRPC Request Message |
|--------------------|----------|----------------------|
| [authorize](#authorize) | Other | `—` |
| [create_order](#create_order) | Other | `—` |
| [create_server_authentication_token](#create_server_authentication_token) | Other | `—` |
| [get](#get) | Other | `—` |
| [handle_event](#handle_event) | Other | `—` |
| [proxy_authorize](#proxy_authorize) | Other | `—` |
| [refund](#refund) | Other | `—` |
| [refund_get](#refund_get) | Other | `—` |

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
| iDEAL | ✓ |
| Sofort | ✓ |
| Trustly | ⚠ |
| Giropay | ✓ |
| EPS | ✓ |
| Przelewy24 | ⚠ |
| PSE | ⚠ |
| BLIK | ✓ |
| Interac | ⚠ |
| Bizum | ⚠ |
| EFT | ⚠ |
| DuitNow | x |
| ACH | ⚠ |
| SEPA | ✓ |
| BACS | ⚠ |
| Multibanco | ⚠ |
| Instant | ✓ |
| Instant FI | ✓ |
| Instant PL | ✓ |
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

**Examples:** [Python](../../examples/trustpay/trustpay.py#L230) · [TypeScript](../../examples/trustpay/trustpay.ts#L222) · [Kotlin](../../examples/trustpay/trustpay.kt) · [Rust](../../examples/trustpay/trustpay.rs#L237)

#### create_order

**Examples:** [Python](../../examples/trustpay/trustpay.py#L283) · [TypeScript](../../examples/trustpay/trustpay.ts#L273) · [Kotlin](../../examples/trustpay/trustpay.kt) · [Rust](../../examples/trustpay/trustpay.rs#L290)

#### create_server_authentication_token

**Examples:** [Python](../../examples/trustpay/trustpay.py#L306) · [TypeScript](../../examples/trustpay/trustpay.ts#L292) · [Kotlin](../../examples/trustpay/trustpay.kt) · [Rust](../../examples/trustpay/trustpay.rs#L310)

#### get

**Examples:** [Python](../../examples/trustpay/trustpay.py#L320) · [TypeScript](../../examples/trustpay/trustpay.ts#L302) · [Kotlin](../../examples/trustpay/trustpay.kt) · [Rust](../../examples/trustpay/trustpay.rs#L319)

#### handle_event

**Examples:** [Python](../../examples/trustpay/trustpay.py#L344) · [TypeScript](../../examples/trustpay/trustpay.ts#L322) · [Kotlin](../../examples/trustpay/trustpay.kt) · [Rust](../../examples/trustpay/trustpay.rs#L340)

#### proxy_authorize

**Examples:** [Python](../../examples/trustpay/trustpay.py#L358) · [TypeScript](../../examples/trustpay/trustpay.ts#L332) · [Kotlin](../../examples/trustpay/trustpay.kt) · [Rust](../../examples/trustpay/trustpay.rs#L349)

#### refund

**Examples:** [Python](../../examples/trustpay/trustpay.py#L405) · [TypeScript](../../examples/trustpay/trustpay.ts#L375) · [Kotlin](../../examples/trustpay/trustpay.kt) · [Rust](../../examples/trustpay/trustpay.rs#L395)

#### refund_get

**Examples:** [Python](../../examples/trustpay/trustpay.py#L434) · [TypeScript](../../examples/trustpay/trustpay.ts#L401) · [Kotlin](../../examples/trustpay/trustpay.kt) · [Rust](../../examples/trustpay/trustpay.rs#L418)
