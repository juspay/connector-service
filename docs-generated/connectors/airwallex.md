# Airwallex

<!--
This file is auto-generated. Do not edit by hand.
Source: data/field_probe/airwallex.json
Regenerate: python3 scripts/generators/docs/generate.py airwallex
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
#     airwallex=payment_pb2.AirwallexConfig(api_key=...),
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
    connector: 'Airwallex',
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
    .setConnector("Airwallex")
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
    connector: "Airwallex".to_string(),
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

**Examples:** [Python](../../examples/airwallex/airwallex.py#L23) · [JavaScript](../../examples/airwallex/airwallex.js) · [Kotlin](../../examples/airwallex/airwallex.kt#L23) · [Rust](../../examples/airwallex/airwallex.rs#L27)

### Card Payment (Authorize + Capture)

Two-step card payment. First authorize, then capture. Use when you need to verify funds before finalizing.

**Response status handling:**

| Status | Recommended action |
|--------|-------------------|
| `AUTHORIZED` | Funds reserved — proceed to Capture to settle |
| `PENDING` | Awaiting async confirmation — wait for webhook before capturing |
| `FAILED` | Payment declined — surface error to customer, do not retry without new details |

**Examples:** [Python](../../examples/airwallex/airwallex.py#L68) · [JavaScript](../../examples/airwallex/airwallex.js) · [Kotlin](../../examples/airwallex/airwallex.kt#L55) · [Rust](../../examples/airwallex/airwallex.rs#L73)

### Refund

Return funds to the customer for a completed payment.

**Examples:** [Python](../../examples/airwallex/airwallex.py#L133) · [JavaScript](../../examples/airwallex/airwallex.js) · [Kotlin](../../examples/airwallex/airwallex.kt#L101) · [Rust](../../examples/airwallex/airwallex.rs#L140)

### Void Payment

Cancel an authorized but not-yet-captured payment.

**Examples:** [Python](../../examples/airwallex/airwallex.py#L200) · [JavaScript](../../examples/airwallex/airwallex.js) · [Kotlin](../../examples/airwallex/airwallex.kt#L149) · [Rust](../../examples/airwallex/airwallex.rs#L209)

### Get Payment Status

Retrieve current payment status from the connector.

**Examples:** [Python](../../examples/airwallex/airwallex.py#L258) · [JavaScript](../../examples/airwallex/airwallex.js) · [Kotlin](../../examples/airwallex/airwallex.kt#L190) · [Rust](../../examples/airwallex/airwallex.rs#L268)

## API Reference

| Flow (Service.RPC) | Category | gRPC Request Message |
|--------------------|----------|----------------------|
| [authorize](#authorize) | Other | `—` |
| [capture](#capture) | Other | `—` |
| [create_order](#create_order) | Other | `—` |
| [create_server_authentication_token](#create_server_authentication_token) | Other | `—` |
| [get](#get) | Other | `—` |
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
| Bancontact | x |
| Apple Pay | x |
| Apple Pay Dec | x |
| Apple Pay SDK | x |
| Google Pay | x |
| Google Pay Dec | x |
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
| iDEAL | ✓ |
| Sofort | x |
| Trustly | ✓ |
| Giropay | x |
| EPS | x |
| Przelewy24 | x |
| PSE | x |
| BLIK | ✓ |
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
| ACH | x |
| SEPA | x |
| BACS | x |
| BECS | x |
| SEPA Guaranteed | x |
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

**Examples:** [Python](../../examples/airwallex/airwallex.py#L320) · [TypeScript](../../examples/airwallex/airwallex.ts#L305) · [Kotlin](../../examples/airwallex/airwallex.kt) · [Rust](../../examples/airwallex/airwallex.rs#L330)

#### capture

**Examples:** [Python](../../examples/airwallex/airwallex.py#L362) · [TypeScript](../../examples/airwallex/airwallex.ts#L345) · [Kotlin](../../examples/airwallex/airwallex.kt) · [Rust](../../examples/airwallex/airwallex.rs#L372)

#### create_order

**Examples:** [Python](../../examples/airwallex/airwallex.py#L389) · [TypeScript](../../examples/airwallex/airwallex.ts#L369) · [Kotlin](../../examples/airwallex/airwallex.kt) · [Rust](../../examples/airwallex/airwallex.rs#L393)

#### create_server_authentication_token

**Examples:** [Python](../../examples/airwallex/airwallex.py#L412) · [TypeScript](../../examples/airwallex/airwallex.ts#L388) · [Kotlin](../../examples/airwallex/airwallex.kt) · [Rust](../../examples/airwallex/airwallex.rs#L413)

#### get

**Examples:** [Python](../../examples/airwallex/airwallex.py#L426) · [TypeScript](../../examples/airwallex/airwallex.ts#L398) · [Kotlin](../../examples/airwallex/airwallex.kt) · [Rust](../../examples/airwallex/airwallex.rs#L422)

#### proxy_authorize

**Examples:** [Python](../../examples/airwallex/airwallex.py#L450) · [TypeScript](../../examples/airwallex/airwallex.ts#L418) · [Kotlin](../../examples/airwallex/airwallex.kt) · [Rust](../../examples/airwallex/airwallex.rs#L443)

#### refund

**Examples:** [Python](../../examples/airwallex/airwallex.py#L486) · [TypeScript](../../examples/airwallex/airwallex.ts#L450) · [Kotlin](../../examples/airwallex/airwallex.kt) · [Rust](../../examples/airwallex/airwallex.rs#L478)

#### refund_get

**Examples:** [Python](../../examples/airwallex/airwallex.py#L515) · [TypeScript](../../examples/airwallex/airwallex.ts#L476) · [Kotlin](../../examples/airwallex/airwallex.kt) · [Rust](../../examples/airwallex/airwallex.rs#L501)

#### void

**Examples:** [Python](../../examples/airwallex/airwallex.py#L536) · [TypeScript](../../examples/airwallex/airwallex.ts) · [Kotlin](../../examples/airwallex/airwallex.kt) · [Rust](../../examples/airwallex/airwallex.rs#L519)
