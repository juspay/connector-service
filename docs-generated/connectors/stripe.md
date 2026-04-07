# Stripe

<!--
This file is auto-generated. Do not edit by hand.
Source: data/field_probe/stripe.json
Regenerate: python3 scripts/generators/docs/generate.py stripe
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
#     stripe=payment_pb2.StripeConfig(api_key=...),
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
    connector: 'Stripe',
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
    .setConnector("Stripe")
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
    connector: "Stripe".to_string(),
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

**Examples:** [Python](../../examples/stripe/stripe.py#L23) · [JavaScript](../../examples/stripe/stripe.js) · [Kotlin](../../examples/stripe/stripe.kt#L23) · [Rust](../../examples/stripe/stripe.rs#L27)

### Card Payment (Authorize + Capture)

Two-step card payment. First authorize, then capture. Use when you need to verify funds before finalizing.

**Response status handling:**

| Status | Recommended action |
|--------|-------------------|
| `AUTHORIZED` | Funds reserved — proceed to Capture to settle |
| `PENDING` | Awaiting async confirmation — wait for webhook before capturing |
| `FAILED` | Payment declined — surface error to customer, do not retry without new details |

**Examples:** [Python](../../examples/stripe/stripe.py#L62) · [JavaScript](../../examples/stripe/stripe.js) · [Kotlin](../../examples/stripe/stripe.kt#L51) · [Rust](../../examples/stripe/stripe.rs#L65)

### Refund

Return funds to the customer for a completed payment.

**Examples:** [Python](../../examples/stripe/stripe.py#L116) · [JavaScript](../../examples/stripe/stripe.js) · [Kotlin](../../examples/stripe/stripe.kt#L90) · [Rust](../../examples/stripe/stripe.rs#L117)

### Void Payment

Cancel an authorized but not-yet-captured payment.

**Examples:** [Python](../../examples/stripe/stripe.py#L172) · [JavaScript](../../examples/stripe/stripe.js) · [Kotlin](../../examples/stripe/stripe.kt#L131) · [Rust](../../examples/stripe/stripe.rs#L171)

### Get Payment Status

Retrieve current payment status from the connector.

**Examples:** [Python](../../examples/stripe/stripe.py#L219) · [JavaScript](../../examples/stripe/stripe.js) · [Kotlin](../../examples/stripe/stripe.kt#L165) · [Rust](../../examples/stripe/stripe.rs#L215)

## API Reference

| Flow (Service.RPC) | Category | gRPC Request Message |
|--------------------|----------|----------------------|
| [authorize](#authorize) | Other | `—` |
| [capture](#capture) | Other | `—` |
| [create_client_authentication_token](#create_client_authentication_token) | Other | `—` |
| [create_customer](#create_customer) | Other | `—` |
| [get](#get) | Other | `—` |
| [incremental_authorization](#incremental_authorization) | Other | `—` |
| [proxy_authorize](#proxy_authorize) | Other | `—` |
| [proxy_setup_recurring](#proxy_setup_recurring) | Other | `—` |
| [recurring_charge](#recurring_charge) | Other | `—` |
| [refund](#refund) | Other | `—` |
| [refund_get](#refund_get) | Other | `—` |
| [setup_recurring](#setup_recurring) | Other | `—` |
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
| Apple Pay SDK | ⚠ |
| Google Pay | ✓ |
| Google Pay Dec | ? |
| Google Pay SDK | ⚠ |
| PayPal SDK | ⚠ |
| Amazon Pay | ✓ |
| Cash App | ✓ |
| PayPal | ⚠ |
| WeChat Pay | ✓ |
| Alipay | ✓ |
| Revolut Pay | ✓ |
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
| Sofort | ⚠ |
| Trustly | ⚠ |
| Giropay | ✓ |
| EPS | ✓ |
| Przelewy24 | ✓ |
| PSE | ⚠ |
| BLIK | ✓ |
| Interac | ⚠ |
| Bizum | ⚠ |
| EFT | ⚠ |
| DuitNow | x |
| ACH | ✓ |
| SEPA | ✓ |
| BACS | ✓ |
| Multibanco | ✓ |
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

**Examples:** [Python](../../examples/stripe/stripe.py#L270) · [TypeScript](../../examples/stripe/stripe.ts#L255) · [Kotlin](../../examples/stripe/stripe.kt) · [Rust](../../examples/stripe/stripe.rs#L262)

#### capture

**Examples:** [Python](../../examples/stripe/stripe.py#L306) · [TypeScript](../../examples/stripe/stripe.ts#L289) · [Kotlin](../../examples/stripe/stripe.kt) · [Rust](../../examples/stripe/stripe.rs#L296)

#### create_client_authentication_token

**Examples:** [Python](../../examples/stripe/stripe.py#L328) · [TypeScript](../../examples/stripe/stripe.ts#L308) · [Kotlin](../../examples/stripe/stripe.kt) · [Rust](../../examples/stripe/stripe.rs#L310)

#### create_customer

**Examples:** [Python](../../examples/stripe/stripe.py#L346) · [TypeScript](../../examples/stripe/stripe.ts#L322) · [Kotlin](../../examples/stripe/stripe.kt) · [Rust](../../examples/stripe/stripe.rs#L327)

#### get

**Examples:** [Python](../../examples/stripe/stripe.py#L363) · [TypeScript](../../examples/stripe/stripe.ts#L335) · [Kotlin](../../examples/stripe/stripe.kt) · [Rust](../../examples/stripe/stripe.rs#L339)

#### incremental_authorization

**Examples:** [Python](../../examples/stripe/stripe.py#L382) · [TypeScript](../../examples/stripe/stripe.ts#L350) · [Kotlin](../../examples/stripe/stripe.kt) · [Rust](../../examples/stripe/stripe.rs#L353)

#### proxy_authorize

**Examples:** [Python](../../examples/stripe/stripe.py#L402) · [TypeScript](../../examples/stripe/stripe.ts#L366) · [Kotlin](../../examples/stripe/stripe.kt) · [Rust](../../examples/stripe/stripe.rs#L368)

#### proxy_setup_recurring

**Examples:** [Python](../../examples/stripe/stripe.py#L432) · [TypeScript](../../examples/stripe/stripe.ts#L392) · [Kotlin](../../examples/stripe/stripe.kt) · [Rust](../../examples/stripe/stripe.rs#L395)

#### recurring_charge

**Examples:** [Python](../../examples/stripe/stripe.py#L465) · [TypeScript](../../examples/stripe/stripe.ts#L421) · [Kotlin](../../examples/stripe/stripe.kt) · [Rust](../../examples/stripe/stripe.rs#L425)

#### refund

**Examples:** [Python](../../examples/stripe/stripe.py#L495) · [TypeScript](../../examples/stripe/stripe.ts#L448) · [Kotlin](../../examples/stripe/stripe.kt) · [Rust](../../examples/stripe/stripe.rs#L453)

#### refund_get

**Examples:** [Python](../../examples/stripe/stripe.py#L519) · [TypeScript](../../examples/stripe/stripe.ts#L469) · [Kotlin](../../examples/stripe/stripe.kt) · [Rust](../../examples/stripe/stripe.rs#L469)

#### setup_recurring

**Examples:** [Python](../../examples/stripe/stripe.py#L535) · [TypeScript](../../examples/stripe/stripe.ts#L481) · [Kotlin](../../examples/stripe/stripe.kt) · [Rust](../../examples/stripe/stripe.rs#L480)

#### tokenize

**Examples:** [Python](../../examples/stripe/stripe.py#L577) · [TypeScript](../../examples/stripe/stripe.ts#L517) · [Kotlin](../../examples/stripe/stripe.kt) · [Rust](../../examples/stripe/stripe.rs#L518)

#### void

**Examples:** [Python](../../examples/stripe/stripe.py#L603) · [TypeScript](../../examples/stripe/stripe.ts) · [Kotlin](../../examples/stripe/stripe.kt) · [Rust](../../examples/stripe/stripe.rs#L543)
