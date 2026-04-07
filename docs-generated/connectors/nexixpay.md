# Nexixpay

<!--
This file is auto-generated. Do not edit by hand.
Source: data/field_probe/nexixpay.json
Regenerate: python3 scripts/generators/docs/generate.py nexixpay
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
#     nexixpay=payment_pb2.NexixpayConfig(api_key=...),
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
    connector: 'Nexixpay',
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
    .setConnector("Nexixpay")
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
    connector: "Nexixpay".to_string(),
    environment: Environment::Sandbox,
    auth: ConnectorAuth::HeaderKey { api_key: "YOUR_API_KEY".into() },
    ..Default::default()
};
```

</details>

</td>
</tr>
</table>

## API Reference

| Flow (Service.RPC) | Category | gRPC Request Message |
|--------------------|----------|----------------------|
| [capture](#capture) | Other | `—` |
| [get](#get) | Other | `—` |
| [pre_authenticate](#pre_authenticate) | Other | `—` |
| [refund](#refund) | Other | `—` |
| [refund_get](#refund_get) | Other | `—` |
| [void](#void) | Other | `—` |

### Other

#### capture

**Examples:** [Python](../../examples/nexixpay/nexixpay.py#L23) · [TypeScript](../../examples/nexixpay/nexixpay.ts#L24) · [Kotlin](../../examples/nexixpay/nexixpay.kt) · [Rust](../../examples/nexixpay/nexixpay.rs#L26)

#### get

**Examples:** [Python](../../examples/nexixpay/nexixpay.py#L45) · [TypeScript](../../examples/nexixpay/nexixpay.ts#L43) · [Kotlin](../../examples/nexixpay/nexixpay.kt) · [Rust](../../examples/nexixpay/nexixpay.rs#L40)

#### pre_authenticate

**Examples:** [Python](../../examples/nexixpay/nexixpay.py#L64) · [TypeScript](../../examples/nexixpay/nexixpay.ts#L58) · [Kotlin](../../examples/nexixpay/nexixpay.kt) · [Rust](../../examples/nexixpay/nexixpay.rs#L54)

#### refund

**Examples:** [Python](../../examples/nexixpay/nexixpay.py#L92) · [TypeScript](../../examples/nexixpay/nexixpay.ts#L82) · [Kotlin](../../examples/nexixpay/nexixpay.kt) · [Rust](../../examples/nexixpay/nexixpay.rs#L81)

#### refund_get

**Examples:** [Python](../../examples/nexixpay/nexixpay.py#L116) · [TypeScript](../../examples/nexixpay/nexixpay.ts#L103) · [Kotlin](../../examples/nexixpay/nexixpay.kt) · [Rust](../../examples/nexixpay/nexixpay.rs#L97)

#### void

**Examples:** [Python](../../examples/nexixpay/nexixpay.py#L132) · [TypeScript](../../examples/nexixpay/nexixpay.ts) · [Kotlin](../../examples/nexixpay/nexixpay.kt) · [Rust](../../examples/nexixpay/nexixpay.rs#L108)
