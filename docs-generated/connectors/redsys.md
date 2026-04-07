# Redsys

<!--
This file is auto-generated. Do not edit by hand.
Source: data/field_probe/redsys.json
Regenerate: python3 scripts/generators/docs/generate.py redsys
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
#     redsys=payment_pb2.RedsysConfig(api_key=...),
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
    connector: 'Redsys',
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
    .setConnector("Redsys")
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
    connector: "Redsys".to_string(),
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
| [authenticate](#authenticate) | Other | `—` |
| [capture](#capture) | Other | `—` |
| [get](#get) | Other | `—` |
| [pre_authenticate](#pre_authenticate) | Other | `—` |
| [refund](#refund) | Other | `—` |
| [refund_get](#refund_get) | Other | `—` |
| [void](#void) | Other | `—` |

### Other

#### authenticate

**Examples:** [Python](../../examples/redsys/redsys.py#L23) · [TypeScript](../../examples/redsys/redsys.ts#L24) · [Kotlin](../../examples/redsys/redsys.kt) · [Rust](../../examples/redsys/redsys.rs#L26)

#### capture

**Examples:** [Python](../../examples/redsys/redsys.py#L71) · [TypeScript](../../examples/redsys/redsys.ts#L68) · [Kotlin](../../examples/redsys/redsys.kt) · [Rust](../../examples/redsys/redsys.rs#L73)

#### get

**Examples:** [Python](../../examples/redsys/redsys.py#L93) · [TypeScript](../../examples/redsys/redsys.ts#L87) · [Kotlin](../../examples/redsys/redsys.kt) · [Rust](../../examples/redsys/redsys.rs#L87)

#### pre_authenticate

**Examples:** [Python](../../examples/redsys/redsys.py#L112) · [TypeScript](../../examples/redsys/redsys.ts#L102) · [Kotlin](../../examples/redsys/redsys.kt) · [Rust](../../examples/redsys/redsys.rs#L101)

#### refund

**Examples:** [Python](../../examples/redsys/redsys.py#L140) · [TypeScript](../../examples/redsys/redsys.ts#L126) · [Kotlin](../../examples/redsys/redsys.kt) · [Rust](../../examples/redsys/redsys.rs#L128)

#### refund_get

**Examples:** [Python](../../examples/redsys/redsys.py#L164) · [TypeScript](../../examples/redsys/redsys.ts#L147) · [Kotlin](../../examples/redsys/redsys.kt) · [Rust](../../examples/redsys/redsys.rs#L144)

#### void

**Examples:** [Python](../../examples/redsys/redsys.py#L180) · [TypeScript](../../examples/redsys/redsys.ts) · [Kotlin](../../examples/redsys/redsys.kt) · [Rust](../../examples/redsys/redsys.rs#L155)
