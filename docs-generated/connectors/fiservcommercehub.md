# Fiservcommercehub

<!--
This file is auto-generated. Do not edit by hand.
Source: data/field_probe/fiservcommercehub.json
Regenerate: python3 scripts/generators/docs/generate.py fiservcommercehub
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
#     fiservcommercehub=payment_pb2.FiservcommercehubConfig(api_key=...),
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
    connector: 'Fiservcommercehub',
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
    .setConnector("Fiservcommercehub")
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
    connector: "Fiservcommercehub".to_string(),
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
| [create_server_authentication_token](#create_server_authentication_token) | Other | `—` |
| [get](#get) | Other | `—` |
| [refund](#refund) | Other | `—` |
| [refund_get](#refund_get) | Other | `—` |
| [void](#void) | Other | `—` |

### Other

#### create_server_authentication_token

**Examples:** [Python](../../examples/fiservcommercehub/fiservcommercehub.py#L23) · [TypeScript](../../examples/fiservcommercehub/fiservcommercehub.ts#L24) · [Kotlin](../../examples/fiservcommercehub/fiservcommercehub.kt) · [Rust](../../examples/fiservcommercehub/fiservcommercehub.rs#L26)

#### get

**Examples:** [Python](../../examples/fiservcommercehub/fiservcommercehub.py#L37) · [TypeScript](../../examples/fiservcommercehub/fiservcommercehub.ts#L34) · [Kotlin](../../examples/fiservcommercehub/fiservcommercehub.kt) · [Rust](../../examples/fiservcommercehub/fiservcommercehub.rs#L35)

#### refund

**Examples:** [Python](../../examples/fiservcommercehub/fiservcommercehub.py#L61) · [TypeScript](../../examples/fiservcommercehub/fiservcommercehub.ts#L54) · [Kotlin](../../examples/fiservcommercehub/fiservcommercehub.kt) · [Rust](../../examples/fiservcommercehub/fiservcommercehub.rs#L56)

#### refund_get

**Examples:** [Python](../../examples/fiservcommercehub/fiservcommercehub.py#L90) · [TypeScript](../../examples/fiservcommercehub/fiservcommercehub.ts#L80) · [Kotlin](../../examples/fiservcommercehub/fiservcommercehub.kt) · [Rust](../../examples/fiservcommercehub/fiservcommercehub.rs#L79)

#### void

**Examples:** [Python](../../examples/fiservcommercehub/fiservcommercehub.py#L111) · [TypeScript](../../examples/fiservcommercehub/fiservcommercehub.ts) · [Kotlin](../../examples/fiservcommercehub/fiservcommercehub.kt) · [Rust](../../examples/fiservcommercehub/fiservcommercehub.rs#L97)
