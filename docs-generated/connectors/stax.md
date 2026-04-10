# Stax

<!--
This file is auto-generated. Do not edit by hand.
Source: data/field_probe/stax.json
Regenerate: python3 scripts/generators/docs/generate.py stax
-->

## SDK Configuration

Use this config for all flows in this connector. Replace `YOUR_API_KEY` with your actual credentials.

<table>
<tr><td><b>Python</b></td><td><b>JavaScript</b></td><td><b>Kotlin</b></td><td><b>Rust</b></td></tr>
<tr>
<td valign="top">

<details><summary>Python</summary>

```python
from payments.generated import sdk_config_pb2, payment_pb2, payment_methods_pb2

config = sdk_config_pb2.ConnectorConfig(
    options=sdk_config_pb2.SdkOptions(environment=sdk_config_pb2.Environment.SANDBOX),
)
# Set credentials before running (field names depend on connector auth type):
# config.connector_config.CopyFrom(payment_pb2.ConnectorSpecificConfig(
#     stax=payment_pb2.StaxConfig(api_key=...),
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
    connector: 'Stax',
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
    .setConnector("Stax")
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
    connector: "Stax".to_string(),
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
| [create_customer](#create_customer) | Other | `—` |
| [get](#get) | Other | `—` |
| [refund](#refund) | Other | `—` |
| [refund_get](#refund_get) | Other | `—` |
| [tokenize](#tokenize) | Other | `—` |
| [void](#void) | Other | `—` |

### Other

#### capture

**Examples:** [Python](../../examples/stax/stax.py#L23) · [TypeScript](../../examples/stax/stax.ts#L24) · [Kotlin](../../examples/stax/stax.kt) · [Rust](../../examples/stax/stax.rs#L26)

#### create_customer

**Examples:** [Python](../../examples/stax/stax.py#L45) · [TypeScript](../../examples/stax/stax.ts#L43) · [Kotlin](../../examples/stax/stax.kt) · [Rust](../../examples/stax/stax.rs#L40)

#### get

**Examples:** [Python](../../examples/stax/stax.py#L62) · [TypeScript](../../examples/stax/stax.ts#L56) · [Kotlin](../../examples/stax/stax.kt) · [Rust](../../examples/stax/stax.rs#L52)

#### refund

**Examples:** [Python](../../examples/stax/stax.py#L81) · [TypeScript](../../examples/stax/stax.ts#L71) · [Kotlin](../../examples/stax/stax.kt) · [Rust](../../examples/stax/stax.rs#L66)

#### refund_get

**Examples:** [Python](../../examples/stax/stax.py#L105) · [TypeScript](../../examples/stax/stax.ts#L92) · [Kotlin](../../examples/stax/stax.kt) · [Rust](../../examples/stax/stax.rs#L82)

#### tokenize

**Examples:** [Python](../../examples/stax/stax.py#L121) · [TypeScript](../../examples/stax/stax.ts#L104) · [Kotlin](../../examples/stax/stax.kt) · [Rust](../../examples/stax/stax.rs#L93)

#### void

**Examples:** [Python](../../examples/stax/stax.py#L150) · [TypeScript](../../examples/stax/stax.ts) · [Kotlin](../../examples/stax/stax.kt) · [Rust](../../examples/stax/stax.rs#L121)
