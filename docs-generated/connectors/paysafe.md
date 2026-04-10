# Paysafe

<!--
This file is auto-generated. Do not edit by hand.
Source: data/field_probe/paysafe.json
Regenerate: python3 scripts/generators/docs/generate.py paysafe
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
#     paysafe=payment_pb2.PaysafeConfig(api_key=...),
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
    connector: 'Paysafe',
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
    .setConnector("Paysafe")
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
    connector: "Paysafe".to_string(),
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
| [refund](#refund) | Other | `—` |
| [refund_get](#refund_get) | Other | `—` |
| [token_authorize](#token_authorize) | Other | `—` |
| [tokenize](#tokenize) | Other | `—` |
| [void](#void) | Other | `—` |

### Other

#### capture

**Examples:** [Python](../../examples/paysafe/paysafe.py#L23) · [TypeScript](../../examples/paysafe/paysafe.ts#L24) · [Kotlin](../../examples/paysafe/paysafe.kt) · [Rust](../../examples/paysafe/paysafe.rs#L26)

#### get

**Examples:** [Python](../../examples/paysafe/paysafe.py#L45) · [TypeScript](../../examples/paysafe/paysafe.ts#L43) · [Kotlin](../../examples/paysafe/paysafe.kt) · [Rust](../../examples/paysafe/paysafe.rs#L40)

#### refund

**Examples:** [Python](../../examples/paysafe/paysafe.py#L64) · [TypeScript](../../examples/paysafe/paysafe.ts#L58) · [Kotlin](../../examples/paysafe/paysafe.kt) · [Rust](../../examples/paysafe/paysafe.rs#L54)

#### refund_get

**Examples:** [Python](../../examples/paysafe/paysafe.py#L88) · [TypeScript](../../examples/paysafe/paysafe.ts#L79) · [Kotlin](../../examples/paysafe/paysafe.kt) · [Rust](../../examples/paysafe/paysafe.rs#L70)

#### token_authorize

**Examples:** [Python](../../examples/paysafe/paysafe.py#L104) · [TypeScript](../../examples/paysafe/paysafe.ts#L91) · [Kotlin](../../examples/paysafe/paysafe.kt) · [Rust](../../examples/paysafe/paysafe.rs#L81)

#### tokenize

**Examples:** [Python](../../examples/paysafe/paysafe.py#L127) · [TypeScript](../../examples/paysafe/paysafe.ts#L110) · [Kotlin](../../examples/paysafe/paysafe.kt) · [Rust](../../examples/paysafe/paysafe.rs#L101)

#### void

**Examples:** [Python](../../examples/paysafe/paysafe.py#L154) · [TypeScript](../../examples/paysafe/paysafe.ts) · [Kotlin](../../examples/paysafe/paysafe.kt) · [Rust](../../examples/paysafe/paysafe.rs#L127)
