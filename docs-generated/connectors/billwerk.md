# Billwerk

<!--
This file is auto-generated. Do not edit by hand.
Source: data/field_probe/billwerk.json
Regenerate: python3 scripts/generators/docs/generate.py billwerk
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
#     billwerk=payment_pb2.BillwerkConfig(api_key=...),
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
    connector: 'Billwerk',
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
    .setConnector("Billwerk")
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
    connector: "Billwerk".to_string(),
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
| [recurring_charge](#recurring_charge) | Other | `—` |
| [refund](#refund) | Other | `—` |
| [refund_get](#refund_get) | Other | `—` |
| [token_authorize](#token_authorize) | Other | `—` |
| [token_setup_recurring](#token_setup_recurring) | Other | `—` |
| [tokenize](#tokenize) | Other | `—` |
| [void](#void) | Other | `—` |

### Other

#### capture

**Examples:** [Python](../../examples/billwerk/billwerk.py#L23) · [TypeScript](../../examples/billwerk/billwerk.ts#L24) · [Kotlin](../../examples/billwerk/billwerk.kt) · [Rust](../../examples/billwerk/billwerk.rs#L26)

#### get

**Examples:** [Python](../../examples/billwerk/billwerk.py#L45) · [TypeScript](../../examples/billwerk/billwerk.ts#L43) · [Kotlin](../../examples/billwerk/billwerk.kt) · [Rust](../../examples/billwerk/billwerk.rs#L40)

#### recurring_charge

**Examples:** [Python](../../examples/billwerk/billwerk.py#L65) · [TypeScript](../../examples/billwerk/billwerk.ts#L59) · [Kotlin](../../examples/billwerk/billwerk.kt) · [Rust](../../examples/billwerk/billwerk.rs#L55)

#### refund

**Examples:** [Python](../../examples/billwerk/billwerk.py#L95) · [TypeScript](../../examples/billwerk/billwerk.ts#L86) · [Kotlin](../../examples/billwerk/billwerk.kt) · [Rust](../../examples/billwerk/billwerk.rs#L83)

#### refund_get

**Examples:** [Python](../../examples/billwerk/billwerk.py#L119) · [TypeScript](../../examples/billwerk/billwerk.ts#L107) · [Kotlin](../../examples/billwerk/billwerk.kt) · [Rust](../../examples/billwerk/billwerk.rs#L99)

#### token_authorize

**Examples:** [Python](../../examples/billwerk/billwerk.py#L135) · [TypeScript](../../examples/billwerk/billwerk.ts#L119) · [Kotlin](../../examples/billwerk/billwerk.kt) · [Rust](../../examples/billwerk/billwerk.rs#L110)

#### token_setup_recurring

**Examples:** [Python](../../examples/billwerk/billwerk.py#L158) · [TypeScript](../../examples/billwerk/billwerk.ts#L138) · [Kotlin](../../examples/billwerk/billwerk.kt) · [Rust](../../examples/billwerk/billwerk.rs#L130)

#### tokenize

**Examples:** [Python](../../examples/billwerk/billwerk.py#L190) · [TypeScript](../../examples/billwerk/billwerk.ts#L166) · [Kotlin](../../examples/billwerk/billwerk.kt) · [Rust](../../examples/billwerk/billwerk.rs#L165)

#### void

**Examples:** [Python](../../examples/billwerk/billwerk.py#L216) · [TypeScript](../../examples/billwerk/billwerk.ts) · [Kotlin](../../examples/billwerk/billwerk.kt) · [Rust](../../examples/billwerk/billwerk.rs#L190)
