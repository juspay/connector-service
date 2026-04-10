# Finix

<!--
This file is auto-generated. Do not edit by hand.
Source: data/field_probe/finix.json
Regenerate: python3 scripts/generators/docs/generate.py finix
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
#     finix=payment_pb2.FinixConfig(api_key=...),
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
    connector: 'Finix',
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
    .setConnector("Finix")
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
    connector: "Finix".to_string(),
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
| [token_authorize](#token_authorize) | Other | `—` |
| [tokenize](#tokenize) | Other | `—` |
| [void](#void) | Other | `—` |

### Other

#### capture

**Examples:** [Python](../../examples/finix/finix.py#L23) · [TypeScript](../../examples/finix/finix.ts#L24) · [Kotlin](../../examples/finix/finix.kt) · [Rust](../../examples/finix/finix.rs#L26)

#### create_customer

**Examples:** [Python](../../examples/finix/finix.py#L45) · [TypeScript](../../examples/finix/finix.ts#L43) · [Kotlin](../../examples/finix/finix.kt) · [Rust](../../examples/finix/finix.rs#L40)

#### get

**Examples:** [Python](../../examples/finix/finix.py#L62) · [TypeScript](../../examples/finix/finix.ts#L56) · [Kotlin](../../examples/finix/finix.kt) · [Rust](../../examples/finix/finix.rs#L52)

#### refund

**Examples:** [Python](../../examples/finix/finix.py#L81) · [TypeScript](../../examples/finix/finix.ts#L71) · [Kotlin](../../examples/finix/finix.kt) · [Rust](../../examples/finix/finix.rs#L66)

#### refund_get

**Examples:** [Python](../../examples/finix/finix.py#L105) · [TypeScript](../../examples/finix/finix.ts#L92) · [Kotlin](../../examples/finix/finix.kt) · [Rust](../../examples/finix/finix.rs#L82)

#### token_authorize

**Examples:** [Python](../../examples/finix/finix.py#L121) · [TypeScript](../../examples/finix/finix.ts#L104) · [Kotlin](../../examples/finix/finix.kt) · [Rust](../../examples/finix/finix.rs#L93)

#### tokenize

**Examples:** [Python](../../examples/finix/finix.py#L144) · [TypeScript](../../examples/finix/finix.ts#L123) · [Kotlin](../../examples/finix/finix.kt) · [Rust](../../examples/finix/finix.rs#L113)

#### void

**Examples:** [Python](../../examples/finix/finix.py#L173) · [TypeScript](../../examples/finix/finix.ts) · [Kotlin](../../examples/finix/finix.kt) · [Rust](../../examples/finix/finix.rs#L141)
