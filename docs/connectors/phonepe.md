# PhonePe

<!--
This file is auto-generated. Do not edit by hand.
Source: data/field_probe/phonepe.json
Regenerate: python3 scripts/generate-connector-docs.py phonepe
-->

## Implemented Flows

| Flow (Service.RPC) | Category | gRPC Request Message |
|--------------------|----------|----------------------|
| [PaymentMethodAuthenticationService.Authenticate](#paymentmethodauthenticationserviceauthenticate) | Authentication | `PaymentMethodAuthenticationServiceAuthenticateRequest` |
| [PaymentService.Authorize](#paymentserviceauthorize) | Payments | `PaymentServiceAuthorizeRequest` |
| [PaymentService.Get](#paymentserviceget) | Payments | `PaymentServiceGetRequest` |
| [PaymentMethodAuthenticationService.PostAuthenticate](#paymentmethodauthenticationservicepostauthenticate) | Authentication | `PaymentMethodAuthenticationServicePostAuthenticateRequest` |
| [PaymentMethodAuthenticationService.PreAuthenticate](#paymentmethodauthenticationservicepreauthenticate) | Authentication | `PaymentMethodAuthenticationServicePreAuthenticateRequest` |

## Flow Details

### Payments

#### PaymentService.Authorize

Authorize a payment amount on a payment method. This reserves funds without capturing them, essential for verifying availability before finalizing.

| | Message |
|---|---------|
| **Request** | `PaymentServiceAuthorizeRequest` |
| **Response** | `PaymentServiceAuthorizeResponse` |

**Supported payment method types:**

| Payment Method | Supported |
|----------------|:---------:|
| UPI | ✓ |
| Samsung Pay | — |

<!-- TODO: Add sample payload for `authorize` in `scripts/connector-annotations/phonepe.yaml` -->

#### PaymentService.Get

Retrieve current payment status from the payment processor. Enables synchronization between your system and payment processors for accurate state tracking.

| | Message |
|---|---------|
| **Request** | `PaymentServiceGetRequest` |
| **Response** | `PaymentServiceGetResponse` |

**Example Request**


<table>
<tr><td><b>Python</b></td><td><b>JavaScript</b></td><td><b>Kotlin</b></td><td><b>Rust</b></td></tr>
<tr>
<td valign="top">

<details><summary>Python</summary>

```python
import asyncio
from google.protobuf.json_format import ParseDict
from payments import PaymentClient
from payments.generated import sdk_config_pb2, payment_pb2

config = sdk_config_pb2.ConnectorConfig(
    connector=sdk_config_pb2.Connector.PHONEPE,
    environment=sdk_config_pb2.Environment.SANDBOX,
    auth=sdk_config_pb2.ConnectorAuthType(
        header_key=sdk_config_pb2.HeaderKey(api_key="YOUR_API_KEY"),
    ),
)

request = ParseDict(
{
        "connector_transaction_id": "probe_connector_txn_001",
        "amount": {  # Amount Information
            "minor_amount": 1000,  # Amount in minor units (e.g., 1000 = $10.00)
            "currency": "USD"  # ISO 4217 currency code (e.g., "USD", "EUR")
        },
        "connector_order_reference_id": "probe_order_ref_001"  # Connector Reference Id
    },
    payment_pb2.PaymentServiceGetRequest(),
)

async def main():
    client = PaymentClient(config)
    response = await client.get(request)
    print(response)

asyncio.run(main())
```

</details>

</td>
<td valign="top">

<details><summary>JavaScript</summary>

```javascript
const { ConnectorClient } = require('connector-service-node-ffi');

const client = new ConnectorClient({
    connector: 'Phonepe',
    environment: 'sandbox',
    connector_auth_type: {
        header_key: { api_key: 'YOUR_API_KEY' },
    },
});

const request = {
    "connector_transaction_id": "probe_connector_txn_001",
    "amount": {  // Amount Information
        "minor_amount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
        "currency": "USD"  // ISO 4217 currency code (e.g., "USD", "EUR")
    },
    "connector_order_reference_id": "probe_order_ref_001"  // Connector Reference Id
};

const response = await client.get(request);
console.log(response);
```

</details>

</td>
<td valign="top">

<details><summary>Kotlin</summary>

```kotlin
import payments.PaymentClient
import types.Payment.PaymentServiceGetRequest
import com.google.protobuf.util.JsonFormat

val config = ConnectorConfig.newBuilder()
    .setConnector("Phonepe")
    .setEnvironment(Environment.SANDBOX)
    .setAuth(
        ConnectorAuthType.newBuilder()
            .setHeaderKey(HeaderKey.newBuilder().setApiKey("YOUR_API_KEY"))
    )
    .build()

// JSON with field descriptions (remove comment lines before parsing)
val json = """
{
        "connector_transaction_id": "probe_connector_txn_001",
        // Amount Information
        "amount": {
            // Amount in minor units (e.g., 1000 = $10.00)
            "minor_amount": 1000,
            // ISO 4217 currency code (e.g., "USD", "EUR")
            "currency": "USD"
        },
        // Connector Reference Id
        "connector_order_reference_id": "probe_order_ref_001"
    }
""".trimIndent()

val builder = PaymentServiceGetRequest.newBuilder()
JsonFormat.parser().ignoringUnknownFields().merge(json, builder)
val request = builder.build()

val client = PaymentClient(config)
val response = client.get(request)
println(response)
```

</details>

</td>
<td valign="top">

<details><summary>Rust</summary>

```rust
use connector_service_sdk::{ConnectorClient, ConnectorConfig};
use grpc_api_types::payments::PaymentServiceGetRequest;

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ConnectorConfig {
        connector: "Phonepe".to_string(),
        environment: Environment::Sandbox,
        auth: ConnectorAuth::HeaderKey { api_key: "YOUR_API_KEY".into() },
        ..Default::default()
    };

    // Field names and descriptions from the proto definition above
    let request = PaymentServiceGetRequest {
        // connector_transaction_id: todo!(),
        // amount: todo!(),  // Amount Information
        // connector_order_reference_id: todo!(),  // Connector Reference Id
        ..Default::default()
    };

    let client = ConnectorClient::new(config, None)?;
    let response = client.get(request, &Default::default(), None).await?;
    println!("{response:?}");
    Ok(())
}
```

</details>

</td>
</tr>
</table>

### Authentication

#### PaymentMethodAuthenticationService.Authenticate

Execute 3DS challenge or frictionless verification. Authenticates customer via bank challenge or behind-the-scenes verification for fraud prevention.

| | Message |
|---|---------|
| **Request** | `PaymentMethodAuthenticationServiceAuthenticateRequest` |
| **Response** | `PaymentMethodAuthenticationServiceAuthenticateResponse` |

<!-- TODO: Add sample payload for `authenticate` in `scripts/connector-annotations/phonepe.yaml` -->

#### PaymentMethodAuthenticationService.PostAuthenticate

Validate authentication results with the issuing bank. Processes bank's authentication decision to determine if payment can proceed.

| | Message |
|---|---------|
| **Request** | `PaymentMethodAuthenticationServicePostAuthenticateRequest` |
| **Response** | `PaymentMethodAuthenticationServicePostAuthenticateResponse` |

<!-- TODO: Add sample payload for `post_authenticate` in `scripts/connector-annotations/phonepe.yaml` -->

#### PaymentMethodAuthenticationService.PreAuthenticate

Initiate 3DS flow before payment authorization. Collects device data and prepares authentication context for frictionless or challenge-based verification.

| | Message |
|---|---------|
| **Request** | `PaymentMethodAuthenticationServicePreAuthenticateRequest` |
| **Response** | `PaymentMethodAuthenticationServicePreAuthenticateResponse` |

<!-- TODO: Add sample payload for `pre_authenticate` in `scripts/connector-annotations/phonepe.yaml` -->
