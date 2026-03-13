# Nuvei

<!--
This file is auto-generated. Do not edit by hand.
Source: data/field_probe/nuvei.json
Regenerate: python3 scripts/generate-connector-docs.py nuvei
-->

## Implemented Flows

| Flow (Service.RPC) | Category | gRPC Request Message |
|--------------------|----------|----------------------|
| [PaymentMethodAuthenticationService.Authenticate](#paymentmethodauthenticationserviceauthenticate) | Authentication | `PaymentMethodAuthenticationServiceAuthenticateRequest` |
| [PaymentService.Authorize](#paymentserviceauthorize) | Payments | `PaymentServiceAuthorizeRequest` |
| [PaymentService.Capture](#paymentservicecapture) | Payments | `PaymentServiceCaptureRequest` |
| [MerchantAuthenticationService.CreateSessionToken](#merchantauthenticationservicecreatesessiontoken) | Authentication | `MerchantAuthenticationServiceCreateSessionTokenRequest` |
| [PaymentService.Get](#paymentserviceget) | Payments | `PaymentServiceGetRequest` |
| [PaymentMethodAuthenticationService.PostAuthenticate](#paymentmethodauthenticationservicepostauthenticate) | Authentication | `PaymentMethodAuthenticationServicePostAuthenticateRequest` |
| [PaymentMethodAuthenticationService.PreAuthenticate](#paymentmethodauthenticationservicepreauthenticate) | Authentication | `PaymentMethodAuthenticationServicePreAuthenticateRequest` |
| [PaymentService.Refund](#paymentservicerefund) | Payments | `PaymentServiceRefundRequest` |
| [PaymentService.Void](#paymentservicevoid) | Payments | `PaymentServiceVoidRequest` |

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
| Card | — |
| Samsung Pay | — |

<!-- TODO: Add sample payload for `authorize` in `scripts/connector-annotations/nuvei.yaml` -->

#### PaymentService.Capture

Finalize an authorized payment transaction. Transfers reserved funds from customer to merchant account, completing the payment lifecycle.

| | Message |
|---|---------|
| **Request** | `PaymentServiceCaptureRequest` |
| **Response** | `PaymentServiceCaptureResponse` |

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
    connector=sdk_config_pb2.Connector.NUVEI,
    environment=sdk_config_pb2.Environment.SANDBOX,
    auth=sdk_config_pb2.ConnectorAuthType(
        header_key=sdk_config_pb2.HeaderKey(api_key="YOUR_API_KEY"),
    ),
)

request = ParseDict(
{
        "merchant_capture_id": "probe_capture_001",  # Identification
        "connector_transaction_id": "probe_connector_txn_001",
        "amount_to_capture": {  # Capture Details
            "minor_amount": 1000,  # Amount in minor units (e.g., 1000 = $10.00)
            "currency": "USD"  # ISO 4217 currency code (e.g., "USD", "EUR")
        }
    },
    payment_pb2.PaymentServiceCaptureRequest(),
)

async def main():
    client = PaymentClient(config)
    response = await client.capture(request)
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
    connector: 'Nuvei',
    environment: 'sandbox',
    connector_auth_type: {
        header_key: { api_key: 'YOUR_API_KEY' },
    },
});

const request = {
    "merchant_capture_id": "probe_capture_001",  // Identification
    "connector_transaction_id": "probe_connector_txn_001",
    "amount_to_capture": {  // Capture Details
        "minor_amount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
        "currency": "USD"  // ISO 4217 currency code (e.g., "USD", "EUR")
    }
};

const response = await client.capture(request);
console.log(response);
```

</details>

</td>
<td valign="top">

<details><summary>Kotlin</summary>

```kotlin
import payments.PaymentClient
import types.Payment.PaymentServiceCaptureRequest
import com.google.protobuf.util.JsonFormat

val config = ConnectorConfig.newBuilder()
    .setConnector("Nuvei")
    .setEnvironment(Environment.SANDBOX)
    .setAuth(
        ConnectorAuthType.newBuilder()
            .setHeaderKey(HeaderKey.newBuilder().setApiKey("YOUR_API_KEY"))
    )
    .build()

// JSON with field descriptions (remove comment lines before parsing)
val json = """
{
        // Identification
        "merchant_capture_id": "probe_capture_001",
        "connector_transaction_id": "probe_connector_txn_001",
        // Capture Details
        "amount_to_capture": {
            // Amount in minor units (e.g., 1000 = $10.00)
            "minor_amount": 1000,
            // ISO 4217 currency code (e.g., "USD", "EUR")
            "currency": "USD"
        }
    }
""".trimIndent()

val builder = PaymentServiceCaptureRequest.newBuilder()
JsonFormat.parser().ignoringUnknownFields().merge(json, builder)
val request = builder.build()

val client = PaymentClient(config)
val response = client.capture(request)
println(response)
```

</details>

</td>
<td valign="top">

<details><summary>Rust</summary>

```rust
use connector_service_sdk::{ConnectorClient, ConnectorConfig};
use grpc_api_types::payments::PaymentServiceCaptureRequest;

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ConnectorConfig {
        connector: "Nuvei".to_string(),
        environment: Environment::Sandbox,
        auth: ConnectorAuth::HeaderKey { api_key: "YOUR_API_KEY".into() },
        ..Default::default()
    };

    // Field names and descriptions from the proto definition above
    let request = PaymentServiceCaptureRequest {
        // merchant_capture_id: todo!(),  // Identification
        // connector_transaction_id: todo!(),
        // amount_to_capture: todo!(),  // Capture Details
        ..Default::default()
    };

    let client = ConnectorClient::new(config, None)?;
    let response = client.capture(request, &Default::default(), None).await?;
    println!("{response:?}");
    Ok(())
}
```

</details>

</td>
</tr>
</table>

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
    connector=sdk_config_pb2.Connector.NUVEI,
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
        }
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
    connector: 'Nuvei',
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
    }
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
    .setConnector("Nuvei")
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
        }
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
        connector: "Nuvei".to_string(),
        environment: Environment::Sandbox,
        auth: ConnectorAuth::HeaderKey { api_key: "YOUR_API_KEY".into() },
        ..Default::default()
    };

    // Field names and descriptions from the proto definition above
    let request = PaymentServiceGetRequest {
        // connector_transaction_id: todo!(),
        // amount: todo!(),  // Amount Information
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

#### PaymentService.Refund

Initiate a refund to customer's payment method. Returns funds for returns, cancellations, or service adjustments after original payment.

| | Message |
|---|---------|
| **Request** | `PaymentServiceRefundRequest` |
| **Response** | `RefundResponse` |

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
    connector=sdk_config_pb2.Connector.NUVEI,
    environment=sdk_config_pb2.Environment.SANDBOX,
    auth=sdk_config_pb2.ConnectorAuthType(
        header_key=sdk_config_pb2.HeaderKey(api_key="YOUR_API_KEY"),
    ),
)

request = ParseDict(
{
        "merchant_refund_id": "probe_refund_001",  # Identification
        "connector_transaction_id": "probe_connector_txn_001",
        "payment_amount": 1000,  # Amount Information
        "refund_amount": {
            "minor_amount": 1000,  # Amount in minor units (e.g., 1000 = $10.00)
            "currency": "USD"  # ISO 4217 currency code (e.g., "USD", "EUR")
        },
        "reason": "customer_request"  # Reason for the refund
    },
    payment_pb2.PaymentServiceRefundRequest(),
)

async def main():
    client = PaymentClient(config)
    response = await client.refund(request)
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
    connector: 'Nuvei',
    environment: 'sandbox',
    connector_auth_type: {
        header_key: { api_key: 'YOUR_API_KEY' },
    },
});

const request = {
    "merchant_refund_id": "probe_refund_001",  // Identification
    "connector_transaction_id": "probe_connector_txn_001",
    "payment_amount": 1000,  // Amount Information
    "refund_amount": {
        "minor_amount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
        "currency": "USD"  // ISO 4217 currency code (e.g., "USD", "EUR")
    },
    "reason": "customer_request"  // Reason for the refund
};

const response = await client.refund(request);
console.log(response);
```

</details>

</td>
<td valign="top">

<details><summary>Kotlin</summary>

```kotlin
import payments.PaymentClient
import types.Payment.PaymentServiceRefundRequest
import com.google.protobuf.util.JsonFormat

val config = ConnectorConfig.newBuilder()
    .setConnector("Nuvei")
    .setEnvironment(Environment.SANDBOX)
    .setAuth(
        ConnectorAuthType.newBuilder()
            .setHeaderKey(HeaderKey.newBuilder().setApiKey("YOUR_API_KEY"))
    )
    .build()

// JSON with field descriptions (remove comment lines before parsing)
val json = """
{
        // Identification
        "merchant_refund_id": "probe_refund_001",
        "connector_transaction_id": "probe_connector_txn_001",
        // Amount Information
        "payment_amount": 1000,
        "refund_amount": {
            // Amount in minor units (e.g., 1000 = $10.00)
            "minor_amount": 1000,
            // ISO 4217 currency code (e.g., "USD", "EUR")
            "currency": "USD"
        },
        // Reason for the refund
        "reason": "customer_request"
    }
""".trimIndent()

val builder = PaymentServiceRefundRequest.newBuilder()
JsonFormat.parser().ignoringUnknownFields().merge(json, builder)
val request = builder.build()

val client = PaymentClient(config)
val response = client.refund(request)
println(response)
```

</details>

</td>
<td valign="top">

<details><summary>Rust</summary>

```rust
use connector_service_sdk::{ConnectorClient, ConnectorConfig};
use grpc_api_types::payments::PaymentServiceRefundRequest;

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ConnectorConfig {
        connector: "Nuvei".to_string(),
        environment: Environment::Sandbox,
        auth: ConnectorAuth::HeaderKey { api_key: "YOUR_API_KEY".into() },
        ..Default::default()
    };

    // Field names and descriptions from the proto definition above
    let request = PaymentServiceRefundRequest {
        // merchant_refund_id: todo!(),  // Identification
        // connector_transaction_id: todo!(),
        // payment_amount: todo!(),  // Amount Information
        // refund_amount: todo!(),
        // reason: todo!(),  // Reason for the refund
        ..Default::default()
    };

    let client = ConnectorClient::new(config, None)?;
    let response = client.refund(request, &Default::default(), None).await?;
    println!("{response:?}");
    Ok(())
}
```

</details>

</td>
</tr>
</table>

#### PaymentService.Void

Cancel an authorized payment before capture. Releases held funds back to customer, typically used when orders are cancelled or abandoned.

| | Message |
|---|---------|
| **Request** | `PaymentServiceVoidRequest` |
| **Response** | `PaymentServiceVoidResponse` |

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
    connector=sdk_config_pb2.Connector.NUVEI,
    environment=sdk_config_pb2.Environment.SANDBOX,
    auth=sdk_config_pb2.ConnectorAuthType(
        header_key=sdk_config_pb2.HeaderKey(api_key="YOUR_API_KEY"),
    ),
)

request = ParseDict(
{
        "merchant_void_id": "probe_void_001",  # Identification
        "connector_transaction_id": "probe_connector_txn_001",
        "amount": {  # Amount Information
            "minor_amount": 1000,  # Amount in minor units (e.g., 1000 = $10.00)
            "currency": "USD"  # ISO 4217 currency code (e.g., "USD", "EUR")
        }
    },
    payment_pb2.PaymentServiceVoidRequest(),
)

async def main():
    client = PaymentClient(config)
    response = await client.void(request)
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
    connector: 'Nuvei',
    environment: 'sandbox',
    connector_auth_type: {
        header_key: { api_key: 'YOUR_API_KEY' },
    },
});

const request = {
    "merchant_void_id": "probe_void_001",  // Identification
    "connector_transaction_id": "probe_connector_txn_001",
    "amount": {  // Amount Information
        "minor_amount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
        "currency": "USD"  // ISO 4217 currency code (e.g., "USD", "EUR")
    }
};

const response = await client.void(request);
console.log(response);
```

</details>

</td>
<td valign="top">

<details><summary>Kotlin</summary>

```kotlin
import payments.PaymentClient
import types.Payment.PaymentServiceVoidRequest
import com.google.protobuf.util.JsonFormat

val config = ConnectorConfig.newBuilder()
    .setConnector("Nuvei")
    .setEnvironment(Environment.SANDBOX)
    .setAuth(
        ConnectorAuthType.newBuilder()
            .setHeaderKey(HeaderKey.newBuilder().setApiKey("YOUR_API_KEY"))
    )
    .build()

// JSON with field descriptions (remove comment lines before parsing)
val json = """
{
        // Identification
        "merchant_void_id": "probe_void_001",
        "connector_transaction_id": "probe_connector_txn_001",
        // Amount Information
        "amount": {
            // Amount in minor units (e.g., 1000 = $10.00)
            "minor_amount": 1000,
            // ISO 4217 currency code (e.g., "USD", "EUR")
            "currency": "USD"
        }
    }
""".trimIndent()

val builder = PaymentServiceVoidRequest.newBuilder()
JsonFormat.parser().ignoringUnknownFields().merge(json, builder)
val request = builder.build()

val client = PaymentClient(config)
val response = client.void(request)
println(response)
```

</details>

</td>
<td valign="top">

<details><summary>Rust</summary>

```rust
use connector_service_sdk::{ConnectorClient, ConnectorConfig};
use grpc_api_types::payments::PaymentServiceVoidRequest;

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ConnectorConfig {
        connector: "Nuvei".to_string(),
        environment: Environment::Sandbox,
        auth: ConnectorAuth::HeaderKey { api_key: "YOUR_API_KEY".into() },
        ..Default::default()
    };

    // Field names and descriptions from the proto definition above
    let request = PaymentServiceVoidRequest {
        // merchant_void_id: todo!(),  // Identification
        // connector_transaction_id: todo!(),
        // amount: todo!(),  // Amount Information
        ..Default::default()
    };

    let client = ConnectorClient::new(config, None)?;
    let response = client.void(request, &Default::default(), None).await?;
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

<!-- TODO: Add sample payload for `authenticate` in `scripts/connector-annotations/nuvei.yaml` -->

#### MerchantAuthenticationService.CreateSessionToken

Create session token for payment processing. Maintains session state across multiple payment operations for improved security and tracking.

| | Message |
|---|---------|
| **Request** | `MerchantAuthenticationServiceCreateSessionTokenRequest` |
| **Response** | `MerchantAuthenticationServiceCreateSessionTokenResponse` |

**Example Request**


<table>
<tr><td><b>Python</b></td><td><b>JavaScript</b></td><td><b>Kotlin</b></td><td><b>Rust</b></td></tr>
<tr>
<td valign="top">

<details><summary>Python</summary>

```python
import asyncio
from google.protobuf.json_format import ParseDict
from payments import MerchantAuthenticationClient
from payments.generated import sdk_config_pb2, payment_pb2

config = sdk_config_pb2.ConnectorConfig(
    connector=sdk_config_pb2.Connector.NUVEI,
    environment=sdk_config_pb2.Environment.SANDBOX,
    auth=sdk_config_pb2.ConnectorAuthType(
        header_key=sdk_config_pb2.HeaderKey(api_key="YOUR_API_KEY"),
    ),
)

request = ParseDict(
{
        "amount": {  # Amount Information
            "minor_amount": 1000,  # Amount in minor units (e.g., 1000 = $10.00)
            "currency": "USD"  # ISO 4217 currency code (e.g., "USD", "EUR")
        }
    },
    payment_pb2.MerchantAuthenticationServiceCreateSessionTokenRequest(),
)

async def main():
    client = MerchantAuthenticationClient(config)
    response = await client.create_session_token(request)
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
    connector: 'Nuvei',
    environment: 'sandbox',
    connector_auth_type: {
        header_key: { api_key: 'YOUR_API_KEY' },
    },
});

const request = {
    "amount": {  // Amount Information
        "minor_amount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
        "currency": "USD"  // ISO 4217 currency code (e.g., "USD", "EUR")
    }
};

const response = await client.createSessionToken(request);
console.log(response);
```

</details>

</td>
<td valign="top">

<details><summary>Kotlin</summary>

```kotlin
import payments.MerchantAuthenticationClient
import types.Payment.MerchantAuthenticationServiceCreateSessionTokenRequest
import com.google.protobuf.util.JsonFormat

val config = ConnectorConfig.newBuilder()
    .setConnector("Nuvei")
    .setEnvironment(Environment.SANDBOX)
    .setAuth(
        ConnectorAuthType.newBuilder()
            .setHeaderKey(HeaderKey.newBuilder().setApiKey("YOUR_API_KEY"))
    )
    .build()

// JSON with field descriptions (remove comment lines before parsing)
val json = """
{
        // Amount Information
        "amount": {
            // Amount in minor units (e.g., 1000 = $10.00)
            "minor_amount": 1000,
            // ISO 4217 currency code (e.g., "USD", "EUR")
            "currency": "USD"
        }
    }
""".trimIndent()

val builder = MerchantAuthenticationServiceCreateSessionTokenRequest.newBuilder()
JsonFormat.parser().ignoringUnknownFields().merge(json, builder)
val request = builder.build()

val client = MerchantAuthenticationClient(config)
val response = client.create_session_token(request)
println(response)
```

</details>

</td>
<td valign="top">

<details><summary>Rust</summary>

```rust
use connector_service_sdk::{ConnectorClient, ConnectorConfig};
use grpc_api_types::payments::MerchantAuthenticationServiceCreateSessionTokenRequest;

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ConnectorConfig {
        connector: "Nuvei".to_string(),
        environment: Environment::Sandbox,
        auth: ConnectorAuth::HeaderKey { api_key: "YOUR_API_KEY".into() },
        ..Default::default()
    };

    // Field names and descriptions from the proto definition above
    let request = MerchantAuthenticationServiceCreateSessionTokenRequest {
        // amount: todo!(),  // Amount Information
        ..Default::default()
    };

    let client = ConnectorClient::new(config, None)?;
    let response = client.create_session_token(request, &Default::default(), None).await?;
    println!("{response:?}");
    Ok(())
}
```

</details>

</td>
</tr>
</table>

#### PaymentMethodAuthenticationService.PostAuthenticate

Validate authentication results with the issuing bank. Processes bank's authentication decision to determine if payment can proceed.

| | Message |
|---|---------|
| **Request** | `PaymentMethodAuthenticationServicePostAuthenticateRequest` |
| **Response** | `PaymentMethodAuthenticationServicePostAuthenticateResponse` |

<!-- TODO: Add sample payload for `post_authenticate` in `scripts/connector-annotations/nuvei.yaml` -->

#### PaymentMethodAuthenticationService.PreAuthenticate

Initiate 3DS flow before payment authorization. Collects device data and prepares authentication context for frictionless or challenge-based verification.

| | Message |
|---|---------|
| **Request** | `PaymentMethodAuthenticationServicePreAuthenticateRequest` |
| **Response** | `PaymentMethodAuthenticationServicePreAuthenticateResponse` |

<!-- TODO: Add sample payload for `pre_authenticate` in `scripts/connector-annotations/nuvei.yaml` -->
