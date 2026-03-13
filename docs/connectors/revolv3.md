# Revolv3

<!--
This file is auto-generated. Do not edit by hand.
Source: data/field_probe/revolv3.json
Regenerate: python3 scripts/generate-connector-docs.py revolv3
-->

## Implemented Flows

| Flow (Service.RPC) | Category | gRPC Request Message |
|--------------------|----------|----------------------|
| [PaymentMethodAuthenticationService.Authenticate](#paymentmethodauthenticationserviceauthenticate) | Authentication | `PaymentMethodAuthenticationServiceAuthenticateRequest` |
| [PaymentService.Authorize](#paymentserviceauthorize) | Payments | `PaymentServiceAuthorizeRequest` |
| [PaymentService.Capture](#paymentservicecapture) | Payments | `PaymentServiceCaptureRequest` |
| [PaymentMethodAuthenticationService.PostAuthenticate](#paymentmethodauthenticationservicepostauthenticate) | Authentication | `PaymentMethodAuthenticationServicePostAuthenticateRequest` |
| [PaymentMethodAuthenticationService.PreAuthenticate](#paymentmethodauthenticationservicepreauthenticate) | Authentication | `PaymentMethodAuthenticationServicePreAuthenticateRequest` |
| [PaymentService.Refund](#paymentservicerefund) | Payments | `PaymentServiceRefundRequest` |
| [PaymentService.SetupRecurring](#paymentservicesetuprecurring) | Payments | `PaymentServiceSetupRecurringRequest` |
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
| Card | ✓ |
| Samsung Pay | — |

**Card (Raw PAN)**


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
    connector=sdk_config_pb2.Connector.REVOLV3,
    environment=sdk_config_pb2.Environment.SANDBOX,
    auth=sdk_config_pb2.ConnectorAuthType(
        header_key=sdk_config_pb2.HeaderKey(api_key="YOUR_API_KEY"),
    ),
)

request = ParseDict(
{
        "merchant_transaction_id": "probe_txn_001",  # Identification
        "amount": {  # The amount for the payment
            "minor_amount": 1000,  # Amount in minor units (e.g., 1000 = $10.00)
            "currency": "USD"  # ISO 4217 currency code (e.g., "USD", "EUR")
        },
        "payment_method": {  # Payment method to be used
            "card": {  # Generic card payment
                "card_number": "4111111111111111",  # Card Identification
                "card_exp_month": "03",
                "card_exp_year": "2030",
                "card_cvc": "737",
                "card_holder_name": "John Doe"  # Cardholder Information
            }
        },
        "capture_method": "AUTOMATIC",  # Method for capturing the payment
        "customer": {  # Customer Information
            "name": "John Doe",  # Customer's full name
            "email": "test@example.com",  # Customer's email address
            "id": "cust_probe_123",  # Internal customer ID
            "phone_number": "4155552671",  # Customer's phone number
            "phone_country_code": "+1"  # Customer's phone country code
        },
        "address": {  # Address Information
            "shipping_address": {
                "first_name": "John",  # Personal Information
                "last_name": "Doe",
                "line1": "123 Main St",  # Address Details
                "city": "Seattle",
                "state": "WA",
                "zip_code": "98101",
                "country_alpha2_code": "US",
                "email": "test@example.com",  # Contact Information
                "phone_number": "4155552671",
                "phone_country_code": "+1"
            },
            "billing_address": {
                "first_name": "John",  # Personal Information
                "last_name": "Doe",
                "line1": "123 Main St",  # Address Details
                "city": "Seattle",
                "state": "WA",
                "zip_code": "98101",
                "country_alpha2_code": "US",
                "email": "test@example.com",  # Contact Information
                "phone_number": "4155552671",
                "phone_country_code": "+1"
            }
        },
        "auth_type": "NO_THREE_DS",  # Authentication Details
        "return_url": "https://example.com/return",  # URLs for Redirection and Webhooks
        "webhook_url": "https://example.com/webhook",
        "complete_authorize_url": "https://example.com/complete",
        "browser_info": {
            "color_depth": 24,  # Display Information
            "screen_height": 900,
            "screen_width": 1440,
            "java_enabled": false,  # Browser Settings
            "java_script_enabled": true,
            "language": "en-US",
            "time_zone_offset_minutes": -480,
            "accept_header": "application/json",  # Browser Headers
            "user_agent": "Mozilla/5.0 (probe-bot)",
            "accept_language": "en-US,en;q=0.9",
            "ip_address": "1.2.3.4"  # Device Information
        }
    },
    payment_pb2.PaymentServiceAuthorizeRequest(),
)

async def main():
    client = PaymentClient(config)
    response = await client.authorize(request)
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
    connector: 'Revolv3',
    environment: 'sandbox',
    connector_auth_type: {
        header_key: { api_key: 'YOUR_API_KEY' },
    },
});

const request = {
    "merchant_transaction_id": "probe_txn_001",  // Identification
    "amount": {  // The amount for the payment
        "minor_amount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
        "currency": "USD"  // ISO 4217 currency code (e.g., "USD", "EUR")
    },
    "payment_method": {  // Payment method to be used
        "card": {  // Generic card payment
            "card_number": "4111111111111111",  // Card Identification
            "card_exp_month": "03",
            "card_exp_year": "2030",
            "card_cvc": "737",
            "card_holder_name": "John Doe"  // Cardholder Information
        }
    },
    "capture_method": "AUTOMATIC",  // Method for capturing the payment
    "customer": {  // Customer Information
        "name": "John Doe",  // Customer's full name
        "email": "test@example.com",  // Customer's email address
        "id": "cust_probe_123",  // Internal customer ID
        "phone_number": "4155552671",  // Customer's phone number
        "phone_country_code": "+1"  // Customer's phone country code
    },
    "address": {  // Address Information
        "shipping_address": {
            "first_name": "John",  // Personal Information
            "last_name": "Doe",
            "line1": "123 Main St",  // Address Details
            "city": "Seattle",
            "state": "WA",
            "zip_code": "98101",
            "country_alpha2_code": "US",
            "email": "test@example.com",  // Contact Information
            "phone_number": "4155552671",
            "phone_country_code": "+1"
        },
        "billing_address": {
            "first_name": "John",  // Personal Information
            "last_name": "Doe",
            "line1": "123 Main St",  // Address Details
            "city": "Seattle",
            "state": "WA",
            "zip_code": "98101",
            "country_alpha2_code": "US",
            "email": "test@example.com",  // Contact Information
            "phone_number": "4155552671",
            "phone_country_code": "+1"
        }
    },
    "auth_type": "NO_THREE_DS",  // Authentication Details
    "return_url": "https://example.com/return",  // URLs for Redirection and Webhooks
    "webhook_url": "https://example.com/webhook",
    "complete_authorize_url": "https://example.com/complete",
    "browser_info": {
        "color_depth": 24,  // Display Information
        "screen_height": 900,
        "screen_width": 1440,
        "java_enabled": false,  // Browser Settings
        "java_script_enabled": true,
        "language": "en-US",
        "time_zone_offset_minutes": -480,
        "accept_header": "application/json",  // Browser Headers
        "user_agent": "Mozilla/5.0 (probe-bot)",
        "accept_language": "en-US,en;q=0.9",
        "ip_address": "1.2.3.4"  // Device Information
    }
};

const response = await client.authorize(request);
console.log(response);
```

</details>

</td>
<td valign="top">

<details><summary>Kotlin</summary>

```kotlin
import payments.PaymentClient
import types.Payment.PaymentServiceAuthorizeRequest
import com.google.protobuf.util.JsonFormat

val config = ConnectorConfig.newBuilder()
    .setConnector("Revolv3")
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
        "merchant_transaction_id": "probe_txn_001",
        // The amount for the payment
        "amount": {
            // Amount in minor units (e.g., 1000 = $10.00)
            "minor_amount": 1000,
            // ISO 4217 currency code (e.g., "USD", "EUR")
            "currency": "USD"
        },
        // Payment method to be used
        "payment_method": {
            // Generic card payment
            "card": {
                // Card Identification
                "card_number": "4111111111111111",
                "card_exp_month": "03",
                "card_exp_year": "2030",
                "card_cvc": "737",
                // Cardholder Information
                "card_holder_name": "John Doe"
            }
        },
        // Method for capturing the payment
        "capture_method": "AUTOMATIC",
        // Customer Information
        "customer": {
            // Customer's full name
            "name": "John Doe",
            // Customer's email address
            "email": "test@example.com",
            // Internal customer ID
            "id": "cust_probe_123",
            // Customer's phone number
            "phone_number": "4155552671",
            // Customer's phone country code
            "phone_country_code": "+1"
        },
        // Address Information
        "address": {
            "shipping_address": {
                // Personal Information
                "first_name": "John",
                "last_name": "Doe",
                // Address Details
                "line1": "123 Main St",
                "city": "Seattle",
                "state": "WA",
                "zip_code": "98101",
                "country_alpha2_code": "US",
                // Contact Information
                "email": "test@example.com",
                "phone_number": "4155552671",
                "phone_country_code": "+1"
            },
            "billing_address": {
                // Personal Information
                "first_name": "John",
                "last_name": "Doe",
                // Address Details
                "line1": "123 Main St",
                "city": "Seattle",
                "state": "WA",
                "zip_code": "98101",
                "country_alpha2_code": "US",
                // Contact Information
                "email": "test@example.com",
                "phone_number": "4155552671",
                "phone_country_code": "+1"
            }
        },
        // Authentication Details
        "auth_type": "NO_THREE_DS",
        // URLs for Redirection and Webhooks
        "return_url": "https://example.com/return",
        "webhook_url": "https://example.com/webhook",
        "complete_authorize_url": "https://example.com/complete",
        "browser_info": {
            // Display Information
            "color_depth": 24,
            "screen_height": 900,
            "screen_width": 1440,
            // Browser Settings
            "java_enabled": false,
            "java_script_enabled": true,
            "language": "en-US",
            "time_zone_offset_minutes": -480,
            // Browser Headers
            "accept_header": "application/json",
            "user_agent": "Mozilla/5.0 (probe-bot)",
            "accept_language": "en-US,en;q=0.9",
            // Device Information
            "ip_address": "1.2.3.4"
        }
    }
""".trimIndent()

val builder = PaymentServiceAuthorizeRequest.newBuilder()
JsonFormat.parser().ignoringUnknownFields().merge(json, builder)
val request = builder.build()

val client = PaymentClient(config)
val response = client.authorize(request)
println(response)
```

</details>

</td>
<td valign="top">

<details><summary>Rust</summary>

```rust
use connector_service_sdk::{ConnectorClient, ConnectorConfig};
use grpc_api_types::payments::PaymentServiceAuthorizeRequest;

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ConnectorConfig {
        connector: "Revolv3".to_string(),
        environment: Environment::Sandbox,
        auth: ConnectorAuth::HeaderKey { api_key: "YOUR_API_KEY".into() },
        ..Default::default()
    };

    // Field names and descriptions from the proto definition above
    let request = PaymentServiceAuthorizeRequest {
        // merchant_transaction_id: todo!(),  // Identification
        // amount: todo!(),  // The amount for the payment
        // payment_method: todo!(),  // Payment method to be used
        // capture_method: todo!(),  // Method for capturing the payment
        // customer: todo!(),  // Customer Information
        // address: todo!(),  // Address Information
        // auth_type: todo!(),  // Authentication Details
        // return_url: todo!(),  // URLs for Redirection and Webhooks
        // webhook_url: todo!(),
        // complete_authorize_url: todo!(),
        // ...
        ..Default::default()
    };

    let client = ConnectorClient::new(config, None)?;
    let response = client.authorize(request, &Default::default(), None).await?;
    println!("{response:?}");
    Ok(())
}
```

</details>

</td>
</tr>
</table>

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
    connector=sdk_config_pb2.Connector.REVOLV3,
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
    connector: 'Revolv3',
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
    .setConnector("Revolv3")
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
        connector: "Revolv3".to_string(),
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
    connector=sdk_config_pb2.Connector.REVOLV3,
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
    connector: 'Revolv3',
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
    .setConnector("Revolv3")
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
        connector: "Revolv3".to_string(),
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

#### PaymentService.SetupRecurring

Setup a recurring payment instruction for future payments/ debits. This could be for SaaS subscriptions, monthly bill payments, insurance payments and similar use cases.

| | Message |
|---|---------|
| **Request** | `PaymentServiceSetupRecurringRequest` |
| **Response** | `PaymentServiceSetupRecurringResponse` |

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
    connector=sdk_config_pb2.Connector.REVOLV3,
    environment=sdk_config_pb2.Environment.SANDBOX,
    auth=sdk_config_pb2.ConnectorAuthType(
        header_key=sdk_config_pb2.HeaderKey(api_key="YOUR_API_KEY"),
    ),
)

request = ParseDict(
{
        "merchant_recurring_payment_id": "probe_mandate_001",  # Identification
        "amount": {  # Mandate Details
            "minor_amount": 0,  # Amount in minor units (e.g., 1000 = $10.00)
            "currency": "USD"  # ISO 4217 currency code (e.g., "USD", "EUR")
        },
        "payment_method": {
            "card": {  # Generic card payment
                "card_number": "4111111111111111",  # Card Identification
                "card_exp_month": "03",
                "card_exp_year": "2030",
                "card_cvc": "737",
                "card_holder_name": "John Doe"  # Cardholder Information
            }
        },
        "customer": {
            "name": "John Doe",  # Customer's full name
            "email": "test@example.com",  # Customer's email address
            "id": "cust_probe_123",  # Internal customer ID
            "phone_number": "4155552671",  # Customer's phone number
            "phone_country_code": "+1"  # Customer's phone country code
        },
        "address": {  # Address Information
            "billing_address": {
                "first_name": "John",  # Personal Information
                "last_name": "Doe",
                "line1": "123 Main St",  # Address Details
                "city": "Seattle",
                "state": "WA",
                "zip_code": "98101",
                "country_alpha2_code": "US",
                "email": "test@example.com",  # Contact Information
                "phone_number": "4155552671",
                "phone_country_code": "+1"
            }
        },
        "auth_type": "NO_THREE_DS",  # Type of authentication to be used
        "enrolled_for_3ds": false,  # Indicates if the customer is enrolled for 3D Secure
        "return_url": "https://example.com/mandate-return",  # URL to redirect after setup
        "setup_future_usage": "OFF_SESSION",  # Indicates future usage intention
        "request_incremental_authorization": false,  # Indicates if incremental authorization is requested
        "customer_acceptance": {  # Details of customer acceptance
            "acceptance_type": "OFFLINE",  # Type of acceptance (e.g., online, offline).
            "accepted_at": 0  # Timestamp when the acceptance was made (Unix timestamp, seconds since epoch).
        },
        "browser_info": {  # Information about the customer's browser
            "color_depth": 24,  # Display Information
            "screen_height": 900,
            "screen_width": 1440,
            "java_enabled": false,  # Browser Settings
            "java_script_enabled": true,
            "language": "en-US",
            "time_zone_offset_minutes": -480,
            "accept_header": "application/json",  # Browser Headers
            "user_agent": "Mozilla/5.0 (probe-bot)",
            "accept_language": "en-US,en;q=0.9",
            "ip_address": "1.2.3.4"  # Device Information
        }
    },
    payment_pb2.PaymentServiceSetupRecurringRequest(),
)

async def main():
    client = PaymentClient(config)
    response = await client.setup_recurring(request)
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
    connector: 'Revolv3',
    environment: 'sandbox',
    connector_auth_type: {
        header_key: { api_key: 'YOUR_API_KEY' },
    },
});

const request = {
    "merchant_recurring_payment_id": "probe_mandate_001",  // Identification
    "amount": {  // Mandate Details
        "minor_amount": 0,  // Amount in minor units (e.g., 1000 = $10.00)
        "currency": "USD"  // ISO 4217 currency code (e.g., "USD", "EUR")
    },
    "payment_method": {
        "card": {  // Generic card payment
            "card_number": "4111111111111111",  // Card Identification
            "card_exp_month": "03",
            "card_exp_year": "2030",
            "card_cvc": "737",
            "card_holder_name": "John Doe"  // Cardholder Information
        }
    },
    "customer": {
        "name": "John Doe",  // Customer's full name
        "email": "test@example.com",  // Customer's email address
        "id": "cust_probe_123",  // Internal customer ID
        "phone_number": "4155552671",  // Customer's phone number
        "phone_country_code": "+1"  // Customer's phone country code
    },
    "address": {  // Address Information
        "billing_address": {
            "first_name": "John",  // Personal Information
            "last_name": "Doe",
            "line1": "123 Main St",  // Address Details
            "city": "Seattle",
            "state": "WA",
            "zip_code": "98101",
            "country_alpha2_code": "US",
            "email": "test@example.com",  // Contact Information
            "phone_number": "4155552671",
            "phone_country_code": "+1"
        }
    },
    "auth_type": "NO_THREE_DS",  // Type of authentication to be used
    "enrolled_for_3ds": false,  // Indicates if the customer is enrolled for 3D Secure
    "return_url": "https://example.com/mandate-return",  // URL to redirect after setup
    "setup_future_usage": "OFF_SESSION",  // Indicates future usage intention
    "request_incremental_authorization": false,  // Indicates if incremental authorization is requested
    "customer_acceptance": {  // Details of customer acceptance
        "acceptance_type": "OFFLINE",  // Type of acceptance (e.g., online, offline).
        "accepted_at": 0  // Timestamp when the acceptance was made (Unix timestamp, seconds since epoch).
    },
    "browser_info": {  // Information about the customer's browser
        "color_depth": 24,  // Display Information
        "screen_height": 900,
        "screen_width": 1440,
        "java_enabled": false,  // Browser Settings
        "java_script_enabled": true,
        "language": "en-US",
        "time_zone_offset_minutes": -480,
        "accept_header": "application/json",  // Browser Headers
        "user_agent": "Mozilla/5.0 (probe-bot)",
        "accept_language": "en-US,en;q=0.9",
        "ip_address": "1.2.3.4"  // Device Information
    }
};

const response = await client.setupRecurring(request);
console.log(response);
```

</details>

</td>
<td valign="top">

<details><summary>Kotlin</summary>

```kotlin
import payments.PaymentClient
import types.Payment.PaymentServiceSetupRecurringRequest
import com.google.protobuf.util.JsonFormat

val config = ConnectorConfig.newBuilder()
    .setConnector("Revolv3")
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
        "merchant_recurring_payment_id": "probe_mandate_001",
        // Mandate Details
        "amount": {
            // Amount in minor units (e.g., 1000 = $10.00)
            "minor_amount": 0,
            // ISO 4217 currency code (e.g., "USD", "EUR")
            "currency": "USD"
        },
        "payment_method": {
            // Generic card payment
            "card": {
                // Card Identification
                "card_number": "4111111111111111",
                "card_exp_month": "03",
                "card_exp_year": "2030",
                "card_cvc": "737",
                // Cardholder Information
                "card_holder_name": "John Doe"
            }
        },
        "customer": {
            // Customer's full name
            "name": "John Doe",
            // Customer's email address
            "email": "test@example.com",
            // Internal customer ID
            "id": "cust_probe_123",
            // Customer's phone number
            "phone_number": "4155552671",
            // Customer's phone country code
            "phone_country_code": "+1"
        },
        // Address Information
        "address": {
            "billing_address": {
                // Personal Information
                "first_name": "John",
                "last_name": "Doe",
                // Address Details
                "line1": "123 Main St",
                "city": "Seattle",
                "state": "WA",
                "zip_code": "98101",
                "country_alpha2_code": "US",
                // Contact Information
                "email": "test@example.com",
                "phone_number": "4155552671",
                "phone_country_code": "+1"
            }
        },
        // Type of authentication to be used
        "auth_type": "NO_THREE_DS",
        // Indicates if the customer is enrolled for 3D Secure
        "enrolled_for_3ds": false,
        // URL to redirect after setup
        "return_url": "https://example.com/mandate-return",
        // Indicates future usage intention
        "setup_future_usage": "OFF_SESSION",
        // Indicates if incremental authorization is requested
        "request_incremental_authorization": false,
        // Details of customer acceptance
        "customer_acceptance": {
            // Type of acceptance (e.g., online, offline).
            "acceptance_type": "OFFLINE",
            // Timestamp when the acceptance was made (Unix timestamp, seconds since epoch).
            "accepted_at": 0
        },
        // Information about the customer's browser
        "browser_info": {
            // Display Information
            "color_depth": 24,
            "screen_height": 900,
            "screen_width": 1440,
            // Browser Settings
            "java_enabled": false,
            "java_script_enabled": true,
            "language": "en-US",
            "time_zone_offset_minutes": -480,
            // Browser Headers
            "accept_header": "application/json",
            "user_agent": "Mozilla/5.0 (probe-bot)",
            "accept_language": "en-US,en;q=0.9",
            // Device Information
            "ip_address": "1.2.3.4"
        }
    }
""".trimIndent()

val builder = PaymentServiceSetupRecurringRequest.newBuilder()
JsonFormat.parser().ignoringUnknownFields().merge(json, builder)
val request = builder.build()

val client = PaymentClient(config)
val response = client.setup_recurring(request)
println(response)
```

</details>

</td>
<td valign="top">

<details><summary>Rust</summary>

```rust
use connector_service_sdk::{ConnectorClient, ConnectorConfig};
use grpc_api_types::payments::PaymentServiceSetupRecurringRequest;

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ConnectorConfig {
        connector: "Revolv3".to_string(),
        environment: Environment::Sandbox,
        auth: ConnectorAuth::HeaderKey { api_key: "YOUR_API_KEY".into() },
        ..Default::default()
    };

    // Field names and descriptions from the proto definition above
    let request = PaymentServiceSetupRecurringRequest {
        // merchant_recurring_payment_id: todo!(),  // Identification
        // amount: todo!(),  // Mandate Details
        // payment_method: todo!(),
        // customer: todo!(),
        // address: todo!(),  // Address Information
        // auth_type: todo!(),  // Type of authentication to be used
        // enrolled_for_3ds: todo!(),  // Indicates if the customer is enrolled for 3D Secure
        // return_url: todo!(),  // URL to redirect after setup
        // setup_future_usage: todo!(),  // Indicates future usage intention
        // request_incremental_authorization: todo!(),  // Indicates if incremental authorization is requested
        // ...
        ..Default::default()
    };

    let client = ConnectorClient::new(config, None)?;
    let response = client.setup_recurring(request, &Default::default(), None).await?;
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
    connector=sdk_config_pb2.Connector.REVOLV3,
    environment=sdk_config_pb2.Environment.SANDBOX,
    auth=sdk_config_pb2.ConnectorAuthType(
        header_key=sdk_config_pb2.HeaderKey(api_key="YOUR_API_KEY"),
    ),
)

request = ParseDict(
{
        "merchant_void_id": "probe_void_001",  # Identification
        "connector_transaction_id": "probe_connector_txn_001"
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
    connector: 'Revolv3',
    environment: 'sandbox',
    connector_auth_type: {
        header_key: { api_key: 'YOUR_API_KEY' },
    },
});

const request = {
    "merchant_void_id": "probe_void_001",  // Identification
    "connector_transaction_id": "probe_connector_txn_001"
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
    .setConnector("Revolv3")
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
        "connector_transaction_id": "probe_connector_txn_001"
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
        connector: "Revolv3".to_string(),
        environment: Environment::Sandbox,
        auth: ConnectorAuth::HeaderKey { api_key: "YOUR_API_KEY".into() },
        ..Default::default()
    };

    // Field names and descriptions from the proto definition above
    let request = PaymentServiceVoidRequest {
        // merchant_void_id: todo!(),  // Identification
        // connector_transaction_id: todo!(),
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

<!-- TODO: Add sample payload for `authenticate` in `scripts/connector-annotations/revolv3.yaml` -->

#### PaymentMethodAuthenticationService.PostAuthenticate

Validate authentication results with the issuing bank. Processes bank's authentication decision to determine if payment can proceed.

| | Message |
|---|---------|
| **Request** | `PaymentMethodAuthenticationServicePostAuthenticateRequest` |
| **Response** | `PaymentMethodAuthenticationServicePostAuthenticateResponse` |

<!-- TODO: Add sample payload for `post_authenticate` in `scripts/connector-annotations/revolv3.yaml` -->

#### PaymentMethodAuthenticationService.PreAuthenticate

Initiate 3DS flow before payment authorization. Collects device data and prepares authentication context for frictionless or challenge-based verification.

| | Message |
|---|---------|
| **Request** | `PaymentMethodAuthenticationServicePreAuthenticateRequest` |
| **Response** | `PaymentMethodAuthenticationServicePreAuthenticateResponse` |

<!-- TODO: Add sample payload for `pre_authenticate` in `scripts/connector-annotations/revolv3.yaml` -->
