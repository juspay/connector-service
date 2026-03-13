# PlacetoPay

<!--
This file is auto-generated. Do not edit by hand.
Source: data/field_probe/placetopay.json
Regenerate: python3 scripts/generate-connector-docs.py placetopay
-->

## Implemented Flows

| Flow (Service.RPC) | Category | gRPC Request Message |
|--------------------|----------|----------------------|
| [PaymentMethodAuthenticationService.Authenticate](#paymentmethodauthenticationserviceauthenticate) | Authentication | `PaymentMethodAuthenticationServiceAuthenticateRequest` |
| [PaymentService.Authorize](#paymentserviceauthorize) | Payments | `PaymentServiceAuthorizeRequest` |
| [PaymentService.Capture](#paymentservicecapture) | Payments | `PaymentServiceCaptureRequest` |
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
    connector=sdk_config_pb2.Connector.PLACETOPAY,
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
        },
        "description": "Probe payment"
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
    connector: 'Placetopay',
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
    },
    "description": "Probe payment"
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
    .setConnector("Placetopay")
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
        },
        "description": "Probe payment"
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
        connector: "Placetopay".to_string(),
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

<!-- TODO: Add sample payload for `capture` in `scripts/connector-annotations/placetopay.yaml` -->

#### PaymentService.Get

Retrieve current payment status from the payment processor. Enables synchronization between your system and payment processors for accurate state tracking.

| | Message |
|---|---------|
| **Request** | `PaymentServiceGetRequest` |
| **Response** | `PaymentServiceGetResponse` |

<!-- TODO: Add sample payload for `get` in `scripts/connector-annotations/placetopay.yaml` -->

#### PaymentService.Refund

Initiate a refund to customer's payment method. Returns funds for returns, cancellations, or service adjustments after original payment.

| | Message |
|---|---------|
| **Request** | `PaymentServiceRefundRequest` |
| **Response** | `RefundResponse` |

<!-- TODO: Add sample payload for `refund` in `scripts/connector-annotations/placetopay.yaml` -->

#### PaymentService.Void

Cancel an authorized payment before capture. Releases held funds back to customer, typically used when orders are cancelled or abandoned.

| | Message |
|---|---------|
| **Request** | `PaymentServiceVoidRequest` |
| **Response** | `PaymentServiceVoidResponse` |

<!-- TODO: Add sample payload for `void` in `scripts/connector-annotations/placetopay.yaml` -->

### Authentication

#### PaymentMethodAuthenticationService.Authenticate

Execute 3DS challenge or frictionless verification. Authenticates customer via bank challenge or behind-the-scenes verification for fraud prevention.

| | Message |
|---|---------|
| **Request** | `PaymentMethodAuthenticationServiceAuthenticateRequest` |
| **Response** | `PaymentMethodAuthenticationServiceAuthenticateResponse` |

<!-- TODO: Add sample payload for `authenticate` in `scripts/connector-annotations/placetopay.yaml` -->

#### PaymentMethodAuthenticationService.PostAuthenticate

Validate authentication results with the issuing bank. Processes bank's authentication decision to determine if payment can proceed.

| | Message |
|---|---------|
| **Request** | `PaymentMethodAuthenticationServicePostAuthenticateRequest` |
| **Response** | `PaymentMethodAuthenticationServicePostAuthenticateResponse` |

<!-- TODO: Add sample payload for `post_authenticate` in `scripts/connector-annotations/placetopay.yaml` -->

#### PaymentMethodAuthenticationService.PreAuthenticate

Initiate 3DS flow before payment authorization. Collects device data and prepares authentication context for frictionless or challenge-based verification.

| | Message |
|---|---------|
| **Request** | `PaymentMethodAuthenticationServicePreAuthenticateRequest` |
| **Response** | `PaymentMethodAuthenticationServicePreAuthenticateResponse` |

<!-- TODO: Add sample payload for `pre_authenticate` in `scripts/connector-annotations/placetopay.yaml` -->
