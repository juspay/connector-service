# Authorize.net

<!--
This file is auto-generated. Do not edit by hand.
Source: data/field_probe/authorizedotnet.json
Regenerate: python3 scripts/generate-connector-docs.py authorizedotnet
-->

## Implemented Flows

| Flow (Service.RPC) | Category | gRPC Request Message |
|--------------------|----------|----------------------|
| [PaymentMethodAuthenticationService.Authenticate](#paymentmethodauthenticationserviceauthenticate) | Authentication | `PaymentMethodAuthenticationServiceAuthenticateRequest` |
| [PaymentService.Authorize](#paymentserviceauthorize) | Payments | `PaymentServiceAuthorizeRequest` |
| [PaymentService.Capture](#paymentservicecapture) | Payments | `PaymentServiceCaptureRequest` |
| [CustomerService.Create](#customerservicecreate) | Customers | `CustomerServiceCreateRequest` |
| [PaymentService.Get](#paymentserviceget) | Payments | `PaymentServiceGetRequest` |
| [PaymentMethodAuthenticationService.PostAuthenticate](#paymentmethodauthenticationservicepostauthenticate) | Authentication | `PaymentMethodAuthenticationServicePostAuthenticateRequest` |
| [PaymentMethodAuthenticationService.PreAuthenticate](#paymentmethodauthenticationservicepreauthenticate) | Authentication | `PaymentMethodAuthenticationServicePreAuthenticateRequest` |
| [RecurringPaymentService.Charge](#recurringpaymentservicecharge) | Mandates | `RecurringPaymentServiceChargeRequest` |
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
| Google Pay | — |
| Apple Pay | — |
| ACH | ✓ |
| iDEAL | — |
| PayPal | — |
| BLIK | — |
| Klarna | — |
| Afterpay | — |
| UPI | — |
| Affirm | — |
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
    connector=sdk_config_pb2.Connector.AUTHORIZEDOTNET,
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
    connector: 'Authorizedotnet',
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
    .setConnector("Authorizedotnet")
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
        connector: "Authorizedotnet".to_string(),
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

**ACH Direct Debit**


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
    connector=sdk_config_pb2.Connector.AUTHORIZEDOTNET,
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
            "ach": {  # Ach - Automated Clearing House
                "account_number": "000123456789",  # Account number for ach bank debit payment
                "routing_number": "110000000",  # Routing number for ach bank debit payment
                "bank_account_holder_name": "John Doe"  # Bank account holder name
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
    connector: 'Authorizedotnet',
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
        "ach": {  // Ach - Automated Clearing House
            "account_number": "000123456789",  // Account number for ach bank debit payment
            "routing_number": "110000000",  // Routing number for ach bank debit payment
            "bank_account_holder_name": "John Doe"  // Bank account holder name
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
    .setConnector("Authorizedotnet")
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
            // Ach - Automated Clearing House
            "ach": {
                // Account number for ach bank debit payment
                "account_number": "000123456789",
                // Routing number for ach bank debit payment
                "routing_number": "110000000",
                // Bank account holder name
                "bank_account_holder_name": "John Doe"
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
        connector: "Authorizedotnet".to_string(),
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
    connector=sdk_config_pb2.Connector.AUTHORIZEDOTNET,
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
    connector: 'Authorizedotnet',
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
    .setConnector("Authorizedotnet")
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
        connector: "Authorizedotnet".to_string(),
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
    connector=sdk_config_pb2.Connector.AUTHORIZEDOTNET,
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
    connector: 'Authorizedotnet',
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
    .setConnector("Authorizedotnet")
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
        connector: "Authorizedotnet".to_string(),
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
    connector=sdk_config_pb2.Connector.AUTHORIZEDOTNET,
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
    connector: 'Authorizedotnet',
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
    .setConnector("Authorizedotnet")
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
        connector: "Authorizedotnet".to_string(),
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

<!-- TODO: Add sample payload for `setup_recurring` in `scripts/connector-annotations/authorizedotnet.yaml` -->

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
    connector=sdk_config_pb2.Connector.AUTHORIZEDOTNET,
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
    connector: 'Authorizedotnet',
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
    .setConnector("Authorizedotnet")
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
        connector: "Authorizedotnet".to_string(),
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

### Mandates

#### RecurringPaymentService.Charge

Charge using an existing stored recurring payment instruction. Processes repeat payments for subscriptions or recurring billing without collecting payment details.

| | Message |
|---|---------|
| **Request** | `RecurringPaymentServiceChargeRequest` |
| **Response** | `RecurringPaymentServiceChargeResponse` |

<!-- TODO: Add sample payload for `recurring_charge` in `scripts/connector-annotations/authorizedotnet.yaml` -->

### Customers

#### CustomerService.Create

Create customer record in the payment processor system. Stores customer details for future payment operations without re-sending personal information.

| | Message |
|---|---------|
| **Request** | `CustomerServiceCreateRequest` |
| **Response** | `CustomerServiceCreateResponse` |

**Example Request**


<table>
<tr><td><b>Python</b></td><td><b>JavaScript</b></td><td><b>Kotlin</b></td><td><b>Rust</b></td></tr>
<tr>
<td valign="top">

<details><summary>Python</summary>

```python
import asyncio
from google.protobuf.json_format import ParseDict
from payments import CustomerClient
from payments.generated import sdk_config_pb2, payment_pb2

config = sdk_config_pb2.ConnectorConfig(
    connector=sdk_config_pb2.Connector.AUTHORIZEDOTNET,
    environment=sdk_config_pb2.Environment.SANDBOX,
    auth=sdk_config_pb2.ConnectorAuthType(
        header_key=sdk_config_pb2.HeaderKey(api_key="YOUR_API_KEY"),
    ),
)

request = ParseDict(
{
        "customer_name": "John Doe",  # Name of the customer
        "email": "test@example.com",  # Email address of the customer
        "phone_number": "4155552671",  # Phone number of the customer
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
        }
    },
    payment_pb2.CustomerServiceCreateRequest(),
)

async def main():
    client = CustomerClient(config)
    response = await client.create_customer(request)
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
    connector: 'Authorizedotnet',
    environment: 'sandbox',
    connector_auth_type: {
        header_key: { api_key: 'YOUR_API_KEY' },
    },
});

const request = {
    "customer_name": "John Doe",  // Name of the customer
    "email": "test@example.com",  // Email address of the customer
    "phone_number": "4155552671",  // Phone number of the customer
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
    }
};

const response = await client.createCustomer(request);
console.log(response);
```

</details>

</td>
<td valign="top">

<details><summary>Kotlin</summary>

```kotlin
import payments.CustomerClient
import types.Payment.CustomerServiceCreateRequest
import com.google.protobuf.util.JsonFormat

val config = ConnectorConfig.newBuilder()
    .setConnector("Authorizedotnet")
    .setEnvironment(Environment.SANDBOX)
    .setAuth(
        ConnectorAuthType.newBuilder()
            .setHeaderKey(HeaderKey.newBuilder().setApiKey("YOUR_API_KEY"))
    )
    .build()

// JSON with field descriptions (remove comment lines before parsing)
val json = """
{
        // Name of the customer
        "customer_name": "John Doe",
        // Email address of the customer
        "email": "test@example.com",
        // Phone number of the customer
        "phone_number": "4155552671",
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
        }
    }
""".trimIndent()

val builder = CustomerServiceCreateRequest.newBuilder()
JsonFormat.parser().ignoringUnknownFields().merge(json, builder)
val request = builder.build()

val client = CustomerClient(config)
val response = client.create_customer(request)
println(response)
```

</details>

</td>
<td valign="top">

<details><summary>Rust</summary>

```rust
use connector_service_sdk::{ConnectorClient, ConnectorConfig};
use grpc_api_types::payments::CustomerServiceCreateRequest;

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ConnectorConfig {
        connector: "Authorizedotnet".to_string(),
        environment: Environment::Sandbox,
        auth: ConnectorAuth::HeaderKey { api_key: "YOUR_API_KEY".into() },
        ..Default::default()
    };

    // Field names and descriptions from the proto definition above
    let request = CustomerServiceCreateRequest {
        // customer_name: todo!(),  // Name of the customer
        // email: todo!(),  // Email address of the customer
        // phone_number: todo!(),  // Phone number of the customer
        // address: todo!(),  // Address Information
        ..Default::default()
    };

    let client = ConnectorClient::new(config, None)?;
    let response = client.create_customer(request, &Default::default(), None).await?;
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

<!-- TODO: Add sample payload for `authenticate` in `scripts/connector-annotations/authorizedotnet.yaml` -->

#### PaymentMethodAuthenticationService.PostAuthenticate

Validate authentication results with the issuing bank. Processes bank's authentication decision to determine if payment can proceed.

| | Message |
|---|---------|
| **Request** | `PaymentMethodAuthenticationServicePostAuthenticateRequest` |
| **Response** | `PaymentMethodAuthenticationServicePostAuthenticateResponse` |

<!-- TODO: Add sample payload for `post_authenticate` in `scripts/connector-annotations/authorizedotnet.yaml` -->

#### PaymentMethodAuthenticationService.PreAuthenticate

Initiate 3DS flow before payment authorization. Collects device data and prepares authentication context for frictionless or challenge-based verification.

| | Message |
|---|---------|
| **Request** | `PaymentMethodAuthenticationServicePreAuthenticateRequest` |
| **Response** | `PaymentMethodAuthenticationServicePreAuthenticateResponse` |

<!-- TODO: Add sample payload for `pre_authenticate` in `scripts/connector-annotations/authorizedotnet.yaml` -->
