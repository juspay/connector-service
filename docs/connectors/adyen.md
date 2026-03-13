# Adyen

<!--
This file is auto-generated. Do not edit by hand.
Source: data/field_probe/adyen.json
Regenerate: python3 scripts/generate-connector-docs.py adyen
-->

## Overview

Adyen is a global payment platform supporting 250+ payment methods across 40+ currencies.
It operates at PCI DSS Level 1 and supports advanced fraud detection via RevenueProtect.

| Attribute | Value |
|-----------|-------|
| Connector ID | `ADYEN` |
| Regions | Global |
| Currencies | 40+ |
| API | Adyen Checkout API v69+ |
| Amount Format | Minor units (cents) |

## Required Credentials

| Field | Description |
|-------|-------------|
| `api_key` | Adyen API Key (`AQE...`) |
| `merchant_account` | Adyen Merchant Account name (e.g. `YourCompanyECOM`) |
| `hmac_key` | HMAC key for webhook notification verification |

## Implemented Flows

| Flow (Service.RPC) | Category | gRPC Request Message |
|--------------------|----------|----------------------|
| [PaymentMethodAuthenticationService.Authenticate](#paymentmethodauthenticationserviceauthenticate) | Authentication | `PaymentMethodAuthenticationServiceAuthenticateRequest` |
| [PaymentService.Authorize](#paymentserviceauthorize) | Payments | `PaymentServiceAuthorizeRequest` |
| [PaymentService.Capture](#paymentservicecapture) | Payments | `PaymentServiceCaptureRequest` |
| [DisputeService.Accept](#disputeserviceaccept) | Disputes | `DisputeServiceAcceptRequest` |
| [DisputeService.Defend](#disputeservicedefend) | Disputes | `DisputeServiceDefendRequest` |
| [DisputeService.SubmitEvidence](#disputeservicesubmitevidence) | Disputes | `DisputeServiceSubmitEvidenceRequest` |
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
| Google Pay | ✓ |
| Apple Pay | ✓ |
| SEPA | ✓ |
| BACS | ✓ |
| ACH | ✓ |
| iDEAL | ✓ |
| BLIK | ✓ |
| Klarna | ✓ |
| Afterpay | ✓ |
| Affirm | ✓ |
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
    connector=sdk_config_pb2.Connector.ADYEN,
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
    connector: 'Adyen',
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
    .setConnector("Adyen")
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
        connector: "Adyen".to_string(),
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

**Google Pay**


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
    connector=sdk_config_pb2.Connector.ADYEN,
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
            "google_pay": {  # Google Pay
                "type": "CARD",  # Type of payment method
                "description": "Visa 1111",  # User-facing description of the payment method
                "info": {
                    "card_network": "VISA",  # Card network name
                    "card_details": "1111"  # Card details (usually last 4 digits)
                },
                "tokenization_data": {
                    "encrypted_data": {  # Encrypted Google Pay payment data
                        "token": "{\"version\":\"ECv2\",\"signature\":\"<sig>\",\"intermediateSigningKey\":{\"signedKey\":\"<signed_key>\",\"signatures\":[\"<sig>\"]},\"signedMessage\":\"<signed_message>\"}",  # Token generated for the wallet
                        "token_type": "PAYMENT_GATEWAY"  # The type of the token
                    }
                }
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
    connector: 'Adyen',
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
        "google_pay": {  // Google Pay
            "type": "CARD",  // Type of payment method
            "description": "Visa 1111",  // User-facing description of the payment method
            "info": {
                "card_network": "VISA",  // Card network name
                "card_details": "1111"  // Card details (usually last 4 digits)
            },
            "tokenization_data": {
                "encrypted_data": {  // Encrypted Google Pay payment data
                    "token": "{\"version\":\"ECv2\",\"signature\":\"<sig>\",\"intermediateSigningKey\":{\"signedKey\":\"<signed_key>\",\"signatures\":[\"<sig>\"]},\"signedMessage\":\"<signed_message>\"}",  // Token generated for the wallet
                    "token_type": "PAYMENT_GATEWAY"  // The type of the token
                }
            }
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
    .setConnector("Adyen")
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
            // Google Pay
            "google_pay": {
                // Type of payment method
                "type": "CARD",
                // User-facing description of the payment method
                "description": "Visa 1111",
                "info": {
                    // Card network name
                    "card_network": "VISA",
                    // Card details (usually last 4 digits)
                    "card_details": "1111"
                },
                "tokenization_data": {
                    // Encrypted Google Pay payment data
                    "encrypted_data": {
                        // Token generated for the wallet
                        "token": "{\"version\":\"ECv2\",\"signature\":\"<sig>\",\"intermediateSigningKey\":{\"signedKey\":\"<signed_key>\",\"signatures\":[\"<sig>\"]},\"signedMessage\":\"<signed_message>\"}",
                        // The type of the token
                        "token_type": "PAYMENT_GATEWAY"
                    }
                }
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
        connector: "Adyen".to_string(),
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

**Apple Pay**


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
    connector=sdk_config_pb2.Connector.ADYEN,
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
            "apple_pay": {  # Apple Pay
                "payment_data": {
                    "encrypted_data": "<base64_encoded_apple_pay_payment_token>"  # Encrypted Apple Pay payment data as string
                },
                "payment_method": {
                    "display_name": "Visa 1111",
                    "network": "Visa",
                    "type": "debit"
                },
                "transaction_identifier": "<apple_pay_transaction_identifier>"  # Transaction identifier
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
    connector: 'Adyen',
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
        "apple_pay": {  // Apple Pay
            "payment_data": {
                "encrypted_data": "<base64_encoded_apple_pay_payment_token>"  // Encrypted Apple Pay payment data as string
            },
            "payment_method": {
                "display_name": "Visa 1111",
                "network": "Visa",
                "type": "debit"
            },
            "transaction_identifier": "<apple_pay_transaction_identifier>"  // Transaction identifier
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
    .setConnector("Adyen")
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
            // Apple Pay
            "apple_pay": {
                "payment_data": {
                    // Encrypted Apple Pay payment data as string
                    "encrypted_data": "<base64_encoded_apple_pay_payment_token>"
                },
                "payment_method": {
                    "display_name": "Visa 1111",
                    "network": "Visa",
                    "type": "debit"
                },
                // Transaction identifier
                "transaction_identifier": "<apple_pay_transaction_identifier>"
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
        connector: "Adyen".to_string(),
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

**SEPA Direct Debit**


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
    connector=sdk_config_pb2.Connector.ADYEN,
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
            "sepa": {  # Sepa - Single Euro Payments Area direct debit
                "iban": "DE89370400440532013000",  # International bank account number (iban) for SEPA
                "bank_account_holder_name": "John Doe"  # Owner name for bank debit
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
    connector: 'Adyen',
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
        "sepa": {  // Sepa - Single Euro Payments Area direct debit
            "iban": "DE89370400440532013000",  // International bank account number (iban) for SEPA
            "bank_account_holder_name": "John Doe"  // Owner name for bank debit
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
    .setConnector("Adyen")
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
            // Sepa - Single Euro Payments Area direct debit
            "sepa": {
                // International bank account number (iban) for SEPA
                "iban": "DE89370400440532013000",
                // Owner name for bank debit
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
        connector: "Adyen".to_string(),
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

**BACS Direct Debit**


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
    connector=sdk_config_pb2.Connector.ADYEN,
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
            "bacs": {  # Bacs - Bankers' Automated Clearing Services
                "account_number": "55779911",  # Account number for Bacs payment method
                "sort_code": "200000",  # Sort code for Bacs payment method
                "bank_account_holder_name": "John Doe"  # Holder name for bank debit
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
    connector: 'Adyen',
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
        "bacs": {  // Bacs - Bankers' Automated Clearing Services
            "account_number": "55779911",  // Account number for Bacs payment method
            "sort_code": "200000",  // Sort code for Bacs payment method
            "bank_account_holder_name": "John Doe"  // Holder name for bank debit
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
    .setConnector("Adyen")
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
            // Bacs - Bankers' Automated Clearing Services
            "bacs": {
                // Account number for Bacs payment method
                "account_number": "55779911",
                // Sort code for Bacs payment method
                "sort_code": "200000",
                // Holder name for bank debit
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
        connector: "Adyen".to_string(),
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
    connector=sdk_config_pb2.Connector.ADYEN,
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
    connector: 'Adyen',
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
    .setConnector("Adyen")
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
        connector: "Adyen".to_string(),
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

**iDEAL**


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
    connector=sdk_config_pb2.Connector.ADYEN,
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
            "ideal": {
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
    connector: 'Adyen',
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
        "ideal": {
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
    .setConnector("Adyen")
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
            "ideal": {
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
        connector: "Adyen".to_string(),
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

**BLIK**


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
    connector=sdk_config_pb2.Connector.ADYEN,
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
            "blik": {
                "blik_code": "777124"
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
    connector: 'Adyen',
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
        "blik": {
            "blik_code": "777124"
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
    .setConnector("Adyen")
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
            "blik": {
                "blik_code": "777124"
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
        connector: "Adyen".to_string(),
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

**Klarna**


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
    connector=sdk_config_pb2.Connector.ADYEN,
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
            "klarna": {  # Klarna - Swedish BNPL service
            }
        },
        "capture_method": "AUTOMATIC",  # Method for capturing the payment
        "customer": {  # Customer Information
            "name": "John Doe",  # Customer's full name
            "email": "test@example.com",  # Customer's email address
            "id": "cust_probe_123",  # Internal customer ID
            "connector_customer_id": "probe_cust_connector_001",  # Customer ID in the connector system
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
    connector: 'Adyen',
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
        "klarna": {  // Klarna - Swedish BNPL service
        }
    },
    "capture_method": "AUTOMATIC",  // Method for capturing the payment
    "customer": {  // Customer Information
        "name": "John Doe",  // Customer's full name
        "email": "test@example.com",  // Customer's email address
        "id": "cust_probe_123",  // Internal customer ID
        "connector_customer_id": "probe_cust_connector_001",  // Customer ID in the connector system
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
    .setConnector("Adyen")
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
            // Klarna - Swedish BNPL service
            "klarna": {
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
            // Customer ID in the connector system
            "connector_customer_id": "probe_cust_connector_001",
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
        connector: "Adyen".to_string(),
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

**Afterpay / Clearpay**


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
    connector=sdk_config_pb2.Connector.ADYEN,
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
            "afterpay_clearpay": {  # Afterpay/Clearpay - BNPL service
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
    connector: 'Adyen',
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
        "afterpay_clearpay": {  // Afterpay/Clearpay - BNPL service
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
    .setConnector("Adyen")
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
            // Afterpay/Clearpay - BNPL service
            "afterpay_clearpay": {
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
        connector: "Adyen".to_string(),
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
    connector=sdk_config_pb2.Connector.ADYEN,
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
    connector: 'Adyen',
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
    .setConnector("Adyen")
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
        connector: "Adyen".to_string(),
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

<!-- TODO: Add sample payload for `get` in `scripts/connector-annotations/adyen.yaml` -->

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
    connector=sdk_config_pb2.Connector.ADYEN,
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
    connector: 'Adyen',
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
    .setConnector("Adyen")
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
        connector: "Adyen".to_string(),
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
    connector=sdk_config_pb2.Connector.ADYEN,
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
    connector: 'Adyen',
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
    .setConnector("Adyen")
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
        connector: "Adyen".to_string(),
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
    connector=sdk_config_pb2.Connector.ADYEN,
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
    connector: 'Adyen',
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
    .setConnector("Adyen")
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
        connector: "Adyen".to_string(),
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

**Example Request**


<table>
<tr><td><b>Python</b></td><td><b>JavaScript</b></td><td><b>Kotlin</b></td><td><b>Rust</b></td></tr>
<tr>
<td valign="top">

<details><summary>Python</summary>

```python
import asyncio
from google.protobuf.json_format import ParseDict
from payments import RecurringPaymentClient
from payments.generated import sdk_config_pb2, payment_pb2

config = sdk_config_pb2.ConnectorConfig(
    connector=sdk_config_pb2.Connector.ADYEN,
    environment=sdk_config_pb2.Environment.SANDBOX,
    auth=sdk_config_pb2.ConnectorAuthType(
        header_key=sdk_config_pb2.HeaderKey(api_key="YOUR_API_KEY"),
    ),
)

request = ParseDict(
{
        "connector_recurring_payment_id": {  # Reference to existing mandate
            "mandate_id_type": {
                "connector_mandate_id": "probe_mandate_123"
            }
        },
        "amount": {  # Amount Information
            "minor_amount": 1000,  # Amount in minor units (e.g., 1000 = $10.00)
            "currency": "USD"  # ISO 4217 currency code (e.g., "USD", "EUR")
        },
        "payment_method": {  # Optional payment Method Information (for network transaction flows)
            "token": "probe_pm_token"  # Payment tokens
        },
        "return_url": "https://example.com/recurring-return",
        "connector_customer_id": "probe_cust_connector_001",
        "payment_method_type": "PAY_PAL",
        "off_session": true  # Behavioral Flags and Preferences
    },
    payment_pb2.RecurringPaymentServiceChargeRequest(),
)

async def main():
    client = RecurringPaymentClient(config)
    response = await client.recurring_charge(request)
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
    connector: 'Adyen',
    environment: 'sandbox',
    connector_auth_type: {
        header_key: { api_key: 'YOUR_API_KEY' },
    },
});

const request = {
    "connector_recurring_payment_id": {  // Reference to existing mandate
        "mandate_id_type": {
            "connector_mandate_id": "probe_mandate_123"
        }
    },
    "amount": {  // Amount Information
        "minor_amount": 1000,  // Amount in minor units (e.g., 1000 = $10.00)
        "currency": "USD"  // ISO 4217 currency code (e.g., "USD", "EUR")
    },
    "payment_method": {  // Optional payment Method Information (for network transaction flows)
        "token": "probe_pm_token"  // Payment tokens
    },
    "return_url": "https://example.com/recurring-return",
    "connector_customer_id": "probe_cust_connector_001",
    "payment_method_type": "PAY_PAL",
    "off_session": true  // Behavioral Flags and Preferences
};

const response = await client.recurringCharge(request);
console.log(response);
```

</details>

</td>
<td valign="top">

<details><summary>Kotlin</summary>

```kotlin
import payments.RecurringPaymentClient
import types.Payment.RecurringPaymentServiceChargeRequest
import com.google.protobuf.util.JsonFormat

val config = ConnectorConfig.newBuilder()
    .setConnector("Adyen")
    .setEnvironment(Environment.SANDBOX)
    .setAuth(
        ConnectorAuthType.newBuilder()
            .setHeaderKey(HeaderKey.newBuilder().setApiKey("YOUR_API_KEY"))
    )
    .build()

// JSON with field descriptions (remove comment lines before parsing)
val json = """
{
        // Reference to existing mandate
        "connector_recurring_payment_id": {
            "mandate_id_type": {
                "connector_mandate_id": "probe_mandate_123"
            }
        },
        // Amount Information
        "amount": {
            // Amount in minor units (e.g., 1000 = $10.00)
            "minor_amount": 1000,
            // ISO 4217 currency code (e.g., "USD", "EUR")
            "currency": "USD"
        },
        // Optional payment Method Information (for network transaction flows)
        "payment_method": {
            // Payment tokens
            "token": "probe_pm_token"
        },
        "return_url": "https://example.com/recurring-return",
        "connector_customer_id": "probe_cust_connector_001",
        "payment_method_type": "PAY_PAL",
        // Behavioral Flags and Preferences
        "off_session": true
    }
""".trimIndent()

val builder = RecurringPaymentServiceChargeRequest.newBuilder()
JsonFormat.parser().ignoringUnknownFields().merge(json, builder)
val request = builder.build()

val client = RecurringPaymentClient(config)
val response = client.recurring_charge(request)
println(response)
```

</details>

</td>
<td valign="top">

<details><summary>Rust</summary>

```rust
use connector_service_sdk::{ConnectorClient, ConnectorConfig};
use grpc_api_types::payments::RecurringPaymentServiceChargeRequest;

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ConnectorConfig {
        connector: "Adyen".to_string(),
        environment: Environment::Sandbox,
        auth: ConnectorAuth::HeaderKey { api_key: "YOUR_API_KEY".into() },
        ..Default::default()
    };

    // Field names and descriptions from the proto definition above
    let request = RecurringPaymentServiceChargeRequest {
        // connector_recurring_payment_id: todo!(),  // Reference to existing mandate
        // amount: todo!(),  // Amount Information
        // payment_method: todo!(),  // Optional payment Method Information (for network transaction flows)
        // return_url: todo!(),
        // connector_customer_id: todo!(),
        // payment_method_type: todo!(),
        // off_session: todo!(),  // Behavioral Flags and Preferences
        ..Default::default()
    };

    let client = ConnectorClient::new(config, None)?;
    let response = client.recurring_charge(request, &Default::default(), None).await?;
    println!("{response:?}");
    Ok(())
}
```

</details>

</td>
</tr>
</table>

### Disputes

#### DisputeService.Accept

Concede dispute and accepts chargeback loss. Acknowledges liability and stops dispute defense process when evidence is insufficient.

| | Message |
|---|---------|
| **Request** | `DisputeServiceAcceptRequest` |
| **Response** | `DisputeServiceAcceptResponse` |

**Example Request**


<table>
<tr><td><b>Python</b></td><td><b>JavaScript</b></td><td><b>Kotlin</b></td><td><b>Rust</b></td></tr>
<tr>
<td valign="top">

<details><summary>Python</summary>

```python
import asyncio
from google.protobuf.json_format import ParseDict
from payments import DisputeClient
from payments.generated import sdk_config_pb2, payment_pb2

config = sdk_config_pb2.ConnectorConfig(
    connector=sdk_config_pb2.Connector.ADYEN,
    environment=sdk_config_pb2.Environment.SANDBOX,
    auth=sdk_config_pb2.ConnectorAuthType(
        header_key=sdk_config_pb2.HeaderKey(api_key="YOUR_API_KEY"),
    ),
)

request = ParseDict(
{
        "merchant_dispute_id": "probe_dispute_001",  # Identification
        "connector_transaction_id": "probe_txn_001",
        "dispute_id": "probe_dispute_id_001"
    },
    payment_pb2.DisputeServiceAcceptRequest(),
)

async def main():
    client = DisputeClient(config)
    response = await client.dispute_accept(request)
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
    connector: 'Adyen',
    environment: 'sandbox',
    connector_auth_type: {
        header_key: { api_key: 'YOUR_API_KEY' },
    },
});

const request = {
    "merchant_dispute_id": "probe_dispute_001",  // Identification
    "connector_transaction_id": "probe_txn_001",
    "dispute_id": "probe_dispute_id_001"
};

const response = await client.disputeAccept(request);
console.log(response);
```

</details>

</td>
<td valign="top">

<details><summary>Kotlin</summary>

```kotlin
import payments.DisputeClient
import types.Payment.DisputeServiceAcceptRequest
import com.google.protobuf.util.JsonFormat

val config = ConnectorConfig.newBuilder()
    .setConnector("Adyen")
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
        "merchant_dispute_id": "probe_dispute_001",
        "connector_transaction_id": "probe_txn_001",
        "dispute_id": "probe_dispute_id_001"
    }
""".trimIndent()

val builder = DisputeServiceAcceptRequest.newBuilder()
JsonFormat.parser().ignoringUnknownFields().merge(json, builder)
val request = builder.build()

val client = DisputeClient(config)
val response = client.dispute_accept(request)
println(response)
```

</details>

</td>
<td valign="top">

<details><summary>Rust</summary>

```rust
use connector_service_sdk::{ConnectorClient, ConnectorConfig};
use grpc_api_types::payments::DisputeServiceAcceptRequest;

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ConnectorConfig {
        connector: "Adyen".to_string(),
        environment: Environment::Sandbox,
        auth: ConnectorAuth::HeaderKey { api_key: "YOUR_API_KEY".into() },
        ..Default::default()
    };

    // Field names and descriptions from the proto definition above
    let request = DisputeServiceAcceptRequest {
        // merchant_dispute_id: todo!(),  // Identification
        // connector_transaction_id: todo!(),
        // dispute_id: todo!(),
        ..Default::default()
    };

    let client = ConnectorClient::new(config, None)?;
    let response = client.dispute_accept(request, &Default::default(), None).await?;
    println!("{response:?}");
    Ok(())
}
```

</details>

</td>
</tr>
</table>

#### DisputeService.Defend

Submit defense with reason code for dispute. Presents formal argument against customer's chargeback claim with supporting documentation.

| | Message |
|---|---------|
| **Request** | `DisputeServiceDefendRequest` |
| **Response** | `DisputeServiceDefendResponse` |

**Example Request**


<table>
<tr><td><b>Python</b></td><td><b>JavaScript</b></td><td><b>Kotlin</b></td><td><b>Rust</b></td></tr>
<tr>
<td valign="top">

<details><summary>Python</summary>

```python
import asyncio
from google.protobuf.json_format import ParseDict
from payments import DisputeClient
from payments.generated import sdk_config_pb2, payment_pb2

config = sdk_config_pb2.ConnectorConfig(
    connector=sdk_config_pb2.Connector.ADYEN,
    environment=sdk_config_pb2.Environment.SANDBOX,
    auth=sdk_config_pb2.ConnectorAuthType(
        header_key=sdk_config_pb2.HeaderKey(api_key="YOUR_API_KEY"),
    ),
)

request = ParseDict(
{
        "merchant_dispute_id": "probe_dispute_001",  # Identification
        "connector_transaction_id": "probe_txn_001",
        "dispute_id": "probe_dispute_id_001",
        "reason_code": "probe_reason"  # Defend Details
    },
    payment_pb2.DisputeServiceDefendRequest(),
)

async def main():
    client = DisputeClient(config)
    response = await client.dispute_defend(request)
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
    connector: 'Adyen',
    environment: 'sandbox',
    connector_auth_type: {
        header_key: { api_key: 'YOUR_API_KEY' },
    },
});

const request = {
    "merchant_dispute_id": "probe_dispute_001",  // Identification
    "connector_transaction_id": "probe_txn_001",
    "dispute_id": "probe_dispute_id_001",
    "reason_code": "probe_reason"  // Defend Details
};

const response = await client.disputeDefend(request);
console.log(response);
```

</details>

</td>
<td valign="top">

<details><summary>Kotlin</summary>

```kotlin
import payments.DisputeClient
import types.Payment.DisputeServiceDefendRequest
import com.google.protobuf.util.JsonFormat

val config = ConnectorConfig.newBuilder()
    .setConnector("Adyen")
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
        "merchant_dispute_id": "probe_dispute_001",
        "connector_transaction_id": "probe_txn_001",
        "dispute_id": "probe_dispute_id_001",
        // Defend Details
        "reason_code": "probe_reason"
    }
""".trimIndent()

val builder = DisputeServiceDefendRequest.newBuilder()
JsonFormat.parser().ignoringUnknownFields().merge(json, builder)
val request = builder.build()

val client = DisputeClient(config)
val response = client.dispute_defend(request)
println(response)
```

</details>

</td>
<td valign="top">

<details><summary>Rust</summary>

```rust
use connector_service_sdk::{ConnectorClient, ConnectorConfig};
use grpc_api_types::payments::DisputeServiceDefendRequest;

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ConnectorConfig {
        connector: "Adyen".to_string(),
        environment: Environment::Sandbox,
        auth: ConnectorAuth::HeaderKey { api_key: "YOUR_API_KEY".into() },
        ..Default::default()
    };

    // Field names and descriptions from the proto definition above
    let request = DisputeServiceDefendRequest {
        // merchant_dispute_id: todo!(),  // Identification
        // connector_transaction_id: todo!(),
        // dispute_id: todo!(),
        // reason_code: todo!(),  // Defend Details
        ..Default::default()
    };

    let client = ConnectorClient::new(config, None)?;
    let response = client.dispute_defend(request, &Default::default(), None).await?;
    println!("{response:?}");
    Ok(())
}
```

</details>

</td>
</tr>
</table>

#### DisputeService.SubmitEvidence

Upload evidence to dispute customer chargeback. Provides documentation like receipts and delivery proof to contest fraudulent transaction claims.

| | Message |
|---|---------|
| **Request** | `DisputeServiceSubmitEvidenceRequest` |
| **Response** | `DisputeServiceSubmitEvidenceResponse` |

**Example Request**


<table>
<tr><td><b>Python</b></td><td><b>JavaScript</b></td><td><b>Kotlin</b></td><td><b>Rust</b></td></tr>
<tr>
<td valign="top">

<details><summary>Python</summary>

```python
import asyncio
from google.protobuf.json_format import ParseDict
from payments import DisputeClient
from payments.generated import sdk_config_pb2, payment_pb2

config = sdk_config_pb2.ConnectorConfig(
    connector=sdk_config_pb2.Connector.ADYEN,
    environment=sdk_config_pb2.Environment.SANDBOX,
    auth=sdk_config_pb2.ConnectorAuthType(
        header_key=sdk_config_pb2.HeaderKey(api_key="YOUR_API_KEY"),
    ),
)

request = ParseDict(
{
        "merchant_dispute_id": "probe_dispute_001",  # Identification
        "connector_transaction_id": "probe_txn_001",
        "dispute_id": "probe_dispute_id_001",
        "evidence_documents": [  # Collection of evidence documents
            {
                "evidence_type": "SERVICE_DOCUMENTATION",  # Type of the evidence.
                "file_content": [112, 114, 111, 98, 101, 32, 101, 118, 105, 100, 101, 110, 99, 101, 32, 99, 111, 110, 116, 101, 110, 116],  # Content Options Content of the document, if it's a file.
                "file_mime_type": "application/pdf"  # MIME type of the file (e.g., "application/pdf", "image/png"), if file_content is provided.
            }
        ]
    },
    payment_pb2.DisputeServiceSubmitEvidenceRequest(),
)

async def main():
    client = DisputeClient(config)
    response = await client.dispute_submit_evidence(request)
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
    connector: 'Adyen',
    environment: 'sandbox',
    connector_auth_type: {
        header_key: { api_key: 'YOUR_API_KEY' },
    },
});

const request = {
    "merchant_dispute_id": "probe_dispute_001",  // Identification
    "connector_transaction_id": "probe_txn_001",
    "dispute_id": "probe_dispute_id_001",
    "evidence_documents": [  // Collection of evidence documents
        {
            "evidence_type": "SERVICE_DOCUMENTATION",  // Type of the evidence.
            "file_content": [112, 114, 111, 98, 101, 32, 101, 118, 105, 100, 101, 110, 99, 101, 32, 99, 111, 110, 116, 101, 110, 116],  // Content Options Content of the document, if it's a file.
            "file_mime_type": "application/pdf"  // MIME type of the file (e.g., "application/pdf", "image/png"), if file_content is provided.
        }
    ]
};

const response = await client.disputeSubmitEvidence(request);
console.log(response);
```

</details>

</td>
<td valign="top">

<details><summary>Kotlin</summary>

```kotlin
import payments.DisputeClient
import types.Payment.DisputeServiceSubmitEvidenceRequest
import com.google.protobuf.util.JsonFormat

val config = ConnectorConfig.newBuilder()
    .setConnector("Adyen")
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
        "merchant_dispute_id": "probe_dispute_001",
        "connector_transaction_id": "probe_txn_001",
        "dispute_id": "probe_dispute_id_001",
        // Collection of evidence documents
        "evidence_documents": [
            {
                // Type of the evidence.
                "evidence_type": "SERVICE_DOCUMENTATION",
                // Content Options Content of the document, if it's a file.
                "file_content": [112, 114, 111, 98, 101, 32, 101, 118, 105, 100, 101, 110, 99, 101, 32, 99, 111, 110, 116, 101, 110, 116],
                // MIME type of the file (e.g., "application/pdf", "image/png"), if file_content is provided.
                "file_mime_type": "application/pdf"
            }
        ]
    }
""".trimIndent()

val builder = DisputeServiceSubmitEvidenceRequest.newBuilder()
JsonFormat.parser().ignoringUnknownFields().merge(json, builder)
val request = builder.build()

val client = DisputeClient(config)
val response = client.dispute_submit_evidence(request)
println(response)
```

</details>

</td>
<td valign="top">

<details><summary>Rust</summary>

```rust
use connector_service_sdk::{ConnectorClient, ConnectorConfig};
use grpc_api_types::payments::DisputeServiceSubmitEvidenceRequest;

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ConnectorConfig {
        connector: "Adyen".to_string(),
        environment: Environment::Sandbox,
        auth: ConnectorAuth::HeaderKey { api_key: "YOUR_API_KEY".into() },
        ..Default::default()
    };

    // Field names and descriptions from the proto definition above
    let request = DisputeServiceSubmitEvidenceRequest {
        // merchant_dispute_id: todo!(),  // Identification
        // connector_transaction_id: todo!(),
        // dispute_id: todo!(),
        // evidence_documents: todo!(),  // Collection of evidence documents
        ..Default::default()
    };

    let client = ConnectorClient::new(config, None)?;
    let response = client.dispute_submit_evidence(request, &Default::default(), None).await?;
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

<!-- TODO: Add sample payload for `authenticate` in `scripts/connector-annotations/adyen.yaml` -->

#### PaymentMethodAuthenticationService.PostAuthenticate

Validate authentication results with the issuing bank. Processes bank's authentication decision to determine if payment can proceed.

| | Message |
|---|---------|
| **Request** | `PaymentMethodAuthenticationServicePostAuthenticateRequest` |
| **Response** | `PaymentMethodAuthenticationServicePostAuthenticateResponse` |

<!-- TODO: Add sample payload for `post_authenticate` in `scripts/connector-annotations/adyen.yaml` -->

#### PaymentMethodAuthenticationService.PreAuthenticate

Initiate 3DS flow before payment authorization. Collects device data and prepares authentication context for frictionless or challenge-based verification.

| | Message |
|---|---------|
| **Request** | `PaymentMethodAuthenticationServicePreAuthenticateRequest` |
| **Response** | `PaymentMethodAuthenticationServicePreAuthenticateResponse` |

<!-- TODO: Add sample payload for `pre_authenticate` in `scripts/connector-annotations/adyen.yaml` -->

## Testing

Adyen test credentials are obtained from the Adyen Customer Area (test.adyen.com). The merchant account must be configured separately for test mode.

**Test API Key:** `AQE...your-test-api-key...`

### Test Cards

| Card Number | Brand | CVV | Expiry | Scenario |
|------------|-------|-----|--------|----------|
| `4111111111111111` | Visa | `737` | `03/2030` | Successful payment |
| `4000000000000002` | Visa | `737` | `03/2030` | Refused |
| `5101180000000007` | Mastercard | `737` | `03/2030` | Successful payment |
| `4212345678901237` | Visa | `737` | `03/2030` | 3DS2 required |
| `6703444444444449` | Bancontact | `` | `01/2030` | Bancontact card – success |

### Test Payment Methods

- **iDEAL**: Bank selection triggers a simulated redirect; use any test bank
- **Klarna**: Use `+46 700 123 456` in Sweden test accounts. customer.id required.
- **Blik**: Use any 6-digit code in Adyen test environment
- **EPS**: Use any bank_name enum value. `BANK_AUSTRIA` works.
- **SEPA Direct Debit**: Use IBAN `NL13TEST0123456789` for successful test debit
