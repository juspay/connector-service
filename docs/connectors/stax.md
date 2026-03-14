# Stax

<!--
This file is auto-generated. Do not edit by hand.
Source: data/field_probe/stax.json
Regenerate: python3 scripts/generate-connector-docs.py stax
-->

## SDK Configuration

Use this config for all flows in this connector. Replace `YOUR_API_KEY` with your actual credentials.

<table>
<tr><td><b>Python</b></td><td><b>JavaScript</b></td><td><b>Kotlin</b></td><td><b>Rust</b></td></tr>
<tr>
<td valign="top">

<details><summary>Python</summary>

```python
from payments.generated import sdk_config_pb2

config = sdk_config_pb2.ConnectorConfig(
    connector=sdk_config_pb2.Connector.STAX,
    environment=sdk_config_pb2.Environment.SANDBOX,
    auth=sdk_config_pb2.ConnectorAuthType(
        header_key=sdk_config_pb2.HeaderKey(api_key="YOUR_API_KEY"),
    ),
)
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
| [PaymentService.Refund](#paymentservicerefund) | Payments | `PaymentServiceRefundRequest` |
| [PaymentMethodService.Tokenize](#paymentmethodservicetokenize) | Payments | `PaymentMethodServiceTokenizeRequest` |
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
| SEPA | ✓ |
| BACS | ✓ |
| ACH | ✓ |
| BECS | ✓ |
| Samsung Pay | — |

**Card (Raw PAN)**

> **Client call:** `PaymentClient.authorize(request)`

```python
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
    "payment_method_token": "probe_pm_token"  # Payment Method Token
}
```

**SEPA Direct Debit**

> **Client call:** `PaymentClient.authorize(request)`

```python
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
    },
    "payment_method_token": "probe_pm_token"  # Payment Method Token
}
```

**BACS Direct Debit**

> **Client call:** `PaymentClient.authorize(request)`

```python
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
    },
    "payment_method_token": "probe_pm_token"  # Payment Method Token
}
```

**ACH Direct Debit**

> **Client call:** `PaymentClient.authorize(request)`

```python
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
    },
    "payment_method_token": "probe_pm_token"  # Payment Method Token
}
```

**BECS Direct Debit**

> **Client call:** `PaymentClient.authorize(request)`

```python
{
    "merchant_transaction_id": "probe_txn_001",  # Identification
    "amount": {  # The amount for the payment
        "minor_amount": 1000,  # Amount in minor units (e.g., 1000 = $10.00)
        "currency": "USD"  # ISO 4217 currency code (e.g., "USD", "EUR")
    },
    "payment_method": {  # Payment method to be used
        "becs": {  # Becs - Bulk Electronic Clearing System - Australian direct debit
            "account_number": "000123456",  # Account number for Becs payment method
            "bsb_number": "000000",  # Bank-State-Branch (bsb) number
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
    },
    "payment_method_token": "probe_pm_token"  # Payment Method Token
}
```

#### PaymentService.Capture

Finalize an authorized payment transaction. Transfers reserved funds from customer to merchant account, completing the payment lifecycle.

| | Message |
|---|---------|
| **Request** | `PaymentServiceCaptureRequest` |
| **Response** | `PaymentServiceCaptureResponse` |

**Example Request**

> **Client call:** `PaymentClient.capture(request)`

```python
{
    "merchant_capture_id": "probe_capture_001",  # Identification
    "connector_transaction_id": "probe_connector_txn_001",
    "amount_to_capture": {  # Capture Details
        "minor_amount": 1000,  # Amount in minor units (e.g., 1000 = $10.00)
        "currency": "USD"  # ISO 4217 currency code (e.g., "USD", "EUR")
    }
}
```

#### PaymentService.Get

Retrieve current payment status from the payment processor. Enables synchronization between your system and payment processors for accurate state tracking.

| | Message |
|---|---------|
| **Request** | `PaymentServiceGetRequest` |
| **Response** | `PaymentServiceGetResponse` |

**Example Request**

> **Client call:** `PaymentClient.get(request)`

```python
{
    "connector_transaction_id": "probe_connector_txn_001",
    "amount": {  # Amount Information
        "minor_amount": 1000,  # Amount in minor units (e.g., 1000 = $10.00)
        "currency": "USD"  # ISO 4217 currency code (e.g., "USD", "EUR")
    }
}
```

#### PaymentService.Refund

Initiate a refund to customer's payment method. Returns funds for returns, cancellations, or service adjustments after original payment.

| | Message |
|---|---------|
| **Request** | `PaymentServiceRefundRequest` |
| **Response** | `RefundResponse` |

**Example Request**

> **Client call:** `PaymentClient.refund(request)`

```python
{
    "merchant_refund_id": "probe_refund_001",  # Identification
    "connector_transaction_id": "probe_connector_txn_001",
    "payment_amount": 1000,  # Amount Information
    "refund_amount": {
        "minor_amount": 1000,  # Amount in minor units (e.g., 1000 = $10.00)
        "currency": "USD"  # ISO 4217 currency code (e.g., "USD", "EUR")
    },
    "reason": "customer_request"  # Reason for the refund
}
```

#### PaymentMethodService.Tokenize

Tokenize payment method for secure storage. Replaces raw card details with secure token for one-click payments and recurring billing.

| | Message |
|---|---------|
| **Request** | `PaymentMethodServiceTokenizeRequest` |
| **Response** | `PaymentMethodServiceTokenizeResponse` |

**Example Request**

> **Client call:** `PaymentMethodClient.tokenize(request)`

```python
{
    "amount": {  # Payment Information
        "minor_amount": 1000,  # Amount in minor units (e.g., 1000 = $10.00)
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
    "customer": {  # Customer Information
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
    }
}
```

#### PaymentService.Void

Cancel an authorized payment before capture. Releases held funds back to customer, typically used when orders are cancelled or abandoned.

| | Message |
|---|---------|
| **Request** | `PaymentServiceVoidRequest` |
| **Response** | `PaymentServiceVoidResponse` |

**Example Request**

> **Client call:** `PaymentClient.void(request)`

```python
{
    "merchant_void_id": "probe_void_001",  # Identification
    "connector_transaction_id": "probe_connector_txn_001"
}
```

### Customers

#### CustomerService.Create

Create customer record in the payment processor system. Stores customer details for future payment operations without re-sending personal information.

| | Message |
|---|---------|
| **Request** | `CustomerServiceCreateRequest` |
| **Response** | `CustomerServiceCreateResponse` |

**Example Request**

> **Client call:** `CustomerClient.createCustomer(request)`

```python
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
}
```

### Authentication

#### PaymentMethodAuthenticationService.Authenticate

Execute 3DS challenge or frictionless verification. Authenticates customer via bank challenge or behind-the-scenes verification for fraud prevention.

| | Message |
|---|---------|
| **Request** | `PaymentMethodAuthenticationServiceAuthenticateRequest` |
| **Response** | `PaymentMethodAuthenticationServiceAuthenticateResponse` |

<!-- TODO: Add sample payload for `authenticate` in `scripts/connector-annotations/stax.yaml` -->

#### PaymentMethodAuthenticationService.PostAuthenticate

Validate authentication results with the issuing bank. Processes bank's authentication decision to determine if payment can proceed.

| | Message |
|---|---------|
| **Request** | `PaymentMethodAuthenticationServicePostAuthenticateRequest` |
| **Response** | `PaymentMethodAuthenticationServicePostAuthenticateResponse` |

<!-- TODO: Add sample payload for `post_authenticate` in `scripts/connector-annotations/stax.yaml` -->

#### PaymentMethodAuthenticationService.PreAuthenticate

Initiate 3DS flow before payment authorization. Collects device data and prepares authentication context for frictionless or challenge-based verification.

| | Message |
|---|---------|
| **Request** | `PaymentMethodAuthenticationServicePreAuthenticateRequest` |
| **Response** | `PaymentMethodAuthenticationServicePreAuthenticateResponse` |

<!-- TODO: Add sample payload for `pre_authenticate` in `scripts/connector-annotations/stax.yaml` -->
