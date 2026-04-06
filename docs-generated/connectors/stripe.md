# Stripe

<!--
This file is auto-generated. Do not edit by hand.
Source: data/field_probe/stripe.json
Regenerate: python3 scripts/generators/docs/generate.py stripe
-->

## SDK Configuration

Use this config for all flows in this connector. Replace `YOUR_API_KEY` with your actual credentials.

<table>
<tr><td><b>Python</b></td><td><b>JavaScript</b></td><td><b>Kotlin</b></td><td><b>Rust</b></td></tr>
<tr>
<td valign="top">

<details><summary>Python</summary>

```python
from payments.generated import sdk_config_pb2, payment_pb2

config = sdk_config_pb2.ConnectorConfig(
    options=sdk_config_pb2.SdkOptions(environment=sdk_config_pb2.Environment.SANDBOX),
)
# Set credentials before running (field names depend on connector auth type):
# config.connector_config.CopyFrom(payment_pb2.ConnectorSpecificConfig(
#     stripe=payment_pb2.StripeConfig(api_key=...),
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
    connector: 'Stripe',
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
    .setConnector("Stripe")
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
    connector: "Stripe".to_string(),
    environment: Environment::Sandbox,
    auth: ConnectorAuth::HeaderKey { api_key: "YOUR_API_KEY".into() },
    ..Default::default()
};
```

</details>

</td>
</tr>
</table>

## Integration Scenarios

Complete, runnable examples for common integration patterns. Each example shows the full flow with status handling. Copy-paste into your app and replace placeholder values.

### One-step Payment (Authorize + Capture)

Simple payment that authorizes and captures in one call. Use for immediate charges.

**Response status handling:**

| Status | Recommended action |
|--------|-------------------|
| `AUTHORIZED` | Payment authorized and captured — funds will be settled automatically |
| `PENDING` | Payment processing — await webhook for final status before fulfilling |
| `FAILED` | Payment declined — surface error to customer, do not retry without new details |

**Examples:** [Python](../../examples/stripe/python/stripe.py#L178) · [JavaScript](../../examples/stripe/javascript/stripe.js#L162) · [Kotlin](../../examples/stripe/kotlin/stripe.kt#L91) · [Rust](../../examples/stripe/rust/stripe.rs#L175)

### Card Payment (Authorize + Capture)

Two-step card payment. First authorize, then capture. Use when you need to verify funds before finalizing.

**Response status handling:**

| Status | Recommended action |
|--------|-------------------|
| `AUTHORIZED` | Funds reserved — proceed to Capture to settle |
| `PENDING` | Awaiting async confirmation — wait for webhook before capturing |
| `FAILED` | Payment declined — surface error to customer, do not retry without new details |

**Examples:** [Python](../../examples/stripe/python/stripe.py#L197) · [JavaScript](../../examples/stripe/javascript/stripe.js#L181) · [Kotlin](../../examples/stripe/kotlin/stripe.kt#L107) · [Rust](../../examples/stripe/rust/stripe.rs#L191)

### Refund

Return funds to the customer for a completed payment.

**Examples:** [Python](../../examples/stripe/python/stripe.py#L222) · [JavaScript](../../examples/stripe/javascript/stripe.js#L207) · [Kotlin](../../examples/stripe/kotlin/stripe.kt#L129) · [Rust](../../examples/stripe/rust/stripe.rs#L214)

### Void Payment

Cancel an authorized but not-yet-captured payment.

**Examples:** [Python](../../examples/stripe/python/stripe.py#L247) · [JavaScript](../../examples/stripe/javascript/stripe.js#L233) · [Kotlin](../../examples/stripe/kotlin/stripe.kt#L151) · [Rust](../../examples/stripe/rust/stripe.rs#L237)

### Get Payment Status

Retrieve current payment status from the connector.

**Examples:** [Python](../../examples/stripe/python/stripe.py#L275) · [JavaScript](../../examples/stripe/javascript/stripe.js#L259) · [Kotlin](../../examples/stripe/kotlin/stripe.kt#L174) · [Rust](../../examples/stripe/rust/stripe.rs#L259)

## API Reference

| Flow (Service.RPC) | Category | gRPC Request Message |
|--------------------|----------|----------------------|
| [PaymentService.Authorize](#paymentserviceauthorize) | Payments | `PaymentServiceAuthorizeRequest` |
| [PaymentService.Capture](#paymentservicecapture) | Payments | `PaymentServiceCaptureRequest` |
| [CustomerService.Create](#customerservicecreate) | Customers | `CustomerServiceCreateRequest` |
| [PayoutService.Get](#payoutserviceget) | Other | `—` |
| [PaymentService.ProxyAuthorize](#paymentserviceproxyauthorize) | Other | `—` |
| [RecurringPaymentService.Charge](#recurringpaymentservicecharge) | Mandates | `RecurringPaymentServiceChargeRequest` |
| [PaymentService.Refund](#paymentservicerefund) | Payments | `PaymentServiceRefundRequest` |
| [PaymentService.SetupRecurring](#paymentservicesetuprecurring) | Payments | `PaymentServiceSetupRecurringRequest` |
| [PaymentMethodService.Tokenize](#paymentmethodservicetokenize) | Payments | `PaymentMethodServiceTokenizeRequest` |
| [PayoutService.Void](#payoutservicevoid) | Other | `—` |

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
| Apple Pay | ✓ |
| Apple Pay Dec | ✓ |
| Google Pay | ✓ |
| Google Pay Dec | ? |
| PayPal | ⚠ |
| Samsung Pay | ⚠ |
| Affirm | ✓ |
| Afterpay | ✓ |
| Klarna | ✓ |
| UPI Collect | ⚠ |
| iDEAL | ✓ |
| BLIK | ✓ |
| ACH | ✓ |
| SEPA | ✓ |
| BACS | ✓ |
| BECS | ✓ |

**Payment method objects** — use these in the `payment_method` field of the Authorize request.

##### Card (Raw PAN)

```python
"payment_method": {
    "card": {  # Generic card payment
        "card_number": {"value": "4111111111111111"},  # Card Identification
        "card_exp_month": {"value": "03"},
        "card_exp_year": {"value": "2030"},
        "card_cvc": {"value": "737"},
        "card_holder_name": {"value": "John Doe"}  # Cardholder Information
    }
}
```

##### Google Pay

```python
"payment_method": {
    "google_pay": {  # Google Pay
        "type": "CARD",  # Type of payment method
        "description": "Visa 1111",  # User-facing description of the payment method
        "info": {
            "card_network": "VISA",  # Card network name
            "card_details": "1111"  # Card details (usually last 4 digits)
        },
        "tokenization_data": {
            "encrypted_data": {  # Encrypted Google Pay payment data
                "token_type": "PAYMENT_GATEWAY",  # The type of the token
                "token": "{\"id\":\"tok_probe_gpay\",\"object\":\"token\",\"type\":\"card\"}"  # Token generated for the wallet
            }
        }
    }
}
```

##### Apple Pay

```python
"payment_method": {
    "apple_pay": {  # Apple Pay
        "payment_data": {
            "encrypted_data": "eyJ2ZXJzaW9uIjoiRUNfdjEiLCJkYXRhIjoicHJvYmUiLCJzaWduYXR1cmUiOiJwcm9iZSJ9"  # Encrypted Apple Pay payment data as string
        },
        "payment_method": {
            "display_name": "Visa 1111",
            "network": "Visa",
            "type": "debit"
        },
        "transaction_identifier": "probe_txn_id"  # Transaction identifier
    }
}
```

##### SEPA Direct Debit

```python
"payment_method": {
    "sepa": {  # Sepa - Single Euro Payments Area direct debit
        "iban": {"value": "DE89370400440532013000"},  # International bank account number (iban) for SEPA
        "bank_account_holder_name": {"value": "John Doe"}  # Owner name for bank debit
    }
}
```

##### BACS Direct Debit

```python
"payment_method": {
    "bacs": {  # Bacs - Bankers' Automated Clearing Services
        "account_number": {"value": "55779911"},  # Account number for Bacs payment method
        "sort_code": {"value": "200000"},  # Sort code for Bacs payment method
        "bank_account_holder_name": {"value": "John Doe"}  # Holder name for bank debit
    }
}
```

##### ACH Direct Debit

```python
"payment_method": {
    "ach": {  # Ach - Automated Clearing House
        "account_number": {"value": "000123456789"},  # Account number for ach bank debit payment
        "routing_number": {"value": "110000000"},  # Routing number for ach bank debit payment
        "bank_account_holder_name": {"value": "John Doe"}  # Bank account holder name
    }
}
```

##### BECS Direct Debit

```python
"payment_method": {
    "becs": {  # Becs - Bulk Electronic Clearing System - Australian direct debit
        "account_number": {"value": "000123456"},  # Account number for Becs payment method
        "bsb_number": {"value": "000000"},  # Bank-State-Branch (bsb) number
        "bank_account_holder_name": {"value": "John Doe"}  # Owner name for bank debit
    }
}
```

##### iDEAL

```python
"payment_method": {
    "ideal": {
    }
}
```

##### BLIK

```python
"payment_method": {
    "blik": {
        "blik_code": "777124"
    }
}
```

##### Klarna

```python
"payment_method": {
    "klarna": {  # Klarna - Swedish BNPL service
    }
}
```

##### Afterpay / Clearpay

```python
"payment_method": {
    "afterpay_clearpay": {  # Afterpay/Clearpay - BNPL service
    }
}
```

##### Affirm

```python
"payment_method": {
    "affirm": {  # Affirm - US BNPL service
    }
}
```

**Examples:** [Python](../../examples/stripe/python/stripe.py#L307) · [JavaScript](../../examples/stripe/javascript/stripe.js#L288) · [Kotlin](../../examples/stripe/kotlin/stripe.kt#L198) · [Rust](../../examples/stripe/rust/stripe.rs#L284)

#### PaymentService.Capture

Finalize an authorized payment transaction. Transfers reserved funds from customer to merchant account, completing the payment lifecycle.

| | Message |
|---|---------|
| **Request** | `PaymentServiceCaptureRequest` |
| **Response** | `PaymentServiceCaptureResponse` |

**Examples:** [Python](../../examples/stripe/python/stripe.py#L316) · [JavaScript](../../examples/stripe/javascript/stripe.js#L297) · [Kotlin](../../examples/stripe/kotlin/stripe.kt#L210) · [Rust](../../examples/stripe/rust/stripe.rs#L296)

#### PaymentService.Refund

Initiate a refund to customer's payment method. Returns funds for returns, cancellations, or service adjustments after original payment.

| | Message |
|---|---------|
| **Request** | `PaymentServiceRefundRequest` |
| **Response** | `RefundResponse` |

**Examples:** [Python](../../examples/stripe/python/stripe.py#L392) · [JavaScript](../../examples/stripe/javascript/stripe.js#L365) · [Kotlin](../../examples/stripe/kotlin/stripe.kt#L264) · [Rust](../../examples/stripe/rust/stripe.rs#L358)

#### PaymentService.SetupRecurring

Setup a recurring payment instruction for future payments/ debits. This could be for SaaS subscriptions, monthly bill payments, insurance payments and similar use cases.

| | Message |
|---|---------|
| **Request** | `PaymentServiceSetupRecurringRequest` |
| **Response** | `PaymentServiceSetupRecurringResponse` |

**Examples:** [Python](../../examples/stripe/python/stripe.py#L401) · [JavaScript](../../examples/stripe/javascript/stripe.js#L374) · [Kotlin](../../examples/stripe/kotlin/stripe.kt#L274) · [Rust](../../examples/stripe/rust/stripe.rs#L365)

#### PaymentMethodService.Tokenize

Tokenize payment method for secure storage. Replaces raw card details with secure token for one-click payments and recurring billing.

| | Message |
|---|---------|
| **Request** | `PaymentMethodServiceTokenizeRequest` |
| **Response** | `PaymentMethodServiceTokenizeResponse` |

**Examples:** [Python](../../examples/stripe/python/stripe.py#L410) · [JavaScript](../../examples/stripe/javascript/stripe.js#L383) · [Kotlin](../../examples/stripe/kotlin/stripe.kt#L313) · [Rust](../../examples/stripe/rust/stripe.rs#L375)

### Mandates

#### RecurringPaymentService.Charge

Charge using an existing stored recurring payment instruction. Processes repeat payments for subscriptions or recurring billing without collecting payment details.

| | Message |
|---|---------|
| **Request** | `RecurringPaymentServiceChargeRequest` |
| **Response** | `RecurringPaymentServiceChargeResponse` |

**Examples:** [Python](../../examples/stripe/python/stripe.py#L383) · [JavaScript](../../examples/stripe/javascript/stripe.js#L356) · [Kotlin](../../examples/stripe/kotlin/stripe.kt#L233) · [Rust](../../examples/stripe/rust/stripe.rs#L351)

### Customers

#### CustomerService.Create

Create customer record in the payment processor system. Stores customer details for future payment operations without re-sending personal information.

| | Message |
|---|---------|
| **Request** | `CustomerServiceCreateRequest` |
| **Response** | `CustomerServiceCreateResponse` |

**Examples:** [Python](../../examples/stripe/python/stripe.py#L325) · [JavaScript](../../examples/stripe/javascript/stripe.js#L306) · [Kotlin](../../examples/stripe/kotlin/stripe.kt#L220) · [Rust](../../examples/stripe/rust/stripe.rs#L303)

### Other

#### PayoutService.Get

**Examples:** [Python](../../examples/stripe/python/stripe.py#L334) · [JavaScript](../../examples/stripe/javascript/stripe.js#L315) · [Kotlin](../../examples/stripe/kotlin/stripe.kt) · [Rust](../../examples/stripe/rust/stripe.rs#L310)

#### PaymentService.ProxyAuthorize

**Examples:** [Python](../../examples/stripe/python/stripe.py#L353) · [JavaScript](../../examples/stripe/javascript/stripe.js#L330) · [Kotlin](../../examples/stripe/kotlin/stripe.kt) · [Rust](../../examples/stripe/rust/stripe.rs#L324)

#### PayoutService.Void

**Examples:** [Python](../../examples/stripe/python/stripe.py#L419) · [JavaScript](../../examples/stripe/javascript/stripe.js#L392) · [Kotlin](../../examples/stripe/kotlin/stripe.kt) · [Rust](../../examples/stripe/rust/stripe.rs#L382)
