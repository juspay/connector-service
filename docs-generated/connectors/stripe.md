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

### Card Payment (Authorize + Capture)

Reserve funds with Authorize, then settle with a separate Capture call. Use for physical goods or delayed fulfillment where capture happens later.

**Response status handling:**

| Status | Recommended action |
|--------|-------------------|
| `AUTHORIZED` | Funds reserved — proceed to Capture to settle |
| `PENDING` | Awaiting async confirmation — wait for webhook before capturing |
| `FAILED` | Payment declined — surface error to customer, do not retry without new details |

**Examples:** [Python](../../examples/stripe/python/stripe.py#L373) · [JavaScript](../../examples/stripe/javascript/stripe.js#L337) · [Kotlin](../../examples/stripe/kotlin/stripe.kt#L119) · [Rust](../../examples/stripe/rust/stripe.rs#L349)

### Card Payment (Automatic Capture)

Authorize and capture in one call using `capture_method=AUTOMATIC`. Use for digital goods or immediate fulfillment.

**Response status handling:**

| Status | Recommended action |
|--------|-------------------|
| `AUTHORIZED` | Payment authorized and captured — funds will be settled automatically |
| `PENDING` | Payment processing — await webhook for final status before fulfilling |
| `FAILED` | Payment declined — surface error to customer, do not retry without new details |

**Examples:** [Python](../../examples/stripe/python/stripe.py#L398) · [JavaScript](../../examples/stripe/javascript/stripe.js#L363) · [Kotlin](../../examples/stripe/kotlin/stripe.kt#L141) · [Rust](../../examples/stripe/rust/stripe.rs#L372)

### Wallet Payment (Google Pay / Apple Pay)

Wallet payments pass an encrypted token from the browser/device SDK. Pass the token blob directly — do not decrypt client-side.

**Response status handling:**

| Status | Recommended action |
|--------|-------------------|
| `AUTHORIZED` | Payment authorized and captured — funds will be settled automatically |
| `PENDING` | Payment processing — await webhook for final status before fulfilling |
| `FAILED` | Payment declined — surface error to customer, do not retry without new details |

**Examples:** [Python](../../examples/stripe/python/stripe.py#L417) · [JavaScript](../../examples/stripe/javascript/stripe.js#L382) · [Kotlin](../../examples/stripe/kotlin/stripe.kt#L157) · [Rust](../../examples/stripe/rust/stripe.rs#L388)

### Bank Transfer (SEPA / ACH / BACS)

Direct bank debit (Sepa). Bank transfers typically use `capture_method=AUTOMATIC`.

**Response status handling:**

| Status | Recommended action |
|--------|-------------------|
| `AUTHORIZED` | Payment authorized and captured — funds will be settled automatically |
| `PENDING` | Payment processing — await webhook for final status before fulfilling |
| `FAILED` | Payment declined — surface error to customer, do not retry without new details |

**Examples:** [Python](../../examples/stripe/python/stripe.py#L468) · [JavaScript](../../examples/stripe/javascript/stripe.js#L430) · [Kotlin](../../examples/stripe/kotlin/stripe.kt#L202) · [Rust](../../examples/stripe/rust/stripe.rs#L436)

### Refund a Payment

Authorize with automatic capture, then refund the captured amount. `connector_transaction_id` from the Authorize response is reused for the Refund call.

**Examples:** [Python](../../examples/stripe/python/stripe.py#L509) · [JavaScript](../../examples/stripe/javascript/stripe.js#L468) · [Kotlin](../../examples/stripe/kotlin/stripe.kt#L237) · [Rust](../../examples/stripe/rust/stripe.rs#L474)

### Recurring / Mandate Payments

Store a payment mandate with SetupRecurring, then charge it repeatedly with RecurringPaymentService.Charge without requiring customer action.

**Response status handling:**

| Status | Recommended action |
|--------|-------------------|
| `PENDING` | Mandate stored — save connector_transaction_id for future RecurringPaymentService.Charge calls |
| `FAILED` | Setup failed — customer must re-enter payment details |

**Examples:** [Python](../../examples/stripe/python/stripe.py#L534) · [JavaScript](../../examples/stripe/javascript/stripe.js#L494) · [Kotlin](../../examples/stripe/kotlin/stripe.kt#L259) · [Rust](../../examples/stripe/rust/stripe.rs#L497)

### Void a Payment

Authorize funds with a manual capture flag, then cancel the authorization with Void before any capture occurs. Releases the hold on the customer's funds.

**Examples:** [Python](../../examples/stripe/python/stripe.py#L603) · [JavaScript](../../examples/stripe/javascript/stripe.js#L554) · [Kotlin](../../examples/stripe/kotlin/stripe.kt#L321) · [Rust](../../examples/stripe/rust/stripe.rs#L557)

### Get Payment Status

Authorize a payment, then poll the connector for its current status using Get. Use this to sync payment state when webhooks are unavailable or delayed.

**Examples:** [Python](../../examples/stripe/python/stripe.py#L625) · [JavaScript](../../examples/stripe/javascript/stripe.js#L576) · [Kotlin](../../examples/stripe/kotlin/stripe.kt#L340) · [Rust](../../examples/stripe/rust/stripe.rs#L576)

### Create Customer

Register a customer record in the connector system. Returns a connector_customer_id that can be reused for recurring payments and tokenized card storage.

**Examples:** [Python](../../examples/stripe/python/stripe.py#L647) · [JavaScript](../../examples/stripe/javascript/stripe.js#L598) · [Kotlin](../../examples/stripe/kotlin/stripe.kt#L359) · [Rust](../../examples/stripe/rust/stripe.rs#L595)

### Tokenize Payment Method

Store card details in the connector's vault and receive a reusable payment token. Use the returned token for one-click payments and recurring billing without re-collecting card data.

**Examples:** [Python](../../examples/stripe/python/stripe.py#L668) · [JavaScript](../../examples/stripe/javascript/stripe.js#L614) · [Kotlin](../../examples/stripe/kotlin/stripe.kt#L375) · [Rust](../../examples/stripe/rust/stripe.rs#L610)

### Tokenized Payment (Authorize + Capture)

Authorize using a connector-issued payment method token (e.g. Stripe pm_xxx). Card data never touches your server — only the token is sent. Capture settles the reserved funds.

**Examples:** [Python](../../examples/stripe/python/stripe.py#L702) · [JavaScript](../../examples/stripe/javascript/stripe.js#L643) · [Kotlin](../../examples/stripe/kotlin/stripe.kt#L404) · [Rust](../../examples/stripe/rust/stripe.rs#L640)

### Tokenized Recurring Payments

Store a payment mandate using a connector token with SetupRecurring, then charge it repeatedly with RecurringPaymentService without requiring customer action or re-collecting card data.

**Examples:** [Python](../../examples/stripe/python/stripe.py#L750) · [JavaScript](../../examples/stripe/javascript/stripe.js#L684) · [Kotlin](../../examples/stripe/kotlin/stripe.kt#L444) · [Rust](../../examples/stripe/rust/stripe.rs#L678)

### Proxy Payment via Vault (VGS / Basis Theory)

Authorize using vault alias tokens. Configure an outbound proxy URL in RequestConfig — the proxy substitutes aliases with real card values before the request reaches the connector. Card data never touches your server.

**Examples:** [Python](../../examples/stripe/python/stripe.py#L813) · [JavaScript](../../examples/stripe/javascript/stripe.js#L740) · [Kotlin](../../examples/stripe/kotlin/stripe.kt#L497) · [Rust](../../examples/stripe/rust/stripe.rs#L738)

### Proxy Payment with 3DS (VGS + Proxy 3DS)

Full 3DS flow using vault alias tokens routed through an outbound proxy. The proxy substitutes aliases before forwarding to Netcetera (3DS server). Authorize after successful authentication using the same vault aliases.

**Examples:** [Python](../../examples/stripe/python/stripe.py#L853) · [JavaScript](../../examples/stripe/javascript/stripe.js) · [Kotlin](../../examples/stripe/kotlin/stripe.kt) · [Rust](../../examples/stripe/rust/stripe.rs#L778)

## API Reference

| Flow (Service.RPC) | Category | gRPC Request Message |
|--------------------|----------|----------------------|
| [PaymentService.Authorize](#paymentserviceauthorize) | Payments | `PaymentServiceAuthorizeRequest` |
| [PaymentService.Capture](#paymentservicecapture) | Payments | `PaymentServiceCaptureRequest` |
| [CustomerService.Create](#customerservicecreate) | Customers | `CustomerServiceCreateRequest` |
| [PaymentService.Get](#paymentserviceget) | Payments | `PaymentServiceGetRequest` |
| [RecurringPaymentService.Charge](#recurringpaymentservicecharge) | Mandates | `RecurringPaymentServiceChargeRequest` |
| [PaymentService.Refund](#paymentservicerefund) | Payments | `PaymentServiceRefundRequest` |
| [PaymentService.SetupRecurring](#paymentservicesetuprecurring) | Payments | `PaymentServiceSetupRecurringRequest` |
| [PaymentMethodService.Tokenize](#paymentmethodservicetokenize) | Payments | `PaymentMethodServiceTokenizeRequest` |
| [PaymentService.Void](#paymentservicevoid) | Payments | `PaymentServiceVoidRequest` |
| [TokenizedPaymentService.Authorize](#tokenizedpaymentserviceauthorize) | Non-PCI Payments | `TokenizedPaymentServiceAuthorizeRequest` |
| [TokenizedPaymentService.SetupRecurring](#tokenizedpaymentservicesetuprecurring) | Non-PCI Payments | `TokenizedPaymentServiceSetupRecurringRequest` |
| [ProxyPaymentService.Authorize](#proxypaymentserviceauthorize) | Non-PCI Payments | `ProxyPaymentServiceAuthorizeRequest` |
| [ProxyPaymentService.SetupRecurring](#proxypaymentservicesetuprecurring) | Non-PCI Payments | `ProxyPaymentServiceSetupRecurringRequest` |
| [ProxyPaymentService.PreAuthenticate](#proxypaymentservicepreauthenticate) | Non-PCI Authentication | `ProxyPaymentMethodAuthenticationServicePreAuthenticateRequest` |
| [ProxyPaymentService.Authenticate](#proxypaymentserviceauthenticate) | Non-PCI Authentication | `ProxyPaymentMethodAuthenticationServiceAuthenticateRequest` |
| [ProxyPaymentService.PostAuthenticate](#proxypaymentservicepostauthenticate) | Non-PCI Authentication | `ProxyPaymentMethodAuthenticationServicePostAuthenticateRequest` |

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
| BECS | ✓ |
| iDEAL | ✓ |
| PayPal | ⚠ |
| BLIK | ✓ |
| Klarna | ✓ |
| Afterpay | ✓ |
| UPI | ⚠ |
| Affirm | ✓ |
| Samsung Pay | ⚠ |

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

**Examples:** [Python](../../examples/stripe/python/stripe.py#L962) · [JavaScript](../../examples/stripe/javascript/stripe.js#L869) · [Kotlin](../../examples/stripe/kotlin/stripe.kt#L626) · [Rust](../../examples/stripe/rust/stripe.rs#L889)

#### PaymentService.Capture

Finalize an authorized payment transaction. Transfers reserved funds from customer to merchant account, completing the payment lifecycle.

| | Message |
|---|---------|
| **Request** | `PaymentServiceCaptureRequest` |
| **Response** | `PaymentServiceCaptureResponse` |

**Examples:** [Python](../../examples/stripe/python/stripe.py#L971) · [JavaScript](../../examples/stripe/javascript/stripe.js#L878) · [Kotlin](../../examples/stripe/kotlin/stripe.kt#L638) · [Rust](../../examples/stripe/rust/stripe.rs#L901)

#### PaymentService.Get

Retrieve current payment status from the payment processor. Enables synchronization between your system and payment processors for accurate state tracking.

| | Message |
|---|---------|
| **Request** | `PaymentServiceGetRequest` |
| **Response** | `PaymentServiceGetResponse` |

**Examples:** [Python](../../examples/stripe/python/stripe.py#L989) · [JavaScript](../../examples/stripe/javascript/stripe.js#L896) · [Kotlin](../../examples/stripe/kotlin/stripe.kt#L661) · [Rust](../../examples/stripe/rust/stripe.rs#L915)

#### PaymentService.Refund

Initiate a refund to customer's payment method. Returns funds for returns, cancellations, or service adjustments after original payment.

| | Message |
|---|---------|
| **Request** | `PaymentServiceRefundRequest` |
| **Response** | `RefundResponse` |

**Examples:** [Python](../../examples/stripe/python/stripe.py#L1007) · [JavaScript](../../examples/stripe/javascript/stripe.js#L914) · [Kotlin](../../examples/stripe/kotlin/stripe.kt#L698) · [Rust](../../examples/stripe/rust/stripe.rs#L929)

#### PaymentService.SetupRecurring

Setup a recurring payment instruction for future payments/ debits. This could be for SaaS subscriptions, monthly bill payments, insurance payments and similar use cases.

| | Message |
|---|---------|
| **Request** | `PaymentServiceSetupRecurringRequest` |
| **Response** | `PaymentServiceSetupRecurringResponse` |

**Examples:** [Python](../../examples/stripe/python/stripe.py#L1016) · [JavaScript](../../examples/stripe/javascript/stripe.js#L923) · [Kotlin](../../examples/stripe/kotlin/stripe.kt#L708) · [Rust](../../examples/stripe/rust/stripe.rs#L936)

#### PaymentMethodService.Tokenize

Tokenize payment method for secure storage. Replaces raw card details with secure token for one-click payments and recurring billing.

| | Message |
|---|---------|
| **Request** | `PaymentMethodServiceTokenizeRequest` |
| **Response** | `PaymentMethodServiceTokenizeResponse` |

**Examples:** [Python](../../examples/stripe/python/stripe.py#L1025) · [JavaScript](../../examples/stripe/javascript/stripe.js#L932) · [Kotlin](../../examples/stripe/kotlin/stripe.kt#L747) · [Rust](../../examples/stripe/rust/stripe.rs#L946)

#### PaymentService.Void

Cancel an authorized payment before capture. Releases held funds back to customer, typically used when orders are cancelled or abandoned.

| | Message |
|---|---------|
| **Request** | `PaymentServiceVoidRequest` |
| **Response** | `PaymentServiceVoidResponse` |

**Examples:** [Python](../../examples/stripe/python/stripe.py#L1034) · [JavaScript](../../examples/stripe/javascript/stripe.js#L941) · [Kotlin](../../examples/stripe/kotlin/stripe.kt#L773) · [Rust](../../examples/stripe/rust/stripe.rs#L953)

### Mandates

#### RecurringPaymentService.Charge

Charge using an existing stored recurring payment instruction. Processes repeat payments for subscriptions or recurring billing without collecting payment details.

| | Message |
|---|---------|
| **Request** | `RecurringPaymentServiceChargeRequest` |
| **Response** | `RecurringPaymentServiceChargeResponse` |

**Examples:** [Python](../../examples/stripe/python/stripe.py#L998) · [JavaScript](../../examples/stripe/javascript/stripe.js#L905) · [Kotlin](../../examples/stripe/kotlin/stripe.kt#L669) · [Rust](../../examples/stripe/rust/stripe.rs#L922)

### Customers

#### CustomerService.Create

Create customer record in the payment processor system. Stores customer details for future payment operations without re-sending personal information.

| | Message |
|---|---------|
| **Request** | `CustomerServiceCreateRequest` |
| **Response** | `CustomerServiceCreateResponse` |

**Examples:** [Python](../../examples/stripe/python/stripe.py#L980) · [JavaScript](../../examples/stripe/javascript/stripe.js#L887) · [Kotlin](../../examples/stripe/kotlin/stripe.kt#L648) · [Rust](../../examples/stripe/rust/stripe.rs#L908)
