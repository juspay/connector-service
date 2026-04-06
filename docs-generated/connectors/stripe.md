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

**Examples:** [Python](../../examples/stripe/python/stripe.py#L292) · [JavaScript](../../examples/stripe/javascript/stripe.js#L261) · [Kotlin](../../examples/stripe/kotlin/stripe.kt#L117) · [Rust](../../examples/stripe/rust/stripe.rs#L278)

### Card Payment (Authorize + Capture)

Two-step card payment. First authorize, then capture. Use when you need to verify funds before finalizing.

**Response status handling:**

| Status | Recommended action |
|--------|-------------------|
| `AUTHORIZED` | Funds reserved — proceed to Capture to settle |
| `PENDING` | Awaiting async confirmation — wait for webhook before capturing |
| `FAILED` | Payment declined — surface error to customer, do not retry without new details |

**Examples:** [Python](../../examples/stripe/python/stripe.py#L311) · [JavaScript](../../examples/stripe/javascript/stripe.js#L280) · [Kotlin](../../examples/stripe/kotlin/stripe.kt#L133) · [Rust](../../examples/stripe/rust/stripe.rs#L294)

### Refund

Return funds to the customer for a completed payment.

**Examples:** [Python](../../examples/stripe/python/stripe.py#L336) · [JavaScript](../../examples/stripe/javascript/stripe.js#L306) · [Kotlin](../../examples/stripe/kotlin/stripe.kt#L155) · [Rust](../../examples/stripe/rust/stripe.rs#L317)

### Void Payment

Cancel an authorized but not-yet-captured payment.

**Examples:** [Python](../../examples/stripe/python/stripe.py#L361) · [JavaScript](../../examples/stripe/javascript/stripe.js#L332) · [Kotlin](../../examples/stripe/kotlin/stripe.kt#L177) · [Rust](../../examples/stripe/rust/stripe.rs#L340)

### Get Payment Status

Retrieve current payment status from the connector.

**Examples:** [Python](../../examples/stripe/python/stripe.py#L383) · [JavaScript](../../examples/stripe/javascript/stripe.js#L354) · [Kotlin](../../examples/stripe/kotlin/stripe.kt#L196) · [Rust](../../examples/stripe/rust/stripe.rs#L359)

## API Reference

| Flow (Service.RPC) | Category | gRPC Request Message |
|--------------------|----------|----------------------|
| [PaymentService.Authorize](#paymentserviceauthorize) | Payments | `PaymentServiceAuthorizeRequest` |
| [PaymentService.Capture](#paymentservicecapture) | Payments | `PaymentServiceCaptureRequest` |
| [MerchantAuthenticationService.CreateClientAuthenticationToken](#merchantauthenticationservicecreateclientauthenticationtoken) | Authentication | `MerchantAuthenticationServiceCreateClientAuthenticationTokenRequest` |
| [CustomerService.Create](#customerservicecreate) | Customers | `CustomerServiceCreateRequest` |
| [PaymentService.Get](#paymentserviceget) | Payments | `PaymentServiceGetRequest` |
| [PaymentService.IncrementalAuthorization](#paymentserviceincrementalauthorization) | Payments | `PaymentServiceIncrementalAuthorizationRequest` |
| [PaymentService.ProxyAuthorize](#paymentserviceproxyauthorize) | Payments | `PaymentServiceProxyAuthorizeRequest` |
| [PaymentService.ProxySetupRecurring](#paymentserviceproxysetuprecurring) | Payments | `PaymentServiceProxySetupRecurringRequest` |
| [RecurringPaymentService.Charge](#recurringpaymentservicecharge) | Mandates | `RecurringPaymentServiceChargeRequest` |
| [PaymentService.Refund](#paymentservicerefund) | Payments | `PaymentServiceRefundRequest` |
| [RefundService.Get](#refundserviceget) | Refunds | `RefundServiceGetRequest` |
| [PaymentService.SetupRecurring](#paymentservicesetuprecurring) | Payments | `PaymentServiceSetupRecurringRequest` |
| [PaymentMethodService.Tokenize](#paymentmethodservicetokenize) | Payments | `PaymentMethodServiceTokenizeRequest` |
| [PaymentService.Void](#paymentservicevoid) | Payments | `PaymentServiceVoidRequest` |

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
| Bancontact | ✓ |
| Apple Pay | ✓ |
| Apple Pay Dec | ✓ |
| Apple Pay SDK | ⚠ |
| Google Pay | ✓ |
| Google Pay Dec | ? |
| Google Pay SDK | ⚠ |
| PayPal SDK | ⚠ |
| Amazon Pay | ✓ |
| Cash App | ✓ |
| PayPal | ⚠ |
| WeChat Pay | ✓ |
| Alipay | ✓ |
| Revolut Pay | ✓ |
| MiFinity | ⚠ |
| Bluecode | ⚠ |
| Paze | x |
| Samsung Pay | ⚠ |
| MB Way | ⚠ |
| Satispay | ⚠ |
| Wero | ⚠ |
| Affirm | ✓ |
| Afterpay | ✓ |
| Klarna | ✓ |
| UPI Collect | ⚠ |
| UPI Intent | ⚠ |
| UPI QR | ⚠ |
| Thailand | ⚠ |
| Czech | ⚠ |
| Finland | ⚠ |
| FPX | ⚠ |
| Poland | ⚠ |
| Slovakia | ⚠ |
| UK | ⚠ |
| PIS | x |
| Generic | ⚠ |
| Local | ⚠ |
| iDEAL | ✓ |
| Sofort | ⚠ |
| Trustly | ⚠ |
| Giropay | ✓ |
| EPS | ✓ |
| Przelewy24 | ✓ |
| PSE | ⚠ |
| BLIK | ✓ |
| Interac | ⚠ |
| Bizum | ⚠ |
| EFT | ⚠ |
| DuitNow | x |
| ACH | ✓ |
| SEPA | ✓ |
| BACS | ✓ |
| Multibanco | ✓ |
| Instant | ⚠ |
| Instant FI | ⚠ |
| Instant PL | ⚠ |
| Pix | ⚠ |
| Permata | ⚠ |
| BCA | ⚠ |
| BNI VA | ⚠ |
| BRI VA | ⚠ |
| CIMB VA | ⚠ |
| Danamon VA | ⚠ |
| Mandiri VA | ⚠ |
| Local | ⚠ |
| Indonesian | ⚠ |
| ACH | ✓ |
| SEPA | ✓ |
| BACS | ✓ |
| BECS | ✓ |
| SEPA Guaranteed | ⚠ |
| Crypto | x |
| Reward | ⚠ |
| Givex | x |
| PaySafeCard | x |
| E-Voucher | ⚠ |
| Boleto | ⚠ |
| Efecty | ⚠ |
| Pago Efectivo | ⚠ |
| Red Compra | ⚠ |
| Red Pagos | ⚠ |
| Alfamart | ⚠ |
| Indomaret | ⚠ |
| Oxxo | ⚠ |
| 7-Eleven | ⚠ |
| Lawson | ⚠ |
| Mini Stop | ⚠ |
| Family Mart | ⚠ |
| Seicomart | ⚠ |
| Pay Easy | ⚠ |

**Payment method objects** — use these in the `payment_method` field of the Authorize request.

##### Card (Raw PAN)

```python
"payment_method": {
    "card": {  # Generic card payment.
        "card_number": {"value": "4111111111111111"},  # Card Identification.
        "card_exp_month": {"value": "03"},
        "card_exp_year": {"value": "2030"},
        "card_cvc": {"value": "737"},
        "card_holder_name": {"value": "John Doe"}  # Cardholder Information.
    }
}
```

##### Google Pay

```python
"payment_method": {
    "google_pay": {  # Google Pay.
        "type": "CARD",  # Type of payment method.
        "description": "Visa 1111",  # User-facing description of the payment method.
        "info": {
            "card_network": "VISA",  # Card network name.
            "card_details": "1111"  # Card details (usually last 4 digits).
        },
        "tokenization_data": {
            "encrypted_data": {  # Encrypted Google Pay payment data.
                "token_type": "PAYMENT_GATEWAY",  # The type of the token.
                "token": "{\"id\":\"tok_probe_gpay\",\"object\":\"token\",\"type\":\"card\"}"  # Token generated for the wallet.
            }
        }
    }
}
```

##### Apple Pay

```python
"payment_method": {
    "apple_pay": {  # Apple Pay.
        "payment_data": {
            "encrypted_data": "eyJ2ZXJzaW9uIjoiRUNfdjEiLCJkYXRhIjoicHJvYmUiLCJzaWduYXR1cmUiOiJwcm9iZSJ9"  # Encrypted Apple Pay payment data as string.
        },
        "payment_method": {
            "display_name": "Visa 1111",
            "network": "Visa",
            "type": "debit"
        },
        "transaction_identifier": "probe_txn_id"  # Transaction identifier.
    }
}
```

##### SEPA Direct Debit

```python
"payment_method": {
    "sepa": {  # Sepa - Single Euro Payments Area direct debit.
        "iban": {"value": "DE89370400440532013000"},  # International bank account number (iban) for SEPA.
        "bank_account_holder_name": {"value": "John Doe"}  # Owner name for bank debit.
    }
}
```

##### BACS Direct Debit

```python
"payment_method": {
    "bacs": {  # Bacs - Bankers' Automated Clearing Services.
        "account_number": {"value": "55779911"},  # Account number for Bacs payment method.
        "sort_code": {"value": "200000"},  # Sort code for Bacs payment method.
        "bank_account_holder_name": {"value": "John Doe"}  # Holder name for bank debit.
    }
}
```

##### ACH Direct Debit

```python
"payment_method": {
    "ach": {  # Ach - Automated Clearing House.
        "account_number": {"value": "000123456789"},  # Account number for ach bank debit payment.
        "routing_number": {"value": "110000000"},  # Routing number for ach bank debit payment.
        "bank_account_holder_name": {"value": "John Doe"}  # Bank account holder name.
    }
}
```

##### BECS Direct Debit

```python
"payment_method": {
    "becs": {  # Becs - Bulk Electronic Clearing System - Australian direct debit.
        "account_number": {"value": "000123456"},  # Account number for Becs payment method.
        "bsb_number": {"value": "000000"},  # Bank-State-Branch (bsb) number.
        "bank_account_holder_name": {"value": "John Doe"}  # Owner name for bank debit.
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
    "klarna": {  # Klarna - Swedish BNPL service.
    }
}
```

##### Afterpay / Clearpay

```python
"payment_method": {
    "afterpay_clearpay": {  # Afterpay/Clearpay - BNPL service.
    }
}
```

##### Affirm

```python
"payment_method": {
    "affirm": {  # Affirm - US BNPL service.
    }
}
```

**Examples:** [Python](../../examples/stripe/python/stripe.py#L405) · [JavaScript](../../examples/stripe/javascript/stripe.js#L375) · [Kotlin](../../examples/stripe/kotlin/stripe.kt#L214) · [Rust](../../examples/stripe/rust/stripe.rs#L377)

#### PaymentService.Capture

Finalize an authorized payment by transferring funds. Captures the authorized amount to complete the transaction and move funds to your merchant account.

| | Message |
|---|---------|
| **Request** | `PaymentServiceCaptureRequest` |
| **Response** | `PaymentServiceCaptureResponse` |

**Examples:** [Python](../../examples/stripe/python/stripe.py#L414) · [JavaScript](../../examples/stripe/javascript/stripe.js#L384) · [Kotlin](../../examples/stripe/kotlin/stripe.kt#L226) · [Rust](../../examples/stripe/rust/stripe.rs#L389)

#### PaymentService.Get

Retrieve current payment status from the payment processor. Enables synchronization between your system and payment processors for accurate state tracking.

| | Message |
|---|---------|
| **Request** | `PaymentServiceGetRequest` |
| **Response** | `PaymentServiceGetResponse` |

**Examples:** [Python](../../examples/stripe/python/stripe.py#L441) · [JavaScript](../../examples/stripe/javascript/stripe.js#L411) · [Kotlin](../../examples/stripe/kotlin/stripe.kt#L265) · [Rust](../../examples/stripe/rust/stripe.rs#L410)

#### PaymentService.IncrementalAuthorization

Increase the authorized amount for an existing payment. Enables you to capture additional funds when the transaction amount changes after initial authorization.

| | Message |
|---|---------|
| **Request** | `PaymentServiceIncrementalAuthorizationRequest` |
| **Response** | `PaymentServiceIncrementalAuthorizationResponse` |

**Examples:** [Python](../../examples/stripe/python/stripe.py#L450) · [JavaScript](../../examples/stripe/javascript/stripe.js#L420) · [Kotlin](../../examples/stripe/kotlin/stripe.kt#L273) · [Rust](../../examples/stripe/rust/stripe.rs#L417)

#### PaymentService.ProxyAuthorize

Authorize using vault-aliased card data. Proxy substitutes before connector.

| | Message |
|---|---------|
| **Request** | `PaymentServiceProxyAuthorizeRequest` |
| **Response** | `PaymentServiceAuthorizeResponse` |

**Examples:** [Python](../../examples/stripe/python/stripe.py#L459) · [JavaScript](../../examples/stripe/javascript/stripe.js#L429) · [Kotlin](../../examples/stripe/kotlin/stripe.kt#L289) · [Rust](../../examples/stripe/rust/stripe.rs#L424)

#### PaymentService.ProxySetupRecurring

Setup recurring mandate using vault-aliased card data.

| | Message |
|---|---------|
| **Request** | `PaymentServiceProxySetupRecurringRequest` |
| **Response** | `PaymentServiceSetupRecurringResponse` |

**Examples:** [Python](../../examples/stripe/python/stripe.py#L468) · [JavaScript](../../examples/stripe/javascript/stripe.js#L438) · [Kotlin](../../examples/stripe/kotlin/stripe.kt#L317) · [Rust](../../examples/stripe/rust/stripe.rs#L431)

#### PaymentService.Refund

Process a partial or full refund for a captured payment. Returns funds to the customer when goods are returned or services are cancelled.

| | Message |
|---|---------|
| **Request** | `PaymentServiceRefundRequest` |
| **Response** | `RefundResponse` |

**Examples:** [Python](../../examples/stripe/python/stripe.py#L486) · [JavaScript](../../examples/stripe/javascript/stripe.js#L456) · [Kotlin](../../examples/stripe/kotlin/stripe.kt#L379) · [Rust](../../examples/stripe/rust/stripe.rs#L445)

#### PaymentService.SetupRecurring

Configure a payment method for recurring billing. Sets up the mandate and payment details needed for future automated charges.

| | Message |
|---|---------|
| **Request** | `PaymentServiceSetupRecurringRequest` |
| **Response** | `PaymentServiceSetupRecurringResponse` |

**Examples:** [Python](../../examples/stripe/python/stripe.py#L504) · [JavaScript](../../examples/stripe/javascript/stripe.js#L474) · [Kotlin](../../examples/stripe/kotlin/stripe.kt#L401) · [Rust](../../examples/stripe/rust/stripe.rs#L459)

#### PaymentMethodService.Tokenize

Tokenize payment method for secure storage. Replaces raw card details with secure token for one-click payments and recurring billing.

| | Message |
|---|---------|
| **Request** | `PaymentMethodServiceTokenizeRequest` |
| **Response** | `PaymentMethodServiceTokenizeResponse` |

**Examples:** [Python](../../examples/stripe/python/stripe.py#L513) · [JavaScript](../../examples/stripe/javascript/stripe.js#L483) · [Kotlin](../../examples/stripe/kotlin/stripe.kt#L440) · [Rust](../../examples/stripe/rust/stripe.rs#L469)

#### PaymentService.Void

Cancel an authorized payment that has not been captured. Releases held funds back to the customer's payment method when a transaction cannot be completed.

| | Message |
|---|---------|
| **Request** | `PaymentServiceVoidRequest` |
| **Response** | `PaymentServiceVoidResponse` |

**Examples:** [Python](../../examples/stripe/python/stripe.py#L522) · [JavaScript](../../examples/stripe/javascript/stripe.js#L492) · [Kotlin](../../examples/stripe/kotlin/stripe.kt#L466) · [Rust](../../examples/stripe/rust/stripe.rs#L476)

### Refunds

#### RefundService.Get

Retrieve refund status from the payment processor. Tracks refund progress through processor settlement for accurate customer communication.

| | Message |
|---|---------|
| **Request** | `RefundServiceGetRequest` |
| **Response** | `RefundResponse` |

**Examples:** [Python](../../examples/stripe/python/stripe.py#L495) · [JavaScript](../../examples/stripe/javascript/stripe.js#L465) · [Kotlin](../../examples/stripe/kotlin/stripe.kt#L389) · [Rust](../../examples/stripe/rust/stripe.rs#L452)

### Mandates

#### RecurringPaymentService.Charge

Charge using an existing stored recurring payment instruction. Processes repeat payments for subscriptions or recurring billing without collecting payment details.

| | Message |
|---|---------|
| **Request** | `RecurringPaymentServiceChargeRequest` |
| **Response** | `RecurringPaymentServiceChargeResponse` |

**Examples:** [Python](../../examples/stripe/python/stripe.py#L477) · [JavaScript](../../examples/stripe/javascript/stripe.js#L447) · [Kotlin](../../examples/stripe/kotlin/stripe.kt#L348) · [Rust](../../examples/stripe/rust/stripe.rs#L438)

### Customers

#### CustomerService.Create

Create customer record in the payment processor system. Stores customer details for future payment operations without re-sending personal information.

| | Message |
|---|---------|
| **Request** | `CustomerServiceCreateRequest` |
| **Response** | `CustomerServiceCreateResponse` |

**Examples:** [Python](../../examples/stripe/python/stripe.py#L432) · [JavaScript](../../examples/stripe/javascript/stripe.js#L402) · [Kotlin](../../examples/stripe/kotlin/stripe.kt#L252) · [Rust](../../examples/stripe/rust/stripe.rs#L403)

### Authentication

#### MerchantAuthenticationService.CreateClientAuthenticationToken

Initialize client-facing SDK sessions for wallets, device fingerprinting, etc. Returns structured data the client SDK needs to render payment/verification UI.

| | Message |
|---|---------|
| **Request** | `MerchantAuthenticationServiceCreateClientAuthenticationTokenRequest` |
| **Response** | `MerchantAuthenticationServiceCreateClientAuthenticationTokenResponse` |

**Examples:** [Python](../../examples/stripe/python/stripe.py#L423) · [JavaScript](../../examples/stripe/javascript/stripe.js#L393) · [Kotlin](../../examples/stripe/kotlin/stripe.kt#L236) · [Rust](../../examples/stripe/rust/stripe.rs#L396)
