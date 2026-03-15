# Adyen

<!--
This file is auto-generated. Do not edit by hand.
Source: data/field_probe/adyen.json
Regenerate: python3 scripts/generate-connector-docs.py adyen
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
#     adyen=payment_pb2.AdyenConfig(api_key=...),
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
    connector: 'Adyen',
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
    .setConnector("Adyen")
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
    connector: "Adyen".to_string(),
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

**Examples:** [Python](../../examples/adyen/python/adyen.py#L120) · [JavaScript](../../examples/adyen/javascript/adyen.js#L111) · [Kotlin](../../examples/adyen/kotlin/adyen.kt#L143) · [Rust](../../examples/adyen/rust/adyen.rs#L130)

### Card Payment (Automatic Capture)

Authorize and capture in one call using `capture_method=AUTOMATIC`. Use for digital goods or immediate fulfillment.

**Response status handling:**

| Status | Recommended action |
|--------|-------------------|
| `AUTHORIZED` | Payment authorized and captured — funds will be settled automatically |
| `PENDING` | Payment processing — await webhook for final status before fulfilling |
| `FAILED` | Payment declined — surface error to customer, do not retry without new details |

**Examples:** [Python](../../examples/adyen/python/adyen.py#L145) · [JavaScript](../../examples/adyen/javascript/adyen.js#L137) · [Kotlin](../../examples/adyen/kotlin/adyen.kt#L165) · [Rust](../../examples/adyen/rust/adyen.rs#L152)

### Wallet Payment (Google Pay / Apple Pay)

Wallet payments pass an encrypted token from the browser/device SDK. Pass the token blob directly — do not decrypt client-side.

**Response status handling:**

| Status | Recommended action |
|--------|-------------------|
| `AUTHORIZED` | Payment authorized and captured — funds will be settled automatically |
| `PENDING` | Payment processing — await webhook for final status before fulfilling |
| `FAILED` | Payment declined — surface error to customer, do not retry without new details |

**Examples:** [Python](../../examples/adyen/python/adyen.py#L164) · [JavaScript](../../examples/adyen/javascript/adyen.js#L156) · [Kotlin](../../examples/adyen/kotlin/adyen.kt#L181) · [Rust](../../examples/adyen/rust/adyen.rs#L167)

### Bank Transfer (SEPA / ACH / BACS)

Direct bank debit (Sepa). Bank transfers typically use `capture_method=AUTOMATIC`.

**Response status handling:**

| Status | Recommended action |
|--------|-------------------|
| `AUTHORIZED` | Payment authorized and captured — funds will be settled automatically |
| `PENDING` | Payment processing — await webhook for final status before fulfilling |
| `FAILED` | Payment declined — surface error to customer, do not retry without new details |

**Examples:** [Python](../../examples/adyen/python/adyen.py#L259) · [JavaScript](../../examples/adyen/javascript/adyen.js#L248) · [Kotlin](../../examples/adyen/kotlin/adyen.kt#L270) · [Rust](../../examples/adyen/rust/adyen.rs#L257)

### Refund a Payment

Authorize with automatic capture, then refund the captured amount. `connector_transaction_id` from the Authorize response is reused for the Refund call.

**Examples:** [Python](../../examples/adyen/python/adyen.py#L344) · [JavaScript](../../examples/adyen/javascript/adyen.js#L330) · [Kotlin](../../examples/adyen/kotlin/adyen.kt#L349) · [Rust](../../examples/adyen/rust/adyen.rs#L337)

### Recurring / Mandate Payments

Store a payment mandate with SetupRecurring, then charge it repeatedly with RecurringPaymentService.Charge without requiring customer action.

**Response status handling:**

| Status | Recommended action |
|--------|-------------------|
| `PENDING` | Mandate stored — save connector_transaction_id for future RecurringPaymentService.Charge calls |
| `FAILED` | Setup failed — customer must re-enter payment details |

**Examples:** [Python](../../examples/adyen/python/adyen.py#L381) · [JavaScript](../../examples/adyen/javascript/adyen.js#L365) · [Kotlin](../../examples/adyen/kotlin/adyen.kt#L371) · [Rust](../../examples/adyen/rust/adyen.rs#L359)

### Void a Payment

Authorize funds with a manual capture flag, then cancel the authorization with Void before any capture occurs. Releases the hold on the customer's funds.

**Examples:** [Python](../../examples/adyen/python/adyen.py#L479) · [JavaScript](../../examples/adyen/javascript/adyen.js#L454) · [Kotlin](../../examples/adyen/kotlin/adyen.kt#L462) · [Rust](../../examples/adyen/rust/adyen.rs#L447)

## API Reference

| Flow (Service.RPC) | Category | gRPC Request Message |
|--------------------|----------|----------------------|
| [PaymentService.Authorize](#paymentserviceauthorize) | Payments | `PaymentServiceAuthorizeRequest` |
| [PaymentService.Capture](#paymentservicecapture) | Payments | `PaymentServiceCaptureRequest` |
| [DisputeService.Accept](#disputeserviceaccept) | Disputes | `DisputeServiceAcceptRequest` |
| [DisputeService.Defend](#disputeservicedefend) | Disputes | `DisputeServiceDefendRequest` |
| [DisputeService.SubmitEvidence](#disputeservicesubmitevidence) | Disputes | `DisputeServiceSubmitEvidenceRequest` |
| [RecurringPaymentService.Charge](#recurringpaymentservicecharge) | Mandates | `RecurringPaymentServiceChargeRequest` |
| [PaymentService.Refund](#paymentservicerefund) | Payments | `PaymentServiceRefundRequest` |
| [PaymentService.SetupRecurring](#paymentservicesetuprecurring) | Payments | `PaymentServiceSetupRecurringRequest` |
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
                "token": "{\"version\":\"ECv2\",\"signature\":\"<sig>\",\"intermediateSigningKey\":{\"signedKey\":\"<signed_key>\",\"signatures\":[\"<sig>\"]},\"signedMessage\":\"<signed_message>\"}",  # Token generated for the wallet
                "token_type": "PAYMENT_GATEWAY"  # The type of the token
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
            "encrypted_data": "<base64_encoded_apple_pay_payment_token>"  # Encrypted Apple Pay payment data as string
        },
        "payment_method": {
            "display_name": "Visa 1111",
            "network": "Visa",
            "type": "debit"
        },
        "transaction_identifier": "<apple_pay_transaction_identifier>"  # Transaction identifier
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

**Examples:** [Python](../../examples/adyen/python/adyen.py#L501) · [JavaScript](../../examples/adyen/javascript/adyen.js#L475) · [Kotlin](../../examples/adyen/kotlin/adyen.kt#L480) · [Rust](../../examples/adyen/rust/adyen.rs#L464)

#### PaymentService.Capture

Finalize an authorized payment transaction. Transfers reserved funds from customer to merchant account, completing the payment lifecycle.

| | Message |
|---|---------|
| **Request** | `PaymentServiceCaptureRequest` |
| **Response** | `PaymentServiceCaptureResponse` |

**Examples:** [Python](../../examples/adyen/python/adyen.py#L510) · [JavaScript](../../examples/adyen/javascript/adyen.js#L484) · [Kotlin](../../examples/adyen/kotlin/adyen.kt#L492) · [Rust](../../examples/adyen/rust/adyen.rs#L475)

#### PaymentService.Refund

Initiate a refund to customer's payment method. Returns funds for returns, cancellations, or service adjustments after original payment.

| | Message |
|---|---------|
| **Request** | `PaymentServiceRefundRequest` |
| **Response** | `RefundResponse` |

**Examples:** [Python](../../examples/adyen/python/adyen.py#L344) · [JavaScript](../../examples/adyen/javascript/adyen.js#L330) · [Kotlin](../../examples/adyen/kotlin/adyen.kt#L569) · [Rust](../../examples/adyen/rust/adyen.rs#L538)

#### PaymentService.SetupRecurring

Setup a recurring payment instruction for future payments/ debits. This could be for SaaS subscriptions, monthly bill payments, insurance payments and similar use cases.

| | Message |
|---|---------|
| **Request** | `PaymentServiceSetupRecurringRequest` |
| **Response** | `PaymentServiceSetupRecurringResponse` |

**Examples:** [Python](../../examples/adyen/python/adyen.py#L605) · [JavaScript](../../examples/adyen/javascript/adyen.js#L560) · [Kotlin](../../examples/adyen/kotlin/adyen.kt#L579) · [Rust](../../examples/adyen/rust/adyen.rs#L544)

#### PaymentService.Void

Cancel an authorized payment before capture. Releases held funds back to customer, typically used when orders are cancelled or abandoned.

| | Message |
|---|---------|
| **Request** | `PaymentServiceVoidRequest` |
| **Response** | `PaymentServiceVoidResponse` |

**Examples:** [Python](../../examples/adyen/python/adyen.py#L682) · [JavaScript](../../examples/adyen/javascript/adyen.js#L630) · [Kotlin](../../examples/adyen/kotlin/adyen.kt#L648) · [Rust](../../examples/adyen/rust/adyen.rs#L613)

### Mandates

#### RecurringPaymentService.Charge

Charge using an existing stored recurring payment instruction. Processes repeat payments for subscriptions or recurring billing without collecting payment details.

| | Message |
|---|---------|
| **Request** | `RecurringPaymentServiceChargeRequest` |
| **Response** | `RecurringPaymentServiceChargeResponse` |

**Examples:** [Python](../../examples/adyen/python/adyen.py#L572) · [JavaScript](../../examples/adyen/javascript/adyen.js#L531) · [Kotlin](../../examples/adyen/kotlin/adyen.kt#L540) · [Rust](../../examples/adyen/rust/adyen.rs#L513)

### Disputes

#### DisputeService.Accept

Concede dispute and accepts chargeback loss. Acknowledges liability and stops dispute defense process when evidence is insufficient.

| | Message |
|---|---------|
| **Request** | `DisputeServiceAcceptRequest` |
| **Response** | `DisputeServiceAcceptResponse` |

**Examples:** [Python](../../examples/adyen/python/adyen.py#L519) · [JavaScript](../../examples/adyen/javascript/adyen.js#L493) · [Kotlin](../../examples/adyen/kotlin/adyen.kt#L502) · [Rust](../../examples/adyen/rust/adyen.rs#L481)

#### DisputeService.Defend

Submit defense with reason code for dispute. Presents formal argument against customer's chargeback claim with supporting documentation.

| | Message |
|---|---------|
| **Request** | `DisputeServiceDefendRequest` |
| **Response** | `DisputeServiceDefendResponse` |

**Examples:** [Python](../../examples/adyen/python/adyen.py#L536) · [JavaScript](../../examples/adyen/javascript/adyen.js#L505) · [Kotlin](../../examples/adyen/kotlin/adyen.kt#L514) · [Rust](../../examples/adyen/rust/adyen.rs#L491)

#### DisputeService.SubmitEvidence

Upload evidence to dispute customer chargeback. Provides documentation like receipts and delivery proof to contest fraudulent transaction claims.

| | Message |
|---|---------|
| **Request** | `DisputeServiceSubmitEvidenceRequest` |
| **Response** | `DisputeServiceSubmitEvidenceResponse` |

**Examples:** [Python](../../examples/adyen/python/adyen.py#L554) · [JavaScript](../../examples/adyen/javascript/adyen.js#L518) · [Kotlin](../../examples/adyen/kotlin/adyen.kt#L527) · [Rust](../../examples/adyen/rust/adyen.rs#L502)
