# Paytm

<!--
This file is auto-generated. Do not edit by hand.
Source: data/field_probe/paytm.json
Regenerate: python3 scripts/generate-connector-docs.py paytm
-->

## Implemented Flows

| Flow (Service.RPC) | Category | gRPC Request Message |
|--------------------|----------|----------------------|
| [PaymentService.Authorize](#paymentserviceauthorize) | Payments | `PaymentServiceAuthorizeRequest` |
| [MerchantAuthenticationService.CreateSessionToken](#merchantauthenticationservicecreatesessiontoken) | Authentication | `MerchantAuthenticationServiceCreateSessionTokenRequest` |
| [PaymentService.Get](#paymentserviceget) | Payments | `PaymentServiceGetRequest` |

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
| Google Pay | — |
| Apple Pay | — |
| SEPA | — |
| BACS | — |
| ACH | — |
| BECS | — |
| iDEAL | — |
| PayPal | — |
| BLIK | — |
| Klarna | — |
| Afterpay | — |
| UPI | — |
| Affirm | — |

<!-- TODO: Add sample payload for `authorize` in `scripts/connector-annotations/paytm.yaml` -->

#### PaymentService.Get

Retrieve current payment status from the payment processor. Enables synchronization between your system and payment processors for accurate state tracking.

| | Message |
|---|---------|
| **Request** | `PaymentServiceGetRequest` |
| **Response** | `PaymentServiceGetResponse` |

**Minimum Request**

```json
{
  "connector_transaction_id": "probe_connector_txn_001",
  "amount": {
    "minor_amount": 1000,
    "currency": "USD"
  }
}
```

### Authentication

#### MerchantAuthenticationService.CreateSessionToken

Create session token for payment processing. Maintains session state across multiple payment operations for improved security and tracking.

| | Message |
|---|---------|
| **Request** | `MerchantAuthenticationServiceCreateSessionTokenRequest` |
| **Response** | `MerchantAuthenticationServiceCreateSessionTokenResponse` |

**Minimum Request**

```json
{
  "amount": {
    "minor_amount": 1000,
    "currency": "USD"
  }
}
```
