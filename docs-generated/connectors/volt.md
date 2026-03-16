# Volt

<!--
This file is auto-generated. Do not edit by hand.
Source: data/field_probe/volt.json
Regenerate: python3 scripts/generate-connector-docs.py volt
-->

## Implemented Flows

| Flow (Service.RPC) | Category | gRPC Request Message |
|--------------------|----------|----------------------|
| [MerchantAuthenticationService.CreateAccessToken](#merchantauthenticationservicecreateaccesstoken) | Authentication | `MerchantAuthenticationServiceCreateAccessTokenRequest` |
| [PaymentService.Get](#paymentserviceget) | Payments | `PaymentServiceGetRequest` |
| [PaymentService.Refund](#paymentservicerefund) | Payments | `PaymentServiceRefundRequest` |

## Flow Details

### Payments

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
  },
  "state": {
    "access_token": {
      "token": "probe_access_token",
      "expires_in_seconds": 3600,
      "token_type": "Bearer"
    }
  }
}
```

#### PaymentService.Refund

Initiate a refund to customer's payment method. Returns funds for returns, cancellations, or service adjustments after original payment.

| | Message |
|---|---------|
| **Request** | `PaymentServiceRefundRequest` |
| **Response** | `RefundResponse` |

**Minimum Request**

```json
{
  "merchant_refund_id": "probe_refund_001",
  "connector_transaction_id": "probe_connector_txn_001",
  "payment_amount": 1000,
  "refund_amount": {
    "minor_amount": 1000,
    "currency": "USD"
  },
  "reason": "customer_request",
  "state": {
    "access_token": {
      "token": "probe_access_token",
      "expires_in_seconds": 3600,
      "token_type": "Bearer"
    }
  }
}
```

### Authentication

#### MerchantAuthenticationService.CreateAccessToken

Generate short-lived connector authentication token. Provides secure credentials for connector API access without storing secrets client-side.

| | Message |
|---|---------|
| **Request** | `MerchantAuthenticationServiceCreateAccessTokenRequest` |
| **Response** | `MerchantAuthenticationServiceCreateAccessTokenResponse` |

**Minimum Request**

```json
{}
```
