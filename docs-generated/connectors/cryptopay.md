# CryptoPay

<!--
This file is auto-generated. Do not edit by hand.
Source: data/field_probe/cryptopay.json
Regenerate: python3 scripts/generate-connector-docs.py cryptopay
-->

## Implemented Flows

| Flow (Service.RPC) | Category | gRPC Request Message |
|--------------------|----------|----------------------|
| [PaymentService.Get](#paymentserviceget) | Payments | `PaymentServiceGetRequest` |

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
  }
}
```
