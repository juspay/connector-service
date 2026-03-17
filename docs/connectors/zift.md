# Zift

<!--
This file is auto-generated. Do not edit by hand.
Source: data/field_probe/zift.json
Regenerate: python3 scripts/generate-connector-docs.py zift
-->

## Implemented Flows

| Flow (Service.RPC) | Category | gRPC Request Message |
|--------------------|----------|----------------------|
| [PaymentService.Authorize](#paymentserviceauthorize) | Payments | `PaymentServiceAuthorizeRequest` |
| [PaymentService.Capture](#paymentservicecapture) | Payments | `PaymentServiceCaptureRequest` |
| [PaymentService.Get](#paymentserviceget) | Payments | `PaymentServiceGetRequest` |
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

**Card (Raw PAN)**

```json
{
  "merchant_transaction_id": "probe_txn_001",
  "amount": {
    "minor_amount": 1000,
    "currency": "USD"
  },
  "payment_method": {
    "card": {
      "card_number": "4111111111111111",
      "card_exp_month": "03",
      "card_exp_year": "2030",
      "card_cvc": "737",
      "card_holder_name": "John Doe"
    }
  },
  "capture_method": "AUTOMATIC",
  "customer": {
    "name": "John Doe",
    "email": "test@example.com",
    "id": "cust_probe_123",
    "phone_number": "4155552671",
    "phone_country_code": "+1"
  },
  "address": {
    "shipping_address": {
      "first_name": "John",
      "last_name": "Doe",
      "line1": "123 Main St",
      "city": "Seattle",
      "state": "WA",
      "zip_code": "98101",
      "country_alpha2_code": "US",
      "email": "test@example.com",
      "phone_number": "4155552671",
      "phone_country_code": "+1"
    },
    "billing_address": {
      "first_name": "John",
      "last_name": "Doe",
      "line1": "123 Main St",
      "city": "Seattle",
      "state": "WA",
      "zip_code": "98101",
      "country_alpha2_code": "US",
      "email": "test@example.com",
      "phone_number": "4155552671",
      "phone_country_code": "+1"
    }
  },
  "auth_type": "NO_THREE_DS",
  "return_url": "https://example.com/return",
  "webhook_url": "https://example.com/webhook",
  "complete_authorize_url": "https://example.com/complete",
  "browser_info": {
    "color_depth": 24,
    "screen_height": 900,
    "screen_width": 1440,
    "java_enabled": false,
    "java_script_enabled": true,
    "language": "en-US",
    "time_zone_offset_minutes": -480,
    "accept_header": "application/json",
    "user_agent": "Mozilla/5.0 (probe-bot)",
    "accept_language": "en-US,en;q=0.9",
    "ip_address": "1.2.3.4"
  }
}
```

#### PaymentService.Capture

Finalize an authorized payment transaction. Transfers reserved funds from customer to merchant account, completing the payment lifecycle.

| | Message |
|---|---------|
| **Request** | `PaymentServiceCaptureRequest` |
| **Response** | `PaymentServiceCaptureResponse` |

<!-- TODO: Add sample payload for `capture` in `scripts/connector-annotations/zift.yaml` -->

#### PaymentService.Get

Retrieve current payment status from the payment processor. Enables synchronization between your system and payment processors for accurate state tracking.

| | Message |
|---|---------|
| **Request** | `PaymentServiceGetRequest` |
| **Response** | `PaymentServiceGetResponse` |

<!-- TODO: Add sample payload for `get` in `scripts/connector-annotations/zift.yaml` -->

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
  "reason": "customer_request"
}
```

#### PaymentService.SetupRecurring

Setup a recurring payment instruction for future payments/ debits. This could be for SaaS subscriptions, monthly bill payments, insurance payments and similar use cases.

| | Message |
|---|---------|
| **Request** | `PaymentServiceSetupRecurringRequest` |
| **Response** | `PaymentServiceSetupRecurringResponse` |

**Minimum Request**

```json
{
  "merchant_recurring_payment_id": "probe_mandate_001",
  "amount": {
    "minor_amount": 0,
    "currency": "USD"
  },
  "payment_method": {
    "card": {
      "card_number": "4111111111111111",
      "card_exp_month": "03",
      "card_exp_year": "2030",
      "card_cvc": "737",
      "card_holder_name": "John Doe"
    }
  },
  "customer": {
    "name": "John Doe",
    "email": "test@example.com",
    "id": "cust_probe_123",
    "phone_number": "4155552671",
    "phone_country_code": "+1"
  },
  "address": {
    "billing_address": {
      "first_name": "John",
      "last_name": "Doe",
      "line1": "123 Main St",
      "city": "Seattle",
      "state": "WA",
      "zip_code": "98101",
      "country_alpha2_code": "US",
      "email": "test@example.com",
      "phone_number": "4155552671",
      "phone_country_code": "+1"
    }
  },
  "auth_type": "NO_THREE_DS",
  "enrolled_for_3ds": false,
  "return_url": "https://example.com/mandate-return",
  "setup_future_usage": "OFF_SESSION",
  "request_incremental_authorization": false,
  "customer_acceptance": {
    "acceptance_type": "OFFLINE",
    "accepted_at": 0
  },
  "browser_info": {
    "color_depth": 24,
    "screen_height": 900,
    "screen_width": 1440,
    "java_enabled": false,
    "java_script_enabled": true,
    "language": "en-US",
    "time_zone_offset_minutes": -480,
    "accept_header": "application/json",
    "user_agent": "Mozilla/5.0 (probe-bot)",
    "accept_language": "en-US,en;q=0.9",
    "ip_address": "1.2.3.4"
  }
}
```

#### PaymentService.Void

Cancel an authorized payment before capture. Releases held funds back to customer, typically used when orders are cancelled or abandoned.

| | Message |
|---|---------|
| **Request** | `PaymentServiceVoidRequest` |
| **Response** | `PaymentServiceVoidResponse` |

<!-- TODO: Add sample payload for `void` in `scripts/connector-annotations/zift.yaml` -->
