# Bluesnap

<!--
This file is auto-generated. Do not edit by hand.
Source: data/field_probe/bluesnap.json
Regenerate: python3 scripts/generate-connector-docs.py bluesnap
-->

## Implemented Flows

| Flow (Service.RPC) | Category | gRPC Request Message |
|--------------------|----------|----------------------|
| [PaymentService.Authorize](#paymentserviceauthorize) | Payments | `PaymentServiceAuthorizeRequest` |
| [PaymentService.Capture](#paymentservicecapture) | Payments | `PaymentServiceCaptureRequest` |
| [PaymentService.Get](#paymentserviceget) | Payments | `PaymentServiceGetRequest` |
| [PaymentService.Refund](#paymentservicerefund) | Payments | `PaymentServiceRefundRequest` |
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
| ACH | ✓ |

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

**Google Pay**

```json
{
  "merchant_transaction_id": "probe_txn_001",
  "amount": {
    "minor_amount": 1000,
    "currency": "USD"
  },
  "payment_method": {
    "google_pay": {
      "type": "CARD",
      "description": "Visa 1111",
      "info": {
        "card_network": "VISA",
        "card_details": "1111"
      },
      "tokenization_data": {
        "encrypted_data": {
          "token": "{\"version\":\"ECv2\",\"signature\":\"<sig>\",\"intermediateSigningKey\":{\"signedKey\":\"<signed_key>\",\"signatures\":[\"<sig>\"]},\"signedMessage\":\"<signed_message>\"}",
          "token_type": "PAYMENT_GATEWAY"
        }
      }
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

**Apple Pay**

```json
{
  "merchant_transaction_id": "probe_txn_001",
  "amount": {
    "minor_amount": 1000,
    "currency": "USD"
  },
  "payment_method": {
    "apple_pay": {
      "payment_data": {
        "encrypted_data": "<base64_encoded_apple_pay_payment_token>"
      },
      "payment_method": {
        "display_name": "Visa 1111",
        "network": "Visa",
        "type": "debit"
      },
      "transaction_identifier": "<apple_pay_transaction_identifier>"
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

**ACH Direct Debit**

```json
{
  "merchant_transaction_id": "probe_txn_001",
  "amount": {
    "minor_amount": 1000,
    "currency": "USD"
  },
  "payment_method": {
    "ach": {
      "account_number": "000123456789",
      "routing_number": "110000000",
      "bank_account_holder_name": "John Doe"
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

**Minimum Request**

```json
{
  "merchant_capture_id": "probe_capture_001",
  "connector_transaction_id": "probe_connector_txn_001",
  "amount_to_capture": {
    "minor_amount": 1000,
    "currency": "USD"
  }
}
```

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

#### PaymentService.Void

Cancel an authorized payment before capture. Releases held funds back to customer, typically used when orders are cancelled or abandoned.

| | Message |
|---|---------|
| **Request** | `PaymentServiceVoidRequest` |
| **Response** | `PaymentServiceVoidResponse` |

**Minimum Request**

```json
{
  "merchant_void_id": "probe_void_001",
  "connector_transaction_id": "probe_connector_txn_001"
}
```
