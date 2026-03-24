# Connector `revolut` / Suite `capture` / Scenario `capture_with_merchant_order_id`

- Service: `PaymentService/Capture`
- PM / PMT: `-` / `-`
- Result: `FAIL`

**Error**

```text
assertion failed for field 'connector_transaction_id': expected field to exist
```

**Pre Requisites Executed**

<details>
<summary>1. authorize(no3ds_manual_capture_credit_card) — PASS</summary>

<details>
<summary>Show Dependency Request (masked)</summary>

```bash
grpcurl -plaintext \
  -H "x-connector: revolut" \
  -H "x-merchant-id: test_merchant" \
  -H "x-tenant-id: default" \
  -H "x-request-id: authorize_no3ds_manual_capture_credit_card_req" \
  -H "x-connector-request-reference-id: authorize_no3ds_manual_capture_credit_card_ref" \
  -H "x-auth: ***MASKED***" \
  -H "x-api-key: ***MASKED***" \
  -d @ localhost:8000 types.PaymentService/Authorize <<'JSON'
{
  "merchant_transaction_id": "mti_c30c163fd08c46c1ba8b9f77dbef28a8",
  "amount": {
    "minor_amount": 6000,
    "currency": "USD"
  },
  "order_tax_amount": 0,
  "shipping_cost": 0,
  "payment_method": {
    "card": {
      "card_number": ***MASKED***
        "value": "4111111111111111"
      },
      "card_exp_month": {
        "value": "08"
      },
      "card_exp_year": {
        "value": "30"
      },
      "card_cvc": ***MASKED***
        "value": "999"
      },
      "card_holder_name": {
        "value": "Emma Brown"
      },
      "card_type": "credit"
    }
  },
  "capture_method": "MANUAL",
  "customer": {
    "name": "Ethan Wilson",
    "email": {
      "value": "alex.9620@sandbox.example.com"
    },
    "id": "cust_f8f046dda1f84ec68fcc208503831cdd",
    "phone_number": "+448829303109"
  },
  "locale": "en-US",
  "address": {
    "shipping_address": {
      "first_name": {
        "value": "Ava"
      },
      "last_name": {
        "value": "Brown"
      },
      "line1": {
        "value": "3751 Market Ave"
      },
      "line2": {
        "value": "2836 Oak Blvd"
      },
      "line3": {
        "value": "4640 Sunset Blvd"
      },
      "city": {
        "value": "Los Angeles"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "33366"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "riley.8307@example.com"
      },
      "phone_number": {
        "value": "6838522844"
      },
      "phone_country_code": "+91"
    },
    "billing_address": {
      "first_name": {
        "value": "Liam"
      },
      "last_name": {
        "value": "Smith"
      },
      "line1": {
        "value": "211 Main Ave"
      },
      "line2": {
        "value": "655 Oak Dr"
      },
      "line3": {
        "value": "5103 Lake Rd"
      },
      "city": {
        "value": "Chicago"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "91150"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "riley.3202@testmail.io"
      },
      "phone_number": {
        "value": "5843127201"
      },
      "phone_country_code": "+91"
    }
  },
  "auth_type": "NO_THREE_DS",
  "enrolled_for_3ds": false,
  "return_url": "https://example.com/payment/return",
  "webhook_url": "https://example.com/payment/webhook",
  "complete_authorize_url": "https://example.com/payment/complete",
  "order_category": "physical",
  "setup_future_usage": "ON_SESSION",
  "off_session": false,
  "description": "No3DS manual capture card payment (credit)",
  "payment_channel": "ECOMMERCE",
  "test_mode": true
}
JSON
```

</details>

<details>
<summary>Show Dependency Response (masked)</summary>

```text
Resolved method descriptor:
// Authorize a payment amount on a payment method. This reserves funds
// without capturing them, essential for verifying availability before finalizing.
rpc Authorize ( .types.PaymentServiceAuthorizeRequest ) returns ( .types.PaymentServiceAuthorizeResponse );

Request metadata to send:
x-api-key: ***MASKED***
x-auth: ***MASKED***
x-connector: revolut
x-connector-request-reference-id: authorize_no3ds_manual_capture_credit_card_ref
x-merchant-id: test_merchant
x-request-id: authorize_no3ds_manual_capture_credit_card_req
x-tenant-id: default

Response headers received:
content-type: application/grpc
date: Tue, 24 Mar 2026 13:34:07 GMT
x-request-id: authorize_no3ds_manual_capture_credit_card_req

Response contents:
{
  "merchantTransactionId": "69c292cf-ea0a-aa81-b7cb-357f1d2dbc4f",
  "connectorTransactionId": "69c292cf-ea0a-aa81-b7cb-357f1d2dbc4f",
  "status": "AUTHENTICATION_PENDING",
  "statusCode": 200,
  "responseHeaders": {
    "cf-cache-status": "DYNAMIC",
    "cf-ray": "9e160d2dccc17f3a-MAA",
    "connection": "keep-alive",
    "content-length": "1019",
    "content-type": "application/json",
    "date": "Tue, 24 Mar 2026 13:34:07 GMT",
    "request-id": "1D0KRDBKZN33Q",
    "server": "cloudflare",
    "set-cookie": "_cfuvid=oucib1uMnbsjh6VpQosWkvxtW1BpR_WEe.GZZR8UiJs-1774359247432-0.0.1.1-604800000; path=/; domain=.revolut.com; HttpOnly; Secure; SameSite=None",
    "strict-transport-security": "max-age=2592000; includeSubDomains; preload",
    "via": "1.1 google",
    "x-content-type-options": "nosniff"
  },
  "redirectionData": {
    "uri": {
      "uri": "https://sandbox-checkout.revolut.com/payment-link/68a73dca-ee8f-4fa6-8fe1-1079a7bc1a36"
    }
  },
  "rawConnectorResponse": {
    "value": "{\"id\":\"69c292cf-ea0a-aa81-b7cb-357f1d2dbc4f\",\"token\":\"68a73dca-ee8f-4fa6-8fe1-1079a7bc1a36\",\"type\":\"payment\",\"state\":\"pending\",\"created_at\":\"2026-03-24T13:34:07.244748Z\",\"updated_at\":\"2026-03-24T13:34:07.244748Z\",\"amount\":6000,\"currency\":\"USD\",\"outstanding_amount\":6000,\"capture_mode\":\"manual\",\"description\":\"No3DS manual capture card payment (credit)\",\"checkout_url\":\"https://sandbox-checkout.revolut.com/payment-link/68a73dca-ee8f-4fa6-8fe1-1079a7bc1a36\",\"enforce_challenge\":\"automatic\",\"redirect_url\":\"https://example.com/payment/return\",\"authorisation_type\":\"final\",\"customer\":{\"id\":\"7ed86388-0140-408d-abd2-5810b341c632\",\"email\":\"alex.9620@sandbox.example.com\"},\"merchant_order_data\":{\"url\":\"https://example.com/payment/return\",\"reference\":\"mti_c30c163fd08c46c1ba8b9f77dbef28a8\"},\"shipping\":{\"address\":{\"street_line_1\":\"3751 Market Ave\",\"street_line_2\":\"2836 Oak Blvd\",\"region\":\"CA\",\"city\":\"Los Angeles\",\"country_code\":\"US\",\"postcode\":\"33366\"},\"contact\":{\"email\":\"riley.8307@example.com\",\"phone\":\"+916838522844\"}}}"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://sandbox-merchant.revolut.com//api/orders\",\"method\":\"POST\",\"headers\":{\"Authorization\":\"Bearer ***MASKED***",\"Revolut-Api-Version\":\"2024-09-01\",\"via\":\"HyperSwitch\",\"Content-Type\":\"application/json\"},\"body\":{\"amount\":6000,\"currency\":\"USD\",\"description\":\"No3DS manual capture card payment (credit)\",\"customer\":{\"email\":\"alex.9620@sandbox.example.com\"},\"shipping\":{\"address\":{\"street_line_1\":\"3751 Market Ave\",\"street_line_2\":\"2836 Oak Blvd\",\"region\":\"CA\",\"city\":\"Los Angeles\",\"country_code\":\"US\",\"postcode\":\"33366\"},\"contact\":{\"full_name\":\"Ava Brown\",\"phone\":\"+916838522844\",\"email\":\"riley.8307@example.com\"}},\"capture_mode\":\"manual\",\"merchant_order_data\":{\"url\":\"https://example.com/payment/return\",\"reference\":\"mti_c30c163fd08c46c1ba8b9f77dbef28a8\"},\"redirect_url\":\"https://example.com/payment/return\"}}"
  }
}

Response trailers received:
(empty)
Sent 1 request and received 1 response
```

</details>

</details>
<details>
<summary>Show Request (masked)</summary>

```bash
grpcurl -plaintext \
  -H "x-connector: revolut" \
  -H "x-merchant-id: test_merchant" \
  -H "x-tenant-id: default" \
  -H "x-request-id: capture_capture_with_merchant_order_id_req" \
  -H "x-connector-request-reference-id: capture_capture_with_merchant_order_id_ref" \
  -H "x-auth: ***MASKED***" \
  -H "x-api-key: ***MASKED***" \
  -d @ localhost:8000 types.PaymentService/Capture <<'JSON'
{
  "connector_transaction_id": "69c292cf-ea0a-aa81-b7cb-357f1d2dbc4f",
  "amount_to_capture": {
    "minor_amount": 6000,
    "currency": "USD"
  },
  "merchant_capture_id": "mci_fe5b44ae79504e07907479a9a5ca13d1",
  "merchant_order_id": "gen_171304"
}
JSON
```

</details>

<details>
<summary>Show Response (masked)</summary>

```text
Resolved method descriptor:
// Finalize an authorized payment transaction. Transfers reserved funds from
// customer to merchant account, completing the payment lifecycle.
rpc Capture ( .types.PaymentServiceCaptureRequest ) returns ( .types.PaymentServiceCaptureResponse );

Request metadata to send:
x-api-key: ***MASKED***
x-auth: ***MASKED***
x-connector: revolut
x-connector-request-reference-id: capture_capture_with_merchant_order_id_ref
x-merchant-id: test_merchant
x-request-id: capture_capture_with_merchant_order_id_req
x-tenant-id: default

Response headers received:
content-type: application/grpc
date: Tue, 24 Mar 2026 13:34:07 GMT
x-request-id: capture_capture_with_merchant_order_id_req

Response contents:
{
  "status": "PENDING",
  "error": {
    "connectorDetails": {
      "code": "order_invalid_state",
      "message": "Operation cannot be performed because order is in pending state and expected is [authorised, completed]",
      "reason": "Operation cannot be performed because order is in pending state and expected is [authorised, completed]"
    }
  },
  "statusCode": 422,
  "responseHeaders": {
    "cf-cache-status": "DYNAMIC",
    "cf-ray": "9e160d30d8497f3a-MAA",
    "connection": "keep-alive",
    "content-length": "172",
    "content-type": "application/json",
    "date": "Tue, 24 Mar 2026 13:34:07 GMT",
    "request-id": "1UEU4HEVWUROP",
    "server": "cloudflare",
    "set-cookie": "_cfuvid=YQ11msXlTm.CxKWsU5TLsaFW9SwN2sl7tQ.FIjYDiTY-1774359247883-0.0.1.1-604800000; path=/; domain=.revolut.com; HttpOnly; Secure; SameSite=None",
    "strict-transport-security": "max-age=2592000; includeSubDomains; preload",
    "via": "1.1 google",
    "x-content-type-options": "nosniff"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://sandbox-merchant.revolut.com//api/orders/69c292cf-ea0a-aa81-b7cb-357f1d2dbc4f/capture\",\"method\":\"POST\",\"headers\":{\"Revolut-Api-Version\":\"2024-09-01\",\"Content-Type\":\"application/json\",\"via\":\"HyperSwitch\",\"Authorization\":\"Bearer ***MASKED***"},\"body\":{\"amount\":6000}}"
  }
}

Response trailers received:
(empty)
Sent 1 request and received 1 response
```

</details>


[Back to Connector Suite](../capture.md) | [Back to Overview](../../../test_overview.md)
