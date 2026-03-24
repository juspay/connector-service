# Connector `revolut` / Suite `capture` / Scenario `capture_full_amount`

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
  "merchant_transaction_id": "mti_5f1fa15ec7834e0b98e5525618ebd825",
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
        "value": "Mia Johnson"
      },
      "card_type": "credit"
    }
  },
  "capture_method": "MANUAL",
  "customer": {
    "name": "Noah Wilson",
    "email": {
      "value": "morgan.2789@testmail.io"
    },
    "id": "cust_60fa3b6976564e4a830ce77bafd99415",
    "phone_number": "+919483503838"
  },
  "locale": "en-US",
  "address": {
    "shipping_address": {
      "first_name": {
        "value": "Noah"
      },
      "last_name": {
        "value": "Brown"
      },
      "line1": {
        "value": "5339 Sunset Blvd"
      },
      "line2": {
        "value": "5199 Pine Ln"
      },
      "line3": {
        "value": "6912 Sunset Blvd"
      },
      "city": {
        "value": "San Francisco"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "95082"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "alex.1799@example.com"
      },
      "phone_number": {
        "value": "9251619780"
      },
      "phone_country_code": "+91"
    },
    "billing_address": {
      "first_name": {
        "value": "Noah"
      },
      "last_name": {
        "value": "Smith"
      },
      "line1": {
        "value": "5650 Pine Dr"
      },
      "line2": {
        "value": "7661 Lake Blvd"
      },
      "line3": {
        "value": "6395 Market Rd"
      },
      "city": {
        "value": "New York"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "19216"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "alex.7071@example.com"
      },
      "phone_number": {
        "value": "2337457558"
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
date: Tue, 24 Mar 2026 13:34:05 GMT
x-request-id: authorize_no3ds_manual_capture_credit_card_req

Response contents:
{
  "merchantTransactionId": "69c292cd-5121-a67a-882f-66f6507f4198",
  "connectorTransactionId": "69c292cd-5121-a67a-882f-66f6507f4198",
  "status": "AUTHENTICATION_PENDING",
  "statusCode": 200,
  "responseHeaders": {
    "cf-cache-status": "DYNAMIC",
    "cf-ray": "9e160d219d797f3a-MAA",
    "connection": "keep-alive",
    "content-length": "1014",
    "content-type": "application/json",
    "date": "Tue, 24 Mar 2026 13:34:05 GMT",
    "request-id": "BQIMZ2055CXD",
    "server": "cloudflare",
    "set-cookie": "_cfuvid=Q0lu3nnpKjqw4VhBTUllgWMQsePQKVD__T5tmuTKTQw-1774359245470-0.0.1.1-604800000; path=/; domain=.revolut.com; HttpOnly; Secure; SameSite=None",
    "strict-transport-security": "max-age=2592000; includeSubDomains; preload",
    "via": "1.1 google",
    "x-content-type-options": "nosniff"
  },
  "redirectionData": {
    "uri": {
      "uri": "https://sandbox-checkout.revolut.com/payment-link/50aedf26-40ca-468f-8916-dd6d58af7e89"
    }
  },
  "rawConnectorResponse": {
    "value": "{\"id\":\"69c292cd-5121-a67a-882f-66f6507f4198\",\"token\":\"50aedf26-40ca-468f-8916-dd6d58af7e89\",\"type\":\"payment\",\"state\":\"pending\",\"created_at\":\"2026-03-24T13:34:05.287774Z\",\"updated_at\":\"2026-03-24T13:34:05.287774Z\",\"amount\":6000,\"currency\":\"USD\",\"outstanding_amount\":6000,\"capture_mode\":\"manual\",\"description\":\"No3DS manual capture card payment (credit)\",\"checkout_url\":\"https://sandbox-checkout.revolut.com/payment-link/50aedf26-40ca-468f-8916-dd6d58af7e89\",\"enforce_challenge\":\"automatic\",\"redirect_url\":\"https://example.com/payment/return\",\"authorisation_type\":\"final\",\"customer\":{\"id\":\"e80c39e4-3a1b-4309-a628-5a1907ec6f48\",\"email\":\"morgan.2789@testmail.io\"},\"merchant_order_data\":{\"url\":\"https://example.com/payment/return\",\"reference\":\"mti_5f1fa15ec7834e0b98e5525618ebd825\"},\"shipping\":{\"address\":{\"street_line_1\":\"5339 Sunset Blvd\",\"street_line_2\":\"5199 Pine Ln\",\"region\":\"CA\",\"city\":\"San Francisco\",\"country_code\":\"US\",\"postcode\":\"95082\"},\"contact\":{\"email\":\"alex.1799@example.com\",\"phone\":\"+919251619780\"}}}"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://sandbox-merchant.revolut.com//api/orders\",\"method\":\"POST\",\"headers\":{\"Revolut-Api-Version\":\"2024-09-01\",\"Authorization\":\"Bearer ***MASKED***",\"via\":\"HyperSwitch\",\"Content-Type\":\"application/json\"},\"body\":{\"amount\":6000,\"currency\":\"USD\",\"description\":\"No3DS manual capture card payment (credit)\",\"customer\":{\"email\":\"morgan.2789@testmail.io\"},\"shipping\":{\"address\":{\"street_line_1\":\"5339 Sunset Blvd\",\"street_line_2\":\"5199 Pine Ln\",\"region\":\"CA\",\"city\":\"San Francisco\",\"country_code\":\"US\",\"postcode\":\"95082\"},\"contact\":{\"full_name\":\"Noah Brown\",\"phone\":\"+919251619780\",\"email\":\"alex.1799@example.com\"}},\"capture_mode\":\"manual\",\"merchant_order_data\":{\"url\":\"https://example.com/payment/return\",\"reference\":\"mti_5f1fa15ec7834e0b98e5525618ebd825\"},\"redirect_url\":\"https://example.com/payment/return\"}}"
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
  -H "x-request-id: capture_capture_full_amount_req" \
  -H "x-connector-request-reference-id: capture_capture_full_amount_ref" \
  -H "x-auth: ***MASKED***" \
  -H "x-api-key: ***MASKED***" \
  -d @ localhost:8000 types.PaymentService/Capture <<'JSON'
{
  "connector_transaction_id": "69c292cd-5121-a67a-882f-66f6507f4198",
  "amount_to_capture": {
    "minor_amount": 6000,
    "currency": "USD"
  },
  "merchant_capture_id": "mci_8d894e08edd94c9caa4846a7c2b8a96e"
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
x-connector-request-reference-id: capture_capture_full_amount_ref
x-merchant-id: test_merchant
x-request-id: capture_capture_full_amount_req
x-tenant-id: default

Response headers received:
content-type: application/grpc
date: Tue, 24 Mar 2026 13:34:05 GMT
x-request-id: capture_capture_full_amount_req

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
    "cf-ray": "9e160d2499497f3a-MAA",
    "connection": "keep-alive",
    "content-length": "172",
    "content-type": "application/json",
    "date": "Tue, 24 Mar 2026 13:34:05 GMT",
    "request-id": "127I54C9IKUYB",
    "server": "cloudflare",
    "set-cookie": "_cfuvid=0WBHZ6DtO8AHQzisP9BU0FwJBMsasJrLyeFnycDiv5k-1774359245944-0.0.1.1-604800000; path=/; domain=.revolut.com; HttpOnly; Secure; SameSite=None",
    "strict-transport-security": "max-age=2592000; includeSubDomains; preload",
    "via": "1.1 google",
    "x-content-type-options": "nosniff"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://sandbox-merchant.revolut.com//api/orders/69c292cd-5121-a67a-882f-66f6507f4198/capture\",\"method\":\"POST\",\"headers\":{\"Content-Type\":\"application/json\",\"Revolut-Api-Version\":\"2025-10-16\",\"Authorization\":\"Bearer ***MASKED***",\"via\":\"HyperSwitch\"},\"body\":{\"amount\":6000}}"
  }
}

Response trailers received:
(empty)
Sent 1 request and received 1 response
```

</details>


[Back to Connector Suite](../capture.md) | [Back to Overview](../../../test_overview.md)
