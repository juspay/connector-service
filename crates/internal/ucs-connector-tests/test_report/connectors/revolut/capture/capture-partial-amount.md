# Connector `revolut` / Suite `capture` / Scenario `capture_partial_amount`

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
  "merchant_transaction_id": "mti_b3563ac59aea404fa8d52857ab29b831",
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
        "value": "Ethan Johnson"
      },
      "card_type": "credit"
    }
  },
  "capture_method": "MANUAL",
  "customer": {
    "name": "Noah Brown",
    "email": {
      "value": "morgan.9547@example.com"
    },
    "id": "cust_df563a1303f2411b975785832058212d",
    "phone_number": "+11383236070"
  },
  "locale": "en-US",
  "address": {
    "shipping_address": {
      "first_name": {
        "value": "Ethan"
      },
      "last_name": {
        "value": "Taylor"
      },
      "line1": {
        "value": "2452 Lake St"
      },
      "line2": {
        "value": "5389 Lake Dr"
      },
      "line3": {
        "value": "7658 Main Blvd"
      },
      "city": {
        "value": "San Francisco"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "34774"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "riley.7432@sandbox.example.com"
      },
      "phone_number": {
        "value": "4650166264"
      },
      "phone_country_code": "+91"
    },
    "billing_address": {
      "first_name": {
        "value": "Liam"
      },
      "last_name": {
        "value": "Wilson"
      },
      "line1": {
        "value": "2173 Pine Ave"
      },
      "line2": {
        "value": "1070 Pine St"
      },
      "line3": {
        "value": "8616 Market Blvd"
      },
      "city": {
        "value": "New York"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "71308"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "sam.7953@sandbox.example.com"
      },
      "phone_number": {
        "value": "5688727439"
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
date: Tue, 24 Mar 2026 13:34:06 GMT
x-request-id: authorize_no3ds_manual_capture_credit_card_req

Response contents:
{
  "merchantTransactionId": "69c292ce-66b9-a5ba-94df-7d0a59c52715",
  "connectorTransactionId": "69c292ce-66b9-a5ba-94df-7d0a59c52715",
  "status": "AUTHENTICATION_PENDING",
  "statusCode": 200,
  "responseHeaders": {
    "cf-cache-status": "DYNAMIC",
    "cf-ray": "9e160d278d127f3a-MAA",
    "connection": "keep-alive",
    "content-length": "1019",
    "content-type": "application/json",
    "date": "Tue, 24 Mar 2026 13:34:06 GMT",
    "request-id": "96A2QMEKJPQG",
    "server": "cloudflare",
    "set-cookie": "_cfuvid=ptjftGsoETqTzyLqfQRzg8P6A9lEXurcyMqsjs4vjgA-1774359246419-0.0.1.1-604800000; path=/; domain=.revolut.com; HttpOnly; Secure; SameSite=None",
    "strict-transport-security": "max-age=2592000; includeSubDomains; preload",
    "via": "1.1 google",
    "x-content-type-options": "nosniff"
  },
  "redirectionData": {
    "uri": {
      "uri": "https://sandbox-checkout.revolut.com/payment-link/cf912ed3-13a2-482a-9b20-57eff2f3c199"
    }
  },
  "rawConnectorResponse": {
    "value": "{\"id\":\"69c292ce-66b9-a5ba-94df-7d0a59c52715\",\"token\":\"cf912ed3-13a2-482a-9b20-57eff2f3c199\",\"type\":\"payment\",\"state\":\"pending\",\"created_at\":\"2026-03-24T13:34:06.231810Z\",\"updated_at\":\"2026-03-24T13:34:06.231810Z\",\"amount\":6000,\"currency\":\"USD\",\"outstanding_amount\":6000,\"capture_mode\":\"manual\",\"description\":\"No3DS manual capture card payment (credit)\",\"checkout_url\":\"https://sandbox-checkout.revolut.com/payment-link/cf912ed3-13a2-482a-9b20-57eff2f3c199\",\"enforce_challenge\":\"automatic\",\"redirect_url\":\"https://example.com/payment/return\",\"authorisation_type\":\"final\",\"customer\":{\"id\":\"3d28b15c-7cf4-43ed-89ba-5559d679822d\",\"email\":\"morgan.9547@example.com\"},\"merchant_order_data\":{\"url\":\"https://example.com/payment/return\",\"reference\":\"mti_b3563ac59aea404fa8d52857ab29b831\"},\"shipping\":{\"address\":{\"street_line_1\":\"2452 Lake St\",\"street_line_2\":\"5389 Lake Dr\",\"region\":\"CA\",\"city\":\"San Francisco\",\"country_code\":\"US\",\"postcode\":\"34774\"},\"contact\":{\"email\":\"riley.7432@sandbox.example.com\",\"phone\":\"+914650166264\"}}}"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://sandbox-merchant.revolut.com//api/orders\",\"method\":\"POST\",\"headers\":{\"Authorization\":\"Bearer ***MASKED***",\"Content-Type\":\"application/json\",\"Revolut-Api-Version\":\"2024-09-01\",\"via\":\"HyperSwitch\"},\"body\":{\"amount\":6000,\"currency\":\"USD\",\"description\":\"No3DS manual capture card payment (credit)\",\"customer\":{\"email\":\"morgan.9547@example.com\"},\"shipping\":{\"address\":{\"street_line_1\":\"2452 Lake St\",\"street_line_2\":\"5389 Lake Dr\",\"region\":\"CA\",\"city\":\"San Francisco\",\"country_code\":\"US\",\"postcode\":\"34774\"},\"contact\":{\"full_name\":\"Ethan Taylor\",\"phone\":\"+914650166264\",\"email\":\"riley.7432@sandbox.example.com\"}},\"capture_mode\":\"manual\",\"merchant_order_data\":{\"url\":\"https://example.com/payment/return\",\"reference\":\"mti_b3563ac59aea404fa8d52857ab29b831\"},\"redirect_url\":\"https://example.com/payment/return\"}}"
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
  -H "x-request-id: capture_capture_partial_amount_req" \
  -H "x-connector-request-reference-id: capture_capture_partial_amount_ref" \
  -H "x-auth: ***MASKED***" \
  -H "x-api-key: ***MASKED***" \
  -d @ localhost:8000 types.PaymentService/Capture <<'JSON'
{
  "connector_transaction_id": "69c292ce-66b9-a5ba-94df-7d0a59c52715",
  "amount_to_capture": {
    "minor_amount": 3000,
    "currency": "USD"
  },
  "merchant_capture_id": "mci_071c6b61a2ae4b6e95509aa3bd29663e"
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
x-connector-request-reference-id: capture_capture_partial_amount_ref
x-merchant-id: test_merchant
x-request-id: capture_capture_partial_amount_req
x-tenant-id: default

Response headers received:
content-type: application/grpc
date: Tue, 24 Mar 2026 13:34:06 GMT
x-request-id: capture_capture_partial_amount_req

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
    "cf-ray": "9e160d2a98c57f3a-MAA",
    "connection": "keep-alive",
    "content-length": "172",
    "content-type": "application/json",
    "date": "Tue, 24 Mar 2026 13:34:06 GMT",
    "request-id": "1UQ6OUMXUOI02",
    "server": "cloudflare",
    "set-cookie": "_cfuvid=jkUCUNXuRDhbt.moqgeJOo9O4bJ6s_hZEP44wsU.PjE-1774359246872-0.0.1.1-604800000; path=/; domain=.revolut.com; HttpOnly; Secure; SameSite=None",
    "strict-transport-security": "max-age=2592000; includeSubDomains; preload",
    "via": "1.1 google",
    "x-content-type-options": "nosniff"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://sandbox-merchant.revolut.com//api/orders/69c292ce-66b9-a5ba-94df-7d0a59c52715/capture\",\"method\":\"POST\",\"headers\":{\"Authorization\":\"Bearer ***MASKED***",\"Revolut-Api-Version\":\"2024-09-01\",\"Content-Type\":\"application/json\",\"via\":\"HyperSwitch\"},\"body\":{\"amount\":3000}}"
  }
}

Response trailers received:
(empty)
Sent 1 request and received 1 response
```

</details>


[Back to Connector Suite](../capture.md) | [Back to Overview](../../../test_overview.md)
