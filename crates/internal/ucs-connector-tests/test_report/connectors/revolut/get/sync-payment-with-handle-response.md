# Connector `revolut` / Suite `get` / Scenario `sync_payment_with_handle_response`

- Service: `PaymentService/Get`
- PM / PMT: `-` / `-`
- Result: `PASS`

**Pre Requisites Executed**

<details>
<summary>1. authorize(no3ds_auto_capture_credit_card) — PASS</summary>

<details>
<summary>Show Dependency Request (masked)</summary>

```bash
grpcurl -plaintext \
  -H "x-connector: revolut" \
  -H "x-merchant-id: test_merchant" \
  -H "x-tenant-id: default" \
  -H "x-request-id: authorize_no3ds_auto_capture_credit_card_req" \
  -H "x-connector-request-reference-id: authorize_no3ds_auto_capture_credit_card_ref" \
  -H "x-auth: ***MASKED***" \
  -H "x-api-key: ***MASKED***" \
  -d @ localhost:8000 types.PaymentService/Authorize <<'JSON'
{
  "merchant_transaction_id": "mti_4f1f5794a8d34ffa823c387acb96bbc7",
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
        "value": "Liam Brown"
      },
      "card_type": "credit"
    }
  },
  "capture_method": "AUTOMATIC",
  "customer": {
    "name": "Ethan Johnson",
    "email": {
      "value": "casey.8168@testmail.io"
    },
    "id": "cust_1ce7610176ee4b77bea1d2d90669644d",
    "phone_number": "+12455020330"
  },
  "locale": "en-US",
  "address": {
    "shipping_address": {
      "first_name": {
        "value": "Liam"
      },
      "last_name": {
        "value": "Taylor"
      },
      "line1": {
        "value": "9480 Pine Blvd"
      },
      "line2": {
        "value": "4394 Main Blvd"
      },
      "line3": {
        "value": "39 Sunset Rd"
      },
      "city": {
        "value": "New York"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "98967"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "riley.1616@testmail.io"
      },
      "phone_number": {
        "value": "4958245266"
      },
      "phone_country_code": "+91"
    },
    "billing_address": {
      "first_name": {
        "value": "Ethan"
      },
      "last_name": {
        "value": "Wilson"
      },
      "line1": {
        "value": "7461 Oak Blvd"
      },
      "line2": {
        "value": "5692 Market Ave"
      },
      "line3": {
        "value": "9481 Sunset Dr"
      },
      "city": {
        "value": "New York"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "89995"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "sam.4232@testmail.io"
      },
      "phone_number": {
        "value": "5373078862"
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
  "description": "No3DS auto capture card payment (credit)",
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
x-connector-request-reference-id: authorize_no3ds_auto_capture_credit_card_ref
x-merchant-id: test_merchant
x-request-id: authorize_no3ds_auto_capture_credit_card_req
x-tenant-id: default

Response headers received:
content-type: application/grpc
date: Tue, 24 Mar 2026 13:34:16 GMT
x-request-id: authorize_no3ds_auto_capture_credit_card_req

Response contents:
{
  "merchantTransactionId": "69c292d7-8fdf-a689-877e-a4363480336c",
  "connectorTransactionId": "69c292d7-8fdf-a689-877e-a4363480336c",
  "status": "AUTHENTICATION_PENDING",
  "statusCode": 200,
  "responseHeaders": {
    "cf-cache-status": "DYNAMIC",
    "cf-ray": "9e160d644e23f3eb-MAA",
    "connection": "keep-alive",
    "content-length": "1010",
    "content-type": "application/json",
    "date": "Tue, 24 Mar 2026 13:34:16 GMT",
    "request-id": "1HPGF8DLUT95O",
    "server": "cloudflare",
    "set-cookie": "_cfuvid=MQ7E9A119ayq_C1xTaBEWGL3_U62YbaEmxlI9eA7VJM-1774359256119-0.0.1.1-604800000; path=/; domain=.revolut.com; HttpOnly; Secure; SameSite=None",
    "strict-transport-security": "max-age=2592000; includeSubDomains; preload",
    "via": "1.1 google",
    "x-content-type-options": "nosniff"
  },
  "redirectionData": {
    "uri": {
      "uri": "https://sandbox-checkout.revolut.com/payment-link/f4d6a50b-80fc-4bba-92fd-039ee0799ca9"
    }
  },
  "rawConnectorResponse": {
    "value": "{\"id\":\"69c292d7-8fdf-a689-877e-a4363480336c\",\"token\":\"f4d6a50b-80fc-4bba-92fd-039ee0799ca9\",\"type\":\"payment\",\"state\":\"pending\",\"created_at\":\"2026-03-24T13:34:15.935445Z\",\"updated_at\":\"2026-03-24T13:34:15.935445Z\",\"amount\":6000,\"currency\":\"USD\",\"outstanding_amount\":6000,\"capture_mode\":\"automatic\",\"description\":\"No3DS auto capture card payment (credit)\",\"checkout_url\":\"https://sandbox-checkout.revolut.com/payment-link/f4d6a50b-80fc-4bba-92fd-039ee0799ca9\",\"enforce_challenge\":\"automatic\",\"redirect_url\":\"https://example.com/payment/return\",\"authorisation_type\":\"final\",\"customer\":{\"id\":\"af075e5e-383c-49d7-8cca-0fde09956567\",\"email\":\"casey.8168@testmail.io\"},\"merchant_order_data\":{\"url\":\"https://example.com/payment/return\",\"reference\":\"mti_4f1f5794a8d34ffa823c387acb96bbc7\"},\"shipping\":{\"address\":{\"street_line_1\":\"9480 Pine Blvd\",\"street_line_2\":\"4394 Main Blvd\",\"region\":\"CA\",\"city\":\"New York\",\"country_code\":\"US\",\"postcode\":\"98967\"},\"contact\":{\"email\":\"riley.1616@testmail.io\",\"phone\":\"+914958245266\"}}}"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://sandbox-merchant.revolut.com//api/orders\",\"method\":\"POST\",\"headers\":{\"via\":\"HyperSwitch\",\"Authorization\":\"Bearer ***MASKED***",\"Content-Type\":\"application/json\",\"Revolut-Api-Version\":\"2024-09-01\"},\"body\":{\"amount\":6000,\"currency\":\"USD\",\"description\":\"No3DS auto capture card payment (credit)\",\"customer\":{\"email\":\"casey.8168@testmail.io\"},\"shipping\":{\"address\":{\"street_line_1\":\"9480 Pine Blvd\",\"street_line_2\":\"4394 Main Blvd\",\"region\":\"CA\",\"city\":\"New York\",\"country_code\":\"US\",\"postcode\":\"98967\"},\"contact\":{\"full_name\":\"Liam Taylor\",\"phone\":\"+914958245266\",\"email\":\"riley.1616@testmail.io\"}},\"capture_mode\":\"automatic\",\"merchant_order_data\":{\"url\":\"https://example.com/payment/return\",\"reference\":\"mti_4f1f5794a8d34ffa823c387acb96bbc7\"},\"redirect_url\":\"https://example.com/payment/return\"}}"
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
  -H "x-request-id: get_sync_payment_with_handle_response_req" \
  -H "x-connector-request-reference-id: get_sync_payment_with_handle_response_ref" \
  -H "x-auth: ***MASKED***" \
  -H "x-api-key: ***MASKED***" \
  -d @ localhost:8000 types.PaymentService/Get <<'JSON'
{
  "connector_transaction_id": "69c292d7-8fdf-a689-877e-a4363480336c",
  "amount": {
    "minor_amount": 6000,
    "currency": "USD"
  }
}
JSON
```

</details>

<details>
<summary>Show Response (masked)</summary>

```text
Resolved method descriptor:
// Retrieve current payment status from the payment processor. Enables synchronization
// between your system and payment processors for accurate state tracking.
rpc Get ( .types.PaymentServiceGetRequest ) returns ( .types.PaymentServiceGetResponse );

Request metadata to send:
x-api-key: ***MASKED***
x-auth: ***MASKED***
x-connector: revolut
x-connector-request-reference-id: get_sync_payment_with_handle_response_ref
x-merchant-id: test_merchant
x-request-id: get_sync_payment_with_handle_response_req
x-tenant-id: default

Response headers received:
content-type: application/grpc
date: Tue, 24 Mar 2026 13:34:16 GMT
x-request-id: get_sync_payment_with_handle_response_req

Response contents:
{
  "connectorTransactionId": "69c292d7-8fdf-a689-877e-a4363480336c",
  "status": "AUTHENTICATION_PENDING",
  "statusCode": 200,
  "responseHeaders": {
    "cf-cache-status": "DYNAMIC",
    "cf-ray": "9e160d67685af3eb-MAA",
    "connection": "keep-alive",
    "content-type": "application/json",
    "date": "Tue, 24 Mar 2026 13:34:16 GMT",
    "request-id": "1WXT6G83ZGKOX",
    "server": "cloudflare",
    "set-cookie": "_cfuvid=ztYdUU1Z1ij9WW_FkckWwkwSyV2z41vFaXKRPMQjFpo-1774359256614-0.0.1.1-604800000; path=/; domain=.revolut.com; HttpOnly; Secure; SameSite=None",
    "strict-transport-security": "max-age=2592000; includeSubDomains; preload",
    "transfer-encoding": "chunked",
    "via": "1.1 google",
    "x-content-type-options": "nosniff"
  },
  "rawConnectorResponse": {
    "value": "{\"id\":\"69c292d7-8fdf-a689-877e-a4363480336c\",\"token\":\"f4d6a50b-80fc-4bba-92fd-039ee0799ca9\",\"type\":\"payment\",\"state\":\"pending\",\"created_at\":\"2026-03-24T13:34:15.935445Z\",\"updated_at\":\"2026-03-24T13:34:15.935445Z\",\"amount\":6000,\"currency\":\"USD\",\"outstanding_amount\":6000,\"capture_mode\":\"automatic\",\"description\":\"No3DS auto capture card payment (credit)\",\"checkout_url\":\"https://sandbox-checkout.revolut.com/payment-link/f4d6a50b-80fc-4bba-92fd-039ee0799ca9\",\"enforce_challenge\":\"automatic\",\"redirect_url\":\"https://example.com/payment/return\",\"authorisation_type\":\"final\",\"customer\":{\"id\":\"af075e5e-383c-49d7-8cca-0fde09956567\",\"email\":\"casey.8168@testmail.io\"},\"merchant_order_data\":{\"url\":\"https://example.com/payment/return\",\"reference\":\"mti_4f1f5794a8d34ffa823c387acb96bbc7\"},\"shipping\":{\"address\":{\"street_line_1\":\"9480 Pine Blvd\",\"street_line_2\":\"4394 Main Blvd\",\"region\":\"CA\",\"city\":\"New York\",\"country_code\":\"US\",\"postcode\":\"98967\"},\"contact\":{\"email\":\"riley.1616@testmail.io\",\"phone\":\"+914958245266\"}}}"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://sandbox-merchant.revolut.com//api/orders/69c292d7-8fdf-a689-877e-a4363480336c\",\"method\":\"GET\",\"headers\":{\"Authorization\":\"Bearer ***MASKED***",\"via\":\"HyperSwitch\",\"Revolut-Api-Version\":\"2024-09-01\",\"Content-Type\":\"application/json\"},\"body\":null}"
  },
  "merchantTransactionId": "69c292d7-8fdf-a689-877e-a4363480336c"
}

Response trailers received:
(empty)
Sent 1 request and received 1 response
```

</details>


[Back to Connector Suite](../get.md) | [Back to Overview](../../../test_overview.md)
