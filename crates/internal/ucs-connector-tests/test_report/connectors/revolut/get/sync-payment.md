# Connector `revolut` / Suite `get` / Scenario `sync_payment`

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
  "merchant_transaction_id": "mti_bfd6681cfa2a4cb3a8e1a816de16cf4c",
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
  "capture_method": "AUTOMATIC",
  "customer": {
    "name": "Ava Miller",
    "email": {
      "value": "casey.8753@sandbox.example.com"
    },
    "id": "cust_3fb91a65878e4980999736ff7fb0ff50",
    "phone_number": "+911831154211"
  },
  "locale": "en-US",
  "address": {
    "shipping_address": {
      "first_name": {
        "value": "Emma"
      },
      "last_name": {
        "value": "Miller"
      },
      "line1": {
        "value": "2726 Main Rd"
      },
      "line2": {
        "value": "451 Pine St"
      },
      "line3": {
        "value": "1420 Market Dr"
      },
      "city": {
        "value": "Austin"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "20744"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "alex.6083@testmail.io"
      },
      "phone_number": {
        "value": "7992888781"
      },
      "phone_country_code": "+91"
    },
    "billing_address": {
      "first_name": {
        "value": "Ava"
      },
      "last_name": {
        "value": "Wilson"
      },
      "line1": {
        "value": "5666 Market Dr"
      },
      "line2": {
        "value": "3743 Pine St"
      },
      "line3": {
        "value": "9904 Market Rd"
      },
      "city": {
        "value": "Chicago"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "90166"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "jordan.2600@testmail.io"
      },
      "phone_number": {
        "value": "7688953713"
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
date: Tue, 24 Mar 2026 13:34:15 GMT
x-request-id: authorize_no3ds_auto_capture_credit_card_req

Response contents:
{
  "merchantTransactionId": "69c292d7-7197-a683-b9c6-03a06e91632d",
  "connectorTransactionId": "69c292d7-7197-a683-b9c6-03a06e91632d",
  "status": "AUTHENTICATION_PENDING",
  "statusCode": 200,
  "responseHeaders": {
    "cf-cache-status": "DYNAMIC",
    "cf-ray": "9e160d5e7a78f3eb-MAA",
    "connection": "keep-alive",
    "content-length": "1010",
    "content-type": "application/json",
    "date": "Tue, 24 Mar 2026 13:34:15 GMT",
    "request-id": "1G3KHZZSQWQXL",
    "server": "cloudflare",
    "set-cookie": "_cfuvid=NfSuv0NaWTnQw3wS2ApfalfAzqRgTB4cFp0gt7VU4fE-1774359255202-0.0.1.1-604800000; path=/; domain=.revolut.com; HttpOnly; Secure; SameSite=None",
    "strict-transport-security": "max-age=2592000; includeSubDomains; preload",
    "via": "1.1 google",
    "x-content-type-options": "nosniff"
  },
  "redirectionData": {
    "uri": {
      "uri": "https://sandbox-checkout.revolut.com/payment-link/6be3eb31-2c82-41f0-ab23-0151c304e12f"
    }
  },
  "rawConnectorResponse": {
    "value": "{\"id\":\"69c292d7-7197-a683-b9c6-03a06e91632d\",\"token\":\"6be3eb31-2c82-41f0-ab23-0151c304e12f\",\"type\":\"payment\",\"state\":\"pending\",\"created_at\":\"2026-03-24T13:34:15.016734Z\",\"updated_at\":\"2026-03-24T13:34:15.016734Z\",\"amount\":6000,\"currency\":\"USD\",\"outstanding_amount\":6000,\"capture_mode\":\"automatic\",\"description\":\"No3DS auto capture card payment (credit)\",\"checkout_url\":\"https://sandbox-checkout.revolut.com/payment-link/6be3eb31-2c82-41f0-ab23-0151c304e12f\",\"enforce_challenge\":\"automatic\",\"redirect_url\":\"https://example.com/payment/return\",\"authorisation_type\":\"final\",\"customer\":{\"id\":\"cf52c2a8-0185-46ca-bcd2-0684b2923154\",\"email\":\"casey.8753@sandbox.example.com\"},\"merchant_order_data\":{\"url\":\"https://example.com/payment/return\",\"reference\":\"mti_bfd6681cfa2a4cb3a8e1a816de16cf4c\"},\"shipping\":{\"address\":{\"street_line_1\":\"2726 Main Rd\",\"street_line_2\":\"451 Pine St\",\"region\":\"CA\",\"city\":\"Austin\",\"country_code\":\"US\",\"postcode\":\"20744\"},\"contact\":{\"email\":\"alex.6083@testmail.io\",\"phone\":\"+917992888781\"}}}"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://sandbox-merchant.revolut.com//api/orders\",\"method\":\"POST\",\"headers\":{\"Content-Type\":\"application/json\",\"Revolut-Api-Version\":\"2024-09-01\",\"via\":\"HyperSwitch\",\"Authorization\":\"Bearer ***MASKED***"},\"body\":{\"amount\":6000,\"currency\":\"USD\",\"description\":\"No3DS auto capture card payment (credit)\",\"customer\":{\"email\":\"casey.8753@sandbox.example.com\"},\"shipping\":{\"address\":{\"street_line_1\":\"2726 Main Rd\",\"street_line_2\":\"451 Pine St\",\"region\":\"CA\",\"city\":\"Austin\",\"country_code\":\"US\",\"postcode\":\"20744\"},\"contact\":{\"full_name\":\"Emma Miller\",\"phone\":\"+917992888781\",\"email\":\"alex.6083@testmail.io\"}},\"capture_mode\":\"automatic\",\"merchant_order_data\":{\"url\":\"https://example.com/payment/return\",\"reference\":\"mti_bfd6681cfa2a4cb3a8e1a816de16cf4c\"},\"redirect_url\":\"https://example.com/payment/return\"}}"
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
  -H "x-request-id: get_sync_payment_req" \
  -H "x-connector-request-reference-id: get_sync_payment_ref" \
  -H "x-auth: ***MASKED***" \
  -H "x-api-key: ***MASKED***" \
  -d @ localhost:8000 types.PaymentService/Get <<'JSON'
{
  "connector_transaction_id": "69c292d7-7197-a683-b9c6-03a06e91632d",
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
x-connector-request-reference-id: get_sync_payment_ref
x-merchant-id: test_merchant
x-request-id: get_sync_payment_req
x-tenant-id: default

Response headers received:
content-type: application/grpc
date: Tue, 24 Mar 2026 13:34:15 GMT
x-request-id: get_sync_payment_req

Response contents:
{
  "connectorTransactionId": "69c292d7-7197-a683-b9c6-03a06e91632d",
  "status": "AUTHENTICATION_PENDING",
  "statusCode": 200,
  "responseHeaders": {
    "cf-cache-status": "DYNAMIC",
    "cf-ray": "9e160d616c88f3eb-MAA",
    "connection": "keep-alive",
    "content-type": "application/json",
    "date": "Tue, 24 Mar 2026 13:34:15 GMT",
    "request-id": "A9TO96SQYTCM",
    "server": "cloudflare",
    "set-cookie": "_cfuvid=MCcDylUjTL06ai.xYcFdWmUmZpqgHX9B_Hbm4vEvPwY-1774359255664-0.0.1.1-604800000; path=/; domain=.revolut.com; HttpOnly; Secure; SameSite=None",
    "strict-transport-security": "max-age=2592000; includeSubDomains; preload",
    "transfer-encoding": "chunked",
    "via": "1.1 google",
    "x-content-type-options": "nosniff"
  },
  "rawConnectorResponse": {
    "value": "{\"id\":\"69c292d7-7197-a683-b9c6-03a06e91632d\",\"token\":\"6be3eb31-2c82-41f0-ab23-0151c304e12f\",\"type\":\"payment\",\"state\":\"pending\",\"created_at\":\"2026-03-24T13:34:15.016734Z\",\"updated_at\":\"2026-03-24T13:34:15.016734Z\",\"amount\":6000,\"currency\":\"USD\",\"outstanding_amount\":6000,\"capture_mode\":\"automatic\",\"description\":\"No3DS auto capture card payment (credit)\",\"checkout_url\":\"https://sandbox-checkout.revolut.com/payment-link/6be3eb31-2c82-41f0-ab23-0151c304e12f\",\"enforce_challenge\":\"automatic\",\"redirect_url\":\"https://example.com/payment/return\",\"authorisation_type\":\"final\",\"customer\":{\"id\":\"cf52c2a8-0185-46ca-bcd2-0684b2923154\",\"email\":\"casey.8753@sandbox.example.com\"},\"merchant_order_data\":{\"url\":\"https://example.com/payment/return\",\"reference\":\"mti_bfd6681cfa2a4cb3a8e1a816de16cf4c\"},\"shipping\":{\"address\":{\"street_line_1\":\"2726 Main Rd\",\"street_line_2\":\"451 Pine St\",\"region\":\"CA\",\"city\":\"Austin\",\"country_code\":\"US\",\"postcode\":\"20744\"},\"contact\":{\"email\":\"alex.6083@testmail.io\",\"phone\":\"+917992888781\"}}}"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://sandbox-merchant.revolut.com//api/orders/69c292d7-7197-a683-b9c6-03a06e91632d\",\"method\":\"GET\",\"headers\":{\"Authorization\":\"Bearer ***MASKED***",\"via\":\"HyperSwitch\",\"Content-Type\":\"application/json\",\"Revolut-Api-Version\":\"2024-09-01\"},\"body\":null}"
  },
  "merchantTransactionId": "69c292d7-7197-a683-b9c6-03a06e91632d"
}

Response trailers received:
(empty)
Sent 1 request and received 1 response
```

</details>


[Back to Connector Suite](../get.md) | [Back to Overview](../../../test_overview.md)
