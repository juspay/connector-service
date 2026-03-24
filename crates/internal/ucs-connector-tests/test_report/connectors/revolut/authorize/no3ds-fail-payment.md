# Connector `revolut` / Suite `authorize` / Scenario `no3ds_fail_payment`

- Service: `PaymentService/Authorize`
- PM / PMT: `card` / `credit`
- Result: `FAIL`

**Error**

```text
assertion failed for field 'error': expected field to exist
```

**Pre Requisites Executed**

- None
<details>
<summary>Show Request (masked)</summary>

```bash
grpcurl -plaintext \
  -H "x-connector: revolut" \
  -H "x-merchant-id: test_merchant" \
  -H "x-tenant-id: default" \
  -H "x-request-id: authorize_no3ds_fail_payment_req" \
  -H "x-connector-request-reference-id: authorize_no3ds_fail_payment_ref" \
  -H "x-auth: ***MASKED***" \
  -H "x-api-key: ***MASKED***" \
  -d @ localhost:8000 types.PaymentService/Authorize <<'JSON'
{
  "merchant_transaction_id": "mti_ba23a62b47694ee5866892b55239387c",
  "amount": {
    "minor_amount": 6000,
    "currency": "USD"
  },
  "order_tax_amount": 0,
  "shipping_cost": 0,
  "payment_method": {
    "card": {
      "card_number": ***MASKED***
        "value": "4000000000000002"
      },
      "card_exp_month": {
        "value": "01"
      },
      "card_exp_year": {
        "value": "35"
      },
      "card_cvc": ***MASKED***
        "value": "123"
      },
      "card_holder_name": {
        "value": "Noah Johnson"
      },
      "card_type": "credit"
    }
  },
  "capture_method": "AUTOMATIC",
  "customer": {
    "name": "Ava Smith",
    "email": {
      "value": "riley.2040@sandbox.example.com"
    },
    "id": "cust_9b31259516d4433aae5a773bf4bc8089",
    "phone_number": "+915048028661"
  },
  "locale": "en-US",
  "address": {
    "shipping_address": {
      "first_name": {
        "value": "Noah"
      },
      "last_name": {
        "value": "Johnson"
      },
      "line1": {
        "value": "3297 Sunset Rd"
      },
      "line2": {
        "value": "548 Market Ln"
      },
      "line3": {
        "value": "1945 Sunset Ave"
      },
      "city": {
        "value": "Chicago"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "37111"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "morgan.8958@example.com"
      },
      "phone_number": {
        "value": "2747136712"
      },
      "phone_country_code": "+91"
    },
    "billing_address": {
      "first_name": {
        "value": "Mia"
      },
      "last_name": {
        "value": "Johnson"
      },
      "line1": {
        "value": "6699 Lake Blvd"
      },
      "line2": {
        "value": "8571 Pine Ln"
      },
      "line3": {
        "value": "5292 Market Dr"
      },
      "city": {
        "value": "Chicago"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "26402"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "sam.3714@testmail.io"
      },
      "phone_number": {
        "value": "5650776897"
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
  "description": "No3DS fail payment flow",
  "payment_channel": "ECOMMERCE",
  "test_mode": true
}
JSON
```

</details>

<details>
<summary>Show Response (masked)</summary>

```text
Resolved method descriptor:
// Authorize a payment amount on a payment method. This reserves funds
// without capturing them, essential for verifying availability before finalizing.
rpc Authorize ( .types.PaymentServiceAuthorizeRequest ) returns ( .types.PaymentServiceAuthorizeResponse );

Request metadata to send:
x-api-key: ***MASKED***
x-auth: ***MASKED***
x-connector: revolut
x-connector-request-reference-id: authorize_no3ds_fail_payment_ref
x-merchant-id: test_merchant
x-request-id: authorize_no3ds_fail_payment_req
x-tenant-id: default

Response headers received:
content-type: application/grpc
date: Tue, 24 Mar 2026 13:34:04 GMT
x-request-id: authorize_no3ds_fail_payment_req

Response contents:
{
  "merchantTransactionId": "69c292cb-3080-ac72-9531-a4b5fdf8a432",
  "connectorTransactionId": "69c292cb-3080-ac72-9531-a4b5fdf8a432",
  "status": "AUTHENTICATION_PENDING",
  "statusCode": 200,
  "responseHeaders": {
    "cf-cache-status": "DYNAMIC",
    "cf-ray": "9e160d18ab307f3a-MAA",
    "connection": "keep-alive",
    "content-length": "1000",
    "content-type": "application/json",
    "date": "Tue, 24 Mar 2026 13:34:04 GMT",
    "request-id": "V4QO2V22YC4N",
    "server": "cloudflare",
    "set-cookie": "_cfuvid=RYmCMbZ8mWqJ801wKg0n4_rSFZNYn6kO853YyaHI2RA-1774359244032-0.0.1.1-604800000; path=/; domain=.revolut.com; HttpOnly; Secure; SameSite=None",
    "strict-transport-security": "max-age=2592000; includeSubDomains; preload",
    "via": "1.1 google",
    "x-content-type-options": "nosniff"
  },
  "redirectionData": {
    "uri": {
      "uri": "https://sandbox-checkout.revolut.com/payment-link/184ebf40-0128-4f54-a4cd-5cf1f8279fc5"
    }
  },
  "rawConnectorResponse": {
    "value": "{\"id\":\"69c292cb-3080-ac72-9531-a4b5fdf8a432\",\"token\":\"184ebf40-0128-4f54-a4cd-5cf1f8279fc5\",\"type\":\"payment\",\"state\":\"pending\",\"created_at\":\"2026-03-24T13:34:03.852490Z\",\"updated_at\":\"2026-03-24T13:34:03.852490Z\",\"amount\":6000,\"currency\":\"USD\",\"outstanding_amount\":6000,\"capture_mode\":\"automatic\",\"description\":\"No3DS fail payment flow\",\"checkout_url\":\"https://sandbox-checkout.revolut.com/payment-link/184ebf40-0128-4f54-a4cd-5cf1f8279fc5\",\"enforce_challenge\":\"automatic\",\"redirect_url\":\"https://example.com/payment/return\",\"authorisation_type\":\"final\",\"customer\":{\"id\":\"6ef23f68-5d4a-4887-a2d3-0ed4d21b39f8\",\"email\":\"riley.2040@sandbox.example.com\"},\"merchant_order_data\":{\"url\":\"https://example.com/payment/return\",\"reference\":\"mti_ba23a62b47694ee5866892b55239387c\"},\"shipping\":{\"address\":{\"street_line_1\":\"3297 Sunset Rd\",\"street_line_2\":\"548 Market Ln\",\"region\":\"CA\",\"city\":\"Chicago\",\"country_code\":\"US\",\"postcode\":\"37111\"},\"contact\":{\"email\":\"morgan.8958@example.com\",\"phone\":\"+912747136712\"}}}"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://sandbox-merchant.revolut.com//api/orders\",\"method\":\"POST\",\"headers\":{\"Content-Type\":\"application/json\",\"Revolut-Api-Version\":\"2024-09-01\",\"via\":\"HyperSwitch\",\"Authorization\":\"Bearer ***MASKED***"},\"body\":{\"amount\":6000,\"currency\":\"USD\",\"description\":\"No3DS fail payment flow\",\"customer\":{\"email\":\"riley.2040@sandbox.example.com\"},\"shipping\":{\"address\":{\"street_line_1\":\"3297 Sunset Rd\",\"street_line_2\":\"548 Market Ln\",\"region\":\"CA\",\"city\":\"Chicago\",\"country_code\":\"US\",\"postcode\":\"37111\"},\"contact\":{\"full_name\":\"Noah Johnson\",\"phone\":\"+912747136712\",\"email\":\"morgan.8958@example.com\"}},\"capture_mode\":\"automatic\",\"merchant_order_data\":{\"url\":\"https://example.com/payment/return\",\"reference\":\"mti_ba23a62b47694ee5866892b55239387c\"},\"redirect_url\":\"https://example.com/payment/return\"}}"
  }
}

Response trailers received:
(empty)
Sent 1 request and received 1 response
```

</details>


[Back to Connector Suite](../authorize.md) | [Back to Overview](../../../test_overview.md)
