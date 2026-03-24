# Connector `revolut` / Suite `authorize` / Scenario `no3ds_manual_capture_debit_card`

- Service: `PaymentService/Authorize`
- PM / PMT: `card` / `debit`
- Result: `PASS`

**Pre Requisites Executed**

- None
<details>
<summary>Show Request (masked)</summary>

```bash
grpcurl -plaintext \
  -H "x-connector: revolut" \
  -H "x-merchant-id: test_merchant" \
  -H "x-tenant-id: default" \
  -H "x-request-id: authorize_no3ds_manual_capture_debit_card_req" \
  -H "x-connector-request-reference-id: authorize_no3ds_manual_capture_debit_card_ref" \
  -H "x-auth: ***MASKED***" \
  -H "x-api-key: ***MASKED***" \
  -d @ localhost:8000 types.PaymentService/Authorize <<'JSON'
{
  "merchant_transaction_id": "mti_1fb943c9774148389f23abd9e32f1e5c",
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
        "value": "Liam Taylor"
      },
      "card_type": "debit"
    }
  },
  "capture_method": "MANUAL",
  "customer": {
    "name": "Ava Brown",
    "email": {
      "value": "morgan.1827@testmail.io"
    },
    "id": "cust_ef9037b51c004de2a6d0f5b03b1ac7f7",
    "phone_number": "+912454045220"
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
        "value": "5565 Sunset St"
      },
      "line2": {
        "value": "8074 Oak Blvd"
      },
      "line3": {
        "value": "4167 Oak Rd"
      },
      "city": {
        "value": "Seattle"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "36663"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "alex.5101@sandbox.example.com"
      },
      "phone_number": {
        "value": "1712790256"
      },
      "phone_country_code": "+91"
    },
    "billing_address": {
      "first_name": {
        "value": "Ethan"
      },
      "last_name": {
        "value": "Johnson"
      },
      "line1": {
        "value": "3760 Sunset Blvd"
      },
      "line2": {
        "value": "7219 Main Ln"
      },
      "line3": {
        "value": "2382 Lake Rd"
      },
      "city": {
        "value": "Seattle"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "16904"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "alex.2315@testmail.io"
      },
      "phone_number": {
        "value": "1001529461"
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
  "description": "No3DS manual capture card payment (debit)",
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
x-connector-request-reference-id: authorize_no3ds_manual_capture_debit_card_ref
x-merchant-id: test_merchant
x-request-id: authorize_no3ds_manual_capture_debit_card_req
x-tenant-id: default

Response headers received:
content-type: application/grpc
date: Tue, 24 Mar 2026 13:34:05 GMT
x-request-id: authorize_no3ds_manual_capture_debit_card_req

Response contents:
{
  "merchantTransactionId": "69c292cc-44b9-aa2a-9871-af1eb4cf23c9",
  "connectorTransactionId": "69c292cc-44b9-aa2a-9871-af1eb4cf23c9",
  "status": "AUTHENTICATION_PENDING",
  "statusCode": 200,
  "responseHeaders": {
    "cf-cache-status": "DYNAMIC",
    "cf-ray": "9e160d1e99e57f3a-MAA",
    "connection": "keep-alive",
    "content-length": "1014",
    "content-type": "application/json",
    "date": "Tue, 24 Mar 2026 13:34:04 GMT",
    "request-id": "1HKF5RV94ZMPU",
    "server": "cloudflare",
    "set-cookie": "_cfuvid=3.ndd9tlBfscuvQZWO2Ipo8oJbL9IkaNm99PCl.onnE-1774359244990-0.0.1.1-604800000; path=/; domain=.revolut.com; HttpOnly; Secure; SameSite=None",
    "strict-transport-security": "max-age=2592000; includeSubDomains; preload",
    "via": "1.1 google",
    "x-content-type-options": "nosniff"
  },
  "redirectionData": {
    "uri": {
      "uri": "https://sandbox-checkout.revolut.com/payment-link/acdb6bf5-d1b6-46a5-8773-3395ce2a61e9"
    }
  },
  "rawConnectorResponse": {
    "value": "{\"id\":\"69c292cc-44b9-aa2a-9871-af1eb4cf23c9\",\"token\":\"acdb6bf5-d1b6-46a5-8773-3395ce2a61e9\",\"type\":\"payment\",\"state\":\"pending\",\"created_at\":\"2026-03-24T13:34:04.808130Z\",\"updated_at\":\"2026-03-24T13:34:04.808130Z\",\"amount\":6000,\"currency\":\"USD\",\"outstanding_amount\":6000,\"capture_mode\":\"manual\",\"description\":\"No3DS manual capture card payment (debit)\",\"checkout_url\":\"https://sandbox-checkout.revolut.com/payment-link/acdb6bf5-d1b6-46a5-8773-3395ce2a61e9\",\"enforce_challenge\":\"automatic\",\"redirect_url\":\"https://example.com/payment/return\",\"authorisation_type\":\"final\",\"customer\":{\"id\":\"717e3d68-d750-43bf-bb5e-88c737c92882\",\"email\":\"morgan.1827@testmail.io\"},\"merchant_order_data\":{\"url\":\"https://example.com/payment/return\",\"reference\":\"mti_1fb943c9774148389f23abd9e32f1e5c\"},\"shipping\":{\"address\":{\"street_line_1\":\"5565 Sunset St\",\"street_line_2\":\"8074 Oak Blvd\",\"region\":\"CA\",\"city\":\"Seattle\",\"country_code\":\"US\",\"postcode\":\"36663\"},\"contact\":{\"email\":\"alex.5101@sandbox.example.com\",\"phone\":\"+911712790256\"}}}"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://sandbox-merchant.revolut.com//api/orders\",\"method\":\"POST\",\"headers\":{\"Revolut-Api-Version\":\"2024-09-01\",\"Content-Type\":\"application/json\",\"Authorization\":\"Bearer ***MASKED***",\"via\":\"HyperSwitch\"},\"body\":{\"amount\":6000,\"currency\":\"USD\",\"description\":\"No3DS manual capture card payment (debit)\",\"customer\":{\"email\":\"morgan.1827@testmail.io\"},\"shipping\":{\"address\":{\"street_line_1\":\"5565 Sunset St\",\"street_line_2\":\"8074 Oak Blvd\",\"region\":\"CA\",\"city\":\"Seattle\",\"country_code\":\"US\",\"postcode\":\"36663\"},\"contact\":{\"full_name\":\"Noah Johnson\",\"phone\":\"+911712790256\",\"email\":\"alex.5101@sandbox.example.com\"}},\"capture_mode\":\"manual\",\"merchant_order_data\":{\"url\":\"https://example.com/payment/return\",\"reference\":\"mti_1fb943c9774148389f23abd9e32f1e5c\"},\"redirect_url\":\"https://example.com/payment/return\"}}"
  }
}

Response trailers received:
(empty)
Sent 1 request and received 1 response
```

</details>


[Back to Connector Suite](../authorize.md) | [Back to Overview](../../../test_overview.md)
