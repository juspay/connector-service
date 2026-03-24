# Connector `revolut` / Suite `authorize` / Scenario `no3ds_auto_capture_credit_card`

- Service: `PaymentService/Authorize`
- PM / PMT: `card` / `credit`
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
  -H "x-request-id: authorize_no3ds_auto_capture_credit_card_req" \
  -H "x-connector-request-reference-id: authorize_no3ds_auto_capture_credit_card_ref" \
  -H "x-auth: ***MASKED***" \
  -H "x-api-key: ***MASKED***" \
  -d @ localhost:8000 types.PaymentService/Authorize <<'JSON'
{
  "merchant_transaction_id": "mti_03e41a3a77c9409e863804d8fd4f2066",
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
        "value": "Ethan Miller"
      },
      "card_type": "credit"
    }
  },
  "capture_method": "AUTOMATIC",
  "customer": {
    "name": "Liam Miller",
    "email": {
      "value": "riley.5999@testmail.io"
    },
    "id": "cust_457abe70d98c4cb799993e2daaf39010",
    "phone_number": "+11812775866"
  },
  "locale": "en-US",
  "address": {
    "shipping_address": {
      "first_name": {
        "value": "Ava"
      },
      "last_name": {
        "value": "Johnson"
      },
      "line1": {
        "value": "7166 Main Rd"
      },
      "line2": {
        "value": "7890 Sunset Rd"
      },
      "line3": {
        "value": "8823 Market St"
      },
      "city": {
        "value": "Chicago"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "86976"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "casey.3438@example.com"
      },
      "phone_number": {
        "value": "4617537912"
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
        "value": "908 Pine Dr"
      },
      "line2": {
        "value": "6488 Oak St"
      },
      "line3": {
        "value": "6724 Oak Blvd"
      },
      "city": {
        "value": "Seattle"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "12030"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "morgan.4063@sandbox.example.com"
      },
      "phone_number": {
        "value": "4275043338"
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
x-connector-request-reference-id: authorize_no3ds_auto_capture_credit_card_ref
x-merchant-id: test_merchant
x-request-id: authorize_no3ds_auto_capture_credit_card_req
x-tenant-id: default

Response headers received:
content-type: application/grpc
date: Tue, 24 Mar 2026 13:34:03 GMT
x-request-id: authorize_no3ds_auto_capture_credit_card_req

Response contents:
{
  "merchantTransactionId": "69c292ca-c80e-a1a2-b728-cb964019f066",
  "connectorTransactionId": "69c292ca-c80e-a1a2-b728-cb964019f066",
  "status": "AUTHENTICATION_PENDING",
  "statusCode": 200,
  "responseHeaders": {
    "cf-cache-status": "DYNAMIC",
    "cf-ray": "9e160d126bec7f3a-MAA",
    "connection": "keep-alive",
    "content-length": "1007",
    "content-type": "application/json",
    "date": "Tue, 24 Mar 2026 13:34:03 GMT",
    "request-id": "1C8MBTWTFT1K0",
    "server": "cloudflare",
    "set-cookie": "_cfuvid=j1ts0WDFxHYw9lx2.Eo7tWY1dfeYIHRMfEIx5bOZ0iU-1774359243067-0.0.1.1-604800000; path=/; domain=.revolut.com; HttpOnly; Secure; SameSite=None",
    "strict-transport-security": "max-age=2592000; includeSubDomains; preload",
    "via": "1.1 google",
    "x-content-type-options": "nosniff"
  },
  "redirectionData": {
    "uri": {
      "uri": "https://sandbox-checkout.revolut.com/payment-link/90edc8a7-74a9-4368-a83d-00f78f936759"
    }
  },
  "rawConnectorResponse": {
    "value": "{\"id\":\"69c292ca-c80e-a1a2-b728-cb964019f066\",\"token\":\"90edc8a7-74a9-4368-a83d-00f78f936759\",\"type\":\"payment\",\"state\":\"pending\",\"created_at\":\"2026-03-24T13:34:02.875685Z\",\"updated_at\":\"2026-03-24T13:34:02.875685Z\",\"amount\":6000,\"currency\":\"USD\",\"outstanding_amount\":6000,\"capture_mode\":\"automatic\",\"description\":\"No3DS auto capture card payment (credit)\",\"checkout_url\":\"https://sandbox-checkout.revolut.com/payment-link/90edc8a7-74a9-4368-a83d-00f78f936759\",\"enforce_challenge\":\"automatic\",\"redirect_url\":\"https://example.com/payment/return\",\"authorisation_type\":\"final\",\"customer\":{\"id\":\"57e1e11c-4abb-43af-b713-91b8f0fe70b1\",\"email\":\"riley.5999@testmail.io\"},\"merchant_order_data\":{\"url\":\"https://example.com/payment/return\",\"reference\":\"mti_03e41a3a77c9409e863804d8fd4f2066\"},\"shipping\":{\"address\":{\"street_line_1\":\"7166 Main Rd\",\"street_line_2\":\"7890 Sunset Rd\",\"region\":\"CA\",\"city\":\"Chicago\",\"country_code\":\"US\",\"postcode\":\"86976\"},\"contact\":{\"email\":\"casey.3438@example.com\",\"phone\":\"+914617537912\"}}}"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://sandbox-merchant.revolut.com//api/orders\",\"method\":\"POST\",\"headers\":{\"Content-Type\":\"application/json\",\"Authorization\":\"Bearer ***MASKED***",\"Revolut-Api-Version\":\"2024-09-01\",\"via\":\"HyperSwitch\"},\"body\":{\"amount\":6000,\"currency\":\"USD\",\"description\":\"No3DS auto capture card payment (credit)\",\"customer\":{\"email\":\"riley.5999@testmail.io\"},\"shipping\":{\"address\":{\"street_line_1\":\"7166 Main Rd\",\"street_line_2\":\"7890 Sunset Rd\",\"region\":\"CA\",\"city\":\"Chicago\",\"country_code\":\"US\",\"postcode\":\"86976\"},\"contact\":{\"full_name\":\"Ava Johnson\",\"phone\":\"+914617537912\",\"email\":\"casey.3438@example.com\"}},\"capture_mode\":\"automatic\",\"merchant_order_data\":{\"url\":\"https://example.com/payment/return\",\"reference\":\"mti_03e41a3a77c9409e863804d8fd4f2066\"},\"redirect_url\":\"https://example.com/payment/return\"}}"
  }
}

Response trailers received:
(empty)
Sent 1 request and received 1 response
```

</details>


[Back to Connector Suite](../authorize.md) | [Back to Overview](../../../test_overview.md)
