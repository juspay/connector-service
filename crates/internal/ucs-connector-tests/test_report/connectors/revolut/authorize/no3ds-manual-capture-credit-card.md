# Connector `revolut` / Suite `authorize` / Scenario `no3ds_manual_capture_credit_card`

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
  -H "x-request-id: authorize_no3ds_manual_capture_credit_card_req" \
  -H "x-connector-request-reference-id: authorize_no3ds_manual_capture_credit_card_ref" \
  -H "x-auth: ***MASKED***" \
  -H "x-api-key: ***MASKED***" \
  -d @ localhost:8000 types.PaymentService/Authorize <<'JSON'
{
  "merchant_transaction_id": "mti_3a2a8818588d475c84db23be5100cd05",
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
        "value": "Ethan Smith"
      },
      "card_type": "credit"
    }
  },
  "capture_method": "MANUAL",
  "customer": {
    "name": "Emma Miller",
    "email": {
      "value": "morgan.2750@testmail.io"
    },
    "id": "cust_eb58a8fe59c4419294e0abeb65a08cf7",
    "phone_number": "+19414181402"
  },
  "locale": "en-US",
  "address": {
    "shipping_address": {
      "first_name": {
        "value": "Ethan"
      },
      "last_name": {
        "value": "Brown"
      },
      "line1": {
        "value": "3375 Oak Ln"
      },
      "line2": {
        "value": "1083 Sunset Ave"
      },
      "line3": {
        "value": "8164 Lake St"
      },
      "city": {
        "value": "Austin"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "95552"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "morgan.7039@testmail.io"
      },
      "phone_number": {
        "value": "1629697684"
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
        "value": "5173 Oak Dr"
      },
      "line2": {
        "value": "2402 Sunset Blvd"
      },
      "line3": {
        "value": "4055 Pine Blvd"
      },
      "city": {
        "value": "San Francisco"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "78016"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "casey.3814@example.com"
      },
      "phone_number": {
        "value": "1683827244"
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
x-connector-request-reference-id: authorize_no3ds_manual_capture_credit_card_ref
x-merchant-id: test_merchant
x-request-id: authorize_no3ds_manual_capture_credit_card_req
x-tenant-id: default

Response headers received:
content-type: application/grpc
date: Tue, 24 Mar 2026 13:34:04 GMT
x-request-id: authorize_no3ds_manual_capture_credit_card_req

Response contents:
{
  "merchantTransactionId": "69c292cc-bbe9-a89a-9506-74eac04cb1d4",
  "connectorTransactionId": "69c292cc-bbe9-a89a-9506-74eac04cb1d4",
  "status": "AUTHENTICATION_PENDING",
  "statusCode": 200,
  "responseHeaders": {
    "cf-cache-status": "DYNAMIC",
    "cf-ray": "9e160d1b9e6a7f3a-MAA",
    "connection": "keep-alive",
    "content-length": "1007",
    "content-type": "application/json",
    "date": "Tue, 24 Mar 2026 13:34:04 GMT",
    "request-id": "UVWL9SE2MKES",
    "server": "cloudflare",
    "set-cookie": "_cfuvid=A6POlVjSDx608OLu.DiI1nY022cSoXr6Wnih1vCnZBU-1774359244507-0.0.1.1-604800000; path=/; domain=.revolut.com; HttpOnly; Secure; SameSite=None",
    "strict-transport-security": "max-age=2592000; includeSubDomains; preload",
    "via": "1.1 google",
    "x-content-type-options": "nosniff"
  },
  "redirectionData": {
    "uri": {
      "uri": "https://sandbox-checkout.revolut.com/payment-link/294500c3-a4ce-4597-a231-d0374ddb7784"
    }
  },
  "rawConnectorResponse": {
    "value": "{\"id\":\"69c292cc-bbe9-a89a-9506-74eac04cb1d4\",\"token\":\"294500c3-a4ce-4597-a231-d0374ddb7784\",\"type\":\"payment\",\"state\":\"pending\",\"created_at\":\"2026-03-24T13:34:04.325820Z\",\"updated_at\":\"2026-03-24T13:34:04.325820Z\",\"amount\":6000,\"currency\":\"USD\",\"outstanding_amount\":6000,\"capture_mode\":\"manual\",\"description\":\"No3DS manual capture card payment (credit)\",\"checkout_url\":\"https://sandbox-checkout.revolut.com/payment-link/294500c3-a4ce-4597-a231-d0374ddb7784\",\"enforce_challenge\":\"automatic\",\"redirect_url\":\"https://example.com/payment/return\",\"authorisation_type\":\"final\",\"customer\":{\"id\":\"728a856c-81a5-40ec-8455-dffa92d05c79\",\"email\":\"morgan.2750@testmail.io\"},\"merchant_order_data\":{\"url\":\"https://example.com/payment/return\",\"reference\":\"mti_3a2a8818588d475c84db23be5100cd05\"},\"shipping\":{\"address\":{\"street_line_1\":\"3375 Oak Ln\",\"street_line_2\":\"1083 Sunset Ave\",\"region\":\"CA\",\"city\":\"Austin\",\"country_code\":\"US\",\"postcode\":\"95552\"},\"contact\":{\"email\":\"morgan.7039@testmail.io\",\"phone\":\"+911629697684\"}}}"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://sandbox-merchant.revolut.com//api/orders\",\"method\":\"POST\",\"headers\":{\"Revolut-Api-Version\":\"2024-09-01\",\"Authorization\":\"Bearer ***MASKED***",\"Content-Type\":\"application/json\",\"via\":\"HyperSwitch\"},\"body\":{\"amount\":6000,\"currency\":\"USD\",\"description\":\"No3DS manual capture card payment (credit)\",\"customer\":{\"email\":\"morgan.2750@testmail.io\"},\"shipping\":{\"address\":{\"street_line_1\":\"3375 Oak Ln\",\"street_line_2\":\"1083 Sunset Ave\",\"region\":\"CA\",\"city\":\"Austin\",\"country_code\":\"US\",\"postcode\":\"95552\"},\"contact\":{\"full_name\":\"Ethan Brown\",\"phone\":\"+911629697684\",\"email\":\"morgan.7039@testmail.io\"}},\"capture_mode\":\"manual\",\"merchant_order_data\":{\"url\":\"https://example.com/payment/return\",\"reference\":\"mti_3a2a8818588d475c84db23be5100cd05\"},\"redirect_url\":\"https://example.com/payment/return\"}}"
  }
}

Response trailers received:
(empty)
Sent 1 request and received 1 response
```

</details>


[Back to Connector Suite](../authorize.md) | [Back to Overview](../../../test_overview.md)
