# Connector `revolut` / Suite `authorize` / Scenario `no3ds_auto_capture_debit_card`

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
  -H "x-request-id: authorize_no3ds_auto_capture_debit_card_req" \
  -H "x-connector-request-reference-id: authorize_no3ds_auto_capture_debit_card_ref" \
  -H "x-auth: ***MASKED***" \
  -H "x-api-key: ***MASKED***" \
  -d @ localhost:8000 types.PaymentService/Authorize <<'JSON'
{
  "merchant_transaction_id": "mti_0be19884e77c4bb7be7d568561c97239",
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
        "value": "Liam Miller"
      },
      "card_type": "debit"
    }
  },
  "capture_method": "AUTOMATIC",
  "customer": {
    "name": "Mia Miller",
    "email": {
      "value": "sam.6489@sandbox.example.com"
    },
    "id": "cust_1f6efba562e94a29b1331ab31a6a850a",
    "phone_number": "+17452339082"
  },
  "locale": "en-US",
  "address": {
    "shipping_address": {
      "first_name": {
        "value": "Ethan"
      },
      "last_name": {
        "value": "Johnson"
      },
      "line1": {
        "value": "2709 Main Dr"
      },
      "line2": {
        "value": "2230 Main Dr"
      },
      "line3": {
        "value": "6531 Sunset Dr"
      },
      "city": {
        "value": "Austin"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "17723"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "morgan.7520@testmail.io"
      },
      "phone_number": {
        "value": "3017920271"
      },
      "phone_country_code": "+91"
    },
    "billing_address": {
      "first_name": {
        "value": "Emma"
      },
      "last_name": {
        "value": "Smith"
      },
      "line1": {
        "value": "7323 Main Ave"
      },
      "line2": {
        "value": "5138 Pine Dr"
      },
      "line3": {
        "value": "7939 Main St"
      },
      "city": {
        "value": "New York"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "93122"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "riley.3599@sandbox.example.com"
      },
      "phone_number": {
        "value": "8263999065"
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
  "description": "No3DS auto capture card payment (debit)",
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
x-connector-request-reference-id: authorize_no3ds_auto_capture_debit_card_ref
x-merchant-id: test_merchant
x-request-id: authorize_no3ds_auto_capture_debit_card_req
x-tenant-id: default

Response headers received:
content-type: application/grpc
date: Tue, 24 Mar 2026 13:34:03 GMT
x-request-id: authorize_no3ds_auto_capture_debit_card_req

Response contents:
{
  "merchantTransactionId": "69c292cb-13c0-a2db-82a2-b0e2c8f1da3e",
  "connectorTransactionId": "69c292cb-13c0-a2db-82a2-b0e2c8f1da3e",
  "status": "AUTHENTICATION_PENDING",
  "statusCode": 200,
  "responseHeaders": {
    "cf-cache-status": "DYNAMIC",
    "cf-ray": "9e160d158fa77f3a-MAA",
    "connection": "keep-alive",
    "content-length": "1010",
    "content-type": "application/json",
    "date": "Tue, 24 Mar 2026 13:34:03 GMT",
    "request-id": "1WUOCQ71COFQC",
    "server": "cloudflare",
    "set-cookie": "_cfuvid=1yXzzEuThuyIT947IMFYNbjO_OUh54ihzMnZX10QDVA-1774359243549-0.0.1.1-604800000; path=/; domain=.revolut.com; HttpOnly; Secure; SameSite=None",
    "strict-transport-security": "max-age=2592000; includeSubDomains; preload",
    "via": "1.1 google",
    "x-content-type-options": "nosniff"
  },
  "redirectionData": {
    "uri": {
      "uri": "https://sandbox-checkout.revolut.com/payment-link/5a37c7de-d780-4dfb-82c0-1c22ea57bc20"
    }
  },
  "rawConnectorResponse": {
    "value": "{\"id\":\"69c292cb-13c0-a2db-82a2-b0e2c8f1da3e\",\"token\":\"5a37c7de-d780-4dfb-82c0-1c22ea57bc20\",\"type\":\"payment\",\"state\":\"pending\",\"created_at\":\"2026-03-24T13:34:03.364760Z\",\"updated_at\":\"2026-03-24T13:34:03.364760Z\",\"amount\":6000,\"currency\":\"USD\",\"outstanding_amount\":6000,\"capture_mode\":\"automatic\",\"description\":\"No3DS auto capture card payment (debit)\",\"checkout_url\":\"https://sandbox-checkout.revolut.com/payment-link/5a37c7de-d780-4dfb-82c0-1c22ea57bc20\",\"enforce_challenge\":\"automatic\",\"redirect_url\":\"https://example.com/payment/return\",\"authorisation_type\":\"final\",\"customer\":{\"id\":\"684344ea-ee55-4e64-a9b6-f6602bd40f13\",\"email\":\"sam.6489@sandbox.example.com\"},\"merchant_order_data\":{\"url\":\"https://example.com/payment/return\",\"reference\":\"mti_0be19884e77c4bb7be7d568561c97239\"},\"shipping\":{\"address\":{\"street_line_1\":\"2709 Main Dr\",\"street_line_2\":\"2230 Main Dr\",\"region\":\"CA\",\"city\":\"Austin\",\"country_code\":\"US\",\"postcode\":\"17723\"},\"contact\":{\"email\":\"morgan.7520@testmail.io\",\"phone\":\"+913017920271\"}}}"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://sandbox-merchant.revolut.com//api/orders\",\"method\":\"POST\",\"headers\":{\"Authorization\":\"Bearer ***MASKED***",\"Content-Type\":\"application/json\",\"via\":\"HyperSwitch\",\"Revolut-Api-Version\":\"2024-09-01\"},\"body\":{\"amount\":6000,\"currency\":\"USD\",\"description\":\"No3DS auto capture card payment (debit)\",\"customer\":{\"email\":\"sam.6489@sandbox.example.com\"},\"shipping\":{\"address\":{\"street_line_1\":\"2709 Main Dr\",\"street_line_2\":\"2230 Main Dr\",\"region\":\"CA\",\"city\":\"Austin\",\"country_code\":\"US\",\"postcode\":\"17723\"},\"contact\":{\"full_name\":\"Ethan Johnson\",\"phone\":\"+913017920271\",\"email\":\"morgan.7520@testmail.io\"}},\"capture_mode\":\"automatic\",\"merchant_order_data\":{\"url\":\"https://example.com/payment/return\",\"reference\":\"mti_0be19884e77c4bb7be7d568561c97239\"},\"redirect_url\":\"https://example.com/payment/return\"}}"
  }
}

Response trailers received:
(empty)
Sent 1 request and received 1 response
```

</details>


[Back to Connector Suite](../authorize.md) | [Back to Overview](../../../test_overview.md)
