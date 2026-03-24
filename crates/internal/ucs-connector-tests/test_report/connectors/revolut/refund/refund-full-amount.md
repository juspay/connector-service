# Connector `revolut` / Suite `refund` / Scenario `refund_full_amount`

- Service: `PaymentService/Refund`
- PM / PMT: `-` / `-`
- Result: `FAIL`

**Error**

```text
assertion failed for field 'connector_refund_id': expected field to exist
```

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
  "merchant_transaction_id": "mti_eda70f917e9e41078526cfc83bd606ca",
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
        "value": "Ethan Wilson"
      },
      "card_type": "credit"
    }
  },
  "capture_method": "AUTOMATIC",
  "customer": {
    "name": "Ava Miller",
    "email": {
      "value": "riley.2457@testmail.io"
    },
    "id": "cust_b64b822ba6064b6a8558cac410c5e965",
    "phone_number": "+917973640239"
  },
  "locale": "en-US",
  "address": {
    "shipping_address": {
      "first_name": {
        "value": "Emma"
      },
      "last_name": {
        "value": "Johnson"
      },
      "line1": {
        "value": "177 Market Dr"
      },
      "line2": {
        "value": "1421 Pine St"
      },
      "line3": {
        "value": "8965 Main Ave"
      },
      "city": {
        "value": "Chicago"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "73665"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "jordan.3590@example.com"
      },
      "phone_number": {
        "value": "5776257503"
      },
      "phone_country_code": "+91"
    },
    "billing_address": {
      "first_name": {
        "value": "Noah"
      },
      "last_name": {
        "value": "Wilson"
      },
      "line1": {
        "value": "8092 Market Rd"
      },
      "line2": {
        "value": "9788 Oak Dr"
      },
      "line3": {
        "value": "4264 Oak Ave"
      },
      "city": {
        "value": "Seattle"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "13341"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "casey.7164@testmail.io"
      },
      "phone_number": {
        "value": "9762622909"
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
date: Tue, 24 Mar 2026 13:34:08 GMT
x-request-id: authorize_no3ds_auto_capture_credit_card_req

Response contents:
{
  "merchantTransactionId": "69c292d0-4080-a4bc-b972-c15e6e2d4581",
  "connectorTransactionId": "69c292d0-4080-a4bc-b972-c15e6e2d4581",
  "status": "AUTHENTICATION_PENDING",
  "statusCode": 200,
  "responseHeaders": {
    "cf-cache-status": "DYNAMIC",
    "cf-ray": "9e160d33abca7f3a-MAA",
    "connection": "keep-alive",
    "content-length": "1007",
    "content-type": "application/json",
    "date": "Tue, 24 Mar 2026 13:34:08 GMT",
    "request-id": "1XXPER31VSDND",
    "server": "cloudflare",
    "set-cookie": "_cfuvid=2ytRiPky0KjK1EA_3t6.LQmVHk8Kv.icMg9SyHQV7QY-1774359248380-0.0.1.1-604800000; path=/; domain=.revolut.com; HttpOnly; Secure; SameSite=None",
    "strict-transport-security": "max-age=2592000; includeSubDomains; preload",
    "via": "1.1 google",
    "x-content-type-options": "nosniff"
  },
  "redirectionData": {
    "uri": {
      "uri": "https://sandbox-checkout.revolut.com/payment-link/6c463721-bf91-4cc2-afdd-c8b5d2a963f5"
    }
  },
  "rawConnectorResponse": {
    "value": "{\"id\":\"69c292d0-4080-a4bc-b972-c15e6e2d4581\",\"token\":\"6c463721-bf91-4cc2-afdd-c8b5d2a963f5\",\"type\":\"payment\",\"state\":\"pending\",\"created_at\":\"2026-03-24T13:34:08.164101Z\",\"updated_at\":\"2026-03-24T13:34:08.164101Z\",\"amount\":6000,\"currency\":\"USD\",\"outstanding_amount\":6000,\"capture_mode\":\"automatic\",\"description\":\"No3DS auto capture card payment (credit)\",\"checkout_url\":\"https://sandbox-checkout.revolut.com/payment-link/6c463721-bf91-4cc2-afdd-c8b5d2a963f5\",\"enforce_challenge\":\"automatic\",\"redirect_url\":\"https://example.com/payment/return\",\"authorisation_type\":\"final\",\"customer\":{\"id\":\"dc46b480-811e-49a3-9fce-35cd8703ccd0\",\"email\":\"riley.2457@testmail.io\"},\"merchant_order_data\":{\"url\":\"https://example.com/payment/return\",\"reference\":\"mti_eda70f917e9e41078526cfc83bd606ca\"},\"shipping\":{\"address\":{\"street_line_1\":\"177 Market Dr\",\"street_line_2\":\"1421 Pine St\",\"region\":\"CA\",\"city\":\"Chicago\",\"country_code\":\"US\",\"postcode\":\"73665\"},\"contact\":{\"email\":\"jordan.3590@example.com\",\"phone\":\"+915776257503\"}}}"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://sandbox-merchant.revolut.com//api/orders\",\"method\":\"POST\",\"headers\":{\"Authorization\":\"Bearer ***MASKED***",\"Revolut-Api-Version\":\"2024-09-01\",\"Content-Type\":\"application/json\",\"via\":\"HyperSwitch\"},\"body\":{\"amount\":6000,\"currency\":\"USD\",\"description\":\"No3DS auto capture card payment (credit)\",\"customer\":{\"email\":\"riley.2457@testmail.io\"},\"shipping\":{\"address\":{\"street_line_1\":\"177 Market Dr\",\"street_line_2\":\"1421 Pine St\",\"region\":\"CA\",\"city\":\"Chicago\",\"country_code\":\"US\",\"postcode\":\"73665\"},\"contact\":{\"full_name\":\"Emma Johnson\",\"phone\":\"+915776257503\",\"email\":\"jordan.3590@example.com\"}},\"capture_mode\":\"automatic\",\"merchant_order_data\":{\"url\":\"https://example.com/payment/return\",\"reference\":\"mti_eda70f917e9e41078526cfc83bd606ca\"},\"redirect_url\":\"https://example.com/payment/return\"}}"
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
  -H "x-request-id: refund_refund_full_amount_req" \
  -H "x-connector-request-reference-id: refund_refund_full_amount_ref" \
  -H "x-auth: ***MASKED***" \
  -H "x-api-key: ***MASKED***" \
  -d @ localhost:8000 types.PaymentService/Refund <<'JSON'
{
  "merchant_refund_id": "mri_cac8fb0c624949d08d21c536461d1481",
  "connector_transaction_id": "69c292d0-4080-a4bc-b972-c15e6e2d4581",
  "payment_amount": 6000,
  "refund_amount": {
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
// Initiate a refund to customer's payment method. Returns funds for
// returns, cancellations, or service adjustments after original payment.
rpc Refund ( .types.PaymentServiceRefundRequest ) returns ( .types.RefundResponse );

Request metadata to send:
x-api-key: ***MASKED***
x-auth: ***MASKED***
x-connector: revolut
x-connector-request-reference-id: refund_refund_full_amount_ref
x-merchant-id: test_merchant
x-request-id: refund_refund_full_amount_req
x-tenant-id: default

Response headers received:
content-type: application/grpc
date: Tue, 24 Mar 2026 13:34:08 GMT
x-request-id: refund_refund_full_amount_req

Response contents:
{
  "status": 20,
  "error": {
    "connectorDetails": {
      "code": "bad_state",
      "message": "No refundable payment found for order 69c292d0-4080-a4bc-b972-c15e6e2d4581.",
      "reason": "No refundable payment found for order 69c292d0-4080-a4bc-b972-c15e6e2d4581."
    }
  },
  "statusCode": 422,
  "responseHeaders": {
    "cf-cache-status": "DYNAMIC",
    "cf-ray": "9e160d36ff7c7f3a-MAA",
    "connection": "keep-alive",
    "content-length": "134",
    "content-type": "application/json",
    "date": "Tue, 24 Mar 2026 13:34:08 GMT",
    "request-id": "O57RF5GD21VV",
    "server": "cloudflare",
    "set-cookie": "_cfuvid=_Psu_ZTXJ0lkdszZcQxgVaX2CSw87LEHE3C0Veo34t4-1774359248867-0.0.1.1-604800000; path=/; domain=.revolut.com; HttpOnly; Secure; SameSite=None",
    "strict-transport-security": "max-age=2592000; includeSubDomains; preload",
    "via": "1.1 google",
    "x-content-type-options": "nosniff"
  },
  "rawConnectorResponse": {
    "value": "{\"code\":\"bad_state\",\"message\":\"No refundable payment found for order 69c292d0-4080-a4bc-b972-c15e6e2d4581.\",\"timestamp\":1774359248707}"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://sandbox-merchant.revolut.com//api/orders/69c292d0-4080-a4bc-b972-c15e6e2d4581/refund\",\"method\":\"POST\",\"headers\":{\"Revolut-Api-Version\":\"2024-09-01\",\"via\":\"HyperSwitch\",\"Authorization\":\"Bearer ***MASKED***",\"Content-Type\":\"application/json\"},\"body\":{\"amount\":6000,\"currency\":\"USD\",\"merchant_order_data\":{\"url\":null,\"reference\":\"mri_cac8fb0c624949d08d21c536461d1481\"},\"metadata\":null,\"description\":null}}"
  }
}

Response trailers received:
(empty)
Sent 1 request and received 1 response
```

</details>


[Back to Connector Suite](../refund.md) | [Back to Overview](../../../test_overview.md)
