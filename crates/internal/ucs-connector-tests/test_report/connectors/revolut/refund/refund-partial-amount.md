# Connector `revolut` / Suite `refund` / Scenario `refund_partial_amount`

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
  "merchant_transaction_id": "mti_0f2084bbb6e44714b756a01e34db5196",
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
        "value": "Ethan Brown"
      },
      "card_type": "credit"
    }
  },
  "capture_method": "AUTOMATIC",
  "customer": {
    "name": "Liam Brown",
    "email": {
      "value": "alex.9054@testmail.io"
    },
    "id": "cust_830e6e4b98bf49408992e5232f1817b2",
    "phone_number": "+16325127281"
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
        "value": "6259 Oak Blvd"
      },
      "line2": {
        "value": "1854 Lake Dr"
      },
      "line3": {
        "value": "1188 Market Ave"
      },
      "city": {
        "value": "San Francisco"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "25349"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "casey.1670@sandbox.example.com"
      },
      "phone_number": {
        "value": "9362774785"
      },
      "phone_country_code": "+91"
    },
    "billing_address": {
      "first_name": {
        "value": "Ava"
      },
      "last_name": {
        "value": "Smith"
      },
      "line1": {
        "value": "3564 Lake St"
      },
      "line2": {
        "value": "8337 Lake Ln"
      },
      "line3": {
        "value": "7816 Pine Ave"
      },
      "city": {
        "value": "Chicago"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "13405"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "morgan.3148@sandbox.example.com"
      },
      "phone_number": {
        "value": "3351849594"
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
date: Tue, 24 Mar 2026 13:34:09 GMT
x-request-id: authorize_no3ds_auto_capture_credit_card_req

Response contents:
{
  "merchantTransactionId": "69c292d1-fa07-ac5b-9114-472602c05e61",
  "connectorTransactionId": "69c292d1-fa07-ac5b-9114-472602c05e61",
  "status": "AUTHENTICATION_PENDING",
  "statusCode": 200,
  "responseHeaders": {
    "cf-cache-status": "DYNAMIC",
    "cf-ray": "9e160d39eb1f7f3a-MAA",
    "connection": "keep-alive",
    "content-length": "1019",
    "content-type": "application/json",
    "date": "Tue, 24 Mar 2026 13:34:09 GMT",
    "request-id": "1IRTEHCL90FJD",
    "server": "cloudflare",
    "set-cookie": "_cfuvid=gjWkvaowD06mwzYzOPlFXsdQVZkYJ14hsdNXlSKqKpI-1774359249387-0.0.1.1-604800000; path=/; domain=.revolut.com; HttpOnly; Secure; SameSite=None",
    "strict-transport-security": "max-age=2592000; includeSubDomains; preload",
    "via": "1.1 google",
    "x-content-type-options": "nosniff"
  },
  "redirectionData": {
    "uri": {
      "uri": "https://sandbox-checkout.revolut.com/payment-link/5f987a0a-1be9-47ea-80ba-95786933490a"
    }
  },
  "rawConnectorResponse": {
    "value": "{\"id\":\"69c292d1-fa07-ac5b-9114-472602c05e61\",\"token\":\"5f987a0a-1be9-47ea-80ba-95786933490a\",\"type\":\"payment\",\"state\":\"pending\",\"created_at\":\"2026-03-24T13:34:09.178264Z\",\"updated_at\":\"2026-03-24T13:34:09.178264Z\",\"amount\":6000,\"currency\":\"USD\",\"outstanding_amount\":6000,\"capture_mode\":\"automatic\",\"description\":\"No3DS auto capture card payment (credit)\",\"checkout_url\":\"https://sandbox-checkout.revolut.com/payment-link/5f987a0a-1be9-47ea-80ba-95786933490a\",\"enforce_challenge\":\"automatic\",\"redirect_url\":\"https://example.com/payment/return\",\"authorisation_type\":\"final\",\"customer\":{\"id\":\"ac5b2feb-11f0-41af-b46c-06377547a823\",\"email\":\"alex.9054@testmail.io\"},\"merchant_order_data\":{\"url\":\"https://example.com/payment/return\",\"reference\":\"mti_0f2084bbb6e44714b756a01e34db5196\"},\"shipping\":{\"address\":{\"street_line_1\":\"6259 Oak Blvd\",\"street_line_2\":\"1854 Lake Dr\",\"region\":\"CA\",\"city\":\"San Francisco\",\"country_code\":\"US\",\"postcode\":\"25349\"},\"contact\":{\"email\":\"casey.1670@sandbox.example.com\",\"phone\":\"+919362774785\"}}}"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://sandbox-merchant.revolut.com//api/orders\",\"method\":\"POST\",\"headers\":{\"via\":\"HyperSwitch\",\"Content-Type\":\"application/json\",\"Authorization\":\"Bearer ***MASKED***",\"Revolut-Api-Version\":\"2024-09-01\"},\"body\":{\"amount\":6000,\"currency\":\"USD\",\"description\":\"No3DS auto capture card payment (credit)\",\"customer\":{\"email\":\"alex.9054@testmail.io\"},\"shipping\":{\"address\":{\"street_line_1\":\"6259 Oak Blvd\",\"street_line_2\":\"1854 Lake Dr\",\"region\":\"CA\",\"city\":\"San Francisco\",\"country_code\":\"US\",\"postcode\":\"25349\"},\"contact\":{\"full_name\":\"Ava Johnson\",\"phone\":\"+919362774785\",\"email\":\"casey.1670@sandbox.example.com\"}},\"capture_mode\":\"automatic\",\"merchant_order_data\":{\"url\":\"https://example.com/payment/return\",\"reference\":\"mti_0f2084bbb6e44714b756a01e34db5196\"},\"redirect_url\":\"https://example.com/payment/return\"}}"
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
  -H "x-request-id: refund_refund_partial_amount_req" \
  -H "x-connector-request-reference-id: refund_refund_partial_amount_ref" \
  -H "x-auth: ***MASKED***" \
  -H "x-api-key: ***MASKED***" \
  -d @ localhost:8000 types.PaymentService/Refund <<'JSON'
{
  "merchant_refund_id": "mri_ccec2d876d084ef3892b2645a8354e06",
  "connector_transaction_id": "69c292d1-fa07-ac5b-9114-472602c05e61",
  "payment_amount": 6000,
  "refund_amount": {
    "minor_amount": 3000,
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
x-connector-request-reference-id: refund_refund_partial_amount_ref
x-merchant-id: test_merchant
x-request-id: refund_refund_partial_amount_req
x-tenant-id: default

Response headers received:
content-type: application/grpc
date: Tue, 24 Mar 2026 13:34:09 GMT
x-request-id: refund_refund_partial_amount_req

Response contents:
{
  "status": 20,
  "error": {
    "connectorDetails": {
      "code": "bad_state",
      "message": "No refundable payment found for order 69c292d1-fa07-ac5b-9114-472602c05e61.",
      "reason": "No refundable payment found for order 69c292d1-fa07-ac5b-9114-472602c05e61."
    }
  },
  "statusCode": 422,
  "responseHeaders": {
    "cf-cache-status": "DYNAMIC",
    "cf-ray": "9e160d3d2ea77f3a-MAA",
    "connection": "keep-alive",
    "content-length": "134",
    "content-type": "application/json",
    "date": "Tue, 24 Mar 2026 13:34:09 GMT",
    "request-id": "1MFFB48EWPGGU",
    "server": "cloudflare",
    "set-cookie": "_cfuvid=EUwgk_pq2ev2Tm0AVWIiqK6YZYPC8z7ZptKxv._cGNU-1774359249860-0.0.1.1-604800000; path=/; domain=.revolut.com; HttpOnly; Secure; SameSite=None",
    "strict-transport-security": "max-age=2592000; includeSubDomains; preload",
    "via": "1.1 google",
    "x-content-type-options": "nosniff"
  },
  "rawConnectorResponse": {
    "value": "{\"code\":\"bad_state\",\"message\":\"No refundable payment found for order 69c292d1-fa07-ac5b-9114-472602c05e61.\",\"timestamp\":1774359249700}"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://sandbox-merchant.revolut.com//api/orders/69c292d1-fa07-ac5b-9114-472602c05e61/refund\",\"method\":\"POST\",\"headers\":{\"Authorization\":\"Bearer ***MASKED***",\"via\":\"HyperSwitch\",\"Content-Type\":\"application/json\",\"Revolut-Api-Version\":\"2024-09-01\"},\"body\":{\"amount\":3000,\"currency\":\"USD\",\"merchant_order_data\":{\"url\":null,\"reference\":\"mri_ccec2d876d084ef3892b2645a8354e06\"},\"metadata\":null,\"description\":null}}"
  }
}

Response trailers received:
(empty)
Sent 1 request and received 1 response
```

</details>


[Back to Connector Suite](../refund.md) | [Back to Overview](../../../test_overview.md)
