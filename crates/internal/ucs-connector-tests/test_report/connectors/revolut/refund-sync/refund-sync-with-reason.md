# Connector `revolut` / Suite `refund_sync` / Scenario `refund_sync_with_reason`

- Service: `RefundService/Get`
- PM / PMT: `-` / `-`
- Result: `FAIL`

**Error**

```text
Resolved method descriptor:
// Retrieve refund status from the payment processor. Tracks refund progress
// through processor settlement for accurate customer communication.
rpc Get ( .types.RefundServiceGetRequest ) returns ( .types.RefundResponse );

Request metadata to send:
x-api-key: ***MASKED***
x-auth: ***MASKED***
x-connector: revolut
x-connector-request-reference-id: refund_sync_refund_sync_with_reason_ref
x-merchant-id: test_merchant
x-request-id: refund_sync_refund_sync_with_reason_req
x-tenant-id: default

Response headers received:
(empty)

Response trailers received:
content-type: application/grpc
date: Tue, 24 Mar 2026 13:34:14 GMT
x-request-id: refund_sync_refund_sync_with_reason_req
Sent 1 request and received 0 responses

ERROR:
  Code: Internal
  Message: Failed to deserialize connector response
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
  "merchant_transaction_id": "mti_22b11438542f477585cb23b13f2c3fd6",
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
  "capture_method": "AUTOMATIC",
  "customer": {
    "name": "Noah Miller",
    "email": {
      "value": "jordan.7322@sandbox.example.com"
    },
    "id": "cust_b2c4aedc1f4649a1aba4046fad4d4696",
    "phone_number": "+912591736800"
  },
  "locale": "en-US",
  "address": {
    "shipping_address": {
      "first_name": {
        "value": "Liam"
      },
      "last_name": {
        "value": "Miller"
      },
      "line1": {
        "value": "464 Main Ln"
      },
      "line2": {
        "value": "9275 Main Ln"
      },
      "line3": {
        "value": "9731 Market Blvd"
      },
      "city": {
        "value": "Austin"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "62507"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "jordan.6388@example.com"
      },
      "phone_number": {
        "value": "2122276672"
      },
      "phone_country_code": "+91"
    },
    "billing_address": {
      "first_name": {
        "value": "Ethan"
      },
      "last_name": {
        "value": "Brown"
      },
      "line1": {
        "value": "3009 Oak Ln"
      },
      "line2": {
        "value": "6714 Pine Ave"
      },
      "line3": {
        "value": "1566 Market Blvd"
      },
      "city": {
        "value": "Los Angeles"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "19441"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "jordan.2327@example.com"
      },
      "phone_number": {
        "value": "1294687960"
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
date: Tue, 24 Mar 2026 13:34:13 GMT
x-request-id: authorize_no3ds_auto_capture_credit_card_req

Response contents:
{
  "merchantTransactionId": "69c292d5-92dd-a435-928e-2f1036d133ca",
  "connectorTransactionId": "69c292d5-92dd-a435-928e-2f1036d133ca",
  "status": "AUTHENTICATION_PENDING",
  "statusCode": 200,
  "responseHeaders": {
    "cf-cache-status": "DYNAMIC",
    "cf-ray": "9e160d53cf70f3eb-MAA",
    "connection": "keep-alive",
    "content-length": "1013",
    "content-type": "application/json",
    "date": "Tue, 24 Mar 2026 13:34:13 GMT",
    "request-id": "QKYE3SIZ3QED",
    "server": "cloudflare",
    "set-cookie": "_cfuvid=oIhcnZy0Lwtk1obPRFEx3uKLIV3xukXKnbFqfOsdWRc-1774359253496-0.0.1.1-604800000; path=/; domain=.revolut.com; HttpOnly; Secure; SameSite=None",
    "strict-transport-security": "max-age=2592000; includeSubDomains; preload",
    "via": "1.1 google",
    "x-content-type-options": "nosniff"
  },
  "redirectionData": {
    "uri": {
      "uri": "https://sandbox-checkout.revolut.com/payment-link/01d6f54d-158e-4003-b8e4-01a7fe917f79"
    }
  },
  "rawConnectorResponse": {
    "value": "{\"id\":\"69c292d5-92dd-a435-928e-2f1036d133ca\",\"token\":\"01d6f54d-158e-4003-b8e4-01a7fe917f79\",\"type\":\"payment\",\"state\":\"pending\",\"created_at\":\"2026-03-24T13:34:13.305195Z\",\"updated_at\":\"2026-03-24T13:34:13.305195Z\",\"amount\":6000,\"currency\":\"USD\",\"outstanding_amount\":6000,\"capture_mode\":\"automatic\",\"description\":\"No3DS auto capture card payment (credit)\",\"checkout_url\":\"https://sandbox-checkout.revolut.com/payment-link/01d6f54d-158e-4003-b8e4-01a7fe917f79\",\"enforce_challenge\":\"automatic\",\"redirect_url\":\"https://example.com/payment/return\",\"authorisation_type\":\"final\",\"customer\":{\"id\":\"6e28261e-e87e-4d37-93cf-3e1ad407c32b\",\"email\":\"jordan.7322@sandbox.example.com\"},\"merchant_order_data\":{\"url\":\"https://example.com/payment/return\",\"reference\":\"mti_22b11438542f477585cb23b13f2c3fd6\"},\"shipping\":{\"address\":{\"street_line_1\":\"464 Main Ln\",\"street_line_2\":\"9275 Main Ln\",\"region\":\"CA\",\"city\":\"Austin\",\"country_code\":\"US\",\"postcode\":\"62507\"},\"contact\":{\"email\":\"jordan.6388@example.com\",\"phone\":\"+912122276672\"}}}"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://sandbox-merchant.revolut.com//api/orders\",\"method\":\"POST\",\"headers\":{\"Content-Type\":\"application/json\",\"Revolut-Api-Version\":\"2024-09-01\",\"via\":\"HyperSwitch\",\"Authorization\":\"Bearer ***MASKED***"},\"body\":{\"amount\":6000,\"currency\":\"USD\",\"description\":\"No3DS auto capture card payment (credit)\",\"customer\":{\"email\":\"jordan.7322@sandbox.example.com\"},\"shipping\":{\"address\":{\"street_line_1\":\"464 Main Ln\",\"street_line_2\":\"9275 Main Ln\",\"region\":\"CA\",\"city\":\"Austin\",\"country_code\":\"US\",\"postcode\":\"62507\"},\"contact\":{\"full_name\":\"Liam Miller\",\"phone\":\"+912122276672\",\"email\":\"jordan.6388@example.com\"}},\"capture_mode\":\"automatic\",\"merchant_order_data\":{\"url\":\"https://example.com/payment/return\",\"reference\":\"mti_22b11438542f477585cb23b13f2c3fd6\"},\"redirect_url\":\"https://example.com/payment/return\"}}"
  }
}

Response trailers received:
(empty)
Sent 1 request and received 1 response
```

</details>

</details>
<details>
<summary>2. refund(refund_full_amount) — FAIL</summary>

**Dependency Error**

```text
assertion failed for field 'connector_refund_id': expected field to exist
```

<details>
<summary>Show Dependency Request (masked)</summary>

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
  "merchant_refund_id": "mri_f90250558b9d4e1a905b6fe77313b396",
  "connector_transaction_id": "69c292d5-92dd-a435-928e-2f1036d133ca",
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
<summary>Show Dependency Response (masked)</summary>

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
date: Tue, 24 Mar 2026 13:34:13 GMT
x-request-id: refund_refund_full_amount_req

Response contents:
{
  "status": 20,
  "error": {
    "connectorDetails": {
      "code": "bad_state",
      "message": "No refundable payment found for order 69c292d5-92dd-a435-928e-2f1036d133ca.",
      "reason": "No refundable payment found for order 69c292d5-92dd-a435-928e-2f1036d133ca."
    }
  },
  "statusCode": 422,
  "responseHeaders": {
    "cf-cache-status": "DYNAMIC",
    "cf-ray": "9e160d56b97af3eb-MAA",
    "connection": "keep-alive",
    "content-length": "134",
    "content-type": "application/json",
    "date": "Tue, 24 Mar 2026 13:34:13 GMT",
    "request-id": "FXJAMRPAKOLS",
    "server": "cloudflare",
    "set-cookie": "_cfuvid=KBGIHMvTQ1QJRXnRKrJYwMrpZRJzOrB6YWsYWM7Jcqw-1774359253962-0.0.1.1-604800000; path=/; domain=.revolut.com; HttpOnly; Secure; SameSite=None",
    "strict-transport-security": "max-age=2592000; includeSubDomains; preload",
    "via": "1.1 google",
    "x-content-type-options": "nosniff"
  },
  "rawConnectorResponse": {
    "value": "{\"code\":\"bad_state\",\"message\":\"No refundable payment found for order 69c292d5-92dd-a435-928e-2f1036d133ca.\",\"timestamp\":1774359253800}"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://sandbox-merchant.revolut.com//api/orders/69c292d5-92dd-a435-928e-2f1036d133ca/refund\",\"method\":\"POST\",\"headers\":{\"Content-Type\":\"application/json\",\"Authorization\":\"Bearer ***MASKED***",\"Revolut-Api-Version\":\"2024-09-01\",\"via\":\"HyperSwitch\"},\"body\":{\"amount\":6000,\"currency\":\"USD\",\"merchant_order_data\":{\"url\":null,\"reference\":\"mri_f90250558b9d4e1a905b6fe77313b396\"},\"metadata\":null,\"description\":null}}"
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
  -H "x-request-id: refund_sync_refund_sync_with_reason_req" \
  -H "x-connector-request-reference-id: refund_sync_refund_sync_with_reason_ref" \
  -H "x-auth: ***MASKED***" \
  -H "x-api-key: ***MASKED***" \
  -d @ localhost:8000 types.RefundService/Get <<'JSON'
{
  "connector_transaction_id": "69c292d5-92dd-a435-928e-2f1036d133ca",
  "refund_reason": "customer_requested"
}
JSON
```

</details>

<details>
<summary>Show Response (masked)</summary>

```text
Resolved method descriptor:
// Retrieve refund status from the payment processor. Tracks refund progress
// through processor settlement for accurate customer communication.
rpc Get ( .types.RefundServiceGetRequest ) returns ( .types.RefundResponse );

Request metadata to send:
x-api-key: ***MASKED***
x-auth: ***MASKED***
x-connector: revolut
x-connector-request-reference-id: refund_sync_refund_sync_with_reason_ref
x-merchant-id: test_merchant
x-request-id: refund_sync_refund_sync_with_reason_req
x-tenant-id: default

Response headers received:
(empty)

Response trailers received:
content-type: application/grpc
date: Tue, 24 Mar 2026 13:34:14 GMT
x-request-id: refund_sync_refund_sync_with_reason_req
Sent 1 request and received 0 responses

ERROR:
  Code: Internal
  Message: Failed to deserialize connector response
```

</details>


[Back to Connector Suite](../refund-sync.md) | [Back to Overview](../../../test_overview.md)
