# Connector `revolut` / Suite `refund` / Scenario `refund_with_reason`

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
  "merchant_transaction_id": "mti_9724e358bc734c17bd72f1fd9a24ef18",
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
        "value": "Noah Brown"
      },
      "card_type": "credit"
    }
  },
  "capture_method": "AUTOMATIC",
  "customer": {
    "name": "Liam Taylor",
    "email": {
      "value": "casey.7709@sandbox.example.com"
    },
    "id": "cust_2dbef1f36dac4cda885913501f55a8fe",
    "phone_number": "+11499113399"
  },
  "locale": "en-US",
  "address": {
    "shipping_address": {
      "first_name": {
        "value": "Ava"
      },
      "last_name": {
        "value": "Wilson"
      },
      "line1": {
        "value": "5576 Main Rd"
      },
      "line2": {
        "value": "233 Market St"
      },
      "line3": {
        "value": "8253 Main Rd"
      },
      "city": {
        "value": "Los Angeles"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "27410"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "sam.1540@testmail.io"
      },
      "phone_number": {
        "value": "3804816045"
      },
      "phone_country_code": "+91"
    },
    "billing_address": {
      "first_name": {
        "value": "Mia"
      },
      "last_name": {
        "value": "Taylor"
      },
      "line1": {
        "value": "8861 Oak Rd"
      },
      "line2": {
        "value": "8772 Market Rd"
      },
      "line3": {
        "value": "7852 Sunset Dr"
      },
      "city": {
        "value": "Austin"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "49014"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "jordan.4103@testmail.io"
      },
      "phone_number": {
        "value": "8684198449"
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
date: Tue, 24 Mar 2026 13:34:10 GMT
x-request-id: authorize_no3ds_auto_capture_credit_card_req

Response contents:
{
  "merchantTransactionId": "69c292d2-a9dc-a52d-8e0c-571210e874c7",
  "connectorTransactionId": "69c292d2-a9dc-a52d-8e0c-571210e874c7",
  "status": "AUTHENTICATION_PENDING",
  "statusCode": 200,
  "responseHeaders": {
    "cf-cache-status": "DYNAMIC",
    "cf-ray": "9e160d400a0b7f3a-MAA",
    "connection": "keep-alive",
    "content-length": "1016",
    "content-type": "application/json",
    "date": "Tue, 24 Mar 2026 13:34:10 GMT",
    "request-id": "1X188EP58VCBW",
    "server": "cloudflare",
    "set-cookie": "_cfuvid=QHLwUy5aDINH750uAVvVul2T5C_FOAHFXZ258jCZrNs-1774359250330-0.0.1.1-604800000; path=/; domain=.revolut.com; HttpOnly; Secure; SameSite=None",
    "strict-transport-security": "max-age=2592000; includeSubDomains; preload",
    "via": "1.1 google",
    "x-content-type-options": "nosniff"
  },
  "redirectionData": {
    "uri": {
      "uri": "https://sandbox-checkout.revolut.com/payment-link/6cc673e1-5dd8-4fe3-bf45-42891ca69459"
    }
  },
  "rawConnectorResponse": {
    "value": "{\"id\":\"69c292d2-a9dc-a52d-8e0c-571210e874c7\",\"token\":\"6cc673e1-5dd8-4fe3-bf45-42891ca69459\",\"type\":\"payment\",\"state\":\"pending\",\"created_at\":\"2026-03-24T13:34:10.149368Z\",\"updated_at\":\"2026-03-24T13:34:10.149368Z\",\"amount\":6000,\"currency\":\"USD\",\"outstanding_amount\":6000,\"capture_mode\":\"automatic\",\"description\":\"No3DS auto capture card payment (credit)\",\"checkout_url\":\"https://sandbox-checkout.revolut.com/payment-link/6cc673e1-5dd8-4fe3-bf45-42891ca69459\",\"enforce_challenge\":\"automatic\",\"redirect_url\":\"https://example.com/payment/return\",\"authorisation_type\":\"final\",\"customer\":{\"id\":\"aeba96c1-26e4-4bf8-85df-279c03d84042\",\"email\":\"casey.7709@sandbox.example.com\"},\"merchant_order_data\":{\"url\":\"https://example.com/payment/return\",\"reference\":\"mti_9724e358bc734c17bd72f1fd9a24ef18\"},\"shipping\":{\"address\":{\"street_line_1\":\"5576 Main Rd\",\"street_line_2\":\"233 Market St\",\"region\":\"CA\",\"city\":\"Los Angeles\",\"country_code\":\"US\",\"postcode\":\"27410\"},\"contact\":{\"email\":\"sam.1540@testmail.io\",\"phone\":\"+913804816045\"}}}"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://sandbox-merchant.revolut.com//api/orders\",\"method\":\"POST\",\"headers\":{\"Authorization\":\"Bearer ***MASKED***",\"Content-Type\":\"application/json\",\"Revolut-Api-Version\":\"2024-09-01\",\"via\":\"HyperSwitch\"},\"body\":{\"amount\":6000,\"currency\":\"USD\",\"description\":\"No3DS auto capture card payment (credit)\",\"customer\":{\"email\":\"casey.7709@sandbox.example.com\"},\"shipping\":{\"address\":{\"street_line_1\":\"5576 Main Rd\",\"street_line_2\":\"233 Market St\",\"region\":\"CA\",\"city\":\"Los Angeles\",\"country_code\":\"US\",\"postcode\":\"27410\"},\"contact\":{\"full_name\":\"Ava Wilson\",\"phone\":\"+913804816045\",\"email\":\"sam.1540@testmail.io\"}},\"capture_mode\":\"automatic\",\"merchant_order_data\":{\"url\":\"https://example.com/payment/return\",\"reference\":\"mti_9724e358bc734c17bd72f1fd9a24ef18\"},\"redirect_url\":\"https://example.com/payment/return\"}}"
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
  -H "x-request-id: refund_refund_with_reason_req" \
  -H "x-connector-request-reference-id: refund_refund_with_reason_ref" \
  -H "x-auth: ***MASKED***" \
  -H "x-api-key: ***MASKED***" \
  -d @ localhost:8000 types.PaymentService/Refund <<'JSON'
{
  "merchant_refund_id": "mri_954b100efc5b45d09029d0dc3db4e58e",
  "connector_transaction_id": "69c292d2-a9dc-a52d-8e0c-571210e874c7",
  "payment_amount": 6000,
  "refund_amount": {
    "minor_amount": 6000,
    "currency": "USD"
  },
  "reason": "customer_requested"
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
x-connector-request-reference-id: refund_refund_with_reason_ref
x-merchant-id: test_merchant
x-request-id: refund_refund_with_reason_req
x-tenant-id: default

Response headers received:
content-type: application/grpc
date: Tue, 24 Mar 2026 13:34:10 GMT
x-request-id: refund_refund_with_reason_req

Response contents:
{
  "status": 20,
  "error": {
    "connectorDetails": {
      "code": "bad_state",
      "message": "No refundable payment found for order 69c292d2-a9dc-a52d-8e0c-571210e874c7.",
      "reason": "No refundable payment found for order 69c292d2-a9dc-a52d-8e0c-571210e874c7."
    }
  },
  "statusCode": 422,
  "responseHeaders": {
    "cf-cache-status": "DYNAMIC",
    "cf-ray": "9e160d431d9e7f3a-MAA",
    "connection": "keep-alive",
    "content-length": "134",
    "content-type": "application/json",
    "date": "Tue, 24 Mar 2026 13:34:10 GMT",
    "request-id": "KPL90YZALPEA",
    "server": "cloudflare",
    "set-cookie": "_cfuvid=j2QrUYwxEFTP1CIsbBtw2t2P4jqWYHlYXOaRiVNuLOU-1774359250840-0.0.1.1-604800000; path=/; domain=.revolut.com; HttpOnly; Secure; SameSite=None",
    "strict-transport-security": "max-age=2592000; includeSubDomains; preload",
    "via": "1.1 google",
    "x-content-type-options": "nosniff"
  },
  "rawConnectorResponse": {
    "value": "{\"code\":\"bad_state\",\"message\":\"No refundable payment found for order 69c292d2-a9dc-a52d-8e0c-571210e874c7.\",\"timestamp\":1774359250678}"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://sandbox-merchant.revolut.com//api/orders/69c292d2-a9dc-a52d-8e0c-571210e874c7/refund\",\"method\":\"POST\",\"headers\":{\"Content-Type\":\"application/json\",\"Authorization\":\"Bearer ***MASKED***",\"via\":\"HyperSwitch\",\"Revolut-Api-Version\":\"2024-09-01\"},\"body\":{\"amount\":6000,\"currency\":\"USD\",\"merchant_order_data\":{\"url\":null,\"reference\":\"mri_954b100efc5b45d09029d0dc3db4e58e\"},\"metadata\":null,\"description\":\"customer_requested\"}}"
  }
}

Response trailers received:
(empty)
Sent 1 request and received 1 response
```

</details>


[Back to Connector Suite](../refund.md) | [Back to Overview](../../../test_overview.md)
