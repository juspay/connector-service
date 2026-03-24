# Connector `revolut` / Suite `refund_sync` / Scenario `refund_sync`

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
x-connector-request-reference-id: refund_sync_refund_sync_ref
x-merchant-id: test_merchant
x-request-id: refund_sync_refund_sync_req
x-tenant-id: default

Response headers received:
(empty)

Response trailers received:
content-type: application/grpc
date: Tue, 24 Mar 2026 13:34:12 GMT
x-request-id: refund_sync_refund_sync_req
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
  "merchant_transaction_id": "mti_6c4b86d4e79541a58eabd60bb8ab9f13",
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
        "value": "Liam Smith"
      },
      "card_type": "credit"
    }
  },
  "capture_method": "AUTOMATIC",
  "customer": {
    "name": "Mia Miller",
    "email": {
      "value": "casey.2922@testmail.io"
    },
    "id": "cust_8405409e637a488daf47fb2e29e1bafb",
    "phone_number": "+447497532645"
  },
  "locale": "en-US",
  "address": {
    "shipping_address": {
      "first_name": {
        "value": "Emma"
      },
      "last_name": {
        "value": "Brown"
      },
      "line1": {
        "value": "9165 Pine Ln"
      },
      "line2": {
        "value": "7831 Main St"
      },
      "line3": {
        "value": "1719 Lake Ave"
      },
      "city": {
        "value": "Austin"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "46436"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "morgan.8415@sandbox.example.com"
      },
      "phone_number": {
        "value": "2405339372"
      },
      "phone_country_code": "+91"
    },
    "billing_address": {
      "first_name": {
        "value": "Ava"
      },
      "last_name": {
        "value": "Taylor"
      },
      "line1": {
        "value": "4577 Sunset Rd"
      },
      "line2": {
        "value": "661 Market Blvd"
      },
      "line3": {
        "value": "6299 Pine Rd"
      },
      "city": {
        "value": "San Francisco"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "47966"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "sam.5720@example.com"
      },
      "phone_number": {
        "value": "8078577498"
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
date: Tue, 24 Mar 2026 13:34:11 GMT
x-request-id: authorize_no3ds_auto_capture_credit_card_req

Response contents:
{
  "merchantTransactionId": "69c292d3-037f-ad58-82f0-f5e32bf4155b",
  "connectorTransactionId": "69c292d3-037f-ad58-82f0-f5e32bf4155b",
  "status": "AUTHENTICATION_PENDING",
  "statusCode": 200,
  "responseHeaders": {
    "cf-cache-status": "DYNAMIC",
    "cf-ray": "9e160d4629b57f3a-MAA",
    "connection": "keep-alive",
    "content-length": "1013",
    "content-type": "application/json",
    "date": "Tue, 24 Mar 2026 13:34:11 GMT",
    "request-id": "1D4AP7SX6E1OX",
    "server": "cloudflare",
    "set-cookie": "_cfuvid=mMBw_9IMQQh_ZQiKaOEqaB9UlBW07T8hF9FHhXffTV0-1774359251296-0.0.1.1-604800000; path=/; domain=.revolut.com; HttpOnly; Secure; SameSite=None",
    "strict-transport-security": "max-age=2592000; includeSubDomains; preload",
    "via": "1.1 google",
    "x-content-type-options": "nosniff"
  },
  "redirectionData": {
    "uri": {
      "uri": "https://sandbox-checkout.revolut.com/payment-link/c1bb3a91-6311-4c0a-a652-2563b8131361"
    }
  },
  "rawConnectorResponse": {
    "value": "{\"id\":\"69c292d3-037f-ad58-82f0-f5e32bf4155b\",\"token\":\"c1bb3a91-6311-4c0a-a652-2563b8131361\",\"type\":\"payment\",\"state\":\"pending\",\"created_at\":\"2026-03-24T13:34:11.114035Z\",\"updated_at\":\"2026-03-24T13:34:11.114035Z\",\"amount\":6000,\"currency\":\"USD\",\"outstanding_amount\":6000,\"capture_mode\":\"automatic\",\"description\":\"No3DS auto capture card payment (credit)\",\"checkout_url\":\"https://sandbox-checkout.revolut.com/payment-link/c1bb3a91-6311-4c0a-a652-2563b8131361\",\"enforce_challenge\":\"automatic\",\"redirect_url\":\"https://example.com/payment/return\",\"authorisation_type\":\"final\",\"customer\":{\"id\":\"666a334d-ee92-4cfd-a7a9-4f7c2a251e18\",\"email\":\"casey.2922@testmail.io\"},\"merchant_order_data\":{\"url\":\"https://example.com/payment/return\",\"reference\":\"mti_6c4b86d4e79541a58eabd60bb8ab9f13\"},\"shipping\":{\"address\":{\"street_line_1\":\"9165 Pine Ln\",\"street_line_2\":\"7831 Main St\",\"region\":\"CA\",\"city\":\"Austin\",\"country_code\":\"US\",\"postcode\":\"46436\"},\"contact\":{\"email\":\"morgan.8415@sandbox.example.com\",\"phone\":\"+912405339372\"}}}"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://sandbox-merchant.revolut.com//api/orders\",\"method\":\"POST\",\"headers\":{\"Content-Type\":\"application/json\",\"Revolut-Api-Version\":\"2024-09-01\",\"Authorization\":\"Bearer ***MASKED***",\"via\":\"HyperSwitch\"},\"body\":{\"amount\":6000,\"currency\":\"USD\",\"description\":\"No3DS auto capture card payment (credit)\",\"customer\":{\"email\":\"casey.2922@testmail.io\"},\"shipping\":{\"address\":{\"street_line_1\":\"9165 Pine Ln\",\"street_line_2\":\"7831 Main St\",\"region\":\"CA\",\"city\":\"Austin\",\"country_code\":\"US\",\"postcode\":\"46436\"},\"contact\":{\"full_name\":\"Emma Brown\",\"phone\":\"+912405339372\",\"email\":\"morgan.8415@sandbox.example.com\"}},\"capture_mode\":\"automatic\",\"merchant_order_data\":{\"url\":\"https://example.com/payment/return\",\"reference\":\"mti_6c4b86d4e79541a58eabd60bb8ab9f13\"},\"redirect_url\":\"https://example.com/payment/return\"}}"
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
  "merchant_refund_id": "mri_96c93a442d4b49ce8c10e3603094ee70",
  "connector_transaction_id": "69c292d3-037f-ad58-82f0-f5e32bf4155b",
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
date: Tue, 24 Mar 2026 13:34:11 GMT
x-request-id: refund_refund_full_amount_req

Response contents:
{
  "status": 20,
  "error": {
    "connectorDetails": {
      "code": "bad_state",
      "message": "No refundable payment found for order 69c292d3-037f-ad58-82f0-f5e32bf4155b.",
      "reason": "No refundable payment found for order 69c292d3-037f-ad58-82f0-f5e32bf4155b."
    }
  },
  "statusCode": 422,
  "responseHeaders": {
    "cf-cache-status": "DYNAMIC",
    "cf-ray": "9e160d48fcd17f3a-MAA",
    "connection": "keep-alive",
    "content-length": "134",
    "content-type": "application/json",
    "date": "Tue, 24 Mar 2026 13:34:11 GMT",
    "request-id": "1SM6V37UZ15EH",
    "server": "cloudflare",
    "set-cookie": "_cfuvid=wB3YIo9O7jQbhAl4BBdsC250fJry9KnGuga1oEsGtBA-1774359251761-0.0.1.1-604800000; path=/; domain=.revolut.com; HttpOnly; Secure; SameSite=None",
    "strict-transport-security": "max-age=2592000; includeSubDomains; preload",
    "via": "1.1 google",
    "x-content-type-options": "nosniff"
  },
  "rawConnectorResponse": {
    "value": "{\"code\":\"bad_state\",\"message\":\"No refundable payment found for order 69c292d3-037f-ad58-82f0-f5e32bf4155b.\",\"timestamp\":1774359251598}"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://sandbox-merchant.revolut.com//api/orders/69c292d3-037f-ad58-82f0-f5e32bf4155b/refund\",\"method\":\"POST\",\"headers\":{\"via\":\"HyperSwitch\",\"Content-Type\":\"application/json\",\"Revolut-Api-Version\":\"2024-09-01\",\"Authorization\":\"Bearer ***MASKED***"},\"body\":{\"amount\":6000,\"currency\":\"USD\",\"merchant_order_data\":{\"url\":null,\"reference\":\"mri_96c93a442d4b49ce8c10e3603094ee70\"},\"metadata\":null,\"description\":null}}"
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
  -H "x-request-id: refund_sync_refund_sync_req" \
  -H "x-connector-request-reference-id: refund_sync_refund_sync_ref" \
  -H "x-auth: ***MASKED***" \
  -H "x-api-key: ***MASKED***" \
  -d @ localhost:8000 types.RefundService/Get <<'JSON'
{
  "connector_transaction_id": "69c292d3-037f-ad58-82f0-f5e32bf4155b"
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
x-connector-request-reference-id: refund_sync_refund_sync_ref
x-merchant-id: test_merchant
x-request-id: refund_sync_refund_sync_req
x-tenant-id: default

Response headers received:
(empty)

Response trailers received:
content-type: application/grpc
date: Tue, 24 Mar 2026 13:34:12 GMT
x-request-id: refund_sync_refund_sync_req
Sent 1 request and received 0 responses

ERROR:
  Code: Internal
  Message: Failed to deserialize connector response
```

</details>


[Back to Connector Suite](../refund-sync.md) | [Back to Overview](../../../test_overview.md)
