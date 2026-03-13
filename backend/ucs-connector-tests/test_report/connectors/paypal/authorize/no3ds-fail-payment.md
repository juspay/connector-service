# Connector `paypal` / Suite `authorize` / Scenario `no3ds_fail_payment`

- Service: `PaymentService/Authorize`
- PM / PMT: `card` / `credit`
- Result: `FAIL`

**Error**

```text
assertion failed for field 'error': expected field to exist
```

**Pre Requisites Executed**

<details>
<summary>1. create_access_token(create_access_token) — PASS</summary>

<details>
<summary>Show Dependency Request (masked)</summary>

```bash
grpcurl -plaintext \
  -H "x-connector: paypal" \
  -H "x-merchant-id: test_merchant" \
  -H "x-tenant-id: default" \
  -H "x-request-id: create_access_token_create_access_token_req" \
  -H "x-connector-request-reference-id: create_access_token_create_access_token_ref" \
  -H "x-auth: ***MASKED***" \
  -H "x-api-key: ***MASKED***" \
  -H "x-key1: ***MASKED***" \
  -d @ localhost:8000 types.MerchantAuthenticationService/CreateAccessToken <<'JSON'
{
  "merchant_access_token_id": ***MASKED***"
  "connector": "STRIPE",
  "test_mode": true
}
JSON
```

</details>

<details>
<summary>Show Dependency Response (masked)</summary>

```text
Resolved method descriptor:
// Generate short-lived connector authentication token. Provides secure
// credentials for connector API access without storing secrets client-side.
rpc CreateAccessToken ( .types.MerchantAuthenticationServiceCreateAccessTokenRequest ) returns ( .types.MerchantAuthenticationServiceCreateAccessTokenResponse );

Request metadata to send:
x-api-key: ***MASKED***
x-auth: ***MASKED***
x-connector: paypal
x-connector-request-reference-id: create_access_token_create_access_token_ref
x-key1: ***MASKED***
x-merchant-id: test_merchant
x-request-id: create_access_token_create_access_token_req
x-tenant-id: default

Response headers received:
content-type: application/grpc
date: Thu, 12 Mar 2026 15:40:54 GMT
x-request-id: create_access_token_create_access_token_req

Response contents:
{
  "accessToken": ***MASKED***
    "value": "A21AAIimoa-rtl4fS-Ww8qyaVqqMy85SmTVtYFXjFdA8emovXqLOH2syMZB9-jr5IkNejzMI3nGlOB7HG9auRQqlejeSk0Q_A"
  },
  "expiresInSeconds": "30544",
  "status": "OPERATION_STATUS_SUCCESS",
  "statusCode": 200
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
  -H "x-connector: paypal" \
  -H "x-merchant-id: test_merchant" \
  -H "x-tenant-id: default" \
  -H "x-request-id: authorize_no3ds_fail_payment_req" \
  -H "x-connector-request-reference-id: authorize_no3ds_fail_payment_ref" \
  -H "x-auth: ***MASKED***" \
  -H "x-api-key: ***MASKED***" \
  -H "x-key1: ***MASKED***" \
  -d @ localhost:8000 types.PaymentService/Authorize <<'JSON'
{
  "merchant_transaction_id": "mti_4e70e565b8de4b4d8d710a9ba283d52f",
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
        "value": "Ava Wilson"
      },
      "card_type": "credit"
    }
  },
  "capture_method": "AUTOMATIC",
  "customer": {
    "name": "Noah Johnson",
    "email": {
      "value": "riley.1138@example.com"
    },
    "id": "cust_82304e7c2bff4be3aae3abf46299b29d",
    "phone_number": "+18828608731"
  },
  "state": {
    "access_token": ***MASKED***
      "token": ***MASKED***
        "value": "A21AAIimoa-rtl4fS-Ww8qyaVqqMy85SmTVtYFXjFdA8emovXqLOH2syMZB9-jr5IkNejzMI3nGlOB7HG9auRQqlejeSk0Q_A"
      },
      "expires_in_seconds": "30544"
    }
  },
  "address": {
    "shipping_address": {
      "first_name": {
        "value": "Ethan"
      },
      "last_name": {
        "value": "Miller"
      },
      "line1": {
        "value": "1907 Oak Blvd"
      },
      "line2": {
        "value": "9656 Main Rd"
      },
      "line3": {
        "value": "7252 Oak Blvd"
      },
      "city": {
        "value": "San Francisco"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "11400"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "alex.3091@testmail.io"
      },
      "phone_number": {
        "value": "7212177498"
      },
      "phone_country_code": "+91"
    },
    "billing_address": {
      "first_name": {
        "value": "Noah"
      },
      "last_name": {
        "value": "Johnson"
      },
      "line1": {
        "value": "4763 Pine St"
      },
      "line2": {
        "value": "9779 Main Rd"
      },
      "line3": {
        "value": "737 Lake Ave"
      },
      "city": {
        "value": "New York"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "98430"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "jordan.1773@testmail.io"
      },
      "phone_number": {
        "value": "1244520078"
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
  "test_mode": true,
  "locale": "en-US"
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
x-connector: paypal
x-connector-request-reference-id: authorize_no3ds_fail_payment_ref
x-key1: ***MASKED***
x-merchant-id: test_merchant
x-request-id: authorize_no3ds_fail_payment_req
x-tenant-id: default

Response headers received:
content-type: application/grpc
date: Thu, 12 Mar 2026 15:41:03 GMT
x-request-id: authorize_no3ds_fail_payment_req

Response contents:
{
  "merchantTransactionId": "mti_4e70e565b8de4b4d8d710a9ba283d52f",
  "connectorTransactionId": "44740332CP372645W",
  "status": "CHARGED",
  "statusCode": 201,
  "responseHeaders": {
    "accept-ranges": "bytes",
    "access-control-expose-headers": "Server-Timing",
    "cache-control": "max-age=0, no-cache, no-store, must-revalidate",
    "connection": "keep-alive",
    "content-length": "2537",
    "content-type": "application/json",
    "date": "Thu, 12 Mar 2026 15:41:03 GMT",
    "edge-control": "max-age=0",
    "http_x_pp_az_locator": "ccg18.slc",
    "paypal-debug-id": "f50824573d24b",
    "server": "nginx",
    "server-timing": "traceparent;desc=\"00-0000000000000000000f50824573d24b-9782dff4534f561e-01\"",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "vary": "Accept-Encoding",
    "via": "1.1 varnish, 1.1 varnish",
    "x-cache": "MISS, MISS",
    "x-cache-hits": "0, 0",
    "x-served-by": "cache-sin-wsat1880062-SIN, cache-bom-vanm7210086-BOM",
    "x-timer": "S1773330061.095059,VS0,VE2134"
  },
  "state": {
    "accessToken": ***MASKED***
      "token": ***MASKED***
        "value": "A21AAIimoa-rtl4fS-Ww8qyaVqqMy85SmTVtYFXjFdA8emovXqLOH2syMZB9-jr5IkNejzMI3nGlOB7HG9auRQqlejeSk0Q_A"
      },
      "expiresInSeconds": "30544"
    }
  },
  "rawConnectorResponse": {
    "value": "{\"id\":\"44740332CP372645W\",\"intent\":\"CAPTURE\",\"status\":\"COMPLETED\",\"payment_source\":{\"card\":{\"name\":\"Noah Johnson\",\"last_digits\":\"0002\",\"expiry\":\"2035-01\",\"brand\":\"VISA\",\"available_networks\":[\"VISA\"],\"type\":\"CREDIT\",\"bin_details\":{\"bin\":\"40000000000\",\"issuing_bank\":\"CARDINAL_TESTING_VISA\",\"bin_country_code\":\"IT\",\"products\":[\"CORPORATE\"]}}},\"purchase_units\":[{\"reference_id\":\"mti_4e70e565b8de4b4d8d710a9ba283d52f\",\"amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\",\"breakdown\":{\"item_total\":{\"currency_code\":\"USD\",\"value\":\"60.00\"},\"shipping\":{\"currency_code\":\"USD\",\"value\":\"0.00\"},\"handling\":{\"currency_code\":\"USD\",\"value\":\"0.00\"},\"tax_total\":{\"currency_code\":\"USD\",\"value\":\"0.00\"},\"insurance\":{\"currency_code\":\"USD\",\"value\":\"0.00\"},\"shipping_discount\":{\"currency_code\":\"USD\",\"value\":\"0.00\"}}},\"payee\":{\"email_address\":\"sb-itwmi27136406@business.example.com\",\"merchant_id\":\"DUM69V9DDNYEJ\"},\"description\":\"Payment for invoice mti_4e70e565b8de4b4d8d710a9ba283d52f\",\"invoice_id\":\"mti_4e70e565b8de4b4d8d710a9ba283d52f\",\"soft_descriptor\":\"TEST STORE\",\"items\":[{\"name\":\"Payment for invoice mti_4e70e565b8de4b4d8d710a9ba283d52f\",\"unit_amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\"},\"tax\":{\"currency_code\":\"USD\",\"value\":\"0.00\"},\"quantity\":\"1\"}],\"shipping\":{\"name\":{\"full_name\":\"Ethan\"},\"address\":{\"address_line_1\":\"1907 Oak Blvd\",\"admin_area_2\":\"San Francisco\",\"postal_code\":\"11400\",\"country_code\":\"US\"}},\"payments\":{\"captures\":[{\"id\":\"7G951242H1237245J\",\"status\":\"COMPLETED\",\"amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\"},\"final_capture\":true,\"seller_protection\":{\"status\":\"NOT_ELIGIBLE\"},\"seller_receivable_breakdown\":{\"gross_amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\"},\"net_amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\"}},\"invoice_id\":\"mti_4e70e565b8de4b4d8d710a9ba283d52f\",\"links\":[{\"href\":\"https://api.sandbox.paypal.com/v2/payments/captures/7G951242H1237245J\",\"rel\":\"self\",\"method\":\"GET\"},{\"href\":\"https://api.sandbox.paypal.com/v2/payments/captures/7G951242H1237245J/refund\",\"rel\":\"refund\",\"method\":\"POST\"},{\"href\":\"https://api.sandbox.paypal.com/v2/checkout/orders/44740332CP372645W\",\"rel\":\"up\",\"method\":\"GET\"}],\"create_time\":\"2026-03-12T15:41:02Z\",\"update_time\":\"2026-03-12T15:41:02Z\",\"network_transaction_reference\":{\"id\":\"625879325622783\",\"network\":\"VISA\"},\"processor_response\":{\"avs_code\":\"A\",\"cvv_code\":\"M\",\"response_code\":\"0000\"}}]}}],\"create_time\":\"2026-03-12T15:41:02Z\",\"update_time\":\"2026-03-12T15:41:02Z\",\"links\":[{\"href\":\"https://api.sandbox.paypal.com/v2/checkout/orders/44740332CP372645W\",\"rel\":\"self\",\"method\":\"GET\"}]}"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://api-m.sandbox.paypal.com/v2/checkout/orders\",\"method\":\"POST\",\"headers\":{\"Content-Type\":\"application/json\",\"Prefer\":\"return=representation\",\"via\":\"HyperSwitch\",\"PayPal-Request-Id\":\"mti_4e70e565b8de4b4d8d710a9ba283d52f\",\"PayPal-Partner-Attribution-Id\":\"HyperSwitchlegacy_Ecom\",\"Authorization\":\"Bearer ***MASKED***"},\"body\":{\"intent\":\"CAPTURE\",\"purchase_units\":[{\"reference_id\":\"mti_4e70e565b8de4b4d8d710a9ba283d52f\",\"invoice_id\":\"mti_4e70e565b8de4b4d8d710a9ba283d52f\",\"custom_id\":null,\"amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\",\"breakdown\":{\"item_total\":{\"currency_code\":\"USD\",\"value\":\"60.00\"},\"tax_total\":null,\"shipping\":{\"currency_code\":\"USD\",\"value\":\"0.00\"}}},\"shipping\":{\"address\":{\"address_line_1\":\"1907 Oak Blvd\",\"postal_code\":\"11400\",\"country_code\":\"US\",\"admin_area_2\":\"San Francisco\"},\"name\":{\"full_name\":\"Ethan\"}},\"items\":[{\"name\":\"Payment for invoice mti_4e70e565b8de4b4d8d710a9ba283d52f\",\"quantity\":1,\"unit_amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\"},\"tax\":null}]}],\"payment_source\":{\"card\":{\"billing_address\":{\"address_line_1\":\"4763 Pine St\",\"postal_code\":\"98430\",\"country_code\":\"US\",\"admin_area_2\":\"New York\"},\"expiry\":\"2035-01\",\"name\":\"Noah Johnson\",\"number\":\"4000000000000002\",\"security_code\":\"123\",\"attributes\":{\"vault\":null,\"verification\":null}}}}}"
  },
  "mandateReference": {
    "connectorMandateId": {}
  },
  "connectorFeatureData": {
    "value": "{\"authorize_id\":null,\"capture_id\":\"7G951242H1237245J\",\"incremental_authorization_id\":null,\"psync_flow\":\"CAPTURE\",\"next_action\":null,\"order_id\":null}"
  }
}

Response trailers received:
(empty)
Sent 1 request and received 1 response
```

</details>


[Back to Connector Suite](../authorize.md) | [Back to Overview](../../../test_overview.md)
