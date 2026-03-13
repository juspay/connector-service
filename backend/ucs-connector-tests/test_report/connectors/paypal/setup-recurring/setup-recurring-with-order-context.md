# Connector `paypal` / Suite `setup_recurring` / Scenario `setup_recurring_with_order_context`

- Service: `PaymentService/SetupRecurring`
- PM / PMT: `card` / `credit`
- Result: `PASS`

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
date: Thu, 12 Mar 2026 15:42:20 GMT
x-request-id: create_access_token_create_access_token_req

Response contents:
{
  "accessToken": ***MASKED***
    "value": "A21AAIimoa-rtl4fS-Ww8qyaVqqMy85SmTVtYFXjFdA8emovXqLOH2syMZB9-jr5IkNejzMI3nGlOB7HG9auRQqlejeSk0Q_A"
  },
  "expiresInSeconds": "30458",
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
  -H "x-request-id: setup_recurring_setup_recurring_with_order_context_req" \
  -H "x-connector-request-reference-id: setup_recurring_setup_recurring_with_order_context_ref" \
  -H "x-auth: ***MASKED***" \
  -H "x-api-key: ***MASKED***" \
  -H "x-key1: ***MASKED***" \
  -d @ localhost:8000 types.PaymentService/SetupRecurring <<'JSON'
{
  "merchant_recurring_payment_id": "mrpi_412bdc33e58c4746860ed4b480f75cd2",
  "amount": {
    "minor_amount": 6000,
    "currency": "USD"
  },
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
        "value": "Noah Taylor"
      },
      "card_type": "credit"
    }
  },
  "customer": {
    "name": "Noah Smith",
    "email": {
      "value": "morgan.6595@testmail.io"
    },
    "id": "cust_1e4178f7963c4d978e4544b7c0d81b53",
    "phone_number": "+17079153666"
  },
  "state": {
    "access_token": ***MASKED***
      "token": ***MASKED***
        "value": "A21AAIimoa-rtl4fS-Ww8qyaVqqMy85SmTVtYFXjFdA8emovXqLOH2syMZB9-jr5IkNejzMI3nGlOB7HG9auRQqlejeSk0Q_A"
      },
      "expires_in_seconds": "30458"
    }
  },
  "address": {
    "billing_address": {
      "first_name": {
        "value": "Liam"
      },
      "last_name": {
        "value": "Wilson"
      },
      "line1": {
        "value": "1585 Market Rd"
      },
      "line2": {
        "value": "8701 Sunset Rd"
      },
      "line3": {
        "value": "5522 Lake Rd"
      },
      "city": {
        "value": "San Francisco"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "89310"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "jordan.7502@sandbox.example.com"
      },
      "phone_number": {
        "value": "4242445520"
      },
      "phone_country_code": "+91"
    }
  },
  "auth_type": "NO_THREE_DS",
  "enrolled_for_3ds": false,
  "customer_acceptance": {
    "acceptance_type": "OFFLINE"
  },
  "setup_future_usage": "OFF_SESSION",
  "off_session": true,
  "merchant_order_id": "gen_848248",
  "order_category": "subscription",
  "return_url": "https://example.com/payment/return",
  "webhook_url": "https://example.com/payment/webhook",
  "complete_authorize_url": "https://example.com/payment/complete"
}
JSON
```

</details>

<details>
<summary>Show Response (masked)</summary>

```text
Resolved method descriptor:
// Setup a recurring payment instruction for future payments/ debits. This could be
// for SaaS subscriptions, monthly bill payments, insurance payments and similar use cases.
rpc SetupRecurring ( .types.PaymentServiceSetupRecurringRequest ) returns ( .types.PaymentServiceSetupRecurringResponse );

Request metadata to send:
x-api-key: ***MASKED***
x-auth: ***MASKED***
x-connector: paypal
x-connector-request-reference-id: setup_recurring_setup_recurring_with_order_context_ref
x-key1: ***MASKED***
x-merchant-id: test_merchant
x-request-id: setup_recurring_setup_recurring_with_order_context_req
x-tenant-id: default

Response headers received:
content-type: application/grpc
date: Thu, 12 Mar 2026 15:42:23 GMT
x-request-id: setup_recurring_setup_recurring_with_order_context_req

Response contents:
{
  "connectorRecurringPaymentId": "7sw22062rm943115h",
  "status": "CHARGED",
  "statusCode": 201,
  "responseHeaders": {
    "accept-ranges": "bytes",
    "access-control-expose-headers": "Server-Timing",
    "cache-control": "max-age=0, no-cache, no-store, must-revalidate",
    "connection": "keep-alive",
    "content-length": "585",
    "content-type": "application/json",
    "date": "Thu, 12 Mar 2026 15:42:23 GMT",
    "edge-control": "max-age=0",
    "http_x_pp_az_locator": "ccg18.slc",
    "paypal-debug-id": "f402332aba172",
    "server": "nginx",
    "server-timing": "traceparent;desc=\"00-0000000000000000000f402332aba172-436c6c4027362b43-01\"",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "vary": "Accept-Encoding",
    "via": "1.1 varnish, 1.1 varnish",
    "x-cache": "MISS, MISS",
    "x-cache-hits": "0, 0",
    "x-served-by": "cache-sin-wsss1830051-SIN, cache-bom-vanm7210086-BOM",
    "x-timer": "S1773330142.235237,VS0,VE1015"
  },
  "mandateReference": {
    "connectorMandateId": {
      "connectorMandateId": "7sw22062rm943115h"
    }
  },
  "merchantRecurringPaymentId": "7sw22062rm943115h",
  "capturedAmount": "0",
  "state": {
    "accessToken": ***MASKED***
      "token": ***MASKED***
        "value": "A21AAIimoa-rtl4fS-Ww8qyaVqqMy85SmTVtYFXjFdA8emovXqLOH2syMZB9-jr5IkNejzMI3nGlOB7HG9auRQqlejeSk0Q_A"
      },
      "expiresInSeconds": "30458"
    }
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://api-m.sandbox.paypal.com/v3/vault/payment-tokens/\",\"method\":\"POST\",\"headers\":{\"via\":\"HyperSwitch\",\"PayPal-Partner-Attribution-Id\":\"HyperSwitchlegacy_Ecom\",\"PayPal-Request-Id\":\"mrpi_412bdc33e58c4746860ed4b480f75cd2\",\"Authorization\":\"Bearer ***MASKED***",\"Prefer\":\"return=representation\",\"Content-Type\":\"application/json\"},\"body\":{\"payment_source\":{\"card\":{\"billing_address\":{\"address_line_1\":\"1585 Market Rd\",\"postal_code\":\"89310\",\"country_code\":\"US\",\"admin_area_2\":\"San Francisco\"},\"expiry\":\"2030-08\",\"name\":\"Liam Wilson\",\"number\":\"4111111111111111\"}}}}"
  }
}

Response trailers received:
(empty)
Sent 1 request and received 1 response
```

</details>


[Back to Connector Suite](../setup-recurring.md) | [Back to Overview](../../../test_overview.md)
