# Scenario `create_customer`

- Suite: `create_customer`
- Service: `CustomerService/Create`
- PM / PMT: `-` / `-`

## Connector Summary

| Connector | Result | Prerequisites |
|:----------|:------:|:--------------|
| `authorizedotnet` | [PASS](./scenarios/create-customer/create-customer.md#connector-authorizedotnet) | None |
| `stripe` | [PASS](./scenarios/create-customer/create-customer.md#connector-stripe) | None |

---

<a id="connector-authorizedotnet"></a>
## Connector `authorizedotnet` — `PASS`


**Pre Requisites Executed**

- None
<details>
<summary>Show gRPC Request (masked)</summary>

```bash
grpcurl -plaintext \
  -H "x-connector: authorizedotnet" \
  -H "x-merchant-id: test_merchant" \
  -H "x-tenant-id: default" \
  -H "x-request-id: create_customer_create_customer_req" \
  -H "x-connector-request-reference-id: create_customer_create_customer_ref" \
  -H "x-auth: ***MASKED***" \
  -H "x-api-key: ***MASKED***" \
  -H "x-key1: ***MASKED***" \
  -d @ localhost:8000 types.CustomerService/Create <<'JSON'
{
  "merchant_customer_id": "mcui_d610ca9abc874f39aee3fdba67e8d68d",
  "customer_name": "Mia Wilson",
  "email": {
    "value": "casey.7356@sandbox.example.com"
  },
  "phone_number": "+914797306635",
  "address": {
    "shipping_address": {
      "first_name": {
        "value": "Mia"
      },
      "last_name": {
        "value": "Taylor"
      },
      "line1": {
        "value": "635 Oak Ln"
      },
      "line2": {
        "value": "5231 Sunset Ave"
      },
      "line3": {
        "value": "4027 Sunset Blvd"
      },
      "city": {
        "value": "Seattle"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "13356"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "sam.3835@testmail.io"
      },
      "phone_number": {
        "value": "8463688357"
      },
      "phone_country_code": "+91"
    },
    "billing_address": {
      "first_name": {
        "value": "Noah"
      },
      "last_name": {
        "value": "Brown"
      },
      "line1": {
        "value": "4905 Pine St"
      },
      "line2": {
        "value": "3942 Pine Dr"
      },
      "line3": {
        "value": "5757 Market Rd"
      },
      "city": {
        "value": "Chicago"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "58450"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "riley.9038@sandbox.example.com"
      },
      "phone_number": {
        "value": "4608507927"
      },
      "phone_country_code": "+91"
    }
  },
  "test_mode": true
}
JSON
```

</details>

<details>
<summary>Show gRPC Response (masked)</summary>

```text
Resolved method descriptor:
// Create customer record in the payment processor system. Stores customer details
// for future payment operations without re-sending personal information.
rpc Create ( .types.CustomerServiceCreateRequest ) returns ( .types.CustomerServiceCreateResponse );

Request metadata to send:
x-api-key: ***MASKED***
x-auth: ***MASKED***
x-connector: authorizedotnet
x-connector-request-reference-id: create_customer_create_customer_ref
x-key1: ***MASKED***
x-merchant-id: test_merchant
x-request-id: create_customer_create_customer_req
x-tenant-id: default

Response headers received:
content-type: application/grpc
date: Thu, 12 Mar 2026 15:40:05 GMT
x-request-id: create_customer_create_customer_req

Response contents:
{
  "merchantCustomerId": "934839049",
  "connectorCustomerId": "934839049",
  "statusCode": 200,
  "responseHeaders": {
    "access-control-allow-credentials": "true",
    "access-control-allow-headers": "x-requested-with,cache-control,content-type,origin,method,SOAPAction",
    "access-control-allow-methods": "PUT,OPTIONS,POST,GET",
    "access-control-allow-origin": "*",
    "cache-control": "no-cache, no-store, max-age=0",
    "content-length": "232",
    "content-type": "application/json; charset=utf-8",
    "date": "Thu, 12 Mar 2026 15:40:04 GMT",
    "expires": "-1",
    "pragma": "no-cache",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-cnection": "close",
    "x-download-options": "noopen",
    "x-opnet-transaction-trace": "6275c255-1f58-458f-b516-e5c061e8590b-12436-10988499"
  }
}

Response trailers received:
(empty)
Sent 1 request and received 1 response
```

</details>

<details>
<summary>Show Request Body</summary>

```json
{
  "merchant_customer_id": "mcui_d610ca9abc874f39aee3fdba67e8d68d",
  "customer_name": "Mia Wilson",
  "email": {
    "value": "casey.7356@sandbox.example.com"
  },
  "phone_number": "+914797306635",
  "address": {
    "shipping_address": {
      "first_name": {
        "value": "Mia"
      },
      "last_name": {
        "value": "Taylor"
      },
      "line1": {
        "value": "635 Oak Ln"
      },
      "line2": {
        "value": "5231 Sunset Ave"
      },
      "line3": {
        "value": "4027 Sunset Blvd"
      },
      "city": {
        "value": "Seattle"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "13356"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "sam.3835@testmail.io"
      },
      "phone_number": {
        "value": "8463688357"
      },
      "phone_country_code": "+91"
    },
    "billing_address": {
      "first_name": {
        "value": "Noah"
      },
      "last_name": {
        "value": "Brown"
      },
      "line1": {
        "value": "4905 Pine St"
      },
      "line2": {
        "value": "3942 Pine Dr"
      },
      "line3": {
        "value": "5757 Market Rd"
      },
      "city": {
        "value": "Chicago"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "58450"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "riley.9038@sandbox.example.com"
      },
      "phone_number": {
        "value": "4608507927"
      },
      "phone_country_code": "+91"
    }
  },
  "test_mode": true
}
```

</details>

<details>
<summary>Show Response Body</summary>

```json
{
  "merchantCustomerId": "934839049",
  "connectorCustomerId": "934839049",
  "statusCode": 200,
  "responseHeaders": {
    "access-control-allow-credentials": "true",
    "access-control-allow-headers": "x-requested-with,cache-control,content-type,origin,method,SOAPAction",
    "access-control-allow-methods": "PUT,OPTIONS,POST,GET",
    "access-control-allow-origin": "*",
    "cache-control": "no-cache, no-store, max-age=0",
    "content-length": "232",
    "content-type": "application/json; charset=utf-8",
    "date": "Thu, 12 Mar 2026 15:40:04 GMT",
    "expires": "-1",
    "pragma": "no-cache",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-cnection": "close",
    "x-download-options": "noopen",
    "x-opnet-transaction-trace": "6275c255-1f58-458f-b516-e5c061e8590b-12436-10988499"
  }
}
```

</details>


---

<a id="connector-stripe"></a>
## Connector `stripe` — `PASS`


**Pre Requisites Executed**

- None
<details>
<summary>Show gRPC Request (masked)</summary>

```bash
grpcurl -plaintext \
  -H "x-connector: stripe" \
  -H "x-merchant-id: test_merchant" \
  -H "x-tenant-id: default" \
  -H "x-request-id: create_customer_create_customer_req" \
  -H "x-connector-request-reference-id: create_customer_create_customer_ref" \
  -H "x-auth: ***MASKED***" \
  -H "x-api-key: ***MASKED***" \
  -d @ localhost:8000 types.CustomerService/Create <<'JSON'
{
  "merchant_customer_id": "mcui_83489bc461fe456d89b4a9b77473de73",
  "customer_name": "Noah Brown",
  "email": {
    "value": "riley.4066@testmail.io"
  },
  "phone_number": "+448122500454",
  "address": {
    "shipping_address": {
      "first_name": {
        "value": "Ethan"
      },
      "last_name": {
        "value": "Brown"
      },
      "line1": {
        "value": "1363 Main Ln"
      },
      "line2": {
        "value": "8933 Pine Dr"
      },
      "line3": {
        "value": "3755 Main St"
      },
      "city": {
        "value": "San Francisco"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "72906"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "jordan.1784@testmail.io"
      },
      "phone_number": {
        "value": "1868198982"
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
        "value": "8602 Oak Ln"
      },
      "line2": {
        "value": "8843 Sunset Rd"
      },
      "line3": {
        "value": "3223 Oak Blvd"
      },
      "city": {
        "value": "Seattle"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "18024"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "casey.6895@testmail.io"
      },
      "phone_number": {
        "value": "4078821476"
      },
      "phone_country_code": "+91"
    }
  },
  "test_mode": true
}
JSON
```

</details>

<details>
<summary>Show gRPC Response (masked)</summary>

```text
Resolved method descriptor:
// Create customer record in the payment processor system. Stores customer details
// for future payment operations without re-sending personal information.
rpc Create ( .types.CustomerServiceCreateRequest ) returns ( .types.CustomerServiceCreateResponse );

Request metadata to send:
x-api-key: ***MASKED***
x-auth: ***MASKED***
x-connector: stripe
x-connector-request-reference-id: create_customer_create_customer_ref
x-merchant-id: test_merchant
x-request-id: create_customer_create_customer_req
x-tenant-id: default

Response headers received:
content-type: application/grpc
date: Thu, 12 Mar 2026 15:42:33 GMT
x-request-id: create_customer_create_customer_req

Response contents:
{
  "merchantCustomerId": "cus_U8SINPZPkrgRCk",
  "connectorCustomerId": "cus_U8SINPZPkrgRCk",
  "statusCode": 200,
  "responseHeaders": {
    "access-control-allow-credentials": "true",
    "access-control-allow-methods": "GET, HEAD, PUT, PATCH, POST, DELETE",
    "access-control-allow-origin": "*",
    "access-control-expose-headers": "Request-Id, Stripe-Manage-Version, Stripe-Should-Retry, X-Stripe-External-Auth-Required, X-Stripe-Privileged-Session-Required",
    "access-control-max-age": "300",
    "cache-control": "no-cache, no-store",
    "connection": "keep-alive",
    "content-length": "670",
    "content-security-policy": "base-uri 'none'; default-src 'none'; form-action 'none'; frame-ancestors 'none'; img-src 'self'; script-src 'self' 'report-sample'; style-src 'self'; worker-src 'none'; upgrade-insecure-requests; report-uri https://q.stripe.com/csp-violation?q=XbpkE0Obtc-D-_OVcHByv3HX2Cz2ZXWthan_OSmhaX_cdx20p33NXUJkyzusgJOGoDWC714Lefdz6v3w",
    "content-type": "application/json",
    "date": "Thu, 12 Mar 2026 15:42:33 GMT",
    "idempotency-key": "81b91bca-527f-412d-bfd5-a1b4090fcda6",
    "original-request": "req_Ts03rAAyOukmuh",
    "request-id": "req_Ts03rAAyOukmuh",
    "server": "nginx",
    "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
    "stripe-should-retry": "false",
    "stripe-version": "2022-11-15",
    "vary": "Origin",
    "x-stripe-priority-routing-enabled": "true",
    "x-stripe-routing-context-priority-tier": "api-testmode",
    "x-wc": "ABGHIJ"
  }
}

Response trailers received:
(empty)
Sent 1 request and received 1 response
```

</details>

<details>
<summary>Show Request Body</summary>

```json
{
  "merchant_customer_id": "mcui_83489bc461fe456d89b4a9b77473de73",
  "customer_name": "Noah Brown",
  "email": {
    "value": "riley.4066@testmail.io"
  },
  "phone_number": "+448122500454",
  "address": {
    "shipping_address": {
      "first_name": {
        "value": "Ethan"
      },
      "last_name": {
        "value": "Brown"
      },
      "line1": {
        "value": "1363 Main Ln"
      },
      "line2": {
        "value": "8933 Pine Dr"
      },
      "line3": {
        "value": "3755 Main St"
      },
      "city": {
        "value": "San Francisco"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "72906"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "jordan.1784@testmail.io"
      },
      "phone_number": {
        "value": "1868198982"
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
        "value": "8602 Oak Ln"
      },
      "line2": {
        "value": "8843 Sunset Rd"
      },
      "line3": {
        "value": "3223 Oak Blvd"
      },
      "city": {
        "value": "Seattle"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "18024"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "casey.6895@testmail.io"
      },
      "phone_number": {
        "value": "4078821476"
      },
      "phone_country_code": "+91"
    }
  },
  "test_mode": true
}
```

</details>

<details>
<summary>Show Response Body</summary>

```json
{
  "merchantCustomerId": "cus_U8SINPZPkrgRCk",
  "connectorCustomerId": "cus_U8SINPZPkrgRCk",
  "statusCode": 200,
  "responseHeaders": {
    "access-control-allow-credentials": "true",
    "access-control-allow-methods": "GET, HEAD, PUT, PATCH, POST, DELETE",
    "access-control-allow-origin": "*",
    "access-control-expose-headers": "Request-Id, Stripe-Manage-Version, Stripe-Should-Retry, X-Stripe-External-Auth-Required, X-Stripe-Privileged-Session-Required",
    "access-control-max-age": "300",
    "cache-control": "no-cache, no-store",
    "connection": "keep-alive",
    "content-length": "670",
    "content-security-policy": "base-uri 'none'; default-src 'none'; form-action 'none'; frame-ancestors 'none'; img-src 'self'; script-src 'self' 'report-sample'; style-src 'self'; worker-src 'none'; upgrade-insecure-requests; report-uri https://q.stripe.com/csp-violation?q=XbpkE0Obtc-D-_OVcHByv3HX2Cz2ZXWthan_OSmhaX_cdx20p33NXUJkyzusgJOGoDWC714Lefdz6v3w",
    "content-type": "application/json",
    "date": "Thu, 12 Mar 2026 15:42:33 GMT",
    "idempotency-key": "81b91bca-527f-412d-bfd5-a1b4090fcda6",
    "original-request": "req_Ts03rAAyOukmuh",
    "request-id": "req_Ts03rAAyOukmuh",
    "server": "nginx",
    "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
    "stripe-should-retry": "false",
    "stripe-version": "2022-11-15",
    "vary": "Origin",
    "x-stripe-priority-routing-enabled": "true",
    "x-stripe-routing-context-priority-tier": "api-testmode",
    "x-wc": "ABGHIJ"
  }
}
```

</details>


[Back to Overview](../../test_overview.md)
