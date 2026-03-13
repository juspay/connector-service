# Connector `stripe` / Suite `recurring_charge` / Scenario `recurring_charge`

- Service: `RecurringPaymentService/Charge`
- PM / PMT: `-` / `-`
- Result: `FAIL`

**Error**

```text
assertion failed for field 'connector_transaction_id': expected field to exist
```

**Pre Requisites Executed**

<details>
<summary>1. create_customer(create_customer) — PASS</summary>

<details>
<summary>Show Dependency Request (masked)</summary>

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
  "merchant_customer_id": "mcui_a21886fdac44442e897406378642f787",
  "customer_name": "Ethan Smith",
  "email": {
    "value": "riley.4289@example.com"
  },
  "phone_number": "+15496645083",
  "address": {
    "shipping_address": {
      "first_name": {
        "value": "Noah"
      },
      "last_name": {
        "value": "Smith"
      },
      "line1": {
        "value": "1942 Lake Blvd"
      },
      "line2": {
        "value": "990 Sunset Dr"
      },
      "line3": {
        "value": "2076 Oak Dr"
      },
      "city": {
        "value": "Los Angeles"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "84409"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "riley.3225@example.com"
      },
      "phone_number": {
        "value": "8792928287"
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
        "value": "6397 Sunset Ave"
      },
      "line2": {
        "value": "5544 Sunset Ln"
      },
      "line3": {
        "value": "5711 Oak St"
      },
      "city": {
        "value": "San Francisco"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "73498"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "riley.4852@testmail.io"
      },
      "phone_number": {
        "value": "4145624997"
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
<summary>Show Dependency Response (masked)</summary>

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
date: Thu, 12 Mar 2026 15:43:32 GMT
x-request-id: create_customer_create_customer_req

Response contents:
{
  "merchantCustomerId": "cus_U8SJr1fMbLIR7j",
  "connectorCustomerId": "cus_U8SJr1fMbLIR7j",
  "statusCode": 200,
  "responseHeaders": {
    "access-control-allow-credentials": "true",
    "access-control-allow-methods": "GET, HEAD, PUT, PATCH, POST, DELETE",
    "access-control-allow-origin": "*",
    "access-control-expose-headers": "Request-Id, Stripe-Manage-Version, Stripe-Should-Retry, X-Stripe-External-Auth-Required, X-Stripe-Privileged-Session-Required",
    "access-control-max-age": "300",
    "cache-control": "no-cache, no-store",
    "connection": "keep-alive",
    "content-length": "671",
    "content-security-policy": "base-uri 'none'; default-src 'none'; form-action 'none'; frame-ancestors 'none'; img-src 'self'; script-src 'self' 'report-sample'; style-src 'self'; worker-src 'none'; upgrade-insecure-requests; report-uri https://q.stripe.com/csp-violation?q=XbpkE0Obtc-D-_OVcHByv3HX2Cz2ZXWthan_OSmhaX_cdx20p33NXUJkyzusgJOGoDWC714Lefdz6v3w",
    "content-type": "application/json",
    "date": "Thu, 12 Mar 2026 15:43:32 GMT",
    "idempotency-key": "d5d6e401-930b-449b-b671-d173b0a677ee",
    "original-request": "req_90Rnia2Fchyyou",
    "request-id": "req_90Rnia2Fchyyou",
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

</details>
<details>
<summary>2. setup_recurring(setup_recurring) — PASS</summary>

<details>
<summary>Show Dependency Request (masked)</summary>

```bash
grpcurl -plaintext \
  -H "x-connector: stripe" \
  -H "x-merchant-id: test_merchant" \
  -H "x-tenant-id: default" \
  -H "x-request-id: setup_recurring_setup_recurring_req" \
  -H "x-connector-request-reference-id: setup_recurring_setup_recurring_ref" \
  -H "x-auth: ***MASKED***" \
  -H "x-api-key: ***MASKED***" \
  -d @ localhost:8000 types.PaymentService/SetupRecurring <<'JSON'
{
  "merchant_recurring_payment_id": "mrpi_4bbcfb9fd50f4111aa72058f849b6528",
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
        "value": "Mia Miller"
      },
      "card_type": "credit"
    }
  },
  "customer": {
    "name": "Emma Brown",
    "email": {
      "value": "alex.3431@testmail.io"
    },
    "id": "cust_ad8f1f5fef2a43c096db5c1fb86f0ce2",
    "phone_number": "+19415344336",
    "connector_customer_id": "cus_U8SJr1fMbLIR7j"
  },
  "setup_future_usage": "OFF_SESSION",
  "address": {
    "billing_address": {
      "first_name": {
        "value": "Noah"
      },
      "last_name": {
        "value": "Brown"
      },
      "line1": {
        "value": "6397 Sunset Ave"
      },
      "line2": {
        "value": "5544 Sunset Ln"
      },
      "line3": {
        "value": "5711 Oak St"
      },
      "city": {
        "value": "San Francisco"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "73498"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "riley.4852@testmail.io"
      },
      "phone_number": {
        "value": "4145624997"
      },
      "phone_country_code": "+91"
    }
  },
  "auth_type": "NO_THREE_DS",
  "enrolled_for_3ds": false,
  "customer_acceptance": {
    "acceptance_type": "OFFLINE"
  }
}
JSON
```

</details>

<details>
<summary>Show Dependency Response (masked)</summary>

```text
Resolved method descriptor:
// Setup a recurring payment instruction for future payments/ debits. This could be
// for SaaS subscriptions, monthly bill payments, insurance payments and similar use cases.
rpc SetupRecurring ( .types.PaymentServiceSetupRecurringRequest ) returns ( .types.PaymentServiceSetupRecurringResponse );

Request metadata to send:
x-api-key: ***MASKED***
x-auth: ***MASKED***
x-connector: stripe
x-connector-request-reference-id: setup_recurring_setup_recurring_ref
x-merchant-id: test_merchant
x-request-id: setup_recurring_setup_recurring_req
x-tenant-id: default

Response headers received:
content-type: application/grpc
date: Thu, 12 Mar 2026 15:43:33 GMT
x-request-id: setup_recurring_setup_recurring_req

Response contents:
{
  "connectorRecurringPaymentId": "seti_1TABObD5R7gDAGffrzPGyC1d",
  "status": "CHARGED",
  "statusCode": 200,
  "responseHeaders": {
    "access-control-allow-credentials": "true",
    "access-control-allow-methods": "GET, HEAD, PUT, PATCH, POST, DELETE",
    "access-control-allow-origin": "*",
    "access-control-expose-headers": "Request-Id, Stripe-Manage-Version, Stripe-Should-Retry, X-Stripe-External-Auth-Required, X-Stripe-Privileged-Session-Required",
    "access-control-max-age": "300",
    "cache-control": "no-cache, no-store",
    "connection": "keep-alive",
    "content-length": "1997",
    "content-security-policy": "base-uri 'none'; default-src 'none'; form-action 'none'; frame-ancestors 'none'; img-src 'self'; script-src 'self' 'report-sample'; style-src 'self'; worker-src 'none'; upgrade-insecure-requests; report-uri https://q.stripe.com/csp-violation?q=XbpkE0Obtc-D-_OVcHByv3HX2Cz2ZXWthan_OSmhaX_cdx20p33NXUJkyzusgJOGoDWC714Lefdz6v3w",
    "content-type": "application/json",
    "date": "Thu, 12 Mar 2026 15:43:33 GMT",
    "idempotency-key": "47003f1e-bb89-4f1f-b85a-5fcea7183626",
    "original-request": "req_wdG6lzGdeP2YYL",
    "request-id": "req_wdG6lzGdeP2YYL",
    "server": "nginx",
    "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
    "stripe-should-retry": "false",
    "stripe-version": "2022-11-15",
    "vary": "Origin",
    "x-stripe-priority-routing-enabled": "true",
    "x-stripe-routing-context-priority-tier": "api-testmode",
    "x-wc": "ABGHIJ"
  },
  "mandateReference": {
    "connectorMandateId": {
      "connectorMandateId": "pm_1TABOaD5R7gDAGff0h09mPS8",
      "paymentMethodId": "pm_1TABOaD5R7gDAGff0h09mPS8"
    }
  },
  "merchantRecurringPaymentId": "seti_1TABObD5R7gDAGffrzPGyC1d",
  "connectorResponse": {
    "additionalPaymentMethodData": {
      "card": {
        "paymentChecks": "eyJhZGRyZXNzX2xpbmUxX2NoZWNrIjpudWxsLCJhZGRyZXNzX3Bvc3RhbF9jb2RlX2NoZWNrIjpudWxsLCJjdmNfY2hlY2siOiJwYXNzIn0="
      }
    }
  },
  "capturedAmount": "0",
  "state": {
    "connectorCustomerId": "cus_U8SJr1fMbLIR7j"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://api.stripe.com/v1/setup_intents\",\"method\":\"POST\",\"headers\":{\"via\":\"HyperSwitch\",\"Content-Type\":\"application/x-www-form-urlencoded\",\"Authorization\":\"Bearer ***MASKED***",\"stripe-version\":\"2022-11-15\"},\"body\":\"confirm=true\u0026usage=off_session\u0026customer=cus_U8SJr1fMbLIR7j\u0026payment_method_data%5Btype%5D=card\u0026payment_method_data%5Bcard%5D%5Bnumber%5D=4111111111111111\u0026payment_method_data%5Bcard%5D%5Bexp_month%5D=08\u0026payment_method_data%5Bcard%5D%5Bexp_year%5D=30\u0026payment_method_data%5Bcard%5D%5Bcvc%5D=999\u0026payment_method_options%5Bcard%5D%5Brequest_three_d_secure%5D=automatic\u0026metadata%5Border_id%5D=mrpi_4bbcfb9fd50f4111aa72058f849b6528\u0026payment_method_types%5B0%5D=card\u0026expand%5B0%5D=latest_attempt\"}"
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
  -H "x-connector: stripe" \
  -H "x-merchant-id: test_merchant" \
  -H "x-tenant-id: default" \
  -H "x-request-id: recurring_charge_recurring_charge_req" \
  -H "x-connector-request-reference-id: recurring_charge_recurring_charge_ref" \
  -H "x-auth: ***MASKED***" \
  -H "x-api-key: ***MASKED***" \
  -d @ localhost:8000 types.RecurringPaymentService/Charge <<'JSON'
{
  "merchant_charge_id": "mchi_869979259f1a495488525f7912ecd0f8",
  "connector_recurring_payment_id": {
    "connector_mandate_id": {
      "connector_mandate_id": "cmi_4be204289e614f74af717265f79d3897"
    }
  },
  "amount": {
    "minor_amount": 6000,
    "currency": "USD"
  },
  "connector_customer_id": "cus_U8SJr1fMbLIR7j",
  "customer": {
    "connector_customer_id": "cus_U8SJr1fMbLIR7j"
  }
}
JSON
```

</details>

<details>
<summary>Show Response (masked)</summary>

```text
Resolved method descriptor:
// Charge using an existing stored recurring payment instruction. Processes repeat payments for
// subscriptions or recurring billing without collecting payment details.
rpc Charge ( .types.RecurringPaymentServiceChargeRequest ) returns ( .types.RecurringPaymentServiceChargeResponse );

Request metadata to send:
x-api-key: ***MASKED***
x-auth: ***MASKED***
x-connector: stripe
x-connector-request-reference-id: recurring_charge_recurring_charge_ref
x-merchant-id: test_merchant
x-request-id: recurring_charge_recurring_charge_req
x-tenant-id: default

Response headers received:
content-type: application/grpc
date: Thu, 12 Mar 2026 15:43:34 GMT
x-request-id: recurring_charge_recurring_charge_req

Response contents:
{
  "error": {
    "issuerDetails": {
      "networkDetails": {}
    },
    "connectorDetails": {
      "code": "resource_missing",
      "message": "No such PaymentMethod: 'cmi_4be204289e614f74af717265f79d3897'; It's possible this PaymentMethod exists on one of your connected accounts, in which case you should retry this request on that connected account. Learn more at https://stripe.com/docs/connect/authentication",
      "reason": "No such PaymentMethod: 'cmi_4be204289e614f74af717265f79d3897'; It's possible this PaymentMethod exists on one of your connected accounts, in which case you should retry this request on that connected account. Learn more at https://stripe.com/docs/connect/authentication"
    }
  },
  "statusCode": 400,
  "responseHeaders": {
    "access-control-allow-credentials": "true",
    "access-control-allow-methods": "GET, HEAD, PUT, PATCH, POST, DELETE",
    "access-control-allow-origin": "*",
    "access-control-expose-headers": "Request-Id, Stripe-Manage-Version, Stripe-Should-Retry, X-Stripe-External-Auth-Required, X-Stripe-Privileged-Session-Required",
    "access-control-max-age": "300",
    "cache-control": "no-cache, no-store",
    "connection": "keep-alive",
    "content-length": "602",
    "content-security-policy": "base-uri 'none'; default-src 'none'; form-action 'none'; frame-ancestors 'none'; img-src 'self'; script-src 'self' 'report-sample'; style-src 'self'; worker-src 'none'; upgrade-insecure-requests; report-uri https://q.stripe.com/csp-violation?q=XbpkE0Obtc-D-_OVcHByv3HX2Cz2ZXWthan_OSmhaX_cdx20p33NXUJkyzusgJOGoDWC714Lefdz6v3w",
    "content-type": "application/json",
    "date": "Thu, 12 Mar 2026 15:43:34 GMT",
    "idempotency-key": "fc656cd3-1d8f-4424-a497-205095e04a14",
    "original-request": "req_VfSYOmuW6PMvXn",
    "request-id": "req_VfSYOmuW6PMvXn",
    "server": "nginx",
    "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
    "stripe-version": "2022-11-15",
    "vary": "Origin",
    "x-stripe-priority-routing-enabled": "true",
    "x-stripe-routing-context-priority-tier": "api-testmode",
    "x-wc": "ABGHIJ"
  },
  "state": {
    "connectorCustomerId": "cus_U8SJr1fMbLIR7j"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://api.stripe.com/v1/payment_intents\",\"method\":\"POST\",\"headers\":{\"Content-Type\":\"application/x-www-form-urlencoded\",\"stripe-version\":\"2022-11-15\",\"via\":\"HyperSwitch\",\"Authorization\":\"Bearer ***MASKED***"},\"body\":\"amount=6000\u0026currency=USD\u0026metadata%5Border_id%5D=mchi_869979259f1a495488525f7912ecd0f8\u0026return_url=https%3A%2F%2Fjuspay.in%2F\u0026confirm=true\u0026payment_method=cmi_4be204289e614f74af717265f79d3897\u0026customer=cus_U8SJr1fMbLIR7j\u0026capture_method=automatic\u0026payment_method_types%5B0%5D=card\u0026expand%5B0%5D=latest_charge\"}"
  }
}

Response trailers received:
(empty)
Sent 1 request and received 1 response
```

</details>


[Back to Connector Suite](../recurring-charge.md) | [Back to Overview](../../../test_overview.md)
