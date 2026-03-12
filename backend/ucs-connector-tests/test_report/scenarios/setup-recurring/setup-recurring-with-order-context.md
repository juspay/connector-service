# Scenario `setup_recurring_with_order_context`

- Suite: `setup_recurring`
- Service: `PaymentService/SetupRecurring`
- PM / PMT: `card` / `credit`

## Connector Summary

| Connector | Result | Prerequisites |
|:----------|:------:|:--------------|
| `authorizedotnet` | [PASS](./scenarios/setup-recurring/setup-recurring-with-order-context.md#connector-authorizedotnet) | `create_customer(create_customer)` (PASS) |
| `paypal` | [PASS](./scenarios/setup-recurring/setup-recurring-with-order-context.md#connector-paypal) | `create_access_token(create_access_token)` (PASS) |
| `stripe` | [PASS](./scenarios/setup-recurring/setup-recurring-with-order-context.md#connector-stripe) | `create_customer(create_customer)` (PASS) |

---

<a id="connector-authorizedotnet"></a>
## Connector `authorizedotnet` — `PASS`


**Pre Requisites Executed**

<details>
<summary>1. create_customer(create_customer) — PASS</summary>

<details>
<summary>Show Dependency gRPC Request (masked)</summary>

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
  "merchant_customer_id": "mcui_692654de64f04e859d4fcaca1e74f770",
  "customer_name": "Ava Brown",
  "email": {
    "value": "casey.7600@sandbox.example.com"
  },
  "phone_number": "+448122557398",
  "address": {
    "shipping_address": {
      "first_name": {
        "value": "Ethan"
      },
      "last_name": {
        "value": "Brown"
      },
      "line1": {
        "value": "2318 Sunset Ave"
      },
      "line2": {
        "value": "2960 Lake Ln"
      },
      "line3": {
        "value": "961 Oak St"
      },
      "city": {
        "value": "San Francisco"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "44459"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "morgan.9736@example.com"
      },
      "phone_number": {
        "value": "5373368867"
      },
      "phone_country_code": "+91"
    },
    "billing_address": {
      "first_name": {
        "value": "Liam"
      },
      "last_name": {
        "value": "Miller"
      },
      "line1": {
        "value": "6159 Main St"
      },
      "line2": {
        "value": "7029 Pine Ave"
      },
      "line3": {
        "value": "3891 Main Dr"
      },
      "city": {
        "value": "New York"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "80626"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "riley.1514@sandbox.example.com"
      },
      "phone_number": {
        "value": "5773374310"
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
<summary>Show Dependency gRPC Response (masked)</summary>

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
date: Thu, 12 Mar 2026 15:40:48 GMT
x-request-id: create_customer_create_customer_req

Response contents:
{
  "merchantCustomerId": "934839066",
  "connectorCustomerId": "934839066",
  "statusCode": 200,
  "responseHeaders": {
    "access-control-allow-credentials": "true",
    "access-control-allow-headers": "x-requested-with,cache-control,content-type,origin,method,SOAPAction",
    "access-control-allow-methods": "PUT,OPTIONS,POST,GET",
    "access-control-allow-origin": "*",
    "cache-control": "no-cache, no-store, max-age=0",
    "content-length": "232",
    "content-type": "application/json; charset=utf-8",
    "date": "Thu, 12 Mar 2026 15:40:47 GMT",
    "expires": "-1",
    "pragma": "no-cache",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-cnection": "close",
    "x-download-options": "noopen",
    "x-opnet-transaction-trace": "39598f69-930a-4eea-a65b-19a85a5612aa-17512-11769613"
  }
}

Response trailers received:
(empty)
Sent 1 request and received 1 response
```

</details>

<details>
<summary>Show Dependency Request Body</summary>

```json
{
  "merchant_customer_id": "mcui_692654de64f04e859d4fcaca1e74f770",
  "customer_name": "Ava Brown",
  "email": {
    "value": "casey.7600@sandbox.example.com"
  },
  "phone_number": "+448122557398",
  "address": {
    "shipping_address": {
      "first_name": {
        "value": "Ethan"
      },
      "last_name": {
        "value": "Brown"
      },
      "line1": {
        "value": "2318 Sunset Ave"
      },
      "line2": {
        "value": "2960 Lake Ln"
      },
      "line3": {
        "value": "961 Oak St"
      },
      "city": {
        "value": "San Francisco"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "44459"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "morgan.9736@example.com"
      },
      "phone_number": {
        "value": "5373368867"
      },
      "phone_country_code": "+91"
    },
    "billing_address": {
      "first_name": {
        "value": "Liam"
      },
      "last_name": {
        "value": "Miller"
      },
      "line1": {
        "value": "6159 Main St"
      },
      "line2": {
        "value": "7029 Pine Ave"
      },
      "line3": {
        "value": "3891 Main Dr"
      },
      "city": {
        "value": "New York"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "80626"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "riley.1514@sandbox.example.com"
      },
      "phone_number": {
        "value": "5773374310"
      },
      "phone_country_code": "+91"
    }
  },
  "test_mode": true
}
```

</details>

<details>
<summary>Show Dependency Response Body</summary>

```json
{
  "merchantCustomerId": "934839066",
  "connectorCustomerId": "934839066",
  "statusCode": 200,
  "responseHeaders": {
    "access-control-allow-credentials": "true",
    "access-control-allow-headers": "x-requested-with,cache-control,content-type,origin,method,SOAPAction",
    "access-control-allow-methods": "PUT,OPTIONS,POST,GET",
    "access-control-allow-origin": "*",
    "cache-control": "no-cache, no-store, max-age=0",
    "content-length": "232",
    "content-type": "application/json; charset=utf-8",
    "date": "Thu, 12 Mar 2026 15:40:47 GMT",
    "expires": "-1",
    "pragma": "no-cache",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-cnection": "close",
    "x-download-options": "noopen",
    "x-opnet-transaction-trace": "39598f69-930a-4eea-a65b-19a85a5612aa-17512-11769613"
  }
}
```

</details>

</details>
<details>
<summary>Show gRPC Request (masked)</summary>

```bash
grpcurl -plaintext \
  -H "x-connector: authorizedotnet" \
  -H "x-merchant-id: test_merchant" \
  -H "x-tenant-id: default" \
  -H "x-request-id: setup_recurring_setup_recurring_with_order_context_req" \
  -H "x-connector-request-reference-id: setup_recurring_setup_recurring_with_order_context_ref" \
  -H "x-auth: ***MASKED***" \
  -H "x-api-key: ***MASKED***" \
  -H "x-key1: ***MASKED***" \
  -d @ localhost:8000 types.PaymentService/SetupRecurring <<'JSON'
{
  "merchant_recurring_payment_id": "mrpi_84c48d2dffcf44ebb9f5dae8924c3fe5",
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
        "value": "Ava Brown"
      },
      "card_type": "credit"
    }
  },
  "customer": {
    "name": "Emma Taylor",
    "email": {
      "value": "alex.7448@example.com"
    },
    "id": "cust_73665a2a42004ab89892adcf78b10f9b",
    "phone_number": "+14714898534",
    "connector_customer_id": "934839066"
  },
  "complete_authorize_url": "https://example.com/payment/complete",
  "address": {
    "billing_address": {
      "first_name": {
        "value": "Liam"
      },
      "last_name": {
        "value": "Miller"
      },
      "line1": {
        "value": "6159 Main St"
      },
      "line2": {
        "value": "7029 Pine Ave"
      },
      "line3": {
        "value": "3891 Main Dr"
      },
      "city": {
        "value": "New York"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "80626"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "riley.1514@sandbox.example.com"
      },
      "phone_number": {
        "value": "5773374310"
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
  "merchant_order_id": "gen_623105",
  "order_category": "subscription",
  "return_url": "https://example.com/payment/return",
  "webhook_url": "https://example.com/payment/webhook"
}
JSON
```

</details>

<details>
<summary>Show gRPC Response (masked)</summary>

```text
Resolved method descriptor:
// Setup a recurring payment instruction for future payments/ debits. This could be
// for SaaS subscriptions, monthly bill payments, insurance payments and similar use cases.
rpc SetupRecurring ( .types.PaymentServiceSetupRecurringRequest ) returns ( .types.PaymentServiceSetupRecurringResponse );

Request metadata to send:
x-api-key: ***MASKED***
x-auth: ***MASKED***
x-connector: authorizedotnet
x-connector-request-reference-id: setup_recurring_setup_recurring_with_order_context_ref
x-key1: ***MASKED***
x-merchant-id: test_merchant
x-request-id: setup_recurring_setup_recurring_with_order_context_req
x-tenant-id: default

Response headers received:
content-type: application/grpc
date: Thu, 12 Mar 2026 15:40:50 GMT
x-request-id: setup_recurring_setup_recurring_with_order_context_req

Response contents:
{
  "status": "CHARGED",
  "statusCode": 200,
  "responseHeaders": {
    "access-control-allow-credentials": "true",
    "access-control-allow-headers": "x-requested-with,cache-control,content-type,origin,method,SOAPAction",
    "access-control-allow-methods": "PUT,OPTIONS,POST,GET",
    "access-control-allow-origin": "*",
    "cache-control": "no-cache, no-store, max-age=0",
    "content-length": "547",
    "content-type": "application/json; charset=utf-8",
    "date": "Thu, 12 Mar 2026 15:40:50 GMT",
    "expires": "-1",
    "pragma": "no-cache",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-cnection": "close",
    "x-download-options": "noopen",
    "x-opnet-transaction-trace": "39598f69-930a-4eea-a65b-19a85a5612aa-17512-11769909"
  },
  "mandateReference": {
    "connectorMandateId": {
      "connectorMandateId": "934839066-934084493"
    }
  },
  "capturedAmount": "0",
  "state": {
    "connectorCustomerId": "934839066"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://apitest.authorize.net/xml/v1/request.api\",\"method\":\"POST\",\"headers\":{\"Content-Type\":\"application/json\",\"via\":\"HyperSwitch\"},\"body\":{\"createCustomerPaymentProfileRequest\":{\"merchantAuthentication\":{\"name\":\"9ARWr5wz49D3\",\"transactionKey\":\"3d9SHV2699mgmHre\"},\"customerProfileId\":\"934839066\",\"paymentProfile\":{\"billTo\":{\"firstName\":\"Liam\",\"lastName\":\"Miller\",\"address\":\"6159 Main St 7029 Pine Ave 3891 Main Dr\",\"city\":\"New York\",\"state\":\"CA\",\"zip\":\"80626\",\"country\":\"US\"},\"payment\":{\"creditCard\":{\"cardNumber\":\"4111111111111111\",\"expirationDate\":\"2030-08\",\"cardCode\":\"999\"}}},\"validationMode\":\"testMode\"}}}"
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
  "merchant_recurring_payment_id": "mrpi_84c48d2dffcf44ebb9f5dae8924c3fe5",
  "amount": {
    "minor_amount": 6000,
    "currency": "USD"
  },
  "payment_method": {
    "card": {
      "card_number": "***MASKED***",
      "card_exp_month": {
        "value": "08"
      },
      "card_exp_year": {
        "value": "30"
      },
      "card_cvc": "***MASKED***",
      "card_holder_name": {
        "value": "Ava Brown"
      },
      "card_type": "credit"
    }
  },
  "customer": {
    "name": "Emma Taylor",
    "email": {
      "value": "alex.7448@example.com"
    },
    "id": "cust_73665a2a42004ab89892adcf78b10f9b",
    "phone_number": "+14714898534",
    "connector_customer_id": "934839066"
  },
  "complete_authorize_url": "https://example.com/payment/complete",
  "address": {
    "billing_address": {
      "first_name": {
        "value": "Liam"
      },
      "last_name": {
        "value": "Miller"
      },
      "line1": {
        "value": "6159 Main St"
      },
      "line2": {
        "value": "7029 Pine Ave"
      },
      "line3": {
        "value": "3891 Main Dr"
      },
      "city": {
        "value": "New York"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "80626"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "riley.1514@sandbox.example.com"
      },
      "phone_number": {
        "value": "5773374310"
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
  "merchant_order_id": "gen_623105",
  "order_category": "subscription",
  "return_url": "https://example.com/payment/return",
  "webhook_url": "https://example.com/payment/webhook"
}
```

</details>

<details>
<summary>Show Response Body</summary>

```json
{
  "status": "CHARGED",
  "statusCode": 200,
  "responseHeaders": {
    "access-control-allow-credentials": "true",
    "access-control-allow-headers": "x-requested-with,cache-control,content-type,origin,method,SOAPAction",
    "access-control-allow-methods": "PUT,OPTIONS,POST,GET",
    "access-control-allow-origin": "*",
    "cache-control": "no-cache, no-store, max-age=0",
    "content-length": "547",
    "content-type": "application/json; charset=utf-8",
    "date": "Thu, 12 Mar 2026 15:40:50 GMT",
    "expires": "-1",
    "pragma": "no-cache",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-cnection": "close",
    "x-download-options": "noopen",
    "x-opnet-transaction-trace": "39598f69-930a-4eea-a65b-19a85a5612aa-17512-11769909"
  },
  "mandateReference": {
    "connectorMandateId": {
      "connectorMandateId": "934839066-934084493"
    }
  },
  "capturedAmount": "0",
  "state": {
    "connectorCustomerId": "934839066"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://apitest.authorize.net/xml/v1/request.api\",\"method\":\"POST\",\"headers\":{\"Content-Type\":\"application/json\",\"via\":\"HyperSwitch\"},\"body\":{\"createCustomerPaymentProfileRequest\":{\"merchantAuthentication\":{\"name\":\"9ARWr5wz49D3\",\"transactionKey\":\"3d9SHV2699mgmHre\"},\"customerProfileId\":\"934839066\",\"paymentProfile\":{\"billTo\":{\"firstName\":\"Liam\",\"lastName\":\"Miller\",\"address\":\"6159 Main St 7029 Pine Ave 3891 Main Dr\",\"city\":\"New York\",\"state\":\"CA\",\"zip\":\"80626\",\"country\":\"US\"},\"payment\":{\"creditCard\":{\"cardNumber\":\"4111111111111111\",\"expirationDate\":\"2030-08\",\"cardCode\":\"999\"}}},\"validationMode\":\"testMode\"}}}"
  }
}
```

</details>


---

<a id="connector-paypal"></a>
## Connector `paypal` — `PASS`


**Pre Requisites Executed**

<details>
<summary>1. create_access_token(create_access_token) — PASS</summary>

<details>
<summary>Show Dependency gRPC Request (masked)</summary>

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
<summary>Show Dependency gRPC Response (masked)</summary>

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

<details>
<summary>Show Dependency Request Body</summary>

```json
{
  "merchant_access_token_id": "***MASKED***",
  "connector": "STRIPE",
  "test_mode": true
}
```

</details>

<details>
<summary>Show Dependency Response Body</summary>

```json
{
  "accessToken": "***MASKED***",
  "expiresInSeconds": "30458",
  "status": "OPERATION_STATUS_SUCCESS",
  "statusCode": 200
}
```

</details>

</details>
<details>
<summary>Show gRPC Request (masked)</summary>

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
<summary>Show gRPC Response (masked)</summary>

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

<details>
<summary>Show Request Body</summary>

```json
{
  "merchant_recurring_payment_id": "mrpi_412bdc33e58c4746860ed4b480f75cd2",
  "amount": {
    "minor_amount": 6000,
    "currency": "USD"
  },
  "payment_method": {
    "card": {
      "card_number": "***MASKED***",
      "card_exp_month": {
        "value": "08"
      },
      "card_exp_year": {
        "value": "30"
      },
      "card_cvc": "***MASKED***",
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
    "access_token": "***MASKED***"
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
```

</details>

<details>
<summary>Show Response Body</summary>

```json
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
    "accessToken": "***MASKED***"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://api-m.sandbox.paypal.com/v3/vault/payment-tokens/\",\"method\":\"POST\",\"headers\":{\"via\":\"HyperSwitch\",\"PayPal-Partner-Attribution-Id\":\"HyperSwitchlegacy_Ecom\",\"PayPal-Request-Id\":\"mrpi_412bdc33e58c4746860ed4b480f75cd2\",\"Authorization\":\"Bearer ***MASKED***\",\"Prefer\":\"return=representation\",\"Content-Type\":\"application/json\"},\"body\":{\"payment_source\":{\"card\":{\"billing_address\":{\"address_line_1\":\"1585 Market Rd\",\"postal_code\":\"89310\",\"country_code\":\"US\",\"admin_area_2\":\"San Francisco\"},\"expiry\":\"2030-08\",\"name\":\"Liam Wilson\",\"number\":\"4111111111111111\"}}}}"
  }
}
```

</details>


---

<a id="connector-stripe"></a>
## Connector `stripe` — `PASS`


**Pre Requisites Executed**

<details>
<summary>1. create_customer(create_customer) — PASS</summary>

<details>
<summary>Show Dependency gRPC Request (masked)</summary>

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
  "merchant_customer_id": "mcui_c02f8261eb0f4687872d1caeb0a8bb77",
  "customer_name": "Emma Brown",
  "email": {
    "value": "jordan.9222@testmail.io"
  },
  "phone_number": "+446327967899",
  "address": {
    "shipping_address": {
      "first_name": {
        "value": "Liam"
      },
      "last_name": {
        "value": "Taylor"
      },
      "line1": {
        "value": "6397 Lake Dr"
      },
      "line2": {
        "value": "5650 Sunset St"
      },
      "line3": {
        "value": "7172 Lake Rd"
      },
      "city": {
        "value": "Los Angeles"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "21433"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "alex.6612@example.com"
      },
      "phone_number": {
        "value": "7276002009"
      },
      "phone_country_code": "+91"
    },
    "billing_address": {
      "first_name": {
        "value": "Ava"
      },
      "last_name": {
        "value": "Miller"
      },
      "line1": {
        "value": "3679 Market St"
      },
      "line2": {
        "value": "5204 Oak Ln"
      },
      "line3": {
        "value": "3645 Market Blvd"
      },
      "city": {
        "value": "San Francisco"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "97740"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "jordan.8996@testmail.io"
      },
      "phone_number": {
        "value": "8416902809"
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
<summary>Show Dependency gRPC Response (masked)</summary>

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
date: Thu, 12 Mar 2026 15:43:27 GMT
x-request-id: create_customer_create_customer_req

Response contents:
{
  "merchantCustomerId": "cus_U8SJ44vRzyTxlb",
  "connectorCustomerId": "cus_U8SJ44vRzyTxlb",
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
    "date": "Thu, 12 Mar 2026 15:43:27 GMT",
    "idempotency-key": "cd8a1a21-eef7-4a43-b74b-908d2ac32dec",
    "original-request": "req_QwaBsD8UhMEK4K",
    "request-id": "req_QwaBsD8UhMEK4K",
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
<summary>Show Dependency Request Body</summary>

```json
{
  "merchant_customer_id": "mcui_c02f8261eb0f4687872d1caeb0a8bb77",
  "customer_name": "Emma Brown",
  "email": {
    "value": "jordan.9222@testmail.io"
  },
  "phone_number": "+446327967899",
  "address": {
    "shipping_address": {
      "first_name": {
        "value": "Liam"
      },
      "last_name": {
        "value": "Taylor"
      },
      "line1": {
        "value": "6397 Lake Dr"
      },
      "line2": {
        "value": "5650 Sunset St"
      },
      "line3": {
        "value": "7172 Lake Rd"
      },
      "city": {
        "value": "Los Angeles"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "21433"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "alex.6612@example.com"
      },
      "phone_number": {
        "value": "7276002009"
      },
      "phone_country_code": "+91"
    },
    "billing_address": {
      "first_name": {
        "value": "Ava"
      },
      "last_name": {
        "value": "Miller"
      },
      "line1": {
        "value": "3679 Market St"
      },
      "line2": {
        "value": "5204 Oak Ln"
      },
      "line3": {
        "value": "3645 Market Blvd"
      },
      "city": {
        "value": "San Francisco"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "97740"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "jordan.8996@testmail.io"
      },
      "phone_number": {
        "value": "8416902809"
      },
      "phone_country_code": "+91"
    }
  },
  "test_mode": true
}
```

</details>

<details>
<summary>Show Dependency Response Body</summary>

```json
{
  "merchantCustomerId": "cus_U8SJ44vRzyTxlb",
  "connectorCustomerId": "cus_U8SJ44vRzyTxlb",
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
    "date": "Thu, 12 Mar 2026 15:43:27 GMT",
    "idempotency-key": "cd8a1a21-eef7-4a43-b74b-908d2ac32dec",
    "original-request": "req_QwaBsD8UhMEK4K",
    "request-id": "req_QwaBsD8UhMEK4K",
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

</details>
<details>
<summary>Show gRPC Request (masked)</summary>

```bash
grpcurl -plaintext \
  -H "x-connector: stripe" \
  -H "x-merchant-id: test_merchant" \
  -H "x-tenant-id: default" \
  -H "x-request-id: setup_recurring_setup_recurring_with_order_context_req" \
  -H "x-connector-request-reference-id: setup_recurring_setup_recurring_with_order_context_ref" \
  -H "x-auth: ***MASKED***" \
  -H "x-api-key: ***MASKED***" \
  -d @ localhost:8000 types.PaymentService/SetupRecurring <<'JSON'
{
  "merchant_recurring_payment_id": "mrpi_8958580c52e14167afa224ee3987a85d",
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
        "value": "Liam Johnson"
      },
      "card_type": "credit"
    }
  },
  "customer": {
    "name": "Mia Brown",
    "email": {
      "value": "jordan.8890@example.com"
    },
    "id": "cust_34d3ffc5a2a442e3876cc9db714d69e1",
    "phone_number": "+15776707488",
    "connector_customer_id": "cus_U8SJ44vRzyTxlb"
  },
  "webhook_url": "https://example.com/payment/webhook",
  "address": {
    "billing_address": {
      "first_name": {
        "value": "Ava"
      },
      "last_name": {
        "value": "Miller"
      },
      "line1": {
        "value": "3679 Market St"
      },
      "line2": {
        "value": "5204 Oak Ln"
      },
      "line3": {
        "value": "3645 Market Blvd"
      },
      "city": {
        "value": "San Francisco"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "97740"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "jordan.8996@testmail.io"
      },
      "phone_number": {
        "value": "8416902809"
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
  "complete_authorize_url": "https://example.com/payment/complete",
  "merchant_order_id": "gen_425355",
  "order_category": "subscription",
  "return_url": "https://example.com/payment/return"
}
JSON
```

</details>

<details>
<summary>Show gRPC Response (masked)</summary>

```text
Resolved method descriptor:
// Setup a recurring payment instruction for future payments/ debits. This could be
// for SaaS subscriptions, monthly bill payments, insurance payments and similar use cases.
rpc SetupRecurring ( .types.PaymentServiceSetupRecurringRequest ) returns ( .types.PaymentServiceSetupRecurringResponse );

Request metadata to send:
x-api-key: ***MASKED***
x-auth: ***MASKED***
x-connector: stripe
x-connector-request-reference-id: setup_recurring_setup_recurring_with_order_context_ref
x-merchant-id: test_merchant
x-request-id: setup_recurring_setup_recurring_with_order_context_req
x-tenant-id: default

Response headers received:
content-type: application/grpc
date: Thu, 12 Mar 2026 15:43:30 GMT
x-request-id: setup_recurring_setup_recurring_with_order_context_req

Response contents:
{
  "connectorRecurringPaymentId": "seti_1TABOXD5R7gDAGffWlGxYV7h",
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
    "date": "Thu, 12 Mar 2026 15:43:30 GMT",
    "idempotency-key": "bb3beccb-3538-4b9e-899e-691323a9e6f9",
    "original-request": "req_96huC9evBsWrCo",
    "request-id": "req_96huC9evBsWrCo",
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
      "connectorMandateId": "pm_1TABOXD5R7gDAGffOoLykB13",
      "paymentMethodId": "pm_1TABOXD5R7gDAGffOoLykB13"
    }
  },
  "merchantRecurringPaymentId": "seti_1TABOXD5R7gDAGffWlGxYV7h",
  "connectorResponse": {
    "additionalPaymentMethodData": {
      "card": {
        "paymentChecks": "eyJhZGRyZXNzX2xpbmUxX2NoZWNrIjpudWxsLCJhZGRyZXNzX3Bvc3RhbF9jb2RlX2NoZWNrIjpudWxsLCJjdmNfY2hlY2siOiJwYXNzIn0="
      }
    }
  },
  "capturedAmount": "0",
  "state": {
    "connectorCustomerId": "cus_U8SJ44vRzyTxlb"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://api.stripe.com/v1/setup_intents\",\"method\":\"POST\",\"headers\":{\"stripe-version\":\"2022-11-15\",\"Content-Type\":\"application/x-www-form-urlencoded\",\"Authorization\":\"Bearer ***MASKED***",\"via\":\"HyperSwitch\"},\"body\":\"confirm=true\u0026usage=off_session\u0026customer=cus_U8SJ44vRzyTxlb\u0026return_url=https%3A%2F%2Fexample.com%2Fpayment%2Freturn\u0026payment_method_data%5Btype%5D=card\u0026payment_method_data%5Bcard%5D%5Bnumber%5D=4111111111111111\u0026payment_method_data%5Bcard%5D%5Bexp_month%5D=08\u0026payment_method_data%5Bcard%5D%5Bexp_year%5D=30\u0026payment_method_data%5Bcard%5D%5Bcvc%5D=999\u0026payment_method_options%5Bcard%5D%5Brequest_three_d_secure%5D=automatic\u0026metadata%5Border_id%5D=mrpi_8958580c52e14167afa224ee3987a85d\u0026payment_method_types%5B0%5D=card\u0026expand%5B0%5D=latest_attempt\"}"
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
  "merchant_recurring_payment_id": "mrpi_8958580c52e14167afa224ee3987a85d",
  "amount": {
    "minor_amount": 6000,
    "currency": "USD"
  },
  "payment_method": {
    "card": {
      "card_number": "***MASKED***",
      "card_exp_month": {
        "value": "08"
      },
      "card_exp_year": {
        "value": "30"
      },
      "card_cvc": "***MASKED***",
      "card_holder_name": {
        "value": "Liam Johnson"
      },
      "card_type": "credit"
    }
  },
  "customer": {
    "name": "Mia Brown",
    "email": {
      "value": "jordan.8890@example.com"
    },
    "id": "cust_34d3ffc5a2a442e3876cc9db714d69e1",
    "phone_number": "+15776707488",
    "connector_customer_id": "cus_U8SJ44vRzyTxlb"
  },
  "webhook_url": "https://example.com/payment/webhook",
  "address": {
    "billing_address": {
      "first_name": {
        "value": "Ava"
      },
      "last_name": {
        "value": "Miller"
      },
      "line1": {
        "value": "3679 Market St"
      },
      "line2": {
        "value": "5204 Oak Ln"
      },
      "line3": {
        "value": "3645 Market Blvd"
      },
      "city": {
        "value": "San Francisco"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "97740"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "jordan.8996@testmail.io"
      },
      "phone_number": {
        "value": "8416902809"
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
  "complete_authorize_url": "https://example.com/payment/complete",
  "merchant_order_id": "gen_425355",
  "order_category": "subscription",
  "return_url": "https://example.com/payment/return"
}
```

</details>

<details>
<summary>Show Response Body</summary>

```json
{
  "connectorRecurringPaymentId": "seti_1TABOXD5R7gDAGffWlGxYV7h",
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
    "date": "Thu, 12 Mar 2026 15:43:30 GMT",
    "idempotency-key": "bb3beccb-3538-4b9e-899e-691323a9e6f9",
    "original-request": "req_96huC9evBsWrCo",
    "request-id": "req_96huC9evBsWrCo",
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
      "connectorMandateId": "pm_1TABOXD5R7gDAGffOoLykB13",
      "paymentMethodId": "pm_1TABOXD5R7gDAGffOoLykB13"
    }
  },
  "merchantRecurringPaymentId": "seti_1TABOXD5R7gDAGffWlGxYV7h",
  "connectorResponse": {
    "additionalPaymentMethodData": {
      "card": {
        "paymentChecks": "eyJhZGRyZXNzX2xpbmUxX2NoZWNrIjpudWxsLCJhZGRyZXNzX3Bvc3RhbF9jb2RlX2NoZWNrIjpudWxsLCJjdmNfY2hlY2siOiJwYXNzIn0="
      }
    }
  },
  "capturedAmount": "0",
  "state": {
    "connectorCustomerId": "cus_U8SJ44vRzyTxlb"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://api.stripe.com/v1/setup_intents\",\"method\":\"POST\",\"headers\":{\"stripe-version\":\"2022-11-15\",\"Content-Type\":\"application/x-www-form-urlencoded\",\"Authorization\":\"Bearer ***MASKED***\",\"via\":\"HyperSwitch\"},\"body\":\"confirm=true&usage=off_session&customer=cus_U8SJ44vRzyTxlb&return_url=https%3A%2F%2Fexample.com%2Fpayment%2Freturn&payment_method_data%5Btype%5D=card&payment_method_data%5Bcard%5D%5Bnumber%5D=4111111111111111&payment_method_data%5Bcard%5D%5Bexp_month%5D=08&payment_method_data%5Bcard%5D%5Bexp_year%5D=30&payment_method_data%5Bcard%5D%5Bcvc%5D=999&payment_method_options%5Bcard%5D%5Brequest_three_d_secure%5D=automatic&metadata%5Border_id%5D=mrpi_8958580c52e14167afa224ee3987a85d&payment_method_types%5B0%5D=card&expand%5B0%5D=latest_attempt\"}"
  }
}
```

</details>


[Back to Overview](../../test_overview.md)
