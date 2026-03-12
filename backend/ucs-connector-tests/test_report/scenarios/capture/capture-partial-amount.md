# Scenario `capture_partial_amount`

- Suite: `capture`
- Service: `PaymentService/Capture`
- PM / PMT: `-` / `-`

## Connector Summary

| Connector | Result | Prerequisites |
|:----------|:------:|:--------------|
| `authorizedotnet` | [PASS](./scenarios/capture/capture-partial-amount.md#connector-authorizedotnet) | `create_customer(create_customer)` (PASS) -> `authorize(no3ds_manual_capture_credit_card)` (PASS) |
| `paypal` | [PASS](./scenarios/capture/capture-partial-amount.md#connector-paypal) | `create_access_token(create_access_token)` (PASS) -> `authorize(no3ds_manual_capture_credit_card)` (PASS) |
| `stripe` | [PASS](./scenarios/capture/capture-partial-amount.md#connector-stripe) | `create_customer(create_customer)` (PASS) -> `authorize(no3ds_manual_capture_credit_card)` (PASS) |

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
  "merchant_customer_id": "mcui_35c4a1603d4c417fb7203d84bdeaafb5",
  "customer_name": "Noah Johnson",
  "email": {
    "value": "alex.6265@example.com"
  },
  "phone_number": "+918493680081",
  "address": {
    "shipping_address": {
      "first_name": {
        "value": "Ava"
      },
      "last_name": {
        "value": "Smith"
      },
      "line1": {
        "value": "6985 Oak St"
      },
      "line2": {
        "value": "5228 Market Blvd"
      },
      "line3": {
        "value": "7470 Market Ave"
      },
      "city": {
        "value": "New York"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "92202"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "jordan.8796@sandbox.example.com"
      },
      "phone_number": {
        "value": "9544562705"
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
        "value": "3171 Main St"
      },
      "line2": {
        "value": "8484 Main Rd"
      },
      "line3": {
        "value": "1558 Pine St"
      },
      "city": {
        "value": "San Francisco"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "54306"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "morgan.6328@testmail.io"
      },
      "phone_number": {
        "value": "9342988935"
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
date: Thu, 12 Mar 2026 15:40:12 GMT
x-request-id: create_customer_create_customer_req

Response contents:
{
  "merchantCustomerId": "934839053",
  "connectorCustomerId": "934839053",
  "statusCode": 200,
  "responseHeaders": {
    "access-control-allow-credentials": "true",
    "access-control-allow-headers": "x-requested-with,cache-control,content-type,origin,method,SOAPAction",
    "access-control-allow-methods": "PUT,OPTIONS,POST,GET",
    "access-control-allow-origin": "*",
    "cache-control": "no-cache, no-store, max-age=0",
    "content-length": "232",
    "content-type": "application/json; charset=utf-8",
    "date": "Thu, 12 Mar 2026 15:40:11 GMT",
    "expires": "-1",
    "pragma": "no-cache",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-cnection": "close",
    "x-download-options": "noopen",
    "x-opnet-transaction-trace": "39598f69-930a-4eea-a65b-19a85a5612aa-17512-11761993"
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
  "merchant_customer_id": "mcui_35c4a1603d4c417fb7203d84bdeaafb5",
  "customer_name": "Noah Johnson",
  "email": {
    "value": "alex.6265@example.com"
  },
  "phone_number": "+918493680081",
  "address": {
    "shipping_address": {
      "first_name": {
        "value": "Ava"
      },
      "last_name": {
        "value": "Smith"
      },
      "line1": {
        "value": "6985 Oak St"
      },
      "line2": {
        "value": "5228 Market Blvd"
      },
      "line3": {
        "value": "7470 Market Ave"
      },
      "city": {
        "value": "New York"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "92202"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "jordan.8796@sandbox.example.com"
      },
      "phone_number": {
        "value": "9544562705"
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
        "value": "3171 Main St"
      },
      "line2": {
        "value": "8484 Main Rd"
      },
      "line3": {
        "value": "1558 Pine St"
      },
      "city": {
        "value": "San Francisco"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "54306"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "morgan.6328@testmail.io"
      },
      "phone_number": {
        "value": "9342988935"
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
  "merchantCustomerId": "934839053",
  "connectorCustomerId": "934839053",
  "statusCode": 200,
  "responseHeaders": {
    "access-control-allow-credentials": "true",
    "access-control-allow-headers": "x-requested-with,cache-control,content-type,origin,method,SOAPAction",
    "access-control-allow-methods": "PUT,OPTIONS,POST,GET",
    "access-control-allow-origin": "*",
    "cache-control": "no-cache, no-store, max-age=0",
    "content-length": "232",
    "content-type": "application/json; charset=utf-8",
    "date": "Thu, 12 Mar 2026 15:40:11 GMT",
    "expires": "-1",
    "pragma": "no-cache",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-cnection": "close",
    "x-download-options": "noopen",
    "x-opnet-transaction-trace": "39598f69-930a-4eea-a65b-19a85a5612aa-17512-11761993"
  }
}
```

</details>

</details>
<details>
<summary>2. authorize(no3ds_manual_capture_credit_card) — PASS</summary>

<details>
<summary>Show Dependency gRPC Request (masked)</summary>

```bash
grpcurl -plaintext \
  -H "x-connector: authorizedotnet" \
  -H "x-merchant-id: test_merchant" \
  -H "x-tenant-id: default" \
  -H "x-request-id: authorize_no3ds_manual_capture_credit_card_req" \
  -H "x-connector-request-reference-id: authorize_no3ds_manual_capture_credit_card_ref" \
  -H "x-auth: ***MASKED***" \
  -H "x-api-key: ***MASKED***" \
  -H "x-key1: ***MASKED***" \
  -d @ localhost:8000 types.PaymentService/Authorize <<'JSON'
{
  "merchant_transaction_id": "mti_df4dadc30bf34f0fab9dab0a0f87ae11",
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
  "capture_method": "MANUAL",
  "customer": {
    "name": "Mia Johnson",
    "email": {
      "value": "casey.5075@sandbox.example.com"
    },
    "id": "cust_a1f88da193c04abc8497d84558a161d3",
    "phone_number": "+914464202886",
    "connector_customer_id": "934839053"
  },
  "locale": "en-US",
  "address": {
    "shipping_address": {
      "first_name": {
        "value": "Ava"
      },
      "last_name": {
        "value": "Smith"
      },
      "line1": {
        "value": "6985 Oak St"
      },
      "line2": {
        "value": "5228 Market Blvd"
      },
      "line3": {
        "value": "7470 Market Ave"
      },
      "city": {
        "value": "New York"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "92202"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "jordan.8796@sandbox.example.com"
      },
      "phone_number": {
        "value": "9544562705"
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
        "value": "3171 Main St"
      },
      "line2": {
        "value": "8484 Main Rd"
      },
      "line3": {
        "value": "1558 Pine St"
      },
      "city": {
        "value": "San Francisco"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "54306"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "morgan.6328@testmail.io"
      },
      "phone_number": {
        "value": "9342988935"
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
  "description": "No3DS manual capture card payment (credit)",
  "payment_channel": "ECOMMERCE",
  "test_mode": true
}
JSON
```

</details>

<details>
<summary>Show Dependency gRPC Response (masked)</summary>

```text
Resolved method descriptor:
// Authorize a payment amount on a payment method. This reserves funds
// without capturing them, essential for verifying availability before finalizing.
rpc Authorize ( .types.PaymentServiceAuthorizeRequest ) returns ( .types.PaymentServiceAuthorizeResponse );

Request metadata to send:
x-api-key: ***MASKED***
x-auth: ***MASKED***
x-connector: authorizedotnet
x-connector-request-reference-id: authorize_no3ds_manual_capture_credit_card_ref
x-key1: ***MASKED***
x-merchant-id: test_merchant
x-request-id: authorize_no3ds_manual_capture_credit_card_req
x-tenant-id: default

Response headers received:
content-type: application/grpc
date: Thu, 12 Mar 2026 15:40:13 GMT
x-request-id: authorize_no3ds_manual_capture_credit_card_req

Response contents:
{
  "merchantTransactionId": "120079432049",
  "connectorTransactionId": "120079432049",
  "status": "AUTHORIZED",
  "statusCode": 200,
  "responseHeaders": {
    "access-control-allow-credentials": "true",
    "access-control-allow-headers": "x-requested-with,cache-control,content-type,origin,method,SOAPAction",
    "access-control-allow-methods": "PUT,OPTIONS,POST,GET",
    "access-control-allow-origin": "*",
    "cache-control": "no-cache, no-store, max-age=0",
    "content-length": "654",
    "content-type": "application/json; charset=utf-8",
    "date": "Thu, 12 Mar 2026 15:40:12 GMT",
    "expires": "-1",
    "pragma": "no-cache",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-cnection": "close",
    "x-download-options": "noopen",
    "x-opnet-transaction-trace": "39598f69-930a-4eea-a65b-19a85a5612aa-17512-11762164"
  },
  "networkTransactionId": "XH9CMRS3T9X4Q1KC1VTNH10",
  "state": {
    "connectorCustomerId": "934839053"
  },
  "rawConnectorResponse": {
    "value": "{\"transactionResponse\":{\"responseCode\":\"1\",\"authCode\":\"AQCDLD\",\"avsResultCode\":\"Y\",\"cvvResultCode\":\"P\",\"cavvResultCode\":\"2\",\"transId\":\"120079432049\",\"refTransID\":\"\",\"transHash\":\"\",\"testRequest\":\"0\",\"accountNumber\":\"XXXX1111\",\"accountType\":\"Visa\",\"messages\":[{\"code\":\"1\",\"description\":\"This transaction has been approved.\"}],\"transHashSha2\":\"1DB65D624593B248CFE6BF878E84E04916D108086C74231FB31E4AFBC1144A1D1A65F84BB900BE5FC67EF3D5F80CE7A9996201D290D7550DE3A2A71BD0572776\",\"SupplementalDataQualificationIndicator\":0,\"networkTransId\":\"XH9CMRS3T9X4Q1KC1VTNH10\"},\"refId\":\"\",\"messages\":{\"resultCode\":\"Ok\",\"message\":[{\"code\":\"I00001\",\"text\":\"Successful.\"}]}}"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://apitest.authorize.net/xml/v1/request.api\",\"method\":\"POST\",\"headers\":{\"via\":\"HyperSwitch\",\"Content-Type\":\"application/json\"},\"body\":{\"createTransactionRequest\":{\"merchantAuthentication\":{\"name\":\"9ARWr5wz49D3\",\"transactionKey\":\"3d9SHV2699mgmHre\"},\"refId\":null,\"transactionRequest\":{\"transactionType\":\"authOnlyTransaction\",\"amount\":60.0,\"currencyCode\":\"USD\",\"payment\":{\"creditCard\":{\"cardNumber\":\"4111111111111111\",\"expirationDate\":\"2030-08\",\"cardCode\":\"999\"}},\"order\":{\"invoiceNumber\":\"58csc01ugz0e47LHEHjz\",\"description\":\"mti_df4dadc30bf34f0fab9dab0a0f87ae11\"},\"customer\":{\"id\":\"934839053\",\"email\":\"casey.5075@sandbox.example.com\"},\"billTo\":{\"firstName\":\"Ethan\",\"lastName\":\"Brown\",\"address\":\"3171 Main St 8484 Main Rd 1558 Pine St\",\"city\":\"San Francisco\",\"state\":\"CA\",\"zip\":\"54306\",\"country\":\"US\"}}}}}"
  },
  "connectorResponse": {
    "additionalPaymentMethodData": {
      "card": {
        "paymentChecks": "eyJhdnNfcmVzdWx0X2NvZGUiOiJZIiwiZGVzY3JpcHRpb24iOiJUaGUgc3RyZWV0IGFkZHJlc3MgYW5kIHBvc3RhbCBjb2RlIG1hdGNoZWQuIn0="
      }
    }
  },
  "connectorFeatureData": {
    "value": "{\"creditCard\":{\"cardNumber\":\"XXXX1111\",\"expirationDate\":\"XXXX\"}}"
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
  "merchant_transaction_id": "mti_df4dadc30bf34f0fab9dab0a0f87ae11",
  "amount": {
    "minor_amount": 6000,
    "currency": "USD"
  },
  "order_tax_amount": 0,
  "shipping_cost": 0,
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
        "value": "Ethan Brown"
      },
      "card_type": "credit"
    }
  },
  "capture_method": "MANUAL",
  "customer": {
    "name": "Mia Johnson",
    "email": {
      "value": "casey.5075@sandbox.example.com"
    },
    "id": "cust_a1f88da193c04abc8497d84558a161d3",
    "phone_number": "+914464202886",
    "connector_customer_id": "934839053"
  },
  "locale": "en-US",
  "address": {
    "shipping_address": {
      "first_name": {
        "value": "Ava"
      },
      "last_name": {
        "value": "Smith"
      },
      "line1": {
        "value": "6985 Oak St"
      },
      "line2": {
        "value": "5228 Market Blvd"
      },
      "line3": {
        "value": "7470 Market Ave"
      },
      "city": {
        "value": "New York"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "92202"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "jordan.8796@sandbox.example.com"
      },
      "phone_number": {
        "value": "9544562705"
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
        "value": "3171 Main St"
      },
      "line2": {
        "value": "8484 Main Rd"
      },
      "line3": {
        "value": "1558 Pine St"
      },
      "city": {
        "value": "San Francisco"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "54306"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "morgan.6328@testmail.io"
      },
      "phone_number": {
        "value": "9342988935"
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
  "description": "No3DS manual capture card payment (credit)",
  "payment_channel": "ECOMMERCE",
  "test_mode": true
}
```

</details>

<details>
<summary>Show Dependency Response Body</summary>

```json
{
  "merchantTransactionId": "120079432049",
  "connectorTransactionId": "120079432049",
  "status": "AUTHORIZED",
  "statusCode": 200,
  "responseHeaders": {
    "access-control-allow-credentials": "true",
    "access-control-allow-headers": "x-requested-with,cache-control,content-type,origin,method,SOAPAction",
    "access-control-allow-methods": "PUT,OPTIONS,POST,GET",
    "access-control-allow-origin": "*",
    "cache-control": "no-cache, no-store, max-age=0",
    "content-length": "654",
    "content-type": "application/json; charset=utf-8",
    "date": "Thu, 12 Mar 2026 15:40:12 GMT",
    "expires": "-1",
    "pragma": "no-cache",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-cnection": "close",
    "x-download-options": "noopen",
    "x-opnet-transaction-trace": "39598f69-930a-4eea-a65b-19a85a5612aa-17512-11762164"
  },
  "networkTransactionId": "XH9CMRS3T9X4Q1KC1VTNH10",
  "state": {
    "connectorCustomerId": "934839053"
  },
  "rawConnectorResponse": {
    "value": "{\"transactionResponse\":{\"responseCode\":\"1\",\"authCode\":\"AQCDLD\",\"avsResultCode\":\"Y\",\"cvvResultCode\":\"P\",\"cavvResultCode\":\"2\",\"transId\":\"120079432049\",\"refTransID\":\"\",\"transHash\":\"\",\"testRequest\":\"0\",\"accountNumber\":\"XXXX1111\",\"accountType\":\"Visa\",\"messages\":[{\"code\":\"1\",\"description\":\"This transaction has been approved.\"}],\"transHashSha2\":\"1DB65D624593B248CFE6BF878E84E04916D108086C74231FB31E4AFBC1144A1D1A65F84BB900BE5FC67EF3D5F80CE7A9996201D290D7550DE3A2A71BD0572776\",\"SupplementalDataQualificationIndicator\":0,\"networkTransId\":\"XH9CMRS3T9X4Q1KC1VTNH10\"},\"refId\":\"\",\"messages\":{\"resultCode\":\"Ok\",\"message\":[{\"code\":\"I00001\",\"text\":\"Successful.\"}]}}"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://apitest.authorize.net/xml/v1/request.api\",\"method\":\"POST\",\"headers\":{\"via\":\"HyperSwitch\",\"Content-Type\":\"application/json\"},\"body\":{\"createTransactionRequest\":{\"merchantAuthentication\":{\"name\":\"9ARWr5wz49D3\",\"transactionKey\":\"3d9SHV2699mgmHre\"},\"refId\":null,\"transactionRequest\":{\"transactionType\":\"authOnlyTransaction\",\"amount\":60.0,\"currencyCode\":\"USD\",\"payment\":{\"creditCard\":{\"cardNumber\":\"4111111111111111\",\"expirationDate\":\"2030-08\",\"cardCode\":\"999\"}},\"order\":{\"invoiceNumber\":\"58csc01ugz0e47LHEHjz\",\"description\":\"mti_df4dadc30bf34f0fab9dab0a0f87ae11\"},\"customer\":{\"id\":\"934839053\",\"email\":\"casey.5075@sandbox.example.com\"},\"billTo\":{\"firstName\":\"Ethan\",\"lastName\":\"Brown\",\"address\":\"3171 Main St 8484 Main Rd 1558 Pine St\",\"city\":\"San Francisco\",\"state\":\"CA\",\"zip\":\"54306\",\"country\":\"US\"}}}}}"
  },
  "connectorResponse": {
    "additionalPaymentMethodData": {
      "card": {
        "paymentChecks": "eyJhdnNfcmVzdWx0X2NvZGUiOiJZIiwiZGVzY3JpcHRpb24iOiJUaGUgc3RyZWV0IGFkZHJlc3MgYW5kIHBvc3RhbCBjb2RlIG1hdGNoZWQuIn0="
      }
    }
  },
  "connectorFeatureData": {
    "value": "{\"creditCard\":{\"cardNumber\":\"XXXX1111\",\"expirationDate\":\"XXXX\"}}"
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
  -H "x-request-id: capture_capture_partial_amount_req" \
  -H "x-connector-request-reference-id: capture_capture_partial_amount_ref" \
  -H "x-auth: ***MASKED***" \
  -H "x-api-key: ***MASKED***" \
  -H "x-key1: ***MASKED***" \
  -d @ localhost:8000 types.PaymentService/Capture <<'JSON'
{
  "connector_transaction_id": "120079432049",
  "amount_to_capture": {
    "minor_amount": 3000,
    "currency": "USD"
  },
  "merchant_capture_id": "mci_e0eca54bbbd74fe2ae74f1530128e7be",
  "state": {
    "connector_customer_id": "934839053"
  },
  "connector_feature_data": {
    "value": "{\"creditCard\":{\"cardNumber\":\"XXXX1111\",\"expirationDate\":\"XXXX\"}}"
  }
}
JSON
```

</details>

<details>
<summary>Show gRPC Response (masked)</summary>

```text
Resolved method descriptor:
// Finalize an authorized payment transaction. Transfers reserved funds from
// customer to merchant account, completing the payment lifecycle.
rpc Capture ( .types.PaymentServiceCaptureRequest ) returns ( .types.PaymentServiceCaptureResponse );

Request metadata to send:
x-api-key: ***MASKED***
x-auth: ***MASKED***
x-connector: authorizedotnet
x-connector-request-reference-id: capture_capture_partial_amount_ref
x-key1: ***MASKED***
x-merchant-id: test_merchant
x-request-id: capture_capture_partial_amount_req
x-tenant-id: default

Response headers received:
content-type: application/grpc
date: Thu, 12 Mar 2026 15:40:13 GMT
x-request-id: capture_capture_partial_amount_req

Response contents:
{
  "connectorTransactionId": "120079432049",
  "status": "CHARGED",
  "statusCode": 200,
  "responseHeaders": {
    "access-control-allow-credentials": "true",
    "access-control-allow-headers": "x-requested-with,cache-control,content-type,origin,method,SOAPAction",
    "access-control-allow-methods": "PUT,OPTIONS,POST,GET",
    "access-control-allow-origin": "*",
    "cache-control": "no-cache, no-store, max-age=0",
    "content-length": "610",
    "content-type": "application/json; charset=utf-8",
    "date": "Thu, 12 Mar 2026 15:40:12 GMT",
    "expires": "-1",
    "pragma": "no-cache",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-cnection": "close",
    "x-download-options": "noopen",
    "x-opnet-transaction-trace": "39598f69-930a-4eea-a65b-19a85a5612aa-17512-11762326"
  },
  "merchantCaptureId": "120079432049",
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://apitest.authorize.net/xml/v1/request.api\",\"method\":\"POST\",\"headers\":{\"via\":\"HyperSwitch\",\"Content-Type\":\"application/json\"},\"body\":{\"createTransactionRequest\":{\"merchantAuthentication\":{\"name\":\"9ARWr5wz49D3\",\"transactionKey\":\"3d9SHV2699mgmHre\"},\"transactionRequest\":{\"transactionType\":\"priorAuthCaptureTransaction\",\"amount\":30.0,\"refTransId\":\"120079432049\"}}}}"
  },
  "connectorFeatureData": {
    "value": "{\"creditCard\":{\"cardNumber\":\"XXXX1111\",\"expirationDate\":\"XXXX\"}}"
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
  "connector_transaction_id": "120079432049",
  "amount_to_capture": {
    "minor_amount": 3000,
    "currency": "USD"
  },
  "merchant_capture_id": "mci_e0eca54bbbd74fe2ae74f1530128e7be",
  "state": {
    "connector_customer_id": "934839053"
  },
  "connector_feature_data": {
    "value": "{\"creditCard\":{\"cardNumber\":\"XXXX1111\",\"expirationDate\":\"XXXX\"}}"
  }
}
```

</details>

<details>
<summary>Show Response Body</summary>

```json
{
  "connectorTransactionId": "120079432049",
  "status": "CHARGED",
  "statusCode": 200,
  "responseHeaders": {
    "access-control-allow-credentials": "true",
    "access-control-allow-headers": "x-requested-with,cache-control,content-type,origin,method,SOAPAction",
    "access-control-allow-methods": "PUT,OPTIONS,POST,GET",
    "access-control-allow-origin": "*",
    "cache-control": "no-cache, no-store, max-age=0",
    "content-length": "610",
    "content-type": "application/json; charset=utf-8",
    "date": "Thu, 12 Mar 2026 15:40:12 GMT",
    "expires": "-1",
    "pragma": "no-cache",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-cnection": "close",
    "x-download-options": "noopen",
    "x-opnet-transaction-trace": "39598f69-930a-4eea-a65b-19a85a5612aa-17512-11762326"
  },
  "merchantCaptureId": "120079432049",
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://apitest.authorize.net/xml/v1/request.api\",\"method\":\"POST\",\"headers\":{\"via\":\"HyperSwitch\",\"Content-Type\":\"application/json\"},\"body\":{\"createTransactionRequest\":{\"merchantAuthentication\":{\"name\":\"9ARWr5wz49D3\",\"transactionKey\":\"3d9SHV2699mgmHre\"},\"transactionRequest\":{\"transactionType\":\"priorAuthCaptureTransaction\",\"amount\":30.0,\"refTransId\":\"120079432049\"}}}}"
  },
  "connectorFeatureData": {
    "value": "{\"creditCard\":{\"cardNumber\":\"XXXX1111\",\"expirationDate\":\"XXXX\"}}"
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
date: Thu, 12 Mar 2026 15:41:15 GMT
x-request-id: create_access_token_create_access_token_req

Response contents:
{
  "accessToken": ***MASKED***
    "value": "A21AAIimoa-rtl4fS-Ww8qyaVqqMy85SmTVtYFXjFdA8emovXqLOH2syMZB9-jr5IkNejzMI3nGlOB7HG9auRQqlejeSk0Q_A"
  },
  "expiresInSeconds": "30524",
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
  "expiresInSeconds": "30524",
  "status": "OPERATION_STATUS_SUCCESS",
  "statusCode": 200
}
```

</details>

</details>
<details>
<summary>2. authorize(no3ds_manual_capture_credit_card) — PASS</summary>

<details>
<summary>Show Dependency gRPC Request (masked)</summary>

```bash
grpcurl -plaintext \
  -H "x-connector: paypal" \
  -H "x-merchant-id: test_merchant" \
  -H "x-tenant-id: default" \
  -H "x-request-id: authorize_no3ds_manual_capture_credit_card_req" \
  -H "x-connector-request-reference-id: authorize_no3ds_manual_capture_credit_card_ref" \
  -H "x-auth: ***MASKED***" \
  -H "x-api-key: ***MASKED***" \
  -H "x-key1: ***MASKED***" \
  -d @ localhost:8000 types.PaymentService/Authorize <<'JSON'
{
  "merchant_transaction_id": "mti_288698f24f244bae8fbba7d7032f96a6",
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
        "value": "Liam Miller"
      },
      "card_type": "credit"
    }
  },
  "capture_method": "MANUAL",
  "customer": {
    "name": "Noah Johnson",
    "email": {
      "value": "morgan.5216@testmail.io"
    },
    "id": "cust_560d2296471b475185856661cdb31473",
    "phone_number": "+13017716420"
  },
  "state": {
    "access_token": ***MASKED***
      "token": ***MASKED***
        "value": "A21AAIimoa-rtl4fS-Ww8qyaVqqMy85SmTVtYFXjFdA8emovXqLOH2syMZB9-jr5IkNejzMI3nGlOB7HG9auRQqlejeSk0Q_A"
      },
      "expires_in_seconds": "30524"
    }
  },
  "address": {
    "shipping_address": {
      "first_name": {
        "value": "Mia"
      },
      "last_name": {
        "value": "Wilson"
      },
      "line1": {
        "value": "776 Market St"
      },
      "line2": {
        "value": "5780 Sunset Dr"
      },
      "line3": {
        "value": "1265 Sunset Ave"
      },
      "city": {
        "value": "San Francisco"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "72370"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "morgan.6960@sandbox.example.com"
      },
      "phone_number": {
        "value": "2078904213"
      },
      "phone_country_code": "+91"
    },
    "billing_address": {
      "first_name": {
        "value": "Ava"
      },
      "last_name": {
        "value": "Wilson"
      },
      "line1": {
        "value": "6265 Oak Rd"
      },
      "line2": {
        "value": "3841 Lake St"
      },
      "line3": {
        "value": "7104 Sunset St"
      },
      "city": {
        "value": "Austin"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "31940"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "riley.6891@sandbox.example.com"
      },
      "phone_number": {
        "value": "4205547663"
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
  "description": "No3DS manual capture card payment (credit)",
  "payment_channel": "ECOMMERCE",
  "test_mode": true,
  "locale": "en-US"
}
JSON
```

</details>

<details>
<summary>Show Dependency gRPC Response (masked)</summary>

```text
Resolved method descriptor:
// Authorize a payment amount on a payment method. This reserves funds
// without capturing them, essential for verifying availability before finalizing.
rpc Authorize ( .types.PaymentServiceAuthorizeRequest ) returns ( .types.PaymentServiceAuthorizeResponse );

Request metadata to send:
x-api-key: ***MASKED***
x-auth: ***MASKED***
x-connector: paypal
x-connector-request-reference-id: authorize_no3ds_manual_capture_credit_card_ref
x-key1: ***MASKED***
x-merchant-id: test_merchant
x-request-id: authorize_no3ds_manual_capture_credit_card_req
x-tenant-id: default

Response headers received:
content-type: application/grpc
date: Thu, 12 Mar 2026 15:41:17 GMT
x-request-id: authorize_no3ds_manual_capture_credit_card_req

Response contents:
{
  "merchantTransactionId": "mti_288698f24f244bae8fbba7d7032f96a6",
  "connectorTransactionId": "1BA01125L2916663L",
  "status": "AUTHORIZED",
  "statusCode": 201,
  "responseHeaders": {
    "accept-ranges": "bytes",
    "access-control-expose-headers": "Server-Timing",
    "cache-control": "max-age=0, no-cache, no-store, must-revalidate",
    "connection": "keep-alive",
    "content-length": "2522",
    "content-type": "application/json",
    "date": "Thu, 12 Mar 2026 15:41:17 GMT",
    "edge-control": "max-age=0",
    "http_x_pp_az_locator": "ccg18.slc",
    "paypal-debug-id": "f547692ef9cf3",
    "server": "nginx",
    "server-timing": "traceparent;desc=\"00-0000000000000000000f547692ef9cf3-8fee08e4267776df-01\"",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "vary": "Accept-Encoding",
    "via": "1.1 varnish, 1.1 varnish",
    "x-cache": "MISS, MISS",
    "x-cache-hits": "0, 0",
    "x-served-by": "cache-sin-wsss1830073-SIN, cache-bom-vanm7210086-BOM",
    "x-timer": "S1773330075.198061,VS0,VE2616"
  },
  "state": {
    "accessToken": ***MASKED***
      "token": ***MASKED***
        "value": "A21AAIimoa-rtl4fS-Ww8qyaVqqMy85SmTVtYFXjFdA8emovXqLOH2syMZB9-jr5IkNejzMI3nGlOB7HG9auRQqlejeSk0Q_A"
      },
      "expiresInSeconds": "30524"
    }
  },
  "rawConnectorResponse": {
    "value": "{\"id\":\"1BA01125L2916663L\",\"intent\":\"AUTHORIZE\",\"status\":\"COMPLETED\",\"payment_source\":{\"card\":{\"name\":\"Ava Wilson\",\"last_digits\":\"1111\",\"expiry\":\"2030-08\",\"brand\":\"VISA\",\"type\":\"UNKNOWN\",\"bin_details\":{}}},\"purchase_units\":[{\"reference_id\":\"mti_288698f24f244bae8fbba7d7032f96a6\",\"amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\",\"breakdown\":{\"item_total\":{\"currency_code\":\"USD\",\"value\":\"60.00\"},\"shipping\":{\"currency_code\":\"USD\",\"value\":\"0.00\"},\"handling\":{\"currency_code\":\"USD\",\"value\":\"0.00\"},\"insurance\":{\"currency_code\":\"USD\",\"value\":\"0.00\"},\"shipping_discount\":{\"currency_code\":\"USD\",\"value\":\"0.00\"}}},\"payee\":{\"email_address\":\"sb-itwmi27136406@business.example.com\",\"merchant_id\":\"DUM69V9DDNYEJ\"},\"description\":\"Payment for invoice mti_288698f24f244bae8fbba7d7032f96a6\",\"invoice_id\":\"mti_288698f24f244bae8fbba7d7032f96a6\",\"soft_descriptor\":\"TEST STORE\",\"items\":[{\"name\":\"Payment for invoice mti_288698f24f244bae8fbba7d7032f96a6\",\"unit_amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\"},\"tax\":{\"currency_code\":\"USD\",\"value\":\"0.00\"},\"quantity\":\"1\"}],\"shipping\":{\"name\":{\"full_name\":\"Mia\"},\"address\":{\"address_line_1\":\"776 Market St\",\"admin_area_2\":\"San Francisco\",\"admin_area_1\":\"XX\",\"postal_code\":\"72370\",\"country_code\":\"US\"}},\"payments\":{\"authorizations\":[{\"status\":\"CREATED\",\"id\":\"6217723575876613B\",\"amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\"},\"invoice_id\":\"mti_288698f24f244bae8fbba7d7032f96a6\",\"seller_protection\":{\"status\":\"NOT_ELIGIBLE\"},\"processor_response\":{\"avs_code\":\"A\",\"cvv_code\":\"M\",\"response_code\":\"0000\"},\"expiration_time\":\"2026-04-10T15:41:17Z\",\"links\":[{\"href\":\"https://api.sandbox.paypal.com/v2/payments/authorizations/6217723575876613B\",\"rel\":\"self\",\"method\":\"GET\"},{\"href\":\"https://api.sandbox.paypal.com/v2/payments/authorizations/6217723575876613B/capture\",\"rel\":\"capture\",\"method\":\"POST\"},{\"href\":\"https://api.sandbox.paypal.com/v2/payments/authorizations/6217723575876613B/void\",\"rel\":\"void\",\"method\":\"POST\"},{\"href\":\"https://api.sandbox.paypal.com/v2/payments/authorizations/6217723575876613B/reauthorize\",\"rel\":\"reauthorize\",\"method\":\"POST\"},{\"href\":\"https://api.sandbox.paypal.com/v2/checkout/orders/1BA01125L2916663L\",\"rel\":\"up\",\"method\":\"GET\"}],\"create_time\":\"2026-03-12T15:41:17Z\",\"update_time\":\"2026-03-12T15:41:17Z\",\"network_transaction_reference\":{\"id\":\"126999257411266\",\"network\":\"VISA\"}}]}}],\"create_time\":\"2026-03-12T15:41:17Z\",\"update_time\":\"2026-03-12T15:41:17Z\",\"links\":[{\"href\":\"https://api.sandbox.paypal.com/v2/checkout/orders/1BA01125L2916663L\",\"rel\":\"self\",\"method\":\"GET\"}]}"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://api-m.sandbox.paypal.com/v2/checkout/orders\",\"method\":\"POST\",\"headers\":{\"via\":\"HyperSwitch\",\"PayPal-Partner-Attribution-Id\":\"HyperSwitchlegacy_Ecom\",\"Prefer\":\"return=representation\",\"Authorization\":\"Bearer ***MASKED***",\"PayPal-Request-Id\":\"mti_288698f24f244bae8fbba7d7032f96a6\",\"Content-Type\":\"application/json\"},\"body\":{\"intent\":\"AUTHORIZE\",\"purchase_units\":[{\"reference_id\":\"mti_288698f24f244bae8fbba7d7032f96a6\",\"invoice_id\":\"mti_288698f24f244bae8fbba7d7032f96a6\",\"custom_id\":null,\"amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\",\"breakdown\":{\"item_total\":{\"currency_code\":\"USD\",\"value\":\"60.00\"},\"tax_total\":null,\"shipping\":{\"currency_code\":\"USD\",\"value\":\"0.00\"}}},\"shipping\":{\"address\":{\"address_line_1\":\"776 Market St\",\"postal_code\":\"72370\",\"country_code\":\"US\",\"admin_area_2\":\"San Francisco\"},\"name\":{\"full_name\":\"Mia\"}},\"items\":[{\"name\":\"Payment for invoice mti_288698f24f244bae8fbba7d7032f96a6\",\"quantity\":1,\"unit_amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\"},\"tax\":null}]}],\"payment_source\":{\"card\":{\"billing_address\":{\"address_line_1\":\"6265 Oak Rd\",\"postal_code\":\"31940\",\"country_code\":\"US\",\"admin_area_2\":\"Austin\"},\"expiry\":\"2030-08\",\"name\":\"Ava Wilson\",\"number\":\"4111111111111111\",\"security_code\":\"999\",\"attributes\":{\"vault\":null,\"verification\":null}}}}}"
  },
  "mandateReference": {
    "connectorMandateId": {}
  },
  "connectorFeatureData": {
    "value": "{\"authorize_id\":\"6217723575876613B\",\"capture_id\":null,\"incremental_authorization_id\":\"6217723575876613B\",\"psync_flow\":\"AUTHORIZE\",\"next_action\":null,\"order_id\":null}"
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
  "merchant_transaction_id": "mti_288698f24f244bae8fbba7d7032f96a6",
  "amount": {
    "minor_amount": 6000,
    "currency": "USD"
  },
  "order_tax_amount": 0,
  "shipping_cost": 0,
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
        "value": "Liam Miller"
      },
      "card_type": "credit"
    }
  },
  "capture_method": "MANUAL",
  "customer": {
    "name": "Noah Johnson",
    "email": {
      "value": "morgan.5216@testmail.io"
    },
    "id": "cust_560d2296471b475185856661cdb31473",
    "phone_number": "+13017716420"
  },
  "state": {
    "access_token": "***MASKED***"
  },
  "address": {
    "shipping_address": {
      "first_name": {
        "value": "Mia"
      },
      "last_name": {
        "value": "Wilson"
      },
      "line1": {
        "value": "776 Market St"
      },
      "line2": {
        "value": "5780 Sunset Dr"
      },
      "line3": {
        "value": "1265 Sunset Ave"
      },
      "city": {
        "value": "San Francisco"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "72370"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "morgan.6960@sandbox.example.com"
      },
      "phone_number": {
        "value": "2078904213"
      },
      "phone_country_code": "+91"
    },
    "billing_address": {
      "first_name": {
        "value": "Ava"
      },
      "last_name": {
        "value": "Wilson"
      },
      "line1": {
        "value": "6265 Oak Rd"
      },
      "line2": {
        "value": "3841 Lake St"
      },
      "line3": {
        "value": "7104 Sunset St"
      },
      "city": {
        "value": "Austin"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "31940"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "riley.6891@sandbox.example.com"
      },
      "phone_number": {
        "value": "4205547663"
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
  "description": "No3DS manual capture card payment (credit)",
  "payment_channel": "ECOMMERCE",
  "test_mode": true,
  "locale": "en-US"
}
```

</details>

<details>
<summary>Show Dependency Response Body</summary>

```json
{
  "merchantTransactionId": "mti_288698f24f244bae8fbba7d7032f96a6",
  "connectorTransactionId": "1BA01125L2916663L",
  "status": "AUTHORIZED",
  "statusCode": 201,
  "responseHeaders": {
    "accept-ranges": "bytes",
    "access-control-expose-headers": "Server-Timing",
    "cache-control": "max-age=0, no-cache, no-store, must-revalidate",
    "connection": "keep-alive",
    "content-length": "2522",
    "content-type": "application/json",
    "date": "Thu, 12 Mar 2026 15:41:17 GMT",
    "edge-control": "max-age=0",
    "http_x_pp_az_locator": "ccg18.slc",
    "paypal-debug-id": "f547692ef9cf3",
    "server": "nginx",
    "server-timing": "traceparent;desc=\"00-0000000000000000000f547692ef9cf3-8fee08e4267776df-01\"",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "vary": "Accept-Encoding",
    "via": "1.1 varnish, 1.1 varnish",
    "x-cache": "MISS, MISS",
    "x-cache-hits": "0, 0",
    "x-served-by": "cache-sin-wsss1830073-SIN, cache-bom-vanm7210086-BOM",
    "x-timer": "S1773330075.198061,VS0,VE2616"
  },
  "state": {
    "accessToken": "***MASKED***"
  },
  "rawConnectorResponse": {
    "value": "{\"id\":\"1BA01125L2916663L\",\"intent\":\"AUTHORIZE\",\"status\":\"COMPLETED\",\"payment_source\":{\"card\":{\"name\":\"Ava Wilson\",\"last_digits\":\"1111\",\"expiry\":\"2030-08\",\"brand\":\"VISA\",\"type\":\"UNKNOWN\",\"bin_details\":{}}},\"purchase_units\":[{\"reference_id\":\"mti_288698f24f244bae8fbba7d7032f96a6\",\"amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\",\"breakdown\":{\"item_total\":{\"currency_code\":\"USD\",\"value\":\"60.00\"},\"shipping\":{\"currency_code\":\"USD\",\"value\":\"0.00\"},\"handling\":{\"currency_code\":\"USD\",\"value\":\"0.00\"},\"insurance\":{\"currency_code\":\"USD\",\"value\":\"0.00\"},\"shipping_discount\":{\"currency_code\":\"USD\",\"value\":\"0.00\"}}},\"payee\":{\"email_address\":\"sb-itwmi27136406@business.example.com\",\"merchant_id\":\"DUM69V9DDNYEJ\"},\"description\":\"Payment for invoice mti_288698f24f244bae8fbba7d7032f96a6\",\"invoice_id\":\"mti_288698f24f244bae8fbba7d7032f96a6\",\"soft_descriptor\":\"TEST STORE\",\"items\":[{\"name\":\"Payment for invoice mti_288698f24f244bae8fbba7d7032f96a6\",\"unit_amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\"},\"tax\":{\"currency_code\":\"USD\",\"value\":\"0.00\"},\"quantity\":\"1\"}],\"shipping\":{\"name\":{\"full_name\":\"Mia\"},\"address\":{\"address_line_1\":\"776 Market St\",\"admin_area_2\":\"San Francisco\",\"admin_area_1\":\"XX\",\"postal_code\":\"72370\",\"country_code\":\"US\"}},\"payments\":{\"authorizations\":[{\"status\":\"CREATED\",\"id\":\"6217723575876613B\",\"amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\"},\"invoice_id\":\"mti_288698f24f244bae8fbba7d7032f96a6\",\"seller_protection\":{\"status\":\"NOT_ELIGIBLE\"},\"processor_response\":{\"avs_code\":\"A\",\"cvv_code\":\"M\",\"response_code\":\"0000\"},\"expiration_time\":\"2026-04-10T15:41:17Z\",\"links\":[{\"href\":\"https://api.sandbox.paypal.com/v2/payments/authorizations/6217723575876613B\",\"rel\":\"self\",\"method\":\"GET\"},{\"href\":\"https://api.sandbox.paypal.com/v2/payments/authorizations/6217723575876613B/capture\",\"rel\":\"capture\",\"method\":\"POST\"},{\"href\":\"https://api.sandbox.paypal.com/v2/payments/authorizations/6217723575876613B/void\",\"rel\":\"void\",\"method\":\"POST\"},{\"href\":\"https://api.sandbox.paypal.com/v2/payments/authorizations/6217723575876613B/reauthorize\",\"rel\":\"reauthorize\",\"method\":\"POST\"},{\"href\":\"https://api.sandbox.paypal.com/v2/checkout/orders/1BA01125L2916663L\",\"rel\":\"up\",\"method\":\"GET\"}],\"create_time\":\"2026-03-12T15:41:17Z\",\"update_time\":\"2026-03-12T15:41:17Z\",\"network_transaction_reference\":{\"id\":\"126999257411266\",\"network\":\"VISA\"}}]}}],\"create_time\":\"2026-03-12T15:41:17Z\",\"update_time\":\"2026-03-12T15:41:17Z\",\"links\":[{\"href\":\"https://api.sandbox.paypal.com/v2/checkout/orders/1BA01125L2916663L\",\"rel\":\"self\",\"method\":\"GET\"}]}"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://api-m.sandbox.paypal.com/v2/checkout/orders\",\"method\":\"POST\",\"headers\":{\"via\":\"HyperSwitch\",\"PayPal-Partner-Attribution-Id\":\"HyperSwitchlegacy_Ecom\",\"Prefer\":\"return=representation\",\"Authorization\":\"Bearer ***MASKED***\",\"PayPal-Request-Id\":\"mti_288698f24f244bae8fbba7d7032f96a6\",\"Content-Type\":\"application/json\"},\"body\":{\"intent\":\"AUTHORIZE\",\"purchase_units\":[{\"reference_id\":\"mti_288698f24f244bae8fbba7d7032f96a6\",\"invoice_id\":\"mti_288698f24f244bae8fbba7d7032f96a6\",\"custom_id\":null,\"amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\",\"breakdown\":{\"item_total\":{\"currency_code\":\"USD\",\"value\":\"60.00\"},\"tax_total\":null,\"shipping\":{\"currency_code\":\"USD\",\"value\":\"0.00\"}}},\"shipping\":{\"address\":{\"address_line_1\":\"776 Market St\",\"postal_code\":\"72370\",\"country_code\":\"US\",\"admin_area_2\":\"San Francisco\"},\"name\":{\"full_name\":\"Mia\"}},\"items\":[{\"name\":\"Payment for invoice mti_288698f24f244bae8fbba7d7032f96a6\",\"quantity\":1,\"unit_amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\"},\"tax\":null}]}],\"payment_source\":{\"card\":{\"billing_address\":{\"address_line_1\":\"6265 Oak Rd\",\"postal_code\":\"31940\",\"country_code\":\"US\",\"admin_area_2\":\"Austin\"},\"expiry\":\"2030-08\",\"name\":\"Ava Wilson\",\"number\":\"4111111111111111\",\"security_code\":\"999\",\"attributes\":{\"vault\":null,\"verification\":null}}}}}"
  },
  "mandateReference": {
    "connectorMandateId": {}
  },
  "connectorFeatureData": {
    "value": "{\"authorize_id\":\"6217723575876613B\",\"capture_id\":null,\"incremental_authorization_id\":\"6217723575876613B\",\"psync_flow\":\"AUTHORIZE\",\"next_action\":null,\"order_id\":null}"
  }
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
  -H "x-request-id: capture_capture_partial_amount_req" \
  -H "x-connector-request-reference-id: capture_capture_partial_amount_ref" \
  -H "x-auth: ***MASKED***" \
  -H "x-api-key: ***MASKED***" \
  -H "x-key1: ***MASKED***" \
  -d @ localhost:8000 types.PaymentService/Capture <<'JSON'
{
  "connector_transaction_id": "1BA01125L2916663L",
  "amount_to_capture": {
    "minor_amount": 3000,
    "currency": "USD"
  },
  "merchant_capture_id": "mci_80d5b3a1ae064b00843e4787d9706900",
  "state": {
    "access_token": ***MASKED***
      "token": ***MASKED***
        "value": "A21AAIimoa-rtl4fS-Ww8qyaVqqMy85SmTVtYFXjFdA8emovXqLOH2syMZB9-jr5IkNejzMI3nGlOB7HG9auRQqlejeSk0Q_A"
      },
      "expires_in_seconds": "30524"
    }
  },
  "connector_feature_data": {
    "value": "{\"authorize_id\":\"6217723575876613B\",\"capture_id\":null,\"incremental_authorization_id\":\"6217723575876613B\",\"psync_flow\":\"AUTHORIZE\",\"next_action\":null,\"order_id\":null}"
  }
}
JSON
```

</details>

<details>
<summary>Show gRPC Response (masked)</summary>

```text
Resolved method descriptor:
// Finalize an authorized payment transaction. Transfers reserved funds from
// customer to merchant account, completing the payment lifecycle.
rpc Capture ( .types.PaymentServiceCaptureRequest ) returns ( .types.PaymentServiceCaptureResponse );

Request metadata to send:
x-api-key: ***MASKED***
x-auth: ***MASKED***
x-connector: paypal
x-connector-request-reference-id: capture_capture_partial_amount_ref
x-key1: ***MASKED***
x-merchant-id: test_merchant
x-request-id: capture_capture_partial_amount_req
x-tenant-id: default

Response headers received:
content-type: application/grpc
date: Thu, 12 Mar 2026 15:41:19 GMT
x-request-id: capture_capture_partial_amount_req

Response contents:
{
  "connectorTransactionId": "1BA01125L2916663L",
  "status": "CHARGED",
  "statusCode": 201,
  "responseHeaders": {
    "accept-ranges": "bytes",
    "access-control-expose-headers": "Server-Timing",
    "cache-control": "max-age=0, no-cache, no-store, must-revalidate",
    "connection": "keep-alive",
    "content-length": "925",
    "content-type": "application/json;charset=UTF-8",
    "date": "Thu, 12 Mar 2026 15:41:19 GMT",
    "edge-control": "max-age=0",
    "http_x_pp_az_locator": "ccg18.slc",
    "paypal-debug-id": "f849801526f17",
    "server": "nginx",
    "server-timing": "traceparent;desc=\"00-0000000000000000000f849801526f17-92d0dabab215102c-01\"",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "vary": "Accept-Encoding",
    "via": "1.1 varnish, 1.1 varnish",
    "x-cache": "MISS, MISS",
    "x-cache-hits": "0, 0",
    "x-served-by": "cache-sin-wsss1830086-SIN, cache-bom-vanm7210086-BOM",
    "x-timer": "S1773330078.005032,VS0,VE1608"
  },
  "merchantCaptureId": "mti_288698f24f244bae8fbba7d7032f96a6",
  "state": {
    "accessToken": ***MASKED***
      "token": ***MASKED***
        "value": "A21AAIimoa-rtl4fS-Ww8qyaVqqMy85SmTVtYFXjFdA8emovXqLOH2syMZB9-jr5IkNejzMI3nGlOB7HG9auRQqlejeSk0Q_A"
      },
      "expiresInSeconds": "30524"
    }
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://api-m.sandbox.paypal.com/v2/payments/authorizations/6217723575876613B/capture\",\"method\":\"POST\",\"headers\":{\"via\":\"HyperSwitch\",\"Content-Type\":\"application/json\",\"PayPal-Partner-Attribution-Id\":\"HyperSwitchlegacy_Ecom\",\"Prefer\":\"return=representation\",\"PayPal-Request-Id\":\"mci_80d5b3a1ae064b00843e4787d9706900\",\"Authorization\":\"Bearer ***MASKED***"},\"body\":{\"amount\":{\"currency_code\":\"USD\",\"value\":\"30.00\"},\"final_capture\":true}}"
  },
  "capturedAmount": "3000",
  "connectorFeatureData": {
    "value": "{\"authorize_id\":\"6217723575876613B\",\"capture_id\":\"5L992538MS046704H\",\"incremental_authorization_id\":null,\"psync_flow\":\"CAPTURE\",\"next_action\":null,\"order_id\":null}"
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
  "connector_transaction_id": "1BA01125L2916663L",
  "amount_to_capture": {
    "minor_amount": 3000,
    "currency": "USD"
  },
  "merchant_capture_id": "mci_80d5b3a1ae064b00843e4787d9706900",
  "state": {
    "access_token": "***MASKED***"
  },
  "connector_feature_data": {
    "value": "{\"authorize_id\":\"6217723575876613B\",\"capture_id\":null,\"incremental_authorization_id\":\"6217723575876613B\",\"psync_flow\":\"AUTHORIZE\",\"next_action\":null,\"order_id\":null}"
  }
}
```

</details>

<details>
<summary>Show Response Body</summary>

```json
{
  "connectorTransactionId": "1BA01125L2916663L",
  "status": "CHARGED",
  "statusCode": 201,
  "responseHeaders": {
    "accept-ranges": "bytes",
    "access-control-expose-headers": "Server-Timing",
    "cache-control": "max-age=0, no-cache, no-store, must-revalidate",
    "connection": "keep-alive",
    "content-length": "925",
    "content-type": "application/json;charset=UTF-8",
    "date": "Thu, 12 Mar 2026 15:41:19 GMT",
    "edge-control": "max-age=0",
    "http_x_pp_az_locator": "ccg18.slc",
    "paypal-debug-id": "f849801526f17",
    "server": "nginx",
    "server-timing": "traceparent;desc=\"00-0000000000000000000f849801526f17-92d0dabab215102c-01\"",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "vary": "Accept-Encoding",
    "via": "1.1 varnish, 1.1 varnish",
    "x-cache": "MISS, MISS",
    "x-cache-hits": "0, 0",
    "x-served-by": "cache-sin-wsss1830086-SIN, cache-bom-vanm7210086-BOM",
    "x-timer": "S1773330078.005032,VS0,VE1608"
  },
  "merchantCaptureId": "mti_288698f24f244bae8fbba7d7032f96a6",
  "state": {
    "accessToken": "***MASKED***"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://api-m.sandbox.paypal.com/v2/payments/authorizations/6217723575876613B/capture\",\"method\":\"POST\",\"headers\":{\"via\":\"HyperSwitch\",\"Content-Type\":\"application/json\",\"PayPal-Partner-Attribution-Id\":\"HyperSwitchlegacy_Ecom\",\"Prefer\":\"return=representation\",\"PayPal-Request-Id\":\"mci_80d5b3a1ae064b00843e4787d9706900\",\"Authorization\":\"Bearer ***MASKED***\"},\"body\":{\"amount\":{\"currency_code\":\"USD\",\"value\":\"30.00\"},\"final_capture\":true}}"
  },
  "capturedAmount": "3000",
  "connectorFeatureData": {
    "value": "{\"authorize_id\":\"6217723575876613B\",\"capture_id\":\"5L992538MS046704H\",\"incremental_authorization_id\":null,\"psync_flow\":\"CAPTURE\",\"next_action\":null,\"order_id\":null}"
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
  "merchant_customer_id": "mcui_7367768e3c524b8e8d653b4738a01286",
  "customer_name": "Emma Taylor",
  "email": {
    "value": "sam.3148@testmail.io"
  },
  "phone_number": "+915998728342",
  "address": {
    "shipping_address": {
      "first_name": {
        "value": "Noah"
      },
      "last_name": {
        "value": "Taylor"
      },
      "line1": {
        "value": "2352 Oak St"
      },
      "line2": {
        "value": "4428 Oak Ave"
      },
      "line3": {
        "value": "6459 Market St"
      },
      "city": {
        "value": "Seattle"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "65078"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "alex.7712@sandbox.example.com"
      },
      "phone_number": {
        "value": "3497811122"
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
        "value": "911 Sunset Dr"
      },
      "line2": {
        "value": "4515 Oak Ln"
      },
      "line3": {
        "value": "5788 Lake Ln"
      },
      "city": {
        "value": "Chicago"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "96323"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "casey.2549@example.com"
      },
      "phone_number": {
        "value": "3557577585"
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
date: Thu, 12 Mar 2026 15:42:45 GMT
x-request-id: create_customer_create_customer_req

Response contents:
{
  "merchantCustomerId": "cus_U8SIckPKdqj22u",
  "connectorCustomerId": "cus_U8SIckPKdqj22u",
  "statusCode": 200,
  "responseHeaders": {
    "access-control-allow-credentials": "true",
    "access-control-allow-methods": "GET, HEAD, PUT, PATCH, POST, DELETE",
    "access-control-allow-origin": "*",
    "access-control-expose-headers": "Request-Id, Stripe-Manage-Version, Stripe-Should-Retry, X-Stripe-External-Auth-Required, X-Stripe-Privileged-Session-Required",
    "access-control-max-age": "300",
    "cache-control": "no-cache, no-store",
    "connection": "keep-alive",
    "content-length": "669",
    "content-security-policy": "base-uri 'none'; default-src 'none'; form-action 'none'; frame-ancestors 'none'; img-src 'self'; script-src 'self' 'report-sample'; style-src 'self'; worker-src 'none'; upgrade-insecure-requests; report-uri https://q.stripe.com/csp-violation?q=XbpkE0Obtc-D-_OVcHByv3HX2Cz2ZXWthan_OSmhaX_cdx20p33NXUJkyzusgJOGoDWC714Lefdz6v3w",
    "content-type": "application/json",
    "date": "Thu, 12 Mar 2026 15:42:45 GMT",
    "idempotency-key": "64f0e0c0-14b3-4cd0-8d88-3660740dc760",
    "original-request": "req_W9O7vYE7Z2Pc0n",
    "request-id": "req_W9O7vYE7Z2Pc0n",
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
  "merchant_customer_id": "mcui_7367768e3c524b8e8d653b4738a01286",
  "customer_name": "Emma Taylor",
  "email": {
    "value": "sam.3148@testmail.io"
  },
  "phone_number": "+915998728342",
  "address": {
    "shipping_address": {
      "first_name": {
        "value": "Noah"
      },
      "last_name": {
        "value": "Taylor"
      },
      "line1": {
        "value": "2352 Oak St"
      },
      "line2": {
        "value": "4428 Oak Ave"
      },
      "line3": {
        "value": "6459 Market St"
      },
      "city": {
        "value": "Seattle"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "65078"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "alex.7712@sandbox.example.com"
      },
      "phone_number": {
        "value": "3497811122"
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
        "value": "911 Sunset Dr"
      },
      "line2": {
        "value": "4515 Oak Ln"
      },
      "line3": {
        "value": "5788 Lake Ln"
      },
      "city": {
        "value": "Chicago"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "96323"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "casey.2549@example.com"
      },
      "phone_number": {
        "value": "3557577585"
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
  "merchantCustomerId": "cus_U8SIckPKdqj22u",
  "connectorCustomerId": "cus_U8SIckPKdqj22u",
  "statusCode": 200,
  "responseHeaders": {
    "access-control-allow-credentials": "true",
    "access-control-allow-methods": "GET, HEAD, PUT, PATCH, POST, DELETE",
    "access-control-allow-origin": "*",
    "access-control-expose-headers": "Request-Id, Stripe-Manage-Version, Stripe-Should-Retry, X-Stripe-External-Auth-Required, X-Stripe-Privileged-Session-Required",
    "access-control-max-age": "300",
    "cache-control": "no-cache, no-store",
    "connection": "keep-alive",
    "content-length": "669",
    "content-security-policy": "base-uri 'none'; default-src 'none'; form-action 'none'; frame-ancestors 'none'; img-src 'self'; script-src 'self' 'report-sample'; style-src 'self'; worker-src 'none'; upgrade-insecure-requests; report-uri https://q.stripe.com/csp-violation?q=XbpkE0Obtc-D-_OVcHByv3HX2Cz2ZXWthan_OSmhaX_cdx20p33NXUJkyzusgJOGoDWC714Lefdz6v3w",
    "content-type": "application/json",
    "date": "Thu, 12 Mar 2026 15:42:45 GMT",
    "idempotency-key": "64f0e0c0-14b3-4cd0-8d88-3660740dc760",
    "original-request": "req_W9O7vYE7Z2Pc0n",
    "request-id": "req_W9O7vYE7Z2Pc0n",
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
<summary>2. authorize(no3ds_manual_capture_credit_card) — PASS</summary>

<details>
<summary>Show Dependency gRPC Request (masked)</summary>

```bash
grpcurl -plaintext \
  -H "x-connector: stripe" \
  -H "x-merchant-id: test_merchant" \
  -H "x-tenant-id: default" \
  -H "x-request-id: authorize_no3ds_manual_capture_credit_card_req" \
  -H "x-connector-request-reference-id: authorize_no3ds_manual_capture_credit_card_ref" \
  -H "x-auth: ***MASKED***" \
  -H "x-api-key: ***MASKED***" \
  -d @ localhost:8000 types.PaymentService/Authorize <<'JSON'
{
  "merchant_transaction_id": "mti_4a479d0a63b542068e1f243738ea0a42",
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
        "value": "Liam Miller"
      },
      "card_type": "credit"
    }
  },
  "capture_method": "MANUAL",
  "customer": {
    "name": "Emma Taylor",
    "email": {
      "value": "jordan.3715@example.com"
    },
    "id": "cust_48dbd0c580aa451088ebde48d00ac0e5",
    "phone_number": "+17791661696",
    "connector_customer_id": "cus_U8SIckPKdqj22u"
  },
  "locale": "en-US",
  "address": {
    "shipping_address": {
      "first_name": {
        "value": "Noah"
      },
      "last_name": {
        "value": "Taylor"
      },
      "line1": {
        "value": "2352 Oak St"
      },
      "line2": {
        "value": "4428 Oak Ave"
      },
      "line3": {
        "value": "6459 Market St"
      },
      "city": {
        "value": "Seattle"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "65078"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "alex.7712@sandbox.example.com"
      },
      "phone_number": {
        "value": "3497811122"
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
        "value": "911 Sunset Dr"
      },
      "line2": {
        "value": "4515 Oak Ln"
      },
      "line3": {
        "value": "5788 Lake Ln"
      },
      "city": {
        "value": "Chicago"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "96323"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "casey.2549@example.com"
      },
      "phone_number": {
        "value": "3557577585"
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
  "description": "No3DS manual capture card payment (credit)",
  "payment_channel": "ECOMMERCE",
  "test_mode": true
}
JSON
```

</details>

<details>
<summary>Show Dependency gRPC Response (masked)</summary>

```text
Resolved method descriptor:
// Authorize a payment amount on a payment method. This reserves funds
// without capturing them, essential for verifying availability before finalizing.
rpc Authorize ( .types.PaymentServiceAuthorizeRequest ) returns ( .types.PaymentServiceAuthorizeResponse );

Request metadata to send:
x-api-key: ***MASKED***
x-auth: ***MASKED***
x-connector: stripe
x-connector-request-reference-id: authorize_no3ds_manual_capture_credit_card_ref
x-merchant-id: test_merchant
x-request-id: authorize_no3ds_manual_capture_credit_card_req
x-tenant-id: default

Response headers received:
content-type: application/grpc
date: Thu, 12 Mar 2026 15:42:46 GMT
x-request-id: authorize_no3ds_manual_capture_credit_card_req

Response contents:
{
  "merchantTransactionId": "pi_3TABNpD5R7gDAGff10BfPcFf",
  "connectorTransactionId": "pi_3TABNpD5R7gDAGff10BfPcFf",
  "status": "AUTHORIZED",
  "statusCode": 200,
  "responseHeaders": {
    "access-control-allow-credentials": "true",
    "access-control-allow-methods": "GET, HEAD, PUT, PATCH, POST, DELETE",
    "access-control-allow-origin": "*",
    "access-control-expose-headers": "Request-Id, Stripe-Manage-Version, Stripe-Should-Retry, X-Stripe-External-Auth-Required, X-Stripe-Privileged-Session-Required",
    "access-control-max-age": "300",
    "cache-control": "no-cache, no-store",
    "connection": "keep-alive",
    "content-length": "5544",
    "content-security-policy": "base-uri 'none'; default-src 'none'; form-action 'none'; frame-ancestors 'none'; img-src 'self'; script-src 'self' 'report-sample'; style-src 'self'; worker-src 'none'; upgrade-insecure-requests; report-uri https://q.stripe.com/csp-violation?q=XbpkE0Obtc-D-_OVcHByv3HX2Cz2ZXWthan_OSmhaX_cdx20p33NXUJkyzusgJOGoDWC714Lefdz6v3w",
    "content-type": "application/json",
    "date": "Thu, 12 Mar 2026 15:42:46 GMT",
    "idempotency-key": "4fbc56ad-e110-43e6-a58f-e73f6b140e56",
    "original-request": "req_HY2MdMDOiRzPDL",
    "request-id": "req_HY2MdMDOiRzPDL",
    "server": "nginx",
    "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
    "stripe-should-retry": "false",
    "stripe-version": "2022-11-15",
    "vary": "Origin",
    "x-stripe-priority-routing-enabled": "true",
    "x-stripe-routing-context-priority-tier": "api-testmode",
    "x-wc": "ABGHIJ"
  },
  "networkTransactionId": "976910110049114",
  "state": {
    "connectorCustomerId": "cus_U8SIckPKdqj22u"
  },
  "rawConnectorResponse": {
    "value": "{\n  \"id\": \"pi_3TABNpD5R7gDAGff10BfPcFf\",\n  \"object\": \"payment_intent\",\n  \"amount\": 6000,\n  \"amount_capturable\": 6000,\n  \"amount_details\": {\n    \"tip\": {}\n  },\n  \"amount_received\": 0,\n  \"application\": null,\n  \"application_fee_amount\": null,\n  \"automatic_payment_methods\": null,\n  \"canceled_at\": null,\n  \"cancellation_reason\": null,\n  \"capture_method\": \"manual\",\n  \"client_secret\": \"pi_3TABNpD5R7gDAGff10BfPcFf_secret_lQGSLagbRry7gtaJLwJZwV2Hc\",\n  \"confirmation_method\": \"automatic\",\n  \"created\": 1773330165,\n  \"currency\": \"usd\",\n  \"customer\": \"cus_U8SIckPKdqj22u\",\n  \"customer_account\": null,\n  \"description\": \"No3DS manual capture card payment (credit)\",\n  \"excluded_payment_method_types\": null,\n  \"invoice\": null,\n  \"last_payment_error\": null,\n  \"latest_charge\": {\n    \"id\": \"ch_3TABNpD5R7gDAGff1okOR7Gh\",\n    \"object\": \"charge\",\n    \"amount\": 6000,\n    \"amount_captured\": 0,\n    \"amount_refunded\": 0,\n    \"amount_updates\": [],\n    \"application\": null,\n    \"application_fee\": null,\n    \"application_fee_amount\": null,\n    \"balance_transaction\": null,\n    \"billing_details\": {\n      \"address\": {\n        \"city\": \"Chicago\",\n        \"country\": \"US\",\n        \"line1\": \"911 Sunset Dr\",\n        \"line2\": \"4515 Oak Ln\",\n        \"postal_code\": \"96323\",\n        \"state\": \"CA\"\n      },\n      \"email\": \"casey.2549@example.com\",\n      \"name\": \"Liam Miller\",\n      \"phone\": \"3557577585\",\n      \"tax_id\": null\n    },\n    \"calculated_statement_descriptor\": \"BERNARD\",\n    \"captured\": false,\n    \"created\": 1773330165,\n    \"currency\": \"usd\",\n    \"customer\": \"cus_U8SIckPKdqj22u\",\n    \"description\": \"No3DS manual capture card payment (credit)\",\n    \"destination\": null,\n    \"dispute\": null,\n    \"disputed\": false,\n    \"failure_balance_transaction\": null,\n    \"failure_code\": null,\n    \"failure_message\": null,\n    \"fraud_details\": {},\n    \"invoice\": null,\n    \"livemode\": false,\n    \"metadata\": {\n      \"order_id\": \"mti_4a479d0a63b542068e1f243738ea0a42\"\n    },\n    \"on_behalf_of\": null,\n    \"order\": null,\n    \"outcome\": {\n      \"advice_code\": null,\n      \"network_advice_code\": null,\n      \"network_decline_code\": null,\n      \"network_status\": \"approved_by_network\",\n      \"reason\": null,\n      \"risk_level\": \"normal\",\n      \"risk_score\": 15,\n      \"seller_message\": \"Payment complete.\",\n      \"type\": \"authorized\"\n    },\n    \"paid\": true,\n    \"payment_intent\": \"pi_3TABNpD5R7gDAGff10BfPcFf\",\n    \"payment_method\": \"pm_1TABNpD5R7gDAGffIV0xjSns\",\n    \"payment_method_details\": {\n      \"card\": {\n        \"amount_authorized\": 6000,\n        \"authorization_code\": \"448368\",\n        \"brand\": \"visa\",\n        \"capture_before\": 1773934965,\n        \"checks\": {\n          \"address_line1_check\": \"pass\",\n          \"address_postal_code_check\": \"pass\",\n          \"cvc_check\": \"pass\"\n        },\n        \"country\": \"US\",\n        \"exp_month\": 8,\n        \"exp_year\": 2030,\n        \"extended_authorization\": {\n          \"status\": \"disabled\"\n        },\n        \"fingerprint\": \"aEed1rfhfa5JNpoz\",\n        \"funding\": \"credit\",\n        \"incremental_authorization\": {\n          \"status\": \"unavailable\"\n        },\n        \"installments\": null,\n        \"last4\": \"1111\",\n        \"mandate\": null,\n        \"moto\": null,\n        \"multicapture\": {\n          \"status\": \"unavailable\"\n        },\n        \"network\": \"visa\",\n        \"network_token\": {\n          \"used\": false\n        },\n        \"network_transaction_id\": \"976910110049114\",\n        \"overcapture\": {\n          \"maximum_amount_capturable\": 6000,\n          \"status\": \"unavailable\"\n        },\n        \"regulated_status\": \"unregulated\",\n        \"three_d_secure\": null,\n        \"wallet\": null\n      },\n      \"type\": \"card\"\n    },\n    \"radar_options\": {},\n    \"receipt_email\": null,\n    \"receipt_number\": null,\n    \"receipt_url\": \"https://pay.stripe.com/receipts/payment/CAcaFwoVYWNjdF8xTTdmVGFENVI3Z0RBR2ZmKPa9y80GMgYTS1vyRFY6LBY97tWmOFoVwiSo-OsgW8yyNzKyb5ANFBF8i7sm8eBqjp4idWai57r-f0a9\",\n    \"refunded\": false,\n    \"review\": null,\n    \"shipping\": {\n      \"address\": {\n        \"city\": \"Seattle\",\n        \"country\": \"US\",\n        \"line1\": \"2352 Oak St\",\n        \"line2\": \"4428 Oak Ave\",\n        \"postal_code\": \"65078\",\n        \"state\": \"CA\"\n      },\n      \"carrier\": null,\n      \"name\": \"Noah Taylor\",\n      \"phone\": \"+913497811122\",\n      \"tracking_number\": null\n    },\n    \"source\": null,\n    \"source_transfer\": null,\n    \"statement_descriptor\": null,\n    \"statement_descriptor_suffix\": null,\n    \"status\": \"succeeded\",\n    \"transfer_data\": null,\n    \"transfer_group\": null\n  },\n  \"livemode\": false,\n  \"metadata\": {\n    \"order_id\": \"mti_4a479d0a63b542068e1f243738ea0a42\"\n  },\n  \"next_action\": null,\n  \"on_behalf_of\": null,\n  \"payment_method\": \"pm_1TABNpD5R7gDAGffIV0xjSns\",\n  \"payment_method_configuration_details\": null,\n  \"payment_method_options\": {\n    \"card\": {\n      \"installments\": null,\n      \"mandate_options\": null,\n      \"network\": null,\n      \"request_three_d_secure\": \"automatic\"\n    }\n  },\n  \"payment_method_types\": [\n    \"card\"\n  ],\n  \"processing\": null,\n  \"receipt_email\": null,\n  \"review\": null,\n  \"setup_future_usage\": \"on_session\",\n  \"shipping\": {\n    \"address\": {\n      \"city\": \"Seattle\",\n      \"country\": \"US\",\n      \"line1\": \"2352 Oak St\",\n      \"line2\": \"4428 Oak Ave\",\n      \"postal_code\": \"65078\",\n      \"state\": \"CA\"\n    },\n    \"carrier\": null,\n    \"name\": \"Noah Taylor\",\n    \"phone\": \"+913497811122\",\n    \"tracking_number\": null\n  },\n  \"source\": null,\n  \"statement_descriptor\": null,\n  \"statement_descriptor_suffix\": null,\n  \"status\": \"requires_capture\",\n  \"transfer_data\": null,\n  \"transfer_group\": null\n}"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://api.stripe.com/v1/payment_intents\",\"method\":\"POST\",\"headers\":{\"Content-Type\":\"application/x-www-form-urlencoded\",\"stripe-version\":\"2022-11-15\",\"via\":\"HyperSwitch\",\"Authorization\":\"Bearer ***MASKED***"},\"body\":\"amount=6000\u0026currency=USD\u0026metadata%5Border_id%5D=mti_4a479d0a63b542068e1f243738ea0a42\u0026return_url=https%3A%2F%2Fexample.com%2Fpayment%2Freturn\u0026confirm=true\u0026customer=cus_U8SIckPKdqj22u\u0026description=No3DS+manual+capture+card+payment+%28credit%29\u0026shipping%5Baddress%5D%5Bcity%5D=Seattle\u0026shipping%5Baddress%5D%5Bcountry%5D=US\u0026shipping%5Baddress%5D%5Bline1%5D=2352+Oak+St\u0026shipping%5Baddress%5D%5Bline2%5D=4428+Oak+Ave\u0026shipping%5Baddress%5D%5Bpostal_code%5D=65078\u0026shipping%5Baddress%5D%5Bstate%5D=CA\u0026shipping%5Bname%5D=Noah+Taylor\u0026shipping%5Bphone%5D=%2B913497811122\u0026payment_method_data%5Bbilling_details%5D%5Bemail%5D=casey.2549%40example.com\u0026payment_method_data%5Bbilling_details%5D%5Baddress%5D%5Bcountry%5D=US\u0026payment_method_data%5Bbilling_details%5D%5Bname%5D=Liam+Miller\u0026payment_method_data%5Bbilling_details%5D%5Baddress%5D%5Bcity%5D=Chicago\u0026payment_method_data%5Bbilling_details%5D%5Baddress%5D%5Bline1%5D=911+Sunset+Dr\u0026payment_method_data%5Bbilling_details%5D%5Baddress%5D%5Bline2%5D=4515+Oak+Ln\u0026payment_method_data%5Bbilling_details%5D%5Baddress%5D%5Bpostal_code%5D=96323\u0026payment_method_data%5Bbilling_details%5D%5Baddress%5D%5Bstate%5D=CA\u0026payment_method_data%5Bbilling_details%5D%5Bphone%5D=3557577585\u0026payment_method_data%5Btype%5D=card\u0026payment_method_data%5Bcard%5D%5Bnumber%5D=4111111111111111\u0026payment_method_data%5Bcard%5D%5Bexp_month%5D=08\u0026payment_method_data%5Bcard%5D%5Bexp_year%5D=30\u0026payment_method_data%5Bcard%5D%5Bcvc%5D=999\u0026payment_method_options%5Bcard%5D%5Brequest_three_d_secure%5D=automatic\u0026capture_method=manual\u0026setup_future_usage=on_session\u0026off_session=false\u0026payment_method_types%5B0%5D=card\u0026expand%5B0%5D=latest_charge\"}"
  },
  "mandateReference": {
    "connectorMandateId": {
      "connectorMandateId": "pm_1TABNpD5R7gDAGffIV0xjSns",
      "paymentMethodId": "pm_1TABNpD5R7gDAGffIV0xjSns"
    }
  },
  "connectorResponse": {
    "additionalPaymentMethodData": {
      "card": {
        "paymentChecks": "eyJhZGRyZXNzX2xpbmUxX2NoZWNrIjoicGFzcyIsImFkZHJlc3NfcG9zdGFsX2NvZGVfY2hlY2siOiJwYXNzIiwiY3ZjX2NoZWNrIjoicGFzcyJ9"
      }
    },
    "extendedAuthorizationResponseData": ***MASKED***
      "extendedAuthenticationApplied": false
    },
    "isOvercaptureEnabled": false
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
  "merchant_transaction_id": "mti_4a479d0a63b542068e1f243738ea0a42",
  "amount": {
    "minor_amount": 6000,
    "currency": "USD"
  },
  "order_tax_amount": 0,
  "shipping_cost": 0,
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
        "value": "Liam Miller"
      },
      "card_type": "credit"
    }
  },
  "capture_method": "MANUAL",
  "customer": {
    "name": "Emma Taylor",
    "email": {
      "value": "jordan.3715@example.com"
    },
    "id": "cust_48dbd0c580aa451088ebde48d00ac0e5",
    "phone_number": "+17791661696",
    "connector_customer_id": "cus_U8SIckPKdqj22u"
  },
  "locale": "en-US",
  "address": {
    "shipping_address": {
      "first_name": {
        "value": "Noah"
      },
      "last_name": {
        "value": "Taylor"
      },
      "line1": {
        "value": "2352 Oak St"
      },
      "line2": {
        "value": "4428 Oak Ave"
      },
      "line3": {
        "value": "6459 Market St"
      },
      "city": {
        "value": "Seattle"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "65078"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "alex.7712@sandbox.example.com"
      },
      "phone_number": {
        "value": "3497811122"
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
        "value": "911 Sunset Dr"
      },
      "line2": {
        "value": "4515 Oak Ln"
      },
      "line3": {
        "value": "5788 Lake Ln"
      },
      "city": {
        "value": "Chicago"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "96323"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "casey.2549@example.com"
      },
      "phone_number": {
        "value": "3557577585"
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
  "description": "No3DS manual capture card payment (credit)",
  "payment_channel": "ECOMMERCE",
  "test_mode": true
}
```

</details>

<details>
<summary>Show Dependency Response Body</summary>

```json
{
  "merchantTransactionId": "pi_3TABNpD5R7gDAGff10BfPcFf",
  "connectorTransactionId": "pi_3TABNpD5R7gDAGff10BfPcFf",
  "status": "AUTHORIZED",
  "statusCode": 200,
  "responseHeaders": {
    "access-control-allow-credentials": "true",
    "access-control-allow-methods": "GET, HEAD, PUT, PATCH, POST, DELETE",
    "access-control-allow-origin": "*",
    "access-control-expose-headers": "Request-Id, Stripe-Manage-Version, Stripe-Should-Retry, X-Stripe-External-Auth-Required, X-Stripe-Privileged-Session-Required",
    "access-control-max-age": "300",
    "cache-control": "no-cache, no-store",
    "connection": "keep-alive",
    "content-length": "5544",
    "content-security-policy": "base-uri 'none'; default-src 'none'; form-action 'none'; frame-ancestors 'none'; img-src 'self'; script-src 'self' 'report-sample'; style-src 'self'; worker-src 'none'; upgrade-insecure-requests; report-uri https://q.stripe.com/csp-violation?q=XbpkE0Obtc-D-_OVcHByv3HX2Cz2ZXWthan_OSmhaX_cdx20p33NXUJkyzusgJOGoDWC714Lefdz6v3w",
    "content-type": "application/json",
    "date": "Thu, 12 Mar 2026 15:42:46 GMT",
    "idempotency-key": "4fbc56ad-e110-43e6-a58f-e73f6b140e56",
    "original-request": "req_HY2MdMDOiRzPDL",
    "request-id": "req_HY2MdMDOiRzPDL",
    "server": "nginx",
    "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
    "stripe-should-retry": "false",
    "stripe-version": "2022-11-15",
    "vary": "Origin",
    "x-stripe-priority-routing-enabled": "true",
    "x-stripe-routing-context-priority-tier": "api-testmode",
    "x-wc": "ABGHIJ"
  },
  "networkTransactionId": "976910110049114",
  "state": {
    "connectorCustomerId": "cus_U8SIckPKdqj22u"
  },
  "rawConnectorResponse": {
    "value": "{\n  \"id\": \"pi_3TABNpD5R7gDAGff10BfPcFf\",\n  \"object\": \"payment_intent\",\n  \"amount\": 6000,\n  \"amount_capturable\": 6000,\n  \"amount_details\": {\n    \"tip\": {}\n  },\n  \"amount_received\": 0,\n  \"application\": null,\n  \"application_fee_amount\": null,\n  \"automatic_payment_methods\": null,\n  \"canceled_at\": null,\n  \"cancellation_reason\": null,\n  \"capture_method\": \"manual\",\n  \"client_secret\": ***MASKED***\"\n  \"confirmation_method\": \"automatic\",\n  \"created\": 1773330165,\n  \"currency\": \"usd\",\n  \"customer\": \"cus_U8SIckPKdqj22u\",\n  \"customer_account\": null,\n  \"description\": \"No3DS manual capture card payment (credit)\",\n  \"excluded_payment_method_types\": null,\n  \"invoice\": null,\n  \"last_payment_error\": null,\n  \"latest_charge\": {\n    \"id\": \"ch_3TABNpD5R7gDAGff1okOR7Gh\",\n    \"object\": \"charge\",\n    \"amount\": 6000,\n    \"amount_captured\": 0,\n    \"amount_refunded\": 0,\n    \"amount_updates\": [],\n    \"application\": null,\n    \"application_fee\": null,\n    \"application_fee_amount\": null,\n    \"balance_transaction\": null,\n    \"billing_details\": {\n      \"address\": {\n        \"city\": \"Chicago\",\n        \"country\": \"US\",\n        \"line1\": \"911 Sunset Dr\",\n        \"line2\": \"4515 Oak Ln\",\n        \"postal_code\": \"96323\",\n        \"state\": \"CA\"\n      },\n      \"email\": \"casey.2549@example.com\",\n      \"name\": \"Liam Miller\",\n      \"phone\": \"3557577585\",\n      \"tax_id\": null\n    },\n    \"calculated_statement_descriptor\": \"BERNARD\",\n    \"captured\": false,\n    \"created\": 1773330165,\n    \"currency\": \"usd\",\n    \"customer\": \"cus_U8SIckPKdqj22u\",\n    \"description\": \"No3DS manual capture card payment (credit)\",\n    \"destination\": null,\n    \"dispute\": null,\n    \"disputed\": false,\n    \"failure_balance_transaction\": null,\n    \"failure_code\": null,\n    \"failure_message\": null,\n    \"fraud_details\": {},\n    \"invoice\": null,\n    \"livemode\": false,\n    \"metadata\": {\n      \"order_id\": \"mti_4a479d0a63b542068e1f243738ea0a42\"\n    },\n    \"on_behalf_of\": null,\n    \"order\": null,\n    \"outcome\": {\n      \"advice_code\": null,\n      \"network_advice_code\": null,\n      \"network_decline_code\": null,\n      \"network_status\": \"approved_by_network\",\n      \"reason\": null,\n      \"risk_level\": \"normal\",\n      \"risk_score\": 15,\n      \"seller_message\": \"Payment complete.\",\n      \"type\": \"authorized\"\n    },\n    \"paid\": true,\n    \"payment_intent\": \"pi_3TABNpD5R7gDAGff10BfPcFf\",\n    \"payment_method\": \"pm_1TABNpD5R7gDAGffIV0xjSns\",\n    \"payment_method_details\": {\n      \"card\": {\n        \"amount_authorized\": 6000,\n        \"authorization_code\": ***MASKED***\"\n        \"brand\": \"visa\",\n        \"capture_before\": 1773934965,\n        \"checks\": {\n          \"address_line1_check\": \"pass\",\n          \"address_postal_code_check\": \"pass\",\n          \"cvc_check\": ***MASKED***\"\n        },\n        \"country\": \"US\",\n        \"exp_month\": ***MASKED***\n        \"exp_year\": ***MASKED***\n        \"extended_authorization\": ***MASKED***\n          \"status\": \"disabled\"\n        },\n        \"fingerprint\": \"aEed1rfhfa5JNpoz\",\n        \"funding\": \"credit\",\n        \"incremental_authorization\": ***MASKED***\n          \"status\": \"unavailable\"\n        },\n        \"installments\": null,\n        \"last4\": \"1111\",\n        \"mandate\": null,\n        \"moto\": null,\n        \"multicapture\": {\n          \"status\": \"unavailable\"\n        },\n        \"network\": \"visa\",\n        \"network_token\": ***MASKED***\n          \"used\": false\n        },\n        \"network_transaction_id\": \"976910110049114\",\n        \"overcapture\": {\n          \"maximum_amount_capturable\": 6000,\n          \"status\": \"unavailable\"\n        },\n        \"regulated_status\": \"unregulated\",\n        \"three_d_secure\": null,\n        \"wallet\": null\n      },\n      \"type\": \"card\"\n    },\n    \"radar_options\": {},\n    \"receipt_email\": null,\n    \"receipt_number\": null,\n    \"receipt_url\": \"https://pay.stripe.com/receipts/payment/CAcaFwoVYWNjdF8xTTdmVGFENVI3Z0RBR2ZmKPa9y80GMgYTS1vyRFY6LBY97tWmOFoVwiSo-OsgW8yyNzKyb5ANFBF8i7sm8eBqjp4idWai57r-f0a9\",\n    \"refunded\": false,\n    \"review\": null,\n    \"shipping\": {\n      \"address\": {\n        \"city\": \"Seattle\",\n        \"country\": \"US\",\n        \"line1\": \"2352 Oak St\",\n        \"line2\": \"4428 Oak Ave\",\n        \"postal_code\": \"65078\",\n        \"state\": \"CA\"\n      },\n      \"carrier\": null,\n      \"name\": \"Noah Taylor\",\n      \"phone\": \"+913497811122\",\n      \"tracking_number\": null\n    },\n    \"source\": null,\n    \"source_transfer\": null,\n    \"statement_descriptor\": null,\n    \"statement_descriptor_suffix\": null,\n    \"status\": \"succeeded\",\n    \"transfer_data\": null,\n    \"transfer_group\": null\n  },\n  \"livemode\": false,\n  \"metadata\": {\n    \"order_id\": \"mti_4a479d0a63b542068e1f243738ea0a42\"\n  },\n  \"next_action\": null,\n  \"on_behalf_of\": null,\n  \"payment_method\": \"pm_1TABNpD5R7gDAGffIV0xjSns\",\n  \"payment_method_configuration_details\": null,\n  \"payment_method_options\": {\n    \"card\": {\n      \"installments\": null,\n      \"mandate_options\": null,\n      \"network\": null,\n      \"request_three_d_secure\": \"automatic\"\n    }\n  },\n  \"payment_method_types\": [\n    \"card\"\n  ],\n  \"processing\": null,\n  \"receipt_email\": null,\n  \"review\": null,\n  \"setup_future_usage\": \"on_session\",\n  \"shipping\": {\n    \"address\": {\n      \"city\": \"Seattle\",\n      \"country\": \"US\",\n      \"line1\": \"2352 Oak St\",\n      \"line2\": \"4428 Oak Ave\",\n      \"postal_code\": \"65078\",\n      \"state\": \"CA\"\n    },\n    \"carrier\": null,\n    \"name\": \"Noah Taylor\",\n    \"phone\": \"+913497811122\",\n    \"tracking_number\": null\n  },\n  \"source\": null,\n  \"statement_descriptor\": null,\n  \"statement_descriptor_suffix\": null,\n  \"status\": \"requires_capture\",\n  \"transfer_data\": null,\n  \"transfer_group\": null\n}"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://api.stripe.com/v1/payment_intents\",\"method\":\"POST\",\"headers\":{\"Content-Type\":\"application/x-www-form-urlencoded\",\"stripe-version\":\"2022-11-15\",\"via\":\"HyperSwitch\",\"Authorization\":\"Bearer ***MASKED***\"},\"body\":\"amount=6000&currency=USD&metadata%5Border_id%5D=mti_4a479d0a63b542068e1f243738ea0a42&return_url=https%3A%2F%2Fexample.com%2Fpayment%2Freturn&confirm=true&customer=cus_U8SIckPKdqj22u&description=No3DS+manual+capture+card+payment+%28credit%29&shipping%5Baddress%5D%5Bcity%5D=Seattle&shipping%5Baddress%5D%5Bcountry%5D=US&shipping%5Baddress%5D%5Bline1%5D=2352+Oak+St&shipping%5Baddress%5D%5Bline2%5D=4428+Oak+Ave&shipping%5Baddress%5D%5Bpostal_code%5D=65078&shipping%5Baddress%5D%5Bstate%5D=CA&shipping%5Bname%5D=Noah+Taylor&shipping%5Bphone%5D=%2B913497811122&payment_method_data%5Bbilling_details%5D%5Bemail%5D=casey.2549%40example.com&payment_method_data%5Bbilling_details%5D%5Baddress%5D%5Bcountry%5D=US&payment_method_data%5Bbilling_details%5D%5Bname%5D=Liam+Miller&payment_method_data%5Bbilling_details%5D%5Baddress%5D%5Bcity%5D=Chicago&payment_method_data%5Bbilling_details%5D%5Baddress%5D%5Bline1%5D=911+Sunset+Dr&payment_method_data%5Bbilling_details%5D%5Baddress%5D%5Bline2%5D=4515+Oak+Ln&payment_method_data%5Bbilling_details%5D%5Baddress%5D%5Bpostal_code%5D=96323&payment_method_data%5Bbilling_details%5D%5Baddress%5D%5Bstate%5D=CA&payment_method_data%5Bbilling_details%5D%5Bphone%5D=3557577585&payment_method_data%5Btype%5D=card&payment_method_data%5Bcard%5D%5Bnumber%5D=4111111111111111&payment_method_data%5Bcard%5D%5Bexp_month%5D=08&payment_method_data%5Bcard%5D%5Bexp_year%5D=30&payment_method_data%5Bcard%5D%5Bcvc%5D=999&payment_method_options%5Bcard%5D%5Brequest_three_d_secure%5D=automatic&capture_method=manual&setup_future_usage=on_session&off_session=false&payment_method_types%5B0%5D=card&expand%5B0%5D=latest_charge\"}"
  },
  "mandateReference": {
    "connectorMandateId": {
      "connectorMandateId": "pm_1TABNpD5R7gDAGffIV0xjSns",
      "paymentMethodId": "pm_1TABNpD5R7gDAGffIV0xjSns"
    }
  },
  "connectorResponse": {
    "additionalPaymentMethodData": {
      "card": {
        "paymentChecks": "eyJhZGRyZXNzX2xpbmUxX2NoZWNrIjoicGFzcyIsImFkZHJlc3NfcG9zdGFsX2NvZGVfY2hlY2siOiJwYXNzIiwiY3ZjX2NoZWNrIjoicGFzcyJ9"
      }
    },
    "extendedAuthorizationResponseData": "***MASKED***",
    "isOvercaptureEnabled": false
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
  -H "x-request-id: capture_capture_partial_amount_req" \
  -H "x-connector-request-reference-id: capture_capture_partial_amount_ref" \
  -H "x-auth: ***MASKED***" \
  -H "x-api-key: ***MASKED***" \
  -d @ localhost:8000 types.PaymentService/Capture <<'JSON'
{
  "connector_transaction_id": "pi_3TABNpD5R7gDAGff10BfPcFf",
  "amount_to_capture": {
    "minor_amount": 3000,
    "currency": "USD"
  },
  "merchant_capture_id": "mci_1d9d685b795d4dba804010a0bb18c612",
  "state": {
    "connector_customer_id": "cus_U8SIckPKdqj22u"
  }
}
JSON
```

</details>

<details>
<summary>Show gRPC Response (masked)</summary>

```text
Resolved method descriptor:
// Finalize an authorized payment transaction. Transfers reserved funds from
// customer to merchant account, completing the payment lifecycle.
rpc Capture ( .types.PaymentServiceCaptureRequest ) returns ( .types.PaymentServiceCaptureResponse );

Request metadata to send:
x-api-key: ***MASKED***
x-auth: ***MASKED***
x-connector: stripe
x-connector-request-reference-id: capture_capture_partial_amount_ref
x-merchant-id: test_merchant
x-request-id: capture_capture_partial_amount_req
x-tenant-id: default

Response headers received:
content-type: application/grpc
date: Thu, 12 Mar 2026 15:42:48 GMT
x-request-id: capture_capture_partial_amount_req

Response contents:
{
  "connectorTransactionId": "pi_3TABNpD5R7gDAGff10BfPcFf",
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
    "content-length": "1841",
    "content-security-policy": "base-uri 'none'; default-src 'none'; form-action 'none'; frame-ancestors 'none'; img-src 'self'; script-src 'self' 'report-sample'; style-src 'self'; worker-src 'none'; upgrade-insecure-requests; report-uri https://q.stripe.com/csp-violation?q=XbpkE0Obtc-D-_OVcHByv3HX2Cz2ZXWthan_OSmhaX_cdx20p33NXUJkyzusgJOGoDWC714Lefdz6v3w",
    "content-type": "application/json",
    "date": "Thu, 12 Mar 2026 15:42:48 GMT",
    "idempotency-key": "b873f65d-b3c9-459b-a99d-f90cd01cc942",
    "original-request": "req_XX0cOE1tLKkaFH",
    "request-id": "req_XX0cOE1tLKkaFH",
    "server": "nginx",
    "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
    "stripe-should-retry": "false",
    "stripe-version": "2022-11-15",
    "vary": "Origin",
    "x-stripe-priority-routing-enabled": "true",
    "x-stripe-routing-context-priority-tier": "api-testmode",
    "x-wc": "ABGHIJ"
  },
  "merchantCaptureId": "pi_3TABNpD5R7gDAGff10BfPcFf",
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://api.stripe.com/v1/payment_intents/pi_3TABNpD5R7gDAGff10BfPcFf/capture\",\"method\":\"POST\",\"headers\":{\"Authorization\":\"Bearer ***MASKED***",\"via\":\"HyperSwitch\",\"stripe-version\":\"2022-11-15\",\"Content-Type\":\"application/x-www-form-urlencoded\"},\"body\":\"amount_to_capture=3000\"}"
  },
  "capturedAmount": "3000",
  "mandateReference": {
    "connectorMandateId": {
      "connectorMandateId": "pm_1TABNpD5R7gDAGffIV0xjSns",
      "paymentMethodId": "pm_1TABNpD5R7gDAGffIV0xjSns"
    }
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
  "connector_transaction_id": "pi_3TABNpD5R7gDAGff10BfPcFf",
  "amount_to_capture": {
    "minor_amount": 3000,
    "currency": "USD"
  },
  "merchant_capture_id": "mci_1d9d685b795d4dba804010a0bb18c612",
  "state": {
    "connector_customer_id": "cus_U8SIckPKdqj22u"
  }
}
```

</details>

<details>
<summary>Show Response Body</summary>

```json
{
  "connectorTransactionId": "pi_3TABNpD5R7gDAGff10BfPcFf",
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
    "content-length": "1841",
    "content-security-policy": "base-uri 'none'; default-src 'none'; form-action 'none'; frame-ancestors 'none'; img-src 'self'; script-src 'self' 'report-sample'; style-src 'self'; worker-src 'none'; upgrade-insecure-requests; report-uri https://q.stripe.com/csp-violation?q=XbpkE0Obtc-D-_OVcHByv3HX2Cz2ZXWthan_OSmhaX_cdx20p33NXUJkyzusgJOGoDWC714Lefdz6v3w",
    "content-type": "application/json",
    "date": "Thu, 12 Mar 2026 15:42:48 GMT",
    "idempotency-key": "b873f65d-b3c9-459b-a99d-f90cd01cc942",
    "original-request": "req_XX0cOE1tLKkaFH",
    "request-id": "req_XX0cOE1tLKkaFH",
    "server": "nginx",
    "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
    "stripe-should-retry": "false",
    "stripe-version": "2022-11-15",
    "vary": "Origin",
    "x-stripe-priority-routing-enabled": "true",
    "x-stripe-routing-context-priority-tier": "api-testmode",
    "x-wc": "ABGHIJ"
  },
  "merchantCaptureId": "pi_3TABNpD5R7gDAGff10BfPcFf",
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://api.stripe.com/v1/payment_intents/pi_3TABNpD5R7gDAGff10BfPcFf/capture\",\"method\":\"POST\",\"headers\":{\"Authorization\":\"Bearer ***MASKED***\",\"via\":\"HyperSwitch\",\"stripe-version\":\"2022-11-15\",\"Content-Type\":\"application/x-www-form-urlencoded\"},\"body\":\"amount_to_capture=3000\"}"
  },
  "capturedAmount": "3000",
  "mandateReference": {
    "connectorMandateId": {
      "connectorMandateId": "pm_1TABNpD5R7gDAGffIV0xjSns",
      "paymentMethodId": "pm_1TABNpD5R7gDAGffIV0xjSns"
    }
  }
}
```

</details>


[Back to Overview](../../test_overview.md)
