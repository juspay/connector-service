# Scenario `no3ds_fail_payment`

- Suite: `authorize`
- Service: `PaymentService/Authorize`
- PM / PMT: `card` / `credit`

## Connector Summary

| Connector | Result | Prerequisites |
|:----------|:------:|:--------------|
| `authorizedotnet` | [FAIL](./scenarios/authorize/no3ds-fail-payment.md#connector-authorizedotnet) | `create_customer(create_customer)` (PASS) |
| `paypal` | [FAIL](./scenarios/authorize/no3ds-fail-payment.md#connector-paypal) | `create_access_token(create_access_token)` (PASS) |
| `stripe` | [PASS](./scenarios/authorize/no3ds-fail-payment.md#connector-stripe) | `create_customer(create_customer)` (PASS) |

---

<a id="connector-authorizedotnet"></a>
## Connector `authorizedotnet` — `FAIL`


**Error**

```text
assertion failed for field 'error': expected field to exist
```

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
  "merchant_customer_id": "mcui_f5524de9b14146789dd9a26ad0bb6a9a",
  "customer_name": "Ethan Miller",
  "email": {
    "value": "alex.2783@sandbox.example.com"
  },
  "phone_number": "+449497204783",
  "address": {
    "shipping_address": {
      "first_name": {
        "value": "Mia"
      },
      "last_name": {
        "value": "Smith"
      },
      "line1": {
        "value": "3906 Oak Rd"
      },
      "line2": {
        "value": "4961 Lake St"
      },
      "line3": {
        "value": "696 Lake St"
      },
      "city": {
        "value": "Seattle"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "89370"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "morgan.1435@sandbox.example.com"
      },
      "phone_number": {
        "value": "9556215597"
      },
      "phone_country_code": "+91"
    },
    "billing_address": {
      "first_name": {
        "value": "Emma"
      },
      "last_name": {
        "value": "Johnson"
      },
      "line1": {
        "value": "2266 Market Blvd"
      },
      "line2": {
        "value": "3943 Oak Rd"
      },
      "line3": {
        "value": "3253 Main Ave"
      },
      "city": {
        "value": "Seattle"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "36052"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "casey.2238@example.com"
      },
      "phone_number": {
        "value": "4843389571"
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
date: Thu, 12 Mar 2026 15:40:05 GMT
x-request-id: create_customer_create_customer_req

Response contents:
{
  "merchantCustomerId": "934839050",
  "connectorCustomerId": "934839050",
  "statusCode": 200,
  "responseHeaders": {
    "access-control-allow-credentials": "true",
    "access-control-allow-headers": "x-requested-with,cache-control,content-type,origin,method,SOAPAction",
    "access-control-allow-methods": "PUT,OPTIONS,POST,GET",
    "access-control-allow-origin": "*",
    "cache-control": "no-cache, no-store, max-age=0",
    "content-length": "232",
    "content-type": "application/json; charset=utf-8",
    "date": "Thu, 12 Mar 2026 15:40:05 GMT",
    "expires": "-1",
    "pragma": "no-cache",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-cnection": "close",
    "x-download-options": "noopen",
    "x-opnet-transaction-trace": "6275c255-1f58-458f-b516-e5c061e8590b-12436-10988680"
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
  "merchant_customer_id": "mcui_f5524de9b14146789dd9a26ad0bb6a9a",
  "customer_name": "Ethan Miller",
  "email": {
    "value": "alex.2783@sandbox.example.com"
  },
  "phone_number": "+449497204783",
  "address": {
    "shipping_address": {
      "first_name": {
        "value": "Mia"
      },
      "last_name": {
        "value": "Smith"
      },
      "line1": {
        "value": "3906 Oak Rd"
      },
      "line2": {
        "value": "4961 Lake St"
      },
      "line3": {
        "value": "696 Lake St"
      },
      "city": {
        "value": "Seattle"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "89370"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "morgan.1435@sandbox.example.com"
      },
      "phone_number": {
        "value": "9556215597"
      },
      "phone_country_code": "+91"
    },
    "billing_address": {
      "first_name": {
        "value": "Emma"
      },
      "last_name": {
        "value": "Johnson"
      },
      "line1": {
        "value": "2266 Market Blvd"
      },
      "line2": {
        "value": "3943 Oak Rd"
      },
      "line3": {
        "value": "3253 Main Ave"
      },
      "city": {
        "value": "Seattle"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "36052"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "casey.2238@example.com"
      },
      "phone_number": {
        "value": "4843389571"
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
  "merchantCustomerId": "934839050",
  "connectorCustomerId": "934839050",
  "statusCode": 200,
  "responseHeaders": {
    "access-control-allow-credentials": "true",
    "access-control-allow-headers": "x-requested-with,cache-control,content-type,origin,method,SOAPAction",
    "access-control-allow-methods": "PUT,OPTIONS,POST,GET",
    "access-control-allow-origin": "*",
    "cache-control": "no-cache, no-store, max-age=0",
    "content-length": "232",
    "content-type": "application/json; charset=utf-8",
    "date": "Thu, 12 Mar 2026 15:40:05 GMT",
    "expires": "-1",
    "pragma": "no-cache",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-cnection": "close",
    "x-download-options": "noopen",
    "x-opnet-transaction-trace": "6275c255-1f58-458f-b516-e5c061e8590b-12436-10988680"
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
  -H "x-request-id: authorize_no3ds_fail_payment_req" \
  -H "x-connector-request-reference-id: authorize_no3ds_fail_payment_ref" \
  -H "x-auth: ***MASKED***" \
  -H "x-api-key: ***MASKED***" \
  -H "x-key1: ***MASKED***" \
  -d @ localhost:8000 types.PaymentService/Authorize <<'JSON'
{
  "merchant_transaction_id": "mti_d85131628f4d4e6abc2fb1441de785dd",
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
        "value": "Mia Taylor"
      },
      "card_type": "credit"
    }
  },
  "capture_method": "AUTOMATIC",
  "customer": {
    "name": "Mia Johnson",
    "email": {
      "value": "morgan.8670@sandbox.example.com"
    },
    "id": "cust_db005cae5cd3431695792c15986c9700",
    "phone_number": "+917759963406",
    "connector_customer_id": "934839050"
  },
  "locale": "en-US",
  "address": {
    "shipping_address": {
      "first_name": {
        "value": "Mia"
      },
      "last_name": {
        "value": "Smith"
      },
      "line1": {
        "value": "3906 Oak Rd"
      },
      "line2": {
        "value": "4961 Lake St"
      },
      "line3": {
        "value": "696 Lake St"
      },
      "city": {
        "value": "Seattle"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "89370"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "morgan.1435@sandbox.example.com"
      },
      "phone_number": {
        "value": "9556215597"
      },
      "phone_country_code": "+91"
    },
    "billing_address": {
      "first_name": {
        "value": "Emma"
      },
      "last_name": {
        "value": "Johnson"
      },
      "line1": {
        "value": "2266 Market Blvd"
      },
      "line2": {
        "value": "3943 Oak Rd"
      },
      "line3": {
        "value": "3253 Main Ave"
      },
      "city": {
        "value": "Seattle"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "36052"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "casey.2238@example.com"
      },
      "phone_number": {
        "value": "4843389571"
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
  "test_mode": true
}
JSON
```

</details>

<details>
<summary>Show gRPC Response (masked)</summary>

```text
Resolved method descriptor:
// Authorize a payment amount on a payment method. This reserves funds
// without capturing them, essential for verifying availability before finalizing.
rpc Authorize ( .types.PaymentServiceAuthorizeRequest ) returns ( .types.PaymentServiceAuthorizeResponse );

Request metadata to send:
x-api-key: ***MASKED***
x-auth: ***MASKED***
x-connector: authorizedotnet
x-connector-request-reference-id: authorize_no3ds_fail_payment_ref
x-key1: ***MASKED***
x-merchant-id: test_merchant
x-request-id: authorize_no3ds_fail_payment_req
x-tenant-id: default

Response headers received:
content-type: application/grpc
date: Thu, 12 Mar 2026 15:40:08 GMT
x-request-id: authorize_no3ds_fail_payment_req

Response contents:
{
  "merchantTransactionId": "120079432042",
  "connectorTransactionId": "120079432042",
  "status": "CHARGED",
  "statusCode": 200,
  "responseHeaders": {
    "access-control-allow-credentials": "true",
    "access-control-allow-headers": "x-requested-with,cache-control,content-type,origin,method,SOAPAction",
    "access-control-allow-methods": "PUT,OPTIONS,POST,GET",
    "access-control-allow-origin": "*",
    "cache-control": "no-cache, no-store, max-age=0",
    "content-length": "654",
    "content-type": "application/json; charset=utf-8",
    "date": "Thu, 12 Mar 2026 15:40:07 GMT",
    "expires": "-1",
    "pragma": "no-cache",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-cnection": "close",
    "x-download-options": "noopen",
    "x-opnet-transaction-trace": "6275c255-1f58-458f-b516-e5c061e8590b-12436-10989150"
  },
  "networkTransactionId": "JRWP1YJVSLBSSTQRBWAZVJO",
  "state": {
    "connectorCustomerId": "934839050"
  },
  "rawConnectorResponse": {
    "value": "{\"transactionResponse\":{\"responseCode\":\"1\",\"authCode\":\"J8TWNT\",\"avsResultCode\":\"Y\",\"cvvResultCode\":\"P\",\"cavvResultCode\":\"2\",\"transId\":\"120079432042\",\"refTransID\":\"\",\"transHash\":\"\",\"testRequest\":\"0\",\"accountNumber\":\"XXXX0002\",\"accountType\":\"Visa\",\"messages\":[{\"code\":\"1\",\"description\":\"This transaction has been approved.\"}],\"transHashSha2\":\"4A53AFFF7E831231AD4CA4395A9B96047C81D56EA47E0DAE5DFA8EEAE7CD4D2BA686B1C5C867D262B10FDE62D2A6086CD7773FAB7D6F157C5A2B79FCB9F63F1D\",\"SupplementalDataQualificationIndicator\":0,\"networkTransId\":\"JRWP1YJVSLBSSTQRBWAZVJO\"},\"refId\":\"\",\"messages\":{\"resultCode\":\"Ok\",\"message\":[{\"code\":\"I00001\",\"text\":\"Successful.\"}]}}"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://apitest.authorize.net/xml/v1/request.api\",\"method\":\"POST\",\"headers\":{\"Content-Type\":\"application/json\",\"via\":\"HyperSwitch\"},\"body\":{\"createTransactionRequest\":{\"merchantAuthentication\":{\"name\":\"9ARWr5wz49D3\",\"transactionKey\":\"3d9SHV2699mgmHre\"},\"refId\":null,\"transactionRequest\":{\"transactionType\":\"authCaptureTransaction\",\"amount\":60.0,\"currencyCode\":\"USD\",\"payment\":{\"creditCard\":{\"cardNumber\":\"4000000000000002\",\"expirationDate\":\"2035-01\",\"cardCode\":\"123\"}},\"order\":{\"invoiceNumber\":\"3oLFWtuYXMPuOKoKTQgn\",\"description\":\"mti_d85131628f4d4e6abc2fb1441de785dd\"},\"customer\":{\"id\":\"934839050\",\"email\":\"morgan.8670@sandbox.example.com\"},\"billTo\":{\"firstName\":\"Emma\",\"lastName\":\"Johnson\",\"address\":\"2266 Market Blvd 3943 Oak Rd 3253 Main Ave\",\"city\":\"Seattle\",\"state\":\"CA\",\"zip\":\"36052\",\"country\":\"US\"}}}}}"
  },
  "connectorResponse": {
    "additionalPaymentMethodData": {
      "card": {
        "paymentChecks": "eyJhdnNfcmVzdWx0X2NvZGUiOiJZIiwiZGVzY3JpcHRpb24iOiJUaGUgc3RyZWV0IGFkZHJlc3MgYW5kIHBvc3RhbCBjb2RlIG1hdGNoZWQuIn0="
      }
    }
  },
  "connectorFeatureData": {
    "value": "{\"creditCard\":{\"cardNumber\":\"XXXX0002\",\"expirationDate\":\"XXXX\"}}"
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
  "merchant_transaction_id": "mti_d85131628f4d4e6abc2fb1441de785dd",
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
        "value": "01"
      },
      "card_exp_year": {
        "value": "35"
      },
      "card_cvc": "***MASKED***",
      "card_holder_name": {
        "value": "Mia Taylor"
      },
      "card_type": "credit"
    }
  },
  "capture_method": "AUTOMATIC",
  "customer": {
    "name": "Mia Johnson",
    "email": {
      "value": "morgan.8670@sandbox.example.com"
    },
    "id": "cust_db005cae5cd3431695792c15986c9700",
    "phone_number": "+917759963406",
    "connector_customer_id": "934839050"
  },
  "locale": "en-US",
  "address": {
    "shipping_address": {
      "first_name": {
        "value": "Mia"
      },
      "last_name": {
        "value": "Smith"
      },
      "line1": {
        "value": "3906 Oak Rd"
      },
      "line2": {
        "value": "4961 Lake St"
      },
      "line3": {
        "value": "696 Lake St"
      },
      "city": {
        "value": "Seattle"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "89370"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "morgan.1435@sandbox.example.com"
      },
      "phone_number": {
        "value": "9556215597"
      },
      "phone_country_code": "+91"
    },
    "billing_address": {
      "first_name": {
        "value": "Emma"
      },
      "last_name": {
        "value": "Johnson"
      },
      "line1": {
        "value": "2266 Market Blvd"
      },
      "line2": {
        "value": "3943 Oak Rd"
      },
      "line3": {
        "value": "3253 Main Ave"
      },
      "city": {
        "value": "Seattle"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "36052"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "casey.2238@example.com"
      },
      "phone_number": {
        "value": "4843389571"
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
  "test_mode": true
}
```

</details>

<details>
<summary>Show Response Body</summary>

```json
{
  "merchantTransactionId": "120079432042",
  "connectorTransactionId": "120079432042",
  "status": "CHARGED",
  "statusCode": 200,
  "responseHeaders": {
    "access-control-allow-credentials": "true",
    "access-control-allow-headers": "x-requested-with,cache-control,content-type,origin,method,SOAPAction",
    "access-control-allow-methods": "PUT,OPTIONS,POST,GET",
    "access-control-allow-origin": "*",
    "cache-control": "no-cache, no-store, max-age=0",
    "content-length": "654",
    "content-type": "application/json; charset=utf-8",
    "date": "Thu, 12 Mar 2026 15:40:07 GMT",
    "expires": "-1",
    "pragma": "no-cache",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-cnection": "close",
    "x-download-options": "noopen",
    "x-opnet-transaction-trace": "6275c255-1f58-458f-b516-e5c061e8590b-12436-10989150"
  },
  "networkTransactionId": "JRWP1YJVSLBSSTQRBWAZVJO",
  "state": {
    "connectorCustomerId": "934839050"
  },
  "rawConnectorResponse": {
    "value": "{\"transactionResponse\":{\"responseCode\":\"1\",\"authCode\":\"J8TWNT\",\"avsResultCode\":\"Y\",\"cvvResultCode\":\"P\",\"cavvResultCode\":\"2\",\"transId\":\"120079432042\",\"refTransID\":\"\",\"transHash\":\"\",\"testRequest\":\"0\",\"accountNumber\":\"XXXX0002\",\"accountType\":\"Visa\",\"messages\":[{\"code\":\"1\",\"description\":\"This transaction has been approved.\"}],\"transHashSha2\":\"4A53AFFF7E831231AD4CA4395A9B96047C81D56EA47E0DAE5DFA8EEAE7CD4D2BA686B1C5C867D262B10FDE62D2A6086CD7773FAB7D6F157C5A2B79FCB9F63F1D\",\"SupplementalDataQualificationIndicator\":0,\"networkTransId\":\"JRWP1YJVSLBSSTQRBWAZVJO\"},\"refId\":\"\",\"messages\":{\"resultCode\":\"Ok\",\"message\":[{\"code\":\"I00001\",\"text\":\"Successful.\"}]}}"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://apitest.authorize.net/xml/v1/request.api\",\"method\":\"POST\",\"headers\":{\"Content-Type\":\"application/json\",\"via\":\"HyperSwitch\"},\"body\":{\"createTransactionRequest\":{\"merchantAuthentication\":{\"name\":\"9ARWr5wz49D3\",\"transactionKey\":\"3d9SHV2699mgmHre\"},\"refId\":null,\"transactionRequest\":{\"transactionType\":\"authCaptureTransaction\",\"amount\":60.0,\"currencyCode\":\"USD\",\"payment\":{\"creditCard\":{\"cardNumber\":\"4000000000000002\",\"expirationDate\":\"2035-01\",\"cardCode\":\"123\"}},\"order\":{\"invoiceNumber\":\"3oLFWtuYXMPuOKoKTQgn\",\"description\":\"mti_d85131628f4d4e6abc2fb1441de785dd\"},\"customer\":{\"id\":\"934839050\",\"email\":\"morgan.8670@sandbox.example.com\"},\"billTo\":{\"firstName\":\"Emma\",\"lastName\":\"Johnson\",\"address\":\"2266 Market Blvd 3943 Oak Rd 3253 Main Ave\",\"city\":\"Seattle\",\"state\":\"CA\",\"zip\":\"36052\",\"country\":\"US\"}}}}}"
  },
  "connectorResponse": {
    "additionalPaymentMethodData": {
      "card": {
        "paymentChecks": "eyJhdnNfcmVzdWx0X2NvZGUiOiJZIiwiZGVzY3JpcHRpb24iOiJUaGUgc3RyZWV0IGFkZHJlc3MgYW5kIHBvc3RhbCBjb2RlIG1hdGNoZWQuIn0="
      }
    }
  },
  "connectorFeatureData": {
    "value": "{\"creditCard\":{\"cardNumber\":\"XXXX0002\",\"expirationDate\":\"XXXX\"}}"
  }
}
```

</details>


---

<a id="connector-paypal"></a>
## Connector `paypal` — `FAIL`


**Error**

```text
assertion failed for field 'error': expected field to exist
```

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
  "expiresInSeconds": "30544",
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
<summary>Show gRPC Response (masked)</summary>

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

<details>
<summary>Show Request Body</summary>

```json
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
      "card_number": "***MASKED***",
      "card_exp_month": {
        "value": "01"
      },
      "card_exp_year": {
        "value": "35"
      },
      "card_cvc": "***MASKED***",
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
    "access_token": "***MASKED***"
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
```

</details>

<details>
<summary>Show Response Body</summary>

```json
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
    "accessToken": "***MASKED***"
  },
  "rawConnectorResponse": {
    "value": "{\"id\":\"44740332CP372645W\",\"intent\":\"CAPTURE\",\"status\":\"COMPLETED\",\"payment_source\":{\"card\":{\"name\":\"Noah Johnson\",\"last_digits\":\"0002\",\"expiry\":\"2035-01\",\"brand\":\"VISA\",\"available_networks\":[\"VISA\"],\"type\":\"CREDIT\",\"bin_details\":{\"bin\":\"40000000000\",\"issuing_bank\":\"CARDINAL_TESTING_VISA\",\"bin_country_code\":\"IT\",\"products\":[\"CORPORATE\"]}}},\"purchase_units\":[{\"reference_id\":\"mti_4e70e565b8de4b4d8d710a9ba283d52f\",\"amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\",\"breakdown\":{\"item_total\":{\"currency_code\":\"USD\",\"value\":\"60.00\"},\"shipping\":{\"currency_code\":\"USD\",\"value\":\"0.00\"},\"handling\":{\"currency_code\":\"USD\",\"value\":\"0.00\"},\"tax_total\":{\"currency_code\":\"USD\",\"value\":\"0.00\"},\"insurance\":{\"currency_code\":\"USD\",\"value\":\"0.00\"},\"shipping_discount\":{\"currency_code\":\"USD\",\"value\":\"0.00\"}}},\"payee\":{\"email_address\":\"sb-itwmi27136406@business.example.com\",\"merchant_id\":\"DUM69V9DDNYEJ\"},\"description\":\"Payment for invoice mti_4e70e565b8de4b4d8d710a9ba283d52f\",\"invoice_id\":\"mti_4e70e565b8de4b4d8d710a9ba283d52f\",\"soft_descriptor\":\"TEST STORE\",\"items\":[{\"name\":\"Payment for invoice mti_4e70e565b8de4b4d8d710a9ba283d52f\",\"unit_amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\"},\"tax\":{\"currency_code\":\"USD\",\"value\":\"0.00\"},\"quantity\":\"1\"}],\"shipping\":{\"name\":{\"full_name\":\"Ethan\"},\"address\":{\"address_line_1\":\"1907 Oak Blvd\",\"admin_area_2\":\"San Francisco\",\"postal_code\":\"11400\",\"country_code\":\"US\"}},\"payments\":{\"captures\":[{\"id\":\"7G951242H1237245J\",\"status\":\"COMPLETED\",\"amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\"},\"final_capture\":true,\"seller_protection\":{\"status\":\"NOT_ELIGIBLE\"},\"seller_receivable_breakdown\":{\"gross_amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\"},\"net_amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\"}},\"invoice_id\":\"mti_4e70e565b8de4b4d8d710a9ba283d52f\",\"links\":[{\"href\":\"https://api.sandbox.paypal.com/v2/payments/captures/7G951242H1237245J\",\"rel\":\"self\",\"method\":\"GET\"},{\"href\":\"https://api.sandbox.paypal.com/v2/payments/captures/7G951242H1237245J/refund\",\"rel\":\"refund\",\"method\":\"POST\"},{\"href\":\"https://api.sandbox.paypal.com/v2/checkout/orders/44740332CP372645W\",\"rel\":\"up\",\"method\":\"GET\"}],\"create_time\":\"2026-03-12T15:41:02Z\",\"update_time\":\"2026-03-12T15:41:02Z\",\"network_transaction_reference\":{\"id\":\"625879325622783\",\"network\":\"VISA\"},\"processor_response\":{\"avs_code\":\"A\",\"cvv_code\":\"M\",\"response_code\":\"0000\"}}]}}],\"create_time\":\"2026-03-12T15:41:02Z\",\"update_time\":\"2026-03-12T15:41:02Z\",\"links\":[{\"href\":\"https://api.sandbox.paypal.com/v2/checkout/orders/44740332CP372645W\",\"rel\":\"self\",\"method\":\"GET\"}]}"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://api-m.sandbox.paypal.com/v2/checkout/orders\",\"method\":\"POST\",\"headers\":{\"Content-Type\":\"application/json\",\"Prefer\":\"return=representation\",\"via\":\"HyperSwitch\",\"PayPal-Request-Id\":\"mti_4e70e565b8de4b4d8d710a9ba283d52f\",\"PayPal-Partner-Attribution-Id\":\"HyperSwitchlegacy_Ecom\",\"Authorization\":\"Bearer ***MASKED***\"},\"body\":{\"intent\":\"CAPTURE\",\"purchase_units\":[{\"reference_id\":\"mti_4e70e565b8de4b4d8d710a9ba283d52f\",\"invoice_id\":\"mti_4e70e565b8de4b4d8d710a9ba283d52f\",\"custom_id\":null,\"amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\",\"breakdown\":{\"item_total\":{\"currency_code\":\"USD\",\"value\":\"60.00\"},\"tax_total\":null,\"shipping\":{\"currency_code\":\"USD\",\"value\":\"0.00\"}}},\"shipping\":{\"address\":{\"address_line_1\":\"1907 Oak Blvd\",\"postal_code\":\"11400\",\"country_code\":\"US\",\"admin_area_2\":\"San Francisco\"},\"name\":{\"full_name\":\"Ethan\"}},\"items\":[{\"name\":\"Payment for invoice mti_4e70e565b8de4b4d8d710a9ba283d52f\",\"quantity\":1,\"unit_amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\"},\"tax\":null}]}],\"payment_source\":{\"card\":{\"billing_address\":{\"address_line_1\":\"4763 Pine St\",\"postal_code\":\"98430\",\"country_code\":\"US\",\"admin_area_2\":\"New York\"},\"expiry\":\"2035-01\",\"name\":\"Noah Johnson\",\"number\":\"4000000000000002\",\"security_code\":\"123\",\"attributes\":{\"vault\":null,\"verification\":null}}}}}"
  },
  "mandateReference": {
    "connectorMandateId": {}
  },
  "connectorFeatureData": {
    "value": "{\"authorize_id\":null,\"capture_id\":\"7G951242H1237245J\",\"incremental_authorization_id\":null,\"psync_flow\":\"CAPTURE\",\"next_action\":null,\"order_id\":null}"
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
  "merchant_customer_id": "mcui_d92522a041a5443b99cb65df6418603d",
  "customer_name": "Liam Taylor",
  "email": {
    "value": "jordan.1845@sandbox.example.com"
  },
  "phone_number": "+913762400819",
  "address": {
    "shipping_address": {
      "first_name": {
        "value": "Ethan"
      },
      "last_name": {
        "value": "Johnson"
      },
      "line1": {
        "value": "8628 Lake Dr"
      },
      "line2": {
        "value": "63 Lake St"
      },
      "line3": {
        "value": "501 Oak Ln"
      },
      "city": {
        "value": "Austin"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "95996"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "jordan.5450@testmail.io"
      },
      "phone_number": {
        "value": "1001378882"
      },
      "phone_country_code": "+91"
    },
    "billing_address": {
      "first_name": {
        "value": "Emma"
      },
      "last_name": {
        "value": "Miller"
      },
      "line1": {
        "value": "7297 Market St"
      },
      "line2": {
        "value": "2736 Main Dr"
      },
      "line3": {
        "value": "3134 Sunset Rd"
      },
      "city": {
        "value": "Chicago"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "83242"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "casey.3657@sandbox.example.com"
      },
      "phone_number": {
        "value": "1001673800"
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
date: Thu, 12 Mar 2026 15:42:34 GMT
x-request-id: create_customer_create_customer_req

Response contents:
{
  "merchantCustomerId": "cus_U8SIyZsBbJaaAz",
  "connectorCustomerId": "cus_U8SIyZsBbJaaAz",
  "statusCode": 200,
  "responseHeaders": {
    "access-control-allow-credentials": "true",
    "access-control-allow-methods": "GET, HEAD, PUT, PATCH, POST, DELETE",
    "access-control-allow-origin": "*",
    "access-control-expose-headers": "Request-Id, Stripe-Manage-Version, Stripe-Should-Retry, X-Stripe-External-Auth-Required, X-Stripe-Privileged-Session-Required",
    "access-control-max-age": "300",
    "cache-control": "no-cache, no-store",
    "connection": "keep-alive",
    "content-length": "680",
    "content-security-policy": "base-uri 'none'; default-src 'none'; form-action 'none'; frame-ancestors 'none'; img-src 'self'; script-src 'self' 'report-sample'; style-src 'self'; worker-src 'none'; upgrade-insecure-requests; report-uri https://q.stripe.com/csp-violation?q=XbpkE0Obtc-D-_OVcHByv3HX2Cz2ZXWthan_OSmhaX_cdx20p33NXUJkyzusgJOGoDWC714Lefdz6v3w",
    "content-type": "application/json",
    "date": "Thu, 12 Mar 2026 15:42:34 GMT",
    "idempotency-key": "a13ca5a4-f8ac-4732-9f6f-bd3996f61df4",
    "original-request": "req_IuNPjC6h0JR6qe",
    "request-id": "req_IuNPjC6h0JR6qe",
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
  "merchant_customer_id": "mcui_d92522a041a5443b99cb65df6418603d",
  "customer_name": "Liam Taylor",
  "email": {
    "value": "jordan.1845@sandbox.example.com"
  },
  "phone_number": "+913762400819",
  "address": {
    "shipping_address": {
      "first_name": {
        "value": "Ethan"
      },
      "last_name": {
        "value": "Johnson"
      },
      "line1": {
        "value": "8628 Lake Dr"
      },
      "line2": {
        "value": "63 Lake St"
      },
      "line3": {
        "value": "501 Oak Ln"
      },
      "city": {
        "value": "Austin"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "95996"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "jordan.5450@testmail.io"
      },
      "phone_number": {
        "value": "1001378882"
      },
      "phone_country_code": "+91"
    },
    "billing_address": {
      "first_name": {
        "value": "Emma"
      },
      "last_name": {
        "value": "Miller"
      },
      "line1": {
        "value": "7297 Market St"
      },
      "line2": {
        "value": "2736 Main Dr"
      },
      "line3": {
        "value": "3134 Sunset Rd"
      },
      "city": {
        "value": "Chicago"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "83242"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "casey.3657@sandbox.example.com"
      },
      "phone_number": {
        "value": "1001673800"
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
  "merchantCustomerId": "cus_U8SIyZsBbJaaAz",
  "connectorCustomerId": "cus_U8SIyZsBbJaaAz",
  "statusCode": 200,
  "responseHeaders": {
    "access-control-allow-credentials": "true",
    "access-control-allow-methods": "GET, HEAD, PUT, PATCH, POST, DELETE",
    "access-control-allow-origin": "*",
    "access-control-expose-headers": "Request-Id, Stripe-Manage-Version, Stripe-Should-Retry, X-Stripe-External-Auth-Required, X-Stripe-Privileged-Session-Required",
    "access-control-max-age": "300",
    "cache-control": "no-cache, no-store",
    "connection": "keep-alive",
    "content-length": "680",
    "content-security-policy": "base-uri 'none'; default-src 'none'; form-action 'none'; frame-ancestors 'none'; img-src 'self'; script-src 'self' 'report-sample'; style-src 'self'; worker-src 'none'; upgrade-insecure-requests; report-uri https://q.stripe.com/csp-violation?q=XbpkE0Obtc-D-_OVcHByv3HX2Cz2ZXWthan_OSmhaX_cdx20p33NXUJkyzusgJOGoDWC714Lefdz6v3w",
    "content-type": "application/json",
    "date": "Thu, 12 Mar 2026 15:42:34 GMT",
    "idempotency-key": "a13ca5a4-f8ac-4732-9f6f-bd3996f61df4",
    "original-request": "req_IuNPjC6h0JR6qe",
    "request-id": "req_IuNPjC6h0JR6qe",
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
  -H "x-request-id: authorize_no3ds_fail_payment_req" \
  -H "x-connector-request-reference-id: authorize_no3ds_fail_payment_ref" \
  -H "x-auth: ***MASKED***" \
  -H "x-api-key: ***MASKED***" \
  -d @ localhost:8000 types.PaymentService/Authorize <<'JSON'
{
  "merchant_transaction_id": "mti_209abdd925ce4f06b3d7eaca27e1cfc1",
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
        "value": "Ava Taylor"
      },
      "card_type": "credit"
    }
  },
  "capture_method": "AUTOMATIC",
  "customer": {
    "name": "Emma Smith",
    "email": {
      "value": "jordan.3074@example.com"
    },
    "id": "cust_020fe5a1ae5649088629258d99bac4f3",
    "phone_number": "+444300152810",
    "connector_customer_id": "cus_U8SIyZsBbJaaAz"
  },
  "locale": "en-US",
  "address": {
    "shipping_address": {
      "first_name": {
        "value": "Ethan"
      },
      "last_name": {
        "value": "Johnson"
      },
      "line1": {
        "value": "8628 Lake Dr"
      },
      "line2": {
        "value": "63 Lake St"
      },
      "line3": {
        "value": "501 Oak Ln"
      },
      "city": {
        "value": "Austin"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "95996"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "jordan.5450@testmail.io"
      },
      "phone_number": {
        "value": "1001378882"
      },
      "phone_country_code": "+91"
    },
    "billing_address": {
      "first_name": {
        "value": "Emma"
      },
      "last_name": {
        "value": "Miller"
      },
      "line1": {
        "value": "7297 Market St"
      },
      "line2": {
        "value": "2736 Main Dr"
      },
      "line3": {
        "value": "3134 Sunset Rd"
      },
      "city": {
        "value": "Chicago"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "83242"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "casey.3657@sandbox.example.com"
      },
      "phone_number": {
        "value": "1001673800"
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
  "test_mode": true
}
JSON
```

</details>

<details>
<summary>Show gRPC Response (masked)</summary>

```text
Resolved method descriptor:
// Authorize a payment amount on a payment method. This reserves funds
// without capturing them, essential for verifying availability before finalizing.
rpc Authorize ( .types.PaymentServiceAuthorizeRequest ) returns ( .types.PaymentServiceAuthorizeResponse );

Request metadata to send:
x-api-key: ***MASKED***
x-auth: ***MASKED***
x-connector: stripe
x-connector-request-reference-id: authorize_no3ds_fail_payment_ref
x-merchant-id: test_merchant
x-request-id: authorize_no3ds_fail_payment_req
x-tenant-id: default

Response headers received:
content-type: application/grpc
date: Thu, 12 Mar 2026 15:42:38 GMT
x-request-id: authorize_no3ds_fail_payment_req

Response contents:
{
  "merchantTransactionId": "pi_3TABNhD5R7gDAGff0WnEUvCQ",
  "connectorTransactionId": "pi_3TABNhD5R7gDAGff0WnEUvCQ",
  "error": {
    "issuerDetails": {
      "message": "generic_decline",
      "networkDetails": {
        "declineCode": "01",
        "errorMessage": "generic_decline"
      }
    },
    "connectorDetails": {
      "code": "card_declined",
      "message": "Your card was declined.",
      "reason": "message - Your card was declined., decline_code - generic_decline"
    }
  },
  "statusCode": 402,
  "responseHeaders": {
    "access-control-allow-credentials": "true",
    "access-control-allow-methods": "GET, HEAD, PUT, PATCH, POST, DELETE",
    "access-control-allow-origin": "*",
    "access-control-expose-headers": "Request-Id, Stripe-Manage-Version, Stripe-Should-Retry, X-Stripe-External-Auth-Required, X-Stripe-Privileged-Session-Required",
    "access-control-max-age": "300",
    "cache-control": "no-cache, no-store",
    "connection": "keep-alive",
    "content-length": "5908",
    "content-security-policy": "base-uri 'none'; default-src 'none'; form-action 'none'; frame-ancestors 'none'; img-src 'self'; script-src 'self' 'report-sample'; style-src 'self'; worker-src 'none'; upgrade-insecure-requests; report-uri https://q.stripe.com/csp-violation?q=XbpkE0Obtc-D-_OVcHByv3HX2Cz2ZXWthan_OSmhaX_cdx20p33NXUJkyzusgJOGoDWC714Lefdz6v3w",
    "content-type": "application/json",
    "date": "Thu, 12 Mar 2026 15:42:38 GMT",
    "idempotency-key": "69b0925a-dc9e-46d8-be38-e19c92220170",
    "original-request": "req_9ovBJTrD0tr4Ew",
    "request-id": "req_9ovBJTrD0tr4Ew",
    "server": "nginx",
    "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
    "stripe-should-retry": "false",
    "stripe-version": "2022-11-15",
    "vary": "Origin",
    "x-stripe-priority-routing-enabled": "true",
    "x-stripe-routing-context-priority-tier": "api-testmode",
    "x-wc": "ABGHIJ"
  },
  "state": {
    "connectorCustomerId": "cus_U8SIyZsBbJaaAz"
  },
  "rawConnectorResponse": {
    "value": "{\n  \"error\": {\n    \"advice_code\": \"try_again_later\",\n    \"charge\": \"ch_3TABNhD5R7gDAGff0Lyw0yhv\",\n    \"code\": \"card_declined\",\n    \"decline_code\": \"generic_decline\",\n    \"doc_url\": \"https://stripe.com/docs/error-codes/card-declined\",\n    \"message\": \"Your card was declined.\",\n    \"network_decline_code\": \"01\",\n    \"payment_intent\": {\n      \"id\": \"pi_3TABNhD5R7gDAGff0WnEUvCQ\",\n      \"object\": \"payment_intent\",\n      \"amount\": 6000,\n      \"amount_capturable\": 0,\n      \"amount_details\": {\n        \"tip\": {}\n      },\n      \"amount_received\": 0,\n      \"application\": null,\n      \"application_fee_amount\": null,\n      \"automatic_payment_methods\": null,\n      \"canceled_at\": null,\n      \"cancellation_reason\": null,\n      \"capture_method\": \"automatic\",\n      \"client_secret\": \"pi_3TABNhD5R7gDAGff0WnEUvCQ_secret_pxFH8BNk90K3PQ8UVzDUUgpb4\",\n      \"confirmation_method\": \"automatic\",\n      \"created\": 1773330157,\n      \"currency\": \"usd\",\n      \"customer\": \"cus_U8SIyZsBbJaaAz\",\n      \"customer_account\": null,\n      \"description\": \"No3DS fail payment flow\",\n      \"excluded_payment_method_types\": null,\n      \"invoice\": null,\n      \"last_payment_error\": {\n        \"advice_code\": \"try_again_later\",\n        \"charge\": \"ch_3TABNhD5R7gDAGff0Lyw0yhv\",\n        \"code\": \"card_declined\",\n        \"decline_code\": \"generic_decline\",\n        \"doc_url\": \"https://stripe.com/docs/error-codes/card-declined\",\n        \"message\": \"Your card was declined.\",\n        \"network_decline_code\": \"01\",\n        \"payment_method\": {\n          \"id\": \"pm_1TABNhD5R7gDAGffQfNBYZPL\",\n          \"object\": \"payment_method\",\n          \"allow_redisplay\": \"unspecified\",\n          \"billing_details\": {\n            \"address\": {\n              \"city\": \"Chicago\",\n              \"country\": \"US\",\n              \"line1\": \"7297 Market St\",\n              \"line2\": \"2736 Main Dr\",\n              \"postal_code\": \"83242\",\n              \"state\": \"CA\"\n            },\n            \"email\": \"casey.3657@sandbox.example.com\",\n            \"name\": \"Emma Miller\",\n            \"phone\": \"1001673800\",\n            \"tax_id\": null\n          },\n          \"card\": {\n            \"brand\": \"visa\",\n            \"checks\": {\n              \"address_line1_check\": \"pass\",\n              \"address_postal_code_check\": \"pass\",\n              \"cvc_check\": \"pass\"\n            },\n            \"country\": \"US\",\n            \"display_brand\": \"visa\",\n            \"exp_month\": 1,\n            \"exp_year\": 2035,\n            \"fingerprint\": \"Xxnq9tzcR7ZXkksL\",\n            \"funding\": \"credit\",\n            \"generated_from\": null,\n            \"last4\": \"0002\",\n            \"networks\": {\n              \"available\": [\n                \"visa\"\n              ],\n              \"preferred\": null\n            },\n            \"regulated_status\": \"unregulated\",\n            \"three_d_secure_usage\": {\n              \"supported\": true\n            },\n            \"wallet\": null\n          },\n          \"created\": 1773330157,\n          \"customer\": null,\n          \"customer_account\": null,\n          \"livemode\": false,\n          \"metadata\": {},\n          \"type\": \"card\"\n        },\n        \"type\": \"card_error\"\n      },\n      \"latest_charge\": \"ch_3TABNhD5R7gDAGff0Lyw0yhv\",\n      \"livemode\": false,\n      \"metadata\": {\n        \"order_id\": \"mti_209abdd925ce4f06b3d7eaca27e1cfc1\"\n      },\n      \"next_action\": null,\n      \"on_behalf_of\": null,\n      \"payment_method\": null,\n      \"payment_method_configuration_details\": null,\n      \"payment_method_options\": {\n        \"card\": {\n          \"installments\": null,\n          \"mandate_options\": null,\n          \"network\": null,\n          \"request_three_d_secure\": \"automatic\"\n        }\n      },\n      \"payment_method_types\": [\n        \"card\"\n      ],\n      \"processing\": null,\n      \"receipt_email\": null,\n      \"review\": null,\n      \"setup_future_usage\": \"on_session\",\n      \"shipping\": {\n        \"address\": {\n          \"city\": \"Austin\",\n          \"country\": \"US\",\n          \"line1\": \"8628 Lake Dr\",\n          \"line2\": \"63 Lake St\",\n          \"postal_code\": \"95996\",\n          \"state\": \"CA\"\n        },\n        \"carrier\": null,\n        \"name\": \"Ethan Johnson\",\n        \"phone\": \"+911001378882\",\n        \"tracking_number\": null\n      },\n      \"source\": null,\n      \"statement_descriptor\": null,\n      \"statement_descriptor_suffix\": null,\n      \"status\": \"requires_payment_method\",\n      \"transfer_data\": null,\n      \"transfer_group\": null\n    },\n    \"payment_method\": {\n      \"id\": \"pm_1TABNhD5R7gDAGffQfNBYZPL\",\n      \"object\": \"payment_method\",\n      \"allow_redisplay\": \"unspecified\",\n      \"billing_details\": {\n        \"address\": {\n          \"city\": \"Chicago\",\n          \"country\": \"US\",\n          \"line1\": \"7297 Market St\",\n          \"line2\": \"2736 Main Dr\",\n          \"postal_code\": \"83242\",\n          \"state\": \"CA\"\n        },\n        \"email\": \"casey.3657@sandbox.example.com\",\n        \"name\": \"Emma Miller\",\n        \"phone\": \"1001673800\",\n        \"tax_id\": null\n      },\n      \"card\": {\n        \"brand\": \"visa\",\n        \"checks\": {\n          \"address_line1_check\": \"pass\",\n          \"address_postal_code_check\": \"pass\",\n          \"cvc_check\": \"pass\"\n        },\n        \"country\": \"US\",\n        \"display_brand\": \"visa\",\n        \"exp_month\": 1,\n        \"exp_year\": 2035,\n        \"fingerprint\": \"Xxnq9tzcR7ZXkksL\",\n        \"funding\": \"credit\",\n        \"generated_from\": null,\n        \"last4\": \"0002\",\n        \"networks\": {\n          \"available\": [\n            \"visa\"\n          ],\n          \"preferred\": null\n        },\n        \"regulated_status\": \"unregulated\",\n        \"three_d_secure_usage\": {\n          \"supported\": true\n        },\n        \"wallet\": null\n      },\n      \"created\": 1773330157,\n      \"customer\": null,\n      \"customer_account\": null,\n      \"livemode\": false,\n      \"metadata\": {},\n      \"type\": \"card\"\n    },\n    \"request_log_url\": \"https://dashboard.stripe.com/acct_1M7fTaD5R7gDAGff/test/workbench/logs?object=req_9ovBJTrD0tr4Ew\",\n    \"type\": \"card_error\"\n  }\n}\n"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://api.stripe.com/v1/payment_intents\",\"method\":\"POST\",\"headers\":{\"Authorization\":\"Bearer ***MASKED***",\"via\":\"HyperSwitch\",\"stripe-version\":\"2022-11-15\",\"Content-Type\":\"application/x-www-form-urlencoded\"},\"body\":\"amount=6000\u0026currency=USD\u0026metadata%5Border_id%5D=mti_209abdd925ce4f06b3d7eaca27e1cfc1\u0026return_url=https%3A%2F%2Fexample.com%2Fpayment%2Freturn\u0026confirm=true\u0026customer=cus_U8SIyZsBbJaaAz\u0026description=No3DS+fail+payment+flow\u0026shipping%5Baddress%5D%5Bcity%5D=Austin\u0026shipping%5Baddress%5D%5Bcountry%5D=US\u0026shipping%5Baddress%5D%5Bline1%5D=8628+Lake+Dr\u0026shipping%5Baddress%5D%5Bline2%5D=63+Lake+St\u0026shipping%5Baddress%5D%5Bpostal_code%5D=95996\u0026shipping%5Baddress%5D%5Bstate%5D=CA\u0026shipping%5Bname%5D=Ethan+Johnson\u0026shipping%5Bphone%5D=%2B911001378882\u0026payment_method_data%5Bbilling_details%5D%5Bemail%5D=casey.3657%40sandbox.example.com\u0026payment_method_data%5Bbilling_details%5D%5Baddress%5D%5Bcountry%5D=US\u0026payment_method_data%5Bbilling_details%5D%5Bname%5D=Emma+Miller\u0026payment_method_data%5Bbilling_details%5D%5Baddress%5D%5Bcity%5D=Chicago\u0026payment_method_data%5Bbilling_details%5D%5Baddress%5D%5Bline1%5D=7297+Market+St\u0026payment_method_data%5Bbilling_details%5D%5Baddress%5D%5Bline2%5D=2736+Main+Dr\u0026payment_method_data%5Bbilling_details%5D%5Baddress%5D%5Bpostal_code%5D=83242\u0026payment_method_data%5Bbilling_details%5D%5Baddress%5D%5Bstate%5D=CA\u0026payment_method_data%5Bbilling_details%5D%5Bphone%5D=1001673800\u0026payment_method_data%5Btype%5D=card\u0026payment_method_data%5Bcard%5D%5Bnumber%5D=4000000000000002\u0026payment_method_data%5Bcard%5D%5Bexp_month%5D=01\u0026payment_method_data%5Bcard%5D%5Bexp_year%5D=35\u0026payment_method_data%5Bcard%5D%5Bcvc%5D=123\u0026payment_method_options%5Bcard%5D%5Brequest_three_d_secure%5D=automatic\u0026capture_method=automatic\u0026setup_future_usage=on_session\u0026off_session=false\u0026payment_method_types%5B0%5D=card\u0026expand%5B0%5D=latest_charge\"}"
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
  "merchant_transaction_id": "mti_209abdd925ce4f06b3d7eaca27e1cfc1",
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
        "value": "01"
      },
      "card_exp_year": {
        "value": "35"
      },
      "card_cvc": "***MASKED***",
      "card_holder_name": {
        "value": "Ava Taylor"
      },
      "card_type": "credit"
    }
  },
  "capture_method": "AUTOMATIC",
  "customer": {
    "name": "Emma Smith",
    "email": {
      "value": "jordan.3074@example.com"
    },
    "id": "cust_020fe5a1ae5649088629258d99bac4f3",
    "phone_number": "+444300152810",
    "connector_customer_id": "cus_U8SIyZsBbJaaAz"
  },
  "locale": "en-US",
  "address": {
    "shipping_address": {
      "first_name": {
        "value": "Ethan"
      },
      "last_name": {
        "value": "Johnson"
      },
      "line1": {
        "value": "8628 Lake Dr"
      },
      "line2": {
        "value": "63 Lake St"
      },
      "line3": {
        "value": "501 Oak Ln"
      },
      "city": {
        "value": "Austin"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "95996"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "jordan.5450@testmail.io"
      },
      "phone_number": {
        "value": "1001378882"
      },
      "phone_country_code": "+91"
    },
    "billing_address": {
      "first_name": {
        "value": "Emma"
      },
      "last_name": {
        "value": "Miller"
      },
      "line1": {
        "value": "7297 Market St"
      },
      "line2": {
        "value": "2736 Main Dr"
      },
      "line3": {
        "value": "3134 Sunset Rd"
      },
      "city": {
        "value": "Chicago"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "83242"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "casey.3657@sandbox.example.com"
      },
      "phone_number": {
        "value": "1001673800"
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
  "test_mode": true
}
```

</details>

<details>
<summary>Show Response Body</summary>

```json
{
  "merchantTransactionId": "pi_3TABNhD5R7gDAGff0WnEUvCQ",
  "connectorTransactionId": "pi_3TABNhD5R7gDAGff0WnEUvCQ",
  "error": {
    "issuerDetails": {
      "message": "generic_decline",
      "networkDetails": {
        "declineCode": "01",
        "errorMessage": "generic_decline"
      }
    },
    "connectorDetails": {
      "code": "card_declined",
      "message": "Your card was declined.",
      "reason": "message - Your card was declined., decline_code - generic_decline"
    }
  },
  "statusCode": 402,
  "responseHeaders": {
    "access-control-allow-credentials": "true",
    "access-control-allow-methods": "GET, HEAD, PUT, PATCH, POST, DELETE",
    "access-control-allow-origin": "*",
    "access-control-expose-headers": "Request-Id, Stripe-Manage-Version, Stripe-Should-Retry, X-Stripe-External-Auth-Required, X-Stripe-Privileged-Session-Required",
    "access-control-max-age": "300",
    "cache-control": "no-cache, no-store",
    "connection": "keep-alive",
    "content-length": "5908",
    "content-security-policy": "base-uri 'none'; default-src 'none'; form-action 'none'; frame-ancestors 'none'; img-src 'self'; script-src 'self' 'report-sample'; style-src 'self'; worker-src 'none'; upgrade-insecure-requests; report-uri https://q.stripe.com/csp-violation?q=XbpkE0Obtc-D-_OVcHByv3HX2Cz2ZXWthan_OSmhaX_cdx20p33NXUJkyzusgJOGoDWC714Lefdz6v3w",
    "content-type": "application/json",
    "date": "Thu, 12 Mar 2026 15:42:38 GMT",
    "idempotency-key": "69b0925a-dc9e-46d8-be38-e19c92220170",
    "original-request": "req_9ovBJTrD0tr4Ew",
    "request-id": "req_9ovBJTrD0tr4Ew",
    "server": "nginx",
    "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
    "stripe-should-retry": "false",
    "stripe-version": "2022-11-15",
    "vary": "Origin",
    "x-stripe-priority-routing-enabled": "true",
    "x-stripe-routing-context-priority-tier": "api-testmode",
    "x-wc": "ABGHIJ"
  },
  "state": {
    "connectorCustomerId": "cus_U8SIyZsBbJaaAz"
  },
  "rawConnectorResponse": {
    "value": "{\n  \"error\": {\n    \"advice_code\": \"try_again_later\",\n    \"charge\": \"ch_3TABNhD5R7gDAGff0Lyw0yhv\",\n    \"code\": \"card_declined\",\n    \"decline_code\": \"generic_decline\",\n    \"doc_url\": \"https://stripe.com/docs/error-codes/card-declined\",\n    \"message\": \"Your card was declined.\",\n    \"network_decline_code\": \"01\",\n    \"payment_intent\": {\n      \"id\": \"pi_3TABNhD5R7gDAGff0WnEUvCQ\",\n      \"object\": \"payment_intent\",\n      \"amount\": 6000,\n      \"amount_capturable\": 0,\n      \"amount_details\": {\n        \"tip\": {}\n      },\n      \"amount_received\": 0,\n      \"application\": null,\n      \"application_fee_amount\": null,\n      \"automatic_payment_methods\": null,\n      \"canceled_at\": null,\n      \"cancellation_reason\": null,\n      \"capture_method\": \"automatic\",\n      \"client_secret\": ***MASKED***\"\n      \"confirmation_method\": \"automatic\",\n      \"created\": 1773330157,\n      \"currency\": \"usd\",\n      \"customer\": \"cus_U8SIyZsBbJaaAz\",\n      \"customer_account\": null,\n      \"description\": \"No3DS fail payment flow\",\n      \"excluded_payment_method_types\": null,\n      \"invoice\": null,\n      \"last_payment_error\": {\n        \"advice_code\": \"try_again_later\",\n        \"charge\": \"ch_3TABNhD5R7gDAGff0Lyw0yhv\",\n        \"code\": \"card_declined\",\n        \"decline_code\": \"generic_decline\",\n        \"doc_url\": \"https://stripe.com/docs/error-codes/card-declined\",\n        \"message\": \"Your card was declined.\",\n        \"network_decline_code\": \"01\",\n        \"payment_method\": {\n          \"id\": \"pm_1TABNhD5R7gDAGffQfNBYZPL\",\n          \"object\": \"payment_method\",\n          \"allow_redisplay\": \"unspecified\",\n          \"billing_details\": {\n            \"address\": {\n              \"city\": \"Chicago\",\n              \"country\": \"US\",\n              \"line1\": \"7297 Market St\",\n              \"line2\": \"2736 Main Dr\",\n              \"postal_code\": \"83242\",\n              \"state\": \"CA\"\n            },\n            \"email\": \"casey.3657@sandbox.example.com\",\n            \"name\": \"Emma Miller\",\n            \"phone\": \"1001673800\",\n            \"tax_id\": null\n          },\n          \"card\": {\n            \"brand\": \"visa\",\n            \"checks\": {\n              \"address_line1_check\": \"pass\",\n              \"address_postal_code_check\": \"pass\",\n              \"cvc_check\": ***MASKED***\"\n            },\n            \"country\": \"US\",\n            \"display_brand\": \"visa\",\n            \"exp_month\": ***MASKED***\n            \"exp_year\": ***MASKED***\n            \"fingerprint\": \"Xxnq9tzcR7ZXkksL\",\n            \"funding\": \"credit\",\n            \"generated_from\": null,\n            \"last4\": \"0002\",\n            \"networks\": {\n              \"available\": [\n                \"visa\"\n              ],\n              \"preferred\": null\n            },\n            \"regulated_status\": \"unregulated\",\n            \"three_d_secure_usage\": {\n              \"supported\": true\n            },\n            \"wallet\": null\n          },\n          \"created\": 1773330157,\n          \"customer\": null,\n          \"customer_account\": null,\n          \"livemode\": false,\n          \"metadata\": {},\n          \"type\": \"card\"\n        },\n        \"type\": \"card_error\"\n      },\n      \"latest_charge\": \"ch_3TABNhD5R7gDAGff0Lyw0yhv\",\n      \"livemode\": false,\n      \"metadata\": {\n        \"order_id\": \"mti_209abdd925ce4f06b3d7eaca27e1cfc1\"\n      },\n      \"next_action\": null,\n      \"on_behalf_of\": null,\n      \"payment_method\": null,\n      \"payment_method_configuration_details\": null,\n      \"payment_method_options\": {\n        \"card\": {\n          \"installments\": null,\n          \"mandate_options\": null,\n          \"network\": null,\n          \"request_three_d_secure\": \"automatic\"\n        }\n      },\n      \"payment_method_types\": [\n        \"card\"\n      ],\n      \"processing\": null,\n      \"receipt_email\": null,\n      \"review\": null,\n      \"setup_future_usage\": \"on_session\",\n      \"shipping\": {\n        \"address\": {\n          \"city\": \"Austin\",\n          \"country\": \"US\",\n          \"line1\": \"8628 Lake Dr\",\n          \"line2\": \"63 Lake St\",\n          \"postal_code\": \"95996\",\n          \"state\": \"CA\"\n        },\n        \"carrier\": null,\n        \"name\": \"Ethan Johnson\",\n        \"phone\": \"+911001378882\",\n        \"tracking_number\": null\n      },\n      \"source\": null,\n      \"statement_descriptor\": null,\n      \"statement_descriptor_suffix\": null,\n      \"status\": \"requires_payment_method\",\n      \"transfer_data\": null,\n      \"transfer_group\": null\n    },\n    \"payment_method\": {\n      \"id\": \"pm_1TABNhD5R7gDAGffQfNBYZPL\",\n      \"object\": \"payment_method\",\n      \"allow_redisplay\": \"unspecified\",\n      \"billing_details\": {\n        \"address\": {\n          \"city\": \"Chicago\",\n          \"country\": \"US\",\n          \"line1\": \"7297 Market St\",\n          \"line2\": \"2736 Main Dr\",\n          \"postal_code\": \"83242\",\n          \"state\": \"CA\"\n        },\n        \"email\": \"casey.3657@sandbox.example.com\",\n        \"name\": \"Emma Miller\",\n        \"phone\": \"1001673800\",\n        \"tax_id\": null\n      },\n      \"card\": {\n        \"brand\": \"visa\",\n        \"checks\": {\n          \"address_line1_check\": \"pass\",\n          \"address_postal_code_check\": \"pass\",\n          \"cvc_check\": ***MASKED***\"\n        },\n        \"country\": \"US\",\n        \"display_brand\": \"visa\",\n        \"exp_month\": ***MASKED***\n        \"exp_year\": ***MASKED***\n        \"fingerprint\": \"Xxnq9tzcR7ZXkksL\",\n        \"funding\": \"credit\",\n        \"generated_from\": null,\n        \"last4\": \"0002\",\n        \"networks\": {\n          \"available\": [\n            \"visa\"\n          ],\n          \"preferred\": null\n        },\n        \"regulated_status\": \"unregulated\",\n        \"three_d_secure_usage\": {\n          \"supported\": true\n        },\n        \"wallet\": null\n      },\n      \"created\": 1773330157,\n      \"customer\": null,\n      \"customer_account\": null,\n      \"livemode\": false,\n      \"metadata\": {},\n      \"type\": \"card\"\n    },\n    \"request_log_url\": \"https://dashboard.stripe.com/acct_1M7fTaD5R7gDAGff/test/workbench/logs?object=req_9ovBJTrD0tr4Ew\",\n    \"type\": \"card_error\"\n  }\n}"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://api.stripe.com/v1/payment_intents\",\"method\":\"POST\",\"headers\":{\"Authorization\":\"Bearer ***MASKED***\",\"via\":\"HyperSwitch\",\"stripe-version\":\"2022-11-15\",\"Content-Type\":\"application/x-www-form-urlencoded\"},\"body\":\"amount=6000&currency=USD&metadata%5Border_id%5D=mti_209abdd925ce4f06b3d7eaca27e1cfc1&return_url=https%3A%2F%2Fexample.com%2Fpayment%2Freturn&confirm=true&customer=cus_U8SIyZsBbJaaAz&description=No3DS+fail+payment+flow&shipping%5Baddress%5D%5Bcity%5D=Austin&shipping%5Baddress%5D%5Bcountry%5D=US&shipping%5Baddress%5D%5Bline1%5D=8628+Lake+Dr&shipping%5Baddress%5D%5Bline2%5D=63+Lake+St&shipping%5Baddress%5D%5Bpostal_code%5D=95996&shipping%5Baddress%5D%5Bstate%5D=CA&shipping%5Bname%5D=Ethan+Johnson&shipping%5Bphone%5D=%2B911001378882&payment_method_data%5Bbilling_details%5D%5Bemail%5D=casey.3657%40sandbox.example.com&payment_method_data%5Bbilling_details%5D%5Baddress%5D%5Bcountry%5D=US&payment_method_data%5Bbilling_details%5D%5Bname%5D=Emma+Miller&payment_method_data%5Bbilling_details%5D%5Baddress%5D%5Bcity%5D=Chicago&payment_method_data%5Bbilling_details%5D%5Baddress%5D%5Bline1%5D=7297+Market+St&payment_method_data%5Bbilling_details%5D%5Baddress%5D%5Bline2%5D=2736+Main+Dr&payment_method_data%5Bbilling_details%5D%5Baddress%5D%5Bpostal_code%5D=83242&payment_method_data%5Bbilling_details%5D%5Baddress%5D%5Bstate%5D=CA&payment_method_data%5Bbilling_details%5D%5Bphone%5D=1001673800&payment_method_data%5Btype%5D=card&payment_method_data%5Bcard%5D%5Bnumber%5D=4000000000000002&payment_method_data%5Bcard%5D%5Bexp_month%5D=01&payment_method_data%5Bcard%5D%5Bexp_year%5D=35&payment_method_data%5Bcard%5D%5Bcvc%5D=123&payment_method_options%5Bcard%5D%5Brequest_three_d_secure%5D=automatic&capture_method=automatic&setup_future_usage=on_session&off_session=false&payment_method_types%5B0%5D=card&expand%5B0%5D=latest_charge\"}"
  }
}
```

</details>


[Back to Overview](../../test_overview.md)
