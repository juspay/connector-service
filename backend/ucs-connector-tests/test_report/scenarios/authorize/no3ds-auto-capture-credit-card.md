# Scenario `no3ds_auto_capture_credit_card`

- Suite: `authorize`
- Service: `PaymentService/Authorize`
- PM / PMT: `card` / `credit`

## Connector Summary

| Connector | Result | Prerequisites |
|:----------|:------:|:--------------|
| `authorizedotnet` | [PASS](./scenarios/authorize/no3ds-auto-capture-credit-card.md#connector-authorizedotnet) | `create_customer(create_customer)` (PASS) |
| `paypal` | [PASS](./scenarios/authorize/no3ds-auto-capture-credit-card.md#connector-paypal) | `create_access_token(create_access_token)` (PASS) |
| `stripe` | [PASS](./scenarios/authorize/no3ds-auto-capture-credit-card.md#connector-stripe) | `create_customer(create_customer)` (PASS) |

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
  -H "x-request-id: authorize_no3ds_auto_capture_credit_card_req" \
  -H "x-connector-request-reference-id: authorize_no3ds_auto_capture_credit_card_ref" \
  -H "x-auth: ***MASKED***" \
  -H "x-api-key: ***MASKED***" \
  -H "x-key1: ***MASKED***" \
  -d @ localhost:8000 types.PaymentService/Authorize <<'JSON'
{
  "merchant_transaction_id": "mti_162f9a3af73945128505d1cb4fab90c9",
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
        "value": "Liam Brown"
      },
      "card_type": "credit"
    }
  },
  "capture_method": "AUTOMATIC",
  "customer": {
    "name": "Liam Smith",
    "email": {
      "value": "alex.6993@sandbox.example.com"
    },
    "id": "cust_c9eb1f5ea5e143d9bdc39d3b7c8c5fa4",
    "phone_number": "+915590829126",
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
  "description": "No3DS auto capture card payment (credit)",
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
x-connector-request-reference-id: authorize_no3ds_auto_capture_credit_card_ref
x-key1: ***MASKED***
x-merchant-id: test_merchant
x-request-id: authorize_no3ds_auto_capture_credit_card_req
x-tenant-id: default

Response headers received:
content-type: application/grpc
date: Thu, 12 Mar 2026 15:40:06 GMT
x-request-id: authorize_no3ds_auto_capture_credit_card_req

Response contents:
{
  "merchantTransactionId": "120079432040",
  "connectorTransactionId": "120079432040",
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
    "date": "Thu, 12 Mar 2026 15:40:05 GMT",
    "expires": "-1",
    "pragma": "no-cache",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-cnection": "close",
    "x-download-options": "noopen",
    "x-opnet-transaction-trace": "39598f69-930a-4eea-a65b-19a85a5612aa-17512-11760791"
  },
  "networkTransactionId": "7QSE18JROJ2A4U6BMDUDPM7",
  "state": {
    "connectorCustomerId": "934839050"
  },
  "rawConnectorResponse": {
    "value": "{\"transactionResponse\":{\"responseCode\":\"1\",\"authCode\":\"ZUESHX\",\"avsResultCode\":\"Y\",\"cvvResultCode\":\"P\",\"cavvResultCode\":\"2\",\"transId\":\"120079432040\",\"refTransID\":\"\",\"transHash\":\"\",\"testRequest\":\"0\",\"accountNumber\":\"XXXX1111\",\"accountType\":\"Visa\",\"messages\":[{\"code\":\"1\",\"description\":\"This transaction has been approved.\"}],\"transHashSha2\":\"BB04E0A1B9CA73C07165F66DDC6784FABF69695F0E53C13DB27ACCD3336614F327098FE8BF3D1587F4FDB5C31F310C36C88E9AFD960D0C673544E4FFE41A6B1E\",\"SupplementalDataQualificationIndicator\":0,\"networkTransId\":\"7QSE18JROJ2A4U6BMDUDPM7\"},\"refId\":\"\",\"messages\":{\"resultCode\":\"Ok\",\"message\":[{\"code\":\"I00001\",\"text\":\"Successful.\"}]}}"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://apitest.authorize.net/xml/v1/request.api\",\"method\":\"POST\",\"headers\":{\"via\":\"HyperSwitch\",\"Content-Type\":\"application/json\"},\"body\":{\"createTransactionRequest\":{\"merchantAuthentication\":{\"name\":\"9ARWr5wz49D3\",\"transactionKey\":\"3d9SHV2699mgmHre\"},\"refId\":null,\"transactionRequest\":{\"transactionType\":\"authCaptureTransaction\",\"amount\":60.0,\"currencyCode\":\"USD\",\"payment\":{\"creditCard\":{\"cardNumber\":\"4111111111111111\",\"expirationDate\":\"2030-08\",\"cardCode\":\"999\"}},\"order\":{\"invoiceNumber\":\"szAES2F4jg4ZP13NlnF1\",\"description\":\"mti_162f9a3af73945128505d1cb4fab90c9\"},\"customer\":{\"id\":\"934839050\",\"email\":\"alex.6993@sandbox.example.com\"},\"billTo\":{\"firstName\":\"Emma\",\"lastName\":\"Johnson\",\"address\":\"2266 Market Blvd 3943 Oak Rd 3253 Main Ave\",\"city\":\"Seattle\",\"state\":\"CA\",\"zip\":\"36052\",\"country\":\"US\"}}}}}"
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
<summary>Show Request Body</summary>

```json
{
  "merchant_transaction_id": "mti_162f9a3af73945128505d1cb4fab90c9",
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
        "value": "Liam Brown"
      },
      "card_type": "credit"
    }
  },
  "capture_method": "AUTOMATIC",
  "customer": {
    "name": "Liam Smith",
    "email": {
      "value": "alex.6993@sandbox.example.com"
    },
    "id": "cust_c9eb1f5ea5e143d9bdc39d3b7c8c5fa4",
    "phone_number": "+915590829126",
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
  "description": "No3DS auto capture card payment (credit)",
  "payment_channel": "ECOMMERCE",
  "test_mode": true
}
```

</details>

<details>
<summary>Show Response Body</summary>

```json
{
  "merchantTransactionId": "120079432040",
  "connectorTransactionId": "120079432040",
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
    "date": "Thu, 12 Mar 2026 15:40:05 GMT",
    "expires": "-1",
    "pragma": "no-cache",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-cnection": "close",
    "x-download-options": "noopen",
    "x-opnet-transaction-trace": "39598f69-930a-4eea-a65b-19a85a5612aa-17512-11760791"
  },
  "networkTransactionId": "7QSE18JROJ2A4U6BMDUDPM7",
  "state": {
    "connectorCustomerId": "934839050"
  },
  "rawConnectorResponse": {
    "value": "{\"transactionResponse\":{\"responseCode\":\"1\",\"authCode\":\"ZUESHX\",\"avsResultCode\":\"Y\",\"cvvResultCode\":\"P\",\"cavvResultCode\":\"2\",\"transId\":\"120079432040\",\"refTransID\":\"\",\"transHash\":\"\",\"testRequest\":\"0\",\"accountNumber\":\"XXXX1111\",\"accountType\":\"Visa\",\"messages\":[{\"code\":\"1\",\"description\":\"This transaction has been approved.\"}],\"transHashSha2\":\"BB04E0A1B9CA73C07165F66DDC6784FABF69695F0E53C13DB27ACCD3336614F327098FE8BF3D1587F4FDB5C31F310C36C88E9AFD960D0C673544E4FFE41A6B1E\",\"SupplementalDataQualificationIndicator\":0,\"networkTransId\":\"7QSE18JROJ2A4U6BMDUDPM7\"},\"refId\":\"\",\"messages\":{\"resultCode\":\"Ok\",\"message\":[{\"code\":\"I00001\",\"text\":\"Successful.\"}]}}"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://apitest.authorize.net/xml/v1/request.api\",\"method\":\"POST\",\"headers\":{\"via\":\"HyperSwitch\",\"Content-Type\":\"application/json\"},\"body\":{\"createTransactionRequest\":{\"merchantAuthentication\":{\"name\":\"9ARWr5wz49D3\",\"transactionKey\":\"3d9SHV2699mgmHre\"},\"refId\":null,\"transactionRequest\":{\"transactionType\":\"authCaptureTransaction\",\"amount\":60.0,\"currencyCode\":\"USD\",\"payment\":{\"creditCard\":{\"cardNumber\":\"4111111111111111\",\"expirationDate\":\"2030-08\",\"cardCode\":\"999\"}},\"order\":{\"invoiceNumber\":\"szAES2F4jg4ZP13NlnF1\",\"description\":\"mti_162f9a3af73945128505d1cb4fab90c9\"},\"customer\":{\"id\":\"934839050\",\"email\":\"alex.6993@sandbox.example.com\"},\"billTo\":{\"firstName\":\"Emma\",\"lastName\":\"Johnson\",\"address\":\"2266 Market Blvd 3943 Oak Rd 3253 Main Ave\",\"city\":\"Seattle\",\"state\":\"CA\",\"zip\":\"36052\",\"country\":\"US\"}}}}}"
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
  -H "x-request-id: authorize_no3ds_auto_capture_credit_card_req" \
  -H "x-connector-request-reference-id: authorize_no3ds_auto_capture_credit_card_ref" \
  -H "x-auth: ***MASKED***" \
  -H "x-api-key: ***MASKED***" \
  -H "x-key1: ***MASKED***" \
  -d @ localhost:8000 types.PaymentService/Authorize <<'JSON'
{
  "merchant_transaction_id": "mti_03d860b172af4e4fa59090adc241ab81",
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
        "value": "Mia Wilson"
      },
      "card_type": "credit"
    }
  },
  "capture_method": "AUTOMATIC",
  "customer": {
    "name": "Noah Wilson",
    "email": {
      "value": "sam.5871@sandbox.example.com"
    },
    "id": "cust_90558e272d4746e481657468f696fac6",
    "phone_number": "+914459721418"
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
        "value": "Noah"
      },
      "last_name": {
        "value": "Miller"
      },
      "line1": {
        "value": "7644 Market Rd"
      },
      "line2": {
        "value": "2274 Market Ave"
      },
      "line3": {
        "value": "4058 Main Ave"
      },
      "city": {
        "value": "Los Angeles"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "91699"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "riley.3997@sandbox.example.com"
      },
      "phone_number": {
        "value": "7916785710"
      },
      "phone_country_code": "+91"
    },
    "billing_address": {
      "first_name": {
        "value": "Emma"
      },
      "last_name": {
        "value": "Wilson"
      },
      "line1": {
        "value": "452 Sunset Ln"
      },
      "line2": {
        "value": "4048 Oak Rd"
      },
      "line3": {
        "value": "4736 Oak Ln"
      },
      "city": {
        "value": "New York"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "28727"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "alex.5435@sandbox.example.com"
      },
      "phone_number": {
        "value": "5391215750"
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
x-connector-request-reference-id: authorize_no3ds_auto_capture_credit_card_ref
x-key1: ***MASKED***
x-merchant-id: test_merchant
x-request-id: authorize_no3ds_auto_capture_credit_card_req
x-tenant-id: default

Response headers received:
content-type: application/grpc
date: Thu, 12 Mar 2026 15:40:58 GMT
x-request-id: authorize_no3ds_auto_capture_credit_card_req

Response contents:
{
  "merchantTransactionId": "mti_03d860b172af4e4fa59090adc241ab81",
  "connectorTransactionId": "82R11796J12817241",
  "status": "CHARGED",
  "statusCode": 201,
  "responseHeaders": {
    "accept-ranges": "bytes",
    "access-control-expose-headers": "Server-Timing",
    "cache-control": "max-age=0, no-cache, no-store, must-revalidate",
    "connection": "keep-alive",
    "content-length": "2397",
    "content-type": "application/json",
    "date": "Thu, 12 Mar 2026 15:40:58 GMT",
    "edge-control": "max-age=0",
    "http_x_pp_az_locator": "ccg18.slc",
    "paypal-debug-id": "f60931828ab7f",
    "server": "nginx",
    "server-timing": "traceparent;desc=\"00-0000000000000000000f60931828ab7f-70dedff6ab1a5be8-01\"",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "vary": "Accept-Encoding",
    "via": "1.1 varnish, 1.1 varnish",
    "x-cache": "MISS, MISS",
    "x-cache-hits": "0, 0",
    "x-served-by": "cache-sin-wsss1830047-SIN, cache-bom-vanm7210086-BOM",
    "x-timer": "S1773330055.071517,VS0,VE3033"
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
    "value": "{\"id\":\"82R11796J12817241\",\"intent\":\"CAPTURE\",\"status\":\"COMPLETED\",\"payment_source\":{\"card\":{\"name\":\"Emma Wilson\",\"last_digits\":\"1111\",\"expiry\":\"2030-08\",\"brand\":\"VISA\",\"type\":\"CREDIT\",\"bin_details\":{}}},\"purchase_units\":[{\"reference_id\":\"mti_03d860b172af4e4fa59090adc241ab81\",\"amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\",\"breakdown\":{\"item_total\":{\"currency_code\":\"USD\",\"value\":\"60.00\"},\"shipping\":{\"currency_code\":\"USD\",\"value\":\"0.00\"},\"handling\":{\"currency_code\":\"USD\",\"value\":\"0.00\"},\"tax_total\":{\"currency_code\":\"USD\",\"value\":\"0.00\"},\"insurance\":{\"currency_code\":\"USD\",\"value\":\"0.00\"},\"shipping_discount\":{\"currency_code\":\"USD\",\"value\":\"0.00\"}}},\"payee\":{\"email_address\":\"sb-itwmi27136406@business.example.com\",\"merchant_id\":\"DUM69V9DDNYEJ\"},\"description\":\"Payment for invoice mti_03d860b172af4e4fa59090adc241ab81\",\"invoice_id\":\"mti_03d860b172af4e4fa59090adc241ab81\",\"soft_descriptor\":\"TEST STORE\",\"items\":[{\"name\":\"Payment for invoice mti_03d860b172af4e4fa59090adc241ab81\",\"unit_amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\"},\"tax\":{\"currency_code\":\"USD\",\"value\":\"0.00\"},\"quantity\":\"1\"}],\"shipping\":{\"name\":{\"full_name\":\"Noah\"},\"address\":{\"address_line_1\":\"7644 Market Rd\",\"admin_area_2\":\"Los Angeles\",\"postal_code\":\"91699\",\"country_code\":\"US\"}},\"payments\":{\"captures\":[{\"id\":\"9L567944G7825451C\",\"status\":\"COMPLETED\",\"amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\"},\"final_capture\":true,\"seller_protection\":{\"status\":\"NOT_ELIGIBLE\"},\"seller_receivable_breakdown\":{\"gross_amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\"},\"net_amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\"}},\"invoice_id\":\"mti_03d860b172af4e4fa59090adc241ab81\",\"links\":[{\"href\":\"https://api.sandbox.paypal.com/v2/payments/captures/9L567944G7825451C\",\"rel\":\"self\",\"method\":\"GET\"},{\"href\":\"https://api.sandbox.paypal.com/v2/payments/captures/9L567944G7825451C/refund\",\"rel\":\"refund\",\"method\":\"POST\"},{\"href\":\"https://api.sandbox.paypal.com/v2/checkout/orders/82R11796J12817241\",\"rel\":\"up\",\"method\":\"GET\"}],\"create_time\":\"2026-03-12T15:40:57Z\",\"update_time\":\"2026-03-12T15:40:57Z\",\"network_transaction_reference\":{\"id\":\"477472155294184\",\"network\":\"VISA\"},\"processor_response\":{\"avs_code\":\"A\",\"cvv_code\":\"M\",\"response_code\":\"0000\"}}]}}],\"create_time\":\"2026-03-12T15:40:57Z\",\"update_time\":\"2026-03-12T15:40:57Z\",\"links\":[{\"href\":\"https://api.sandbox.paypal.com/v2/checkout/orders/82R11796J12817241\",\"rel\":\"self\",\"method\":\"GET\"}]}"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://api-m.sandbox.paypal.com/v2/checkout/orders\",\"method\":\"POST\",\"headers\":{\"PayPal-Partner-Attribution-Id\":\"HyperSwitchlegacy_Ecom\",\"Content-Type\":\"application/json\",\"PayPal-Request-Id\":\"mti_03d860b172af4e4fa59090adc241ab81\",\"via\":\"HyperSwitch\",\"Authorization\":\"Bearer ***MASKED***",\"Prefer\":\"return=representation\"},\"body\":{\"intent\":\"CAPTURE\",\"purchase_units\":[{\"reference_id\":\"mti_03d860b172af4e4fa59090adc241ab81\",\"invoice_id\":\"mti_03d860b172af4e4fa59090adc241ab81\",\"custom_id\":null,\"amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\",\"breakdown\":{\"item_total\":{\"currency_code\":\"USD\",\"value\":\"60.00\"},\"tax_total\":null,\"shipping\":{\"currency_code\":\"USD\",\"value\":\"0.00\"}}},\"shipping\":{\"address\":{\"address_line_1\":\"7644 Market Rd\",\"postal_code\":\"91699\",\"country_code\":\"US\",\"admin_area_2\":\"Los Angeles\"},\"name\":{\"full_name\":\"Noah\"}},\"items\":[{\"name\":\"Payment for invoice mti_03d860b172af4e4fa59090adc241ab81\",\"quantity\":1,\"unit_amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\"},\"tax\":null}]}],\"payment_source\":{\"card\":{\"billing_address\":{\"address_line_1\":\"452 Sunset Ln\",\"postal_code\":\"28727\",\"country_code\":\"US\",\"admin_area_2\":\"New York\"},\"expiry\":\"2030-08\",\"name\":\"Emma Wilson\",\"number\":\"4111111111111111\",\"security_code\":\"999\",\"attributes\":{\"vault\":null,\"verification\":null}}}}}"
  },
  "mandateReference": {
    "connectorMandateId": {}
  },
  "connectorFeatureData": {
    "value": "{\"authorize_id\":null,\"capture_id\":\"9L567944G7825451C\",\"incremental_authorization_id\":null,\"psync_flow\":\"CAPTURE\",\"next_action\":null,\"order_id\":null}"
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
  "merchant_transaction_id": "mti_03d860b172af4e4fa59090adc241ab81",
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
        "value": "Mia Wilson"
      },
      "card_type": "credit"
    }
  },
  "capture_method": "AUTOMATIC",
  "customer": {
    "name": "Noah Wilson",
    "email": {
      "value": "sam.5871@sandbox.example.com"
    },
    "id": "cust_90558e272d4746e481657468f696fac6",
    "phone_number": "+914459721418"
  },
  "state": {
    "access_token": "***MASKED***"
  },
  "address": {
    "shipping_address": {
      "first_name": {
        "value": "Noah"
      },
      "last_name": {
        "value": "Miller"
      },
      "line1": {
        "value": "7644 Market Rd"
      },
      "line2": {
        "value": "2274 Market Ave"
      },
      "line3": {
        "value": "4058 Main Ave"
      },
      "city": {
        "value": "Los Angeles"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "91699"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "riley.3997@sandbox.example.com"
      },
      "phone_number": {
        "value": "7916785710"
      },
      "phone_country_code": "+91"
    },
    "billing_address": {
      "first_name": {
        "value": "Emma"
      },
      "last_name": {
        "value": "Wilson"
      },
      "line1": {
        "value": "452 Sunset Ln"
      },
      "line2": {
        "value": "4048 Oak Rd"
      },
      "line3": {
        "value": "4736 Oak Ln"
      },
      "city": {
        "value": "New York"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "28727"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "alex.5435@sandbox.example.com"
      },
      "phone_number": {
        "value": "5391215750"
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
  "test_mode": true,
  "locale": "en-US"
}
```

</details>

<details>
<summary>Show Response Body</summary>

```json
{
  "merchantTransactionId": "mti_03d860b172af4e4fa59090adc241ab81",
  "connectorTransactionId": "82R11796J12817241",
  "status": "CHARGED",
  "statusCode": 201,
  "responseHeaders": {
    "accept-ranges": "bytes",
    "access-control-expose-headers": "Server-Timing",
    "cache-control": "max-age=0, no-cache, no-store, must-revalidate",
    "connection": "keep-alive",
    "content-length": "2397",
    "content-type": "application/json",
    "date": "Thu, 12 Mar 2026 15:40:58 GMT",
    "edge-control": "max-age=0",
    "http_x_pp_az_locator": "ccg18.slc",
    "paypal-debug-id": "f60931828ab7f",
    "server": "nginx",
    "server-timing": "traceparent;desc=\"00-0000000000000000000f60931828ab7f-70dedff6ab1a5be8-01\"",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "vary": "Accept-Encoding",
    "via": "1.1 varnish, 1.1 varnish",
    "x-cache": "MISS, MISS",
    "x-cache-hits": "0, 0",
    "x-served-by": "cache-sin-wsss1830047-SIN, cache-bom-vanm7210086-BOM",
    "x-timer": "S1773330055.071517,VS0,VE3033"
  },
  "state": {
    "accessToken": "***MASKED***"
  },
  "rawConnectorResponse": {
    "value": "{\"id\":\"82R11796J12817241\",\"intent\":\"CAPTURE\",\"status\":\"COMPLETED\",\"payment_source\":{\"card\":{\"name\":\"Emma Wilson\",\"last_digits\":\"1111\",\"expiry\":\"2030-08\",\"brand\":\"VISA\",\"type\":\"CREDIT\",\"bin_details\":{}}},\"purchase_units\":[{\"reference_id\":\"mti_03d860b172af4e4fa59090adc241ab81\",\"amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\",\"breakdown\":{\"item_total\":{\"currency_code\":\"USD\",\"value\":\"60.00\"},\"shipping\":{\"currency_code\":\"USD\",\"value\":\"0.00\"},\"handling\":{\"currency_code\":\"USD\",\"value\":\"0.00\"},\"tax_total\":{\"currency_code\":\"USD\",\"value\":\"0.00\"},\"insurance\":{\"currency_code\":\"USD\",\"value\":\"0.00\"},\"shipping_discount\":{\"currency_code\":\"USD\",\"value\":\"0.00\"}}},\"payee\":{\"email_address\":\"sb-itwmi27136406@business.example.com\",\"merchant_id\":\"DUM69V9DDNYEJ\"},\"description\":\"Payment for invoice mti_03d860b172af4e4fa59090adc241ab81\",\"invoice_id\":\"mti_03d860b172af4e4fa59090adc241ab81\",\"soft_descriptor\":\"TEST STORE\",\"items\":[{\"name\":\"Payment for invoice mti_03d860b172af4e4fa59090adc241ab81\",\"unit_amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\"},\"tax\":{\"currency_code\":\"USD\",\"value\":\"0.00\"},\"quantity\":\"1\"}],\"shipping\":{\"name\":{\"full_name\":\"Noah\"},\"address\":{\"address_line_1\":\"7644 Market Rd\",\"admin_area_2\":\"Los Angeles\",\"postal_code\":\"91699\",\"country_code\":\"US\"}},\"payments\":{\"captures\":[{\"id\":\"9L567944G7825451C\",\"status\":\"COMPLETED\",\"amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\"},\"final_capture\":true,\"seller_protection\":{\"status\":\"NOT_ELIGIBLE\"},\"seller_receivable_breakdown\":{\"gross_amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\"},\"net_amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\"}},\"invoice_id\":\"mti_03d860b172af4e4fa59090adc241ab81\",\"links\":[{\"href\":\"https://api.sandbox.paypal.com/v2/payments/captures/9L567944G7825451C\",\"rel\":\"self\",\"method\":\"GET\"},{\"href\":\"https://api.sandbox.paypal.com/v2/payments/captures/9L567944G7825451C/refund\",\"rel\":\"refund\",\"method\":\"POST\"},{\"href\":\"https://api.sandbox.paypal.com/v2/checkout/orders/82R11796J12817241\",\"rel\":\"up\",\"method\":\"GET\"}],\"create_time\":\"2026-03-12T15:40:57Z\",\"update_time\":\"2026-03-12T15:40:57Z\",\"network_transaction_reference\":{\"id\":\"477472155294184\",\"network\":\"VISA\"},\"processor_response\":{\"avs_code\":\"A\",\"cvv_code\":\"M\",\"response_code\":\"0000\"}}]}}],\"create_time\":\"2026-03-12T15:40:57Z\",\"update_time\":\"2026-03-12T15:40:57Z\",\"links\":[{\"href\":\"https://api.sandbox.paypal.com/v2/checkout/orders/82R11796J12817241\",\"rel\":\"self\",\"method\":\"GET\"}]}"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://api-m.sandbox.paypal.com/v2/checkout/orders\",\"method\":\"POST\",\"headers\":{\"PayPal-Partner-Attribution-Id\":\"HyperSwitchlegacy_Ecom\",\"Content-Type\":\"application/json\",\"PayPal-Request-Id\":\"mti_03d860b172af4e4fa59090adc241ab81\",\"via\":\"HyperSwitch\",\"Authorization\":\"Bearer ***MASKED***\",\"Prefer\":\"return=representation\"},\"body\":{\"intent\":\"CAPTURE\",\"purchase_units\":[{\"reference_id\":\"mti_03d860b172af4e4fa59090adc241ab81\",\"invoice_id\":\"mti_03d860b172af4e4fa59090adc241ab81\",\"custom_id\":null,\"amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\",\"breakdown\":{\"item_total\":{\"currency_code\":\"USD\",\"value\":\"60.00\"},\"tax_total\":null,\"shipping\":{\"currency_code\":\"USD\",\"value\":\"0.00\"}}},\"shipping\":{\"address\":{\"address_line_1\":\"7644 Market Rd\",\"postal_code\":\"91699\",\"country_code\":\"US\",\"admin_area_2\":\"Los Angeles\"},\"name\":{\"full_name\":\"Noah\"}},\"items\":[{\"name\":\"Payment for invoice mti_03d860b172af4e4fa59090adc241ab81\",\"quantity\":1,\"unit_amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\"},\"tax\":null}]}],\"payment_source\":{\"card\":{\"billing_address\":{\"address_line_1\":\"452 Sunset Ln\",\"postal_code\":\"28727\",\"country_code\":\"US\",\"admin_area_2\":\"New York\"},\"expiry\":\"2030-08\",\"name\":\"Emma Wilson\",\"number\":\"4111111111111111\",\"security_code\":\"999\",\"attributes\":{\"vault\":null,\"verification\":null}}}}}"
  },
  "mandateReference": {
    "connectorMandateId": {}
  },
  "connectorFeatureData": {
    "value": "{\"authorize_id\":null,\"capture_id\":\"9L567944G7825451C\",\"incremental_authorization_id\":null,\"psync_flow\":\"CAPTURE\",\"next_action\":null,\"order_id\":null}"
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
  -H "x-request-id: authorize_no3ds_auto_capture_credit_card_req" \
  -H "x-connector-request-reference-id: authorize_no3ds_auto_capture_credit_card_ref" \
  -H "x-auth: ***MASKED***" \
  -H "x-api-key: ***MASKED***" \
  -d @ localhost:8000 types.PaymentService/Authorize <<'JSON'
{
  "merchant_transaction_id": "mti_3713581b092045c2bfaf9312da084202",
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
        "value": "Mia Wilson"
      },
      "card_type": "credit"
    }
  },
  "capture_method": "AUTOMATIC",
  "customer": {
    "name": "Mia Johnson",
    "email": {
      "value": "riley.3450@sandbox.example.com"
    },
    "id": "cust_1f7ebb2fb40943afbb11719f6d984277",
    "phone_number": "+448975562423",
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
  "description": "No3DS auto capture card payment (credit)",
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
x-connector-request-reference-id: authorize_no3ds_auto_capture_credit_card_ref
x-merchant-id: test_merchant
x-request-id: authorize_no3ds_auto_capture_credit_card_req
x-tenant-id: default

Response headers received:
content-type: application/grpc
date: Thu, 12 Mar 2026 15:42:35 GMT
x-request-id: authorize_no3ds_auto_capture_credit_card_req

Response contents:
{
  "merchantTransactionId": "pi_3TABNeD5R7gDAGff0n1nNzEM",
  "connectorTransactionId": "pi_3TABNeD5R7gDAGff0n1nNzEM",
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
    "content-length": "5536",
    "content-security-policy": "base-uri 'none'; default-src 'none'; form-action 'none'; frame-ancestors 'none'; img-src 'self'; script-src 'self' 'report-sample'; style-src 'self'; worker-src 'none'; upgrade-insecure-requests; report-uri https://q.stripe.com/csp-violation?q=XbpkE0Obtc-D-_OVcHByv3HX2Cz2ZXWthan_OSmhaX_cdx20p33NXUJkyzusgJOGoDWC714Lefdz6v3w",
    "content-type": "application/json",
    "date": "Thu, 12 Mar 2026 15:42:35 GMT",
    "idempotency-key": "15fbb5d8-a9a1-4f5d-bfaa-0329399cdc37",
    "original-request": "req_xwOgnWNUY0tDWT",
    "request-id": "req_xwOgnWNUY0tDWT",
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
    "connectorCustomerId": "cus_U8SIyZsBbJaaAz"
  },
  "rawConnectorResponse": {
    "value": "{\n  \"id\": \"pi_3TABNeD5R7gDAGff0n1nNzEM\",\n  \"object\": \"payment_intent\",\n  \"amount\": 6000,\n  \"amount_capturable\": 0,\n  \"amount_details\": {\n    \"tip\": {}\n  },\n  \"amount_received\": 6000,\n  \"application\": null,\n  \"application_fee_amount\": null,\n  \"automatic_payment_methods\": null,\n  \"canceled_at\": null,\n  \"cancellation_reason\": null,\n  \"capture_method\": \"automatic\",\n  \"client_secret\": \"pi_3TABNeD5R7gDAGff0n1nNzEM_secret_gC8JmT1aUr0ZmpSleUQ9ZK6qV\",\n  \"confirmation_method\": \"automatic\",\n  \"created\": 1773330154,\n  \"currency\": \"usd\",\n  \"customer\": \"cus_U8SIyZsBbJaaAz\",\n  \"customer_account\": null,\n  \"description\": \"No3DS auto capture card payment (credit)\",\n  \"excluded_payment_method_types\": null,\n  \"invoice\": null,\n  \"last_payment_error\": null,\n  \"latest_charge\": {\n    \"id\": \"ch_3TABNeD5R7gDAGff0yhpVOZY\",\n    \"object\": \"charge\",\n    \"amount\": 6000,\n    \"amount_captured\": 6000,\n    \"amount_refunded\": 0,\n    \"amount_updates\": [],\n    \"application\": null,\n    \"application_fee\": null,\n    \"application_fee_amount\": null,\n    \"balance_transaction\": \"txn_3TABNeD5R7gDAGff0WRk4IKr\",\n    \"billing_details\": {\n      \"address\": {\n        \"city\": \"Chicago\",\n        \"country\": \"US\",\n        \"line1\": \"7297 Market St\",\n        \"line2\": \"2736 Main Dr\",\n        \"postal_code\": \"83242\",\n        \"state\": \"CA\"\n      },\n      \"email\": \"casey.3657@sandbox.example.com\",\n      \"name\": \"Emma Miller\",\n      \"phone\": \"1001673800\",\n      \"tax_id\": null\n    },\n    \"calculated_statement_descriptor\": \"BERNARD\",\n    \"captured\": true,\n    \"created\": 1773330155,\n    \"currency\": \"usd\",\n    \"customer\": \"cus_U8SIyZsBbJaaAz\",\n    \"description\": \"No3DS auto capture card payment (credit)\",\n    \"destination\": null,\n    \"dispute\": null,\n    \"disputed\": false,\n    \"failure_balance_transaction\": null,\n    \"failure_code\": null,\n    \"failure_message\": null,\n    \"fraud_details\": {},\n    \"invoice\": null,\n    \"livemode\": false,\n    \"metadata\": {\n      \"order_id\": \"mti_3713581b092045c2bfaf9312da084202\"\n    },\n    \"on_behalf_of\": null,\n    \"order\": null,\n    \"outcome\": {\n      \"advice_code\": null,\n      \"network_advice_code\": null,\n      \"network_decline_code\": null,\n      \"network_status\": \"approved_by_network\",\n      \"reason\": null,\n      \"risk_level\": \"normal\",\n      \"risk_score\": 44,\n      \"seller_message\": \"Payment complete.\",\n      \"type\": \"authorized\"\n    },\n    \"paid\": true,\n    \"payment_intent\": \"pi_3TABNeD5R7gDAGff0n1nNzEM\",\n    \"payment_method\": \"pm_1TABNeD5R7gDAGffU9kzy08z\",\n    \"payment_method_details\": {\n      \"card\": {\n        \"amount_authorized\": 6000,\n        \"authorization_code\": \"269352\",\n        \"brand\": \"visa\",\n        \"checks\": {\n          \"address_line1_check\": \"pass\",\n          \"address_postal_code_check\": \"pass\",\n          \"cvc_check\": \"pass\"\n        },\n        \"country\": \"US\",\n        \"exp_month\": 8,\n        \"exp_year\": 2030,\n        \"extended_authorization\": {\n          \"status\": \"disabled\"\n        },\n        \"fingerprint\": \"aEed1rfhfa5JNpoz\",\n        \"funding\": \"credit\",\n        \"incremental_authorization\": {\n          \"status\": \"unavailable\"\n        },\n        \"installments\": null,\n        \"last4\": \"1111\",\n        \"mandate\": null,\n        \"moto\": null,\n        \"multicapture\": {\n          \"status\": \"unavailable\"\n        },\n        \"network\": \"visa\",\n        \"network_token\": {\n          \"used\": false\n        },\n        \"network_transaction_id\": \"976910110049114\",\n        \"overcapture\": {\n          \"maximum_amount_capturable\": 6000,\n          \"status\": \"unavailable\"\n        },\n        \"regulated_status\": \"unregulated\",\n        \"three_d_secure\": null,\n        \"wallet\": null\n      },\n      \"type\": \"card\"\n    },\n    \"radar_options\": {},\n    \"receipt_email\": null,\n    \"receipt_number\": null,\n    \"receipt_url\": \"https://pay.stripe.com/receipts/payment/CAcaFwoVYWNjdF8xTTdmVGFENVI3Z0RBR2ZmKOu9y80GMgZ1a87PAlw6LBYdv9gpy9mILwrx0-ZjRcWENb5V1QKXZBHl_FaCcwvg-jSjJA0-OaxcCaQE\",\n    \"refunded\": false,\n    \"review\": null,\n    \"shipping\": {\n      \"address\": {\n        \"city\": \"Austin\",\n        \"country\": \"US\",\n        \"line1\": \"8628 Lake Dr\",\n        \"line2\": \"63 Lake St\",\n        \"postal_code\": \"95996\",\n        \"state\": \"CA\"\n      },\n      \"carrier\": null,\n      \"name\": \"Ethan Johnson\",\n      \"phone\": \"+911001378882\",\n      \"tracking_number\": null\n    },\n    \"source\": null,\n    \"source_transfer\": null,\n    \"statement_descriptor\": null,\n    \"statement_descriptor_suffix\": null,\n    \"status\": \"succeeded\",\n    \"transfer_data\": null,\n    \"transfer_group\": null\n  },\n  \"livemode\": false,\n  \"metadata\": {\n    \"order_id\": \"mti_3713581b092045c2bfaf9312da084202\"\n  },\n  \"next_action\": null,\n  \"on_behalf_of\": null,\n  \"payment_method\": \"pm_1TABNeD5R7gDAGffU9kzy08z\",\n  \"payment_method_configuration_details\": null,\n  \"payment_method_options\": {\n    \"card\": {\n      \"installments\": null,\n      \"mandate_options\": null,\n      \"network\": null,\n      \"request_three_d_secure\": \"automatic\"\n    }\n  },\n  \"payment_method_types\": [\n    \"card\"\n  ],\n  \"processing\": null,\n  \"receipt_email\": null,\n  \"review\": null,\n  \"setup_future_usage\": \"on_session\",\n  \"shipping\": {\n    \"address\": {\n      \"city\": \"Austin\",\n      \"country\": \"US\",\n      \"line1\": \"8628 Lake Dr\",\n      \"line2\": \"63 Lake St\",\n      \"postal_code\": \"95996\",\n      \"state\": \"CA\"\n    },\n    \"carrier\": null,\n    \"name\": \"Ethan Johnson\",\n    \"phone\": \"+911001378882\",\n    \"tracking_number\": null\n  },\n  \"source\": null,\n  \"statement_descriptor\": null,\n  \"statement_descriptor_suffix\": null,\n  \"status\": \"succeeded\",\n  \"transfer_data\": null,\n  \"transfer_group\": null\n}"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://api.stripe.com/v1/payment_intents\",\"method\":\"POST\",\"headers\":{\"Authorization\":\"Bearer ***MASKED***",\"stripe-version\":\"2022-11-15\",\"via\":\"HyperSwitch\",\"Content-Type\":\"application/x-www-form-urlencoded\"},\"body\":\"amount=6000\u0026currency=USD\u0026metadata%5Border_id%5D=mti_3713581b092045c2bfaf9312da084202\u0026return_url=https%3A%2F%2Fexample.com%2Fpayment%2Freturn\u0026confirm=true\u0026customer=cus_U8SIyZsBbJaaAz\u0026description=No3DS+auto+capture+card+payment+%28credit%29\u0026shipping%5Baddress%5D%5Bcity%5D=Austin\u0026shipping%5Baddress%5D%5Bcountry%5D=US\u0026shipping%5Baddress%5D%5Bline1%5D=8628+Lake+Dr\u0026shipping%5Baddress%5D%5Bline2%5D=63+Lake+St\u0026shipping%5Baddress%5D%5Bpostal_code%5D=95996\u0026shipping%5Baddress%5D%5Bstate%5D=CA\u0026shipping%5Bname%5D=Ethan+Johnson\u0026shipping%5Bphone%5D=%2B911001378882\u0026payment_method_data%5Bbilling_details%5D%5Bemail%5D=casey.3657%40sandbox.example.com\u0026payment_method_data%5Bbilling_details%5D%5Baddress%5D%5Bcountry%5D=US\u0026payment_method_data%5Bbilling_details%5D%5Bname%5D=Emma+Miller\u0026payment_method_data%5Bbilling_details%5D%5Baddress%5D%5Bcity%5D=Chicago\u0026payment_method_data%5Bbilling_details%5D%5Baddress%5D%5Bline1%5D=7297+Market+St\u0026payment_method_data%5Bbilling_details%5D%5Baddress%5D%5Bline2%5D=2736+Main+Dr\u0026payment_method_data%5Bbilling_details%5D%5Baddress%5D%5Bpostal_code%5D=83242\u0026payment_method_data%5Bbilling_details%5D%5Baddress%5D%5Bstate%5D=CA\u0026payment_method_data%5Bbilling_details%5D%5Bphone%5D=1001673800\u0026payment_method_data%5Btype%5D=card\u0026payment_method_data%5Bcard%5D%5Bnumber%5D=4111111111111111\u0026payment_method_data%5Bcard%5D%5Bexp_month%5D=08\u0026payment_method_data%5Bcard%5D%5Bexp_year%5D=30\u0026payment_method_data%5Bcard%5D%5Bcvc%5D=999\u0026payment_method_options%5Bcard%5D%5Brequest_three_d_secure%5D=automatic\u0026capture_method=automatic\u0026setup_future_usage=on_session\u0026off_session=false\u0026payment_method_types%5B0%5D=card\u0026expand%5B0%5D=latest_charge\"}"
  },
  "capturedAmount": "6000",
  "mandateReference": {
    "connectorMandateId": {
      "connectorMandateId": "pm_1TABNeD5R7gDAGffU9kzy08z",
      "paymentMethodId": "pm_1TABNeD5R7gDAGffU9kzy08z"
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
<summary>Show Request Body</summary>

```json
{
  "merchant_transaction_id": "mti_3713581b092045c2bfaf9312da084202",
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
        "value": "Mia Wilson"
      },
      "card_type": "credit"
    }
  },
  "capture_method": "AUTOMATIC",
  "customer": {
    "name": "Mia Johnson",
    "email": {
      "value": "riley.3450@sandbox.example.com"
    },
    "id": "cust_1f7ebb2fb40943afbb11719f6d984277",
    "phone_number": "+448975562423",
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
  "description": "No3DS auto capture card payment (credit)",
  "payment_channel": "ECOMMERCE",
  "test_mode": true
}
```

</details>

<details>
<summary>Show Response Body</summary>

```json
{
  "merchantTransactionId": "pi_3TABNeD5R7gDAGff0n1nNzEM",
  "connectorTransactionId": "pi_3TABNeD5R7gDAGff0n1nNzEM",
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
    "content-length": "5536",
    "content-security-policy": "base-uri 'none'; default-src 'none'; form-action 'none'; frame-ancestors 'none'; img-src 'self'; script-src 'self' 'report-sample'; style-src 'self'; worker-src 'none'; upgrade-insecure-requests; report-uri https://q.stripe.com/csp-violation?q=XbpkE0Obtc-D-_OVcHByv3HX2Cz2ZXWthan_OSmhaX_cdx20p33NXUJkyzusgJOGoDWC714Lefdz6v3w",
    "content-type": "application/json",
    "date": "Thu, 12 Mar 2026 15:42:35 GMT",
    "idempotency-key": "15fbb5d8-a9a1-4f5d-bfaa-0329399cdc37",
    "original-request": "req_xwOgnWNUY0tDWT",
    "request-id": "req_xwOgnWNUY0tDWT",
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
    "connectorCustomerId": "cus_U8SIyZsBbJaaAz"
  },
  "rawConnectorResponse": {
    "value": "{\n  \"id\": \"pi_3TABNeD5R7gDAGff0n1nNzEM\",\n  \"object\": \"payment_intent\",\n  \"amount\": 6000,\n  \"amount_capturable\": 0,\n  \"amount_details\": {\n    \"tip\": {}\n  },\n  \"amount_received\": 6000,\n  \"application\": null,\n  \"application_fee_amount\": null,\n  \"automatic_payment_methods\": null,\n  \"canceled_at\": null,\n  \"cancellation_reason\": null,\n  \"capture_method\": \"automatic\",\n  \"client_secret\": ***MASKED***\"\n  \"confirmation_method\": \"automatic\",\n  \"created\": 1773330154,\n  \"currency\": \"usd\",\n  \"customer\": \"cus_U8SIyZsBbJaaAz\",\n  \"customer_account\": null,\n  \"description\": \"No3DS auto capture card payment (credit)\",\n  \"excluded_payment_method_types\": null,\n  \"invoice\": null,\n  \"last_payment_error\": null,\n  \"latest_charge\": {\n    \"id\": \"ch_3TABNeD5R7gDAGff0yhpVOZY\",\n    \"object\": \"charge\",\n    \"amount\": 6000,\n    \"amount_captured\": 6000,\n    \"amount_refunded\": 0,\n    \"amount_updates\": [],\n    \"application\": null,\n    \"application_fee\": null,\n    \"application_fee_amount\": null,\n    \"balance_transaction\": \"txn_3TABNeD5R7gDAGff0WRk4IKr\",\n    \"billing_details\": {\n      \"address\": {\n        \"city\": \"Chicago\",\n        \"country\": \"US\",\n        \"line1\": \"7297 Market St\",\n        \"line2\": \"2736 Main Dr\",\n        \"postal_code\": \"83242\",\n        \"state\": \"CA\"\n      },\n      \"email\": \"casey.3657@sandbox.example.com\",\n      \"name\": \"Emma Miller\",\n      \"phone\": \"1001673800\",\n      \"tax_id\": null\n    },\n    \"calculated_statement_descriptor\": \"BERNARD\",\n    \"captured\": true,\n    \"created\": 1773330155,\n    \"currency\": \"usd\",\n    \"customer\": \"cus_U8SIyZsBbJaaAz\",\n    \"description\": \"No3DS auto capture card payment (credit)\",\n    \"destination\": null,\n    \"dispute\": null,\n    \"disputed\": false,\n    \"failure_balance_transaction\": null,\n    \"failure_code\": null,\n    \"failure_message\": null,\n    \"fraud_details\": {},\n    \"invoice\": null,\n    \"livemode\": false,\n    \"metadata\": {\n      \"order_id\": \"mti_3713581b092045c2bfaf9312da084202\"\n    },\n    \"on_behalf_of\": null,\n    \"order\": null,\n    \"outcome\": {\n      \"advice_code\": null,\n      \"network_advice_code\": null,\n      \"network_decline_code\": null,\n      \"network_status\": \"approved_by_network\",\n      \"reason\": null,\n      \"risk_level\": \"normal\",\n      \"risk_score\": 44,\n      \"seller_message\": \"Payment complete.\",\n      \"type\": \"authorized\"\n    },\n    \"paid\": true,\n    \"payment_intent\": \"pi_3TABNeD5R7gDAGff0n1nNzEM\",\n    \"payment_method\": \"pm_1TABNeD5R7gDAGffU9kzy08z\",\n    \"payment_method_details\": {\n      \"card\": {\n        \"amount_authorized\": 6000,\n        \"authorization_code\": ***MASKED***\"\n        \"brand\": \"visa\",\n        \"checks\": {\n          \"address_line1_check\": \"pass\",\n          \"address_postal_code_check\": \"pass\",\n          \"cvc_check\": ***MASKED***\"\n        },\n        \"country\": \"US\",\n        \"exp_month\": ***MASKED***\n        \"exp_year\": ***MASKED***\n        \"extended_authorization\": ***MASKED***\n          \"status\": \"disabled\"\n        },\n        \"fingerprint\": \"aEed1rfhfa5JNpoz\",\n        \"funding\": \"credit\",\n        \"incremental_authorization\": ***MASKED***\n          \"status\": \"unavailable\"\n        },\n        \"installments\": null,\n        \"last4\": \"1111\",\n        \"mandate\": null,\n        \"moto\": null,\n        \"multicapture\": {\n          \"status\": \"unavailable\"\n        },\n        \"network\": \"visa\",\n        \"network_token\": ***MASKED***\n          \"used\": false\n        },\n        \"network_transaction_id\": \"976910110049114\",\n        \"overcapture\": {\n          \"maximum_amount_capturable\": 6000,\n          \"status\": \"unavailable\"\n        },\n        \"regulated_status\": \"unregulated\",\n        \"three_d_secure\": null,\n        \"wallet\": null\n      },\n      \"type\": \"card\"\n    },\n    \"radar_options\": {},\n    \"receipt_email\": null,\n    \"receipt_number\": null,\n    \"receipt_url\": \"https://pay.stripe.com/receipts/payment/CAcaFwoVYWNjdF8xTTdmVGFENVI3Z0RBR2ZmKOu9y80GMgZ1a87PAlw6LBYdv9gpy9mILwrx0-ZjRcWENb5V1QKXZBHl_FaCcwvg-jSjJA0-OaxcCaQE\",\n    \"refunded\": false,\n    \"review\": null,\n    \"shipping\": {\n      \"address\": {\n        \"city\": \"Austin\",\n        \"country\": \"US\",\n        \"line1\": \"8628 Lake Dr\",\n        \"line2\": \"63 Lake St\",\n        \"postal_code\": \"95996\",\n        \"state\": \"CA\"\n      },\n      \"carrier\": null,\n      \"name\": \"Ethan Johnson\",\n      \"phone\": \"+911001378882\",\n      \"tracking_number\": null\n    },\n    \"source\": null,\n    \"source_transfer\": null,\n    \"statement_descriptor\": null,\n    \"statement_descriptor_suffix\": null,\n    \"status\": \"succeeded\",\n    \"transfer_data\": null,\n    \"transfer_group\": null\n  },\n  \"livemode\": false,\n  \"metadata\": {\n    \"order_id\": \"mti_3713581b092045c2bfaf9312da084202\"\n  },\n  \"next_action\": null,\n  \"on_behalf_of\": null,\n  \"payment_method\": \"pm_1TABNeD5R7gDAGffU9kzy08z\",\n  \"payment_method_configuration_details\": null,\n  \"payment_method_options\": {\n    \"card\": {\n      \"installments\": null,\n      \"mandate_options\": null,\n      \"network\": null,\n      \"request_three_d_secure\": \"automatic\"\n    }\n  },\n  \"payment_method_types\": [\n    \"card\"\n  ],\n  \"processing\": null,\n  \"receipt_email\": null,\n  \"review\": null,\n  \"setup_future_usage\": \"on_session\",\n  \"shipping\": {\n    \"address\": {\n      \"city\": \"Austin\",\n      \"country\": \"US\",\n      \"line1\": \"8628 Lake Dr\",\n      \"line2\": \"63 Lake St\",\n      \"postal_code\": \"95996\",\n      \"state\": \"CA\"\n    },\n    \"carrier\": null,\n    \"name\": \"Ethan Johnson\",\n    \"phone\": \"+911001378882\",\n    \"tracking_number\": null\n  },\n  \"source\": null,\n  \"statement_descriptor\": null,\n  \"statement_descriptor_suffix\": null,\n  \"status\": \"succeeded\",\n  \"transfer_data\": null,\n  \"transfer_group\": null\n}"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://api.stripe.com/v1/payment_intents\",\"method\":\"POST\",\"headers\":{\"Authorization\":\"Bearer ***MASKED***\",\"stripe-version\":\"2022-11-15\",\"via\":\"HyperSwitch\",\"Content-Type\":\"application/x-www-form-urlencoded\"},\"body\":\"amount=6000&currency=USD&metadata%5Border_id%5D=mti_3713581b092045c2bfaf9312da084202&return_url=https%3A%2F%2Fexample.com%2Fpayment%2Freturn&confirm=true&customer=cus_U8SIyZsBbJaaAz&description=No3DS+auto+capture+card+payment+%28credit%29&shipping%5Baddress%5D%5Bcity%5D=Austin&shipping%5Baddress%5D%5Bcountry%5D=US&shipping%5Baddress%5D%5Bline1%5D=8628+Lake+Dr&shipping%5Baddress%5D%5Bline2%5D=63+Lake+St&shipping%5Baddress%5D%5Bpostal_code%5D=95996&shipping%5Baddress%5D%5Bstate%5D=CA&shipping%5Bname%5D=Ethan+Johnson&shipping%5Bphone%5D=%2B911001378882&payment_method_data%5Bbilling_details%5D%5Bemail%5D=casey.3657%40sandbox.example.com&payment_method_data%5Bbilling_details%5D%5Baddress%5D%5Bcountry%5D=US&payment_method_data%5Bbilling_details%5D%5Bname%5D=Emma+Miller&payment_method_data%5Bbilling_details%5D%5Baddress%5D%5Bcity%5D=Chicago&payment_method_data%5Bbilling_details%5D%5Baddress%5D%5Bline1%5D=7297+Market+St&payment_method_data%5Bbilling_details%5D%5Baddress%5D%5Bline2%5D=2736+Main+Dr&payment_method_data%5Bbilling_details%5D%5Baddress%5D%5Bpostal_code%5D=83242&payment_method_data%5Bbilling_details%5D%5Baddress%5D%5Bstate%5D=CA&payment_method_data%5Bbilling_details%5D%5Bphone%5D=1001673800&payment_method_data%5Btype%5D=card&payment_method_data%5Bcard%5D%5Bnumber%5D=4111111111111111&payment_method_data%5Bcard%5D%5Bexp_month%5D=08&payment_method_data%5Bcard%5D%5Bexp_year%5D=30&payment_method_data%5Bcard%5D%5Bcvc%5D=999&payment_method_options%5Bcard%5D%5Brequest_three_d_secure%5D=automatic&capture_method=automatic&setup_future_usage=on_session&off_session=false&payment_method_types%5B0%5D=card&expand%5B0%5D=latest_charge\"}"
  },
  "capturedAmount": "6000",
  "mandateReference": {
    "connectorMandateId": {
      "connectorMandateId": "pm_1TABNeD5R7gDAGffU9kzy08z",
      "paymentMethodId": "pm_1TABNeD5R7gDAGffU9kzy08z"
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


[Back to Overview](../../test_overview.md)
