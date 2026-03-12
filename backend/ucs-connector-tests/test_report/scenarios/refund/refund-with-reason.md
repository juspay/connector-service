# Scenario `refund_with_reason`

- Suite: `refund`
- Service: `PaymentService/Refund`
- PM / PMT: `-` / `-`

## Connector Summary

| Connector | Result | Prerequisites |
|:----------|:------:|:--------------|
| `authorizedotnet` | [PASS](./scenarios/refund/refund-with-reason.md#connector-authorizedotnet) | `create_customer(create_customer)` (PASS) -> `authorize(no3ds_auto_capture_credit_card)` (PASS) |
| `paypal` | [PASS](./scenarios/refund/refund-with-reason.md#connector-paypal) | `create_access_token(create_access_token)` (PASS) -> `authorize(no3ds_auto_capture_credit_card)` (PASS) |
| `stripe` | [PASS](./scenarios/refund/refund-with-reason.md#connector-stripe) | `create_customer(create_customer)` (PASS) -> `authorize(no3ds_auto_capture_credit_card)` (PASS) |

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
  "merchant_customer_id": "mcui_259266764b8f476580559d4309093e53",
  "customer_name": "Liam Smith",
  "email": {
    "value": "jordan.9216@sandbox.example.com"
  },
  "phone_number": "+17849174172",
  "address": {
    "shipping_address": {
      "first_name": {
        "value": "Ava"
      },
      "last_name": {
        "value": "Miller"
      },
      "line1": {
        "value": "1742 Oak Blvd"
      },
      "line2": {
        "value": "7206 Main Blvd"
      },
      "line3": {
        "value": "181 Main Ave"
      },
      "city": {
        "value": "Seattle"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "40580"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "sam.6835@sandbox.example.com"
      },
      "phone_number": {
        "value": "6982482654"
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
        "value": "5280 Oak Ln"
      },
      "line2": {
        "value": "5774 Oak Dr"
      },
      "line3": {
        "value": "8880 Lake Ave"
      },
      "city": {
        "value": "Austin"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "97530"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "jordan.8402@example.com"
      },
      "phone_number": {
        "value": "2853765551"
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
date: Thu, 12 Mar 2026 15:40:36 GMT
x-request-id: create_customer_create_customer_req

Response contents:
{
  "merchantCustomerId": "934839061",
  "connectorCustomerId": "934839061",
  "statusCode": 200,
  "responseHeaders": {
    "access-control-allow-credentials": "true",
    "access-control-allow-headers": "x-requested-with,cache-control,content-type,origin,method,SOAPAction",
    "access-control-allow-methods": "PUT,OPTIONS,POST,GET",
    "access-control-allow-origin": "*",
    "cache-control": "no-cache, no-store, max-age=0",
    "content-length": "232",
    "content-type": "application/json; charset=utf-8",
    "date": "Thu, 12 Mar 2026 15:40:36 GMT",
    "expires": "-1",
    "pragma": "no-cache",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-cnection": "close",
    "x-download-options": "noopen",
    "x-opnet-transaction-trace": "6275c255-1f58-458f-b516-e5c061e8590b-12436-10995044"
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
  "merchant_customer_id": "mcui_259266764b8f476580559d4309093e53",
  "customer_name": "Liam Smith",
  "email": {
    "value": "jordan.9216@sandbox.example.com"
  },
  "phone_number": "+17849174172",
  "address": {
    "shipping_address": {
      "first_name": {
        "value": "Ava"
      },
      "last_name": {
        "value": "Miller"
      },
      "line1": {
        "value": "1742 Oak Blvd"
      },
      "line2": {
        "value": "7206 Main Blvd"
      },
      "line3": {
        "value": "181 Main Ave"
      },
      "city": {
        "value": "Seattle"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "40580"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "sam.6835@sandbox.example.com"
      },
      "phone_number": {
        "value": "6982482654"
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
        "value": "5280 Oak Ln"
      },
      "line2": {
        "value": "5774 Oak Dr"
      },
      "line3": {
        "value": "8880 Lake Ave"
      },
      "city": {
        "value": "Austin"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "97530"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "jordan.8402@example.com"
      },
      "phone_number": {
        "value": "2853765551"
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
  "merchantCustomerId": "934839061",
  "connectorCustomerId": "934839061",
  "statusCode": 200,
  "responseHeaders": {
    "access-control-allow-credentials": "true",
    "access-control-allow-headers": "x-requested-with,cache-control,content-type,origin,method,SOAPAction",
    "access-control-allow-methods": "PUT,OPTIONS,POST,GET",
    "access-control-allow-origin": "*",
    "cache-control": "no-cache, no-store, max-age=0",
    "content-length": "232",
    "content-type": "application/json; charset=utf-8",
    "date": "Thu, 12 Mar 2026 15:40:36 GMT",
    "expires": "-1",
    "pragma": "no-cache",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-cnection": "close",
    "x-download-options": "noopen",
    "x-opnet-transaction-trace": "6275c255-1f58-458f-b516-e5c061e8590b-12436-10995044"
  }
}
```

</details>

</details>
<details>
<summary>2. authorize(no3ds_auto_capture_credit_card) — PASS</summary>

<details>
<summary>Show Dependency gRPC Request (masked)</summary>

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
  "merchant_transaction_id": "mti_cc2e1f0496d24ec1ac8286e7522fec82",
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
        "value": "Mia Taylor"
      },
      "card_type": "credit"
    }
  },
  "capture_method": "AUTOMATIC",
  "customer": {
    "name": "Liam Smith",
    "email": {
      "value": "casey.5783@testmail.io"
    },
    "id": "cust_5e0ab59b6a7140738c3621dbe5d921f5",
    "phone_number": "+13359542440",
    "connector_customer_id": "934839061"
  },
  "locale": "en-US",
  "address": {
    "shipping_address": {
      "first_name": {
        "value": "Ava"
      },
      "last_name": {
        "value": "Miller"
      },
      "line1": {
        "value": "1742 Oak Blvd"
      },
      "line2": {
        "value": "7206 Main Blvd"
      },
      "line3": {
        "value": "181 Main Ave"
      },
      "city": {
        "value": "Seattle"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "40580"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "sam.6835@sandbox.example.com"
      },
      "phone_number": {
        "value": "6982482654"
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
        "value": "5280 Oak Ln"
      },
      "line2": {
        "value": "5774 Oak Dr"
      },
      "line3": {
        "value": "8880 Lake Ave"
      },
      "city": {
        "value": "Austin"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "97530"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "jordan.8402@example.com"
      },
      "phone_number": {
        "value": "2853765551"
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
x-connector-request-reference-id: authorize_no3ds_auto_capture_credit_card_ref
x-key1: ***MASKED***
x-merchant-id: test_merchant
x-request-id: authorize_no3ds_auto_capture_credit_card_req
x-tenant-id: default

Response headers received:
content-type: application/grpc
date: Thu, 12 Mar 2026 15:40:37 GMT
x-request-id: authorize_no3ds_auto_capture_credit_card_req

Response contents:
{
  "merchantTransactionId": "120079432068",
  "connectorTransactionId": "120079432068",
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
    "date": "Thu, 12 Mar 2026 15:40:36 GMT",
    "expires": "-1",
    "pragma": "no-cache",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-cnection": "close",
    "x-download-options": "noopen",
    "x-opnet-transaction-trace": "39598f69-930a-4eea-a65b-19a85a5612aa-17512-11767179"
  },
  "networkTransactionId": "JMMRWUE7WNVIX83BOUBNDGJ",
  "state": {
    "connectorCustomerId": "934839061"
  },
  "rawConnectorResponse": {
    "value": "{\"transactionResponse\":{\"responseCode\":\"1\",\"authCode\":\"T4XA5J\",\"avsResultCode\":\"Y\",\"cvvResultCode\":\"P\",\"cavvResultCode\":\"2\",\"transId\":\"120079432068\",\"refTransID\":\"\",\"transHash\":\"\",\"testRequest\":\"0\",\"accountNumber\":\"XXXX1111\",\"accountType\":\"Visa\",\"messages\":[{\"code\":\"1\",\"description\":\"This transaction has been approved.\"}],\"transHashSha2\":\"140FDF75759FA2BA03B47A7D0FF2F10468694E06352D51B226F401B9DAFF1B3BCB30741AF3DC529432432F1EC26F2AD11AFD36FB1F1D666C26517DA680DFC6DA\",\"SupplementalDataQualificationIndicator\":0,\"networkTransId\":\"JMMRWUE7WNVIX83BOUBNDGJ\"},\"refId\":\"\",\"messages\":{\"resultCode\":\"Ok\",\"message\":[{\"code\":\"I00001\",\"text\":\"Successful.\"}]}}"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://apitest.authorize.net/xml/v1/request.api\",\"method\":\"POST\",\"headers\":{\"via\":\"HyperSwitch\",\"Content-Type\":\"application/json\"},\"body\":{\"createTransactionRequest\":{\"merchantAuthentication\":{\"name\":\"9ARWr5wz49D3\",\"transactionKey\":\"3d9SHV2699mgmHre\"},\"refId\":null,\"transactionRequest\":{\"transactionType\":\"authCaptureTransaction\",\"amount\":60.0,\"currencyCode\":\"USD\",\"payment\":{\"creditCard\":{\"cardNumber\":\"4111111111111111\",\"expirationDate\":\"2030-08\",\"cardCode\":\"999\"}},\"order\":{\"invoiceNumber\":\"Xag9vJ0dDsBEa18l7gf7\",\"description\":\"mti_cc2e1f0496d24ec1ac8286e7522fec82\"},\"customer\":{\"id\":\"934839061\",\"email\":\"casey.5783@testmail.io\"},\"billTo\":{\"firstName\":\"Emma\",\"lastName\":\"Johnson\",\"address\":\"5280 Oak Ln 5774 Oak Dr 8880 Lake Ave\",\"city\":\"Austin\",\"state\":\"CA\",\"zip\":\"97530\",\"country\":\"US\"}}}}}"
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
  "merchant_transaction_id": "mti_cc2e1f0496d24ec1ac8286e7522fec82",
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
        "value": "Mia Taylor"
      },
      "card_type": "credit"
    }
  },
  "capture_method": "AUTOMATIC",
  "customer": {
    "name": "Liam Smith",
    "email": {
      "value": "casey.5783@testmail.io"
    },
    "id": "cust_5e0ab59b6a7140738c3621dbe5d921f5",
    "phone_number": "+13359542440",
    "connector_customer_id": "934839061"
  },
  "locale": "en-US",
  "address": {
    "shipping_address": {
      "first_name": {
        "value": "Ava"
      },
      "last_name": {
        "value": "Miller"
      },
      "line1": {
        "value": "1742 Oak Blvd"
      },
      "line2": {
        "value": "7206 Main Blvd"
      },
      "line3": {
        "value": "181 Main Ave"
      },
      "city": {
        "value": "Seattle"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "40580"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "sam.6835@sandbox.example.com"
      },
      "phone_number": {
        "value": "6982482654"
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
        "value": "5280 Oak Ln"
      },
      "line2": {
        "value": "5774 Oak Dr"
      },
      "line3": {
        "value": "8880 Lake Ave"
      },
      "city": {
        "value": "Austin"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "97530"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "jordan.8402@example.com"
      },
      "phone_number": {
        "value": "2853765551"
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
<summary>Show Dependency Response Body</summary>

```json
{
  "merchantTransactionId": "120079432068",
  "connectorTransactionId": "120079432068",
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
    "date": "Thu, 12 Mar 2026 15:40:36 GMT",
    "expires": "-1",
    "pragma": "no-cache",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-cnection": "close",
    "x-download-options": "noopen",
    "x-opnet-transaction-trace": "39598f69-930a-4eea-a65b-19a85a5612aa-17512-11767179"
  },
  "networkTransactionId": "JMMRWUE7WNVIX83BOUBNDGJ",
  "state": {
    "connectorCustomerId": "934839061"
  },
  "rawConnectorResponse": {
    "value": "{\"transactionResponse\":{\"responseCode\":\"1\",\"authCode\":\"T4XA5J\",\"avsResultCode\":\"Y\",\"cvvResultCode\":\"P\",\"cavvResultCode\":\"2\",\"transId\":\"120079432068\",\"refTransID\":\"\",\"transHash\":\"\",\"testRequest\":\"0\",\"accountNumber\":\"XXXX1111\",\"accountType\":\"Visa\",\"messages\":[{\"code\":\"1\",\"description\":\"This transaction has been approved.\"}],\"transHashSha2\":\"140FDF75759FA2BA03B47A7D0FF2F10468694E06352D51B226F401B9DAFF1B3BCB30741AF3DC529432432F1EC26F2AD11AFD36FB1F1D666C26517DA680DFC6DA\",\"SupplementalDataQualificationIndicator\":0,\"networkTransId\":\"JMMRWUE7WNVIX83BOUBNDGJ\"},\"refId\":\"\",\"messages\":{\"resultCode\":\"Ok\",\"message\":[{\"code\":\"I00001\",\"text\":\"Successful.\"}]}}"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://apitest.authorize.net/xml/v1/request.api\",\"method\":\"POST\",\"headers\":{\"via\":\"HyperSwitch\",\"Content-Type\":\"application/json\"},\"body\":{\"createTransactionRequest\":{\"merchantAuthentication\":{\"name\":\"9ARWr5wz49D3\",\"transactionKey\":\"3d9SHV2699mgmHre\"},\"refId\":null,\"transactionRequest\":{\"transactionType\":\"authCaptureTransaction\",\"amount\":60.0,\"currencyCode\":\"USD\",\"payment\":{\"creditCard\":{\"cardNumber\":\"4111111111111111\",\"expirationDate\":\"2030-08\",\"cardCode\":\"999\"}},\"order\":{\"invoiceNumber\":\"Xag9vJ0dDsBEa18l7gf7\",\"description\":\"mti_cc2e1f0496d24ec1ac8286e7522fec82\"},\"customer\":{\"id\":\"934839061\",\"email\":\"casey.5783@testmail.io\"},\"billTo\":{\"firstName\":\"Emma\",\"lastName\":\"Johnson\",\"address\":\"5280 Oak Ln 5774 Oak Dr 8880 Lake Ave\",\"city\":\"Austin\",\"state\":\"CA\",\"zip\":\"97530\",\"country\":\"US\"}}}}}"
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
  -H "x-request-id: refund_refund_with_reason_req" \
  -H "x-connector-request-reference-id: refund_refund_with_reason_ref" \
  -H "x-auth: ***MASKED***" \
  -H "x-api-key: ***MASKED***" \
  -H "x-key1: ***MASKED***" \
  -d @ localhost:8000 types.PaymentService/Refund <<'JSON'
{
  "merchant_refund_id": "mri_f958a2890f1d42c4a0471f7146a85e6f",
  "connector_transaction_id": "120079432068",
  "payment_amount": 6000,
  "refund_amount": {
    "minor_amount": 6000,
    "currency": "USD"
  },
  "state": {
    "connector_customer_id": "934839061"
  },
  "reason": "customer_requested",
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
// Initiate a refund to customer's payment method. Returns funds for
// returns, cancellations, or service adjustments after original payment.
rpc Refund ( .types.PaymentServiceRefundRequest ) returns ( .types.RefundResponse );

Request metadata to send:
x-api-key: ***MASKED***
x-auth: ***MASKED***
x-connector: authorizedotnet
x-connector-request-reference-id: refund_refund_with_reason_ref
x-key1: ***MASKED***
x-merchant-id: test_merchant
x-request-id: refund_refund_with_reason_req
x-tenant-id: default

Response headers received:
content-type: application/grpc
date: Thu, 12 Mar 2026 15:40:37 GMT
x-request-id: refund_refund_with_reason_req

Response contents:
{
  "status": 21,
  "error": {
    "connectorDetails": {
      "code": "54",
      "message": "The referenced transaction does not meet the criteria for issuing a credit.",
      "reason": "The referenced transaction does not meet the criteria for issuing a credit."
    }
  },
  "statusCode": 200,
  "responseHeaders": {
    "access-control-allow-credentials": "true",
    "access-control-allow-headers": "x-requested-with,cache-control,content-type,origin,method,SOAPAction",
    "access-control-allow-methods": "PUT,OPTIONS,POST,GET",
    "access-control-allow-origin": "*",
    "cache-control": "no-cache, no-store, max-age=0",
    "content-length": "660",
    "content-type": "application/json; charset=utf-8",
    "date": "Thu, 12 Mar 2026 15:40:36 GMT",
    "expires": "-1",
    "pragma": "no-cache",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-cnection": "close",
    "x-download-options": "noopen",
    "x-opnet-transaction-trace": "6275c255-1f58-458f-b516-e5c061e8590b-12436-10995356"
  },
  "connectorTransactionId": "0",
  "rawConnectorResponse": {
    "value": "{\"transactionResponse\":{\"responseCode\":\"3\",\"authCode\":\"\",\"avsResultCode\":\"P\",\"cvvResultCode\":\"\",\"cavvResultCode\":\"\",\"transId\":\"0\",\"refTransID\":\"120079432068\",\"transHash\":\"\",\"testRequest\":\"0\",\"accountNumber\":\"XXXX1111\",\"accountType\":\"Visa\",\"errors\":[{\"errorCode\":\"54\",\"errorText\":\"The referenced transaction does not meet the criteria for issuing a credit.\"}],\"transHashSha2\":\"DD3364110A093C5B08CE258A80B1450D9C5F96D5660F945A2BD49A1313FF4686A48816A23495ABCF6ADEB86E932EB19953A4E582EB3CE124A9C915015BBABCD7\",\"SupplementalDataQualificationIndicator\":0},\"messages\":{\"resultCode\":\"Error\",\"message\":[{\"code\":\"E00027\",\"text\":\"The transaction was unsuccessful.\"}]}}"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://apitest.authorize.net/xml/v1/request.api\",\"method\":\"POST\",\"headers\":{\"via\":\"HyperSwitch\",\"Content-Type\":\"application/json\"},\"body\":{\"createTransactionRequest\":{\"merchantAuthentication\":{\"name\":\"9ARWr5wz49D3\",\"transactionKey\":\"3d9SHV2699mgmHre\"},\"transactionRequest\":{\"transactionType\":\"refundTransaction\",\"amount\":60.0,\"currencyCode\":\"USD\",\"payment\":{\"creditCard\":{\"cardNumber\":\"XXXX1111\",\"expirationDate\":\"XXXX\"}},\"refTransId\":\"120079432068\"}}}}"
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
  "merchant_refund_id": "mri_f958a2890f1d42c4a0471f7146a85e6f",
  "connector_transaction_id": "120079432068",
  "payment_amount": 6000,
  "refund_amount": {
    "minor_amount": 6000,
    "currency": "USD"
  },
  "state": {
    "connector_customer_id": "934839061"
  },
  "reason": "customer_requested",
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
  "status": 21,
  "error": {
    "connectorDetails": {
      "code": "54",
      "message": "The referenced transaction does not meet the criteria for issuing a credit.",
      "reason": "The referenced transaction does not meet the criteria for issuing a credit."
    }
  },
  "statusCode": 200,
  "responseHeaders": {
    "access-control-allow-credentials": "true",
    "access-control-allow-headers": "x-requested-with,cache-control,content-type,origin,method,SOAPAction",
    "access-control-allow-methods": "PUT,OPTIONS,POST,GET",
    "access-control-allow-origin": "*",
    "cache-control": "no-cache, no-store, max-age=0",
    "content-length": "660",
    "content-type": "application/json; charset=utf-8",
    "date": "Thu, 12 Mar 2026 15:40:36 GMT",
    "expires": "-1",
    "pragma": "no-cache",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-cnection": "close",
    "x-download-options": "noopen",
    "x-opnet-transaction-trace": "6275c255-1f58-458f-b516-e5c061e8590b-12436-10995356"
  },
  "connectorTransactionId": "0",
  "rawConnectorResponse": {
    "value": "{\"transactionResponse\":{\"responseCode\":\"3\",\"authCode\":\"\",\"avsResultCode\":\"P\",\"cvvResultCode\":\"\",\"cavvResultCode\":\"\",\"transId\":\"0\",\"refTransID\":\"120079432068\",\"transHash\":\"\",\"testRequest\":\"0\",\"accountNumber\":\"XXXX1111\",\"accountType\":\"Visa\",\"errors\":[{\"errorCode\":\"54\",\"errorText\":\"The referenced transaction does not meet the criteria for issuing a credit.\"}],\"transHashSha2\":\"DD3364110A093C5B08CE258A80B1450D9C5F96D5660F945A2BD49A1313FF4686A48816A23495ABCF6ADEB86E932EB19953A4E582EB3CE124A9C915015BBABCD7\",\"SupplementalDataQualificationIndicator\":0},\"messages\":{\"resultCode\":\"Error\",\"message\":[{\"code\":\"E00027\",\"text\":\"The transaction was unsuccessful.\"}]}}"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://apitest.authorize.net/xml/v1/request.api\",\"method\":\"POST\",\"headers\":{\"via\":\"HyperSwitch\",\"Content-Type\":\"application/json\"},\"body\":{\"createTransactionRequest\":{\"merchantAuthentication\":{\"name\":\"9ARWr5wz49D3\",\"transactionKey\":\"3d9SHV2699mgmHre\"},\"transactionRequest\":{\"transactionType\":\"refundTransaction\",\"amount\":60.0,\"currencyCode\":\"USD\",\"payment\":{\"creditCard\":{\"cardNumber\":\"XXXX1111\",\"expirationDate\":\"XXXX\"}},\"refTransId\":\"120079432068\"}}}}"
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
date: Thu, 12 Mar 2026 15:41:51 GMT
x-request-id: create_access_token_create_access_token_req

Response contents:
{
  "accessToken": ***MASKED***
    "value": "A21AAIimoa-rtl4fS-Ww8qyaVqqMy85SmTVtYFXjFdA8emovXqLOH2syMZB9-jr5IkNejzMI3nGlOB7HG9auRQqlejeSk0Q_A"
  },
  "expiresInSeconds": "30487",
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
  "expiresInSeconds": "30487",
  "status": "OPERATION_STATUS_SUCCESS",
  "statusCode": 200
}
```

</details>

</details>
<details>
<summary>2. authorize(no3ds_auto_capture_credit_card) — PASS</summary>

<details>
<summary>Show Dependency gRPC Request (masked)</summary>

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
  "merchant_transaction_id": "mti_717f8c43984a4d9e8f253595d27cf87c",
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
        "value": "Ava Taylor"
      },
      "card_type": "credit"
    }
  },
  "capture_method": "AUTOMATIC",
  "customer": {
    "name": "Ethan Brown",
    "email": {
      "value": "jordan.2622@testmail.io"
    },
    "id": "cust_9432e38f531243f9905e30c32006e24e",
    "phone_number": "+19653119745"
  },
  "state": {
    "access_token": ***MASKED***
      "token": ***MASKED***
        "value": "A21AAIimoa-rtl4fS-Ww8qyaVqqMy85SmTVtYFXjFdA8emovXqLOH2syMZB9-jr5IkNejzMI3nGlOB7HG9auRQqlejeSk0Q_A"
      },
      "expires_in_seconds": "30487"
    }
  },
  "address": {
    "shipping_address": {
      "first_name": {
        "value": "Ethan"
      },
      "last_name": {
        "value": "Smith"
      },
      "line1": {
        "value": "96 Sunset Ave"
      },
      "line2": {
        "value": "4111 Main St"
      },
      "line3": {
        "value": "8092 Main St"
      },
      "city": {
        "value": "Austin"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "15276"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "riley.7787@example.com"
      },
      "phone_number": {
        "value": "3817847466"
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
        "value": "2649 Pine St"
      },
      "line2": {
        "value": "2980 Market Ave"
      },
      "line3": {
        "value": "4308 Oak Ln"
      },
      "city": {
        "value": "New York"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "36062"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "jordan.3396@sandbox.example.com"
      },
      "phone_number": {
        "value": "1738329896"
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
x-connector-request-reference-id: authorize_no3ds_auto_capture_credit_card_ref
x-key1: ***MASKED***
x-merchant-id: test_merchant
x-request-id: authorize_no3ds_auto_capture_credit_card_req
x-tenant-id: default

Response headers received:
content-type: application/grpc
date: Thu, 12 Mar 2026 15:41:54 GMT
x-request-id: authorize_no3ds_auto_capture_credit_card_req

Response contents:
{
  "merchantTransactionId": "mti_717f8c43984a4d9e8f253595d27cf87c",
  "connectorTransactionId": "8LD917727K092651J",
  "status": "CHARGED",
  "statusCode": 201,
  "responseHeaders": {
    "accept-ranges": "bytes",
    "access-control-expose-headers": "Server-Timing",
    "cache-control": "max-age=0, no-cache, no-store, must-revalidate",
    "connection": "keep-alive",
    "content-length": "2391",
    "content-type": "application/json",
    "date": "Thu, 12 Mar 2026 15:41:54 GMT",
    "edge-control": "max-age=0",
    "http_x_pp_az_locator": "ccg18.slc",
    "paypal-debug-id": "f9276289a85c7",
    "server": "nginx",
    "server-timing": "traceparent;desc=\"00-0000000000000000000f9276289a85c7-cc8ca5729ae84534-01\"",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "vary": "Accept-Encoding",
    "via": "1.1 varnish, 1.1 varnish",
    "x-cache": "MISS, MISS",
    "x-cache-hits": "0, 0",
    "x-served-by": "cache-sin-wsat1880052-SIN, cache-bom-vanm7210086-BOM",
    "x-timer": "S1773330112.682644,VS0,VE2683"
  },
  "state": {
    "accessToken": ***MASKED***
      "token": ***MASKED***
        "value": "A21AAIimoa-rtl4fS-Ww8qyaVqqMy85SmTVtYFXjFdA8emovXqLOH2syMZB9-jr5IkNejzMI3nGlOB7HG9auRQqlejeSk0Q_A"
      },
      "expiresInSeconds": "30487"
    }
  },
  "rawConnectorResponse": {
    "value": "{\"id\":\"8LD917727K092651J\",\"intent\":\"CAPTURE\",\"status\":\"COMPLETED\",\"payment_source\":{\"card\":{\"name\":\"Ava Wilson\",\"last_digits\":\"1111\",\"expiry\":\"2030-08\",\"brand\":\"VISA\",\"type\":\"CREDIT\",\"bin_details\":{}}},\"purchase_units\":[{\"reference_id\":\"mti_717f8c43984a4d9e8f253595d27cf87c\",\"amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\",\"breakdown\":{\"item_total\":{\"currency_code\":\"USD\",\"value\":\"60.00\"},\"shipping\":{\"currency_code\":\"USD\",\"value\":\"0.00\"},\"handling\":{\"currency_code\":\"USD\",\"value\":\"0.00\"},\"tax_total\":{\"currency_code\":\"USD\",\"value\":\"0.00\"},\"insurance\":{\"currency_code\":\"USD\",\"value\":\"0.00\"},\"shipping_discount\":{\"currency_code\":\"USD\",\"value\":\"0.00\"}}},\"payee\":{\"email_address\":\"sb-itwmi27136406@business.example.com\",\"merchant_id\":\"DUM69V9DDNYEJ\"},\"description\":\"Payment for invoice mti_717f8c43984a4d9e8f253595d27cf87c\",\"invoice_id\":\"mti_717f8c43984a4d9e8f253595d27cf87c\",\"soft_descriptor\":\"TEST STORE\",\"items\":[{\"name\":\"Payment for invoice mti_717f8c43984a4d9e8f253595d27cf87c\",\"unit_amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\"},\"tax\":{\"currency_code\":\"USD\",\"value\":\"0.00\"},\"quantity\":\"1\"}],\"shipping\":{\"name\":{\"full_name\":\"Ethan\"},\"address\":{\"address_line_1\":\"96 Sunset Ave\",\"admin_area_2\":\"Austin\",\"postal_code\":\"15276\",\"country_code\":\"US\"}},\"payments\":{\"captures\":[{\"id\":\"0XR04304P96285725\",\"status\":\"COMPLETED\",\"amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\"},\"final_capture\":true,\"seller_protection\":{\"status\":\"NOT_ELIGIBLE\"},\"seller_receivable_breakdown\":{\"gross_amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\"},\"net_amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\"}},\"invoice_id\":\"mti_717f8c43984a4d9e8f253595d27cf87c\",\"links\":[{\"href\":\"https://api.sandbox.paypal.com/v2/payments/captures/0XR04304P96285725\",\"rel\":\"self\",\"method\":\"GET\"},{\"href\":\"https://api.sandbox.paypal.com/v2/payments/captures/0XR04304P96285725/refund\",\"rel\":\"refund\",\"method\":\"POST\"},{\"href\":\"https://api.sandbox.paypal.com/v2/checkout/orders/8LD917727K092651J\",\"rel\":\"up\",\"method\":\"GET\"}],\"create_time\":\"2026-03-12T15:41:54Z\",\"update_time\":\"2026-03-12T15:41:54Z\",\"network_transaction_reference\":{\"id\":\"475622883751988\",\"network\":\"VISA\"},\"processor_response\":{\"avs_code\":\"A\",\"cvv_code\":\"M\",\"response_code\":\"0000\"}}]}}],\"create_time\":\"2026-03-12T15:41:54Z\",\"update_time\":\"2026-03-12T15:41:54Z\",\"links\":[{\"href\":\"https://api.sandbox.paypal.com/v2/checkout/orders/8LD917727K092651J\",\"rel\":\"self\",\"method\":\"GET\"}]}"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://api-m.sandbox.paypal.com/v2/checkout/orders\",\"method\":\"POST\",\"headers\":{\"Authorization\":\"Bearer ***MASKED***",\"PayPal-Request-Id\":\"mti_717f8c43984a4d9e8f253595d27cf87c\",\"Prefer\":\"return=representation\",\"PayPal-Partner-Attribution-Id\":\"HyperSwitchlegacy_Ecom\",\"Content-Type\":\"application/json\",\"via\":\"HyperSwitch\"},\"body\":{\"intent\":\"CAPTURE\",\"purchase_units\":[{\"reference_id\":\"mti_717f8c43984a4d9e8f253595d27cf87c\",\"invoice_id\":\"mti_717f8c43984a4d9e8f253595d27cf87c\",\"custom_id\":null,\"amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\",\"breakdown\":{\"item_total\":{\"currency_code\":\"USD\",\"value\":\"60.00\"},\"tax_total\":null,\"shipping\":{\"currency_code\":\"USD\",\"value\":\"0.00\"}}},\"shipping\":{\"address\":{\"address_line_1\":\"96 Sunset Ave\",\"postal_code\":\"15276\",\"country_code\":\"US\",\"admin_area_2\":\"Austin\"},\"name\":{\"full_name\":\"Ethan\"}},\"items\":[{\"name\":\"Payment for invoice mti_717f8c43984a4d9e8f253595d27cf87c\",\"quantity\":1,\"unit_amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\"},\"tax\":null}]}],\"payment_source\":{\"card\":{\"billing_address\":{\"address_line_1\":\"2649 Pine St\",\"postal_code\":\"36062\",\"country_code\":\"US\",\"admin_area_2\":\"New York\"},\"expiry\":\"2030-08\",\"name\":\"Ava Wilson\",\"number\":\"4111111111111111\",\"security_code\":\"999\",\"attributes\":{\"vault\":null,\"verification\":null}}}}}"
  },
  "mandateReference": {
    "connectorMandateId": {}
  },
  "connectorFeatureData": {
    "value": "{\"authorize_id\":null,\"capture_id\":\"0XR04304P96285725\",\"incremental_authorization_id\":null,\"psync_flow\":\"CAPTURE\",\"next_action\":null,\"order_id\":null}"
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
  "merchant_transaction_id": "mti_717f8c43984a4d9e8f253595d27cf87c",
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
        "value": "Ava Taylor"
      },
      "card_type": "credit"
    }
  },
  "capture_method": "AUTOMATIC",
  "customer": {
    "name": "Ethan Brown",
    "email": {
      "value": "jordan.2622@testmail.io"
    },
    "id": "cust_9432e38f531243f9905e30c32006e24e",
    "phone_number": "+19653119745"
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
        "value": "Smith"
      },
      "line1": {
        "value": "96 Sunset Ave"
      },
      "line2": {
        "value": "4111 Main St"
      },
      "line3": {
        "value": "8092 Main St"
      },
      "city": {
        "value": "Austin"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "15276"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "riley.7787@example.com"
      },
      "phone_number": {
        "value": "3817847466"
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
        "value": "2649 Pine St"
      },
      "line2": {
        "value": "2980 Market Ave"
      },
      "line3": {
        "value": "4308 Oak Ln"
      },
      "city": {
        "value": "New York"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "36062"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "jordan.3396@sandbox.example.com"
      },
      "phone_number": {
        "value": "1738329896"
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
<summary>Show Dependency Response Body</summary>

```json
{
  "merchantTransactionId": "mti_717f8c43984a4d9e8f253595d27cf87c",
  "connectorTransactionId": "8LD917727K092651J",
  "status": "CHARGED",
  "statusCode": 201,
  "responseHeaders": {
    "accept-ranges": "bytes",
    "access-control-expose-headers": "Server-Timing",
    "cache-control": "max-age=0, no-cache, no-store, must-revalidate",
    "connection": "keep-alive",
    "content-length": "2391",
    "content-type": "application/json",
    "date": "Thu, 12 Mar 2026 15:41:54 GMT",
    "edge-control": "max-age=0",
    "http_x_pp_az_locator": "ccg18.slc",
    "paypal-debug-id": "f9276289a85c7",
    "server": "nginx",
    "server-timing": "traceparent;desc=\"00-0000000000000000000f9276289a85c7-cc8ca5729ae84534-01\"",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "vary": "Accept-Encoding",
    "via": "1.1 varnish, 1.1 varnish",
    "x-cache": "MISS, MISS",
    "x-cache-hits": "0, 0",
    "x-served-by": "cache-sin-wsat1880052-SIN, cache-bom-vanm7210086-BOM",
    "x-timer": "S1773330112.682644,VS0,VE2683"
  },
  "state": {
    "accessToken": "***MASKED***"
  },
  "rawConnectorResponse": {
    "value": "{\"id\":\"8LD917727K092651J\",\"intent\":\"CAPTURE\",\"status\":\"COMPLETED\",\"payment_source\":{\"card\":{\"name\":\"Ava Wilson\",\"last_digits\":\"1111\",\"expiry\":\"2030-08\",\"brand\":\"VISA\",\"type\":\"CREDIT\",\"bin_details\":{}}},\"purchase_units\":[{\"reference_id\":\"mti_717f8c43984a4d9e8f253595d27cf87c\",\"amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\",\"breakdown\":{\"item_total\":{\"currency_code\":\"USD\",\"value\":\"60.00\"},\"shipping\":{\"currency_code\":\"USD\",\"value\":\"0.00\"},\"handling\":{\"currency_code\":\"USD\",\"value\":\"0.00\"},\"tax_total\":{\"currency_code\":\"USD\",\"value\":\"0.00\"},\"insurance\":{\"currency_code\":\"USD\",\"value\":\"0.00\"},\"shipping_discount\":{\"currency_code\":\"USD\",\"value\":\"0.00\"}}},\"payee\":{\"email_address\":\"sb-itwmi27136406@business.example.com\",\"merchant_id\":\"DUM69V9DDNYEJ\"},\"description\":\"Payment for invoice mti_717f8c43984a4d9e8f253595d27cf87c\",\"invoice_id\":\"mti_717f8c43984a4d9e8f253595d27cf87c\",\"soft_descriptor\":\"TEST STORE\",\"items\":[{\"name\":\"Payment for invoice mti_717f8c43984a4d9e8f253595d27cf87c\",\"unit_amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\"},\"tax\":{\"currency_code\":\"USD\",\"value\":\"0.00\"},\"quantity\":\"1\"}],\"shipping\":{\"name\":{\"full_name\":\"Ethan\"},\"address\":{\"address_line_1\":\"96 Sunset Ave\",\"admin_area_2\":\"Austin\",\"postal_code\":\"15276\",\"country_code\":\"US\"}},\"payments\":{\"captures\":[{\"id\":\"0XR04304P96285725\",\"status\":\"COMPLETED\",\"amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\"},\"final_capture\":true,\"seller_protection\":{\"status\":\"NOT_ELIGIBLE\"},\"seller_receivable_breakdown\":{\"gross_amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\"},\"net_amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\"}},\"invoice_id\":\"mti_717f8c43984a4d9e8f253595d27cf87c\",\"links\":[{\"href\":\"https://api.sandbox.paypal.com/v2/payments/captures/0XR04304P96285725\",\"rel\":\"self\",\"method\":\"GET\"},{\"href\":\"https://api.sandbox.paypal.com/v2/payments/captures/0XR04304P96285725/refund\",\"rel\":\"refund\",\"method\":\"POST\"},{\"href\":\"https://api.sandbox.paypal.com/v2/checkout/orders/8LD917727K092651J\",\"rel\":\"up\",\"method\":\"GET\"}],\"create_time\":\"2026-03-12T15:41:54Z\",\"update_time\":\"2026-03-12T15:41:54Z\",\"network_transaction_reference\":{\"id\":\"475622883751988\",\"network\":\"VISA\"},\"processor_response\":{\"avs_code\":\"A\",\"cvv_code\":\"M\",\"response_code\":\"0000\"}}]}}],\"create_time\":\"2026-03-12T15:41:54Z\",\"update_time\":\"2026-03-12T15:41:54Z\",\"links\":[{\"href\":\"https://api.sandbox.paypal.com/v2/checkout/orders/8LD917727K092651J\",\"rel\":\"self\",\"method\":\"GET\"}]}"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://api-m.sandbox.paypal.com/v2/checkout/orders\",\"method\":\"POST\",\"headers\":{\"Authorization\":\"Bearer ***MASKED***\",\"PayPal-Request-Id\":\"mti_717f8c43984a4d9e8f253595d27cf87c\",\"Prefer\":\"return=representation\",\"PayPal-Partner-Attribution-Id\":\"HyperSwitchlegacy_Ecom\",\"Content-Type\":\"application/json\",\"via\":\"HyperSwitch\"},\"body\":{\"intent\":\"CAPTURE\",\"purchase_units\":[{\"reference_id\":\"mti_717f8c43984a4d9e8f253595d27cf87c\",\"invoice_id\":\"mti_717f8c43984a4d9e8f253595d27cf87c\",\"custom_id\":null,\"amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\",\"breakdown\":{\"item_total\":{\"currency_code\":\"USD\",\"value\":\"60.00\"},\"tax_total\":null,\"shipping\":{\"currency_code\":\"USD\",\"value\":\"0.00\"}}},\"shipping\":{\"address\":{\"address_line_1\":\"96 Sunset Ave\",\"postal_code\":\"15276\",\"country_code\":\"US\",\"admin_area_2\":\"Austin\"},\"name\":{\"full_name\":\"Ethan\"}},\"items\":[{\"name\":\"Payment for invoice mti_717f8c43984a4d9e8f253595d27cf87c\",\"quantity\":1,\"unit_amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\"},\"tax\":null}]}],\"payment_source\":{\"card\":{\"billing_address\":{\"address_line_1\":\"2649 Pine St\",\"postal_code\":\"36062\",\"country_code\":\"US\",\"admin_area_2\":\"New York\"},\"expiry\":\"2030-08\",\"name\":\"Ava Wilson\",\"number\":\"4111111111111111\",\"security_code\":\"999\",\"attributes\":{\"vault\":null,\"verification\":null}}}}}"
  },
  "mandateReference": {
    "connectorMandateId": {}
  },
  "connectorFeatureData": {
    "value": "{\"authorize_id\":null,\"capture_id\":\"0XR04304P96285725\",\"incremental_authorization_id\":null,\"psync_flow\":\"CAPTURE\",\"next_action\":null,\"order_id\":null}"
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
  -H "x-request-id: refund_refund_with_reason_req" \
  -H "x-connector-request-reference-id: refund_refund_with_reason_ref" \
  -H "x-auth: ***MASKED***" \
  -H "x-api-key: ***MASKED***" \
  -H "x-key1: ***MASKED***" \
  -d @ localhost:8000 types.PaymentService/Refund <<'JSON'
{
  "merchant_refund_id": "mri_bdc323bf549e43ac9406c19e24403e9c",
  "connector_transaction_id": "8LD917727K092651J",
  "payment_amount": 6000,
  "refund_amount": {
    "minor_amount": 6000,
    "currency": "USD"
  },
  "state": {
    "access_token": ***MASKED***
      "token": ***MASKED***
        "value": "A21AAIimoa-rtl4fS-Ww8qyaVqqMy85SmTVtYFXjFdA8emovXqLOH2syMZB9-jr5IkNejzMI3nGlOB7HG9auRQqlejeSk0Q_A"
      },
      "expires_in_seconds": "30487"
    }
  },
  "reason": "customer_requested",
  "connector_feature_data": {
    "value": "{\"authorize_id\":null,\"capture_id\":\"0XR04304P96285725\",\"incremental_authorization_id\":null,\"psync_flow\":\"CAPTURE\",\"next_action\":null,\"order_id\":null}"
  }
}
JSON
```

</details>

<details>
<summary>Show gRPC Response (masked)</summary>

```text
Resolved method descriptor:
// Initiate a refund to customer's payment method. Returns funds for
// returns, cancellations, or service adjustments after original payment.
rpc Refund ( .types.PaymentServiceRefundRequest ) returns ( .types.RefundResponse );

Request metadata to send:
x-api-key: ***MASKED***
x-auth: ***MASKED***
x-connector: paypal
x-connector-request-reference-id: refund_refund_with_reason_ref
x-key1: ***MASKED***
x-merchant-id: test_merchant
x-request-id: refund_refund_with_reason_req
x-tenant-id: default

Response headers received:
content-type: application/grpc
date: Thu, 12 Mar 2026 15:41:56 GMT
x-request-id: refund_refund_with_reason_req

Response contents:
{
  "connectorRefundId": "6TP39595DS263142T",
  "status": "REFUND_SUCCESS",
  "statusCode": 201,
  "responseHeaders": {
    "accept-ranges": "bytes",
    "access-control-expose-headers": "Server-Timing",
    "cache-control": "max-age=0, no-cache, no-store, must-revalidate",
    "connection": "keep-alive",
    "content-length": "710",
    "content-type": "application/json",
    "date": "Thu, 12 Mar 2026 15:41:56 GMT",
    "edge-control": "max-age=0",
    "http_x_pp_az_locator": "ccg18.slc",
    "paypal-debug-id": "f906979b39573",
    "server": "nginx",
    "server-timing": "traceparent;desc=\"00-0000000000000000000f906979b39573-90df8f13bd4a3fa8-01\"",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "vary": "Accept-Encoding",
    "via": "1.1 varnish, 1.1 varnish",
    "x-cache": "MISS, MISS",
    "x-cache-hits": "0, 0",
    "x-served-by": "cache-sin-wsss1830020-SIN, cache-bom-vanm7210086-BOM",
    "x-timer": "S1773330115.541318,VS0,VE2369"
  },
  "rawConnectorResponse": {
    "value": "{\"id\":\"6TP39595DS263142T\",\"amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\"},\"seller_payable_breakdown\":{\"gross_amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\"},\"paypal_fee\":{\"currency_code\":\"USD\",\"value\":\"0.00\"},\"net_amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\"},\"total_refunded_amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\"}},\"invoice_id\":\"mti_717f8c43984a4d9e8f253595d27cf87c\",\"status\":\"COMPLETED\",\"create_time\":\"2026-03-12T08:41:55-07:00\",\"update_time\":\"2026-03-12T08:41:55-07:00\",\"links\":[{\"href\":\"https://api.sandbox.paypal.com/v2/payments/refunds/6TP39595DS263142T\",\"rel\":\"self\",\"method\":\"GET\"},{\"href\":\"https://api.sandbox.paypal.com/v2/payments/captures/0XR04304P96285725\",\"rel\":\"up\",\"method\":\"GET\"}]}"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://api-m.sandbox.paypal.com/v2/payments/captures/0XR04304P96285725/refund\",\"method\":\"POST\",\"headers\":{\"PayPal-Request-Id\":\"mri_bdc323bf549e43ac9406c19e24403e9c\",\"Content-Type\":\"application/json\",\"via\":\"HyperSwitch\",\"Prefer\":\"return=representation\",\"PayPal-Partner-Attribution-Id\":\"HyperSwitchlegacy_Ecom\",\"Authorization\":\"Bearer ***MASKED***"},\"body\":{\"amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\"}}}"
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
  "merchant_refund_id": "mri_bdc323bf549e43ac9406c19e24403e9c",
  "connector_transaction_id": "8LD917727K092651J",
  "payment_amount": 6000,
  "refund_amount": {
    "minor_amount": 6000,
    "currency": "USD"
  },
  "state": {
    "access_token": "***MASKED***"
  },
  "reason": "customer_requested",
  "connector_feature_data": {
    "value": "{\"authorize_id\":null,\"capture_id\":\"0XR04304P96285725\",\"incremental_authorization_id\":null,\"psync_flow\":\"CAPTURE\",\"next_action\":null,\"order_id\":null}"
  }
}
```

</details>

<details>
<summary>Show Response Body</summary>

```json
{
  "connectorRefundId": "6TP39595DS263142T",
  "status": "REFUND_SUCCESS",
  "statusCode": 201,
  "responseHeaders": {
    "accept-ranges": "bytes",
    "access-control-expose-headers": "Server-Timing",
    "cache-control": "max-age=0, no-cache, no-store, must-revalidate",
    "connection": "keep-alive",
    "content-length": "710",
    "content-type": "application/json",
    "date": "Thu, 12 Mar 2026 15:41:56 GMT",
    "edge-control": "max-age=0",
    "http_x_pp_az_locator": "ccg18.slc",
    "paypal-debug-id": "f906979b39573",
    "server": "nginx",
    "server-timing": "traceparent;desc=\"00-0000000000000000000f906979b39573-90df8f13bd4a3fa8-01\"",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "vary": "Accept-Encoding",
    "via": "1.1 varnish, 1.1 varnish",
    "x-cache": "MISS, MISS",
    "x-cache-hits": "0, 0",
    "x-served-by": "cache-sin-wsss1830020-SIN, cache-bom-vanm7210086-BOM",
    "x-timer": "S1773330115.541318,VS0,VE2369"
  },
  "rawConnectorResponse": {
    "value": "{\"id\":\"6TP39595DS263142T\",\"amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\"},\"seller_payable_breakdown\":{\"gross_amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\"},\"paypal_fee\":{\"currency_code\":\"USD\",\"value\":\"0.00\"},\"net_amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\"},\"total_refunded_amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\"}},\"invoice_id\":\"mti_717f8c43984a4d9e8f253595d27cf87c\",\"status\":\"COMPLETED\",\"create_time\":\"2026-03-12T08:41:55-07:00\",\"update_time\":\"2026-03-12T08:41:55-07:00\",\"links\":[{\"href\":\"https://api.sandbox.paypal.com/v2/payments/refunds/6TP39595DS263142T\",\"rel\":\"self\",\"method\":\"GET\"},{\"href\":\"https://api.sandbox.paypal.com/v2/payments/captures/0XR04304P96285725\",\"rel\":\"up\",\"method\":\"GET\"}]}"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://api-m.sandbox.paypal.com/v2/payments/captures/0XR04304P96285725/refund\",\"method\":\"POST\",\"headers\":{\"PayPal-Request-Id\":\"mri_bdc323bf549e43ac9406c19e24403e9c\",\"Content-Type\":\"application/json\",\"via\":\"HyperSwitch\",\"Prefer\":\"return=representation\",\"PayPal-Partner-Attribution-Id\":\"HyperSwitchlegacy_Ecom\",\"Authorization\":\"Bearer ***MASKED***\"},\"body\":{\"amount\":{\"currency_code\":\"USD\",\"value\":\"60.00\"}}}"
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
  "merchant_customer_id": "mcui_5a39981a17144828b894f63f4d3a1792",
  "customer_name": "Emma Taylor",
  "email": {
    "value": "sam.2742@sandbox.example.com"
  },
  "phone_number": "+447569802362",
  "address": {
    "shipping_address": {
      "first_name": {
        "value": "Mia"
      },
      "last_name": {
        "value": "Miller"
      },
      "line1": {
        "value": "9489 Main Ave"
      },
      "line2": {
        "value": "3007 Main Dr"
      },
      "line3": {
        "value": "2068 Sunset St"
      },
      "city": {
        "value": "Los Angeles"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "30219"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "jordan.5487@example.com"
      },
      "phone_number": {
        "value": "1519315685"
      },
      "phone_country_code": "+91"
    },
    "billing_address": {
      "first_name": {
        "value": "Liam"
      },
      "last_name": {
        "value": "Wilson"
      },
      "line1": {
        "value": "7312 Oak Ave"
      },
      "line2": {
        "value": "8969 Pine St"
      },
      "line3": {
        "value": "977 Market Ln"
      },
      "city": {
        "value": "Seattle"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "15145"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "alex.9111@testmail.io"
      },
      "phone_number": {
        "value": "5938054180"
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
date: Thu, 12 Mar 2026 15:43:09 GMT
x-request-id: create_customer_create_customer_req

Response contents:
{
  "merchantCustomerId": "cus_U8SI8Xv2Fm1dPw",
  "connectorCustomerId": "cus_U8SI8Xv2Fm1dPw",
  "statusCode": 200,
  "responseHeaders": {
    "access-control-allow-credentials": "true",
    "access-control-allow-methods": "GET, HEAD, PUT, PATCH, POST, DELETE",
    "access-control-allow-origin": "*",
    "access-control-expose-headers": "Request-Id, Stripe-Manage-Version, Stripe-Should-Retry, X-Stripe-External-Auth-Required, X-Stripe-Privileged-Session-Required",
    "access-control-max-age": "300",
    "cache-control": "no-cache, no-store",
    "connection": "keep-alive",
    "content-length": "677",
    "content-security-policy": "base-uri 'none'; default-src 'none'; form-action 'none'; frame-ancestors 'none'; img-src 'self'; script-src 'self' 'report-sample'; style-src 'self'; worker-src 'none'; upgrade-insecure-requests; report-uri https://q.stripe.com/csp-violation?q=XbpkE0Obtc-D-_OVcHByv3HX2Cz2ZXWthan_OSmhaX_cdx20p33NXUJkyzusgJOGoDWC714Lefdz6v3w",
    "content-type": "application/json",
    "date": "Thu, 12 Mar 2026 15:43:09 GMT",
    "idempotency-key": "e6ed23d0-bb8f-4a94-b44f-6a7c0013f00e",
    "original-request": "req_NQnSZbz6Hjs79Q",
    "request-id": "req_NQnSZbz6Hjs79Q",
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
  "merchant_customer_id": "mcui_5a39981a17144828b894f63f4d3a1792",
  "customer_name": "Emma Taylor",
  "email": {
    "value": "sam.2742@sandbox.example.com"
  },
  "phone_number": "+447569802362",
  "address": {
    "shipping_address": {
      "first_name": {
        "value": "Mia"
      },
      "last_name": {
        "value": "Miller"
      },
      "line1": {
        "value": "9489 Main Ave"
      },
      "line2": {
        "value": "3007 Main Dr"
      },
      "line3": {
        "value": "2068 Sunset St"
      },
      "city": {
        "value": "Los Angeles"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "30219"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "jordan.5487@example.com"
      },
      "phone_number": {
        "value": "1519315685"
      },
      "phone_country_code": "+91"
    },
    "billing_address": {
      "first_name": {
        "value": "Liam"
      },
      "last_name": {
        "value": "Wilson"
      },
      "line1": {
        "value": "7312 Oak Ave"
      },
      "line2": {
        "value": "8969 Pine St"
      },
      "line3": {
        "value": "977 Market Ln"
      },
      "city": {
        "value": "Seattle"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "15145"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "alex.9111@testmail.io"
      },
      "phone_number": {
        "value": "5938054180"
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
  "merchantCustomerId": "cus_U8SI8Xv2Fm1dPw",
  "connectorCustomerId": "cus_U8SI8Xv2Fm1dPw",
  "statusCode": 200,
  "responseHeaders": {
    "access-control-allow-credentials": "true",
    "access-control-allow-methods": "GET, HEAD, PUT, PATCH, POST, DELETE",
    "access-control-allow-origin": "*",
    "access-control-expose-headers": "Request-Id, Stripe-Manage-Version, Stripe-Should-Retry, X-Stripe-External-Auth-Required, X-Stripe-Privileged-Session-Required",
    "access-control-max-age": "300",
    "cache-control": "no-cache, no-store",
    "connection": "keep-alive",
    "content-length": "677",
    "content-security-policy": "base-uri 'none'; default-src 'none'; form-action 'none'; frame-ancestors 'none'; img-src 'self'; script-src 'self' 'report-sample'; style-src 'self'; worker-src 'none'; upgrade-insecure-requests; report-uri https://q.stripe.com/csp-violation?q=XbpkE0Obtc-D-_OVcHByv3HX2Cz2ZXWthan_OSmhaX_cdx20p33NXUJkyzusgJOGoDWC714Lefdz6v3w",
    "content-type": "application/json",
    "date": "Thu, 12 Mar 2026 15:43:09 GMT",
    "idempotency-key": "e6ed23d0-bb8f-4a94-b44f-6a7c0013f00e",
    "original-request": "req_NQnSZbz6Hjs79Q",
    "request-id": "req_NQnSZbz6Hjs79Q",
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
<summary>2. authorize(no3ds_auto_capture_credit_card) — PASS</summary>

<details>
<summary>Show Dependency gRPC Request (masked)</summary>

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
  "merchant_transaction_id": "mti_f834d6ff47b648b786e737f3c3fb2da3",
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
        "value": "Emma Brown"
      },
      "card_type": "credit"
    }
  },
  "capture_method": "AUTOMATIC",
  "customer": {
    "name": "Emma Taylor",
    "email": {
      "value": "casey.6855@testmail.io"
    },
    "id": "cust_bd9c48ad1a3b4e4f8942357a7c88ddb8",
    "phone_number": "+913812389851",
    "connector_customer_id": "cus_U8SI8Xv2Fm1dPw"
  },
  "locale": "en-US",
  "address": {
    "shipping_address": {
      "first_name": {
        "value": "Mia"
      },
      "last_name": {
        "value": "Miller"
      },
      "line1": {
        "value": "9489 Main Ave"
      },
      "line2": {
        "value": "3007 Main Dr"
      },
      "line3": {
        "value": "2068 Sunset St"
      },
      "city": {
        "value": "Los Angeles"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "30219"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "jordan.5487@example.com"
      },
      "phone_number": {
        "value": "1519315685"
      },
      "phone_country_code": "+91"
    },
    "billing_address": {
      "first_name": {
        "value": "Liam"
      },
      "last_name": {
        "value": "Wilson"
      },
      "line1": {
        "value": "7312 Oak Ave"
      },
      "line2": {
        "value": "8969 Pine St"
      },
      "line3": {
        "value": "977 Market Ln"
      },
      "city": {
        "value": "Seattle"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "15145"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "alex.9111@testmail.io"
      },
      "phone_number": {
        "value": "5938054180"
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
x-connector-request-reference-id: authorize_no3ds_auto_capture_credit_card_ref
x-merchant-id: test_merchant
x-request-id: authorize_no3ds_auto_capture_credit_card_req
x-tenant-id: default

Response headers received:
content-type: application/grpc
date: Thu, 12 Mar 2026 15:43:11 GMT
x-request-id: authorize_no3ds_auto_capture_credit_card_req

Response contents:
{
  "merchantTransactionId": "pi_3TABOED5R7gDAGff0EGOPlt7",
  "connectorTransactionId": "pi_3TABOED5R7gDAGff0EGOPlt7",
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
    "content-length": "5535",
    "content-security-policy": "base-uri 'none'; default-src 'none'; form-action 'none'; frame-ancestors 'none'; img-src 'self'; script-src 'self' 'report-sample'; style-src 'self'; worker-src 'none'; upgrade-insecure-requests; report-uri https://q.stripe.com/csp-violation?q=XbpkE0Obtc-D-_OVcHByv3HX2Cz2ZXWthan_OSmhaX_cdx20p33NXUJkyzusgJOGoDWC714Lefdz6v3w",
    "content-type": "application/json",
    "date": "Thu, 12 Mar 2026 15:43:11 GMT",
    "idempotency-key": "007b0635-6c97-43f9-baac-e65bb9bb2c6e",
    "original-request": "req_3DCC5A4DFkAt58",
    "request-id": "req_3DCC5A4DFkAt58",
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
    "connectorCustomerId": "cus_U8SI8Xv2Fm1dPw"
  },
  "rawConnectorResponse": {
    "value": "{\n  \"id\": \"pi_3TABOED5R7gDAGff0EGOPlt7\",\n  \"object\": \"payment_intent\",\n  \"amount\": 6000,\n  \"amount_capturable\": 0,\n  \"amount_details\": {\n    \"tip\": {}\n  },\n  \"amount_received\": 6000,\n  \"application\": null,\n  \"application_fee_amount\": null,\n  \"automatic_payment_methods\": null,\n  \"canceled_at\": null,\n  \"cancellation_reason\": null,\n  \"capture_method\": \"automatic\",\n  \"client_secret\": \"pi_3TABOED5R7gDAGff0EGOPlt7_secret_uaPbmqOdaoeZ0JSoxKHRyfTqz\",\n  \"confirmation_method\": \"automatic\",\n  \"created\": 1773330190,\n  \"currency\": \"usd\",\n  \"customer\": \"cus_U8SI8Xv2Fm1dPw\",\n  \"customer_account\": null,\n  \"description\": \"No3DS auto capture card payment (credit)\",\n  \"excluded_payment_method_types\": null,\n  \"invoice\": null,\n  \"last_payment_error\": null,\n  \"latest_charge\": {\n    \"id\": \"ch_3TABOED5R7gDAGff0Elcng4K\",\n    \"object\": \"charge\",\n    \"amount\": 6000,\n    \"amount_captured\": 6000,\n    \"amount_refunded\": 0,\n    \"amount_updates\": [],\n    \"application\": null,\n    \"application_fee\": null,\n    \"application_fee_amount\": null,\n    \"balance_transaction\": \"txn_3TABOED5R7gDAGff0JGZwKXY\",\n    \"billing_details\": {\n      \"address\": {\n        \"city\": \"Seattle\",\n        \"country\": \"US\",\n        \"line1\": \"7312 Oak Ave\",\n        \"line2\": \"8969 Pine St\",\n        \"postal_code\": \"15145\",\n        \"state\": \"CA\"\n      },\n      \"email\": \"alex.9111@testmail.io\",\n      \"name\": \"Liam Wilson\",\n      \"phone\": \"5938054180\",\n      \"tax_id\": null\n    },\n    \"calculated_statement_descriptor\": \"BERNARD\",\n    \"captured\": true,\n    \"created\": 1773330190,\n    \"currency\": \"usd\",\n    \"customer\": \"cus_U8SI8Xv2Fm1dPw\",\n    \"description\": \"No3DS auto capture card payment (credit)\",\n    \"destination\": null,\n    \"dispute\": null,\n    \"disputed\": false,\n    \"failure_balance_transaction\": null,\n    \"failure_code\": null,\n    \"failure_message\": null,\n    \"fraud_details\": {},\n    \"invoice\": null,\n    \"livemode\": false,\n    \"metadata\": {\n      \"order_id\": \"mti_f834d6ff47b648b786e737f3c3fb2da3\"\n    },\n    \"on_behalf_of\": null,\n    \"order\": null,\n    \"outcome\": {\n      \"advice_code\": null,\n      \"network_advice_code\": null,\n      \"network_decline_code\": null,\n      \"network_status\": \"approved_by_network\",\n      \"reason\": null,\n      \"risk_level\": \"normal\",\n      \"risk_score\": 34,\n      \"seller_message\": \"Payment complete.\",\n      \"type\": \"authorized\"\n    },\n    \"paid\": true,\n    \"payment_intent\": \"pi_3TABOED5R7gDAGff0EGOPlt7\",\n    \"payment_method\": \"pm_1TABOED5R7gDAGffvZoe5iF8\",\n    \"payment_method_details\": {\n      \"card\": {\n        \"amount_authorized\": 6000,\n        \"authorization_code\": \"829356\",\n        \"brand\": \"visa\",\n        \"checks\": {\n          \"address_line1_check\": \"pass\",\n          \"address_postal_code_check\": \"pass\",\n          \"cvc_check\": \"pass\"\n        },\n        \"country\": \"US\",\n        \"exp_month\": 8,\n        \"exp_year\": 2030,\n        \"extended_authorization\": {\n          \"status\": \"disabled\"\n        },\n        \"fingerprint\": \"aEed1rfhfa5JNpoz\",\n        \"funding\": \"credit\",\n        \"incremental_authorization\": {\n          \"status\": \"unavailable\"\n        },\n        \"installments\": null,\n        \"last4\": \"1111\",\n        \"mandate\": null,\n        \"moto\": null,\n        \"multicapture\": {\n          \"status\": \"unavailable\"\n        },\n        \"network\": \"visa\",\n        \"network_token\": {\n          \"used\": false\n        },\n        \"network_transaction_id\": \"976910110049114\",\n        \"overcapture\": {\n          \"maximum_amount_capturable\": 6000,\n          \"status\": \"unavailable\"\n        },\n        \"regulated_status\": \"unregulated\",\n        \"three_d_secure\": null,\n        \"wallet\": null\n      },\n      \"type\": \"card\"\n    },\n    \"radar_options\": {},\n    \"receipt_email\": null,\n    \"receipt_number\": null,\n    \"receipt_url\": \"https://pay.stripe.com/receipts/payment/CAcaFwoVYWNjdF8xTTdmVGFENVI3Z0RBR2ZmKI--y80GMgYKEUxy3H46LBZU9Nj8--HM-EQT4nFeAdWH4X-miQMxHzmMpMzkv6v0aqiCbJMrLROmTLq7\",\n    \"refunded\": false,\n    \"review\": null,\n    \"shipping\": {\n      \"address\": {\n        \"city\": \"Los Angeles\",\n        \"country\": \"US\",\n        \"line1\": \"9489 Main Ave\",\n        \"line2\": \"3007 Main Dr\",\n        \"postal_code\": \"30219\",\n        \"state\": \"CA\"\n      },\n      \"carrier\": null,\n      \"name\": \"Mia Miller\",\n      \"phone\": \"+911519315685\",\n      \"tracking_number\": null\n    },\n    \"source\": null,\n    \"source_transfer\": null,\n    \"statement_descriptor\": null,\n    \"statement_descriptor_suffix\": null,\n    \"status\": \"succeeded\",\n    \"transfer_data\": null,\n    \"transfer_group\": null\n  },\n  \"livemode\": false,\n  \"metadata\": {\n    \"order_id\": \"mti_f834d6ff47b648b786e737f3c3fb2da3\"\n  },\n  \"next_action\": null,\n  \"on_behalf_of\": null,\n  \"payment_method\": \"pm_1TABOED5R7gDAGffvZoe5iF8\",\n  \"payment_method_configuration_details\": null,\n  \"payment_method_options\": {\n    \"card\": {\n      \"installments\": null,\n      \"mandate_options\": null,\n      \"network\": null,\n      \"request_three_d_secure\": \"automatic\"\n    }\n  },\n  \"payment_method_types\": [\n    \"card\"\n  ],\n  \"processing\": null,\n  \"receipt_email\": null,\n  \"review\": null,\n  \"setup_future_usage\": \"on_session\",\n  \"shipping\": {\n    \"address\": {\n      \"city\": \"Los Angeles\",\n      \"country\": \"US\",\n      \"line1\": \"9489 Main Ave\",\n      \"line2\": \"3007 Main Dr\",\n      \"postal_code\": \"30219\",\n      \"state\": \"CA\"\n    },\n    \"carrier\": null,\n    \"name\": \"Mia Miller\",\n    \"phone\": \"+911519315685\",\n    \"tracking_number\": null\n  },\n  \"source\": null,\n  \"statement_descriptor\": null,\n  \"statement_descriptor_suffix\": null,\n  \"status\": \"succeeded\",\n  \"transfer_data\": null,\n  \"transfer_group\": null\n}"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://api.stripe.com/v1/payment_intents\",\"method\":\"POST\",\"headers\":{\"stripe-version\":\"2022-11-15\",\"Authorization\":\"Bearer ***MASKED***",\"via\":\"HyperSwitch\",\"Content-Type\":\"application/x-www-form-urlencoded\"},\"body\":\"amount=6000\u0026currency=USD\u0026metadata%5Border_id%5D=mti_f834d6ff47b648b786e737f3c3fb2da3\u0026return_url=https%3A%2F%2Fexample.com%2Fpayment%2Freturn\u0026confirm=true\u0026customer=cus_U8SI8Xv2Fm1dPw\u0026description=No3DS+auto+capture+card+payment+%28credit%29\u0026shipping%5Baddress%5D%5Bcity%5D=Los+Angeles\u0026shipping%5Baddress%5D%5Bcountry%5D=US\u0026shipping%5Baddress%5D%5Bline1%5D=9489+Main+Ave\u0026shipping%5Baddress%5D%5Bline2%5D=3007+Main+Dr\u0026shipping%5Baddress%5D%5Bpostal_code%5D=30219\u0026shipping%5Baddress%5D%5Bstate%5D=CA\u0026shipping%5Bname%5D=Mia+Miller\u0026shipping%5Bphone%5D=%2B911519315685\u0026payment_method_data%5Bbilling_details%5D%5Bemail%5D=alex.9111%40testmail.io\u0026payment_method_data%5Bbilling_details%5D%5Baddress%5D%5Bcountry%5D=US\u0026payment_method_data%5Bbilling_details%5D%5Bname%5D=Liam+Wilson\u0026payment_method_data%5Bbilling_details%5D%5Baddress%5D%5Bcity%5D=Seattle\u0026payment_method_data%5Bbilling_details%5D%5Baddress%5D%5Bline1%5D=7312+Oak+Ave\u0026payment_method_data%5Bbilling_details%5D%5Baddress%5D%5Bline2%5D=8969+Pine+St\u0026payment_method_data%5Bbilling_details%5D%5Baddress%5D%5Bpostal_code%5D=15145\u0026payment_method_data%5Bbilling_details%5D%5Baddress%5D%5Bstate%5D=CA\u0026payment_method_data%5Bbilling_details%5D%5Bphone%5D=5938054180\u0026payment_method_data%5Btype%5D=card\u0026payment_method_data%5Bcard%5D%5Bnumber%5D=4111111111111111\u0026payment_method_data%5Bcard%5D%5Bexp_month%5D=08\u0026payment_method_data%5Bcard%5D%5Bexp_year%5D=30\u0026payment_method_data%5Bcard%5D%5Bcvc%5D=999\u0026payment_method_options%5Bcard%5D%5Brequest_three_d_secure%5D=automatic\u0026capture_method=automatic\u0026setup_future_usage=on_session\u0026off_session=false\u0026payment_method_types%5B0%5D=card\u0026expand%5B0%5D=latest_charge\"}"
  },
  "capturedAmount": "6000",
  "mandateReference": {
    "connectorMandateId": {
      "connectorMandateId": "pm_1TABOED5R7gDAGffvZoe5iF8",
      "paymentMethodId": "pm_1TABOED5R7gDAGffvZoe5iF8"
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
  "merchant_transaction_id": "mti_f834d6ff47b648b786e737f3c3fb2da3",
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
        "value": "Emma Brown"
      },
      "card_type": "credit"
    }
  },
  "capture_method": "AUTOMATIC",
  "customer": {
    "name": "Emma Taylor",
    "email": {
      "value": "casey.6855@testmail.io"
    },
    "id": "cust_bd9c48ad1a3b4e4f8942357a7c88ddb8",
    "phone_number": "+913812389851",
    "connector_customer_id": "cus_U8SI8Xv2Fm1dPw"
  },
  "locale": "en-US",
  "address": {
    "shipping_address": {
      "first_name": {
        "value": "Mia"
      },
      "last_name": {
        "value": "Miller"
      },
      "line1": {
        "value": "9489 Main Ave"
      },
      "line2": {
        "value": "3007 Main Dr"
      },
      "line3": {
        "value": "2068 Sunset St"
      },
      "city": {
        "value": "Los Angeles"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "30219"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "jordan.5487@example.com"
      },
      "phone_number": {
        "value": "1519315685"
      },
      "phone_country_code": "+91"
    },
    "billing_address": {
      "first_name": {
        "value": "Liam"
      },
      "last_name": {
        "value": "Wilson"
      },
      "line1": {
        "value": "7312 Oak Ave"
      },
      "line2": {
        "value": "8969 Pine St"
      },
      "line3": {
        "value": "977 Market Ln"
      },
      "city": {
        "value": "Seattle"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "15145"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "alex.9111@testmail.io"
      },
      "phone_number": {
        "value": "5938054180"
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
<summary>Show Dependency Response Body</summary>

```json
{
  "merchantTransactionId": "pi_3TABOED5R7gDAGff0EGOPlt7",
  "connectorTransactionId": "pi_3TABOED5R7gDAGff0EGOPlt7",
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
    "content-length": "5535",
    "content-security-policy": "base-uri 'none'; default-src 'none'; form-action 'none'; frame-ancestors 'none'; img-src 'self'; script-src 'self' 'report-sample'; style-src 'self'; worker-src 'none'; upgrade-insecure-requests; report-uri https://q.stripe.com/csp-violation?q=XbpkE0Obtc-D-_OVcHByv3HX2Cz2ZXWthan_OSmhaX_cdx20p33NXUJkyzusgJOGoDWC714Lefdz6v3w",
    "content-type": "application/json",
    "date": "Thu, 12 Mar 2026 15:43:11 GMT",
    "idempotency-key": "007b0635-6c97-43f9-baac-e65bb9bb2c6e",
    "original-request": "req_3DCC5A4DFkAt58",
    "request-id": "req_3DCC5A4DFkAt58",
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
    "connectorCustomerId": "cus_U8SI8Xv2Fm1dPw"
  },
  "rawConnectorResponse": {
    "value": "{\n  \"id\": \"pi_3TABOED5R7gDAGff0EGOPlt7\",\n  \"object\": \"payment_intent\",\n  \"amount\": 6000,\n  \"amount_capturable\": 0,\n  \"amount_details\": {\n    \"tip\": {}\n  },\n  \"amount_received\": 6000,\n  \"application\": null,\n  \"application_fee_amount\": null,\n  \"automatic_payment_methods\": null,\n  \"canceled_at\": null,\n  \"cancellation_reason\": null,\n  \"capture_method\": \"automatic\",\n  \"client_secret\": ***MASKED***\"\n  \"confirmation_method\": \"automatic\",\n  \"created\": 1773330190,\n  \"currency\": \"usd\",\n  \"customer\": \"cus_U8SI8Xv2Fm1dPw\",\n  \"customer_account\": null,\n  \"description\": \"No3DS auto capture card payment (credit)\",\n  \"excluded_payment_method_types\": null,\n  \"invoice\": null,\n  \"last_payment_error\": null,\n  \"latest_charge\": {\n    \"id\": \"ch_3TABOED5R7gDAGff0Elcng4K\",\n    \"object\": \"charge\",\n    \"amount\": 6000,\n    \"amount_captured\": 6000,\n    \"amount_refunded\": 0,\n    \"amount_updates\": [],\n    \"application\": null,\n    \"application_fee\": null,\n    \"application_fee_amount\": null,\n    \"balance_transaction\": \"txn_3TABOED5R7gDAGff0JGZwKXY\",\n    \"billing_details\": {\n      \"address\": {\n        \"city\": \"Seattle\",\n        \"country\": \"US\",\n        \"line1\": \"7312 Oak Ave\",\n        \"line2\": \"8969 Pine St\",\n        \"postal_code\": \"15145\",\n        \"state\": \"CA\"\n      },\n      \"email\": \"alex.9111@testmail.io\",\n      \"name\": \"Liam Wilson\",\n      \"phone\": \"5938054180\",\n      \"tax_id\": null\n    },\n    \"calculated_statement_descriptor\": \"BERNARD\",\n    \"captured\": true,\n    \"created\": 1773330190,\n    \"currency\": \"usd\",\n    \"customer\": \"cus_U8SI8Xv2Fm1dPw\",\n    \"description\": \"No3DS auto capture card payment (credit)\",\n    \"destination\": null,\n    \"dispute\": null,\n    \"disputed\": false,\n    \"failure_balance_transaction\": null,\n    \"failure_code\": null,\n    \"failure_message\": null,\n    \"fraud_details\": {},\n    \"invoice\": null,\n    \"livemode\": false,\n    \"metadata\": {\n      \"order_id\": \"mti_f834d6ff47b648b786e737f3c3fb2da3\"\n    },\n    \"on_behalf_of\": null,\n    \"order\": null,\n    \"outcome\": {\n      \"advice_code\": null,\n      \"network_advice_code\": null,\n      \"network_decline_code\": null,\n      \"network_status\": \"approved_by_network\",\n      \"reason\": null,\n      \"risk_level\": \"normal\",\n      \"risk_score\": 34,\n      \"seller_message\": \"Payment complete.\",\n      \"type\": \"authorized\"\n    },\n    \"paid\": true,\n    \"payment_intent\": \"pi_3TABOED5R7gDAGff0EGOPlt7\",\n    \"payment_method\": \"pm_1TABOED5R7gDAGffvZoe5iF8\",\n    \"payment_method_details\": {\n      \"card\": {\n        \"amount_authorized\": 6000,\n        \"authorization_code\": ***MASKED***\"\n        \"brand\": \"visa\",\n        \"checks\": {\n          \"address_line1_check\": \"pass\",\n          \"address_postal_code_check\": \"pass\",\n          \"cvc_check\": ***MASKED***\"\n        },\n        \"country\": \"US\",\n        \"exp_month\": ***MASKED***\n        \"exp_year\": ***MASKED***\n        \"extended_authorization\": ***MASKED***\n          \"status\": \"disabled\"\n        },\n        \"fingerprint\": \"aEed1rfhfa5JNpoz\",\n        \"funding\": \"credit\",\n        \"incremental_authorization\": ***MASKED***\n          \"status\": \"unavailable\"\n        },\n        \"installments\": null,\n        \"last4\": \"1111\",\n        \"mandate\": null,\n        \"moto\": null,\n        \"multicapture\": {\n          \"status\": \"unavailable\"\n        },\n        \"network\": \"visa\",\n        \"network_token\": ***MASKED***\n          \"used\": false\n        },\n        \"network_transaction_id\": \"976910110049114\",\n        \"overcapture\": {\n          \"maximum_amount_capturable\": 6000,\n          \"status\": \"unavailable\"\n        },\n        \"regulated_status\": \"unregulated\",\n        \"three_d_secure\": null,\n        \"wallet\": null\n      },\n      \"type\": \"card\"\n    },\n    \"radar_options\": {},\n    \"receipt_email\": null,\n    \"receipt_number\": null,\n    \"receipt_url\": \"https://pay.stripe.com/receipts/payment/CAcaFwoVYWNjdF8xTTdmVGFENVI3Z0RBR2ZmKI--y80GMgYKEUxy3H46LBZU9Nj8--HM-EQT4nFeAdWH4X-miQMxHzmMpMzkv6v0aqiCbJMrLROmTLq7\",\n    \"refunded\": false,\n    \"review\": null,\n    \"shipping\": {\n      \"address\": {\n        \"city\": \"Los Angeles\",\n        \"country\": \"US\",\n        \"line1\": \"9489 Main Ave\",\n        \"line2\": \"3007 Main Dr\",\n        \"postal_code\": \"30219\",\n        \"state\": \"CA\"\n      },\n      \"carrier\": null,\n      \"name\": \"Mia Miller\",\n      \"phone\": \"+911519315685\",\n      \"tracking_number\": null\n    },\n    \"source\": null,\n    \"source_transfer\": null,\n    \"statement_descriptor\": null,\n    \"statement_descriptor_suffix\": null,\n    \"status\": \"succeeded\",\n    \"transfer_data\": null,\n    \"transfer_group\": null\n  },\n  \"livemode\": false,\n  \"metadata\": {\n    \"order_id\": \"mti_f834d6ff47b648b786e737f3c3fb2da3\"\n  },\n  \"next_action\": null,\n  \"on_behalf_of\": null,\n  \"payment_method\": \"pm_1TABOED5R7gDAGffvZoe5iF8\",\n  \"payment_method_configuration_details\": null,\n  \"payment_method_options\": {\n    \"card\": {\n      \"installments\": null,\n      \"mandate_options\": null,\n      \"network\": null,\n      \"request_three_d_secure\": \"automatic\"\n    }\n  },\n  \"payment_method_types\": [\n    \"card\"\n  ],\n  \"processing\": null,\n  \"receipt_email\": null,\n  \"review\": null,\n  \"setup_future_usage\": \"on_session\",\n  \"shipping\": {\n    \"address\": {\n      \"city\": \"Los Angeles\",\n      \"country\": \"US\",\n      \"line1\": \"9489 Main Ave\",\n      \"line2\": \"3007 Main Dr\",\n      \"postal_code\": \"30219\",\n      \"state\": \"CA\"\n    },\n    \"carrier\": null,\n    \"name\": \"Mia Miller\",\n    \"phone\": \"+911519315685\",\n    \"tracking_number\": null\n  },\n  \"source\": null,\n  \"statement_descriptor\": null,\n  \"statement_descriptor_suffix\": null,\n  \"status\": \"succeeded\",\n  \"transfer_data\": null,\n  \"transfer_group\": null\n}"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://api.stripe.com/v1/payment_intents\",\"method\":\"POST\",\"headers\":{\"stripe-version\":\"2022-11-15\",\"Authorization\":\"Bearer ***MASKED***\",\"via\":\"HyperSwitch\",\"Content-Type\":\"application/x-www-form-urlencoded\"},\"body\":\"amount=6000&currency=USD&metadata%5Border_id%5D=mti_f834d6ff47b648b786e737f3c3fb2da3&return_url=https%3A%2F%2Fexample.com%2Fpayment%2Freturn&confirm=true&customer=cus_U8SI8Xv2Fm1dPw&description=No3DS+auto+capture+card+payment+%28credit%29&shipping%5Baddress%5D%5Bcity%5D=Los+Angeles&shipping%5Baddress%5D%5Bcountry%5D=US&shipping%5Baddress%5D%5Bline1%5D=9489+Main+Ave&shipping%5Baddress%5D%5Bline2%5D=3007+Main+Dr&shipping%5Baddress%5D%5Bpostal_code%5D=30219&shipping%5Baddress%5D%5Bstate%5D=CA&shipping%5Bname%5D=Mia+Miller&shipping%5Bphone%5D=%2B911519315685&payment_method_data%5Bbilling_details%5D%5Bemail%5D=alex.9111%40testmail.io&payment_method_data%5Bbilling_details%5D%5Baddress%5D%5Bcountry%5D=US&payment_method_data%5Bbilling_details%5D%5Bname%5D=Liam+Wilson&payment_method_data%5Bbilling_details%5D%5Baddress%5D%5Bcity%5D=Seattle&payment_method_data%5Bbilling_details%5D%5Baddress%5D%5Bline1%5D=7312+Oak+Ave&payment_method_data%5Bbilling_details%5D%5Baddress%5D%5Bline2%5D=8969+Pine+St&payment_method_data%5Bbilling_details%5D%5Baddress%5D%5Bpostal_code%5D=15145&payment_method_data%5Bbilling_details%5D%5Baddress%5D%5Bstate%5D=CA&payment_method_data%5Bbilling_details%5D%5Bphone%5D=5938054180&payment_method_data%5Btype%5D=card&payment_method_data%5Bcard%5D%5Bnumber%5D=4111111111111111&payment_method_data%5Bcard%5D%5Bexp_month%5D=08&payment_method_data%5Bcard%5D%5Bexp_year%5D=30&payment_method_data%5Bcard%5D%5Bcvc%5D=999&payment_method_options%5Bcard%5D%5Brequest_three_d_secure%5D=automatic&capture_method=automatic&setup_future_usage=on_session&off_session=false&payment_method_types%5B0%5D=card&expand%5B0%5D=latest_charge\"}"
  },
  "capturedAmount": "6000",
  "mandateReference": {
    "connectorMandateId": {
      "connectorMandateId": "pm_1TABOED5R7gDAGffvZoe5iF8",
      "paymentMethodId": "pm_1TABOED5R7gDAGffvZoe5iF8"
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
  -H "x-request-id: refund_refund_with_reason_req" \
  -H "x-connector-request-reference-id: refund_refund_with_reason_ref" \
  -H "x-auth: ***MASKED***" \
  -H "x-api-key: ***MASKED***" \
  -d @ localhost:8000 types.PaymentService/Refund <<'JSON'
{
  "merchant_refund_id": "mri_9b203cca0a814291b5e28400c632d424",
  "connector_transaction_id": "pi_3TABOED5R7gDAGff0EGOPlt7",
  "payment_amount": 6000,
  "refund_amount": {
    "minor_amount": 6000,
    "currency": "USD"
  },
  "state": {
    "connector_customer_id": "cus_U8SI8Xv2Fm1dPw"
  },
  "reason": "customer_requested"
}
JSON
```

</details>

<details>
<summary>Show gRPC Response (masked)</summary>

```text
Resolved method descriptor:
// Initiate a refund to customer's payment method. Returns funds for
// returns, cancellations, or service adjustments after original payment.
rpc Refund ( .types.PaymentServiceRefundRequest ) returns ( .types.RefundResponse );

Request metadata to send:
x-api-key: ***MASKED***
x-auth: ***MASKED***
x-connector: stripe
x-connector-request-reference-id: refund_refund_with_reason_ref
x-merchant-id: test_merchant
x-request-id: refund_refund_with_reason_req
x-tenant-id: default

Response headers received:
content-type: application/grpc
date: Thu, 12 Mar 2026 15:43:13 GMT
x-request-id: refund_refund_with_reason_req

Response contents:
{
  "connectorRefundId": "re_3TABOED5R7gDAGff0jj134LO",
  "status": "REFUND_SUCCESS",
  "statusCode": 200,
  "responseHeaders": {
    "access-control-allow-credentials": "true",
    "access-control-allow-methods": "GET, HEAD, PUT, PATCH, POST, DELETE",
    "access-control-allow-origin": "*",
    "access-control-expose-headers": "Request-Id, Stripe-Manage-Version, Stripe-Should-Retry, X-Stripe-External-Auth-Required, X-Stripe-Privileged-Session-Required",
    "access-control-max-age": "300",
    "cache-control": "no-cache, no-store",
    "connection": "keep-alive",
    "content-length": "714",
    "content-security-policy": "base-uri 'none'; default-src 'none'; form-action 'none'; frame-ancestors 'none'; img-src 'self'; script-src 'self' 'report-sample'; style-src 'self'; worker-src 'none'; upgrade-insecure-requests; report-uri https://q.stripe.com/csp-violation?q=XbpkE0Obtc-D-_OVcHByv3HX2Cz2ZXWthan_OSmhaX_cdx20p33NXUJkyzusgJOGoDWC714Lefdz6v3w",
    "content-type": "application/json",
    "date": "Thu, 12 Mar 2026 15:43:13 GMT",
    "idempotency-key": "eb204422-5e46-4f8d-8b39-f0e411103bc7",
    "original-request": "req_KxxR1RF8XxzAzE",
    "request-id": "req_KxxR1RF8XxzAzE",
    "server": "nginx",
    "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
    "stripe-should-retry": "false",
    "stripe-version": "2022-11-15",
    "vary": "Origin",
    "x-stripe-priority-routing-enabled": "true",
    "x-stripe-routing-context-priority-tier": "api-testmode",
    "x-wc": "ABGHIJ"
  },
  "rawConnectorResponse": {
    "value": "{\n  \"id\": \"re_3TABOED5R7gDAGff0jj134LO\",\n  \"object\": \"refund\",\n  \"amount\": 6000,\n  \"balance_transaction\": \"txn_3TABOED5R7gDAGff0h5ePZl1\",\n  \"charge\": \"ch_3TABOED5R7gDAGff0Elcng4K\",\n  \"created\": 1773330192,\n  \"currency\": \"usd\",\n  \"destination_details\": {\n    \"card\": {\n      \"reference_status\": \"pending\",\n      \"reference_type\": \"acquirer_reference_number\",\n      \"type\": \"refund\"\n    },\n    \"type\": \"card\"\n  },\n  \"metadata\": {\n    \"is_refund_id_as_reference\": \"true\",\n    \"order_id\": \"mri_9b203cca0a814291b5e28400c632d424\"\n  },\n  \"payment_intent\": \"pi_3TABOED5R7gDAGff0EGOPlt7\",\n  \"reason\": null,\n  \"receipt_number\": null,\n  \"source_transfer_reversal\": null,\n  \"status\": \"succeeded\",\n  \"transfer_reversal\": null\n}"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://api.stripe.com/v1/refunds\",\"method\":\"POST\",\"headers\":{\"Authorization\":\"Bearer ***MASKED***",\"via\":\"HyperSwitch\",\"Content-Type\":\"application/x-www-form-urlencoded\",\"stripe-version\":\"2022-11-15\"},\"body\":\"amount=6000\u0026payment_intent=pi_3TABOED5R7gDAGff0EGOPlt7\u0026metadata%5Border_id%5D=mri_9b203cca0a814291b5e28400c632d424\u0026metadata%5Bis_refund_id_as_reference%5D=true\"}"
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
  "merchant_refund_id": "mri_9b203cca0a814291b5e28400c632d424",
  "connector_transaction_id": "pi_3TABOED5R7gDAGff0EGOPlt7",
  "payment_amount": 6000,
  "refund_amount": {
    "minor_amount": 6000,
    "currency": "USD"
  },
  "state": {
    "connector_customer_id": "cus_U8SI8Xv2Fm1dPw"
  },
  "reason": "customer_requested"
}
```

</details>

<details>
<summary>Show Response Body</summary>

```json
{
  "connectorRefundId": "re_3TABOED5R7gDAGff0jj134LO",
  "status": "REFUND_SUCCESS",
  "statusCode": 200,
  "responseHeaders": {
    "access-control-allow-credentials": "true",
    "access-control-allow-methods": "GET, HEAD, PUT, PATCH, POST, DELETE",
    "access-control-allow-origin": "*",
    "access-control-expose-headers": "Request-Id, Stripe-Manage-Version, Stripe-Should-Retry, X-Stripe-External-Auth-Required, X-Stripe-Privileged-Session-Required",
    "access-control-max-age": "300",
    "cache-control": "no-cache, no-store",
    "connection": "keep-alive",
    "content-length": "714",
    "content-security-policy": "base-uri 'none'; default-src 'none'; form-action 'none'; frame-ancestors 'none'; img-src 'self'; script-src 'self' 'report-sample'; style-src 'self'; worker-src 'none'; upgrade-insecure-requests; report-uri https://q.stripe.com/csp-violation?q=XbpkE0Obtc-D-_OVcHByv3HX2Cz2ZXWthan_OSmhaX_cdx20p33NXUJkyzusgJOGoDWC714Lefdz6v3w",
    "content-type": "application/json",
    "date": "Thu, 12 Mar 2026 15:43:13 GMT",
    "idempotency-key": "eb204422-5e46-4f8d-8b39-f0e411103bc7",
    "original-request": "req_KxxR1RF8XxzAzE",
    "request-id": "req_KxxR1RF8XxzAzE",
    "server": "nginx",
    "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
    "stripe-should-retry": "false",
    "stripe-version": "2022-11-15",
    "vary": "Origin",
    "x-stripe-priority-routing-enabled": "true",
    "x-stripe-routing-context-priority-tier": "api-testmode",
    "x-wc": "ABGHIJ"
  },
  "rawConnectorResponse": {
    "value": "{\n  \"id\": \"re_3TABOED5R7gDAGff0jj134LO\",\n  \"object\": \"refund\",\n  \"amount\": 6000,\n  \"balance_transaction\": \"txn_3TABOED5R7gDAGff0h5ePZl1\",\n  \"charge\": \"ch_3TABOED5R7gDAGff0Elcng4K\",\n  \"created\": 1773330192,\n  \"currency\": \"usd\",\n  \"destination_details\": {\n    \"card\": {\n      \"reference_status\": \"pending\",\n      \"reference_type\": \"acquirer_reference_number\",\n      \"type\": \"refund\"\n    },\n    \"type\": \"card\"\n  },\n  \"metadata\": {\n    \"is_refund_id_as_reference\": \"true\",\n    \"order_id\": \"mri_9b203cca0a814291b5e28400c632d424\"\n  },\n  \"payment_intent\": \"pi_3TABOED5R7gDAGff0EGOPlt7\",\n  \"reason\": null,\n  \"receipt_number\": null,\n  \"source_transfer_reversal\": null,\n  \"status\": \"succeeded\",\n  \"transfer_reversal\": null\n}"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://api.stripe.com/v1/refunds\",\"method\":\"POST\",\"headers\":{\"Authorization\":\"Bearer ***MASKED***\",\"via\":\"HyperSwitch\",\"Content-Type\":\"application/x-www-form-urlencoded\",\"stripe-version\":\"2022-11-15\"},\"body\":\"amount=6000&payment_intent=pi_3TABOED5R7gDAGff0EGOPlt7&metadata%5Border_id%5D=mri_9b203cca0a814291b5e28400c632d424&metadata%5Bis_refund_id_as_reference%5D=true\"}"
  }
}
```

</details>


[Back to Overview](../../test_overview.md)
