# Connector `stripe` / Suite `refund` / Scenario `refund_with_reason`

- Service: `PaymentService/Refund`
- PM / PMT: `-` / `-`
- Result: `PASS`

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

</details>
<details>
<summary>2. authorize(no3ds_auto_capture_credit_card) — PASS</summary>

<details>
<summary>Show Dependency Request (masked)</summary>

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
<summary>Show Dependency Response (masked)</summary>

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

</details>
<details>
<summary>Show Request (masked)</summary>

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
<summary>Show Response (masked)</summary>

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


[Back to Connector Suite](../refund.md) | [Back to Overview](../../../test_overview.md)
