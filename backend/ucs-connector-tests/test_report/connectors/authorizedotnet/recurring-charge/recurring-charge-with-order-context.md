# Connector `authorizedotnet` / Suite `recurring_charge` / Scenario `recurring_charge_with_order_context`

- Service: `RecurringPaymentService/Charge`
- PM / PMT: `-` / `-`
- Result: `FAIL`

**Error**

```text
Resolved method descriptor:
// Charge using an existing stored recurring payment instruction. Processes repeat payments for
// subscriptions or recurring billing without collecting payment details.
rpc Charge ( .types.RecurringPaymentServiceChargeRequest ) returns ( .types.RecurringPaymentServiceChargeResponse );

Request metadata to send:
x-api-key: ***MASKED***
x-auth: ***MASKED***
x-connector: authorizedotnet
x-connector-request-reference-id: recurring_charge_recurring_charge_with_order_context_ref
x-key1: ***MASKED***
x-merchant-id: test_merchant
x-request-id: recurring_charge_recurring_charge_with_order_context_req
x-tenant-id: default

Response headers received:
(empty)

Response trailers received:
content-type: application/grpc
date: Thu, 12 Mar 2026 15:40:53 GMT
x-request-id: recurring_charge_recurring_charge_with_order_context_req
Sent 1 request and received 0 responses

ERROR:
  Code: InvalidArgument
  Message: Missing required field: valid mandate_id format (should contain '-')
```

**Pre Requisites Executed**

<details>
<summary>1. create_customer(create_customer) — PASS</summary>

<details>
<summary>Show Dependency Request (masked)</summary>

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
  "merchant_customer_id": "mcui_44483467240b4aab894960597c04230a",
  "customer_name": "Emma Wilson",
  "email": {
    "value": "alex.5030@example.com"
  },
  "phone_number": "+917576114479",
  "address": {
    "shipping_address": {
      "first_name": {
        "value": "Ava"
      },
      "last_name": {
        "value": "Johnson"
      },
      "line1": {
        "value": "4045 Pine Blvd"
      },
      "line2": {
        "value": "1630 Market St"
      },
      "line3": {
        "value": "1107 Lake Blvd"
      },
      "city": {
        "value": "New York"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "78243"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "riley.7315@sandbox.example.com"
      },
      "phone_number": {
        "value": "3320027854"
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
        "value": "6827 Oak Dr"
      },
      "line2": {
        "value": "2909 Sunset St"
      },
      "line3": {
        "value": "6647 Market Ln"
      },
      "city": {
        "value": "Austin"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "94253"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "casey.4530@testmail.io"
      },
      "phone_number": {
        "value": "2349096044"
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
x-connector: authorizedotnet
x-connector-request-reference-id: create_customer_create_customer_ref
x-key1: ***MASKED***
x-merchant-id: test_merchant
x-request-id: create_customer_create_customer_req
x-tenant-id: default

Response headers received:
content-type: application/grpc
date: Thu, 12 Mar 2026 15:40:51 GMT
x-request-id: create_customer_create_customer_req

Response contents:
{
  "merchantCustomerId": "934839067",
  "connectorCustomerId": "934839067",
  "statusCode": 200,
  "responseHeaders": {
    "access-control-allow-credentials": "true",
    "access-control-allow-headers": "x-requested-with,cache-control,content-type,origin,method,SOAPAction",
    "access-control-allow-methods": "PUT,OPTIONS,POST,GET",
    "access-control-allow-origin": "*",
    "cache-control": "no-cache, no-store, max-age=0",
    "content-length": "232",
    "content-type": "application/json; charset=utf-8",
    "date": "Thu, 12 Mar 2026 15:40:51 GMT",
    "expires": "-1",
    "pragma": "no-cache",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-cnection": "close",
    "x-download-options": "noopen",
    "x-opnet-transaction-trace": "39598f69-930a-4eea-a65b-19a85a5612aa-17512-11770200"
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
  -H "x-connector: authorizedotnet" \
  -H "x-merchant-id: test_merchant" \
  -H "x-tenant-id: default" \
  -H "x-request-id: setup_recurring_setup_recurring_req" \
  -H "x-connector-request-reference-id: setup_recurring_setup_recurring_ref" \
  -H "x-auth: ***MASKED***" \
  -H "x-api-key: ***MASKED***" \
  -H "x-key1: ***MASKED***" \
  -d @ localhost:8000 types.PaymentService/SetupRecurring <<'JSON'
{
  "merchant_recurring_payment_id": "mrpi_6899cd358e804de0a089b1b65843a6bd",
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
        "value": "Liam Wilson"
      },
      "card_type": "credit"
    }
  },
  "customer": {
    "name": "Noah Johnson",
    "email": {
      "value": "sam.2819@example.com"
    },
    "id": "cust_f11a95d7c18e4c2b8fbfa82978d8df8b",
    "phone_number": "+17152868169",
    "connector_customer_id": "934839067"
  },
  "setup_future_usage": "OFF_SESSION",
  "address": {
    "billing_address": {
      "first_name": {
        "value": "Noah"
      },
      "last_name": {
        "value": "Johnson"
      },
      "line1": {
        "value": "6827 Oak Dr"
      },
      "line2": {
        "value": "2909 Sunset St"
      },
      "line3": {
        "value": "6647 Market Ln"
      },
      "city": {
        "value": "Austin"
      },
      "state": {
        "value": "CA"
      },
      "zip_code": {
        "value": "94253"
      },
      "country_alpha2_code": "US",
      "email": {
        "value": "casey.4530@testmail.io"
      },
      "phone_number": {
        "value": "2349096044"
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
x-connector: authorizedotnet
x-connector-request-reference-id: setup_recurring_setup_recurring_ref
x-key1: ***MASKED***
x-merchant-id: test_merchant
x-request-id: setup_recurring_setup_recurring_req
x-tenant-id: default

Response headers received:
content-type: application/grpc
date: Thu, 12 Mar 2026 15:40:52 GMT
x-request-id: setup_recurring_setup_recurring_req

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
    "content-length": "504",
    "content-type": "application/json; charset=utf-8",
    "date": "Thu, 12 Mar 2026 15:40:51 GMT",
    "expires": "-1",
    "pragma": "no-cache",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-cnection": "close",
    "x-download-options": "noopen",
    "x-opnet-transaction-trace": "6275c255-1f58-458f-b516-e5c061e8590b-12436-10998378"
  },
  "mandateReference": {
    "connectorMandateId": {
      "connectorMandateId": "934839067-934084494"
    }
  },
  "capturedAmount": "0",
  "state": {
    "connectorCustomerId": "934839067"
  },
  "rawConnectorRequest": {
    "value": "{\"url\":\"https://apitest.authorize.net/xml/v1/request.api\",\"method\":\"POST\",\"headers\":{\"via\":\"HyperSwitch\",\"Content-Type\":\"application/json\"},\"body\":{\"createCustomerPaymentProfileRequest\":{\"merchantAuthentication\":{\"name\":\"9ARWr5wz49D3\",\"transactionKey\":\"3d9SHV2699mgmHre\"},\"customerProfileId\":\"934839067\",\"paymentProfile\":{\"billTo\":{\"firstName\":\"Noah\",\"lastName\":\"Johnson\",\"address\":\"6827 Oak Dr 2909 Sunset St 6647 Market Ln\",\"city\":\"Austin\",\"state\":\"CA\",\"zip\":\"94253\",\"country\":\"US\"},\"payment\":{\"creditCard\":{\"cardNumber\":\"4111111111111111\",\"expirationDate\":\"2030-08\",\"cardCode\":\"999\"}}},\"validationMode\":\"testMode\"}}}"
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
  -H "x-connector: authorizedotnet" \
  -H "x-merchant-id: test_merchant" \
  -H "x-tenant-id: default" \
  -H "x-request-id: recurring_charge_recurring_charge_with_order_context_req" \
  -H "x-connector-request-reference-id: recurring_charge_recurring_charge_with_order_context_ref" \
  -H "x-auth: ***MASKED***" \
  -H "x-api-key: ***MASKED***" \
  -H "x-key1: ***MASKED***" \
  -d @ localhost:8000 types.RecurringPaymentService/Charge <<'JSON'
{
  "merchant_charge_id": "mchi_50ffc7b7e9284259aad2d52906a41609",
  "connector_recurring_payment_id": {
    "connector_mandate_id": {
      "connector_mandate_id": "cmi_3d902f476fd147c7acab6880cc5bf9f2"
    }
  },
  "amount": {
    "minor_amount": 6000,
    "currency": "USD"
  },
  "merchant_order_id": "gen_643901",
  "webhook_url": "https://example.com/payment/webhook",
  "return_url": "https://example.com/payment/return",
  "description": "Recurring charge with order context",
  "off_session": true,
  "test_mode": true,
  "connector_customer_id": "934839067",
  "customer": {
    "connector_customer_id": "934839067"
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
x-connector: authorizedotnet
x-connector-request-reference-id: recurring_charge_recurring_charge_with_order_context_ref
x-key1: ***MASKED***
x-merchant-id: test_merchant
x-request-id: recurring_charge_recurring_charge_with_order_context_req
x-tenant-id: default

Response headers received:
(empty)

Response trailers received:
content-type: application/grpc
date: Thu, 12 Mar 2026 15:40:53 GMT
x-request-id: recurring_charge_recurring_charge_with_order_context_req
Sent 1 request and received 0 responses

ERROR:
  Code: InvalidArgument
  Message: Missing required field: valid mandate_id format (should contain '-')
```

</details>


[Back to Connector Suite](../recurring-charge.md) | [Back to Overview](../../../test_overview.md)
