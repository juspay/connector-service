# PayPal ACH Direct Debit — API Documentation

---

## Connector Information

| Field | Details |
|---|---|
| **Connector Name** | PayPal Orders API (ACH Direct Debit) |
| **Currency** | USD only |
| **Payment Types** | One-time and Recurring |
| **Approval Required** | Yes — contact Customer Support Manager or Sales |

### Base URLs

| Environment | URL |
|---|---|
| **Sandbox** | `https://api-m.sandbox.paypal.com` |
| **Production** | `https://api-m.paypal.com` |

### Additional URLs

| Type | URL |
|---|---|
| Reference Documentation | `https://www.paypal.com` |
| Payer Checkout Action | `https://www.paypal.com/checkoutnow?token={ORDER_ID}` |

---

## Authentication

| Field | Details |
|---|---|
| **Method** | OAuth 2.0 Bearer Token |
| **Header Name** | `Authorization` |
| **Header Format** | `Bearer ACCESS-TOKEN` |
| **Token Source** | Obtained via PayPal merchant onboarding / Get Started flow |

### Authentication Header Example

```
Authorization: Bearer A21AAGHr9qtiRRXH4oYcQokQgV99rGqEIfgrr8xHCclP0OzmD9KVgg5ppIIg1jzJgQkV4wd02svIvBJyg6cLFJjFow_SjBhxQ
```

---

## Request Headers (Common)

| Header | Type | Description |
|---|---|---|
| `Authorization` | string [1..16000] | Bearer token for authentication |
| `Content-Type` | string | `application/json` |
| `PayPal-Request-Id` | string [1..108] | Idempotency key. Mandatory for single-step create order calls with payment source. Server stores keys for 6 hours (up to 72 hours by request). |
| `PayPal-Partner-Attribution-Id` | string [1..36] | BN Code assigned to PayPal Partners for tracking |
| `PayPal-Client-Metadata-Id` | string [1..68], `^[A-Za-z0-9-{}(),]*$` | GUID from Fraudnet/Dyson for Risk decisions |
| `Prefer` | string [1..25] | Default: `return=minimal`. Options: `return=minimal`, `return=representation` |
| `PayPal-Auth-Assertion` | string [1..10000] | JWT assertion identifying the merchant (requires prior consent setup) |

---

## Complete Endpoint Inventory

---

### 1. Create Order

**POST** `/v2/checkout/orders`

Creates a new order. For ACH direct debit, `intent` must be set to `CAPTURE`.

#### Request

**Headers:**

```
Authorization: Bearer ACCESS-TOKEN
Content-Type: application/json
```

**Request Body Schema:** `application/json`

| Field | Type | Required | Description |
|---|---|---|---|
| `intent` | string | ✅ | Must be `"CAPTURE"` for ACH. Enum: `"CAPTURE"`, `"AUTHORIZE"` |
| `purchase_units` | array [1..10] | ✅ | Array of purchase unit objects |
| `purchase_units[].amount` | object | ✅ | Amount details |
| `purchase_units[].amount.currency_code` | string | ✅ | Must be `"USD"` for ACH |
| `purchase_units[].amount.value` | string | ✅ | Transaction amount |
| `purchase_units[].payee` | object | ❌ | Payee details |
| `purchase_units[].payee.email_address` | string | ❌ | Merchant email |
| `purchase_units[].payment_instruction.platform_fees` | array | ❌ | Platform fees for the order |
| `payment_source` | object | ❌ | Payment source definition |
| `application_context` | object | ❌ | Payer experience customization during approval |
| `payer` | object | ❌ | **Deprecated.** Customer/payer details |

#### cURL Example (ACH — Minimal Create Order)

```bash
curl -v -X POST https://api-m.sandbox.paypal.com/v2/checkout/orders \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer ACCESS-TOKEN' \
  -d '{
    "intent": "CAPTURE",
    "purchase_units": [
      {
        "amount": {
          "currency_code": "USD",
          "value": "100.00"
        },
        "payee": {
          "email_address": "merchant@example.com"
        }
      }
    ]
  }'
```

#### cURL Example (PayPal Wallet as Payment Source)

```bash
curl -v -X POST https://api-m.sandbox.paypal.com/v2/checkout/orders \
  -H 'Authorization: Bearer A21AAGHr9qtiRRXH4oYcQokQgV99rGqEIfgrr8xHCclP0OzmD9KVgg5ppIIg1jzJgQkV4wd02svIvBJyg6cLFJjFow_SjBhxQ' \
  -H 'PayPal-Request-Id: 7b92603e-77ed-4896-8e78-5dea2050476a' \
  -d '{
    "payment_source": {
      "paypal": {
        "experience_context": {
          "payment_method_preference": "IMMEDIATE_PAYMENT_REQUIRED",
          "landing_page": "LOGIN",
          "shipping_preference": "GET_FROM_FILE",
          "user_action": "PAY_NOW",
          "return_url": "https://example.com/returnUrl",
          "cancel_url": "https://example.com/cancelUrl"
        }
      }
    },
    "purchase_units": [
      {
        "invoice_id": "90210",
        "amount": {
          "currency_code": "USD",
          "value": "230.00",
          "breakdown": {
            "item_total": { "currency_code": "USD", "value": "220.00" },
            "shipping": { "currency_code": "USD", "value": "10.00" }
          }
        },
        "items": [
          {
            "name": "T-Shirt",
            "description": "Super Fresh Shirt",
            "unit_amount": { "currency_code": "USD", "value": "20.00" },
            "quantity": "1",
            "category": "PHYSICAL_GOODS",
            "sku": "sku01",
            "image_url": "https://example.com/static/images/items/1/tshirt_green.jpg",
            "url": "https://example.com/url-to-the-item-being-purchased-1",
            "upc": { "type": "UPC-A", "code": "123456789012" }
          },
          {
            "name": "Shoes",
            "description": "Running, Size 10.5",
            "sku": "sku02",
            "unit_amount": { "currency_code": "USD", "value": "100.00" },
            "quantity": "2",
            "category": "PHYSICAL_GOODS",
            "image_url": "https://example.com/static/images/items/1/shoes_running.jpg",
            "url": "https://example.com/url-to-the-item-being-purchased-2",
            "upc": { "type": "UPC-A", "code": "987654321012" }
          }
        ]
      }
    ]
  }'
```

#### Responses

| HTTP Status | Description |
|---|---|
| `200 OK` | Successful idempotent request. Returns order details in JSON. |
| `201 Created` | New order created. Returns minimal response (`id`, `status`, HATEOAS links) by default. Pass `Prefer: return=representation` for full resource. |
| `400 Bad Request` | Request is not well-formed, syntactically incorrect, or violates schema. |
| `422 Unprocessable Entity` | Action could not be performed; semantically incorrect or failed business validation. |

#### Response Body (200 — PayPal Wallet, PAYER_ACTION_REQUIRED)

```json
{
  "id": "5O190127TN364715T",
  "payment_source": {
    "paypal": {}
  },
  "links": [
    {
      "href": "https://api-m.paypal.com/v2/checkout/orders/5O190127TN364715T",
      "rel": "self",
      "method": "GET"
    },
    {
      "href": "https://www.paypal.com/checkoutnow?token=5O190127TN364715T",
      "rel": "payer-action",
      "method": "GET"
    }
  ]
}
```

---

### 2. Capture Order — With Full Bank Account Information (ACH)

**POST** `/v2/checkout/orders/{order_id}/capture`

Captures funds for an approved order using full bank account details.

#### Prerequisites

- Bank account must be verified
- Payer must have authorized the direct debit
- Order status must be `APPROVED`

#### Path Parameters

| Parameter | Description |
|---|---|
| `order_id` | The ID of the order to capture (e.g., `5O190127TN364715T`) |

#### Request Body Schema

| Field | Type | Required | Description |
|---|---|---|---|
| `payment_source.bank.ach_debit.account_number` | string | ✅ | Payer's bank account number |
| `payment_source.bank.ach_debit.routing_number` | string | ✅ | Payer's bank routing number |
| `payment_source.bank.ach_debit.account_holder_name` | string | ✅ | Name of account holder |
| `payment_source.bank.ach_debit.account_type` | string | ✅ | `CHECKING` or `SAVINGS` |
| `payment_source.bank.ach_debit.ownership_type` | string | ✅ | `PERSONAL` or `BUSINESS`. Must be `BUSINESS` for CCD. |
| `payment_source.bank.ach_debit.attributes.vault.store_in_vault` | string | ❌ | `ON_SUCCESS` to tokenize on successful transaction |
| `payment_source.bank.ach_debit.stored_credential.payment_initiator` | string | ❌ | e.g., `CUSTOMER` |
| `payment_source.bank.ach_debit.stored_credential.payment_type` | string | ❌ | e.g., `RECURRING` |
| `payment_source.bank.ach_debit.stored_credential.usage` | string | ❌ | `FIRST` or `SUBSEQUENT` |
| `payment_source.bank.ach_debit.payment_context.standard_entry_class_code` | string | ❌ | SEC code: `WEB` (default), `TEL`, `CCD`, `PPD` |
| `payment_source.bank.ach_debit.payment_context.payee_preferred` | string | ❌ | Set to `IMMEDIATE_PAYMENT_REQUIRED` for instant ACH transfer |

#### cURL Example

```bash
curl -v -k -X POST https://api-m.paypal.com/v2/checkout/orders/5O190127TN364715T/capture \
  -H 'Authorization: Bearer ACCESS-TOKEN;' \
  -H 'Content-Type: application/json' \
  -d '{
    "payment_source": {
      "bank": {
        "ach_debit": {
          "account_number": "ACCOUNT-NUMBER",
          "routing_number": "ROUTING-NUMBER",
          "account_holder_name": "ACCOUNT-HOLDER-NAME",
          "account_type": "ACCOUNT-TYPE",
          "ownership_type": "OWNERSHIP-TYPE",
          "attributes": {
            "vault": {
              "store_in_vault": "ON_SUCCESS"
            }
          },
          "stored_credential": {
            "payment_initiator": "CUSTOMER",
            "payment_type": "RECURRING",
            "usage": "FIRST"
          },
          "payment_context": {
            "standard_entry_class_code": "WEB"
          }
        }
      }
    }
  }'
```

#### Step Result

| Event | Description |
|---|---|
| `PAYMENT.CAPTURE.PENDING` | Transaction not declined; status updates within 5 calendar days |
| `PAYMENT.CAPTURE.COMPLETED` | Payment successfully completed |
| `PAYMENT.CAPTURE.DENIED` | Payment declined (e.g., incorrect routing/account number) |

**Tokenization response fields (when vault used):**

| Field | Description |
|---|---|
| `vault.id` | Unique token identifying the stored bank account |
| `vault.customer.id` | Unique PayPal reference for the customer |
| `ach_debit.last_digits` | Last 4 digits of bank account |
| `ach_debit.routing_number` | Bank routing number |

---

### 3. Capture Order — With Vault Token (ACH)

**POST** `/v2/checkout/orders/{order_id}/capture`

Captures funds using a previously stored vault token instead of raw bank account details.

#### Path Parameters

| Parameter | Description |
|---|---|
| `order_id` | The ID of the order to capture |

#### Request Body Schema

| Field | Type | Required | Description |
|---|---|---|---|
| `payment_source.bank.ach_debit.vault_id` | string | ✅ | Token returned from prior tokenization |
| `payment_source.bank.ach_debit.stored_credential.payment_initiator` | string | ❌ | e.g., `MERCHANT` |
| `payment_source.bank.ach_debit.stored_credential.payment_type` | string | ❌ | e.g., `RECURRING` |
| `payment_source.bank.ach_debit.stored_credential.usage` | string | ❌ | `SUBSEQUENT` for repeat transactions |
| `payment_source.bank.ach_debit.payment_context.standard_entry_class_code` | string | ❌ | SEC code: `WEB` (default), `TEL`, `CCD`, `PPD` |

#### cURL Example

```bash
curl -v -k -X POST https://api-m.paypal.com/v2/checkout/orders/5O190127TN364715T/capture \
  -H 'Authorization: Bearer ACCESS-TOKEN;' \
  -H 'Content-Type: application/json' \
  -d '{
    "payment_source": {
      "bank": {
        "ach_debit": {
          "vault_id": "VAULT-ID",
          "stored_credential": {
            "payment_initiator": "MERCHANT",
            "payment_type": "RECURRING",
            "usage": "SUBSEQUENT"
          },
          "payment_context": {
            "standard_entry_class_code": "WEB"
          }
        }
      }
    }
  }'
```

#### Step Result

| Event | Description |
|---|---|
| `PAYMENT.CAPTURE.PENDING` | Transaction not declined; status updates within 5 calendar days |
| `PAYMENT.CAPTURE.COMPLETED` | Payment successfully completed |
| `PAYMENT.CAPTURE.DENIED` | Payment declined |

---

### 4. Tokenization (Vault API)

**Without a transaction:** Provide bank account details on the Vault API to receive a token and basic bank details.

**With a transaction:** Provide bank account details along with order information in the Orders API. Bank details are saved if the transaction is set up successfully.

> **Note:** Full Vault API endpoint path is not specified in source. Detokenization is available via Vault API using the token from tokenization.

#### Tokenization Input Fields

| Field | Description |
|---|---|
| `account_number` | Full bank account number |
| `routing_number` | Bank routing number |
| `account_type` | `CHECKING` or `SAVINGS` |
| `ownership_type` | `PERSONAL` or `BUSINESS` |
| `account_holder_name` | Name of account holder |
| `verification_method` | Not specified in source |

#### Tokenization Response Fields

| Field | Description |
|---|---|
| `vault.id` | Unique token for the stored bank account |
| `vault.customer.id` | Unique PayPal reference for the customer |
| `ach_debit.last_digits` | Last 4 digits of bank account |
| `ach_debit.routing_number` | Bank routing number |

---

## Flow Categories

### Payment / Authorization Flow

1. Complete Merchant Onboarding
2. Obtain access token (see Get Started)
3. **Create Order** (`POST /v2/checkout/orders`) with `intent: CAPTURE`
4. Payer completes checkout flow → order status becomes `APPROVED`
5. **Capture Order** (`POST /v2/checkout/orders/{id}/capture`) with bank account info or vault token

### Tokenization / Vaulting Flow

- **Tokenize with transaction:** Include `attributes.vault.store_in_vault: ON_SUCCESS` in capture call
- **Tokenize without transaction:** Use Vault API directly with bank account fields
- **Use token:** Pass `vault_id` in the `ach_debit` object instead of raw bank details
- **Detokenize:** Use Vault API detokenize endpoint with the token to retrieve full bank account info

### Recurring Payments Flow

- First transaction: `stored_credential.usage: FIRST`, `payment_initiator: CUSTOMER`
- Subsequent transactions: `stored_credential.usage: SUBSEQUENT`, `payment_initiator: MERCHANT`, use `vault_id`

---

## Standard Entry Class (SEC) Codes

| Code | Name | Use Case | Notes |
|---|---|---|---|
| `WEB` | Internet Initiated Entry | Online direct debit payments | Default. Must collect online authorization. |
| `TEL` | Telephone Initiated Entry | One-time consumer debit authorized by phone | Must collect oral or written authorization. |
| `CCD` | Corporate Credit or Debit | Debiting from a business bank account | `ownership_type` must be `BUSINESS`. Unauthorized return window: 2 business days. |
| `PPD` | Prearranged Payment and Deposit | Consumer account, standing or single-entry authorization | Must have clear and understandable authorization terms. |

---

## Configuration Parameters

| Parameter | Value / Notes |
|---|---|
| Supported Currency | USD only |
| Chargeback Rate Limit | Must be < 0.25% |
| Bank Unauthorized Rate Limit | Must be < 0.25% |
| Standard ACH Settlement | 5 calendar days |
| Consumer Unauthorized Return Window | 60 days |
| Business (CCD) Unauthorized Return Window | 2 business days |
| Instant ACH Option | Set `payee_preferred: IMMEDIATE_PAYMENT_REQUIRED` in `payment_context` |
| Vault Store Trigger | `store_in_vault: ON_SUCCESS` in `attributes.vault` |

---

## ACH Return Reason Codes

| Code | Description | Action |
|---|---|---|
| R01 | Insufficient Funds | Contact payer; ask them to add funds or use different payment method |
| R02 | Account Closed | Contact payer; stop recurring payments from this account |
| R03 | No Account / Unable to Locate Account | Contact payer; stop recurring payments from this account |
| R04 | Invalid Account Number Structure | Contact payer; stop recurring payments from this account |
| R05 | Unauthorized Debit to Consumer Account Using Corporate SEC Code | Correct SEC code and resubmit |
| R06 | Returned per ODFI's Request | Resubmit; contact PayPal if PayPal initiated stop |
| R07 | Authorization Revoked by Customer | Contact payer to resolve |
| R08 | Payment Stopped | Contact payer to resolve |
| R09 | Uncollected Funds | Contact payer; resubmit or request new payment method |
| R10 | Customer Advises Unauthorized / Improper / Ineligible / Incomplete Transaction | Contact payer to resolve |
| R12 | Account Sold to Another DFI | Contact payer; stop recurring payments from this account |
| R13 | Invalid ACH Routing Number | Contact payer; stop recurring payments from this account |
| R14 | Representative Payee Deceased or Unable to Continue | Contact payer; stop recurring payments from this account |
| R15 | Beneficiary of Account Holder Deceased | Contact payer; stop recurring payments from this account |
| R16 | Account Frozen / Returned per OFAC Instruction | Contact payer; stop recurring payments from this account |
| R17 | File Record Edit Criteria | Correct payment fields and resubmit |
| R20 | Non-Transaction Account | Contact payer; stop recurring payments from this account |
| R24 | Duplicate Entry | Verify if duplicate before resending |
| R29 | Corporate Customer Advises Not Authorized | Contact payer to resolve |
| R34 | Limited Participation DFI | Contact payer; stop recurring payments from this account |

---

## Daily Reports

| Report | Description |
|---|---|
| **Decline Analysis Report** | All returned/declined standard ACH debit transactions with ACH network reason codes |
| **Financial Summary Report** | Liability charges from returned ACH transactions; includes instant ACH bank returns, original returned transactions, and fees incurred |

---

## Liability Notes

| Scenario | Liability |
|---|---|
| Unauthorized return (consumer account) | Original transaction amount + $5 dispute fee |
| Unauthorized return (business/CCD account) | Original transaction amount + $5 dispute fee |
| Non-unauthorized return (standard ACH) | Return fee only |
| Non-unauthorized return (instant ACH) | Original transaction amount + return fee |

> ⚠️ Do not issue a refund until funds settle in your account. Simultaneous refund and unauthorized dispute = double-credit to payer.

---

## Authorization Text Reference

### Recurring Payments

> By clicking ["Checkout/Submit"], I authorize PayPal, on behalf of [your business name here] to verify my bank account information using bank information and consumer reports and I authorize [your business name here] to initiate an ACH/electronic debit to my checking/savings account, Depository Name: [customer name], Routing Number: [customer's bank routing number] and Account Number: [customer's bank account number], that will be stored on file, and debited on or after the due date. I agree the ACH transactions I authorize comply with all applicable laws. I understand that this authorization will remain in full force and effect until I notify [your business name here] that I wish to revoke this authorization.

### One-Time Payment

> By clicking ["Checkout/Submit"], I authorize PayPal, on behalf of [your business name here] to verify my bank account information using bank information and consumer reports and I authorize [your business name here] to initiate an ACH/electronic debit to my checking/savings account, Depository Name: [customer name], Routing Number: [customer's bank routing number] and Account Number: [customer's bank account number], in the amount of [$XXX] on [date]. I agree the ACH transactions I authorize comply with all applicable laws.

---

*Documentation generated from PayPal ACH Direct Debit integration guide and Orders v2 API reference.*
