# ACH Direct Debit API Documentation

---

## Connector Information

**Payment Method:** ACH Direct Debit  
**Network:** ACH (Automated Clearing House)  
**Region:** United States only  
**API Type:** GraphQL (mutations and queries)  
**Client SDK:** JavaScript v3 SDK  
**Drop-in UI Support:** Not available

---

## Overview

ACH Direct Debit allows customers to pay for transactions by debiting directly from their bank account, as opposed to processing through a card brand.

Accepting ACH payments consists of four core concepts:

1. **Tokenizing** – Exchange raw payment information for a secure, single-use payment method ID (nonce)
2. **Vaulting** – Exchange a single-use nonce for a persistent, multi-use payment method token
3. **Verifying** – Confirm the customer owns the bank account
4. **Transacting** – Charge the verified, vaulted bank account

---

## Authentication

- **Not specified in source** (standard Braintree API authentication is assumed to apply)

---

## Complete Endpoint Inventory

### 1. Tokenize US Bank Account

**Operation:** `mutation TokenizeUsBankAccount`  
**Purpose:** Exchange raw bank account details for a single-use payment method ID. Does not verify the account; the resulting token is not transactable until vaulted and verified.

#### Mutation

```graphql
mutation TokenizeUsBankAccount($input: TokenizeUsBankAccountInput!) {
  tokenizeUsBankAccount(input: $input) {
    paymentMethod {
      id
      usage
      createdAt
      details {
        ... on UsBankAccountDetails {
          accountholderName
          accountType
          bankName
          last4
          routingNumber
          verified
          achMandate {
            acceptedAt
            acceptanceText
          }
        }
      }
    }
  }
}
```

#### Request Variables

```json
{
  "input": {
    "usBankAccount": {
      "routingNumber": "a_routing_number",
      "accountNumber": "an_account_number",
      "accountType": "CHECKING",
      "achMandate": "I agree to give away all my money",
      "individualOwner": {
        "firstName": "Busy",
        "lastName": "Bee"
      },
      "billingAddress": {
        "streetAddress": "111 Main St",
        "extendedAddress": "#7",
        "city": "San Jose",
        "state": "CA",
        "zipCode": "94085"
      }
    }
  }
}
```

#### Response

```json
{
  "data": {
    "tokenizeUsBankAccount": {
      "paymentMethod": {
        "id": "id_of_payment_method",
        "usage": "SINGLE_USE",
        "createdAt": "created_at_date",
        "details": {
          "accountholderName": "Busy Bee",
          "accountType": "CHECKING",
          "bankName": "name_of_bank",
          "last4": "last_4_digits_of_an_account_number",
          "routingNumber": "a_routing_number",
          "verified": false,
          "achMandate": null
        }
      }
    }
  },
  "extensions": {
    "requestId": "a-uuid-for-the-request"
  }
}
```

---

### 2. Vault US Bank Account

**Operation:** `mutation VaultUsBankAccount`  
**Purpose:** Exchange a single-use payment method ID for a multi-use payment method token. Optionally initiates verification in the same step. A vaulted payment method is only transactable after a successful verification.

> **Note:** Each single-use payment method ID can only be vaulted once.

#### Mutation

```graphql
mutation VaultUsBankAccount($input: VaultUsBankAccountInput!) {
  vaultUsBankAccount(input: $input) {
    paymentMethod {
      id
      legacyId
      details {
        ... on UsBankAccountDetails {
          accountholderName
          accountType
          bankName
          last4
          routingNumber
          verified
          achMandate {
            acceptedAt
            acceptanceText
          }
        }
      }
    }
    verification {
      id
      status
    }
  }
}
```

#### Request Variables

```json
{
  "input": {
    "paymentMethodId": "id_of_payment_method",
    "verificationMerchantAccountId": "id_of_merchant_account",
    "verificationMethod": "MICRO_TRANSFERS"
  }
}
```

| Field | Required | Description |
|---|---|---|
| `paymentMethodId` | Required | Single-use ACH payment method ID |
| `verificationMerchantAccountId` | Optional | ID of merchant account to use for verification |
| `verificationMethod` | Optional | Verification method: `MICRO_TRANSFERS`, `NETWORK_CHECK`, or `INDEPENDENT_CHECK` |

#### Response

```json
{
  "data": {
    "vaultUsBankAccount": {
      "paymentMethod": {
        "id": "id_of_payment_method",
        "legacyId": "legacy_id_of_payment_method",
        "details": {
          "accountholderName": "Busy Bee",
          "accountType": "CHECKING",
          "bankName": "name_of_bank",
          "last4": "3210",
          "routingNumber": "a_routing_number",
          "verified": false,
          "achMandate": {
            "acceptedAt": "accepted_at_date",
            "acceptanceText": "I agree to give away all my money"
          }
        }
      },
      "verification": {
        "id": "id_of_verification",
        "status": "PENDING"
      }
    }
  },
  "extensions": {
    "requestId": "a-uuid-for-the-request"
  }
}
```

---

### 3. Verify US Bank Account (Network Check)

**Operation:** `mutation VerifyUsBankAccount`  
**Purpose:** Instantly verifies bank account details using account and routing numbers. Optional add-ons (e.g., `CUSTOMER_VERIFICATION`) can be requested for additional personal/business information verification.

#### Mutation

```graphql
mutation VerifyUsBankAccount($input: VerifyUsBankAccountInput!) {
  verifyUsBankAccount(input: $input) {
    verification {
      id
      legacyId
      status
      merchantAccountId
      createdAt
      gatewayRejectionReason
      paymentMethod {
        id
      }
      processorResponse {
        legacyCode
        message
      }
    }
  }
}
```

#### Request Variables

```json
{
  "input": {
    "paymentMethodId": "id_of_payment_method",
    "verificationMethod": "NETWORK_CHECK",
    "verificationAddOns": [
      "CUSTOMER_VERIFICATION"
    ]
  }
}
```

| Field | Required | Description |
|---|---|---|
| `paymentMethodId` | Required | Payment method ID to verify |
| `verificationMethod` | Required | Must be `NETWORK_CHECK` for this flow |
| `verificationAddOns` | Optional | E.g., `CUSTOMER_VERIFICATION` for additional info |

#### Response

```json
{
  "data": {
    "verifyUsBankAccount": {
      "verification": {
        "id": "id_of_verification",
        "legacyId": "legacy_id_of_verification",
        "status": "VERIFIED",
        "merchantAccountId": "id_of_merchant_account",
        "createdAt": "created_at_date",
        "gatewayRejectionReason": null,
        "paymentMethod": {
          "id": "id_of_payment_method"
        },
        "processorResponse": {
          "legacyCode": "1000",
          "message": "Approved"
        }
      }
    }
  },
  "extensions": {
    "requestId": "a-uuid-for-the-request"
  }
}
```

---

### 4. Confirm Micro-Transfer Amounts

**Operation:** `mutation ConfirmMicroTransferAmounts`  
**Purpose:** Completes verification for a US bank account via micro-transfers. The customer must provide the two micro-deposit amounts they observed in their bank account. This step is **required** when using the `MICRO_TRANSFERS` verification method.

#### Mutation

```graphql
mutation ConfirmMicroTransferAmounts(
  $input: ConfirmMicroTransferAmountsInput!
) {
  confirmMicroTransferAmounts(input: $input) {
    verification {
      id
      paymentMethod {
        id
        usage
      }
      merchantAccountId
      status
      processorResponse {
        message
      }
    }
    status
  }
}
```

#### Request Variables

```json
{
  "input": {
    "verificationId": "id_of_verification",
    "amountsInCents": [
      17,
      44
    ]
  }
}
```

| Field | Required | Description |
|---|---|---|
| `verificationId` | Required | ID of the verification to confirm |
| `amountsInCents` | Required | Array of two micro-deposit amounts in cents as entered by the customer |

#### Response

```json
{
  "data": {
    "confirmMicroTransferAmounts": {
      "verification": {
        "id": "id_of_verification",
        "paymentMethod": {
          "id": "id_of_payment_method",
          "usage": "MULTI_USE"
        },
        "merchantAccountId": "id_of_merchant_account",
        "status": "CONFIRMED",
        "processorResponse": {
          "message": "Approved"
        }
      }
    },
    "extensions": {
      "requestId": "a-uuid-for-the-request"
    }
  }
}
```

---

### 5. Look Up Verification Status

**Operation:** `query` (search verifications)  
**Purpose:** Periodically check the state of a verification by its ID. Required when using the micro-transfers method, as the bank account may still be waiting for transfers to settle after `confirmMicroTransferAmounts` is called.

#### Query

```graphql
query ($input: VerificationSearchInput!) {
  search {
    verifications(input: $input) {
      edges {
        node {
          id
          status
        }
      }
    }
  }
}
```

#### Request Variables

```json
{
  "input": {
    "id": {
      "is": "id_of_verification"
    }
  }
}
```

#### Response

```json
{
  "data": {
    "search": {
      "verifications": {
        "edges": [
          {
            "node": {
              "id": "id_of_verification",
              "status": "VERIFIED"
            }
          }
        ]
      }
    }
  },
  "extensions": {
    "requestId": "a-uuid-for-the-request"
  }
}
```

---

### 6. Charge US Bank Account

**Operation:** `mutation ChargeUsBankAccount`  
**Purpose:** Create a transaction by charging a verified, vaulted (multi-use) US bank account. Collect device data client-side and pass it via `riskData.deviceData` to help reduce decline rates.

#### Mutation

```graphql
mutation ChargeUsBankAccount($input: ChargeUsBankAccountInput!) {
  chargeUsBankAccount(input: $input) {
    transaction {
      id
      amount {
        value
      }
      paymentMethodSnapshot {
        ... on UsBankAccountDetails {
          accountholderName
          accountType
          verified
        }
      }
    }
  }
}
```

#### Request Variables

```json
{
  "input": {
    "paymentMethodId": "id_of_payment_method",
    "transaction": {
      "amount": "10.00",
      "orderId": "id_of_order",
      "riskData": {
        "customerBrowser": "web_browser_type",
        "customerIp": "ip_address",
        "deviceData": "device_type"
      }
    }
  }
}
```

| Field | Required | Description |
|---|---|---|
| `paymentMethodId` | Required | Multi-use verified payment method ID |
| `transaction.amount` | Required | Transaction amount as a string |
| `transaction.orderId` | Optional | Merchant order ID |
| `transaction.riskData.customerBrowser` | Optional | Customer's browser type |
| `transaction.riskData.customerIp` | Optional | Customer's IP address |
| `transaction.riskData.deviceData` | Optional | Device data collected from JS SDK (recommended to reduce declines) |

#### Response

```json
{
  "data": {
    "chargeUsBankAccount": {
      "transaction": {
        "id": "id_of_transaction",
        "amount": {
          "value": "10.00"
        },
        "paymentMethodSnapshot": {
          "accountholderName": "Busy Bee",
          "accountType": "CHECKING",
          "verified": false
        }
      }
    }
  },
  "extensions": {
    "requestId": "a-uuid-for-the-request"
  }
}
```

---

## Verification Methods

| Method | Description | Notes |
|---|---|---|
| `NETWORK_CHECK` | Instantly verifies account using bank account and routing number; applies risk rules | Optional add-ons available (e.g., `CUSTOMER_VERIFICATION`) |
| `MICRO_TRANSFERS` | Issues two credits of < $1.00 each; customer must confirm exact amounts | Requires a follow-up `confirmMicroTransferAmounts` call and polling for status |
| `INDEPENDENT_CHECK` | Merchant uses their own verification method and manually marks the account as verified | Set `verificationMethod` to `INDEPENDENT_CHECK`; no verification initiated by Braintree |

**Recommended flow:** Use `NETWORK_CHECK` as the primary method, and fall back to `MICRO_TRANSFERS` if it fails (e.g., message: `"No Data Found - Try Another Verification Method"`).

---

## Flow Summary

```
tokenizeUsBankAccount
        │
        ▼
vaultUsBankAccount  ──(optional: verificationMethod)──► verification initiated
        │
        ▼
[Verification Flow – choose one]
  ├── NETWORK_CHECK → verifyUsBankAccount → check processorResponse.message for "Approved"
  ├── MICRO_TRANSFERS → confirmMicroTransferAmounts → poll search.verifications for status
  └── INDEPENDENT_CHECK → mark verified externally
        │
        ▼
chargeUsBankAccount (requires verified multi-use payment method)
```

---

## Error Responses

### Duplicate Vault Attempt

Occurs when attempting to vault a single-use payment method ID more than once.

```json
{
  "errors": [
    {
      "message": "Cannot use a single-use payment method more than once.",
      "locations": [
        {
          "line": 2,
          "column": 3
        }
      ],
      "path": [
        "vaultUsBankAccount"
      ],
      "extensions": {
        "errorClass": "VALIDATION",
        "errorType": "user_error",
        "inputPath": [
          "input",
          "paymentMethodId"
        ],
        "legacyCode": "93107"
      }
    }
  ],
  "data": {
    "vaultUsBankAccount": null
  },
  "extensions": {
    "requestId": "a-uuid-for-the-request"
  }
}
```

### Missing `verificationMethod`

Occurs when `verificationMethod` is not provided where it is required (non-null field).

```json
{
  "errors": [
    {
      "message": "Variable 'input' has an invalid value: Field 'verificationMethod' has coerced Null value for NonNull type 'UsBankAccountVerificationMethod!'",
      "locations": [
        {
          "line": 1,
          "column": 29
        }
      ]
    }
  ],
  "extensions": {
    "requestId": "a-uuid-for-the-request"
  }
}
```

### Verification Failure Messages

| Message | Meaning |
|---|---|
| `"Approved"` | Verification successful |
| `"Processor Network Unavailable - Try Again"` | Transient failure; retry |
| `"No Data Found - Try Another Verification Method"` | Network check found no data; retry with `MICRO_TRANSFERS` |
| `"Invalid routing number"` | Routing number is not valid |
| `"Invalid account type"` | Account type is not recognized |

> **Tip:** To get additional failure details, request `additionalInformation` under `processorResponse` in your `verifyUsBankAccount` query.

---

## Configuration Parameters

| Parameter | Description |
|---|---|
| `paymentMethodId` | Single-use or multi-use payment method ID |
| `verificationMerchantAccountId` | Merchant account to use for verification |
| `verificationMethod` | One of: `NETWORK_CHECK`, `MICRO_TRANSFERS`, `INDEPENDENT_CHECK` |
| `verificationAddOns` | Optional array; e.g., `CUSTOMER_VERIFICATION` |
| `accountType` | `CHECKING` (shown in examples) |
| `riskData.deviceData` | Client-side device data from JS v3 SDK; reduces decline rates |

---

## Integration Requirements

- **Client-side SDK:** Braintree JavaScript v3 SDK (required for tokenization)
- **Server-side SDK:** Any Braintree server-side SDK (for vaulting, verifying, transacting)
- **Drop-in UI:** Not supported for ACH Direct Debit
- **Geography:** United States only
- **Device Data:** Collect via JS v3 SDK and pass to `chargeUsBankAccount` via `riskData.deviceData` to reduce decline rates
