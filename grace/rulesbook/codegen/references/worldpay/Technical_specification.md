 # Worldpay Access Payments API Documentation

**Version:** 2024-06-01  
**Description:** A single API that orchestrates the payment flow to include FraudSight, 3DS and Token creation.

---

## Connector Information

### Base URLs

| Environment | URL |
|-------------|-----|
| Test (Try) | `https://try.access.worldpay.com` |
| Live | `https://access.worldpay.com` |

### Additional URLs

| Purpose | URL |
|---------|-----|
| Service Status | `https://status.access.worldpay.com/` |
| Documentation | `https://docs.worldpay.com/access/products/payments` |
| Postman Collection | `https://docs.worldpay.com/access/products/payments/collections` |
| OpenAPI JSON | `https://docs.worldpay.com/access/_bundle/products/payments/@20240601/openapi.json` |
| OpenAPI YAML | `https://docs.worldpay.com/access/_bundle/products/payments/@20240601/openapi.yaml` |

### DNS Whitelisting Requirements

Whitelist the following URLs:
- `https://try.access.worldpay.com/`
- `https://access.worldpay.com/`

**Note:** Use DNS whitelisting, not explicit IP whitelisting. Cache responses returned from Access Worldpay.

---

## Authentication

### Method
Basic Authentication (BasicAuth)

### Required Headers

| Header | Value | Description |
|--------|-------|-------------|
| `Authorization` | `{your_credentials}` | Base64-encoded Basic Auth username and password |
| `Content-Type` | `application/json` | Content type for requests |
| `WP-Api-Version` | `2024-06-01` | The API version (required for all requests) |

---

## Endpoint Inventory

### Payment Operations

#### 1. Payment Authorization

**Endpoint:** `POST /api/payments`  
**Description:** Take a payment / Initiate payment

**Servers:**
- Test: `https://try.access.worldpay.com/api/payments`
- Live: `https://access.worldpay.com/api/payments`

**Headers:**
- `WP-Api-Version`: `2024-06-01` (required)
- `Content-Type`: `application/json`
- `Authorization`: BasicAuth credentials

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `transactionReference` | string [1..64] | Yes | Unique merchant reference. Pattern: `^[-A-Za-z0-9_!@#$%()\*=.:;?\\[\\]{}~\`/+\]*$` |
| `merchant` | object | Yes | Merchant information |
| `merchant.entity` | string [1..32] | Yes | Routing entity. Pattern: `^([A-Za-z0-9]+[A-Za-z0-9 ]*)?$`. Example: "default" |
| `merchant.mcc` | string | No | Merchant category code. Pattern: `^\d{4}$` |
| `merchant.paymentFacilitator` | object | No | Payment facilitator details |
| `instruction` | object | Yes | Payment configuration |
| `instruction.method` | string | Yes | Payment method. Values: "card", "applepay", "googlepay" |
| `instruction.paymentInstrument` | object | Yes | Payment instrument details |
| `instruction.narrative` | object | Yes | Statement descriptor text |
| `instruction.tokenCreation` | object | No | Token creation settings (card/plain & checkout only) |
| `instruction.value` | object | Yes | Amount and currency |
| `instruction.debtRepayment` | boolean | No | Debt repayment flag |
| `instruction.fraud` | object | No | Fraud assessment configuration |
| `instruction.threeDS` | object | No | 3DS authentication preferences |
| `instruction.exemption` | object | No | SCA Exemption request |
| `instruction.settlement` | object | No | Auto settlement configuration |
| `instruction.customer` | object | No | Customer details |
| `instruction.shipping` | object | No | Shipping data for 3DS/Risk |
| `instruction.customerAgreement` | object | No | Customer agreements |
| `instruction.recipient` | object | No | Recipient info for MCC 6012 (Visa Europe) |
| `instruction.consumerBillPayment` | boolean | No | Consumer bill payment flag (CBPS) |
| `instruction.fundsTransfer` | object | No | Account Funding Transaction details |
| `instruction.requestAccountUpdater` | boolean | No | Real-time account update request (Visa only) |
| `channel` | string | No | Interaction type. Enum: "ecom", "moto". Note: 3DS cannot be used for MOTO |

**Example Request:**
```json
{
  "transactionReference": "Memory265-13/08/1876",
  "merchant": {
    "entity": "default"
  },
  "instruction": {
    "method": "card",
    "paymentInstrument": {
      "type": "plain",
      "cardHolderName": "Sherlock Holmes",
      "cardNumber": "4000000000001091",
      "expiryDate": {
        "month": 5,
        "year": 2035
      },
      "billingAddress": {
        "address1": "221B Baker Street",
        "address2": "Marylebone",
        "address3": "Westminster",
        "postalCode": "SW1 1AA",
        "city": "London",
        "state": "Greater London",
        "countryCode": "GB"
      },
      "cvc": "123"
    },
    "narrative": {
      "line1": "trading name"
    },
    "value": {
      "currency": "GBP",
      "amount": 42
    }
  }
}
```

**Response Codes:** 201, 202, 400, 401, 404, 406, 415, 500

**Response 201 (Created):**

| Field | Type | Description |
|-------|------|-------------|
| `outcome` | string | authorized, refused, fraudHighRisk, 3dsDeviceDataRequired |
| `paymentId` | string | Unique payment identifier. Pattern: `^[A-Za-z0-9_-]+$` |
| `transactionReference` | string | Merchant reference |
| `paymentInstrument` | object | Payment instrument details |
| `paymentInstrument.type` | string | Instrument type |
| `paymentInstrument.cardBin` | string | Card BIN (first 6-8 digits) |
| `paymentInstrument.lastFour` | string | Last four digits |
| `paymentInstrument.countryCode` | string | ISO 3166-1 Alpha-2 country code |
| `paymentInstrument.expiryDate` | object | Expiry date |
| `paymentInstrument.cardBrand` | string | Card brand |
| `paymentInstrument.fundingType` | string | credit, debit, prepaid, chargeCard, deferredDebit, unknown |
| `paymentInstrument.category` | string | commercial, consumer |
| `paymentInstrument.issuerName` | string | Issuer name |
| `paymentInstrument.paymentAccountReference` | string | PAR reference |
| `updatedPaymentInstrument` | object | Updated instrument details |
| `issuer` | object | Contains `authorizationCode` |
| `riskFactors` | array | Risk factors identified |
| `fraud` | object | Fraud assessment outcome |
| `fraud.outcome` | string | lowRisk, highRisk, review, lowRisk(silentMode), highRisk(silentMode), review(silentMode) |
| `fraud.score` | number | Fraud score |
| `threeDS` | object | 3DS authentication details |
| `threeDS.outcome` | string | authenticated, authenticationOutage |
| `threeDS.issuerResponse` | string | frictionless, challenged |
| `threeDS.version` | string | 3DS version |
| `threeDS.eci` | string | Electronic Commerce Indicator |
| `threeDS.acsTransactionId` | string | ACS transaction ID |
| `threeDS.dsTransactionId` | string | Directory server transaction ID |
| `threeDS.status` | string | Y, N, U, A, C, R, I |
| `threeDS.challengePreference` | string | Cartes Bancaires challenge preference |
| `exemption` | object | Exemption details |
| `schemeReference` | string | Scheme reference |
| `token` | object | Token details (if created) |
| `amounts` | object | Transaction amounts (for partial authorizations) |
| `_links` | object | Payment status links |
| `_actions` | object | Available actions |

**Example Response 201:**
```json
{
  "outcome": "authorized",
  "paymentId": "payI-dUcet9fk4_X4qZU0hpU0",
  "transactionReference": "Memory265-13/08/1876",
  "schemeReference": "060720116005060",
  "issuer": {
    "authorizationCode": "675725"
  },
  "riskFactors": [
    {
      "risk": "notChecked",
      "type": "cvc"
    },
    {
      "risk": "notChecked",
      "detail": "address",
      "type": "avs"
    },
    {
      "risk": "notChecked",
      "detail": "postcode",
      "type": "avs"
    }
  ],
  "paymentInstrument": {
    "type": "card/plain+masked",
    "cardBin": "400000",
    "lastFour": "1000",
    "countryCode": "GB",
    "expiryDate": {
      "year": 2035,
      "month": 5
    },
    "cardBrand": "mastercard",
    "fundingType": "debit",
    "category": "consumer",
    "issuerName": "BANK LIMITED",
    "paymentAccountReference": "3001DBT34Q41D6J7PFC5W0UACOT4C"
  },
  "_links": {
    "self": {
      "href": "https://try.access.worldpay.com/api/payments/..."
    }
  },
  "_actions": {
    "cancelPayment": {
      "href": "https://try.access.worldpay.com/api/payments/.../cancellations",
      "method": "POST"
    },
    "settlePayment": {
      "href": "https://try.access.worldpay.com/api/payments/.../settlements",
      "method": "POST"
    },
    "partiallySettlePayment": {
      "href": "https://try.access.worldpay.com/api/payments/.../partialSettlements",
      "method": "POST"
    },
    "reversePayment": {
      "href": "https://try.access.worldpay.com/api/payments/.../reversals",
      "method": "POST"
    }
  }
}
```

#### 2. 3DS Device Data Submission

**Endpoint:** `POST /api/payments/{linkData}/3dsDeviceData`  
**Description:** Submit 3DS device data

**Path Parameters:**
- `linkData`: string (required) - Payment link identifier

#### 3. 3DS Challenge Response

**Endpoint:** `POST /api/payments/{linkData}/3dsChallenges`  
**Description:** Submit 3DS challenge response

**Path Parameters:**
- `linkData`: string (required) - Payment link identifier

---

### Payment Management

#### 4. Query Payment

**Endpoint:** `GET /api/payments/{linkData}`  
**Description:** Query a payment status and available actions

**Path Parameters:**
- `linkData`: string (required) - Payment link identifier

**Headers:**
- `WP-Api-Version`: `2024-06-01` (required)

**Request Body:** No request payload

**Response Codes:** 200, 400, 404, 500

**Response 200 (OK):**

| Field | Type | Description |
|-------|------|-------------|
| `lastEvent` | string | Last event received for payment |
| `_actions` | object | Available actions |

**lastEvent Values:**
- `authorizationTimedOut` - Authorization request timed out
- `authorizationRequested` - Authorization request received
- `authorizationRefused` - Authorization refused by card issuer
- `refundRequested` - Refund request received
- `reversalTimedOut` - Reversal request timed out
- `reversalRequestSubmitted` - Reversal request sent for processing
- `cancellationRequestSubmitted` - Cancellation request sent for processing
- `reversalRequested` - Reversal request received
- `cancellationTimedOut` - Cancellation request timed out
- `cancellationRequested` - Cancellation request received
- `authorizationSucceeded` - Authorization succeeded
- `+11 more`

**Example Response:**
```json
{
  "lastEvent": "authorizationSucceeded",
  "_actions": {
    "cancelPayment": {
      "href": "https://try.access.worldpay.com/api/payments/{linkData}/cancellations",
      "method": "POST"
    },
    "settlePayment": {
      "href": "https://try.access.worldpay.com/api/payments/{linkData}/settlements",
      "method": "POST"
    },
    "partiallySettlePayment": {
      "href": "https://try.access.worldpay.com/api/payments/{linkData}/partialSettlements",
      "method": "POST"
    },
    "refundPayment": {
      "href": "https://try.access.worldpay.com/api/payments/{linkData}/refunds",
      "method": "POST"
    },
    "partiallyRefundPayment": {
      "href": "https://try.access.worldpay.com/api/payments/{linkData}/partialRefunds",
      "method": "POST"
    },
    "reversePayment": {
      "href": "https://try.access.worldpay.com/api/payments/{linkData}/reversals",
      "method": "POST"
    }
  }
}
```

#### 5. Settle Payment (Full)

**Endpoint:** `POST /api/payments/{linkData}/settlements`  
**Description:** Settle a payment (full settlement)

**Path Parameters:**
- `linkData`: string (required) - Payment link identifier

**Headers:**
- `WP-Api-Version`: `2024-06-01` (required)

**Request Body:** `any` (optional, can be null)

**Response Codes:** 202, 401, 404, 406, 415, 500

**Response 202 (Accepted):**

| Field | Type | Description |
|-------|------|-------------|
| `outcome` | string | Value: `sentForSettlement` |
| `paymentId` | string | Payment identifier |
| `_links` | object | Payment status links |
| `_links.self` | object | Self link |
| `_actions` | object | Available actions |

**Example Response:**
```json
{
  "outcome": "sentForSettlement",
  "paymentId": "string",
  "_links": {
    "self": {
      "href": "https://try.access.worldpay.com/api/payments/{linkData}"
    }
  },
  "_actions": {
    "refundPayment": {
      "href": "https://try.access.worldpay.com/api/payments/{linkData}/refunds",
      "method": "POST"
    },
    "partiallyRefundPayment": {
      "href": "https://try.access.worldpay.com/api/payments/{linkData}/partialRefunds",
      "method": "POST"
    },
    "reversePayment": {
      "href": "https://try.access.worldpay.com/api/payments/{linkData}/reversals",
      "method": "POST"
    }
  }
}
```

#### 6. Partial Settlement

**Endpoint:** `POST /api/payments/{linkData}/partialSettlements`  
**Description:** Partially settle a payment

**Path Parameters:**
- `linkData`: string (required) - Payment link identifier

**Headers:**
- `WP-Api-Version`: `2024-06-01` (required)

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `reference` | string (non-empty) | Yes | Reference for partial settlement |
| `sequence` | object | No | Sequence number and total |
| `sequence.number` | integer (int32) | Yes | Sequence number |
| `sequence.total` | integer (int32) | Yes | Total number of expected partial settlements |
| `value` | object | Yes | Value and currency |
| `value.currency` | string (non-empty) | Yes | Three character currency code. Example: "USD" |
| `value.amount` | integer (int32) | Yes | Payment amount (implied decimal). Example: 250 = £2.50 |
| `value.acceptPartialAmount` | boolean | No | Accept partial authorization amount |

**Example Request:**
```json
{
  "sequence": {
    "number": 1,
    "total": 2
  },
  "value": {
    "amount": 500,
    "currency": "GBP"
  },
  "reference": "partial-settle-reference"
}
```

**Response Codes:** 202, 400, 401, 404, 406, 415, 500

**Response 202 (Accepted):**

| Field | Type | Description |
|-------|------|-------------|
| `outcome` | string | Value: `sentForSettlement` |
| `paymentId` | string | Payment identifier |
| `_links` | object | Payment status links |
| `_links.self` | object | Self link |
| `_actions` | object | Available actions (refundPayment, partiallyRefundPayment, partiallySettlePayment, cancelPayment, reversePayment) |

#### 7. Refund Payment (Full)

**Endpoint:** `POST /api/payments/{linkData}/refunds`  
**Description:** Refund a payment (full refund)

**Path Parameters:**
- `linkData`: string (required) - Payment link identifier

**Headers:**
- `WP-Api-Version`: `2024-06-01` (required)

**Request Body:** No request payload

**Response Codes:** 202, 401, 404, 406, 415, 500

**Response 202 (Accepted):**

| Field | Type | Description |
|-------|------|-------------|
| `outcome` | string | Value: `sentForRefund` |
| `paymentId` | string | Payment identifier |
| `_links` | object | Payment status links |
| `_links.self` | object | Self link |

**Example Response:**
```json
{
  "outcome": "sentForRefund",
  "paymentId": "string",
  "_links": {
    "self": {
      "href": "https://try.access.worldpay.com/api/payments/{linkData}"
    }
  }
}
```

#### 8. Partial Refund

**Endpoint:** `POST /api/payments/{linkData}/partialRefunds`  
**Description:** Partially refund a payment

**Path Parameters:**
- `linkData`: string (required) - Payment link identifier

**Headers:**
- `WP-Api-Version`: `2024-06-01` (required)

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `reference` | string (non-empty) | Yes | Reference for partial refund |
| `value` | object | Yes | Value and currency |
| `value.currency` | string (non-empty) | Yes | Three character currency code. Example: "USD" |
| `value.amount` | integer (int32) | Yes | Payment amount (implied decimal). Example: 250 = £2.50 |
| `value.acceptPartialAmount` | boolean | No | Accept partial authorization amount |

**Example Request:**
```json
{
  "value": {
    "amount": 10,
    "currency": "GBP"
  },
  "reference": "partial-refund-reference"
}
```

**Response Codes:** 202, 400, 401, 404, 406, 415, 500

**Response 202 (Accepted):**

| Field | Type | Description |
|-------|------|-------------|
| `outcome` | string | Value: `sentForPartialRefund` |
| `paymentId` | string | Payment identifier |
| `_links` | object | Payment status links |
| `_links.self` | object | Self link |
| `_actions` | object | Available actions (partiallyRefundPayment) |

#### 9. Cancel Payment

**Endpoint:** `POST /api/payments/{linkData}/cancellations`  
**Description:** Cancel a payment

**Path Parameters:**
- `linkData`: string (required) - Payment link identifier

**Headers:**
- `WP-Api-Version`: `2024-06-01` (required)

**Request Body:** No request payload

**Response Codes:** 202, 401, 404, 406, 415, 500

**Response 202 (Accepted):**

| Field | Type | Description |
|-------|------|-------------|
| `outcome` | string | Value: `sentForCancellation` |
| `paymentId` | string | Payment identifier |
| `transactionReference` | string | Transaction reference |
| `schemeReference` | string | Scheme reference |
| `issuer` | object | Contains authorizationCode |
| `riskFactors` | array | Risk factors |
| `fraud` | object | Fraud details |
| `threeDS` | object | 3DS details |
| `paymentInstrument` | object | Payment instrument details |
| `_links` | object | Payment status links |
| `_links.self` | object | Self link |

**Example Response:**
```json
{
  "outcome": "sentForCancellation",
  "paymentId": "payI-dUcet9fk4_X4qZU0hpU0",
  "transactionReference": "f4806b75-89d1-498a-8634-bfa79afca54f",
  "schemeReference": "060720116005060",
  "issuer": {
    "authorizationCode": "675725"
  },
  "riskFactors": [
    {
      "risk": "notMatched",
      "type": "cvc"
    },
    {
      "risk": "notChecked",
      "detail": "address",
      "type": "avs"
    },
    {
      "risk": "notChecked",
      "detail": "postcode",
      "type": "avs"
    }
  ],
  "fraud": {
    "outcome": "lowRisk",
    "score": 44
  },
  "threeDS": {
    "outcome": "authenticated",
    "issuerResponse": "frictionless"
  },
  "paymentInstrument": {
    "type": "card/plain+masked",
    "cardBin": "400000",
    "lastFour": "1000",
    "countryCode": "GB",
    "expiryDate": {
      "year": 2035,
      "month": 5
    },
    "cardBrand": "mastercard",
    "fundingType": "debit",
    "category": "consumer",
    "issuerName": "BANK LIMITED",
    "paymentAccountReference": "3001DBT34Q41D6J7PFC5W0UACOT4C"
  },
  "_links": {
    "self": {
      "href": "https://try.access.worldpay.com/api/payments/{linkData}"
    }
  }
}
```

#### 10. Reverse Payment

**Endpoint:** `POST /api/payments/{linkData}/reversals`  
**Description:** Reverse a payment

**Path Parameters:**
- `linkData`: string (required) - Payment link identifier

**Headers:**
- `WP-Api-Version`: `2024-06-01` (required)

**Request Body:** `any` (optional, can be null)

**Response Codes:** 202, 400, 401, 404, 415, 500

**Response 202 (Accepted):**

| Field | Type | Description |
|-------|------|-------------|
| `outcome` | string | Value: `sentForReversal` |
| `_links` | object | Payment status links |
| `_links.self` | object | Self link |

**Example Response:**
```json
{
  "outcome": "sentForReversal",
  "_links": {
    "self": {
      "href": "https://try.access.worldpay.com/api/payments/{linkData}"
    }
  }
}
```

---

## Configuration Parameters

### Supported Features
- FraudSight (Fraud assessment)
- 3D Secure (3DS) Authentication
- Token creation
- Auto settlement
- SCA Exemptions
- Partial authorizations
- Partial settlements
- Partial refunds
- Payment reversals
- Payment cancellations
- Account Funding Transactions (AFT)
- Real-time Account Updater (Visa only)

### Supported Payment Methods
- Card (plain, tokenized)
- Apple Pay (encrypted, decrypted)
- Google Pay (encrypted, decrypted CRYPTOGRAM_3DS, decrypted PAN_ONLY)

### Channel Types
- `ecom` - eCommerce authorization
- `moto` - Mail Order or Telephone Order (3DS cannot be used for MOTO)

### Card Brands
visa, mastercard, amex, maestro, visaElectron, diners, discover, jcb, argencard, cabal, +17 more

### Funding Types
credit, debit, prepaid, chargeCard, deferredDebit, unknown

### Card Categories
commercial, consumer

### 3DS Outcomes
authenticated, authenticationOutage

### 3DS Status Values
- `Y` - Successful authentication
- `N` - Failed authentication
- `U` - Unable to complete authentication
- `A` - Successful attempts authentication
- `C` - Challenged authentication
- `R` - Authentication rejected (merchant must not submit for authorization)
- `I` - Exemption acknowledged

### 3DS Issuer Response
frictionless, challenged

### Challenge Preference (Cartes Bancaires only)
noPreference, noChallengeRequested, challengeRequested, challengeMandated, noChallengeRequestedTRAPerformed

### ECI Values
- 02 or 05: Fully Authenticated Transaction
- 01 or 06: Attempted Authentication Transaction
- 00 or 07: Non 3-D Secure Transaction

### Exemption Types
lowValue, lowRisk

### Exemption Results
rejected, honored, outOfScope, unknown

### Exemption Reasons
issuerHonored, merchantInitiatedTransaction, oneLegOut, moto, contactless, issuerRejected, highRisk, invalid, unsupportedScheme, notSubscribed, unsupportedAcquirer, unknown

### Risk Factor Types
avs, cvc, riskProfile

### Risk Values
notChecked, notMatched, notSupplied, verificationFailed

### Currency Format
- Three-character ISO currency codes (e.g., "GBP", "USD")
- Amounts in integer format with implied decimal places (e.g., 250 = £2.50)

### Account Updater Messages
- The issuing bank does not participate in the update program
- Contact the cardholder for updated information
- The account number was changed
- No changes found
- The account was closed
- The merchant is not registered in the update program
- The expiry was changed
- No match found

---

## Error Response Codes

### Standard HTTP Status Codes

| Code | Meaning | Usage |
|------|---------|-------|
| 200 | OK | Query requests successful |
| 201 | Created | Payment authorization successful |
| 202 | Accepted | Settlement, refund, cancellation, reversal requests submitted |
| 400 | Bad Request | Invalid request payload |
| 401 | Unauthorized | Authentication failed |
| 404 | Not Found | Payment not found |
| 406 | Not Acceptable | Request not acceptable |
| 415 | Unsupported Media Type | Content type not supported |
| 500 | Internal Server Error | Server error |

### By Endpoint

| Endpoint | Codes |
|----------|-------|
| Payment Authorization | 201, 202, 400, 401, 404, 406, 415, 500 |
| Query Payment | 200, 400, 404, 500 |
| Settle | 202, 401, 404, 406, 415, 500 |
| Partial Settle | 202, 400, 401, 404, 406, 415, 500 |
| Refund | 202, 401, 404, 406, 415, 500 |
| Partial Refund | 202, 400, 401, 404, 406, 415, 500 |
| Cancel | 202, 401, 404, 406, 415, 500 |
| Reverse | 202, 400, 401, 404, 415, 500 |

---

## Integration Requirements

### API Versioning
- Current Version: `2024-06-01`
- Version specified in header: `WP-Api-Version: 2024-06-01`

### Security Requirements
- Basic Authentication with base64-encoded credentials
- HTTPS only (TLS required)
- DNS whitelisting required (not IP whitelisting)

### Response Caching
- Responses should always be cached when making requests within Access Worldpay

### Reference Documentation
- [Worldpay Error Responses](https://docs.worldpay.com/access/products/reference/worldpay-error-responses)
- [Currency/Country Codes](https://docs.worldpay.com/access/products/reference/supported-countries-currencies)
- [API Principles](https://docs.worldpay.com/access/products/reference/api-principles)