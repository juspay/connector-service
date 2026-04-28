# Adyen Connector Technical Specification

## 1. Connector Overview

| Property | Value |
|----------|-------|
| **Connector Name** | adyen |
| **Base URL** | `https://{{merchant_endpoint_prefix}}.adyen.com/` |
| **Test URL** | `https://checkout-test.adyen.com/` |
| **API Version** | v68 |
| **Documentation** | https://docs.adyen.com/api-explorer |
| **Protocol** | REST / JSON |

### Supported Environments
- **Test Environment**: `checkout-test.adyen.com`
- **Live Environment**: `{prefix}.adyen.com` where prefix is merchant-specific

---

## 2. Supported Flows

| Flow | Supported | HTTP Method | Endpoint |
|------|-----------|-------------|----------|
| Authorize (Payment) | Yes | POST | `/v68/payments` |
| Capture | Yes | POST | `/v68/payments/{id}/captures` |
| Refund | Yes | POST | `/v68/payments/{id}/refunds` |
| PSync (Payment Sync) | Yes | POST | `/v68/payments/details` |
| RSync (Refund Sync) | No | Stub | Currently stubbed implementation |

---

## 3. Payment Methods

### 3.1 Credit Card

| Card Brand | Variant Identifier | Supported |
|------------|-------------------|-----------|
| Visa | `visa` | Yes |
| Mastercard | `mc` | Yes |
| American Express | `amex` | Yes |
| JCB | `jcb` | Yes |
| Diners Club | `diners` | Yes |
| Discover | `discover` | Yes |
| Carte Bancaire | `cartebancaire` | Yes |
| China UnionPay | `cup` | Yes |
| Maestro | `maestro` | Yes |

**Card Request Structure:**
```json
{
  "type": "scheme",
  "number": "4111111111111111",
  "expiryMonth": "03",
  "expiryYear": "2030",
  "cvc": "737",
  "holderName": "John Doe"
}
```

### 3.2 Debit Card

Debit cards use the same `scheme` type with card-specific processing. The connector automatically routes based on BIN and card network.

---

## 4. Authentication

### 4.1 API Key Authentication

Adyen uses API key authentication via the `X-Api-Key` header.

| Property | Details |
|----------|---------|
| **Header Name** | `X-Api-Key` |
| **Header Value** | Your Adyen API key |
| **Environment Variable** | `ADYEN_API_KEY` |

**Header Format:**
```
X-Api-Key: YOUR_API_KEY
```

### 4.2 Merchant Account

All requests require a `merchantAccount` parameter identifying the merchant account in Adyen.

---

## 5. Flow Implementation Details

### 5.1 Authorize Flow

Initiates a payment transaction with Adyen.

#### Request

**URL:** `{base_url}/v68/payments`

**Method:** `POST`

**Headers:**
```
Content-Type: application/json
X-Api-Key: {{api_key}}
```

**Body:**
```json
{
  "amount": {
    "currency": "USD",
    "value": 1000
  },
  "reference": "pay_1234567890",
  "merchantAccount": "YOUR_MERCHANT_ACCOUNT",
  "paymentMethod": {
    "type": "scheme",
    "number": "4111111111111111",
    "expiryMonth": "03",
    "expiryYear": "2030",
    "cvc": "737",
    "holderName": "John Doe"
  },
  "returnUrl": "https://example.com/return",
  "shopperInteraction": "Ecommerce",
  "channel": "Web",
  "recurringProcessingModel": "CardOnFile"
}
```

**Field Descriptions:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `amount` | Object | Yes | Amount object with `currency` and `value` (in minor units) |
| `reference` | String | Yes | Unique merchant reference for the payment |
| `merchantAccount` | String | Yes | Your Adyen merchant account |
| `paymentMethod` | Object | Yes | Payment method details (see card structure above) |
| `returnUrl` | String | Conditional | Required for 3DS payments |
| `shopperInteraction` | String | Yes | `Ecommerce` for online payments |
| `channel` | String | Yes | `Web`, `iOS`, `Android`, etc. |
| `recurringProcessingModel` | String | No | `CardOnFile`, `Subscription`, or `UnscheduledCardOnFile` |

#### Response

**Success (200 OK):**
```json
{
  "pspReference": "8816123456789012",
  "resultCode": "Authorised",
  "amount": {
    "currency": "USD",
    "value": 1000
  },
  "merchantReference": "pay_1234567890",
  "paymentMethod": {
    "brand": "visa",
    "type": "scheme"
  }
}
```

**3DS Redirect Required:**
```json
{
  "pspReference": "8816123456789012",
  "resultCode": "RedirectShopper",
  "action": {
    "type": "redirect",
    "url": "https://test.adyen.com/hpp/3d/validate.shtml",
    "data": {
      "PaReq": "...",
      "MD": "..."
    },
    "method": "POST"
  }
}
```

#### Status Mapping

| Adyen Result Code | Hyperswitch Status |
|-------------------|-------------------|
| `Authorised` | `Charged` |
| `Refused` | `Failed` |
| `Pending` | `Pending` |
| `Cancelled` | `Cancelled` |
| `RedirectShopper` | `AuthenticationPending` |
| `IdentifyShopper` | `AuthenticationPending` |
| `ChallengeShopper` | `AuthenticationPending` |

---

### 5.2 Capture Flow

Captures a previously authorized payment.

#### Request

**URL:** `{base_url}/v68/payments/{id}/captures`

**Method:** `POST`

**Headers:**
```
Content-Type: application/json
X-Api-Key: {{api_key}}
```

**Body:**
```json
{
  "merchantAccount": "YOUR_MERCHANT_ACCOUNT",
  "amount": {
    "currency": "USD",
    "value": 1000
  },
  "reference": "capture_1234567890"
}
```

**Field Descriptions:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `merchantAccount` | String | Yes | Your Adyen merchant account |
| `amount` | Object | Yes | Amount to capture (can be partial) |
| `reference` | String | Yes | Unique capture reference |

#### Response

**Success (200 OK):**
```json
{
  "pspReference": "8916123456789012",
  "status": "received",
  "amount": {
    "currency": "USD",
    "value": 1000
  },
  "merchantAccount": "YOUR_MERCHANT_ACCOUNT",
  "reference": "capture_1234567890"
}
```

#### Status Mapping

| Adyen Status | Hyperswitch Status |
|--------------|-------------------|
| `received` | `Charged` |
| `declined` | `Failed` |

---

### 5.3 Refund Flow

Processes a refund for a captured payment.

#### Request

**URL:** `{base_url}/v68/payments/{id}/refunds`

**Method:** `POST`

**Headers:**
```
Content-Type: application/json
X-Api-Key: {{api_key}}
```

**Body:**
```json
{
  "merchantAccount": "YOUR_MERCHANT_ACCOUNT",
  "amount": {
    "currency": "USD",
    "value": 1000
  },
  "reference": "refund_1234567890",
  "merchantOrderReference": "ORDER-123"
}
```

**Field Descriptions:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `merchantAccount` | String | Yes | Your Adyen merchant account |
| `amount` | Object | Yes | Amount to refund |
| `reference` | String | Yes | Unique refund reference |
| `merchantOrderReference` | String | No | Original order reference |

#### Response

**Success (200 OK):**
```json
{
  "pspReference": "9016123456789012",
  "status": "received",
  "amount": {
    "currency": "USD",
    "value": 1000
  },
  "merchantAccount": "YOUR_MERCHANT_ACCOUNT",
  "reference": "refund_1234567890"
}
```

#### Status Mapping

| Adyen Status | Hyperswitch Status |
|--------------|-------------------|
| `received` | `Pending` (async processing) |
| `refunded` | `Success` |

**Note:** Refunds are processed asynchronously. The initial `received` status indicates the refund request was accepted.

---

### 5.4 PSync (Payment Sync) Flow

Synchronizes payment status, particularly for 3DS flows.

#### Request

**URL:** `{base_url}/v68/payments/details`

**Method:** `POST`

**Headers:**
```
Content-Type: application/json
X-Api-Key: {{api_key}}
```

**Body (for 3DS completion):**
```json
{
  "paymentData": "Ab02b4c0...",
  "details": {
    "MD": "ODUxNjY2MjE4NzQxNjYwMzQzOTgx...",
    "PaRes": "eAFVUdtqE0EUfhUuuhcjjoktVaIJghGMRuJNlVKMpE0bG5vb..."
  }
}
```

**Field Descriptions:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `paymentData` | String | Conditional | Payment data from initial authorize response |
| `details` | Object | Conditional | 3DS authentication details |

#### Response

**Success (200 OK):**
```json
{
  "pspReference": "8816123456789012",
  "resultCode": "Authorised",
  "amount": {
    "currency": "USD",
    "value": 1000
  }
}
```

#### Status Mapping

Same as Authorize flow.

---

### 5.5 RSync (Refund Sync) Flow

Currently stubbed in the Adyen connector implementation.

---

## 6. Error Handling

### 6.1 Error Response Format

```json
{
  "status": 422,
  "errorCode": "101",
  "message": "Invalid card number",
  "errorType": "validation"
}
```

### 6.2 Common Error Codes

| Error Code | Description | Hyperswitch Action |
|------------|-------------|-------------------|
| `101` | Invalid card number | Map to `Failed` |
| `103` | Card expired | Map to `Failed` |
| `105` | Invalid CVC | Map to `Failed` |
| `125` | Fraudulent payment | Map to `Failed` |
| `129` | 3D Secure authentication required | Initiate 3DS flow |
| `803` | Invalid currency | Return error |
| `904` | Refusal | Map to `Failed` |

---

## 7. Webhook Handling

### 7.1 Webhook Configuration

Configure webhooks in the Adyen Customer Area:
- **URL**: `https://your-domain.com/webhooks/adyen`
- **Method**: POST
- **Format**: JSON

### 7.2 Webhook Signature Verification

Adyen uses HMAC-SHA256 for webhook signature verification.

#### Signature Format

The signature is computed over the following fields concatenated together:
1. `pspReference`
2. `originalReference`
3. `merchantAccountCode`
4. `merchantReference`
5. `amount.value`
6. `amount.currency`
7. `eventCode`
8. `success`

Fields are concatenated without separators in the order listed above.

#### Verification Process

1. Retrieve the `hmacSignature` from the webhook payload
2. Compute the expected HMAC using your webhook signing key
3. Compare the computed signature with the received signature

**Pseudo-code:**
```
message = pspReference + originalReference + merchantAccountCode + 
          merchantReference + amountValue + amountCurrency + eventCode + success
expectedHmac = HMAC_SHA256(message, webhook_signing_key)
isValid = constantTimeCompare(expectedHmac, receivedHmac)
```

### 7.3 Event Types

| Adyen Event Code | Hyperswitch Event | Description |
|------------------|-------------------|-------------|
| `AUTHORISATION` | `PaymentAuthorized` | Payment was authorized |
| `CAPTURE` | `PaymentCaptured` | Payment was captured |
| `REFUND` | `RefundCompleted` | Refund was processed |
| `CHARGEBACK` | `DisputeOpened` | Chargeback initiated |
| `CANCELLATION` | `PaymentCancelled` | Payment was cancelled |

### 7.4 Webhook Payload Example

```json
{
  "live": "false",
  "notificationItems": [
    {
      "NotificationRequestItem": {
        "additionalData": {
          "hmacSignature": "O8hn0glJaJWry+7ZHpKuho+rvWTG2T9kdN0OjbWqJi0="
        },
        "amount": {
          "currency": "USD",
          "value": 1000
        },
        "eventCode": "AUTHORISATION",
        "eventDate": "2024-01-15T10:30:00+01:00",
        "merchantAccountCode": "YOUR_MERCHANT_ACCOUNT",
        "merchantReference": "pay_1234567890",
        "originalReference": "",
        "paymentMethod": "visa",
        "pspReference": "8816123456789012",
        "reason": "",
        "success": "true"
      }
    }
  ]
}
```

### 7.5 Resource Reference Extraction

| Adyen Field | Hyperswitch Field |
|-------------|-------------------|
| `merchantReference` | `payment_id` |
| `pspReference` | `connector_transaction_id` |
| `originalReference` | `parent_transaction_id` |

---

## 8. Testing

### 8.1 Test Card Numbers

| Card Type | Number | CVC | Expiry |
|-----------|--------|-----|--------|
| Visa | 4111111111111111 | 737 | Any future date |
| Mastercard | 5555555555554444 | 737 | Any future date |
| Amex | 378282246310005 | 7373 | Any future date |
| JCB | 3566111111111113 | 737 | Any future date |
| Diners | 30569309025904 | 737 | Any future date |
| Discover | 6011111111111117 | 737 | Any future date |
| Maestro | 6759649826438453 | 737 | Any future date |

### 8.2 3DS Test Cards

| Test Scenario | Card Number |
|---------------|-------------|
| Frictionless flow | 5201281500000006 |
| Challenge flow | 4917610000000000 |
| Challenge with exemption | 4166676667666746 |

### 8.3 Test URLs

- **Test Environment**: `https://checkout-test.adyen.com/v68/`
- **Return URL**: `https://your-test-domain.com/return`

---

## 9. Configuration

### 9.1 Required Credentials

| Credential | Source | Description |
|------------|--------|-------------|
| `api_key` | Adyen Customer Area | API key for authentication |
| `merchant_account` | Adyen Customer Area | Your merchant account identifier |
| `webhook_secret` | Adyen Customer Area | Secret for webhook verification |
| `merchant_endpoint_prefix` | Adyen Customer Area | Prefix for live environment URLs |

### 9.2 Configuration Example

```json
{
  "connector": "adyen",
  "connector_account_details": {
    "api_key": "AQElhmfx...",
    "merchant_account": "YOUR_MERCHANT_ACCOUNT",
    "webhook_secret": "ABCDEF1234567890",
    "merchant_endpoint_prefix": "prefix"
  },
  "test_mode": true
}
```

### 9.3 Connector Metadata

```json
{
  "connector": {
    "name": "adyen",
    "display_name": "Adyen",
    "description": "Global payment platform supporting cards, wallets, and local payment methods",
    "category": "payment_processor",
    "supported_payment_methods": ["credit_card", "debit_card"],
    "supported_webhooks": true
  }
}
```

---

## 10. Additional Notes

### 10.1 Currency Handling

All amounts are sent in **minor units** (cents for USD, yen for JPY).

### 10.2 Idempotency

Adyen supports idempotency via the `Idempotency-Key` header. Recommended for POST requests.

### 10.3 Retry Policy

- **Retry on**: 5xx errors, timeouts
- **Do not retry on**: 4xx errors (except 429 rate limit)
- **Rate limit status**: 429

### 10.4 Timeout Configuration

| Operation | Recommended Timeout |
|-----------|-------------------|
| Authorize | 30 seconds |
| Capture | 30 seconds |
| Refund | 30 seconds |
| PSync | 30 seconds |

---

## References

- [Adyen Checkout API Documentation](https://docs.adyen.com/api-explorer/#/CheckoutService/v68/overview)
- [Adyen Webhook Documentation](https://docs.adyen.com/development-resources/webhooks)
- [Adyen Test Cards](https://docs.adyen.com/development-resources/testing/test-card-numbers)
- [Hyperswitch Connector Guide](../../connectors/adyen/)
