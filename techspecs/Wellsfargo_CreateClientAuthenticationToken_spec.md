# Wellsfargo CreateClientAuthenticationToken — Technical Specification

> Source: https://developer.cybersource.com/docs/cybs/en-us/digital-accept-flex/developer/all/rest/digital-accept-flex/microform-integ-v2.html
> Source: https://developer.cybersource.com/docs/cybs/en-us/digital-accept-flex/developer/all/rest/digital-accept-flex/microform-integ-v2/micro-v2-reference/flex-capture-context-api-intro.html
> Source: https://developer.cybersource.com/docs/cybs/en-us/platform/developer/all/rest/rest-getting-started.html
> Source: https://developer.cybersource.com/docs/cybs/en-us/digital-accept-flex/developer/all/rest/digital-accept-flex/microform-integ-v2/microform-integ-getting-started-v2.html
> Generated: 2026-05-13T00:00:00Z

---

## 1. Connector Profile

| Field | Value |
|---|---|
| Connector Name | Wellsfargo |
| Primary Flow Scope | CreateClientAuthenticationToken (Flex Microform v2 Capture Context) |
| API Family | CyberSource REST API (Wellsfargo operates on CyberSource's payment platform) |
| Production Host | `api.cybersource.com` |
| Sandbox Host | `apitest.cybersource.com` |
| Base URL (Sandbox) | `https://apitest.cybersource.com/` |
| Base URL (Production) | `https://api.cybersource.com/` |

Wellsfargo's payment integration is powered by CyberSource's REST API infrastructure. The `CreateClientAuthenticationToken` flow generates a Flex Microform v2 capture context (a JWT) that the client-side Microform SDK uses to securely tokenize card data in the browser before it reaches the merchant's server.

---

## 2. Authentication

| Field | Value |
|---|---|
| Scheme | HTTP Signature with HMAC-SHA256 |
| Header | `Signature` |

### Credentials Required

| Credential | Config Key | Description |
|---|---|---|
| `api_key` | `api_key` | CyberSource API Key ID (`keyid` in the signature header) |
| `api_secret` | `api_secret` | Base64-encoded HMAC-SHA256 secret used to sign the signature string |
| `merchant_account` | `merchant_account` | Merchant ID (sent as `v-c-merchant-id` header) |

### Signature Construction

The `Signature` header is constructed as:

```
keyid="{api_key}", algorithm="HmacSHA256", headers="{headers_str}", signature="{signature_value}"
```

For POST requests, `headers_str` is:
```
host date (request-target) digest v-c-merchant-id
```

The signature string is:
```
host: {host}
date: {RFC1123 datetime}
(request-target): post {path}
digest: SHA-256={base64(sha256(request_body))}
v-c-merchant-id: {merchant_id}
```

The `Digest` header (`SHA-256={base64(sha256(body))}`) is included for POST requests.

### Implementation Notes

- The `Date` header must be in RFC1123 format (UTC).
- The `api_secret` must be base64-decoded before use as the HMAC key.
- The `Host` header must be the bare hostname (no scheme, no port).
- For GET requests, `digest` is omitted from `headers_str` and no `Digest` header is sent.

---

## 3. Supported Flows

| Flow | HTTP | Path | Notes |
|---|---|---|---|
| CreateClientAuthenticationToken | POST | `/microform/v2/sessions` | Returns a Flex capture context JWT for Microform SDK initialization |
| Authorize | POST | `/pts/v2/payments/` | Standard card authorization |
| Capture | POST | `/pts/v2/payments/{id}/captures` | Capture a previously authorized payment |
| Void | POST | `/pts/v2/payments/{id}/reversals` | Reverse/cancel an authorization |
| Refund | POST | `/pts/v2/payments/{id}/refunds` | Refund a captured payment |
| PSync | GET | `/pts/v2/payments/{id}` | Retrieve payment status |
| RSync | GET | `/tss/v2/transactions/{id}` | Retrieve refund status |
| SetupMandate | POST | `/pts/v2/payments` | Zero-dollar authorization for mandate setup |
| Webhooks | N/A | N/A | Not supported |

---

## 4. Request Schema Highlights — CreateClientAuthenticationToken

### Endpoint

```
POST /microform/v2/sessions
```

### Headers

| Header | Value | Required |
|---|---|---|
| `Content-Type` | `application/json;charset=utf-8` | yes |
| `Accept` | `application/hal+json;charset=utf-8` | yes |
| `Date` | RFC1123 UTC datetime | yes |
| `Host` | `apitest.cybersource.com` or `api.cybersource.com` | yes |
| `v-c-merchant-id` | Merchant account ID | yes |
| `Signature` | HTTP Signature (HMAC-SHA256, see §2) | yes |
| `Digest` | `SHA-256={base64(sha256(body))}` | yes (POST) |

### Request Body

```json
{
  "targetOrigins": ["https://example.com"],
  "clientVersion": "0.11",
  "allowedCardNetworks": ["VISA", "MASTERCARD", "AMEX", "DISCOVER"],
  "fields": {
    "paymentInformation": {
      "card": {
        "number": {},
        "securityCode": {}
      }
    }
  }
}
```

### Field Reference

| Field | Type | Required | Description |
|---|---|---|---|
| `targetOrigins` | `string[]` | yes | List of origins (scheme + host) from which the Microform will be loaded. Derived from `return_url`. |
| `clientVersion` | `string` | yes | Flex client SDK version. Currently `"0.11"`. |
| `allowedCardNetworks` | `string[]` | no | Card networks the form accepts. Supported values: `VISA`, `MASTERCARD`, `AMEX`, `DISCOVER`. |
| `fields` | `object` | yes | Specifies which card fields the Microform will collect. Must include `paymentInformation.card.number` and optionally `securityCode`. |

### Idempotency

No idempotency key is required or supported for this endpoint. Each call generates a fresh capture context JWT.

---

## 5. Response Schema Highlights

### Success Response (HTTP 200)

The endpoint may return either:

**A) Raw JWT string** (older Flex v2 `/flex/v2/sessions` endpoint, `Content-Type: application/jwt`):
```
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ii4uLiJ9.eyJjdHgiOlsid...
```

**B) JSON object** (`Content-Type: application/json`, `/microform/v2/sessions`):
```json
{
  "captureContext": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ii4uLiJ9..."
}
```

### JWT Payload Structure (decoded)

The capture context JWT payload contains:

| Field Path | Type | Description |
|---|---|---|
| `ctx[0].data.clientLibrary` | `string` | URL to the Microform SDK JavaScript library to load |
| `ctx[0].data.clientLibraryIntegrity` | `string` | SRI hash for the client library (subresource integrity) |
| `ctx[0].data.targetOrigins` | `string[]` | Echo of requested target origins |
| `ctx[0].data.allowedCardNetworks` | `string[]` | Echo of allowed card networks |

### UCS Response Fields Extracted

| UCS Field | Source |
|---|---|
| `capture_context` | Full JWT string (from `captureContext` JSON field or raw string) |
| `client_library` | Decoded from JWT payload at `ctx[0].data.clientLibrary` |
| `client_library_integrity` | Decoded from JWT payload at `ctx[0].data.clientLibraryIntegrity` |

### Transaction IDs

This flow does not generate a payment transaction ID. The capture context is a short-lived JWT used for browser-side tokenization only.

---

## 6. Error Handling

| HTTP | Status / Code | Cause |
|---|---|---|
| 400 | `INVALID_DATA` | Malformed request body, invalid `targetOrigins` format, missing required fields |
| 400 | `MISSING_FIELD` | Required field absent (e.g., `targetOrigins`) |
| 401 | `UNAUTHORIZED` | Missing, invalid, or expired HTTP Signature; wrong `api_key` |
| 403 | `FORBIDDEN` | Merchant account does not have Flex Microform enabled |
| 404 | `NOT_FOUND` | Endpoint path incorrect |
| 429 | `TOO_MANY_REQUESTS` | Rate limit exceeded |
| 500 | `SERVER_ERROR` | CyberSource internal error; retry with backoff |

### Standard Error Body

```json
{
  "id": "f27bc76d-c1a6-4e56-8dcc-2bff2e86bf47",
  "submitTimeUtc": "2024-01-15T10:30:00Z",
  "status": "INVALID_REQUEST",
  "reason": "MISSING_FIELD",
  "message": "One or more required fields are missing.",
  "details": [
    {
      "field": "targetOrigins",
      "reason": "MISSING_REQUIRED_FIELD"
    }
  ]
}
```

### Authentication Error Body (HTTP 401)

```json
{
  "response": {
    "rmsg": "Authentication failed"
  }
}
```

### Status Mapping

| HTTP Status | Condition | UCS Status |
|---|---|---|
| 200 | `captureContext` present | `Success` |
| 400 | Invalid request | `Failure` |
| 401 | Auth failure | `Failure` |
| 403 | Forbidden | `Failure` |
| 429 | Rate limited | Retryable failure |
| 500/502/503/504 | Server error | Retryable failure |

---

## 7. Webhooks / Async Notifications

Webhooks are **not applicable** to the `CreateClientAuthenticationToken` flow. This flow is synchronous — the capture context JWT is returned directly in the HTTP response body.

Wellsfargo does not document webhook delivery for session/token creation events.

**Gaps:**
- No async notification if the session creation fails after HTTP 200 (edge case not documented).
- JWT expiry is not communicated via webhook; clients must track `exp` claim from the decoded JWT.

---

## 8. References

| Title | URL |
|---|---|
| Microform Integration v2 (main) | https://developer.cybersource.com/docs/cybs/en-us/digital-accept-flex/developer/all/rest/digital-accept-flex/microform-integ-v2.html |
| Flex Capture Context API Intro | https://developer.cybersource.com/docs/cybs/en-us/digital-accept-flex/developer/all/rest/digital-accept-flex/microform-integ-v2/micro-v2-reference/flex-capture-context-api-intro.html |
| REST API Getting Started | https://developer.cybersource.com/docs/cybs/en-us/platform/developer/all/rest/rest-getting-started.html |
| Microform Integration Getting Started v2 | https://developer.cybersource.com/docs/cybs/en-us/digital-accept-flex/developer/all/rest/digital-accept-flex/microform-integ-v2/microform-integ-getting-started-v2.html |
| Wellsfargo ACH Payments Intro | https://developer.cybersource.com/docs/cybs/en-us/payments/developer/wellsfargoach/so/payments/payments-intro/payments-intro-payments.html |
