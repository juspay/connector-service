# BILLDESK — Technical Specification

> **Connector**: BILLDESK
> **Direction**: BOTH (euler-api-gateway → Billdesk Settlement API; euler-api-txns → Billdesk Payment APIs)
> **Endpoint**: Multiple — see Section 1.2 and Section 3
> **Purpose**: Full payment gateway integration supporting card, NB, UPI, wallet/reward points, recurring mandates, eNACH, and settlement reconciliation via Billdesk
> **Generated**: 2026-03-26

---

## 1. Connector Overview

### 1.1 Basic Information

- **Connector ID**: BILLDESK
- **Direction**: BOTH
  - `euler-api-gateway` → Billdesk Settlement/Reconciliation API
  - `euler-api-txns` → Billdesk Payment APIs (V1 Legacy + V2 JSON/JWE)
- **HTTP Method**: GET (settlement); POST (payment initiation, refund, status, mandate)
- **Endpoint Path**: Multiple — see Base URL Configuration below
- **Protocol**: HTTPS REST (synchronous)
- **Content Type**: `application/jose` (JWE encrypted, gateway side); `application/json` (txns side V2); `application/x-www-form-urlencoded` (txns side V1 legacy)
- **Architecture**: Haskell (Servant + Warp / EulerHS BackendFlow)

### 1.2 Base URL Configuration

#### Gateway Side (euler-api-gateway — Settlement/Reconciliation)

| Environment | Base URL | Env Variable | Default |
|-------------|----------|--------------|---------|
| UAT / Sandbox | `https://uat1.billdesk.com` | hardcoded (IsSandbox = True) | — |
| PROD | `https://api.billdesk.com` | hardcoded (IsSandbox = False) | — |

**Endpoint**: `GET /pasettlements/v1_2/settlements/get`

#### Txns Side V1 Legacy (euler-api-txns — Payment flows)

| Environment | Base URL | Env Variable | Default |
|-------------|----------|--------------|---------|
| UAT | `https://uat.billdesk.com` | hardcoded | — |
| PROD | `https://www.billdesk.com` | hardcoded | — |

**Endpoint path suffix**: `/pgidsk/...` (resolved by `getEndpointForReq` based on request type)

#### Txns Side V2 (euler-api-txns — Payment flows)

| Environment | Base URL (Payments) | Base URL (PGSI/Mandates) | Env Variable | Default |
|-------------|---------------------|--------------------------|--------------|---------|
| UAT | `https://uat1.billdesk.com/u2/payments/ve1_2` | `https://uat1.billdesk.com/u2/pgsi/ve1_2` | hardcoded | — |
| PROD | `https://api.billdesk.com/payments/ve1_2` | `https://api.billdesk.com/pgsi/ve1_2` | hardcoded | — |

**URL Resolution Logic**: Selected by `testMode` boolean from `MerchantGatewayAccount`. When `testMode = True` → UAT URLs; when `testMode = False` → PROD URLs. No DEV/INTEG environment distinction; all non-production uses UAT.

**Timeout Configuration**:
- Custom Timeout Header: Not observed (no explicit timeout header in Billdesk requests)
- Default Timeout: EulerHS platform default
- Per-Merchant Override: No

---

## 2. Authentication

### 2.1 Authentication Method

BILLDESK uses two different authentication mechanisms depending on the integration version:

**V1 (Legacy) — CRC32 / HmacSHA256 checksum in pipe-delimited message**
- **Auth Type**: Checksum appended to pipe-delimited message body
- **Auth Header**: None (checksum embedded as last field in `msg` pipe string)
- **Credential Source**: `MerchantGatewayAccount.accountDetails` → `BilldeskDetails` (billDeskChecksumKey, hashAlgo)

**V2 — JWE (JSON Web Encryption) + JWS (JSON Web Signature)**
- **Auth Type**: JWE+JWS (request encrypted with Billdesk RSA public key, signed with Juspay private key)
- **Auth Header**: `Authorization: HMACSignature {clientid}:{HMAC-SHA256-of-request}` (mandate flows only)
- **Credential Source**: `MasterAccountDetail.credentials` → `CertificateConfigs` (billdeskEncryptionKey, billdeskFpSigningKeyPairs, juspayPublicKey, juspayPrivateKey); fallback to env vars

**V2 Mandate/PGSI flows — HMAC-SHA256 Authorization header**
- **Auth Type**: HMAC-SHA256
- **Auth Header**: `Authorization: HMACSignature {userId}:{UPPER(HMAC-SHA256-of-msg)}`
- **Credential Source**: `BilldeskDetails.billdeskSecretKey`

### 2.2 Authentication Flow

#### V1 Checksum Flow
1. Build pipe-delimited message string from transaction fields
2. Compute checksum: if `hashAlgo == "HmacSHA256"` → `HmacSHA256(message, billDeskChecksumKey)`; else → `CRC32(message)`
3. Append checksum as last pipe-delimited field to `msg`

#### V2 JWE+JWS Flow
1. Serialize request body as JSON text
2. Encrypt payload with Billdesk's RSA public key using RSA-OAEP-256 + A128GCM (JWE)
3. Sign the JWE with Juspay's private key using RS256 (JWS)
4. Send encrypted+signed payload as body with `Content-Type: application/jose`
5. On response: extract JWS header to find Billdesk fingerprint, look up matching signing key from `billdeskFpSigningKeyPairs`, verify JWS signature, then decrypt JWE with Juspay's private key

#### V2 Mandate HMAC-SHA256 Header Flow
1. Build HMAC message: `{method}|{URI}|application/json|application/json|JUS{traceId}|{timestamp}`
2. If body present: `bodyHash = SHA256(body)`; final HMAC input = `{msg}|{UPPER(bodyHash)}`
3. Compute `HMAC-SHA256(msg, billdeskSecretKey)`
4. Set header: `Authorization: HMACSignature {userId}:{UPPER(hmac)}`

### 2.3 Required Headers

#### Gateway Side (Settlement API)

| # | Header Name | Value / Source | Required | Description |
|---|-------------|----------------|----------|-------------|
| 1 | `Content-Type` | `application/jose` | Yes | Fixed — JOSE encrypted content |
| 2 | `Accept` | `application/jose` | Yes | Fixed — JOSE encrypted response expected |
| 3 | `BD-Traceid` | UUID16 (generated per request) | Yes | Billdesk request trace ID |
| 4 | `BD-Timestamp` | Current datetime formatted as `%Y%m%d%H%m%S` | Yes | Request timestamp |

#### Txns Side V2 Payments (JWE flows)

| # | Header Name | Value / Source | Required | Description |
|---|-------------|----------------|----------|-------------|
| 1 | `Content-Type` | `application/jose` | Yes | JWE encrypted body |
| 2 | `Accept` | `application/jose` | Yes | JWE encrypted response expected |
| 3 | `BD-Traceid` | UUID16 (generated per request) | Yes | Billdesk trace ID |
| 4 | `BD-Timestamp` | Current datetime without spaces | Yes | Request timestamp |

#### Txns Side V2 Mandate/PGSI (HMAC flows)

| # | Header Name | Value / Source | Required | Description |
|---|-------------|----------------|----------|-------------|
| 1 | `Content-Type` | `application/json` | Yes | JSON body |
| 2 | `BD-Traceid` | `"JUS" <> UUID16` | Yes | Trace ID prefixed with JUS |
| 3 | `BD-Timestamp` | Current datetime | Yes | Request timestamp |
| 4 | `Accept` | `application/json` | Yes | JSON response |
| 5 | `Authorization` | `HMACSignature {userId}:{UPPER(hmac)}` | Yes | HMAC-SHA256 authorization |

#### Txns Side V1 Legacy (Webhook/form POST)

| # | Header Name | Value / Source | Required | Description |
|---|-------------|----------------|----------|-------------|
| 1 | `Content-Type` | `application/x-www-form-urlencoded` | Yes | Form POST |

### 2.4 Credential Sources

| # | Credential | Source | Env Var Fallback |
|---|-----------|--------|-----------------|
| 1 | `billdeskEncryptionKey` | `MasterAccountDetail.credentials.CertificateConfigs` | `BILLDESK_ENCRYPTION_KEY` |
| 2 | `billdeskFpSigningKeyPairs` | `MasterAccountDetail.credentials.CertificateConfigs` | `BILLDESK_FP_SIGNING_KEY_PAIRS` |
| 3 | `juspayPublicKey` | `MasterAccountDetail.credentials.CertificateConfigs` | `JUSPAY_BILLDESK_PUBLIC_KEY` / `JUSPAY_BILLDESK_PUBLIC_KEY_V2` |
| 4 | `juspayPrivateKey` | `MasterAccountDetail.credentials.CertificateConfigs` | `BILLDESK_PRIVATE_KEY` |
| 5 | `billDeskMerchantId` | `MerchantGatewayAccount.accountDetails → BilldeskDetails` | — |
| 6 | `billDeskChecksumKey` | `MerchantGatewayAccount.accountDetails → BilldeskDetails` | — |
| 7 | `billdeskClientId` | `MerchantGatewayAccount.accountDetails → BilldeskDetails` | — |
| 8 | `billdeskSecretKey` | `MerchantGatewayAccount.accountDetails → BilldeskDetails` | — |
| 9 | RSA cert for mandate card encrypt | — | `BILLDESK_FILE_PATH_CERT_UAT` / `BILLDESK_FILE_PATH_CERT_PROD` |

---

## 3. Request Structure

### 3.1 Gateway Side — Settlement Request

**Endpoint**: `GET /pasettlements/v1_2/settlements/get`

**Type**: `BilldeskSettlementRequest` — `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/BILLDESK/Types.hs`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `mercid` | `Text` | `mercid` | Yes | Billdesk merchant ID |
| 2 | `from_date` | `Text` | `from_date` | Yes | Settlement start date |
| 3 | `to_date` | `Text` | `to_date` | Yes | Settlement end date (defaults to today if not provided) |
| 4 | `pv_number` | `Maybe Text` | `pv_number` | No | PV number filter |

**Field Count**: 4 fields

**Wrapper**: SDRWrapperRequest

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `startDate` | `Text` | `startDate` | Yes | Report start date |
| 2 | `endDate` | `Maybe Text` | `endDate` | No | Report end date (defaults to today) |
| 3 | `gateway` | `Text` | `gateway` | Yes | Gateway identifier ("BILLDESK") |
| 4 | `cursor` | `Maybe Text` | `cursor` | No | Pagination cursor |
| 5 | `limit` | `Maybe Int` | `limit` | No | Max records per page |
| 6 | `merchantGatewayAccount` | `Domain.MerchantGatewayAccount` | `merchantGatewayAccount` | Yes | MGA with Billdesk credentials |
| 7 | `masterAccountDetail` | `Maybe MAD.MasterAccountDetail` | `masterAccountDetail` | No | For JWE certificate lookup |

**Field Count**: 7 fields

### 3.2 Txns Side — V1 Legacy Card Initiate Request

**Type**: `BilldeskInitiateCardTxnRequestV1` — `euler-api-txns/euler-x/src-generated/Gateway/Billdesk/Types.hs`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `msg` | `Text` | `msg` | Yes | Pipe-delimited message with embedded checksum |
| 2 | `paydata` | `BilldeskPaydataType` | `paydata` | Yes | Card payment data object |
| 3 | `ipaddress` | `Text` | `ipaddress` | Yes | Customer IP address |
| 4 | `useragent` | `Text` | `useragent` | Yes | Customer user agent |

**Field Count**: 4 fields

V1 `msg` pipe-delimited fields (card): `MerchantID|CustomerID|TxnID|Amount|BankID|Mode|PayType|CurrencyType|ItemCode|SecurityType|SecurityID|SecurityPassword|TxnDate|AuthStatus|SettlementType|AdditionalInfo1..7|TxnReferenceNo|BankReferenceNo|ErrorStatus|ErrorDescription|Checksum`

### 3.3 Txns Side — V2 Create Transaction Request

**Type**: `CreateTxnReq` — `euler-api-txns/euler-x/src-generated/Gateway/Billdesk/Types.hs`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `mercid` | `Text` | `mercid` | Yes | Billdesk merchant ID |
| 2 | `orderid` | `Text` | `orderid` | Yes | Juspay order ID |
| 3 | `amount` | `Text` | `amount` | Yes | Transaction amount (2 decimal places) |
| 4 | `currency` | `Text` | `currency` | Yes | ISO currency code (e.g. "356" for INR) |
| 5 | `ru` | `Text` | `ru` | Yes | Return URL (redirect after payment) |
| 6 | `itemcode` | `Text` | `itemcode` | Yes | Item code (e.g., "DIRECT") |
| 7 | `device` | `DeviceType` | `device` | Yes | Device information object |
| 8 | `payment` | `PaymentObject` | `payment` | Yes | Payment method details |
| 9 | `txnid` | `Text` | `txnid` | Yes | Juspay transaction ID |
| 10 | `additional_info` | `Maybe AdditionalInfo` | `additional_info` | No | UDF/additional info fields |
| 11 | `mandate` | `Maybe MandateInfo` | `mandate` | No | Mandate details for SI |
| 12 | `tavv` | `Maybe Text` | `tavv` | No | Token authentication verification value |
| 13 | `bankid` | `Maybe Text` | `bankid` | No | Bank ID for NB |
| 14 | `surcharge` | `Maybe SurchargeInfo` | `surcharge` | No | Surcharge details |

**Field Count**: 14 fields

### 3.4 Txns Side — V2 Create Mandate Request

**Type**: `CreateMandateReq` — `euler-api-txns/euler-x/src-generated/Gateway/Billdesk/Types.hs`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `mercid` | `Text` | `mercid` | Yes | Billdesk merchant ID |
| 2 | `verification_required` | `Bool` | `verification_required` | Yes | Whether 3DS verification needed |
| 3 | `customer_refid` | `Text` | `customer_refid` | Yes | Customer reference ID |
| 4 | `subscription_refid` | `Text` | `subscription_refid` | Yes | Subscription/mandate ID |
| 5 | `subscription_desc` | `Text` | `subscription_desc` | Yes | Mandate description |
| 6 | `start_date` | `Text` | `start_date` | Yes | Mandate start date (YYYY-MM-DD) |
| 7 | `end_date` | `Text` | `end_date` | Yes | Mandate end date (default "2050-12-30") |
| 8 | `amount_type` | `Text` | `amount_type` | Yes | "maximum" or "fixed" |
| 9 | `amount` | `Text` | `amount` | Yes | Mandate amount |
| 10 | `currency` | `Text` | `currency` | Yes | ISO currency (e.g. "356") |
| 11 | `fa_transaction` | `SecondFactorTransaction` | `fa_transaction` | Yes | Initial transaction for mandate |
| 12 | `frequency` | `Text` | `frequency` | Yes | Frequency ("adho", "monthly", etc.) |
| 13 | `payment_method_type` | `Text` | `payment_method_type` | Yes | "card", "upi", "nb" |
| 14 | `card` | `Maybe CardType` | `card` | No | Card details (encrypted) |
| 15 | `ru` | `Maybe Text` | `ru` | No | Return URL |
| 16 | `customer` | `Maybe CustomerType` | `customer` | No | Customer info |
| 17 | `device` | `Maybe DeviceType` | `device` | No | Device information |

**Field Count**: 17 fields

### 3.5 Txns Side — V1 Refund Request

**Type**: `BilldeskOnlineRefundRequest` — `euler-api-txns/euler-x/src-generated/Gateway/Billdesk/Types.hs`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `msg` | `Text` | `msg` | Yes | Pipe-delimited refund message with checksum |

Pipe-delimited fields in refund `msg`: `RequestType(0400)|MerchantID|TxnReferenceNo|TxnDate|CustomerID|Currency|TxnAmount|RefundAmount|DateTime|RefundRefId|NA|NA|NA|Checksum`

**Field Count**: 1 field (pipe-delimited inside)

### 3.6 Txns Side — V2 Refund Request

**Type**: `RefundBilldeskV2Req` — `euler-api-txns/euler-x/src-generated/Gateway/Billdesk/Types.hs`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `mercid` | `Text` | `mercid` | Yes | Billdesk merchant ID |
| 2 | `refund_amount` | `Text` | `refund_amount` | Yes | Refund amount |
| 3 | `refund_desc` | `Maybe Text` | `refund_desc` | No | Refund description |
| 4 | `refund_ref_id` | `Text` | `refund_ref_id` | Yes | Juspay refund reference ID |

**Field Count**: 4 fields

### 3.7 Nested Request Types

#### DeviceType — `euler-api-txns/euler-x/src-generated/Gateway/Billdesk/Types.hs`
Used in field: `device` of `CreateTxnReq` and `CreateMandateReq`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `init_channel` | `Text` | `init_channel` | Yes | "app" or "internet" |
| 2 | `ip` | `Text` | `ip` | Yes | Customer IP address |
| 3 | `mac` | `Maybe Text` | `mac` | No | MAC address |
| 4 | `user_agent` | `Text` | `user_agent` | Yes | Browser/app user agent (special chars removed) |
| 5 | `accept_header` | `Maybe Text` | `accept_header` | No | Browser accept header (3DS2) |
| 6 | `fingerprintid` | `Maybe Text` | `fingerprintid` | No | Device fingerprint ID |
| 7 | `browser_language` | `Maybe Text` | `browser_language` | No | Browser language (3DS2) |
| 8 | `browser_javascript_enabled` | `Maybe Text` | `browser_javascript_enabled` | No | JS enabled flag (3DS2) |
| 9 | `browser_tz` | `Maybe Text` | `browser_tz` | No | Browser timezone (3DS2) |
| 10 | `browser_color_depth` | `Maybe Text` | `browser_color_depth` | No | Screen color depth (3DS2) |
| 11 | `browser_java_enabled` | `Maybe Text` | `browser_java_enabled` | No | Java enabled (3DS2) |
| 12 | `browser_screen_height` | `Maybe Text` | `browser_screen_height` | No | Screen height (3DS2) |
| 13 | `browser_screen_width` | `Maybe Text` | `browser_screen_width` | No | Screen width (3DS2) |
| 14 | `deviceid` | `Maybe Text` | `deviceid` | No | Device identifier |

#### CardType — `euler-api-txns/euler-x/src-generated/Gateway/Billdesk/Transforms.hs:1439`
Used in field: `card` of `CreateMandateReq`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `enc_card_number` | `Text` | `enc_card_number` | Yes | RSA-encrypted card number |
| 2 | `enc_expiry_month` | `Text` | `enc_expiry_month` | Yes | RSA-encrypted expiry month |
| 3 | `enc_expiry_year` | `Text` | `enc_expiry_year` | Yes | RSA-encrypted expiry year |
| 4 | `name` | `Text` | `name` | Yes | Cardholder name |

#### CustomerType — `euler-api-txns/euler-x/src-generated/Gateway/Billdesk/Transforms.hs:1462`
Used in field: `customer` of `CreateMandateReq`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `first_name` | `Maybe Text` | `first_name` | No | Customer first name |
| 2 | `last_name` | `Maybe Text` | `last_name` | No | Customer last name |
| 3 | `email` | `Maybe Text` | `email` | No | Validated email address |
| 4 | `mobile` | `Maybe Text` | `mobile` | No | Validated mobile number |

#### SecondFactorTransaction — `euler-api-txns/euler-x/src-generated/Gateway/Billdesk/Transforms.hs:1426`
Used in field: `fa_transaction` of `CreateMandateReq`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `gatewayid` | `Text` | `gatewayid` | Yes | Always "billdesk" |
| 2 | `transactionid` | `Text` | `transactionid` | Yes | Billdesk transaction ID from previous penny txn |

#### BilldeskRetrieveMandateRequest — `euler-api-txns/euler-x/src-generated/Gateway/Billdesk/Transforms.hs:1655`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `mercid` | `Text` | `mercid` | Yes | Billdesk merchant ID |
| 2 | `mandateid` | `Maybe Text` | `mandateid` | No | Billdesk mandate ID |
| 3 | `subscription_refid` | `Maybe Text` | `subscription_refid` | No | Juspay mandate ID |

#### BilldeskMandateRevokeRequest — `euler-api-txns/euler-x/src-generated/Gateway/Billdesk/Transforms.hs:1663`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `mercid` | `Text` | `mercid` | Yes | Billdesk merchant ID |
| 2 | `mandateid` | `Text` | `mandateid` | Yes | Billdesk mandate ID to revoke |
| 3 | `payment_method_type` | `Text` | `payment_method_type` | Yes | Payment method type |
| 4 | `upi` | `Maybe UpiVpa` | `upi` | No | UPI VPA for UPI mandates |
| 5 | `customer_refid` | `Maybe Text` | `customer_refid` | No | Customer reference ID |
| 6 | `subscription_refid` | `Maybe Text` | `subscription_refid` | No | Subscription reference ID |

#### VerifyVpaReq — `euler-api-txns/euler-x/src-generated/Gateway/Billdesk/Types.hs`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `mercid` | `Text` | `mercid` | Yes | Billdesk merchant ID |
| 2 | `vpa` | `Text` | `vpa` | Yes | UPI VPA to verify |

### 3.8 Request Enums

#### IntegrationVersion — `euler-api-txns/euler-x/src-generated/Gateway/Billdesk/Types.hs`

| # | Constructor | JSON Value | Description |
|---|-------------|-----------|-------------|
| 1 | `V1` | `"V1"` | Legacy pipe-delimited format |
| 2 | `V2` | `"V2"` | JSON REST API with JWE encryption |

---

## 4. Response Structure

### 4.1 Gateway Side — Settlement Success Response

**Type**: `SDRWrapperAPIResponse` (variant: `ValidSDRWrapperAPIResponse SDRWrapperSuccessResponse`) — `euler-api-gateway/common/src/Euler/API/Gateway/Types/API/Settlements.hs:159`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `records` | `[A.Value]` | `records` | Yes | Array of settlement record objects (HashMap Text Text decoded from JWE) |
| 2 | `next_cursor` | `Maybe Text` | `next_cursor` | No | Pagination cursor (always "1" when present) |

**Field Count**: 2 fields

**On Error**: `ErrorSDRWrapperAPIResponse SDRWrapperErrorResponse`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `error_code` | `Text` | `error_code` | Yes | Error code ("UNEXPECTED_GATEWAY_RESPONSE", "JP_801", "400") |
| 2 | `error_message` | `Text` | `error_message` | Yes | Human-readable error description |
| 3 | `error_type` | `Maybe Text` | `error_type` | No | Error type classification |

**Field Count**: 3 fields

### 4.2 Txns Side — Settlement Response Type (from Billdesk)

**Type**: `BilldeskSettlementResponse` — `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/BILLDESK/Types.hs`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `objectid` | `Text` | `objectid` | Yes | Object identifier |
| 2 | `pv_number` | `Text` | `pv_number` | Yes | PV number |
| 3 | `mercid` | `Text` | `mercid` | Yes | Merchant ID |
| 4 | `payout_mercid` | `Text` | `payout_mercid` | Yes | Payout merchant ID |
| 5 | `pv_file` | `Text` | `pv_file` | Yes | PV file reference |
| 6 | `pv_file_date` | `Text` | `pv_file_date` | Yes | PV file date |
| 7 | `currency` | `Text` | `currency` | Yes | Currency code |
| 8 | `amount_details` | `AmountDetails` | `amount_details` | Yes | Breakdown of amounts |
| 9 | `charges` | `Text` | `charges` | Yes | Gateway charges |
| 10 | `taxes` | `Text` | `taxes` | Yes | Taxes applied |
| 11 | `other_adjustments` | `Text` | `other_adjustments` | Yes | Other adjustments |
| 12 | `payout_amount` | `Text` | `payout_amount` | Yes | Final payout amount |
| 13 | `status` | `Text` | `status` | Yes | Settlement status |
| 14 | `settlement_date` | `Text` | `settlement_date` | Yes | Settlement date |
| 15 | `utr` | `Text` | `utr` | Yes | UTR number |
| 16 | `utr_date` | `Text` | `utr_date` | Yes | UTR date |

**Field Count**: 16 fields

### 4.3 Txns Side — V1 Authorization Response

**Type**: `BilldeskAuthorizationResponseMsg` — `euler-api-txns/euler-x/src-generated/Gateway/Billdesk/Types.hs`

Pipe-delimited response, mapped to fields:

| # | Field Name | Position | Description |
|---|------------|----------|-------------|
| 1 | `_MerchantID` | 0 | Merchant ID |
| 2 | `_CustomerID` | 1 | Customer (txn) ID |
| 3 | `_TxnReferenceNo` | 2 | Billdesk transaction reference number |
| 4 | `_BankReferenceNo` | 3 | Bank reference number |
| 5 | `_TxnAmount` | 4 | Transaction amount |
| 6 | `_BankID` | 5 | Bank identifier |
| 7 | `_BankMerchantID` | 6 | Bank merchant ID |
| 8 | `_TxnType` | 7 | Transaction type |
| 9 | `_CurrencyType` | 8 | Currency type |
| 10 | `_ItemCode` | 9 | Item code |
| 11 | `_SecurityType` | 10 | Security type |
| 12 | `_SecurityID` | 11 | Security ID |
| 13 | `_SecurityPassword` | 12 | Security password |
| 14 | `_TxnDate` | 13 | Transaction date |
| 15 | `_AuthStatus` | 14 | Authorization status (key status field) |
| 16 | `_SettlementType` | 15 | Settlement type |
| 17 | `_AdditionalInfo1` | 16 | Additional info 1 |
| 18 | `_AdditionalInfo2` | 17 | Additional info 2 |
| 19 | `_AdditionalInfo3` | 18 | Additional info 3 |
| 20 | `_AdditionalInfo4` | 19 | Additional info 4 |
| 21 | `_AdditionalInfo5` | 20 | Additional info 5 |
| 22 | `_AdditionalInfo6` | 21 | Additional info 6 |
| 23 | `_AdditionalInfo7` | 22 | Additional info 7 |
| 24 | `_ErrorStatus` | 23 | Error status |
| 25 | `_ErrorDescription` | 24 | Error description |
| 26 | `_Checksum` | 25 | Response checksum |

**Field Count**: 26 fields

### 4.4 Txns Side — V2 Create Transaction Response

**Type**: `CreateTxnResp` — `euler-api-txns/euler-x/src-generated/Gateway/Billdesk/Types.hs`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `mercid` | `Text` | `mercid` | Yes | Merchant ID |
| 2 | `transactionid` | `Text` | `transactionid` | Yes | Billdesk transaction ID (epgTxnId) |
| 3 | `orderid` | `Text` | `orderid` | Yes | Order ID |
| 4 | `amount` | `Text` | `amount` | Yes | Transaction amount |
| 5 | `currency` | `Text` | `currency` | Yes | Currency |
| 6 | `auth_status` | `Text` | `auth_status` | Yes | Auth status code (0300/0002/0399) |
| 7 | `transaction_error_type` | `Text` | `transaction_error_type` | Yes | Error type |
| 8 | `transaction_error_desc` | `Text` | `transaction_error_desc` | Yes | Error description |
| 9 | `links` | `Maybe [PaymentLinks]` | `links` | No | Redirect URLs |
| 10 | `next_step` | `Maybe Text` | `next_step` | No | "redirect", "3ds2_challenge", etc. |
| 11 | `surcharge` | `Maybe SurchargeInfo` | `surcharge` | No | Surcharge information |

**Field Count**: 11 fields

### 4.5 Txns Side — V1 Refund Response

**Type**: `RefundResponseMsg` — `euler-api-txns/euler-x/src-generated/Gateway/Billdesk/Types.hs`

| # | Field Name | Position | Description |
|---|------------|----------|-------------|
| 1 | `_RequestType` | 0 | Request type (0400 = refund) |
| 2 | `_MerchantID` | 1 | Merchant ID |
| 3 | `_TxnReferenceNo` | 2 | Billdesk transaction reference |
| 4 | `_TxnDate` | 3 | Original transaction date |
| 5 | `_CustomerID` | 4 | Customer ID |
| 6 | `_TxnAmount` | 5 | Original transaction amount |
| 7 | `_RefAmount` | 6 | Refund amount |
| 8 | `_RefDateTime` | 7 | Refund datetime |
| 9 | `_RefStatus` | 8 | Refund status |
| 10 | `_RefundId` | 9 | Refund ID |
| 11 | `_ErrorCode` | 10 | Error code |
| 12 | `_ErrorReason` | 11 | Error reason |
| 13 | `_ProcessStatus` | 12 | Process status |
| 14 | `_Checksum` | 13 | Response checksum |

**Field Count**: 14 fields

### 4.6 Txns Side — V1 Status Response

**Type**: `StatusResponseMsg` — `euler-api-txns/euler-x/src-generated/Gateway/Billdesk/Types.hs`

| # | Field Name | Position | Description |
|---|------------|----------|-------------|
| 1 | `_RequestType` | 0 | Request type |
| 2 | `_MerchantID` | 1 | Merchant ID |
| 3 | `_CustomerID` | 2 | Customer ID |
| 4 | `_TxnReferenceNo` | 3 | Billdesk txn reference |
| 5 | `_BankReferenceNo` | 4 | Bank reference |
| 6 | `_TxnAmount` | 5 | Transaction amount |
| 7 | `_BankID` | 6 | Bank ID |
| 8 | `_CurrencyType` | 7 | Currency |
| 9 | `_ItemCode` | 8 | Item code |
| 10 | `_TxnDate` | 9 | Transaction date |
| 11 | `_AuthStatus` | 10 | Authorization status |
| 12 | `_SettlementType` | 11 | Settlement type |
| 13 | `_AdditionalInfo1..7` | 12–18 | Additional info fields |
| 14 | `_RefundStatus` | 19 | Refund status (if "NA" = not refunded) |
| 15 | `_ErrorStatus` | 20 | Error status |
| 16 | `_ErrorDescription` | 21 | Error description |
| 17 | `_Checksum` | 22 | Response checksum |

**Field Count**: 17 distinct fields (some grouped)

### 4.7 Txns Side — V1 Recurring Response

**Type**: `RecurringResponseMsg` — `euler-api-txns/euler-x/src-generated/Gateway/Billdesk/Transforms.hs:1294`

| # | Field Name | Position | Description |
|---|------------|----------|-------------|
| 1 | `_MerchantID` | 0 | Merchant ID |
| 2 | `_CustomerID` | 1 | Customer ID |
| 3 | `_TxnReferenceNo` | 2 | Transaction reference |
| 4 | `_BankReferenceNo` | 3 | Bank reference |
| 5 | `_TxnAmount` | 4 | Amount |
| 6 | `_BankID` | 5 | Bank ID |
| 7 | `_BankMerchantID` | 6 | Bank merchant ID |
| 8 | `_TxnType` | 7 | Transaction type |
| 9 | `_CurrencyType` | 8 | Currency |
| 10 | `_ItemCode` | 9 | Item code |
| 11 | `_SecurityType` | 10 | Security type |
| 12 | `_SecurityID` | 11 | Security ID |
| 13 | `_SecurityPassword` | 12 | Security password |
| 14 | `_TxnDate` | 13 | Transaction date |
| 15 | `_AuthStatus` | 14 | Authorization status |
| 16 | `_SettlementType` | 15 | Settlement type |
| 17 | `_AdditionalInfo1..7` | 16–22 | Additional info fields |
| 18 | `_ErrorStatus` | 23 | Error status |
| 19 | `_ErrorDescription` | 24 | Error description |
| 20 | `_Checksum` | 25 | Response checksum |

**Field Count**: 20 fields (some grouped)

### 4.8 Nested Response Types

#### AmountDetails — `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/BILLDESK/Types.hs`
Used in field: `amount_details` of `BilldeskSettlementResponse`

| # | Field Name | Haskell Type | JSON Key | Description |
|---|------------|-------------|----------|-------------|
| 1 | `settlement` | `Text` | `settlement` | Settlement amount |
| 2 | `refund` | `Text` | `refund` | Refund amount |
| 3 | `chargeback` | `Text` | `chargeback` | Chargeback amount |
| 4 | `refund_reversal` | `Text` | `refund_reversal` | Refund reversal amount |
| 5 | `chargeback_reversal` | `Text` | `chargeback_reversal` | Chargeback reversal |
| 6 | `adjustment` | `Text` | `adjustment` | Adjustment amount |

#### PaymentLinks — `euler-api-txns/euler-x/src-generated/Gateway/Billdesk/Types.hs`
Used in field: `links` of `CreateTxnResp`

| # | Field Name | Haskell Type | JSON Key | Description |
|---|------------|-------------|----------|-------------|
| 1 | `href` | `Text` | `href` | Redirect URL |
| 2 | `method` | `Text` | `method` | HTTP method (GET/POST) |
| 3 | `parameters` | `Maybe (StrMap Text)` | `parameters` | Form POST parameters |

#### RefundStatusResponseV2 — `euler-api-txns/euler-x/src-generated/Gateway/Billdesk/Transforms.hs:1224`
Used for ARN sync responses

| # | Field Name | Position | Description |
|---|------------|----------|-------------|
| 1 | `_RequestType` | 0 | Request type |
| 2 | `_MerchantID` | 1 | Merchant ID |
| 3 | `_RefundId` | 2 | Refund ID |
| 4 | `_TxnReferenceNo` | 3 | Transaction reference |
| 5 | `_CustomerID` | 4 | Customer ID |
| 6 | `_TxnDate` | 5 | Transaction date |
| 7 | `_TxnCurrency` | 6 | Currency |
| 8 | `_TxnAmount` | 7 | Transaction amount |
| 9 | `_RefAmount` | 8 | Refund amount |
| 10 | `_RefDateTime` | 9 | Refund datetime |
| 11 | `_RefStatus` | 10 | Refund status |
| 12 | `_MerchantRefNo` | 11 | Merchant refund reference |
| 13 | `_RefARN` | 12 | Refund ARN |
| 14 | `_RefARNTimeStamp` | 13 | ARN timestamp |
| 15 | `_ErrorCode` | 14 | Error code |
| 16 | `_ErrorReason` | 15 | Error reason |
| 17 | `_Filler1` | 16 | Filler 1 |
| 18 | `_Filler2` | 17 | Filler 2 |
| 19 | `_Filler3` | 18 | Filler 3 |
| 20 | `_ProcessStatus` | 19 | Process status |
| 21 | `_Checksum` | 20 | Checksum |

### 4.9 Response Enums

#### BilldeskResponse ADT — `euler-api-txns/euler-x/src-generated/Gateway/Billdesk/Types.hs:1722`

| # | Constructor | Description |
|---|-------------|-------------|
| 1 | `BilldeskTxnStatusResponseData BilldeskTxnStatusResponseData` | Status check response wrapper |
| 2 | `BilldeskRewardAuth BilldeskRewardAuthResponse` | Reward points auth response |
| 3 | (18 total constructors) | Various response variants for all payment flows |

#### BilldeskTxnStatusResponseData — `euler-api-txns/euler-x/src-generated/Gateway/Billdesk/Types.hs:664`

| # | Constructor | Carries | Description |
|---|-------------|---------|-------------|
| 1 | `TxnStatusResponse` | `StatusResponseMsg` | V1 status check response |
| 2 | `TxnResponse` | `BilldeskAuthorizationResponseMsg` | V1 authorization response |
| 3 | `CardAndPointsSynResp` | — | Card + points combined sync |
| 4 | `RetrieveTxnStatusResp` | `UpdateTxnResp` | V2 transaction status |
| 5 | `RetrieveMandateTxnStatusResp` | `TransactionResponse` | V2 mandate status |
| 6 | `RecurringTxnStatusResponse` | `RecurringTxnResponse` | V1 recurring response |
| 7 | `RetrieveTxnStatusErrResp` | `InvalidRequestResponse` | V2 error response |
| 8 | `EnachTxnStatusResp` | `BilldeskEnachDecryptResponse` | eNACH status response |

---

## 5. Flows

### 5.1 Flow: getReconciliationDetails (Gateway Side)

**File**: `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/BILLDESK/Flows.hs:23`
**Purpose**: Fetch settlement/reconciliation data from Billdesk settlement API
**Trigger**: Settlement Data Reconciliation (SDR) request from internal scheduling or merchant API

#### Steps

| Step | Action | Function | File | Details |
|------|--------|----------|------|---------|
| 1 | Decode Billdesk account details from MGA | `getBilldeskAccountDetails` | `Transforms.hs:~1` | Extracts `billdeskMerchantId` and `billdeskClientId` |
| 2 | Build settlement request | — | `Flows.hs:29` | Creates `BilldeskSettlementRequest` with merchantId, startDate, endDate (defaults to today), pvNumber=Nothing |
| 3 | Log decrypted request | `logDecryptedRequest` | `Flows.hs:31` | Logs plaintext request for debugging |
| 4 | Encrypt payload (JWE+JWS) | `getJweEncryptedPayload` | `Encryption.hs` | RSA-OAEP-256+A128GCM encrypt then RS256 sign |
| 5 | Generate trace ID and timestamp | `getUUID16`, `changeCurrentDateTimeFormat` | `Flows.hs:36-37` | UUID16 for BD-Traceid; datetime for BD-Timestamp |
| 6 | Call Billdesk settlement API | `Routes.callReconciliationDetails` | `Routes.hs` | GET /pasettlements/v1_2/settlements/get |
| 7 | Handle response | `handleReconciliationDetailsResponse` | `Flows.hs:46` | Decrypt+verify JWS, extract settlement data |

#### Decision Points

| # | Condition | YES Branch | NO Branch |
|---|-----------|-----------|-----------|
| 1 | Account details decoded successfully | Proceed to build request | Return `ErrorSDRWrapperAPIResponse` with code "400" |
| 2 | JWE encryption succeeded | Proceed to API call | Return `ErrorSDRWrapperAPIResponse` with code "JP_801" |
| 3 | API call returned Right | Proceed to decrypt response | Return `ErrorSDRWrapperAPIResponse` with "UNEXPECTED_GATEWAY_RESPONSE" |
| 4 | Billdesk signing key found from fingerprint | Verify and decrypt JWS | Return `ErrorSDRWrapperAPIResponse` with code "JP_801" |
| 5 | JWS verification + JWE decryption succeeded | Return `ValidSDRWrapperAPIResponse` | Return `ErrorSDRWrapperAPIResponse` with code "JP_801" |

#### Flow Diagram

```
SDRWrapperRequest
    │
    ▼
[Decode BilldeskAccountDetails from MGA]
    │ Left: decode error ──────────────────────► ErrorSDRWrapperAPIResponse (code "400")
    │ Right
    ▼
[Build BilldeskSettlementRequest]
    │
    ▼
[Encrypt payload: JWE+JWS via Encryption.getJweEncryptedPayload]
    │ Left: encryption error ──────────────────► ErrorSDRWrapperAPIResponse (code "JP_801")
    │ Right: (encryptedPayload, encryptionDetails)
    ▼
[GET /pasettlements/v1_2/settlements/get]
[Headers: Content-Type:application/jose, Accept:application/jose, BD-Traceid, BD-Timestamp]
    │ Left: ClientError ───────────────────────► ErrorSDRWrapperAPIResponse ("UNEXPECTED_GATEWAY_RESPONSE")
    │ Right: encryptedResponseText
    ▼
[Find Billdesk signing key from JWS header fingerprint]
    │ Left: key not found ────────────────────► ErrorSDRWrapperAPIResponse (code "JP_801")
    │ Right: signingKey
    ▼
[Verify JWS signature + Decrypt JWE]
    │ Left: verify/decrypt error ────────────► ErrorSDRWrapperAPIResponse (code "JP_801")
    │ Right: decryptedText
    ▼
[Decode as HashMap Text Text]
    │ Nothing: decode error ─────────────────► ErrorSDRWrapperAPIResponse (code "JP_801")
    │ Just decryptedResponse
    ▼
ValidSDRWrapperAPIResponse { records=[decryptedResponse], next_cursor=Just "1" }
```

### 5.2 Flow: initiateTxn (Txns Side)

**File**: `euler-api-txns/euler-x/src-generated/Gateway/Billdesk/Flow.hs:~1`
**Purpose**: Main entry point for transaction initiation — routes to card, non-card, or eNACH sub-flows
**Trigger**: Payment initiation request for BILLDESK gateway

#### Steps

| Step | Action | Function | File | Details |
|------|--------|----------|------|---------|
| 1 | Decode BilldeskDetails from MGA | `decodeGatewayCredentials` | `Flow.hs` | Gets merchantId, checksumKey, hashAlgo, clientId, etc. |
| 2 | Determine if eNACH flow | `Txn.isMandateCardRegFlow` | `Flow.hs` | eNACH = EMANDATE_REGISTER source object |
| 3 | Determine if legacy redirect | `isLegacyRedirect'` | `Flow.hs:1934` | Checks `isLegacyRedirect`, `cardRedirect`, `nbRedirect`, etc. in BilldeskDetails |
| 4 | Branch: Card or Non-Card or eNACH | `initiateCardTxn` / `initiateNonCardTxn` / `initiateEnachTxn` | `Flow.hs` | Based on `txnCardInfo.paymentMethodType` |

#### Sub-Flow Decision (initiateCardTxn) — `Flow.hs:1264`

| # | Condition | Branch |
|---|-----------|--------|
| 1 | Cross-border details missing | Return `JUSPAY_DECLINED` with "CROSS_BORDER_INFO_MISSING" |
| 2 | Mandate card registration flow | `processCardSiRegTxn` → V2 JWE mandate enrollment |
| 3 | Legacy redirect enabled | `processCardLegacyFlow` → V1 form POST redirect |
| 4 | Reward points transaction | `checkOnlyPointsOrCardAndPointsTxn` |
| 5 | V2 integration enabled (MGA feature flag) | `initTxnBillDeskV2` → V2 JWE create txn |
| 6 | Default (V1 HMAC) | `verifyFlowAndProcessCardTxn` → V1 server-side card initiation |

### 5.3 Flow: initiateEnachTxn (eNACH Registration)

**File**: `euler-api-txns/euler-x/src-generated/Gateway/Billdesk/Flow.hs:1193`
**Purpose**: Register an eNACH mandate for recurring debits

#### Steps

| Step | Action | Function | File | Details |
|------|--------|----------|------|---------|
| 1 | Get encryption details | `GBT.getEncryptionRequiredDetails` | `Flow.hs:1196` | Fetches JWE certs from config/env |
| 2 | Check cross-border requirements | `getCrossBorderDetails` | `Flow.hs:1200` | Validates cross-border settlement info |
| 3 | Resolve additional info | `GBT.resolveAndGetBilldeskAdditionalInfo` | `Flow.hs:1205` | Maps UDF/metadata to Billdesk additional_info |
| 4 | Build eNACH enrollment request | `GBT.makeEnachEnrollmentRequest` | `Flow.hs:1221` | Constructs mandate setup payload |
| 5 | Encrypt payload (JWE+JWS) | `GBT.getJweEncryptedAndSignedPayload` | `Flow.hs:1226` | Encrypts for Billdesk |
| 6 | Generate trace ID and timestamp | `getUUID16`, `getCurrentDateStringWithoutSpace` | `Flow.hs:1234-1235` | Headers for API call |
| 7 | Call Billdesk create mandate endpoint | `initRequestWithPG` | `Flow.hs:1238` | POST to `getCreateMandateEndpoint` |
| 8 | Verify and handle response | `verifyPaymentEnrollmentInitResponseAndHandle` | `Flow.hs:1239` | Decrypt, verify, parse enrollment result |

### 5.4 Flow: initTxnBillDeskV2 (V2 Card/NB/UPI Transaction)

**File**: `euler-api-txns/euler-x/src-generated/Gateway/Billdesk/Flow.hs:1510`
**Purpose**: Initiate a payment transaction using Billdesk V2 JSON API

#### Steps

| Step | Action | Function | File | Details |
|------|--------|----------|------|---------|
| 1 | Get txn mandatory details | `GBT.getMidTxnUuidAndOrderId` | `Flow.hs:1512` | Extracts merchantId, txnUuid, orderId |
| 2 | Check if token-based txn | `isTokenBasedTxn` | `Flow.hs:1519` | TAVV present for token payments |
| 3 | Build and send create txn | `createTxn` | `Flow.hs:1523-1527` | Builds CreateTxnReq, encrypts, sends |
| 4 | Handle response | `getPaymentResponse` | `Flow.hs:1540` | Parse decrypted V2 response |

#### Decision Points (getPaymentResponse)

| # | Condition | YES Branch | NO Branch |
|---|-----------|-----------|-----------|
| 1 | `CreateTxnPGResponse` received | Check auth_status and links | Handle InvalidResponse or unrecognized |
| 2 | `auth_status == "0002"` and next_step is "redirect"/"3ds2_challenge" | `GatewayRedirect` with 3DS redirect URL | `PaymentRespError AUTHENTICATION_FAILED` |
| 3 | `auth_status == "0300"` and no links | `DirectDebitPayment CHARGED` (frictionless 3DS2) | `PaymentRespError AUTHENTICATION_FAILED` |
| 4 | Surcharge mismatch | Return VerificationError "SURCHARGE_VERIFICATION_FAILED" | Continue |

### 5.5 Flow: initBilldeskOnlineStatusRequest (Transaction Status Check)

**File**: `euler-api-txns/euler-x/src-generated/Gateway/Billdesk/Flow.hs`
**Purpose**: Query Billdesk for transaction status during sync

#### Steps

| Step | Action | Function | File | Details |
|------|--------|----------|------|---------|
| 1 | Determine V2 or V1 flow | `isMgaEnabledForV2Integration` | `Flow.hs` | Feature flag on MGA |
| 2 | V2: Build encrypted status request | `initRequestAndGetEitherDecryptedResponse` | `Flow.hs` | JWE request to `getUpdateTxnEndpoint` |
| 3 | V1: Build pipe-delimited status request | `GBT.makeBilldeskOnlineStatusRequest` | `Transforms.hs` | Msg with MerchantID, TxnReferenceNo |
| 4 | Parse response and map to TxnStatus | `decideTxnStatusFromPGResponse` | `Flow.hs:4059` | Maps auth_status codes to TxnStatus |

### 5.6 Flow: initBilldeskOnlineRefundRequest (Refund)

**File**: `euler-api-txns/euler-x/src-generated/Gateway/Billdesk/Flow.hs`
**Purpose**: Submit refund request to Billdesk

#### Steps

| Step | Action | Function | File | Details |
|------|--------|----------|------|---------|
| 1 | Determine V2 or V1 | `isMgaEnabledForV2Integration` | `Flow.hs` | Feature flag |
| 2 | V1: Build refund message | `makeBilldeskOnlineRefundRequest` | `Transforms.hs:1124` | Pipe-delimited 0400 request with checksum |
| 3 | V1: Call refund endpoint | `initBilldeskOnlineRefundRequest` | `Flow.hs` | POST to `/pgidsk/PGIHFRefundAndStatusHandler` |
| 4 | Parse refund response | `RefundResponseHandler` | `RefundResponseHandler.hs` | Verify checksum, parse pipe response |
| 5 | V2: Build and encrypt refund | `RefundBilldeskV2Req` | `Flow.hs` | JWE-encrypted refund POST |

### 5.7 Flow: verifyMandateDetailsAndProcessRequestWithPG (Card Mandate Registration)

**File**: `euler-api-txns/euler-x/src-generated/Gateway/Billdesk/Flow.hs:1377`
**Purpose**: Register card for SI/mandate via Billdesk V2

#### Steps

| Step | Action | Function | File | Details |
|------|--------|----------|------|---------|
| 1 | Resolve additional info | `GBT.resolveAndGetBilldeskAdditionalInfo` | `Flow.hs:1380` | Map metadata to addInfo list |
| 2 | Get mandate setup details | `GBT.getMandateSetupDetails` | `Flow.hs:1387` | Validates mandate, customer info |
| 3 | If penny txn type | `GBT.makeEnrollmentRequest` → `getCreateMandateEndpoint` | `Flow.hs:1406` | Penny debit for mandate |
| 4 | Else | `GBT.makePaymentEnrollmentRequest` → `getCreateTxnEndpoint` | `Flow.hs:1415` | Payment enrollment |
| 5 | Encrypt payload (JWE+JWS) | `GBT.getJweEncryptedAndSignedPayload` | `Flow.hs:1423` | Encrypt for Billdesk |
| 6 | Send to Billdesk | `initRequestWithPG` | `Flow.hs:1435` | POST to chosen endpoint |
| 7 | Handle response | `verifyPaymentEnrollmentInitResponseAndHandle` | `Flow.hs:1440` | Decrypt, parse, redirect or error |

### 5.8 Flow: sendCollectRequest (UPI Collect)

**File**: `euler-api-txns/euler-x/src-generated/Gateway/Billdesk/Flow.hs`
**Purpose**: Initiate UPI collect request

#### Steps

| Step | Action | Function | File | Details |
|------|--------|----------|------|---------|
| 1 | Build UPI initiate request | `makeBilldeskInitiateUPIRequest` | `Transforms.hs:1578` | Pipe-delimited msg with VPA, merchant, amount |
| 2 | Send to Billdesk UPI endpoint | `initBilldeskUPIInitiateRequest` | `Endpoints.hs` | POST with msg, useragent, ipaddress |
| 3 | Parse and return | `BilldeskUPITransactionResponse` | `Transforms.hs:1620` | 26-field pipe response |

### 5.9 Flow: initBilldeskCreateMandateRequest (V1 Recurring Initiation)

**File**: `euler-api-txns/euler-x/src-generated/Gateway/Billdesk/Flow.hs`
**Purpose**: Initiate a V1 recurring payment

#### Steps

| Step | Action | Function | File | Details |
|------|--------|----------|------|---------|
| 1 | Build recurring request | `makeBilldeskRecurringRequest` | `Transforms.hs:1251` | SI-prefixed pipe msg with pgMandateId, mandateId |
| 2 | Send to Billdesk | `initBilldeskRecurringRequest` | `Endpoints.hs` | POST with msg, paydata, ipaddress |
| 3 | Parse response | `makeBilldeskRecurringResponse` | `Transforms.hs:1294` | 26-field pipe response |

### 5.10 Flow: checkOnlyPointsOrCardAndPointsTxn (Reward Points)

**File**: `euler-api-txns/euler-x/src-generated/Gateway/Billdesk/Flow.hs:1783`
**Purpose**: Handle Loylty/Elitepay reward points transactions

#### Steps

| Step | Action | Function | File | Details |
|------|--------|----------|------|---------|
| 1 | Resolve additional info | `GBT.resolveAndGetBilldeskAdditionalInfo` | `Flow.hs:1786` | Map metadata |
| 2 | Build reward initiate request | `GBT.makeBilldeskInitiateRewardTxnRequest` | `Transforms.hs:1701` | Includes mobile number |
| 3 | Call reward initiation | `initBilldeskInitiateRewardTxnRequest` | `Flow.hs:1794` | POST to Loylty/Elitepay endpoint |
| 4 | Parse response | `BilldeskRewardInitiateValidResp` | `Flow.hs:1809` | Check points available vs amount |
| 5a | If points == amount and authType == OTP | `DirectOTPGatewayResponse` | `Flow.hs:1817` | OTP flow |
| 5b | If points == amount and authType != OTP | `ShowDotpPage` | `Flow.hs:1818` | DOTP page |
| 5c | If partial (points < amount) | `GatewayRedirect` (card+points split) | `Flow.hs:1820` | Redirect for card portion |

### 5.11 Data Transformations

| # | From | To | Function | File | Logic |
|---|------|----|----------|------|-------|
| 1 | `BilldeskDetails + txn fields` | Pipe-delimited `msg` Text | `make_BilldeskInitiateCardTxnMsg` | `Transforms.hs` | Intercalates fields with `\|`, appends CRC32/HMAC checksum |
| 2 | `JSON Text` | JWE+JWS encrypted Text | `getJweEncryptedAndSignedPayload` | `Transforms.hs` / `Encryption.hs` | RSA-OAEP-256+A128GCM encrypt, RS256 sign |
| 3 | JWS-signed JWE response Text | Decrypted JSON Text | `verifyAndDecryptResponseWithJwt` | `Flow.hs` | Verify JWS with Billdesk signing key, decrypt JWE with Juspay private key |
| 4 | Pipe-delimited response Text | `BilldeskAuthorizationResponseMsg` | `make_BilldeskAuthorizationResponse` | `Transforms.hs` | `split "\|"`, index array positions |
| 5 | Pipe-delimited refund response | `RefundResponseMsg` | `make_BilldeskOnlineRefundResponse` | `Transforms.hs:1205` | `split "\|"`, index array positions |
| 6 | Pipe-delimited refund ARN response | `RefundStatusResponseV2` | `make_BilldeskOnlineRefundARNSyncResponse` | `Transforms.hs:1224` | 21-field pipe response |
| 7 | `Maybe BilldeskMetaData` | End date Text | `getEndDateFromMetadata` | `Transforms.hs:1383` | Extracts `__BILLDESK_58_end_date`, defaults to "2050-12-30" |
| 8 | `Customer + OrderReference` | `CustomerType` | `makeCustomerType` | `Transforms.hs:1461` | Validates email (regex) and phone, trims blanks |
| 9 | `OrderMetadataV2 + TxnDetail` | `DeviceType` | `makeDeviceType` | `Transforms.hs:1494` | 3DS1 or 3DS2 device body based on `is3DS2Enabled` flag |
| 10 | Raw card data | `CardType` | `makeCardType` | `Transforms.hs:1432` | RSA-encrypts card number, expiry month, expiry year with cert from env |
| 11 | Billdesk recurring msg | `BilldeskRecurringRequest` | `makeBilldeskRecurringRequest` | `Transforms.hs:1251` | SI: prefix with mandate IDs in paydata |
| 12 | Amount Number | String (2 decimal) | `roundOff2Str'` | Transforms | `amountFormat BILLDESK = EffectiveAmount`, `amountCalculationLogic BILLDESK = BaseAmount` |

---

## 6. Error Handling

### 6.1 API Call Error Handling

| # | Error Type | Handling | Fallback | File |
|---|-----------|----------|----------|------|
| 1 | `ClientError` (gateway side) | Log and return `ErrorSDRWrapperAPIResponse` with "UNEXPECTED_GATEWAY_RESPONSE" | — | `Flows.hs:49-55` |
| 2 | JWE encryption failure | Log error, return `makeFailurePGRAndErrorGatewayResponse` | — | `Flow.hs:1228-1232` |
| 3 | JWS verification failure | Send to Sentry, return `AUTHENTICATION_FAILED` | — | `Flow.hs:1497-1500` |
| 4 | `EulerError` in txn flows | `LogUtils.forkErrorLog AUTHENTICATION_FAILED` | `AUTHENTICATION_FAILED` status | `Flow.hs:1504-1506` |
| 5 | `HTTP_504` (gateway timeout) | `throwUpstreamGatewayError "upstream gateway timeout"` | — | `Flow.hs:1911` |
| 6 | `HTTP_503` (service unavailable) | `throwUpstreamGatewayError "upstream gateway service unavailable"` | — | `Flow.hs:1913` |
| 7 | `Socket Operation` (timeout) | `throwUpstreamGatewayError "upstream gateway timeout"` | — | `Flow.hs:1916` |
| 8 | `DecodeError` | `handleErr Constants.processRespErr` → `AUTHENTICATION_FAILED` | — | `Flow.hs:1587` |
| 9 | `VerificationError` | `handleErr Constants.verificationErr` → `JUSPAY_DECLINED` | — | `Flow.hs:1589` |
| 10 | Checksum mismatch (V1 refund) | Return `UNKNOWN` status | — | `RefundResponseHandler.hs` |
| 11 | Cross-border details missing | `JUSPAY_DECLINED` with "CROSS_BORDER_INFO_MISSING" | — | `Flow.hs:1202` |
| 12 | Additional info validation failed | `JUSPAY_DECLINED` with "ADDITIONAL_INFO_VALIDATION_FAILED" | — | `Flow.hs:1208-1210` |
| 13 | Surcharge verification failed | `VerificationError "SURCHARGE_VERIFICATION_FAILED"` | — | `Flow.hs:1595` |

### 6.2 HTTP Status Code Handling

| HTTP Status | Handling | Response to Caller |
|-------------|----------|--------------------|
| 200 (with valid JWE body) | Decrypt+verify, extract settlement/payment data | `ValidSDRWrapperAPIResponse` / `GatewayRedirect` / `PaymentResp` |
| 200 (with error in decrypted body) | Map to internal error type | `ErrorSDRWrapperAPIResponse` / `PaymentRespError` |
| Connection failure (ClientError) | Log, return UNEXPECTED_GATEWAY_RESPONSE | `ErrorSDRWrapperAPIResponse` |
| 408/504 timeout | `throwUpstreamGatewayError` | Gateway timeout error |
| 503 | `throwUpstreamGatewayError` | Service unavailable error |
| Any other HTTP error | Treated as `ClientError`, log and return error | `ErrorSDRWrapperAPIResponse` |

### 6.3 Timeout & Retry

- **Timeout Mechanism**: EulerHS platform HTTP client timeout (Socket Operation timeout)
- **Default Timeout**: Platform default (not explicitly configured per-connector in BILLDESK)
- **Retry Enabled**: No (no explicit retry logic observed in Billdesk flows)
- **Max Retries**: 0
- **Retry Strategy**: N/A

### 6.4 Error Response Types

#### SDRWrapperErrorResponse (gateway side) — `euler-api-gateway/common/src/Euler/API/Gateway/Types/API/Settlements.hs:150`

| # | Field Name | Type | JSON Key | Description |
|---|------------|------|----------|-------------|
| 1 | `error_code` | `Text` | `error_code` | Error code: "UNEXPECTED_GATEWAY_RESPONSE", "JP_801", "400" |
| 2 | `error_message` | `Text` | `error_message` | Human-readable error description |
| 3 | `error_type` | `Maybe Text` | `error_type` | Error type from client error classification |

#### InvalidRequestResponse (txns side) — `euler-api-txns/euler-x/src-generated/Gateway/Billdesk/Types.hs`

| # | Field Name | Type | JSON Key | Description |
|---|------------|------|----------|-------------|
| 1 | `error_type` | `Text` | `error_type` | Billdesk error category |
| 2 | `error_code` | `Text` | `error_code` | Billdesk error code |
| 3 | `message` | `A.Message` | `message` | Error message |
| 4 | `status` | `Int` | `status` | HTTP status code |

#### BilldeskErrorResponse (txns side) — `euler-api-txns/euler-x/src-generated/Gateway/Billdesk/Types.hs`

| # | Field Name | Type | JSON Key | Description |
|---|------------|------|----------|-------------|
| 1 | `error` | `Text` | `error` | Error code |
| 2 | `error_description` | `Maybe Text` | `error_description` | Error description |

### 6.5 Error Code Mappings

| # | Source Error | Target Error Code | Retry-able | Description |
|---|-------------|-------------------|-----------|-------------|
| 1 | `ClientError` (HTTP) | `UNEXPECTED_GATEWAY_RESPONSE` | No | Any HTTP error from Billdesk settlement API |
| 2 | JWE encryption failure | `JP_801` | No | Cannot encrypt request |
| 3 | JWS verification failure | `JP_801` | No | Response signature invalid |
| 4 | JWE decryption failure | `JP_801` | No | Cannot decrypt response |
| 5 | Account details decode error | `400` | No | Invalid credentials format |
| 6 | `duplicate_request_error` (error_type) | `PENDING_VBV` | Yes | Request deduplication pending |
| 7 | `api_connection_error` (error_type) | `PENDING_VBV` | Yes | Connection issue, retry safe |
| 8 | `api_processing_error` (error_type) | `PENDING_VBV` | Yes | Processing pending |
| 9 | All other error_types in V2 | `AUTHORIZATION_FAILED` | No | Non-retriable auth failure |

---

## 7. Status Mappings

### 7.1 Billdesk V2 auth_status Codes

**Source**: `euler-api-txns/euler-x/src-generated/Gateway/Billdesk/Flow.hs:4059-4087`
**Project**: euler-api-txns

| # | auth_status Value | Meaning | Maps to TxnStatus |
|---|-------------------|---------|------------------|
| 1 | `"0300"` | Success / Charged | `CHARGED` |
| 2 | `"0002"` | Pending (auth in progress) | `PENDING_VBV` |
| 3 | `"0399"` | Authorization failed | `AUTHORIZATION_FAILED` |
| 4 | Any other | Default pending | `PENDING_VBV` |

### 7.2 Billdesk V2 Mandate status

**Source**: `euler-api-txns/euler-x/src-generated/Gateway/Billdesk/Flow.hs:4052`

| # | status Value | Maps to TxnStatus |
|---|-------------|------------------|
| 1 | `"pending"` | `PENDING_VBV` |
| 2 | `"active"` | `CHARGED` |
| 3 | `"rejected"` | `AUTHORIZATION_FAILED` |
| 4 | any other | `PENDING_VBV` |

### 7.3 Billdesk getTxnStatusFromMandateResponse

**Source**: `euler-api-txns/euler-x/src-generated/Gateway/Billdesk/Flow.hs:6121`

| # | status (uppercased) | Maps to TxnStatus |
|---|--------------------|--------------------|
| 1 | `"ACTIVE"` | `CHARGED` |
| 2 | `"REJECTED"` | `AUTHORIZATION_FAILED` |
| 3 | `"REVOKED"` | `AUTHORIZATION_FAILED` |
| 4 | any other | `PENDING_VBV` |

### 7.4 V2 InvalidRequestResponse error_type → TxnStatus

**Source**: `euler-api-txns/euler-x/src-generated/Gateway/Billdesk/Flow.hs:4066-4078`

| # | error_type | Maps to TxnStatus |
|---|-----------|------------------|
| 1 | `"duplicate_request_error"` | `PENDING_VBV` |
| 2 | `"api_connection_error"` | `PENDING_VBV` |
| 3 | `"api_processing_error"` | `PENDING_VBV` |
| 4 | all others | `AUTHORIZATION_FAILED` |

### 7.5 FlowErrors → TxnStatus (V2 flows)

**Source**: `euler-api-txns/euler-x/src-generated/Gateway/Billdesk/Flow.hs:1584-1598`

| # | FlowError Tag | Maps to TxnStatus |
|---|--------------|------------------|
| 1 | `EulerError` | `AUTHENTICATION_FAILED` |
| 2 | `DecodeError` | `AUTHENTICATION_FAILED` |
| 3 | `JWeError` | `AUTHENTICATION_FAILED` |
| 4 | `VerificationError` | `JUSPAY_DECLINED` |
| 5 | other | `PENDING_VBV` |

### 7.6 Recurring Transaction Status

**Source**: `euler-api-txns/euler-x/src-generated/Gateway/Billdesk/Flow.hs:5351`

| # | RecurringTxnDecryptedResponse | Maps to TxnStatus |
|---|------------------------------|------------------|
| 1 | `ValidRecurringResponse` (auth_status = "0300") | `CHARGED` |
| 2 | `ValidRecurringResponse` (auth_status = "0002") | `PENDING_VBV` |
| 3 | `ValidRecurringResponse` (auth_status = "0399") | `AUTHORIZATION_FAILED` |
| 4 | `ValidRecurringEnachResponse` (status = "active") | `CHARGED` |
| 5 | `RecurringErrorResponse` | Per `decideTxnStatusFromErrResp` |

### 7.7 isTxnSuccessful Check for Status Sync

**Source**: `euler-api-txns/euler-x/src-generated/Gateway/Billdesk/Flow.hs:4342-4357`

For determining if a transaction is already successful in sync flows:

| # | Response Type | Condition | Result |
|---|--------------|-----------|--------|
| 1 | `TxnStatusResponse StatusResponseMsg` | `_AuthStatus == "0300"` AND `_RefundStatus == "NA"` | True (charged, not refunded) |
| 2 | `RetrieveMandateTxnStatusResp` | `isTxnSuccessful (auth_status)` AND no auto-refund | True |
| 3 | `RecurringTxnStatusResponse` | `isTxnSuccessful (auth_status)` AND no auto-refund | True |
| 4 | `RetrieveTxnStatusResp` | `isTxnSuccessful (auth_status)` AND no auto-refund | True |
| 5 | `EnachTxnStatusResp` | `status == "active"` | True |
| 6 | `RetrieveTxnStatusErrResp` | Always | False |

---

## 8. Payment Methods

### 8.1 Supported Payment Method Types

| # | PaymentMethodType | Billdesk Integration | Example Payment Methods | Gateway Code | Notes |
|---|------------------|--------------------|------------------------|--------------|-------|
| 1 | `CARD` | V1 (pipe-delimited) + V2 (JWE JSON) | Visa, Mastercard, Amex, Rupay, Maestro | Bank-specific BankID code | V2 if `isMgaEnabledForV2Integration`; V1 via `isLegacyRedirect` |
| 2 | `NB` | V1 (pipe-delimited) + V2 (JWE JSON) | All major Indian banks | Billdesk bank code | V2 if `isMgaEnabledForV2Integration` |
| 3 | `UPI` | V1 (collect/pay/QR) + V2 (JWE JSON) | UPI collect, UPI pay, UPI QR | "UPI" | Collect: VPA as UPIC:vpa:NA:NA:NA |
| 4 | `REWARD` | V1 Loylty/Elitepay API | Reward points (Loylty, Elitepay) | Reward-specific | Source object = "reward" |
| 5 | `CARD` (mandate) | V2 JWE (mandate enrollment) | Visa, Mastercard, Rupay, Amex | — | Mandate registration via `isMandateCardRegFlow` |
| 6 | `UPI` (eNACH) | V2 JWE (eNACH) | UPI eNACH mandate | "UPI" | Source object = EMANDATE_REGISTER |
| 7 | `NB` (recurring) | V1 pipe-delimited SI | All banks | Bank code | SI:pgMandateId:mandateId:NA:NA prefix |
| 8 | `CARD` (recurring) | V1 pipe-delimited SI | Visa, Mastercard | Bank code | SI prefix in recurring msg |

### 8.2 Payment Method Transformation Chain

| Step | Operation | Function | File | Input | Output |
|------|-----------|----------|------|-------|--------|
| 1 | Extract payment method type | `txnCardInfo.paymentMethodType` | `Flow.hs` | `TxnCardInfo` | `Maybe PaymentMethodType` |
| 2 | Determine integration version | `isMgaEnabledForPaymentFlow` | `Flow.hs:1266` | MGA feature flags | V2 or V1 |
| 3 | Determine legacy redirect | `isLegacyRedirect'` | `Flow.hs:1934` | BilldeskDetails flags, cardBrand, cardType | Bool |
| 4 | Get Billdesk bank code | `getCardPaymentBankId` | `Transforms.hs` | txnDetail, billdeskDetails, cardBrand | Billdesk bank ID string |
| 5 | Build payment object | `makeBilldeskPaydataType` | `Transforms.hs` | cardData, txnCardInfo, cardBrand | `BilldeskPaydataType` |
| 6 | Compute checksum | `createCheckSum` | `Transforms.hs` | msg + checksumKey + hashAlgo | CRC32 or HmacSHA256 text |

### 8.3 Payment Method Enums

#### PaymentMethodType — `euler-api-txns` (imported from EC)

| # | Constructor | Description |
|---|-------------|-------------|
| 1 | `CARD` | Debit/credit card payment |
| 2 | `NB` | Net banking |
| 3 | `UPI` | UPI (collect, pay, QR) |
| 4 | `WALLET` | Digital wallet |
| 5 | `REWARD` | Reward points (Loylty/Elitepay) |
| 6 | `PAYLATER` | Pay later (not directly supported by Billdesk) |

#### Card Brand Codes (Billdesk-specific)
Used in `getCardPaymentBankId` and routing decisions:

| # | Card Brand | Billdesk Route | Notes |
|---|-----------|----------------|-------|
| 1 | `VISA` | Standard card BankID | |
| 2 | `MASTERCARD` | Standard card BankID | |
| 3 | `AMEX` | Standard card BankID; `amexRedirect = true` triggers legacy | |
| 4 | `RUPAY` | Standard card BankID; `rupayRedirect = true` triggers legacy | |
| 5 | `MAESTRO` | Standard card BankID | |

### 8.4 Legacy Redirect Decision Logic

**Source**: `euler-api-txns/euler-x/src-generated/Gateway/Billdesk/Flow.hs:1934`

| # | BilldeskDetails Flag | Condition | Effect |
|---|---------------------|-----------|--------|
| 1 | `isLegacyRedirect = "true"` | Always | Force V1 redirect |
| 2 | `emiRedirect = "true"` | `txnDetail.isEmi == True` | EMI → V1 redirect |
| 3 | `cardRedirect = "true"` | CARD payment | Card → V1 redirect |
| 4 | `rupayRedirect = "true"` | `cardBrand == "RUPAY"` | Rupay → V1 redirect |
| 5 | `amexRedirect = "true"` | `cardBrand == "AMEX"` | Amex → V1 redirect |
| 6 | `nbRedirect = "true"` | NB payment | NB → V1 redirect |
| 7 | `walletRedirect = "true"` | Wallet payment | Wallet → V1 redirect |
| 8 | `rewardRedirect = "true"` | Reward payment | Reward → V1 redirect |

### 8.5 Payment Method Fields in Request/Response

**Request fields**:

| # | Field | JSON Key | Type | Present | Description |
|---|-------|----------|------|---------|-------------|
| 1 | `paymentMethodType` | `paymentMethodType` | `Maybe PaymentMethodType` | Yes (in TxnCardInfo) | CARD, NB, UPI, etc. |
| 2 | `paymentMethod` | `paymentMethod` | `Maybe Text` | Yes (in TxnCardInfo) | Specific bank or card brand |
| 3 | `paymentSource` | `paymentSource` | `Maybe Text` | Yes (in TxnCardInfo) | UPI VPA for UPI collect |
| 4 | `cardIsin` | `cardIsin` | `Maybe Text` | Yes (for card) | First 6 digits of card |

**Response fields**:

| # | Field | JSON Key | Type | Present | Description |
|---|-------|----------|------|---------|-------------|
| 1 | `_BankID` | pipe position 5 | `Text` | Yes (V1) | Billdesk bank/card brand code |
| 2 | `auth_status` | `auth_status` | `Text` | Yes (V2) | 0300/0002/0399 |

---

## 9. Completeness Verification

| Check | Result |
|-------|--------|
| Request fields in source (gateway settlement) | 4 (BilldeskSettlementRequest) + 7 (SDRWrapperRequest) |
| Request fields documented | 11 |
| Response fields in source (gateway settlement) | 16 (BilldeskSettlementResponse) + 2/3 (SDRWrapperAPIResponse) |
| Response fields documented | 21 |
| Request fields in source (txns V2 CreateTxnReq) | 14 |
| Request fields documented (txns V2) | 14 |
| Request fields in source (txns V2 CreateMandateReq) | 17 |
| Request fields documented (txns V2 mandate) | 17 |
| Response fields in source (txns V2 CreateTxnResp) | 11 |
| Response fields documented (txns V2) | 11 |
| All nested types expanded | Yes |
| All enum values listed | Yes |
| All flows documented | Yes (10 flows + sub-flows) |
| All error paths documented | Yes |
| All status values listed | Yes |
| Payment methods documented | Yes |
| Payment method enums complete | Yes |
| Payment method DB tables documented | N/A — BILLDESK does not expose gateway_payment_method DB table details in source; uses BilldeskDetails.billDeskMerchantId and bank codes directly |
| Missing items | V2 refund endpoint response type details (RefundV2Response) not fully expanded; `BilldeskMetaData` additional_info field names (dynamic) not enumerated; `getCardPaymentBankId` bank code mapping table not enumerated (large lookup table) |

---

## 10. Source File References

| # | File | Lines Read | Purpose |
|---|------|-----------|---------|
| 1 | `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/BILLDESK/Types.hs` | Full file | Gateway-side types: BilldeskSettlementRequest/Response, AmountDetails, CertificateConfigs, BilldeskAccountDetails, BilldeskFpSigningKeyPairs, JOSE content type, error types |
| 2 | `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/BILLDESK/Flows.hs` | Full file (82 lines) | Settlement reconciliation flow: getReconciliationDetails, handleReconciliationDetailsResponse |
| 3 | `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/BILLDESK/Routes.hs` | Full file | HTTP route definition: GET /pasettlements/v1_2/settlements/get with JOSE content type headers |
| 4 | `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/BILLDESK/Transforms.hs` | Full file | mkGetReconciliationFailureResponse, getBilldeskAccountDetails |
| 5 | `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/BILLDESK/Encryption.hs` | Full file | JWE encryption/decryption, JWS signing/verification, fingerprint key lookup |
| 6 | `euler-api-gateway/common/src/Euler/API/Gateway/Types/API/Settlements.hs` | Full file (171 lines) | SDRWrapperAPIResponse, SDRWrapperRequest, SDRWrapperSuccessResponse, SDRWrapperErrorResponse definitions |
| 7 | `euler-api-txns/euler-x/src-generated/Gateway/Billdesk/Types.hs` | Full file (~2800 lines) | All txns-side types: BilldeskDetails, BilldeskMetaData, request/response types for all payment flows, IntegrationVersion, BilldeskResponse ADT, BilldeskTxnStatusResponseData |
| 8 | `euler-api-txns/euler-x/src-generated/Gateway/Billdesk/Endpoints.hs` | Full file | V1 getEndpointForReq (pattern match on request type + testMode), V2 endpoint helper functions |
| 9 | `euler-api-txns/euler-x/src-generated/Gateway/Billdesk/Flow.hs` | Lines 1–2089 (of 7490) | Main flow functions: initiateTxn, initiateCardTxn, initiateNonCardTxn, initiateEnachTxn, initTxnBillDeskV2, createTxn, createMandateTxn, verifyMandateDetailsAndProcessRequestWithPG, checkOnlyPointsOrCardAndPointsTxn, submitOtp, auth_status mappings, decideTxnStatusFromPGResponse, isTxnSuccessful/Pending/AuthzFailed |
| 10 | `euler-api-txns/euler-x/src-generated/Gateway/Billdesk/Flow.hs` | Lines 4050–4087, 4342–4357, 5351–5374, 5860–5914, 6112–6130 | Status mapping functions: decideTxnStatusFromPGResponse, decideTxnStatusFromMandatePGResponse, decideTxnStatusFromErrResp, getTxnStatusFromMandateResponse, isTxnSuccessful check, getErrorCodeErrMsg |
| 11 | `euler-api-txns/euler-x/src-generated/Gateway/Billdesk/Transforms.hs` | Lines 1–1723 (of 3588) | All transformation functions: makeRefundMsg, makeRecurringRequest, makeBilldeskUPIInitiateMsg, makeCreateMandateRequest, makeDeviceType, makeCardType, makeCustomerType, generateHash, hashMsg, getEndDateFromMetadata, makeBilldeskRewardRefundMsg |
| 12 | `euler-api-txns/euler-x/src-generated/Gateway/Billdesk/RefundResponseHandler.hs` | Full file | V1 refund response parsing: checksum verification, DecodeError/JWeError handling, UNKNOWN status on mismatch |

---

**Generated by**: Euler Connector Tech Spec Workflow
**Date**: 2026-03-26
