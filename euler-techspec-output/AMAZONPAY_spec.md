# AMAZONPAY — Technical Specification

> **Connector**: AMAZONPAY
> **Direction**: txns→gateway (euler-api-txns → Amazon Pay APIs)
> **Endpoint**: Multiple (see Section 3 — Endpoints per flow)
> **Purpose**: Full Amazon Pay wallet payment gateway integration — supports redirect, S2S direct debit (V1/V2), pre-auth/capture/void, refunds, top-up, wallet linking, balance refresh, eligibility, webhook, and SDK tokenized flows
> **Generated**: 2026-03-26

---

## 1. Connector Overview

### 1.1 Basic Information
- **Connector ID**: AMAZONPAY
- **Direction**: euler-api-txns → Amazon Pay Gateway APIs
- **HTTP Methods**: POST, GET (varies per endpoint)
- **Architecture**: Haskell (Servant + Warp), PureScript backend runtime
- **Protocol**: HTTP REST (synchronous and asynchronous webhook)
- **Content-Type**: `application/json` (most flows); `application/x-www-form-urlencoded` (some GET status flows)
- **Source Module**: `euler-x/src-generated/Gateway/AmazonPay/` in `euler-api-txns`
- **Note**: AMAZONPAY has no connector directory in `euler-api-gateway`; it is implemented entirely within `euler-api-txns` as a direct gateway integration, dispatched from `CommonGateway.hs`.

### 1.2 Base URL Configuration

| Environment | Base URL | Notes |
|-------------|----------|-------|
| Production | `https://amazonpay.amazon.in` | All V1 S2S and V2 PreAuth flows |
| Sandbox | `https://amazonpay-sandbox.amazon.in` | Activated via `testMode = True` from `mga.testMode` |
| OAuth Token | `https://api.amazon.co.uk/auth/o2/token` | Consent token exchange |
| Deeplink (APL EMI) | `https://www.amazon.in/lpa/kux/dl/redirect/initiatePayment` | AmazonPay Later EMI deeplink redirect |
| Legacy Redirect | `https://amazonpay.amazon.in/initiatePayment` | Legacy/redirect initiate |
| V2 payments host | `https://amazonpay.amazon.in` | Prefixed as `v2/payments/` in SDK sign-and-post |

**URL Resolution Logic**: The test mode is read from `mga.testMode` (Boolean). When `testMode = True`, requests are routed to `https://amazonpay-sandbox.amazon.in`. When `testMode = False` (production), requests go to `https://amazonpay.amazon.in`. The sandbox URL is constructed by injecting `-sandbox` into the production hostname. For V2 PreAuth flows, the URL suffix is configured by `AmazonPayEndpoints` enum value and resolved via `getEndpointForReqWithEnv` / `getEndpointForReqAndEnv`.

**Source**: `euler-x/src-generated/Gateway/AmazonPay/Endpoints.hs`, `Types.hs:2007`

**Timeout Configuration**:
- Custom Timeout Header: Not set in standard headers; timeout value encoded in request payload as `transactionTimeout` (S2S V1) or `timeoutInSecs` (V2)
- Per-Merchant Override: Yes — `autoVoidTimeInSec` in `AmazonPayDetails`
- Default Timeout: Not explicitly set globally; per-request payload field

---

## 2. Authentication

### 2.1 Authentication Methods

AMAZONPAY uses **two distinct authentication schemes** depending on the integration version:

#### 2.1.1 Legacy S2S (V1) — HMAC-SHA384 Signature
- **Auth Type**: Custom HMAC-SHA384 signature over request payload
- **Auth Header**: Embedded in request body (`signature` field); additional headers: `merchantId`, `timeStamp`, `attributableProgram: S2S_PAY`
- **Credential Source**: `AmazonPayDetails` decoded from `MerchantGatewayAccount.accountDetails`

#### 2.1.2 V2 PreAuth — AWS-Style AMZ Signature
- **Auth Type**: `Authorization: AMZ {accessKey}:{signature}`
- **Auth Header**: `Authorization: AMZ <accessKey>:<generatedSignature>`
- **Algorithm**: `x-amz-algorithm: AWS4-HMAC-SHA384`
- **Credential Source**: `AmazonPayDetails` (`amazonPayS2SAccessKey`, `amazonPayS2SSecretKey`)

### 2.2 Authentication Flow

#### S2S V1 Flow
1. Extract `AmazonPayDetails` from `MerchantGatewayAccount.accountDetails` (JSON-decoded)
2. Get current timestamp via `getCurrentTimeMillis`
3. Compute HMAC-SHA384 signature over `(secretKey, timeStamp, endpointPath, httpMethod, encodedPayload)`
4. Embed `signature`, `accessKeyId`, `timeStamp`, `merchantId` into request payload
5. Call API endpoint with signed payload

#### V2 PreAuth Flow
1. Extract `AmazonPayDetails` from `MerchantGatewayAccount.accountDetails`
2. Get current UTC timestamp via `getUtcTimeStampFromTimestamp`
3. Build `APayPreAuthHeaders` with `x-amz-*` fields
4. Call `AmazonServerSDK.getSignatureForPreAuthFlow` with headers + payload + utcDate + secretKey + uri + httpMethod + mode + testMode
5. Set `Authorization: AMZ {accessKey}:{signature}` header
6. On response, verify signature via `validateSignature` (re-computes and compares `x-amz-signature`)

### 2.3 Required Headers

#### S2S V1 Headers (embedded in request payload, not HTTP headers)

| # | Header/Field Name | Value / Source | Required | Description |
|---|-------------------|---------------|----------|-------------|
| 1 | `merchantId` | `amazonPayDetails.amazonPaySellerId` | Yes | Merchant seller ID |
| 2 | `accessKeyId` | `amazonPayDetails.amazonPayS2SAccessKey` | Yes | S2S access key |
| 3 | `timeStamp` | current epoch millis | Yes | Request timestamp |
| 4 | `signature` | HMAC-SHA384 computed | Yes | Request signature |
| 5 | `signatureMethod` | `"HmacSHA384"` | Yes | Signature algorithm |
| 6 | `signatureVersion` | `"2"` | Yes | Signature version |
| 7 | `attributableProgram` | `"S2S_PAY"` | Yes | Program identifier |
| 8 | `Content-Type` | `application/json` | Yes | HTTP content type |

#### V2 PreAuth HTTP Headers (`APayPreAuthHeaders`)

| # | Header Name | JSON Key | Value / Source | Required | Description |
|---|-------------|----------|---------------|----------|-------------|
| 1 | `x-amz-client-id` | `__x_45_amz_45_client_45_id` | `amazonPayDetails.amazonPayClientId` | Yes | Client ID |
| 2 | `x-amz-source` | `__x_45_amz_45_source` | `"JUSPAY"` | Yes | Source identifier |
| 3 | `x-amz-user-ip` | `__x_45_amz_45_user_45_ip` | Customer IP address | Yes | User IP |
| 4 | `x-amz-user-agent` | `__x_45_amz_45_user_45_agent` | User-agent string | Yes | User agent |
| 5 | `x-amz-algorithm` | `__x_45_amz_45_algorithm` | `"AWS4-HMAC-SHA384"` | Yes | Algorithm |
| 6 | `x-amz-date` | `__x_45_amz_45_date` | UTC timestamp string | Yes | Request date |
| 7 | `x-amz-expires` | `__x_45_amz_45_expires` | `"900"` | Yes | Expiry in seconds |
| 8 | `Authorization` | — | `AMZ {accessKey}:{sign}` | Yes | AMZ auth header |

**Source**: `euler-x/src-generated/Gateway/AmazonPay/Types.hs:657–665`, `Transforms.hs`

### 2.4 Credential Structure — `AmazonPayDetails`

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `amazonPaySellerId` | Text | Primary merchant seller ID |
| 2 | `amazonPayS2SAccessKey` | Maybe Text | S2S V1 access key |
| 3 | `amazonPayS2SSecretKey` | Maybe Text | S2S V1 secret key |
| 4 | `amazonPayClientId` | Maybe Text | Client ID for V2 PreAuth |
| 5 | `clientSecret` | Maybe Text | OAuth client secret |
| 6 | `integrationV2` | Maybe Text | `"true"` enables V2 PreAuth flows |
| 7 | `amazonPayLaterSellerId` | Maybe Text | AMAZONPAYLATER seller ID |
| 8 | `amazonPayLaterAccessKey` | Maybe Text | AMAZONPAYLATER access key |
| 9 | `amazonPayLaterSecretKey` | Maybe Text | AMAZONPAYLATER secret key |
| 10 | `amazonPayLaterEmiAccessKey` | Maybe Text | APL EMI access key |
| 11 | `amazonPayLaterEmiSecretKey` | Maybe Text | APL EMI secret key |
| 12 | `autoVoidTimeInSec` | Maybe Text | Auto-void timeout override |
| 13 | `shouldCallPreEligibilityForAPL` | Maybe Text | `"true"` to check APL eligibility pre-linking |

---

## 3. Endpoints

### 3.1 All Endpoints

**Source**: `euler-x/src-generated/Gateway/AmazonPay/Endpoints.hs`

| # | Endpoint Enum | HTTP Method | Path | Environment | Purpose |
|---|---------------|-------------|------|-------------|---------|
| 1 | `AmazonPayDirectDebitTxnReq` | POST | `{host}/payment/charge/AMAZON_PAY_BALANCE/v1` | sandbox/prod | S2S V1 direct debit (charge) |
| 2 | `AmazonPayTxnStatusRequest` | GET | `{host}/payment/charge/status/v1` | sandbox/prod | S2S V1 charge status |
| 3 | `AmazonPayRefundInitRequest` | POST | `{host}/payment/refund/v1` | sandbox/prod | S2S V1 refund initiate |
| 4 | `AmazonPayRefundDetailsRequest` | GET | `{host}/payment/refund/status/v1` | sandbox/prod | S2S V1 refund status |
| 5 | `AmazonPayTopUpRequest` | POST | `{host}/payment/topup/v1` | sandbox/prod | S2S V1 top-up |
| 6 | `AmazonPayGetBalanceRequest` | GET | `{host}/customer/CONSENT_TOKEN/{token}/balance/v1` | sandbox/prod | S2S V1 get wallet balance |
| 7 | `AmazonPayChargeReq` | POST (charge), GET (status) | `{host}/v1/payments/charge` | sandbox/prod | V2 PreAuth charge + get status |
| 8 | `AmazonPayPreAuthCaptureReq` | POST | `{host}/v1/payments/capture` | sandbox/prod | V2 PreAuth capture |
| 9 | `AmazonPayPreAuthVoidReq` | POST | `{host}/v1/payments/release` | sandbox/prod | V2 PreAuth void/release |
| 10 | `APayRefreshWallet` | GET | `{host}/v1/payments/instruments` | sandbox/prod | V2 refresh wallet balance |
| 11 | `AplEligiblityRequest` | POST | `{host}/v1/payments/eligibility` | sandbox/prod | APL/EMI eligibility check |
| 12 | `APayRefundInitReq` | POST (init), GET (status) | `{host}/v1/payments/refund` | sandbox/prod | V2 refund init + status |
| 13 | `APayTopUpReq` | POST (topup), GET (status) | `{host}/v1/payments/topup` | sandbox/prod | V2 top-up + top-up status |
| — | Consent Token | POST | `https://api.amazon.co.uk/auth/o2/token` | Always prod | OAuth consent token exchange |
| — | Legacy Redirect | POST | `https://amazonpay.amazon.in/initiatePayment` | prod | SDK redirect initiate |
| — | APL EMI Deeplink | GET | `https://www.amazon.in/lpa/kux/dl/redirect/initiatePayment` | prod | APL EMI deeplink |

**Host resolution**: `testMode=True` → `https://amazonpay-sandbox.amazon.in`; `testMode=False` → `https://amazonpay.amazon.in`

---

## 4. Request Structure

### 4.1 S2S V1 Direct Debit Request — `AmazonPayTxnReqPayload`

**Type**: `AmazonPayTxnReqPayload` — `Types.hs:428`
**Wrapped in**: `AmazonPayRequest` (payload/key/iv) → `AmazonPayTxnReq`
**Endpoint**: `POST /payment/charge/AMAZON_PAY_BALANCE/v1`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `merchantId` | Text | `merchantId` | Yes | Amazon Pay seller ID |
| 2 | `amount` | Maybe Text | `amount` | No | Transaction amount |
| 3 | `currencyCode` | Text | `currencyCode` | Yes | ISO currency code (e.g., `"INR"`) |
| 4 | `merchantReturnToUrl` | Text | `merchantReturnToUrl` | Yes | Redirect URL after payment |
| 5 | `merchantTransactionId` | Text | `merchantTransactionId` | Yes | Juspay transaction ID |
| 6 | `customerIdType` | Text | `customerIdType` | Yes | Type of customer identifier |
| 7 | `customerIdValue` | Text | `customerIdValue` | Yes | Customer identifier value (wallet token) |
| 8 | `signatureMethod` | Text | `signatureMethod` | Yes | `"HmacSHA384"` |
| 9 | `signatureVersion` | Text | `signatureVersion` | Yes | `"2"` |
| 10 | `accessKeyId` | Text | `accessKeyId` | Yes | S2S access key |
| 11 | `timeStamp` | Text | `timeStamp` | Yes | Epoch milliseconds |
| 12 | `signature` | Maybe Text | `signature` | Yes (computed) | HMAC-SHA384 signature |
| 13 | `topUpAmount` | Maybe Text | `topUpAmount` | No | Top-up amount if applicable |
| 14 | `merchantNoteToCustomer` | Maybe Text | `merchantNoteToCustomer` | No | Merchant note to customer |
| 15 | `merchantNote` | Maybe Text | `merchantNote` | No | Internal merchant note |
| 16 | `merchantCustomData` | Maybe Text | `merchantCustomData` | No | Custom data passthrough |
| 17 | `transactionTimeout` | Maybe Text | `transactionTimeout` | No | Transaction timeout in seconds |
| 18 | `sandbox` | Maybe Text | `sandbox` | No | `"true"` for sandbox mode |

**Field Count**: 18 fields

### 4.2 S2S V1 Charge Status Request — `AmazonPayTxnStatusReqPayload`

**Type**: `AmazonPayTxnStatusReqPayload` — `Types.hs:444`
**Endpoint**: `GET /payment/charge/status/v1`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `merchantId` | Text | `merchantId` | Yes | Amazon Pay seller ID |
| 2 | `transactionIdType` | Text | `transactionIdType` | Yes | Type of txn ID (e.g., `"AmazonTransactionId"`) |
| 3 | `transactionId` | Text | `transactionId` | Yes | Transaction ID to query |
| 4 | `signatureMethod` | Text | `signatureMethod` | Yes | `"HmacSHA384"` |
| 5 | `signatureVersion` | Text | `signatureVersion` | Yes | `"2"` |
| 6 | `accessKeyId` | Text | `accessKeyId` | Yes | S2S access key |
| 7 | `timeStamp` | Text | `timeStamp` | Yes | Epoch milliseconds |
| 8 | `signature` | Maybe Text | `signature` | Yes (computed) | HMAC-SHA384 signature |

**Field Count**: 8 fields

### 4.3 S2S V1 Refund Request — `AmazonPayRefundReqPayload`

**Type**: `AmazonPayRefundReqPayload` — `Types.hs:457`
**Endpoint**: `POST /payment/refund/v1`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `merchantId` | Text | `merchantId` | Yes | Amazon Pay seller ID |
| 2 | `amount` | Text | `amount` | Yes | Refund amount |
| 3 | `currencyCode` | Text | `currencyCode` | Yes | ISO currency code |
| 4 | `signatureMethod` | Text | `signatureMethod` | Yes | `"HmacSHA384"` |
| 5 | `signatureVersion` | Text | `signatureVersion` | Yes | `"2"` |
| 6 | `accessKeyId` | Text | `accessKeyId` | Yes | S2S access key |
| 7 | `timeStamp` | Text | `timeStamp` | Yes | Epoch milliseconds |
| 8 | `signature` | Maybe Text | `signature` | Yes (computed) | HMAC-SHA384 signature |
| 9 | `sellerNoteToCustomer` | Maybe Text | `sellerNoteToCustomer` | No | Note to customer |
| 10 | `softDescriptor` | Maybe Text | `softDescriptor` | No | Soft descriptor |
| 11 | `sandbox` | Maybe Text | `sandbox` | No | `"true"` for sandbox mode |
| 12 | `amazonTransactionId` | Text | `amazonTransactionId` | Yes | Amazon transaction ID to refund |
| 13 | `amazonTransactionIdType` | Text | `amazonTransactionIdType` | Yes | Type of Amazon txn ID |
| 14 | `refundReferenceId` | Text | `refundReferenceId` | Yes | Unique refund reference ID |

**Field Count**: 14 fields

### 4.4 V2 PreAuth Charge Request — `AmazonPayChargeRequest`

**Type**: `AmazonPayChargeRequest` — `Types.hs:603`
**Endpoint**: `POST /v1/payments/charge`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `intent` | Text | `intent` | Yes | Payment intent (e.g., `"AUTHORIZE"`, `"AuthorizeWithAutoCapture"`) |
| 2 | `amount` | Text | `amount` | Yes | Payment amount |
| 3 | `currencyCode` | Text | `currencyCode` | Yes | ISO currency code |
| 4 | `callbackUrl` | Text | `callbackUrl` | Yes | Merchant return URL |
| 5 | `accessToken` | Text | `accessToken` | Yes | Customer consent/access token |
| 6 | `chargeId` | Text | `chargeId` | Yes | Juspay txn ID (used as chargeId) |
| 7 | `referenceId` | Text | `referenceId` | Yes | Merchant order/reference ID |
| 8 | `merchantId` | Text | `merchantId` | Yes | Amazon Pay seller ID |
| 9 | `attributableProgram` | Text | `attributableProgram` | Yes | Attribution (e.g., `"JUSPAY"`) |
| 10 | `noteToCustomer` | Maybe Text | `noteToCustomer` | No | Note to customer |
| 11 | `customData` | Maybe Text | `customData` | No | Custom data passthrough |
| 12 | `timeoutInSecs` | Maybe Text | `timeoutInSecs` | No | Payment timeout in seconds |
| 13 | `selectedPaymentInstrumentType` | Text | `selectedPaymentInstrumentType` | Yes | Instrument type (e.g., `"AMAZON_PAY_BALANCE"`) |
| 14 | `paymentMetaData` | Maybe Text | `paymentMetaData` | No | Payment metadata JSON |
| 15 | `sellerStoreName` | Maybe Text | `sellerStoreName` | No | Seller store name |

**Field Count**: 15 fields

### 4.5 V2 PreAuth Capture Request — `AmazonPayPreAuthCaptureRequest`

**Type**: `AmazonPayPreAuthCaptureRequest` — `Types.hs:672`
**Endpoint**: `POST /v1/payments/capture`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `merchantId` | Text | `merchantId` | Yes | Amazon Pay seller ID |
| 2 | `amount` | Text | `amount` | Yes | Capture amount |
| 3 | `currencyCode` | Text | `currencyCode` | Yes | ISO currency code |
| 4 | `chargeIdType` | Text | `chargeIdType` | Yes | Type of charge ID |
| 5 | `chargeId` | Text | `chargeId` | Yes | Charge ID to capture |

**Field Count**: 5 fields

### 4.6 V2 PreAuth Void Request — `AmazonPayPreAuthVoidRequest`

**Type**: `AmazonPayPreAuthVoidRequest` — `Types.hs:681`
**Endpoint**: `POST /v1/payments/release`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `merchantId` | Text | `merchantId` | Yes | Amazon Pay seller ID |
| 2 | `chargeIdType` | Text | `chargeIdType` | Yes | Type of charge ID |
| 3 | `chargeId` | Text | `chargeId` | Yes | Charge ID to void |
| 4 | `noteToCustomer` | Text | `noteToCustomer` | Yes | Reason for void |

**Field Count**: 4 fields

### 4.7 V2 Get Status Request — `APayGetStatusRequest`

**Type**: `APayGetStatusRequest` — `Types.hs:694`
**Endpoint**: `GET /v1/payments/charge`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `merchantId` | Text | `merchantId` | Yes | Amazon Pay seller ID |
| 2 | `txnIdType` | Text | `txnIdType` | Yes | Type of transaction ID |
| 3 | `txnId` | Text | `txnId` | Yes | Transaction ID to check |

**Field Count**: 3 fields

### 4.8 V2 Refund Init Request — `APayRefundInitRequest`

**Type**: `APayRefundInitRequest` — `Types.hs:732`
**Endpoint**: `POST /v1/payments/refund`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `amount` | Text | `amount` | Yes | Refund amount |
| 2 | `chargeId` | Text | `chargeId` | Yes | Charge ID to refund |
| 3 | `chargeIdType` | Text | `chargeIdType` | Yes | Type of charge ID |
| 4 | `currencyCode` | Text | `currencyCode` | Yes | ISO currency code |
| 5 | `merchantId` | Text | `merchantId` | Yes | Amazon Pay seller ID |
| 6 | `noteToCustomer` | Maybe Text | `noteToCustomer` | No | Note to customer |
| 7 | `refundId` | Text | `refundId` | Yes | Unique refund reference ID |
| 8 | `softDescriptor` | Text | `softDescriptor` | Yes | Soft descriptor |

**Field Count**: 8 fields

### 4.9 V2 Top-Up Request — `APayTopupRequest`

**Type**: `APayTopupRequest` — `Types.hs:768`
**Endpoint**: `POST /v1/payments/topup`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `accessToken` | Text | `accessToken` | Yes | Customer consent token |
| 2 | `amount` | Text | `amount` | Yes | Top-up amount |
| 3 | `attributableProgram` | Text | `attributableProgram` | Yes | Attribution identifier |
| 4 | `callbackUrl` | Text | `callbackUrl` | Yes | Callback URL |
| 5 | `chargeId` | Text | `chargeId` | Yes | Charge/transaction ID |
| 6 | `currencyCode` | Text | `currencyCode` | Yes | ISO currency code |
| 7 | `merchantId` | Text | `merchantId` | Yes | Amazon Pay seller ID |
| 8 | `referenceId` | Text | `referenceId` | Yes | Reference ID |
| 9 | `customData` | Maybe Text | `customData` | No | Custom data |
| 10 | `noteToCustomer` | Maybe Text | `noteToCustomer` | No | Note to customer |
| 11 | `timeoutInSecs` | Maybe Text | `timeoutInSecs` | No | Timeout in seconds |

**Field Count**: 11 fields

### 4.10 V2 Refresh Wallet Balance Request — `APayRefreshWalletRequest`

**Type**: `APayRefreshWalletRequest` — `Types.hs:800`
**Endpoint**: `GET /v1/payments/instruments`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `merchantId` | Text | `merchantId` | Yes | Amazon Pay seller ID |
| 2 | `accessToken` | Text | `accessToken` | Yes | Customer consent/access token |
| 3 | `amount` | Maybe Text | `amount` | No | Amount for eligibility check |
| 4 | `instrumentTypes` | Text | `instrumentTypes` | Yes | Instrument types to query |

**Field Count**: 4 fields

### 4.11 Consent Token Request — `AmazonPayConsentTokenReq`

**Type**: `AmazonPayConsentTokenReq` — `Types.hs:287`
**Endpoint**: `POST https://api.amazon.co.uk/auth/o2/token`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `grant_type` | Text | `grant_type` | Yes | OAuth grant type (`"authorization_code"` or `"refresh_token"`) |
| 2 | `code` | Maybe Text | `code` | Cond. | Authorization code (for `authorization_code` grant) |
| 3 | `refresh_token` | Maybe Text | `refresh_token` | Cond. | Refresh token (for `refresh_token` grant) |
| 4 | `client_id` | Text | `client_id` | Yes | OAuth client ID |
| 5 | `code_verifier` | Maybe Text | `code_verifier` | No | PKCE code verifier |
| 6 | `client_secret` | Maybe Text | `client_secret` | No | OAuth client secret |
| 7 | `redirect_uri` | Maybe Text | `redirect_uri` | No | OAuth redirect URI |

**Field Count**: 7 fields

### 4.12 APL Eligibility Request — `APayEmiEligibilityRequest`

**Type**: `APayEmiEligibilityRequest` — `Types.hs:810`
**Endpoint**: `POST /v1/payments/eligibility`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `merchantId` | Text | `merchantId` | Yes | Amazon Pay seller ID |
| 2 | `phoneNumber` | Text | `phoneNumber` | Yes | Customer phone number |
| 3 | `amount` | Text | `amount` | Yes | Transaction amount |
| 4 | `instrumentType` | Text | `instrumentType` | Yes | Instrument type (e.g., `"AmazonPayLater"`) |

**Field Count**: 4 fields

---

## 5. Response Structure

### 5.1 S2S V1 Direct Debit Response — `AmazonPayDirectDebitTxnResp`

**Type**: `AmazonPayDirectDebitTxnResp` — `Types.hs:437`
**Wrapped in**: `AmazonPayDirectDebitTxnResponse` → `GetAmazonPayTxnResp`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `currencyCode` | Text | `currencyCode` | Yes | ISO currency code |
| 2 | `amount` | Text | `amount` | Yes | Transaction amount |
| 3 | `signature` | Maybe Text | `signature` | No | Response signature |
| 4 | `amazonTransactionId` | Text | `amazonTransactionId` | Yes | Amazon's transaction ID |
| 5 | `timeStamp` | Text | `timeStamp` | Yes | Response timestamp |
| 6 | `merchantTransactionId` | Text | `merchantTransactionId` | Yes | Juspay txn ID (echoed back) |
| 7 | `status` | Text | `status` | Yes | Transaction status |
| 8 | `lookAheadToken` | Text | `lookAheadToken` | Yes | Look-ahead token |
| 9 | `payURL` | Maybe Text | `payURL` | No | Payment URL if redirect needed |
| 10 | `merchantCustomData` | Maybe Text | `merchantCustomData` | No | Custom data echoed back |

**Field Count**: 10 fields

### 5.2 S2S V1 Transaction Status Response — `AmazonPayTransactionStatusResp`

**Type**: `AmazonPayTransactionStatusResp` — `Types.hs:450`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `currencyCode` | Text | `currencyCode` | Yes | ISO currency code |
| 2 | `amount` | Text | `amount` | Yes | Transaction amount |
| 3 | `amazonTransactionId` | Text | `amazonTransactionId` | Yes | Amazon transaction ID |
| 4 | `timeStamp` | Text | `timeStamp` | Yes | Response timestamp |
| 5 | `merchantTransactionId` | Text | `merchantTransactionId` | Yes | Juspay txn ID |
| 6 | `status` | Text | `status` | Yes | `"SUCCESS"`, `"PENDING"`, `"FAILURE"` |
| 7 | `reasonCode` | Maybe Text | `reasonCode` | No | Reason code |
| 8 | `reasonCodeDescription` | Maybe Text | `reasonCodeDescription` | No | Reason description |

**Field Count**: 8 fields

### 5.3 S2S V1 Refund Response — `AmazonPayRefundDetailsResponse`

**Type**: `AmazonPayRefundDetailsResponse` — `Types.hs:466`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `refundReferenceId` | Text | `refundReferenceId` | Yes | Refund reference ID |
| 2 | `refundType` | Text | `refundType` | Yes | Type of refund |
| 3 | `sellerNoteToCustomer` | Maybe Text | `sellerNoteToCustomer` | No | Note to customer |
| 4 | `creationTimestamp` | Number | `creationTimestamp` | Yes | Refund creation time |
| 5 | `softDescriptor` | Maybe Text | `softDescriptor` | No | Soft descriptor |
| 6 | `status` | Text | `status` | Yes | Refund status |
| 7 | `lastUpdateTimestamp` | Number | `lastUpdateTimestamp` | Yes | Last update time |
| 8 | `feeRefunded` | FeeRefunded | `feeRefunded` | Yes | Fee refunded amount/currency |
| 9 | `refundAmount` | FeeRefunded | `refundAmount` | Yes | Refund amount/currency |
| 10 | `amazonRefundId` | Maybe Text | `amazonRefundId` | No | Amazon refund ID |
| 11 | `timeStamp` | Number | `timeStamp` | Yes | Timestamp |
| 12 | `reasonCode` | Maybe Text | `reasonCode` | No | Reason code |
| 13 | `reasonCodeDescription` | Maybe Text | `reasonCodeDescription` | No | Reason description |

**Field Count**: 13 fields

### 5.4 V2 PreAuth Charge Response — `APayPreAuthValidChargeResp`

**Type**: `APayPreAuthValidChargeResp` — `Types.hs:641`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `merchantId` | Text | `merchantId` | Yes | Amazon Pay seller ID |
| 2 | `chargeId` | Text | `chargeId` | Yes | Charge ID (Juspay txn ID) |
| 3 | `amazonChargeId` | Text | `amazonChargeId` | Yes | Amazon-assigned charge ID |
| 4 | `requestedAmount` | Text | `requestedAmount` | Yes | Requested amount |
| 5 | `approvedAmount` | Text | `approvedAmount` | Yes | Approved amount |
| 6 | `currencyCode` | Text | `currencyCode` | Yes | ISO currency code |
| 7 | `status` | Text | `status` | Yes | Charge status (e.g., `"AuthApproved"`, `"CaptureApproved"`) |
| 8 | `amazonPayUrl` | Maybe Text | `amazonPayUrl` | No | Redirect URL if pending |
| 9 | `customData` | Maybe Text | `customData` | No | Custom data |
| 10 | `createTime` | Text | `createTime` | Yes | Creation timestamp |
| 11 | `updateTime` | Text | `updateTime` | Yes | Last update timestamp |

**Field Count**: 11 fields

### 5.5 V2 Capture Response — `AmazonPayPreAuthCaptureResponse`

**Type**: `AmazonPayPreAuthCaptureResponse` — `Types.hs:676`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `merchantId` | Text | `merchantId` | Yes | Amazon Pay seller ID |
| 2 | `chargeId` | Text | `chargeId` | Yes | Charge ID |
| 3 | `amazonChargeId` | Text | `amazonChargeId` | Yes | Amazon-assigned charge ID |
| 4 | `requestedAmount` | Text | `requestedAmount` | Yes | Requested capture amount |
| 5 | `approvedAmount` | Text | `approvedAmount` | Yes | Approved capture amount |
| 6 | `currencyCode` | Text | `currencyCode` | Yes | ISO currency code |
| 7 | `status` | Text | `status` | Yes | `"CaptureApproved"`, `"CapturePending"`, `"Declined"` |
| 8 | `customData` | Maybe Text | `customData` | No | Custom data |
| 9 | `createTime` | Text | `createTime` | Yes | Creation timestamp |
| 10 | `updateTime` | Text | `updateTime` | Yes | Last update timestamp |

**Field Count**: 10 fields

### 5.6 V2 Void Response — `AmazonPayPreAuthVoidResponse`

**Type**: `AmazonPayPreAuthVoidResponse` — `Types.hs:689`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `merchantId` | Text | `merchantId` | Yes | Amazon Pay seller ID |
| 2 | `chargeId` | Text | `chargeId` | Yes | Charge ID |
| 3 | `amazonChargeId` | Text | `amazonChargeId` | Yes | Amazon-assigned charge ID |
| 4 | `currencyCode` | Text | `currencyCode` | Yes | ISO currency code |
| 5 | `status` | Text | `status` | Yes | `"Approved"`, `"Pending"`, `"Declined"` |
| 6 | `createTime` | Text | `createTime` | Yes | Creation timestamp |
| 7 | `updateTime` | Text | `updateTime` | Yes | Last update timestamp |
| 8 | `amount` | Text | `amount` | Yes | Transaction amount |

**Field Count**: 8 fields

### 5.7 V2 Refund Response — `APayRefundInitResponse`

**Type**: `APayRefundInitResponse` — `Types.hs:751`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `amazonRefundId` | Text | `amazonRefundId` | Yes | Amazon-assigned refund ID |
| 2 | `amount` | Text | `amount` | Yes | Refunded amount |
| 3 | `createTime` | Text | `createTime` | Yes | Refund creation time |
| 4 | `currencyCode` | Text | `currencyCode` | Yes | ISO currency code |
| 5 | `refundedFee` | Text | `refundedFee` | Yes | Refunded fee amount |
| 6 | `refundId` | Text | `refundId` | Yes | Juspay refund reference ID |
| 7 | `status` | Text | `status` | Yes | Refund status |
| 8 | `updateTime` | Maybe Text | `updateTime` | No | Last update time |

**Field Count**: 8 fields

### 5.8 Consent Token Response — `AmazonPayConsentTokenValidResp`

**Type**: `AmazonPayConsentTokenValidResp` — `Types.hs:298`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `access_token` | Text | `access_token` | Yes | OAuth access/consent token |
| 2 | `token_type` | Maybe Text | `token_type` | No | Token type (e.g., `"bearer"`) |
| 3 | `expires_in` | Number | `expires_in` | Yes | Token expiry in seconds |
| 4 | `refresh_token` | Maybe Text | `refresh_token` | No | OAuth refresh token |

**Field Count**: 4 fields

### 5.9 Webhook Response — `ChargeTransactionDetailsValue`

**Type**: `ChargeTransactionDetailsValue` — `Types.hs:574`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `_OrderID` | Text | `_OrderID` | Yes | Amazon order ID |
| 2 | `_SellerReferenceId` | Text | `_SellerReferenceId` | Yes | Juspay txn ID (used for lookup) |
| 3 | `_Amount` | OrderTotalValue | `_Amount` | Yes | Transaction amount + currency |
| 4 | `_TotalFee` | OrderTotalValue | `_TotalFee` | Yes | Total fee amount + currency |
| 5 | `_PaymentModes` | PaymentModesId | `_PaymentModes` | Yes | Payment mode ID |
| 6 | `_FeeBreakup` | FeeBreakupValue | `_FeeBreakup` | Yes | Fee breakdown |
| 7 | `_CreationTimestamp` | Text | `_CreationTimestamp` | Yes | Creation timestamp |
| 8 | `_Status` | RefundStatusValue | `_Status` | Yes | Transaction status object |

**Field Count**: 8 fields

### 5.10 Nested Response Types

#### `FeeRefunded` — `Types.hs:469`
Used in: `AmazonPayRefundDetailsResponse.feeRefunded`, `.refundAmount`

| # | Field | Type | JSON Key | Description |
|---|-------|------|----------|-------------|
| 1 | `amount` | Text | `amount` | Amount value |
| 2 | `currencyCode` | Text | `currencyCode` | ISO currency code |

#### `OrderTotalValue` — `Types.hs:407`
Used in: `OrderReferenceValue`, `ChargeTransactionDetailsValue`, `RefundDetailValue`

| # | Field | Type | JSON Key | Description |
|---|-------|------|----------|-------------|
| 1 | `_CurrencyCode` | Text | `_CurrencyCode` | ISO currency code |
| 2 | `_Amount` | Text | `_Amount` | Amount string |

#### `RefundStatusValue` — `Types.hs:586`
Used in: `ChargeTransactionDetailsValue._Status`

| # | Field | Type | JSON Key | Description |
|---|-------|------|----------|-------------|
| 1 | `_LastUpdateTimestamp` | Text | `_LastUpdateTimestamp` | Last update time |
| 2 | `_State` | Text | `_State` | Status state string |
| 3 | `_ReasonDescription` | Maybe Text | `_ReasonDescription` | Reason description |
| 4 | `_ReasonCode` | Maybe Text | `_ReasonCode` | Reason code |

#### `APayPreAuthHeaders` — `Types.hs:657`
Used in: V2 PreAuth HTTP request headers

| # | Field | JSON Key (wire header name) | Description |
|---|-------|-----------------------------|-------------|
| 1 | `__x_45_amz_45_client_45_id` | `x-amz-client-id` | OAuth client ID |
| 2 | `__x_45_amz_45_source` | `x-amz-source` | Source system |
| 3 | `__x_45_amz_45_user_45_ip` | `x-amz-user-ip` | Customer IP |
| 4 | `__x_45_amz_45_user_45_agent` | `x-amz-user-agent` | User agent |
| 5 | `__x_45_amz_45_algorithm` | `x-amz-algorithm` | `"AWS4-HMAC-SHA384"` |
| 6 | `__x_45_amz_45_date` | `x-amz-date` | UTC date string |
| 7 | `__x_45_amz_45_expires` | `x-amz-expires` | `"900"` |

---

## 6. Flows

### 6.1 Flow: `initiateTxn` — Redirect / SDK Initiate

**File**: `euler-x/src-generated/Gateway/AmazonPay/Flow.hs` (early lines)
**Purpose**: Initiates an Amazon Pay transaction by building SDK parameters or a redirect URL for the customer
**Trigger**: Called when a transaction is created and the gateway is AMAZONPAY (WALLET, redirect mode)

#### Steps

| Step | Action | Details |
|------|--------|---------|
| 1 | Decode `AmazonPayDetails` from `mga.accountDetails` | Extract credentials |
| 2 | Build `AmazonPayTxnRequest` with order details | `sellerOrderId`, `orderTotalAmount`, `currencyCode`, `isSandbox`, `sellerNote` |
| 3 | Call `APL.getConfig` to build SDK config | Merchant config for AmazonServerSDK |
| 4 | Call `AmazonServerSDK.getPaymentURL` (legacy) or build SDK params | Returns redirect URL to `https://amazonpay.amazon.in/initiatePayment` |
| 5 | Return `HandleResponseRedirectResp` with URL | Redirect customer to Amazon Pay |

#### Decision Points

| # | Condition | YES Branch | NO Branch |
|---|-----------|-----------|-----------|
| 1 | `isAplEmiFlow` (AMAZONPAYLATER_EMI paymentMethod) | Use deeplink URL (`amazon.in/lpa/kux/dl/redirect/initiatePayment`) | Use standard initiate URL |
| 2 | S2S access key exists in `AmazonPayDetails` | Use S2S direct debit flow | Use SDK redirect flow |
| 3 | `integrationV2 = "true"` | Use V2 PreAuth `callV2WalletFlows` | Use S2S V1 `directDebit` |

```
initiateTxn
   │
   ├─ isAplEmiFlow? ──YES──► deeplink redirect URL (APL EMI)
   │
   ├─ s2sAccessKeyExists? ──YES──► directDebit flow
   │                               │
   │                               ├─ isV2? ──YES──► callV2WalletFlows
   │                               └──────── NO───► S2S V1 directDebit
   │
   └── NO ──► SDK getPaymentURL ──► redirect customer
```

---

### 6.2 Flow: `directDebit` — S2S Direct Debit

**File**: `euler-x/src-generated/Gateway/AmazonPay/Flow.hs`
**Purpose**: Server-to-server direct debit from customer's Amazon Pay wallet
**Trigger**: When merchant has S2S credentials and customer has linked wallet (consent token available)

#### Steps

| Step | Action | Function | File | Details |
|------|--------|----------|------|---------|
| 1 | Get consent token | `getWalletToken` | `Flow.hs` | From Redis cache or fresh fetch |
| 2 | Decode `AmazonPayDetails` | `getAmazonPayDetails` | `Flow.hs` | From `mga.accountDetails` |
| 3 | Build request payload | `makeAmazonPayTxnReqPayload` | `Transforms.hs` | 18-field S2S V1 payload |
| 4 | Compute HMAC-SHA384 signature | `verifyAmazonPaySignature` | `Transforms.hs` | Signed over payload |
| 5 | Wrap in `AmazonPayRequest` | `makeAmazonPayRequest` | `Shims.hs` | AES-encrypted payload + key + iv |
| 6 | POST to `/payment/charge/AMAZON_PAY_BALANCE/v1` | `initAmazonPayTxnRequest` | `Transforms.hs` | HTTP call |
| 7 | Decode `GetAmazonPayTxnResp` | — | — | Parse response |
| 8 | Map status → `TxnStatus` | `getTxnStatus` | `Flow.hs` | SUCCESS→CHARGED, PENDING→PENDING_VBV, FAILURE→AUTHENTICATION_FAILED |
| 9 | Verify integrity | `verifyResponseIntegrity` | `Flow.hs` | Hash check + amount/txnId validation |

---

### 6.3 Flow: `callV2WalletFlows` — V2 PreAuth Charge

**File**: `euler-x/src-generated/Gateway/AmazonPay/Flow.hs:2429`
**Purpose**: V2 PreAuth wallet charge using AMZ-signed API
**Trigger**: When `integrationV2 = "true"` and customer has linked wallet

#### Steps

| Step | Action | Function | File | Details |
|------|--------|----------|------|---------|
| 1 | Get consent token | `getWalletToken` | `Flow.hs` | From Redis or error if missing |
| 2 | Build charge payload | `makeAPayChargePayload` | `Transforms.hs` | `AmazonPayChargeRequest` (15 fields) |
| 3 | Get UTC timestamp | `getUtcTimeStampFromTimestamp` | `Flow.hs` | For AMZ date header |
| 4 | Build PreAuth headers | `makeAPayPreAuthHeaders` | `Transforms.hs` | `APayPreAuthHeaders` (7 fields) |
| 5 | Compute AMZ signature | `AmazonServerSDK.getSignatureForPreAuthFlow` | SDK | Over headers + payload + date + secret |
| 6 | POST to `/v1/payments/charge` | `initAPayPreAuthTxnRequest` | `Transforms.hs` | With `Authorization: AMZ {key}:{sign}` |
| 7 | Verify response signature | `validateSignature` | `Flow.hs:2507` | Re-compute + compare `x-amz-signature` |
| 8 | Handle response variant | — | `Flow.hs:2454` | ValidResponse / PendingResponse / ErrorResponse |

#### Decision Points

| # | Condition | YES Branch | NO Branch |
|---|-----------|-----------|-----------|
| 1 | Consent token present | Proceed with charge | Return `MISSING_ACCESS_TOKEN` error |
| 2 | `ValidResponse` returned | Mark AUTHORIZED/CHARGED, verify sig | — |
| 3 | `PendingResponse` with `CapturePending` status | Build SDK params for insufficient-balance redirect | `AUTHORIZATION_FAILED` |
| 4 | `ErrorResponse` | `AUTHENTICATION_FAILED` | — |
| 5 | Signature verified | Return success | Return `AUTHORIZATION_FAILED` |
| 6 | `paymentMethod == AMAZONPAYLATER` AND pre-auth txn type | Decline (not valid call) | Proceed |

---

### 6.4 Flow: `initiateCaptureRequest` — V2 PreAuth Capture

**File**: `euler-x/src-generated/Gateway/AmazonPay/Flow.hs:2516`
**Purpose**: Capture a previously authorized V2 PreAuth transaction
**Trigger**: Post-auth capture initiated by order management system

#### Steps

| Step | Action | Function | File | Details |
|------|--------|----------|------|---------|
| 1 | Get amount for capture | `getTxnAmountForCapture` | `Flow.hs:2553` | Partial capture uses `txnAmount`; full capture uses order amount |
| 2 | Get charge ID | `getTxnIdForCapture` | `Flow.hs:2593` | From `txn.sourceObjectId` (partial) or `txn.txnId` |
| 3 | Build capture payload | `makeAPayPreAuthCaptureRequest` | `Transforms.hs` | 5-field request |
| 4 | Build headers + sign | `makeAPayPreAuthHeaders` + `getSignatureForPreAuthFlow` | `Transforms.hs` / SDK | AMZ signature |
| 5 | POST to `/v1/payments/capture` | `initAPayCaptureRequest` | `Transforms.hs` | HTTP call |
| 6 | Verify response signature | `validateSignature` | `Flow.hs:2507` | Compare `x-amz-signature` |
| 7 | Map status | `getTxnStatusAndPgrInfoForCapture` | `Flow.hs:2616` | CaptureApproved→CHARGED, CapturePending→CAPTURE_INITIATED, Declined→CAPTURE_FAILED |

---

### 6.5 Flow: `initiateVoidRequest` — V2 PreAuth Void

**File**: `euler-x/src-generated/Gateway/AmazonPay/Flow.hs:2636`
**Purpose**: Void a previously authorized V2 PreAuth transaction
**Trigger**: Merchant cancels an authorized order

#### Steps

| Step | Action | Function | File | Details |
|------|--------|----------|------|---------|
| 1 | Build void payload | `makeAPayPreAuthVoidRequest` | `Transforms.hs` | 4-field request |
| 2 | Build headers + sign | `makeAPayPreAuthHeaders` + `getSignatureForPreAuthFlow` | `Transforms.hs` / SDK | AMZ signature |
| 3 | POST to `/v1/payments/release` | `initAPayPreAuthVoidRequest` | `Transforms.hs` | HTTP call |
| 4 | Verify response signature | `validateSignature` | `Flow.hs:2507` | Compare `x-amz-signature` |
| 5 | Handle failure | `retryVoidApi` | `Flow.hs:2666` | One retry on API/socket errors |
| 6 | Map status | `getTxnStatusAndPgrInfoForVoid` | `Flow.hs:2715` | Approved→VOIDED, Pending→VOID_INITIATED, Declined→VOID_FAILED |

#### Decision Points

| # | Condition | YES Branch | NO Branch |
|---|-----------|-----------|-----------|
| 1 | Signature verified | Return `AMAZONPAYVoid` response | Retry void API |
| 2 | API/Socket error | Retry void | On payload error: `VOID_INITIATED` (soft fail) |
| 3 | Retry also fails with sig error | `VOID_INITIATED` | — |

---

### 6.6 Flow: `initAmazonPayRefundRequestW` — Refund Execution

**File**: `euler-x/src-generated/Gateway/AmazonPay/Flow.hs`
**Purpose**: Execute a refund for a completed Amazon Pay transaction
**Trigger**: Refund request from merchant/system

#### Sub-flows by integration type

| Integration | Refund Method | Endpoint |
|-------------|--------------|---------|
| V2 PreAuth | `APayRefundInitRequest` (8 fields) | `POST /v1/payments/refund` |
| S2S V1 | `AmazonPayRefundReqPayload` (14 fields) | `POST /payment/refund/v1` |
| SDK | `AmazonPaySDKRefundRequest` (5 fields) | SDK call via `AmazonServerSDK` |

**Steps (V2)**:
1. Build `APayRefundInitRequest` from txn details
2. Build AMZ headers + signature
3. POST to `/v1/payments/refund`
4. Verify response signature
5. Map response to refund status

---

### 6.7 Flow: `syncWithGateway` / `amazonPayTxnSync` — Transaction Status Sync

**File**: `euler-x/src-generated/Gateway/AmazonPay/Flow.hs:1851–1953`
**Purpose**: Sync transaction status with Amazon Pay gateway
**Trigger**: Periodic sync job or explicit status check

#### Steps

| Step | Action | Function | File | Details |
|------|--------|----------|------|---------|
| 1 | Check if S2S credentials exist | `s2sAccessKeyExists` | `Flow.hs:1876` | Determines sync path |
| 2 | Check if APL EMI flow | `isAmazonpaylaterEmiPm` | `Flow.hs:2902` | Affects sync path |
| 3a | (S2S path) Build status request | `makeAmazonPayTxnStatusReqPayload` | `Transforms.hs` | 8-field status request |
| 3b | (SDK path) Build list order request | `makeAmazonPayListOrderStatusRequest` | `Transforms.hs` | Start/end time range query |
| 4 | Call status API | `initAmazonPayTxnStatusRequest` / `AmazonServerSDK.listOrderReference` | `Transforms.hs` | HTTP GET |
| 5 | Decode and update gateway txn data | `updateGatewayTxnDataInState` | `Flow.hs:1996` | Writes to local state |

---

### 6.8 Flow: `getWalletToken` — Consent Token Management

**File**: `euler-x/src-generated/Gateway/AmazonPay/Flow.hs`
**Purpose**: Obtain and cache the customer's Amazon Pay consent/access token
**Trigger**: Before any direct debit or V2 wallet call

#### Steps

1. Check Redis cache for existing token
2. If cached and valid → return cached token
3. If expired → call `refreshConsentToken` → POST to `https://api.amazon.co.uk/auth/o2/token` with `grant_type=refresh_token`
4. If not cached → call consent token exchange with `grant_type=authorization_code`
5. Cache new token in Redis with TTL based on `expires_in`
6. On `invalid_grant` error → delink wallet (`removeWalletLinkDetails`)
7. On other errors → remove payment methods from wallet

---

### 6.9 Flow: `refreshWalletBalance` / `decideEligibility`

**File**: `euler-x/src-generated/Gateway/AmazonPay/Flow.hs:2905`
**Purpose**: Check wallet balance or APL eligibility before presenting payment option
**Trigger**: Pre-payment eligibility/balance check

#### Eligibility Decision Logic

| Payment Method | Condition | Flow |
|---------------|-----------|------|
| `AMAZONPAYLATER` (wallet linked) | Has consent token | GET `/v1/payments/instruments` with `instrumentTypes=AmazonPayLater` |
| `AMAZONPAYLATER` (not linked) | `shouldCallPreEligibilityForAPL=true` | POST `/v1/payments/eligibility` with customer phone |
| `AMAZONPAYLATER` (not linked) | default | Return `linking_required` |
| `AMAZONPAYLATER_EMI` | — | POST `/v1/payments/eligibility` check |

---

### 6.10 Flow: `extractWebhookResponse` / `verifyWebhookResponse` — Webhook Handling

**File**: `euler-x/src-generated/Gateway/AmazonPay/Flow.hs:2344–2427`
**Purpose**: Process incoming Amazon Pay webhook notifications
**Trigger**: Amazon Pay pushes webhook event to `/pay_response/AMAZONPAY` or `/pay_response_v3/AMAZONPAY`

#### Steps

| Step | Action | Function | File | Details |
|------|--------|----------|------|---------|
| 1 | Verify webhook authenticity | `AmazonServerSDK.verifyAmazonWebhookResponse` | SDK | SNS-signature verification |
| 2 | Log decrypted webhook | `EWL.logDecryptedRequest "AMAZONPAY_INCOMING_WEBHOOK"` | `Flow.hs:2348` | Audit log |
| 3 | Decode as `AmazonPayWebhookResponseMessage` | — | `Flow.hs:2350` | Parse XML-derived JSON |
| 4 | Extract `ChargeTransactionDetailsValue` | — | `Flow.hs:2351` | Transaction details |
| 5 | Extract `_SellerReferenceId` | `extractTxnDetailIdFromWebhookResponse` | `Flow.hs:2363` | Juspay txn ID |
| 6 | Check `_Status._State == "Completed"` | — | `Flow.hs:2369` | Success indicator |
| 7 | Verify response integrity | `verifyWebhookResponse` | `Flow.hs:2381` | Hash + amount check |
| 8 | Update gateway txn data | `updateGatewayTxnDataWithWebhookResponse` | `Flow.hs:2405` | Persist status |

---

### 6.11 Flow: `getEncryptedPayloadAmazonTokenized` — Tokenized SDK Flow

**File**: `euler-x/src-generated/Gateway/AmazonPay/Flow.hs:2329`
**Purpose**: Generate encrypted payload for EC SDK tokenized charge status
**Trigger**: EC SDK calls for charge status with tokenized flow

#### Steps

1. Get `AmazonPayDetails` and build SDK config
2. Build `AmazonPayGetChargeStatusTokenizedFlowRequest` (3 fields: `transactionId`, `transactionIdType`, `operationName`)
3. Call `AmazonServerSDK.generateSignatureAndEncrypt` with timestamp + config + request
4. Return `ChargeStatusTokenizedFlowSuccResp {status, payload}` on success or `ChargeStatusTokenizedFlowErrResp {status, message}` on failure

---

### 6.12 Data Transformations

| # | From | To | Function | File | Logic |
|---|------|----|----------|------|-------|
| 1 | `TxnDetail` + `OrderReference` | `AmazonPayTxnReqPayload` | `makeAmazonPayTxnReqPayload` | `Transforms.hs` | Builds 18-field S2S V1 direct debit payload |
| 2 | Raw payload + merchant details | `AmazonPayRequest` | `makeAmazonPayRequest` | `Shims.hs` | AES-encrypts payload into `{payload, key, iv}` envelope |
| 3 | `TxnDetail` + `AmazonPayDetails` | `AmazonPayChargeRequest` | `makeAPayChargePayload` | `Transforms.hs` | Builds 15-field V2 charge request |
| 4 | `AmazonPayDetails` + `TxnDetail` | `AmazonPayPreAuthCaptureRequest` | `makeAPayPreAuthCaptureRequest` | `Transforms.hs` | Builds 5-field capture request |
| 5 | `AmazonPayDetails` + `TxnDetail` | `AmazonPayPreAuthVoidRequest` | `makeAPayPreAuthVoidRequest` | `Transforms.hs` | Builds 4-field void request |
| 6 | `TxnCardInfo` + `AmazonPayDetails` | Secret key selection | `Transforms.getSecretKey` | `Transforms.hs` | Routes to `amazonPayLaterSecretKey`, `amazonPayLaterEmiSecretKey`, or `amazonPayS2SSecretKey` based on payment method |
| 7 | `TxnCardInfo` + `AmazonPayDetails` | Seller ID selection | `Transforms.getSellerIdBasedOnPM` | `Transforms.hs` | Routes to APL or EMI or main seller ID |
| 8 | Gateway status text | `TxnStatus` | `getTxnStatus` / `getDirectDebitTxnStatus` | `Flow.hs:1817–1849` | Status mapping (see Section 7) |
| 9 | `AmazonPayTransactionResponse` | `PgInfoWithGwInfoParams` | `getPGRInfo` | `Flow.hs:1766` | Builds PGR for storage |
| 10 | `Number` amount | `Text` amount | `roundOff2Str` / `getAmountWithCustomOptions` | `Flow.hs` | Money framework-aware rounding |

---

## 7. Error Handling

### 7.1 API Call Error Handling

| # | Error Type | Handling | Fallback | File |
|---|-----------|----------|----------|------|
| 1 | `HTTP_4XX` (V2 charge) | Decode as `ErrorPayload`, extract `userMessage`, call `handleDirectDebitFailureResponse` | `AUTHENTICATION_FAILED` or redirect | `Flow.hs:2476` |
| 2 | `HTTP_401` | Treated as generic API error, fall to failure handling | — | `Transforms.hs` |
| 3 | `HTTP_5XX` | Logged as gateway error, return failure | `AUTHORIZATION_FAILED` | `Transforms.hs` |
| 4 | `HTTP_504` / timeout | Logged, propagated as left error | `VOID_INITIATED` on void; `CAPTURE_INITIATED` on capture | `Flow.hs` |
| 5 | `HTTP_503` | Treated as server error | — | `Transforms.hs` |
| 6 | `HTTP_429` | Rate-limit; treated as API error | — | `Transforms.hs` |
| 7 | Socket error | `Socket socketError` → failure response | `VOID_INITIATED` (void), redirect (charge) | `Flow.hs:2487, 2648` |
| 8 | Payload decode error | `Payload payload` → failure response | `VOID_INITIATED` (void) | `Flow.hs:2489, 2649` |
| 9 | Signature verification failure | Logged as `SIGNATURE_VALIDATION_ERROR`/`INTEGRITY_ERROR` | Retry (void) or `AUTHORIZATION_FAILED` (charge) | `Flow.hs:2460, 2975` |
| 10 | Missing consent token | `txnValidationErrorResp` with `MISSING_ACCESS_TOKEN` | Error response to merchant | `Flow.hs:2434` |
| 11 | Consent token `invalid_grant` | Delink wallet: `removeWalletLinkDetails` | — | `Flow.hs` |
| 12 | Refund decode error | `handleAPayLeftCase` / `makeRefundAsFailure` | FAILURE refund status | `Flow.hs` |
| 13 | Webhook decode error | `WEBHOOK_DECODE_ERROR` thrown, 400/500 returned | — | `Flow.hs:2354,2378` |
| 14 | TxnId not found in response | `defaultInvalidThrowECException TRANSACTION_ID_NOT_FOUND` | — | `Flow.hs:1763` |
| 15 | PG response decode error | `defaultThrowECException PG_RESPONSE_DECODE_ERROR` | — | `Flow.hs:2198` |

### 7.2 HTTP Status Code Handling

| HTTP Status | Handling | Response to Caller |
|-------------|----------|--------------------|
| 200 | Parse response body, verify signature | Mapped TxnStatus + PGR info |
| 400 | Decode `APayPreAuthErrorChargeResp {code, message}` or `ErrorPayload` | `AUTHENTICATION_FAILED` or redirect |
| 401 | Gateway auth failure | `AUTHORIZATION_FAILED` |
| 4XX (general) | `HTTP_4XX` error, extract user message | Failure response |
| 500 | `HTTP_5XX` server error | `AUTHORIZATION_FAILED` |
| 503 | Service unavailable | Gateway error logged |
| 504 | Timeout | `AUTHORIZATION_FAILED` or soft fail |
| 429 | Rate limit | Gateway error logged |
| Connection Failure | `Socket` error | Retry (void) or failure response |

### 7.3 Timeout & Retry

- **Timeout Mechanism**: Per-request payload field (`transactionTimeout` in S2S V1; `timeoutInSecs` in V2)
- **Per-Merchant Override**: `autoVoidTimeInSec` in `AmazonPayDetails`
- **Retry Enabled**: Yes — void API has one automatic retry on API/socket errors (`retryVoidApi`)
- **Max Retries**: 1 (void only)
- **Retry Strategy**: Immediate re-attempt with same payload on `API` or `Socket` errors; `VOID_INITIATED` on second failure

### 7.4 Error Response Types

#### V2 PreAuth Error Response — `APayPreAuthErrorChargeResp`

| # | Field | Type | JSON Key | Description |
|---|-------|------|----------|-------------|
| 1 | `code` | Text | `code` | Error code |
| 2 | `message` | Text | `message` | Error message (shown to user) |

#### S2S V1 Error Response — `AmazonPayCheckStatusS2SErrorResponse`

| # | Field | Type | JSON Key | Description |
|---|-------|------|----------|-------------|
| 1 | `response.reasonCode` | Text | `response.reasonCode` | Error reason code |
| 2 | `response.reasonDescription` | Text | `response.reasonDescription` | Human-readable reason |
| 3 | `requestId` | Text | `requestId` | Amazon request ID |

#### SDK Error Response — `AmazonPayErrorResponse`

| # | Field | Type | JSON Key | Description |
|---|-------|------|----------|-------------|
| 1 | `_ErrorResponse._Error._Type` | Text | `_Type` | Error type |
| 2 | `_ErrorResponse._Error._Code` | Text | `_Code` | Error code |
| 3 | `_ErrorResponse._Error._Message` | Text | `_Message` | Error message |
| 4 | `_ErrorResponse._RequestId` | Text | `_RequestId` | Amazon request ID |
| 5 | `statusCode` | Int | `statusCode` | HTTP status code |

#### Sync Failure Error Response — `ApaySyncFailureErrorResponse`

| # | Field | Type | JSON Key | Description |
|---|-------|------|----------|-------------|
| 1 | `errorCode` | Text | `errorCode` | Error code |
| 2 | `errorMessage` | Text | `errorMessage` | Error message |
| 3 | `status` | Text | `status` | Always `"FAILURE"` |
| 4 | `syncResp` | Foreign | `syncResp` | Raw sync response JSON |

---

## 8. Status Mappings

### 8.1 S2S V1 Gateway Status → TxnStatus

**Source**: `euler-x/src-generated/Gateway/AmazonPay/Flow.hs:1817`

| # | Gateway Status (S2S V1) | Juspay TxnStatus | Description |
|---|------------------------|-----------------|-------------|
| 1 | `"SUCCESS"` | `CHARGED` | Payment successful |
| 2 | `"PENDING"` | `PENDING_VBV` | Payment pending |
| 3 | `"FAILURE"` | `AUTHENTICATION_FAILED` | Payment failed |
| 4 | (any other) | `AUTHORIZATION_FAILED` | Default fallback |

### 8.2 V2 PreAuth Charge Status → TxnStatus

**Source**: `euler-x/src-generated/Gateway/AmazonPay/Flow.hs:1806`

| # | Gateway Status (V2) | Juspay TxnStatus | Description |
|---|---------------------|-----------------|-------------|
| 1 | `"AuthPending"` | `PENDING_VBV` | Auth pending |
| 2 | `"AuthApproved"` | `AUTHORIZED` | Authorized (pre-auth) |
| 3 | `"CaptureApproved"` | `CHARGED` | Captured / charged |
| 4 | `"CapturePending"` | `CAPTURE_INITIATED` | Capture in progress |
| 5 | `"Declined"` | `AUTHENTICATION_FAILED` | Declined |
| 6 | `"Failed"` | `AUTHENTICATION_FAILED` | Failed |
| 7 | (any other) | `AUTHORIZATION_FAILED` | Fallback |

### 8.3 V2 PostAuth / Get Status → TxnStatus

**Source**: `euler-x/src-generated/Gateway/AmazonPay/Flow.hs:2308`

| # | Gateway Status (V2 Get Status) | Juspay TxnStatus | Description |
|---|-------------------------------|-----------------|-------------|
| 1 | `"CapturePending"` | `CAPTURE_INITIATED` | Capture in progress |
| 2 | `"CaptureApproved"` | `CHARGED` | Successfully captured |
| 3 | `"AuthApproved"` | `AUTHORIZED` | Authorized but not captured |
| 4 | `"Declined"` | `CAPTURE_FAILED` | Capture declined |
| 5 | (other) | existing txnStatus | No change |

### 8.4 V2 Void Status → TxnStatus

**Source**: `euler-x/src-generated/Gateway/AmazonPay/Flow.hs:2319`

| # | Void Status | Juspay TxnStatus | Description |
|---|-------------|-----------------|-------------|
| 1 | `"Approved"` | `VOIDED` | Successfully voided |
| 2 | `"Pending"` | `VOID_INITIATED` | Void in progress |
| 3 | `"Declined"` | `VOID_FAILED` | Void declined |
| 4 | (other) | existing txnStatus | No change |

### 8.5 V2 Capture Response → TxnStatus

**Source**: `euler-x/src-generated/Gateway/AmazonPay/Flow.hs:2619`

| # | Capture Status | Juspay TxnStatus | Description |
|---|---------------|-----------------|-------------|
| 1 | `"CaptureApproved"` | `CHARGED` | Captured |
| 2 | `"CapturePending"` | `CAPTURE_INITIATED` | Pending |
| 3 | `"Declined"` | `CAPTURE_FAILED` | Failed |
| 4 | (other) | `txStatus` (passed in) | No override |

### 8.6 SDK (List Order) Status → TxnStatus

**Source**: `euler-x/src-generated/Gateway/AmazonPay/Flow.hs:1826`

| # | List Order State | Condition | Juspay TxnStatus |
|---|-----------------|-----------|-----------------|
| 1 | `"CLOSED"` | — | `CHARGED` |
| 2 | `"CANCELED"` | — | `AUTHENTICATION_FAILED` |
| 3 | `"PENDING"` | — | `PENDING_VBV` |
| 4 | `"OPEN"` | `ReasonDescription == "Txn Success"` | `CHARGED` |
| 5 | `"OPEN"` | other | `PENDING_VBV` |
| 6 | (other) | — | `AUTHORIZATION_FAILED` |

### 8.7 Mobile Legacy Response → TxnStatus

**Source**: `euler-x/src-generated/Gateway/AmazonPay/Flow.hs:1840`

| # | Description | reasonCode | Juspay TxnStatus |
|---|-------------|-----------|-----------------|
| 1 | `"Txn Success"` | `"001"` | `CHARGED` |
| 2 | `"Txn Success"` | other | `PENDING_VBV` |
| 3 | `"Txn Failed"` | — | `AUTHENTICATION_FAILED` |
| 4 | (other) | — | `AUTHORIZATION_FAILED` |

### 8.8 Top-Up Status Mapping

**Source**: `euler-x/src-generated/Gateway/AmazonPay/Flow.hs:2850`

| # | Amazon Status (uppercase) | Juspay WalletTopupTxnStatus |
|---|--------------------------|----------------------------|
| 1 | `"SUCCESS"` | `SUCCESS` |
| 2 | `"APPROVED"` | `SUCCESS` |
| 3 | `"PENDING"` | `PENDING` |
| 4 | `"FAILED"` | `FAILED` |
| 5 | `"DECLINED"` | `FAILED` |
| 6 | (other) | `PENDING` |

### 8.9 isPaymentSuccessful Logic

**Source**: `euler-x/src-generated/Gateway/AmazonPay/Flow.hs:2200`

| Response Type | Success Condition |
|--------------|-------------------|
| `ListOrderStatusValidResponse` | `OrderReferenceStatus.ReasonDescription == "Txn Success"` |
| `ListOrderStatusErrorResponse` | False |
| `S2SCheckStatusSuccessResponse` | `response.status == "SUCCESS"` |
| `S2SCheckStatusErrorResponse` | False |
| `WebHookTxnStatusResponse` | `_Status._State == "Completed"` |
| `ApayV2GetStatusResponse ValidStatusResponse` | `status == "CaptureApproved"` |
| `ApaySyncFailureErrorResp` | False |

### 8.10 isTxnNotFound Logic

**Source**: `euler-x/src-generated/Gateway/AmazonPay/Flow.hs:2269`

| Response Type | Not-Found Condition |
|--------------|---------------------|
| `ListOrderStatusValidResponse` | `_OrderReference == Nothing` |
| `S2SCheckStatusErrorResponse` | `response.reasonCode == "11-01"` |
| `ApayV2GetStatusResponse ErrorStatusResponse` | `message == "Specified charge id does not exist."` OR starts with `"No charge found for"` |
| Others | False |

---

## 9. Payment Methods

### 9.1 Supported Payment Method Types

| # | PaymentMethodType | Payment Method | Gateway Code | Notes |
|---|-------------------|---------------|--------------|-------|
| 1 | `WALLET` | `AMAZONPAY` | AMAZONPAY | Standard Amazon Pay wallet balance |
| 2 | `CONSUMER_FINANCE` | `AMAZONPAYLATER` | AMAZONPAY | Amazon Pay Later (BNPL) |
| 3 | `CONSUMER_FINANCE` | `AMAZONPAYLATER_EMI` | AMAZONPAY | Amazon Pay Later EMI (deeplink flow) |
| 4 | `WALLET` | `AMAZONPAY_UPI` | AMAZONPAY | UPI flow via Amazon Pay |

**Source**: `euler-x/src-generated/Gateway/AmazonPay/Flow.hs:2902–2903`

### 9.2 Payment Method Routing Logic

| # | Payment Method | Integration Check | Flow Selected |
|---|---------------|------------------|---------------|
| 1 | `AMAZONPAY` | `integrationV2 = "true"` AND S2S credentials | `callV2WalletFlows` (PreAuth) |
| 2 | `AMAZONPAY` | S2S credentials, not V2 | `directDebit` (S2S V1) |
| 3 | `AMAZONPAY` | No S2S credentials | SDK redirect flow |
| 4 | `AMAZONPAYLATER` | Linked wallet + V2 | `callV2WalletFlows` with `AMAZONPAYLATER` instrument |
| 5 | `AMAZONPAYLATER` | Not linked, `shouldCallPreEligibilityForAPL=true` | Eligibility API call |
| 6 | `AMAZONPAYLATER` | Not linked | Return `linking_required` |
| 7 | `AMAZONPAYLATER_EMI` | APL EMI credentials configured | Deeplink redirect + eligibility |

### 9.3 MGA Payment Methods Configuration

The `mga.paymentMethods` JSON field controls which AMAZONPAY payment variants are enabled:

- `"AMAZONPAYLATER"` in `paymentMethods` array → `isAmazonpaylaterEnabledInMgaPaymentMethods = True`
- `"AMAZONPAYLATER_EMI"` in `paymentMethods` array → `isAmazonpaylaterEMIEnabledInMgaPaymentMethods = True`

**Source**: `Flow.hs:2884–2900`

### 9.4 Credential Routing Per Payment Method

| Payment Method | Access Key | Secret Key | Seller ID |
|---------------|-----------|-----------|-----------|
| `AMAZONPAY` (wallet) | `amazonPayS2SAccessKey` | `amazonPayS2SSecretKey` | `amazonPaySellerId` |
| `AMAZONPAYLATER` | `amazonPayLaterAccessKey` | `amazonPayLaterSecretKey` | `amazonPayLaterSellerId` |
| `AMAZONPAYLATER_EMI` | `amazonPayLaterEmiAccessKey` | `amazonPayLaterEmiSecretKey` | `amazonPayLaterSellerId` |

**Source**: `Transforms.getSecretKey`, `Transforms.getSellerIdBasedOnPM`, `Transforms.getAccessKey`

### 9.5 Payment Method Fields in Request

| # | Field | JSON Key | Type | Description |
|---|-------|----------|------|-------------|
| 1 | `paymentMethod` | `payment_method` | Maybe Text | `"AMAZONPAY"`, `"AMAZONPAYLATER"`, `"AMAZONPAYLATER_EMI"` |
| 2 | `paymentMethodType` | `payment_method_type` | Maybe Text | `"WALLET"`, `"CONSUMER_FINANCE"` |

---

## 10. Integrity Verification

### 10.1 Response Integrity Framework

**Source**: `euler-x/src-generated/Gateway/AmazonPay/Flow.hs:3100`

AMAZONPAY implements `CheckIntegrity AMAZONPAY` (new framework) with the following response type handling:

| Response Type | Integrity Check Method |
|--------------|----------------------|
| `WebResponse` | `getHashAndComputedHashValues` via `AmazonServerSDK` SDK; txnId from `sellerOrderId` |
| `MobileSDKResponse` | `getHashAndComputedHashValues` via SDK; txnId from `merchantTransactionId` |
| `ListOrderResponse` | Skip hash; verify `SellerOrderId` + amount only; skip currency verification |
| `MobileRespLagecy` | Skip hash; verify `merchantTransactionId` + amount; skip currency |
| `DirectDebitResponse` | Skip hash; verify `merchantTransactionId` + amount + currency |
| `OrderSyncResponse` (S2S V1 sync) | HMAC-SHA384 hash verification via `verifyAmazonPaySignature` |
| `TxnSyncResp` (webhook) | HMAC-SHA384 hash verification |
| `DirectDebitV2` | Skip hash; verify `chargeId` + `approvedAmount`; skip currency |
| `WebhookResp` | Skip hash; verify `_SellerReferenceId` + amount; skip currency |
| Unrecognized | `shouldRejectWebhook = True` |

### 10.2 V2 Signature Verification

**Source**: `euler-x/src-generated/Gateway/AmazonPay/Flow.hs:2507`

```
validateSignature:
  1. Extract x-amz-signature from response headers
  2. Build response headers object (APayResponseHeaders)
  3. Call AmazonServerSDK.getSignatureForPreAuthFlow with:
       - response headers (encoded)
       - response body (Foreign)
       - x-amz-date
       - secretKey
       - URI
       - HTTP method
       - mode = "verify"
       - testMode
  4. Compare computed signature == received x-amz-signature
```

---

## 11. Completeness Verification

| Check | Result |
|-------|--------|
| S2S V1 Direct Debit request fields | 18 documented |
| S2S V1 Status request fields | 8 documented |
| S2S V1 Refund request fields | 14 documented |
| V2 Charge request fields | 15 documented |
| V2 Capture request fields | 5 documented |
| V2 Void request fields | 4 documented |
| V2 Get Status request fields | 3 documented |
| V2 Refund Init request fields | 8 documented |
| V2 Top-Up request fields | 11 documented |
| V2 Refresh Wallet request fields | 4 documented |
| Consent Token request fields | 7 documented |
| APL Eligibility request fields | 4 documented |
| S2S V1 Direct Debit response fields | 10 documented |
| S2S V1 Status response fields | 8 documented |
| S2S V1 Refund response fields | 13 documented |
| V2 Charge response fields | 11 documented |
| V2 Capture response fields | 10 documented |
| V2 Void response fields | 8 documented |
| V2 Refund response fields | 8 documented |
| Consent Token response fields | 4 documented |
| Webhook response fields | 8 documented |
| All nested types expanded | Yes |
| All status mapping tables documented | Yes (8 mapping tables) |
| All flows documented | Yes (11 major flows) |
| All error paths documented | Yes |
| Payment methods documented | Yes |
| Integrity framework documented | Yes |
| Missing items | None |

---

## 12. Source File References

| # | File | Lines Read | Purpose |
|---|------|-----------|---------|
| 1 | `euler-x/src-generated/Gateway/AmazonPay/Flow.hs` | 1–3240 (all) | All flows, status mappings, integrity, webhook, sync, eligibility |
| 2 | `euler-x/src-generated/Gateway/AmazonPay/Types.hs` | 1–2007 (all) | All request/response types, enums, newtypes, RestEndpoint instances |
| 3 | `euler-x/src-generated/Gateway/AmazonPay/Transforms.hs` | All | Authentication headers, request builders, API call wrappers |
| 4 | `euler-x/src-generated/Gateway/AmazonPay/Endpoints.hs` | All | All endpoint URLs and environment routing logic |
| 5 | `euler-api-gateway/common/src/Euler/API/Gateway/Types/ApiTag.hs` | Lines 50–55, 290–295, 513–518 | AMAZONPAY ApiTag definitions |
| 6 | `euler-api-gateway/common/src/Euler/API/Gateway/Utils/Gateway/Common.hs` | Line 2042 | AMAZONPAY gateway list entry |
| 7 | `euler-techspec-workflow/connectors.json` | All | Connector registry confirmation |

---

**Generated by**: Euler Connector Tech Spec Workflow
**Date**: 2026-03-26
