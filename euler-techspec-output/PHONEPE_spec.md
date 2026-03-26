# PHONEPE — Technical Specification

> **Connector**: PHONEPE
> **Direction**: euler-api-gateway → PhonePe (Mandate/Recurring) | euler-api-txns → PhonePe (All other flows)
> **Endpoint**: Multiple — see Section 1.2 and Section 3
> **Purpose**: Full PhonePe payment gateway integration covering UPI, Wallet, Card, NB, Pre-Auth, Recurring/Mandate, Refund, Webhook, and Checkout flows
> **Generated**: 2026-03-26

---

## 1. Connector Overview

### 1.1 Basic Information
- **Connector ID**: PHONEPE
- **Direction**: euler-api-gateway → PhonePe (Mandate/Recurring flows); euler-api-txns → PhonePe (All other flows)
- **HTTP Method**: GET, POST (varies by endpoint — see endpoint table in Section 1.2)
- **Endpoint Path**: Multiple — see full endpoint table in Section 1.2
- **Protocol**: HTTP REST (synchronous)
- **Content Type**: application/json (application/x-www-form-urlencoded for OAuth token endpoint)
- **Architecture**: Haskell (Servant + Warp)

### 1.2 Base URL Configuration

#### Part A — euler-api-gateway (Mandate/Recurring flows)

| Environment | Base URL | Env Variable | Default |
|-------------|----------|--------------|---------|
| UAT / Sandbox | `https://mercury-uat.phonepe.com/v3/recurring` | hardcoded | N/A |
| PROD | `https://mercury-t2.phonepe.com/v3/recurring` | hardcoded | N/A |

**URL Resolution Logic**: Function `phonePeBaseUrl :: IsSandbox -> Gateway -> C.BaseUrl` in `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/PhonePe/Routes.hs`. `IsSandbox=True` → `host=mercury-uat.phonepe.com`, `path=v3/recurring`; `IsSandbox=False` → `host=mercury-t2.phonepe.com`, `path=v3/recurring`. `IsSandbox` is derived from `MerchantGatewayAccount.testMode`.

#### Part B — euler-api-txns (All other flows)

All URLs fully hardcoded. Selection via `Bool testMode` (`True` = UAT, `False` = PROD).
Source file: `euler-api-txns/euler-x/src-generated/Gateway/PhonePe/Endpoints.hs`

| Endpoint Type | UAT URL | PROD URL |
|---------------|---------|----------|
| PhonePeTransactionRequest | `https://mercury-uat.phonepe.com/v3/debit` | `https://mercury-t2.phonepe.com/v3/debit` |
| PhonePeSdkLessIntent | `https://api-preprod.phonepe.com/apis/pg-sandbox/v4/debit` | `https://mercury-t2.phonepe.com/v4/debit` |
| PhonepeCheckTransactionStatusReq | `https://mercury-uat.phonepe.com/v3/transaction/:mid/:tid/status` | `https://mercury-t2.phonepe.com/v3/transaction/:mid/:tid/status` |
| PhonepeV4CheckTxnStatusReq | `https://api-preprod.phonepe.com/apis/pg-sandbox/v4/transaction/:mid/:tid/status` | `https://mercury-t2.phonepe.com/v4/transaction/:mid/:tid/status` |
| PhonepeRefundRequest | `https://mercury-uat.phonepe.com/v3/credit/backToSource` | `https://mercury-t2.phonepe.com/v3/credit/backToSource` |
| TriggerOtp | `https://mercury-uat.phonepe.com/v3/merchant/otp/send` | `https://mercury-t2.phonepe.com/v3/merchant/otp/send` |
| VerifyOtp | `https://mercury-uat.phonepe.com/v3/merchant/otp/verify` | `https://mercury-t2.phonepe.com/v3/merchant/otp/verify` |
| BalanceCheck | `https://mercury-uat.phonepe.com/v3/wallet/balance` | `https://mercury-t2.phonepe.com/v3/wallet/balance` |
| TopupRequest | `https://mercury-uat.phonepe.com/v3/wallet/topup` | `https://mercury-t2.phonepe.com/v3/wallet/topup` |
| directDebitRequest | `https://mercury-uat.phonepe.com/v3/wallet/debit` | `https://mercury-t2.phonepe.com/v3/wallet/debit` |
| delinkWalletRequest | `https://mercury-uat.phonepe.com/v3/merchant/token/unlink` | `https://mercury-t2.phonepe.com/v3/merchant/token/unlink` |
| AuthApiRequest | `https://mercury-uat.phonepe.com/v3/auth/authorize` | `https://mercury-t2.phonepe.com/v3/auth/authorize` |
| AuthStatusRequest | `https://mercury-uat.phonepe.com/v3/auth/:mid/:tid/status` | `https://mercury-t2.phonepe.com/v3/auth/:mid/:tid/status` |
| captureRequest | `https://mercury-uat.phonepe.com/v3/auth/capture` | `https://mercury-t2.phonepe.com/v3/auth/capture` |
| cancelAuthRequest | `https://mercury-uat.phonepe.com/v3/auth/cancel` | `https://mercury-t2.phonepe.com/v3/auth/cancel` |
| createSubscriptionRequest | `https://mercury-uat.phonepe.com/v3/recurring/subscription/create` | `https://mercury-t2.phonepe.com/v3/recurring/subscription/create` |
| subscriptionStatusRequest | `https://mercury-uat.phonepe.com/v3/recurring/subscription/status/:merchantId/:merchantSubscriptionId` | `https://mercury-t2.phonepe.com/v3/recurring/subscription/status/:merchantId/:merchantSubscriptionId` |
| submitAuthRequest | `https://mercury-uat.phonepe.com/v3/recurring/auth/init` | `https://mercury-t2.phonepe.com/v3/recurring/auth/init` |
| submitAuthStatusRequest | `https://mercury-uat.phonepe.com/v3/recurring/auth/status/:merchantId/:authRequestId` | `https://mercury-t2.phonepe.com/v3/recurring/auth/status/:merchantId/:authRequestId` |
| recurringDebitExecStatusRequest | `https://mercury-uat.phonepe.com/v3/recurring/debit/status/:merchantId/:merchantTransactionId` | `https://mercury-t2.phonepe.com/v3/recurring/debit/status/:merchantId/:merchantTransactionId` |
| PhonePePGRefund | `https://api-preprod.phonepe.com/apis/hermes/pg/v1/refund` | `https://api.phonepe.com/apis/hermes/pg/v1/refund` |
| PhonePePGTxnAndRefundSync | `https://api-preprod.phonepe.com/apis/hermes/pg/v1/status/:mid/:txnid` | `https://api.phonepe.com/apis/hermes/pg/v1/status/:mid/:txnid` |
| PhonePeV2PayRequest | `https://api-preprod.phonepe.com/apis/hermes/pg/v1/pay` | `https://api.phonepe.com/apis/hermes/pg/v1/pay` |
| PhonePeV2VerifyVpaRequest | `https://api-preprod.phonepe.com/apis/hermes/pg/v1/vpa/validate` | `https://api.phonepe.com/apis/hermes/pg/v1/vpa/validate` |
| PhonePeNewCardHostEndpoint | `https://api-preprod.phonepe.com/apis/hermes/pg/v1/pay` | `https://cards.phonepe.com/apis/pg/pg/v1/pay` |
| PhonepeAuthTokeRequest | `https://api-preprod.phonepe.com/apis/pg-sandbox/v1/oauth/token` | `https://api.phonepe.com/apis/identity-manager/v1/oauth/token` |
| PhonePeOrderCreateRequest | `https://api-preprod.phonepe.com/apis/pg-sandbox/checkout/v2/pay` | `https://api.phonepe.com/apis/pg/checkout/v2/pay` |
| PhonePeCreatePaymentRequest | `https://api-preprod.phonepe.com/apis/pg-sandbox/checkout/v2/pay` | `https://api.phonepe.com/apis/pg/checkout/v2/pay` |
| PhonepeCheckoutRequest | `https://api-preprod.phonepe.com/apis/pg-sandbox/checkout/ui/v2/pay` | `https://api.phonepe.com/apis/pg/checkout/ui/v2/pay` |
| PhonepeCheckoutStatusRequest | `https://api-preprod.phonepe.com/apis/pg-sandbox/checkout/v2/order/:tid/status` | `https://api.phonepe.com/apis/pg/checkout/v2/order/:tid/status` |
| IRCTC_Refund | `https://api-preprod.phonepe.com/apis/pg-sandbox/pg/v1/irctc-refund` | `https://api.phonepe.com/apis/hermes/pg/v1/irctc-refund` |
| IRCTC_RefundSync | `https://api-preprod.phonepe.com/apis/pg-sandbox/pg/v1/irctc-refund/status/:mid/:txnid` | `https://api.phonepe.com/apis/hermes/pg/v1/irctc-refund/status/:mid/:txnid` |
| IRCTC_PayIntent | `https://api-preprod.phonepe.com/apis/pg-sandbox/pg/v1/irctc-pay` | `https://api.phonepe.com/apis/hermes/pg/v1/irctc-pay` |
| IRCTC_TxnSync | `https://api-preprod.phonepe.com/apis/pg-sandbox/pg/v1/irctc-pay/status/:mid/:txnid` | `https://api.phonepe.com/apis/hermes/pg/v1/irctc-pay/status/:mid/:txnid` |

#### Gateway-side API Routes (Part A, all under base URL `v3/recurring`):

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/subscription/cancel` | Cancel/revoke mandate |
| POST | `/debit/init` | Recurring debit init |
| POST | `/debit/execute` | Recurring debit execute |
| GET | `/subscription/status/:merchantId/:merchantSubscriptionId` | Subscription status |

**Timeout Configuration**:
- Custom Timeout Header: Not configured at connector level
- Default Timeout: Handled at generic HTTP client layer (not connector-specific)
- Per-Merchant Override: No

---

## 2. Authentication

### 2.1 Authentication Method

Three authentication flows exist, used in different contexts:

**Flow 1 — HMAC SHA256 (V1/Mercury + V2 API)**
- **Auth Type**: HMAC SHA256
- **Auth Header**: `X-VERIFY: sha256(base64Payload + apiPath + saltKey) + "###" + keyIndex`
- **Credential Source**: `PhonepeDetails` from `MerchantGatewayAccount.accountDetails`

**Flow 2 — OAuth Bearer Token (V2/Checkout, S2S-disabled merchants)**
- **Auth Type**: OAuth 2.0 client_credentials
- **Auth Header**: `authorization: O-Bearer {access_token}` (step 1); `authorization: Bearer {payment_token}`, `x-auth-token: {payment_token}` (step 2)
- **Credential Source**: `PhonepeDetails` from `MerchantGatewayAccount.accountDetails`
- **Trigger**: Merchant listed in `PHONEPE_S2S_DISABLED_MERCHANTS` feature flag

**Flow 3 — RSA Encryption (Cards/Token)**
- **Auth Type**: RSA public key encryption applied to card data fields within the payload
- **Credential Source**: `PhonepeDetails.phonepePublicKey`, `PhonepeDetails.phonepePublicKeyId`
- **Note**: X-VERIFY header is still used for the outer request; RSA applies only to card data fields

### 2.2 Authentication Flow

#### Flow 1 — HMAC SHA256
1. Extract `PhonePeDetails` from `MerchantGatewayAccount.accountDetails`
2. Call `getPhonePeSalt`: select `keyIndex1` (default `"1"`) and `phonepeKey1` as `saltKey`
3. Base64-encode the request body
4. Compute: `sha256(base64Body + apiPath + saltKey)`
5. Append: `"###" + keyIndex` → set as `X-VERIFY` header
6. Optionally set `X-CALLBACK-URL` if `isCallback=True`

Source: `euler-api-txns/euler-x/src-generated/Gateway/PhonePe/Transforms.hs` L699–707 (`getPhonePeSalt`), L1499–1500 (`getCheckSumforV2API`)

**V2 sync header variant** (`makePhonePeNewSyncHeader`):
- `X-VERIFY: sha256(apiPath + merchantId + "/" + transactionId + saltKey) + "###" + keyIndex`
- `X-MERCHANT-ID: phonepeMerchantId`

#### Flow 2 — OAuth Bearer Token
1. POST to `PhonepeAuthTokeRequest` with `Content-Type: application/x-www-form-urlencoded`; body: `{ client_id, client_version, client_secret, grant_type="client_credentials" }`
2. Receive `access_token`; use as: `authorization: O-Bearer {access_token}`
3. Extract `payment_token` from redirect URL (split on `"token="`); use as: `authorization: Bearer {payment_token}`, `x-auth-token: {payment_token}`

Source: `euler-api-txns/euler-x/src-generated/Gateway/PhonePe/Transforms.hs` L1856–1879

#### Flow 3 — RSA Encryption
1. Obtain RSA public key from `PhonepeDetails.phonepePublicKey` and `phonepePublicKeyId`
2. Encrypt card fields: `cardNumber` → `encryptedCardNumber`, `CVV` → `encryptedCvv`, `token` → `encryptedToken`
3. Include encrypted values in the request payload body

### 2.3 Required Headers

| # | Header Name | Value / Source | Required | Description |
|---|-------------|----------------|----------|-------------|
| 1 | `X-VERIFY` | `sha256(base64Body + apiPath + saltKey) + "###" + keyIndex` | Yes (HMAC flows) | HMAC SHA256 checksum for request authentication |
| 2 | `Content-Type` | `application/json` | Yes | Request body format |
| 3 | `X-CALLBACK-URL` | `webhookUrl` | No | Webhook callback URL; set if `isCallback=True` |
| 4 | `X-REDIRECT-URL` | `handleResponseUrl` | No (transaction init only) | URL to redirect after payment |
| 5 | `X-REDIRECT-MODE` | `POST` | No (transaction init only) | Redirect HTTP method |
| 6 | `X-CALL-MODE` | `POST` | No (transaction init only) | Call mode for init |
| 7 | `X-SOURCE-PLATFORM` | `JUSPAY` | No (feature flag `enableGwHeader`, no merchant proxy) | Source platform identifier |
| 8 | `X-SOURCE` | `API` | No | Source type |
| 9 | `X-SOURCE-CHANNEL` | `ANDROID` / `IOS` / `WEB` | No | Source channel |
| 10 | `X-MERCHANT-IP` | `ipAddress` | No | Merchant/customer IP address |
| 11 | `X-BROWSER-FINGERPRINT` | `sha256(deviceInfo)` | No (WEB only) | Browser fingerprint for 3DS2 |
| 12 | `USER-AGENT` | `userAgent` | No (WEB only) | Browser user agent |
| 13 | `X-MERCHANT-DOMAIN` | `referer` | No (WEB only) | Merchant domain/referer |
| 14 | `X-SOURCE-CHANNEL-VERSION` | `appVersion` | No (mobile only) | App version |
| 15 | `X-MERCHANT-APP-ID` | `appId` | No (mobile only) | Merchant app identifier |
| 16 | `X-MERCHANT-APP-SIGNATURE` | `""` | No (Android only) | App signature (empty string) |
| 17 | `X-MERCHANT-ID` | `phonepeMerchantId` | No (V2 sync only) | Merchant ID for V2 sync header |
| 18 | `authorization` | `O-Bearer {access_token}` / `Bearer {payment_token}` | Yes (OAuth flow) | OAuth authorization header |
| 19 | `x-auth-token` | `{payment_token}` | Yes (OAuth flow, step 2) | Payment token for checkout flow |
| 20 | `Content-Type` | `application/x-www-form-urlencoded` | Yes (OAuth token request only) | Form encoding for token endpoint |

---

## 3. Request Structure

### 3.1 URL Parameters

**Path Parameters (gateway-side Mandate/Recurring):**

| # | Parameter | Type | Source | Description |
|---|-----------|------|--------|-------------|
| 1 | `merchantId` | Text | `PhonepeDetails.phonepeMerchantId` | PhonePe merchant identifier |
| 2 | `merchantSubscriptionId` | Text | Mandate request / subscription ID | Subscription/mandate identifier |
| 3 | `authRequestId` | Text | Auth response | Auth request identifier (recurring auth status) |
| 4 | `merchantTransactionId` | Text | Transaction request | Transaction identifier (recurring debit status) |

**Path Parameters (txns-side):**

| # | Parameter | Type | Source | Description |
|---|-----------|------|--------|-------------|
| 1 | `mid` | Text | `PhonepeDetails.phonepeMerchantId` | Merchant ID (V3/V4 status, V2 sync) |
| 2 | `tid` | Text | Transaction request `merchantTransactionId` | Transaction ID (V3/V4 status, V2 sync, checkout status, auth status) |
| 3 | `txnid` | Text | Transaction request | Transaction ID (V2 hermes sync, IRCTC sync) |
| 4 | `merchantId` | Text | `PhonepeDetails.phonepeMerchantId` | Merchant ID (subscription status, auth status, debit exec status) |
| 5 | `merchantSubscriptionId` | Text | Subscription/mandate ID | Subscription identifier (subscription status) |
| 6 | `authRequestId` | Text | Auth response | Auth request identifier (submit auth status) |
| 7 | `merchantTransactionId` | Text | Transaction request | Transaction identifier (recurring debit exec status) |

**Query Parameters:**

| # | Parameter | Type | Required | Description |
|---|-----------|------|----------|-------------|
| 1 | `merchantId` | Text | No (BalanceCheck) | Merchant ID for wallet balance check (may be path or query param) |
| 2 | `mobileNumber` | Text | No (BalanceCheck) | Customer mobile number for wallet balance check |

### 3.2 Request Body

#### PhonePeTransactionRequest (V3 S2S debit)
**Type**: `PhonePeTransactionRequest` — `euler-api-txns/euler-x/src-generated/Gateway/PhonePe/Types.hs`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `merchantId` | Text | `merchantId` | Yes | PhonePe merchant identifier |
| 2 | `merchantTransactionId` | Text | `merchantTransactionId` | Yes | Unique transaction identifier (<=38 chars) |
| 3 | `merchantUserId` | Maybe Text | `merchantUserId` | No | Merchant's user identifier |
| 4 | `amount` | Int | `amount` | Yes | Amount in paise |
| 5 | `redirectUrl` | Maybe Text | `redirectUrl` | No | Redirect URL after payment |
| 6 | `redirectMode` | Maybe Text | `redirectMode` | No | Redirect HTTP method |
| 7 | `callbackUrl` | Maybe Text | `callbackUrl` | No | Webhook callback URL |
| 8 | `mobileNumber` | Maybe Text | `mobileNumber` | No | Customer mobile number |
| 9 | `deviceContext` | Maybe DeviceContext | `deviceContext` | No | Device context information |
| 10 | `paymentInstrument` | PaymentInstrument | `paymentInstrument` | Yes | Payment instrument details (type, targetApp, token, tokenType, authRequestId) |

**Field Count**: 10 fields

#### PhonePeSdkLessIntent (V4 SDK-less UPI intent)
**Type**: `PhonePeSdkLessIntent` — `euler-api-txns/euler-x/src-generated/Gateway/PhonePe/Types.hs`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `merchantId` | Text | `merchantId` | Yes | PhonePe merchant identifier |
| 2 | `merchantTransactionId` | Text | `merchantTransactionId` | Yes | Unique transaction identifier |
| 3 | `merchantUserId` | Maybe Text | `merchantUserId` | No | Merchant's user identifier |
| 4 | `amount` | Int | `amount` | Yes | Amount in paise |
| 5 | `redirectUrl` | Maybe Text | `redirectUrl` | No | Redirect URL |
| 6 | `redirectMode` | Maybe Text | `redirectMode` | No | Redirect mode |
| 7 | `callbackUrl` | Maybe Text | `callbackUrl` | No | Webhook callback URL |
| 8 | `mobileNumber` | Maybe Text | `mobileNumber` | No | Customer mobile number |
| 9 | `paymentInstrument` | PaymentInstrument | `paymentInstrument` | Yes | `{type="UPI_INTENT", targetApp}` |

**Field Count**: 9 fields

#### PhonePeNBnCardRequestBody (V2 hermes NB/Card pay)
**Type**: `PhonePeNBnCardRequestBody` — `euler-api-txns/euler-x/src-generated/Gateway/PhonePe/Types.hs`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `merchantId` | Text | `merchantId` | Yes | PhonePe merchant identifier |
| 2 | `merchantTransactionId` | Text | `merchantTransactionId` | Yes | Unique transaction identifier |
| 3 | `merchantUserId` | Maybe Text | `merchantUserId` | No | Merchant's user identifier |
| 4 | `amount` | Int | `amount` | Yes | Amount in paise |
| 5 | `redirectUrl` | Maybe Text | `redirectUrl` | No | Redirect URL |
| 6 | `redirectMode` | Maybe Text | `redirectMode` | No | Redirect mode |
| 7 | `callbackUrl` | Maybe Text | `callbackUrl` | No | Webhook callback URL |
| 8 | `mobileNumber` | Maybe Text | `mobileNumber` | No | Customer mobile number |
| 9 | `deviceContext` | Maybe DeviceContext | `deviceContext` | No | Device context |
| 10 | `paymentInstrument` | PhonePeNBPaymentInstrument / PhonePeCardPaymentInstrument | `paymentInstrument` | Yes | ADT: NB or Card instrument (card fields RSA-encrypted if card) |
| 11 | `browserDetails3DS2` | Maybe BrowserDetails3DS2 | `browserDetails3DS2` | No | Browser details for 3DS2 |

**Field Count**: 11 fields

#### PhonePeCreatePaymentRequest (Checkout/OAuth flow)
**Type**: `PhonePeCreatePaymentRequest` — `euler-api-txns/euler-x/src-generated/Gateway/PhonePe/Types.hs`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `merchantOrderId` | Text | `merchantOrderId` | Yes | Merchant's order identifier |
| 2 | `amount` | Int | `amount` | Yes | Amount in paise |
| 3 | `expireAfter` | Maybe Int | `expireAfter` | No | Order expiry time in seconds |
| 4 | `metaInfo` | Maybe MetaInfo | `metaInfo` | No | Additional metadata |
| 5 | `paymentFlow` | PaymentFlow | `paymentFlow` | Yes | `{flowType, message, mobileNumber, returnUrl, bankId}` |

**Field Count**: 5 fields

#### PhonePeCreateSubscriptionRequest (gateway-side)
**Type**: `PhonePeCreateSubscriptionRequest` — `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/PhonePe/Types.hs`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `merchantId` | Text | `merchantId` | Yes | PhonePe merchant identifier |
| 2 | `merchantSubscriptionId` | Text | `merchantSubscriptionId` | Yes | Unique subscription/mandate identifier |
| 3 | `name` | Text | `name` | Yes | Subscription name |
| 4 | `description` | Maybe Text | `description` | No | Subscription description |
| 5 | `amount` | Int | `amount` | Yes | Amount in paise |
| 6 | `frequency` | Text | `frequency` | Yes | Debit frequency (e.g., MONTHLY) |
| 7 | `recurringCount` | Maybe Int | `recurringCount` | No | Number of recurring debits |
| 8 | `mobileNumber` | Maybe Text | `mobileNumber` | No | Customer mobile number |
| 9 | `deviceContext` | Maybe DeviceContext | `deviceContext` | No | Device context |
| 10 | `paymentInstrument` | PaymentInstrument | `paymentInstrument` | Yes | Payment instrument |
| 11 | `redirectInfo` | Maybe RedirectInfo | `redirectInfo` | No | Redirect URL and callback |

**Field Count**: 11 fields

#### PhonePeDebitInitRequest (gateway-side)
**Type**: `PhonePeDebitInitRequest` — `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/PhonePe/Types.hs`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `merchantId` | Text | `merchantId` | Yes | PhonePe merchant identifier |
| 2 | `merchantTransactionId` | Text | `merchantTransactionId` | Yes | Unique transaction identifier |
| 3 | `merchantSubscriptionId` | Text | `merchantSubscriptionId` | Yes | Subscription/mandate identifier |
| 4 | `amount` | Int | `amount` | Yes | Amount in paise |
| 5 | `callbackUrl` | Maybe Text | `callbackUrl` | No | Webhook callback URL |

**Field Count**: 5 fields

#### PhonePeDebitExecuteRequest (gateway-side)
**Type**: `PhonePeDebitExecuteRequest` — `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/PhonePe/Types.hs`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `merchantId` | Text | `merchantId` | Yes | PhonePe merchant identifier |
| 2 | `merchantTransactionId` | Text | `merchantTransactionId` | Yes | Unique transaction identifier |
| 3 | `merchantSubscriptionId` | Text | `merchantSubscriptionId` | Yes | Subscription/mandate identifier |
| 4 | `amount` | Int | `amount` | Yes | Amount in paise |

**Field Count**: 4 fields

#### PhonePeCancelSubscriptionRequest (gateway-side)
**Type**: `PhonePeCancelSubscriptionRequest` — `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/PhonePe/Types.hs`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `merchantId` | Text | `merchantId` | Yes | PhonePe merchant identifier |
| 2 | `merchantSubscriptionId` | Text | `merchantSubscriptionId` | Yes | Subscription/mandate identifier to cancel |

**Field Count**: 2 fields

#### PhonepeRefundRequest (V3 refund)
**Type**: `PhonepeRefundRequest` — `euler-api-txns/euler-x/src-generated/Gateway/PhonePe/Types.hs`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `merchantId` | Text | `merchantId` | Yes | PhonePe merchant identifier |
| 2 | `originalTransactionId` | Text | `originalTransactionId` | Yes | Original transaction to refund |
| 3 | `merchantTransactionId` | Text | `merchantTransactionId` | Yes | Unique refund transaction identifier |
| 4 | `amount` | Int | `amount` | Yes | Refund amount in paise |
| 5 | `callbackUrl` | Maybe Text | `callbackUrl` | No | Webhook callback URL |
| 6 | `merchantUserId` | Maybe Text | `merchantUserId` | No | Merchant's user identifier |

**Field Count**: 6 fields

#### PhonePeV2RefundRequest (V2 hermes refund)
**Type**: `PhonePeV2RefundRequest` — `euler-api-txns/euler-x/src-generated/Gateway/PhonePe/Types.hs`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `merchantId` | Text | `merchantId` | Yes | PhonePe merchant identifier |
| 2 | `originalTransactionId` | Text | `originalTransactionId` | Yes | Original transaction to refund |
| 3 | `merchantTransactionId` | Text | `merchantTransactionId` | Yes | Unique refund transaction identifier |
| 4 | `amount` | Int | `amount` | Yes | Refund amount in paise |
| 5 | `callbackUrl` | Maybe Text | `callbackUrl` | No | Webhook callback URL |
| 6 | `metaInfo` | Maybe Value | `metaInfo` | No | Additional metadata |

**Field Count**: 6 fields

#### TriggerOtp
**Type**: `TriggerOtp` — `euler-api-txns/euler-x/src-generated/Gateway/PhonePe/Types.hs`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `merchantId` | Text | `merchantId` | Yes | PhonePe merchant identifier |
| 2 | `mobileNumber` | Text | `mobileNumber` | Yes | Customer mobile number |

**Field Count**: 2 fields

#### VerifyOtp
**Type**: `VerifyOtp` — `euler-api-txns/euler-x/src-generated/Gateway/PhonePe/Types.hs`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `merchantId` | Text | `merchantId` | Yes | PhonePe merchant identifier |
| 2 | `mobileNumber` | Text | `mobileNumber` | Yes | Customer mobile number |
| 3 | `otp` | Text | `otp` | Yes | OTP received by customer |

**Field Count**: 3 fields

#### TopupRequest
**Type**: `TopupRequest` — `euler-api-txns/euler-x/src-generated/Gateway/PhonePe/Types.hs`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `merchantId` | Text | `merchantId` | Yes | PhonePe merchant identifier |
| 2 | `merchantTransactionId` | Text | `merchantTransactionId` | Yes | Unique transaction identifier |
| 3 | `amount` | Int | `amount` | Yes | Top-up amount in paise |
| 4 | `mobileNumber` | Text | `mobileNumber` | Yes | Customer mobile number |
| 5 | `callbackUrl` | Maybe Text | `callbackUrl` | No | Webhook callback URL |

**Field Count**: 5 fields

#### directDebitRequest (Wallet)
**Type**: `directDebitRequest` — `euler-api-txns/euler-x/src-generated/Gateway/PhonePe/Types.hs`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `merchantId` | Text | `merchantId` | Yes | PhonePe merchant identifier |
| 2 | `merchantTransactionId` | Text | `merchantTransactionId` | Yes | Unique transaction identifier |
| 3 | `amount` | Int | `amount` | Yes | Debit amount in paise |
| 4 | `mobileNumber` | Text | `mobileNumber` | Yes | Customer mobile number |
| 5 | `callbackUrl` | Maybe Text | `callbackUrl` | No | Webhook callback URL |

**Field Count**: 5 fields

#### delinkWalletRequest
**Type**: `delinkWalletRequest` — `euler-api-txns/euler-x/src-generated/Gateway/PhonePe/Types.hs`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `merchantId` | Text | `merchantId` | Yes | PhonePe merchant identifier |
| 2 | `mobileNumber` | Text | `mobileNumber` | Yes | Customer mobile number |

**Field Count**: 2 fields

#### captureRequest (Pre-Auth)
**Type**: `captureRequest` — `euler-api-txns/euler-x/src-generated/Gateway/PhonePe/Types.hs`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `merchantId` | Text | `merchantId` | Yes | PhonePe merchant identifier |
| 2 | `originalTransactionId` | Text | `originalTransactionId` | Yes | Original pre-auth transaction |
| 3 | `merchantTransactionId` | Text | `merchantTransactionId` | Yes | Unique capture transaction identifier |
| 4 | `amount` | Int | `amount` | Yes | Capture amount in paise |

**Field Count**: 4 fields

#### cancelAuthRequest (Pre-Auth void)
**Type**: `cancelAuthRequest` — `euler-api-txns/euler-x/src-generated/Gateway/PhonePe/Types.hs`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `merchantId` | Text | `merchantId` | Yes | PhonePe merchant identifier |
| 2 | `originalTransactionId` | Text | `originalTransactionId` | Yes | Original pre-auth transaction to void |

**Field Count**: 2 fields

#### PhonepeAuthTokenRequest (OAuth token)
**Type**: `PhonepeAuthTokenRequest` — `euler-api-txns/euler-x/src-generated/Gateway/PhonePe/Types.hs`
**Encoding**: `application/x-www-form-urlencoded`

| # | Field Name | Haskell Type | Form Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `client_id` | Text | `client_id` | Yes | OAuth client ID (`phonepeClientId`) |
| 2 | `client_version` | Text | `client_version` | Yes | OAuth client version (`phonepeClientVersion`) |
| 3 | `client_secret` | Text | `client_secret` | Yes | OAuth client secret (`phonepeClientSecret`) |
| 4 | `grant_type` | Text | `grant_type` | Yes | Always `"client_credentials"` |

**Field Count**: 4 fields

#### createSubscriptionRequest (txns-side recurring)
**Type**: `createSubscriptionRequest` — `euler-api-txns/euler-x/src-generated/Gateway/PhonePe/Types.hs`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `subscriptionId` | Text | `subscriptionId` | Yes | Unique subscription identifier |
| 2 | `merchantId` | Text | `merchantId` | Yes | PhonePe merchant identifier |
| 3 | `name` | Text | `name` | Yes | Subscription name |
| 4 | `description` | Maybe Text | `description` | No | Subscription description |
| 5 | `amount` | Int | `amount` | Yes | Amount in paise |
| 6 | `frequency` | Text | `frequency` | Yes | Recurring frequency |
| 7 | `recurringCount` | Maybe Int | `recurringCount` | No | Number of recurrences |
| 8 | `redirectUrl` | Maybe Text | `redirectUrl` | No | Redirect URL |
| 9 | `callbackUrl` | Maybe Text | `callbackUrl` | No | Webhook callback URL |
| 10 | `mobileNumber` | Maybe Text | `mobileNumber` | No | Customer mobile number |
| 11 | `deviceContext` | Maybe DeviceContext | `deviceContext` | No | Device context |
| 12 | `paymentInstrument` | PaymentInstrument | `paymentInstrument` | Yes | Payment instrument |

**Field Count**: 12 fields

#### submitAuthRequest (recurring auth)
**Type**: `submitAuthRequest` — `euler-api-txns/euler-x/src-generated/Gateway/PhonePe/Types.hs`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `subscriptionId` | Text | `subscriptionId` | Yes | Subscription identifier |
| 2 | `merchantId` | Text | `merchantId` | Yes | PhonePe merchant identifier |
| 3 | `merchantTransactionId` | Text | `merchantTransactionId` | Yes | Unique transaction identifier |
| 4 | `amount` | Int | `amount` | Yes | Amount in paise |
| 5 | `paymentInstrument` | PaymentInstrument | `paymentInstrument` | Yes | Payment instrument |

**Field Count**: 5 fields

### 3.3 Nested Request Types

#### DeviceContext
Used in fields: `deviceContext` (multiple request types)

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `deviceOS` | Maybe Text | `deviceOS` | No | Operating system |
| 2 | `deviceType` | Maybe Text | `deviceType` | No | Device type (ANDROID/IOS/WEB) |
| 3 | `appVersion` | Maybe Text | `appVersion` | No | Application version |

#### PaymentInstrument (V3 ADT)
Used in fields: `paymentInstrument` (multiple request types)

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `type` | Text | `type` | Yes | Instrument type (e.g., UPI_INTENT, UPI_COLLECT, CARD, NB) |
| 2 | `targetApp` | Maybe Text | `targetApp` | No | Target UPI app (for UPI_INTENT) |
| 3 | `token` | Maybe Text | `token` | No | Token for token-based payment |
| 4 | `tokenType` | Maybe Text | `tokenType` | No | Token type |
| 5 | `authRequestId` | Maybe Text | `authRequestId` | No | Auth request ID for recurring |

#### PhonePeCardPaymentInstrument (V2 hermes card)
Used in field: `paymentInstrument` of `PhonePeNBnCardRequestBody`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `type` | Text | `type` | Yes | `"CARD"` |
| 2 | `encryptedCardNumber` | Text | `encryptedCardNumber` | Yes | RSA-encrypted card number |
| 3 | `encryptedCvv` | Text | `encryptedCvv` | Yes | RSA-encrypted CVV |
| 4 | `encryptedToken` | Maybe Text | `encryptedToken` | No | RSA-encrypted token (if token payment) |
| 5 | `cardHolderName` | Maybe Text | `cardHolderName` | No | Card holder name |
| 6 | `expiryMonth` | Maybe Text | `expiryMonth` | No | Card expiry month |
| 7 | `expiryYear` | Maybe Text | `expiryYear` | No | Card expiry year |

#### PaymentFlow (Checkout)
Used in field: `paymentFlow` of `PhonePeCreatePaymentRequest`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `flowType` | Text | `flowType` | Yes | Flow type identifier |
| 2 | `message` | Maybe Text | `message` | No | Message for customer |
| 3 | `mobileNumber` | Maybe Text | `mobileNumber` | No | Customer mobile number |
| 4 | `returnUrl` | Maybe Text | `returnUrl` | No | Return URL after payment |
| 5 | `bankId` | Maybe Text | `bankId` | No | Bank identifier |

#### SdkParams (25-field type)
Used in: `getSdkParams` flow output

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `merchantId` | Text | `merchantId` | Yes | Merchant identifier |
| 2 | `transactionId` | Text | `transactionId` | Yes | Transaction identifier |
| 3 | `subscriptionId` | Maybe Text | `subscriptionId` | No | Subscription identifier |
| 4 | `amount` | Text | `amount` | Yes | Amount |
| 5 | `expiry` | Maybe Text | `expiry` | No | Expiry time |
| 6 | `callbackUrl` | Maybe Text | `callbackUrl` | No | Callback URL |
| 7 | `redirectUrl` | Maybe Text | `redirectUrl` | No | Redirect URL |
| 8 | `vpa` | Maybe Text | `vpa` | No | VPA / UPI ID |
| 9 | `paymentMode` | Maybe Text | `paymentMode` | No | Payment mode |
| 10–25 | (additional SDK fields — all fields) | Various | Various | No | 16 additional fields as per full 25-field SdkParams type |

### 3.4 Request Enums

#### PaymentInstrument type values

| # | Constructor | JSON Value | Description |
|---|-------------|-----------|-------------|
| 1 | UPI_INTENT | `"UPI_INTENT"` | UPI deep-link intent |
| 2 | UPI_COLLECT | `"UPI_COLLECT"` | UPI VPA-based collect |
| 3 | UPI_QR | `"UPI_QR"` | UPI QR code display |
| 4 | CARD | `"CARD"` | Card payment |
| 5 | NET_BANKING | `"NET_BANKING"` | Net banking |

---

## 4. Response Structure

### 4.1 Response Body

#### PhonePeResponse (V3 Transaction — ADT)
**Type**: `PhonePeResponse` — `euler-api-txns/euler-x/src-generated/Gateway/PhonePe/Types.hs`

**Variant 1: PhonePeValidResponse**

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `success` | Bool | `success` | Yes | Whether request succeeded |
| 2 | `code` | Text | `code` | Yes | PhonePe response code |
| 3 | `message` | Text | `message` | Yes | Human-readable message |
| 4 | `data` | PhonePeResponseData | `data` | Yes | Response data object |

**data sub-fields:**

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `merchantId` | Text | `merchantId` | Yes | Merchant identifier |
| 2 | `merchantTransactionId` | Text | `merchantTransactionId` | Yes | Transaction identifier |
| 3 | `transactionId` | Text | `transactionId` | Yes | PhonePe transaction ID |
| 4 | `amount` | Int | `amount` | Yes | Transaction amount |
| 5 | `state` | Text | `state` | Yes | Transaction state string |
| 6 | `responseCode` | Maybe Text | `responseCode` | No | Response code |
| 7 | `paymentInstrument` | Maybe Value | `paymentInstrument` | No | Payment instrument used |

**Variant 2: PhonePeErrorResponse**

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `success` | Bool | `success` | Yes | Always `false` |
| 2 | `code` | Text | `code` | Yes | Error code |
| 3 | `message` | Text | `message` | Yes | Error message |
| 4 | `data` | Maybe Value | `data` | No | Optional error data |

**Field Count**: 4 fields per variant

#### PhonePeCheckResponse (V3 status — ADT)
**Type**: `PhonePeCheckResponse` — `euler-api-txns/euler-x/src-generated/Gateway/PhonePe/Types.hs`

**Variant 1: PhonePeCheckValidResponse**

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `success` | Bool | `success` | Yes | Whether request succeeded |
| 2 | `code` | Text | `code` | Yes | Response code |
| 3 | `message` | Text | `message` | Yes | Message |
| 4 | `data` | StatusData | `data` | Yes | Status data `{state, responseCode, ...}` |

**Variant 2: PhonePeCheckErrorResponse**

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `success` | Bool | `success` | Yes | Always `false` |
| 2 | `code` | Text | `code` | Yes | Error code |
| 3 | `message` | Text | `message` | Yes | Error message |

**Field Count**: 4 fields (success variant) / 3 fields (error variant)

#### PhonePeCreatePaymentValidResp (Checkout)
**Type**: `PhonePeCreatePaymentValidResp` — `euler-api-txns/euler-x/src-generated/Gateway/PhonePe/Types.hs`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `orderId` | Text | `orderId` | Yes | PhonePe order identifier |
| 2 | `state` | Text | `state` | Yes | Order state |
| 3 | `expireAt` | Maybe Int | `expireAt` | No | Order expiry timestamp |
| 4 | `redirectUrl` | Maybe Text | `redirectUrl` | No | Redirect URL for payment |
| 5 | `checkoutUrl` | Maybe Text | `checkoutUrl` | No | Checkout page URL |

**Field Count**: 5 fields

#### PhonePeRedirectionValidResp (Checkout UI)
**Type**: `PhonePeRedirectionValidResp` — `euler-api-txns/euler-x/src-generated/Gateway/PhonePe/Types.hs`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `token` | Text | `token` | Yes | Checkout token |
| 2 | `redirectUrl` | Text | `redirectUrl` | Yes | Redirect URL |

**Field Count**: 2 fields

#### OrderResponse (Checkout status)
**Type**: `OrderResponse` — `euler-api-txns/euler-x/src-generated/Gateway/PhonePe/Types.hs`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `orderId` | Text | `orderId` | Yes | Order identifier |
| 2 | `state` | Text | `state` | Yes | Order state |
| 3 | `amount` | Int | `amount` | Yes | Order amount |
| 4 | `expireAt` | Maybe Int | `expireAt` | No | Expiry timestamp |
| 5 | `paymentDetails` | [PaymentDetail] | `paymentDetails` | Yes | List of payment detail objects |

**Field Count**: 5 fields

#### PhonepeAuthTokenResponse (OAuth)
**Type**: `PhonepeAuthTokenResponse` — `euler-api-txns/euler-x/src-generated/Gateway/PhonePe/Types.hs`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `access_token` | Text | `access_token` | Yes | OAuth access token |
| 2 | `token_type` | Text | `token_type` | Yes | Token type |
| 3 | `expires_in` | Int | `expires_in` | Yes | Token TTL in seconds |
| 4 | `issued_at` | Maybe Text | `issued_at` | No | Token issuance timestamp |
| 5 | `merchant_id` | Maybe Text | `merchant_id` | No | Merchant identifier |

**Field Count**: 5 fields

#### PhonePeSubscriptionStatusResponse — ADT (gateway-side)
**Type**: `PhonePeSubscriptionStatusResponse` — `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/PhonePe/Types.hs`

**Variant 1: PhonePeSubStatusSuccess**

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `success` | Bool | `success` | Yes | Success flag |
| 2 | `code` | Text | `code` | Yes | Response code |
| 3 | `message` | Text | `message` | Yes | Message |
| 4 | `data` | SubStatusData | `data` | Yes | `{merchantId, merchantSubscriptionId, state, authRequestId, ...}` |

**Variant 2: PhonePeSubStatusError**

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `success` | Bool | `success` | Yes | Always `false` |
| 2 | `code` | Text | `code` | Yes | Error code |
| 3 | `message` | Text | `message` | Yes | Error message |

#### PhonePeDebitInitResponse — ADT (gateway-side)
**Type**: `PhonePeDebitInitResponse` — `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/PhonePe/Types.hs`

**Variant 1: PhonePeDebitInitSuccess**

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `success` | Bool | `success` | Yes | Success flag |
| 2 | `code` | Text | `code` | Yes | Response code |
| 3 | `message` | Text | `message` | Yes | Message |
| 4 | `data` | DebitInitData | `data` | Yes | `{redirectUrl, authRequestId, ...}` |

**Variant 2: PhonePeDebitInitError**

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `success` | Bool | `success` | Yes | Always `false` |
| 2 | `code` | Text | `code` | Yes | Error code |
| 3 | `message` | Text | `message` | Yes | Error message |

#### PhonePeDebitExecuteResponse — ADT (gateway-side)
**Type**: `PhonePeDebitExecuteResponse` — `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/PhonePe/Types.hs`

**Variant 1: PhonePeDebitExecuteSuccess**

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `transactionId` | Text | `transactionId` | Yes | PhonePe transaction identifier |
| 2 | `state` | Text | `state` | Yes | Transaction state |
| 3 | `responseCode` | Maybe Text | `responseCode` | No | Response code |

**Variant 2: PhonePeDebitExecuteError**

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `code` | Text | `code` | Yes | Error code |
| 2 | `message` | Text | `message` | Yes | Error message |

#### V2PhonepeSyncResponse — ADT (V2 hermes sync)
**Type**: `V2PhonepeSyncResponse` — `euler-api-txns/euler-x/src-generated/Gateway/PhonePe/Types.hs`

**Variant 1: V2SyncValidResponse**

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `success` | Bool | `success` | Yes | Success flag |
| 2 | `code` | Text | `code` | Yes | Response code |
| 3 | `message` | Text | `message` | Yes | Message |
| 4 | `data` | SyncData | `data` | Yes | Transaction status data |

**Variant 2: V2SyncTxnNotFoundResponse**

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `success` | Bool | `success` | Yes | Always `false` |
| 2 | `code` | Text | `code` | Yes | `TRANSACTION_NOT_FOUND` |
| 3 | `message` | Text | `message` | Yes | Not found message |

### 4.2 Nested Response Types

#### PhonePeWebhookResponse
**Type**: `PhonePeWebhookResponse` — `euler-api-txns/euler-x/src-generated/Gateway/PhonePe/Types.hs`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `response` | Text | `response` | Yes | Base64-encoded payload |
| 2 | `X-VERIFY` | Text (header) | N/A (header) | Yes | HMAC SHA256 signature header |

#### RecurringDebitWebhook
**Type**: `RecurringDebitWebhook` — `euler-api-txns/euler-x/src-generated/Gateway/PhonePe/Types.hs`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `merchantId` | Text | `merchantId` | Yes | Merchant identifier |
| 2 | `merchantSubscriptionId` | Text | `merchantSubscriptionId` | Yes | Subscription identifier |
| 3 | `merchantTransactionId` | Text | `merchantTransactionId` | Yes | Transaction identifier |
| 4 | `transactionId` | Text | `transactionId` | Yes | PhonePe transaction ID |
| 5 | `state` | Text | `state` | Yes | Transaction/mandate state |
| 6 | `authRequestId` | Maybe Text | `authRequestId` | No | Auth request identifier |
| 7 | `responseCode` | Maybe Text | `responseCode` | No | PhonePe response code |
| 8 | `paymentInstrument` | Maybe Value | `paymentInstrument` | No | Payment instrument details |

#### PhonePeV2UpiWebhookRequestData
**Type**: `PhonePeV2UpiWebhookRequestData` — `euler-api-txns/euler-x/src-generated/Gateway/PhonePe/Types.hs`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `merchantId` | Text | `merchantId` | Yes | Merchant identifier |
| 2 | `merchantTransactionId` | Text | `merchantTransactionId` | Yes | Transaction identifier |
| 3 | `transactionId` | Text | `transactionId` | Yes | PhonePe transaction ID |
| 4 | `amount` | Int | `amount` | Yes | Transaction amount |
| 5 | `state` | Text | `state` | Yes | Transaction state |
| 6 | `responseCode` | Maybe Text | `responseCode` | No | Response code |
| 7 | `paymentInstrument` | UpiPaymentInstrumentData | `paymentInstrument` | Yes | `{type, utr, bankTransactionId, bankId}` |

### 4.3 Response Enums

#### PhonePe State Values (wire values in `state` field)

| # | Constructor | JSON Wire Value | Description |
|---|-------------|----------------|-------------|
| 1 | — | `"PAYMENT_SUCCESS"` | Payment completed successfully |
| 2 | — | `"SUCCESS"` | Alternate success value |
| 3 | — | `"PAYMENT_PENDING"` | Payment in progress |
| 4 | — | `"PENDING"` | Alternate pending value |
| 5 | — | `"PAYMENT_ERROR"` | Payment failed |
| 6 | — | `"FAILED"` | Alternate failure value |
| 7 | — | `"ERROR"` | Alternate error value |
| 8 | — | `"PAYMENT_CANCELLED"` | Payment cancelled |
| 9 | — | `"PAYMENT_DECLINED"` | Payment declined |
| 10 | — | `"TIMED_OUT"` | Payment timed out |

---

## 5. Flows

### 5.1 Flow: checkMandateStatusAndExecuteMandate

**File**: `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/PhonePe/Flows/Mandate.hs`
**Purpose**: Check mandate status then execute recurring debit if active
**Trigger**: Gateway HTTP handler for mandate debit request

#### Steps

| Step | Action | Function | File | Details |
|------|--------|----------|------|---------|
| 1 | Receive request | `checkMandateStatusAndExecuteMandate` | `Flows/Mandate.hs` | Extract subscriptionId, transactionId, amount from MandateDebitRequest |
| 2 | Check mandate status | `checkMandateStatus` | `Flows/Mandate.hs` | GET `/subscription/status/:merchantId/:subscriptionId` |
| 3 | Route on status | — | `Flows/Mandate.hs` | ACTIVE → execute; SUSPENDED/PAUSED → MANDATE_SUSPENDED error; REVOKED/CANCELLED/EXPIRED → MANDATE_REVOKED error |
| 4 | Build execute request | — | `Flows/Mandate.hs` | Build `PhonePeDebitExecuteRequest` with transactionId, amount, subscriptionId |
| 5 | API Call → POST `/debit/execute` | `executeMandate` | `Flows/Mandate.hs` | Execute recurring debit |
| 6 | Parse response | — | `Flows/Mandate.hs` | Map PhonePe response → MandateDebitResponse with txnStatus |

#### Decision Points

| # | Condition | YES Branch | NO Branch |
|---|-----------|-----------|-----------|
| 1 | Mandate status = ACTIVE | Proceed to executeMandate (step 4) | Route to error |
| 2 | Status = SUSPENDED or PAUSED | Return MANDATE_SUSPENDED error | Check next condition |
| 3 | Status = REVOKED / CANCELLED / EXPIRED | Return MANDATE_REVOKED error | — |
| 4 | PhonePe debit execute success | Return MandateDebitResponse with txnStatus | Return error with PhonePe error code |

#### Flow Diagram

```
MandateDebitRequest
       |
       v
checkMandateStatus
GET /subscription/status/:merchantId/:subscriptionId
       |
       +-- ACTIVE -----------------------------------------------+
       |                                                          |
       +-- SUSPENDED/PAUSED --> MANDATE_SUSPENDED error           |
       |                                                          |
       +-- REVOKED/CANCELLED/EXPIRED --> MANDATE_REVOKED error    |
                                                                  v
                                               Build PhonePeDebitExecuteRequest
                                                                  |
                                                                  v
                                               POST /debit/execute (executeMandate)
                                                                  |
                                               +---------+--------+
                                               |                  |
                                            Success            Failure
                                               |                  |
                                     MandateDebitResponse     Error response
                                          (txnStatus)      (PhonePe error code)
```

---

### 5.2 Flow: initSendNotification / sendNotification

**File**: `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/PhonePe/Flows/Mandate.hs`
**Purpose**: Initiate recurring debit notification (auth challenge); `sendNotification` is a wrapper around `initSendNotification`
**Trigger**: Mandate notification initiation request

#### Steps

| Step | Action | Function | File | Details |
|------|--------|----------|------|---------|
| 1 | Build debit init request | `initSendNotification` | `Flows/Mandate.hs` | Build `PhonePeDebitInitRequest` with subscriptionId, amount, transactionId |
| 2 | API Call → POST `/debit/init` | — | `Flows/Mandate.hs` | Send notification challenge to PhonePe |
| 3 | Return challenge | — | `Flows/Mandate.hs` | Return notification challenge (redirect URL / UPI intent) |

#### Decision Points

| # | Condition | YES Branch | NO Branch |
|---|-----------|-----------|-----------|
| 1 | PhonePe responds with redirect URL | Return redirect URL | Return UPI intent deep link |

---

### 5.3 Flow: executeMandate

**File**: `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/PhonePe/Flows/Mandate.hs`
**Purpose**: Execute a recurring debit
**Trigger**: Called from `checkMandateStatusAndExecuteMandate` or directly

#### Steps

| Step | Action | Function | File | Details |
|------|--------|----------|------|---------|
| 1 | Build execute request | `executeMandate` | `Flows/Mandate.hs` | Build `PhonePeDebitExecuteRequest` |
| 2 | API Call → POST `/debit/execute` | — | `Flows/Mandate.hs` | Execute recurring debit at PhonePe |
| 3 | Parse response | — | `Flows/Mandate.hs` | Parse `PhonePeDebitExecuteResponse` → map status → return |

#### Decision Points

| # | Condition | YES Branch | NO Branch |
|---|-----------|-----------|-----------|
| 1 | PhonePe execute success | Return success with txnStatus | Return failure with error code |

---

### 5.4 Flow: revokeMandate

**File**: `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/PhonePe/Flows/Mandate.hs`
**Purpose**: Revoke/cancel a mandate subscription
**Trigger**: Mandate revocation request

#### Steps

| Step | Action | Function | File | Details |
|------|--------|----------|------|---------|
| 1 | Build cancel request | `revokeMandate` | `Flows/Mandate.hs` | Build `PhonePeCancelSubscriptionRequest` |
| 2 | API Call → POST `/subscription/cancel` | — | `Flows/Mandate.hs` | Cancel subscription at PhonePe |
| 3 | Parse response | — | `Flows/Mandate.hs` | Return success or failure |

#### Decision Points

| # | Condition | YES Branch | NO Branch |
|---|-----------|-----------|-----------|
| 1 | PhonePe cancel success | Return success | Return failure with error |

---

### 5.5 Flow: checkMandateStatus (gateway-side)

**File**: `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/PhonePe/Flows/Mandate.hs`
**Purpose**: Check current status of a mandate subscription
**Trigger**: Direct status check or called from `checkMandateStatusAndExecuteMandate`

#### Steps

| Step | Action | Function | File | Details |
|------|--------|----------|------|---------|
| 1 | API Call → GET `/subscription/status/:merchantId/:subscriptionId` | `checkMandateStatus` | `Flows/Mandate.hs` | Fetch subscription status |
| 2 | Parse response | — | `Flows/Mandate.hs` | Parse `PhonePeSubscriptionStatusResponse` |
| 3 | Map status | `mapMandateStatus` | `Flows/Mandate.hs` | Map PhonePe status string → internal `MandateStatus` |
| 4 | Return status | — | `Flows/Mandate.hs` | Return mapped MandateStatus |

#### Decision Points

| # | Condition | YES Branch | NO Branch |
|---|-----------|-----------|-----------|
| 1 | Response is PhonePeSubStatusSuccess | Map data.state → MandateStatus | Return error from PhonePeSubStatusError |

---

### 5.6 Flow: createSubscription (txns-side)

**File**: `euler-api-txns/euler-x/src-generated/Gateway/PhonePe/Flow.hs`
**Purpose**: Create a new recurring mandate/subscription
**Trigger**: Subscription creation request

#### Steps

| Step | Action | Function | File | Details |
|------|--------|----------|------|---------|
| 1 | Build subscription request | `createSubscription` | `Flow.hs` | Build `PhonePeCreateSubscriptionRequest` |
| 2 | Add auth header | `getPhonePeSalt` | `Transforms.hs` | Compute and attach `X-VERIFY` HMAC header |
| 3 | API Call → POST `/v3/recurring/subscription/create` | — | `Flow.hs` | Create subscription at PhonePe |
| 4 | Parse response | — | `Flow.hs` | Parse `PhonePeCreateSubscriptionResponse` |
| 5 | Extract fields | — | `Flow.hs` | Extract `subscriptionId`, `authRequestId`, `redirectUrl` |
| 6 | Return response | — | `Flow.hs` | Return `CreateSubscriptionResponse` |

#### Decision Points

| # | Condition | YES Branch | NO Branch |
|---|-----------|-----------|-----------|
| 1 | PhonePe creation success | Return subscriptionId + redirectUrl | Return error |

---

### 5.7 Flow: getSdkParams (+ sub-flows)

**File**: `euler-api-txns/euler-x/src-generated/Gateway/PhonePe/Flow.hs`
**Purpose**: Get SDK parameters for UPI intent/collect/QR payment
**Trigger**: SDK params request for UPI flow

#### Decision Points

| # | Condition | YES Branch | NO Branch |
|---|-----------|-----------|-----------|
| 1 | `isPhonepeIntegrationV2=True` | Route to `PhonePeV2PayRequest` (hermes) | Route to `PhonePeTransactionRequest` (mercury V3) |
| 2 | UPI sub-type = COLLECT | Sub-flow TX_2a: getSdkParamsForUpiCollect | Check intent/QR |
| 3 | UPI sub-type = INTENT | Sub-flow TX_2b: getSdkParamsForUpiIntent | Sub-flow TX_2c: getSdkParamsForUpiQr |

### 5.8 Sub-Flows

#### Sub-Flow: getSdkParamsForUpiCollect (TX_2a)

**File**: `euler-api-txns/euler-x/src-generated/Gateway/PhonePe/Flow.hs`
**Called From**: getSdkParams
**Purpose**: UPI collect via VPA

| Step | Action | Function | File |
|------|--------|----------|------|
| 1 | Build UPI collect request with VPA | `getSdkParamsForUpiCollect` | `Flow.hs` |
| 2 | POST to V2 hermes or V3 mercury (based on isPhonepeIntegrationV2) | — | `Flow.hs` |
| 3 | Parse response → return SdkParams | — | `Flow.hs` |

#### Sub-Flow: getSdkParamsForUpiIntent (TX_2b)

**File**: `euler-api-txns/euler-x/src-generated/Gateway/PhonePe/Flow.hs`
**Called From**: getSdkParams
**Purpose**: UPI intent (deep link)

| Step | Action | Function | File |
|------|--------|----------|------|
| 1 | Build `PhonePeSdkLessIntent` request (V4) or `PhonePeTransactionRequest` (V3) | `getSdkParamsForUpiIntent` | `Flow.hs` |
| 2 | POST to V4 or V3 endpoint based on integration version | — | `Flow.hs` |
| 3 | Parse response → return SdkParams with deep link | — | `Flow.hs` |

#### Sub-Flow: getSdkParamsForUpiQr (TX_2c)

**File**: `euler-api-txns/euler-x/src-generated/Gateway/PhonePe/Flow.hs`
**Called From**: getSdkParams
**Purpose**: UPI QR code

| Step | Action | Function | File |
|------|--------|----------|------|
| 1 | Build QR request | `getSdkParamsForUpiQr` | `Flow.hs` |
| 2 | POST to appropriate endpoint | — | `Flow.hs` |
| 3 | Parse response → return SdkParams with QR data | — | `Flow.hs` |

---

### 5.9 Flow: initiateTxn

**File**: `euler-api-txns/euler-x/src-generated/Gateway/PhonePe/Flow.hs`
**Purpose**: Initiate a payment transaction (Card/NB redirect or Checkout)
**Trigger**: Transaction initiation request

#### Steps

| Step | Action | Function | File | Details |
|------|--------|----------|------|---------|
| 1 | Validate txnId length | `initiateTxn` | `Flow.hs` | Guard: `isTxnlessThan38Char` — if txnId > 38 chars, return `INVALID_TRANSACTION_ID_LENGTH` immediately |
| 2 | Check feature flag | — | `Flow.hs` | Is merchant in `PHONEPE_S2S_DISABLED_MERCHANTS`? |
| 3a | S2S enabled path | `initiatePhonePeNBnCardTxn` | `Flow.hs` | Build `PhonePeNBnCardRequestBody` → POST V2 hermes pay |
| 3b | S2S disabled path (OAuth) | — | `Flow.hs` | POST `PhonepeAuthTokeRequest` → get token → POST `PhonePeCreatePaymentRequest` |
| 4 | Parse response | — | `Flow.hs` | Extract redirect URL or error |

#### Decision Points

| # | Condition | YES Branch | NO Branch |
|---|-----------|-----------|-----------|
| 1 | `txnId.length > 38` | Return `Left INVALID_TRANSACTION_ID_LENGTH` (no API call) | Continue |
| 2 | Merchant in `PHONEPE_S2S_DISABLED_MERCHANTS` | OAuth checkout flow (3b) | S2S NB/Card flow (3a) |
| 3 | OAuth token request success | Use token → POST checkout | Return Left EulerError, abort |

---

### 5.10 Flow: initiatePhonePeNBnCardTxn

**File**: `euler-api-txns/euler-x/src-generated/Gateway/PhonePe/Flow.hs`
**Purpose**: Initiate NB or Card redirect transaction
**Trigger**: Called from `initiateTxn` (S2S path)

#### Steps

| Step | Action | Function | File | Details |
|------|--------|----------|------|---------|
| 1 | Build request body | `initiatePhonePeNBnCardTxn` | `Flow.hs` | Build `PhonePeNBnCardRequestBody` with payment instrument, device info, browser 3DS2 data |
| 2 | RSA-encrypt card fields | — | `Flow.hs` | If card: encrypt `cardNumber`, `CVV`, `token` using `phonepePublicKey` |
| 3 | Add X-VERIFY header | `getPhonePeSalt` | `Transforms.hs` | Compute HMAC SHA256, attach X-VERIFY header |
| 4 | API Call → POST `/apis/hermes/pg/v1/pay` | — | `Flow.hs` | Send V2 hermes pay request |
| 5 | Parse response | — | `Flow.hs` | Extract redirect URL or error from `PhonePeNBnCardResponse` |

#### Decision Points

| # | Condition | YES Branch | NO Branch |
|---|-----------|-----------|-----------|
| 1 | Payment is card type | RSA-encrypt card fields | Skip encryption |
| 2 | PhonePe response is success | Return redirect URL | Return error |

---

### 5.11 Flow: syncWithGateway / phonePeTxnStatusSync (+ sub-flows)

**File**: `euler-api-txns/euler-x/src-generated/Gateway/PhonePe/Flow.hs`
**Purpose**: Sync transaction status with PhonePe
**Trigger**: Status sync request

#### Decision Points

| # | Condition | YES Branch | NO Branch |
|---|-----------|-----------|-----------|
| 1 | Is checkout flow | Checkout status (TX_5d) | Proceed to V3/V4 decision |
| 2 | `isPhonepeIntegrationV2=True` | V4 sync (TX_5b) or V2 hermes sync (TX_5c) | V3 sync (TX_5a) |

#### Sub-Flows

**TX_5a: V3 sync**

| Step | Action | Function | File |
|------|--------|----------|------|
| 1 | API Call → GET `/v3/transaction/:mid/:tid/status` | — | `Flow.hs` |
| 2 | Parse `PhonePeCheckResponse` → map state → return TxnStatus | — | `Flow.hs` |

**TX_5b: V4 sync**

| Step | Action | Function | File |
|------|--------|----------|------|
| 1 | API Call → GET `/v4/transaction/:mid/:tid/status` | — | `Flow.hs` |
| 2 | Parse `PhonePeV4CheckResponse` → map state → return TxnStatus | — | `Flow.hs` |

**TX_5c: V2 hermes sync**

| Step | Action | Function | File |
|------|--------|----------|------|
| 1 | Add `X-VERIFY` + `X-MERCHANT-ID` (makePhonePeNewSyncHeader) | `makePhonePeNewSyncHeader` | `Transforms.hs` |
| 2 | API Call → GET `/apis/hermes/pg/v1/status/:mid/:txnid` | — | `Flow.hs` |
| 3 | Parse `V2PhonepeSyncResponse` → return TxnStatus | — | `Flow.hs` |

**TX_5d: Checkout status sync**

| Step | Action | Function | File |
|------|--------|----------|------|
| 1 | API Call → GET `/checkout/v2/order/:tid/status` | — | `Flow.hs` |
| 2 | Parse `OrderResponse` → return TxnStatus | — | `Flow.hs` |

---

### 5.12 Flow: initRefundRequest

**File**: `euler-api-txns/euler-x/src-generated/Gateway/PhonePe/Flow.hs`
**Purpose**: Initiate a refund
**Trigger**: Refund request

#### Decision Points

| # | Condition | YES Branch | NO Branch |
|---|-----------|-----------|-----------|
| 1 | IRCTC flag set | POST to IRCTC_Refund endpoint | Check integration version |
| 2 | `isPhonepeIntegrationV2=True` | POST `/apis/hermes/pg/v1/refund` (V2) | POST `/v3/credit/backToSource` (V3) |

---

### 5.13 Flow: initPhonepeRefundSync

**File**: `euler-api-txns/euler-x/src-generated/Gateway/PhonePe/Flow.hs`
**Purpose**: Sync refund status
**Trigger**: Refund status check

#### Decision Points

| # | Condition | YES Branch | NO Branch |
|---|-----------|-----------|-----------|
| 1 | IRCTC flag set | GET IRCTC_RefundSync endpoint | Check V2 flag |
| 2 | `isPhonepeIntegrationV2=True` | GET V2 hermes refund status | GET V3 refund status |

---

### 5.14 Flow: extractWebHookEvent (+ sub-flows)

**File**: `euler-api-txns/euler-x/src-generated/Gateway/PhonePe/Flow.hs`
**Purpose**: Parse and verify incoming webhook from PhonePe
**Trigger**: Incoming webhook HTTP request from PhonePe

#### Steps

| Step | Action | Function | File | Details |
|------|--------|----------|------|---------|
| 1 | Decode payload | `extractWebHookEvent` | `Flow.hs` | Base64-decode the webhook response field |
| 2 | Verify signature | `verifyWebhookResponse` | `Flow.hs` | Verify `X-VERIFY` HMAC signature |
| 3 | Parse JSON | — | `Flow.hs` | Parse decoded payload → `PhonePeWebhookResponse` |
| 4 | Map status | — | `Flow.hs` | Map PhonePe status string → internal `TxnStatus` |

#### Decision Points

| # | Condition | YES Branch | NO Branch |
|---|-----------|-----------|-----------|
| 1 | Base64 decode succeeds | Proceed to HMAC verification | Return `Left "INVALID_WEBHOOK_PAYLOAD"` |
| 2 | HMAC verification passes | Proceed to JSON parse | Return `Left "WEBHOOK_SIGNATURE_MISMATCH"` (webhook rejected) |
| 3 | JSON parse succeeds | Map status, return event | Return `Left "WEBHOOK_PARSE_ERROR"` |

---

### 5.15 Flow: verifyWebhookResponse

**File**: `euler-api-txns/euler-x/src-generated/Gateway/PhonePe/Flow.hs`
**Purpose**: Verify webhook HMAC signature before processing
**Trigger**: Called from `extractWebHookEvent`

| Step | Action | Function | File | Details |
|------|--------|----------|------|---------|
| 1 | Extract X-VERIFY header | `verifyWebhookResponse` | `Flow.hs` | Get HMAC from incoming webhook headers |
| 2 | Recompute HMAC | — | `Flow.hs` | sha256(base64Body + apiPath + saltKey) + "###" + keyIndex |
| 3 | Compare | — | `Flow.hs` | If match: accept; else: reject |

---

### 5.16 Flow: verifyMandateStatusWebhook

**File**: `euler-api-txns/euler-x/src-generated/Gateway/PhonePe/Flow.hs`
**Purpose**: Process mandate status change webhook
**Trigger**: Incoming mandate status webhook from PhonePe

| Step | Action | Function | File | Details |
|------|--------|----------|------|---------|
| 1 | Decode and verify | `verifyMandateStatusWebhook` | `Flow.hs` | Same verification as extractWebHookEvent |
| 2 | Parse `RecurringDebitWebhook` | — | `Flow.hs` | Extract mandate status fields |
| 3 | Update mandate status | — | `Flow.hs` | Map state → internal MandateStatus, update DB |

---

### 5.17 Flow: verifyVpa

**File**: `euler-api-txns/euler-x/src-generated/Gateway/PhonePe/Flow.hs`
**Purpose**: Verify if a VPA (UPI ID) is valid
**Trigger**: VPA validation request

#### Steps

| Step | Action | Function | File | Details |
|------|--------|----------|------|---------|
| 1 | Build VPA validate request | `verifyVpa` | `Flow.hs` | Build request with `{vpa}` |
| 2 | API Call → POST `/v3/vpa/validate` or `/apis/hermes/pg/v1/vpa/validate` | — | `Flow.hs` | V1 or V2 based on integration version |
| 3 | Parse response | — | `Flow.hs` | Parse `PhonePeV2VerifyVpaResponse` |
| 4 | Return result | — | `Flow.hs` | Return `isVpaValid`, `payerAccountName` |

#### Decision Points

| # | Condition | YES Branch | NO Branch |
|---|-----------|-----------|-----------|
| 1 | `isPhonepeIntegrationV2=True` | POST V2 hermes VPA validate | POST V3 mercury VPA validate |
| 2 | Response is PhonePeVerifyVpaFailResponse | Return isValid=false (no error thrown) | Return isValid=true with payerAccountName |

---

### 5.18 Flow: initiateCaptureRequest

**File**: `euler-api-txns/euler-x/src-generated/Gateway/PhonePe/Flow.hs`
**Purpose**: Capture a pre-authorized payment
**Trigger**: Pre-auth capture request

#### Steps

| Step | Action | Function | File | Details |
|------|--------|----------|------|---------|
| 1 | Build capture request | `initiateCaptureRequest` | `Flow.hs` | Build `captureRequest` with originalTransactionId, amount |
| 2 | API Call → POST `/v3/auth/capture` | — | `Flow.hs` | Capture pre-auth at PhonePe |
| 3 | Parse response | — | `Flow.hs` | Parse `PhonePeCaptureResponse` → return result |

---

### 5.19 Flow: initiateVoidRequest

**File**: `euler-api-txns/euler-x/src-generated/Gateway/PhonePe/Flow.hs`
**Purpose**: Void/cancel a pre-authorized payment
**Trigger**: Pre-auth void request

#### Steps

| Step | Action | Function | File | Details |
|------|--------|----------|------|---------|
| 1 | Build cancel auth request | `initiateVoidRequest` | `Flow.hs` | Build `cancelAuthRequest` with originalTransactionId |
| 2 | API Call → POST `/v3/auth/cancel` | — | `Flow.hs` | Void/cancel pre-auth at PhonePe |
| 3 | Parse response | — | `Flow.hs` | Parse `PhonePeCancelAuthResponse` → return result |

---

### 5.20 Flow: checkMandateStatus (txns-side)

**File**: `euler-api-txns/euler-x/src-generated/Gateway/PhonePe/Flow.hs`
**Purpose**: Check mandate status from txns service
**Trigger**: Mandate status check request

#### Steps

| Step | Action | Function | File | Details |
|------|--------|----------|------|---------|
| 1 | API Call → GET `/v3/recurring/subscription/status/:merchantId/:subscriptionId` | `checkMandateStatus` | `Flow.hs` | Fetch subscription status |
| 2 | Parse response | — | `Flow.hs` | Map status string → internal `MandateStatus` |

---

### 5.21 Wallet Flows

**File**: `euler-api-txns/euler-x/src-generated/Gateway/PhonePe/Flow.hs`

#### triggerOTP

| Step | Action | File | Details |
|------|--------|------|---------|
| 1 | API Call → POST `/v3/merchant/otp/send` | `Flow.hs` | Send OTP for wallet linking with `{merchantId, mobileNumber}` |
| 2 | Parse `PhonePeTriggerOtpResponse` | `Flow.hs` | Return OTP trigger status |

#### linkOtp / verifyOtp

| Step | Action | File | Details |
|------|--------|------|---------|
| 1 | API Call → POST `/v3/merchant/otp/verify` | `Flow.hs` | Verify OTP with `{merchantId, mobileNumber, otp}` |
| 2 | Parse `PhonePeVerifyOtpResponse` | `Flow.hs` | Return verification status |

#### getWalletBalance

| Step | Action | File | Details |
|------|--------|------|---------|
| 1 | API Call → GET `/v3/wallet/balance` | `Flow.hs` | Fetch balance with merchantId + mobileNumber |
| 2 | Parse `PhonePeBalanceCheckResponse` | `Flow.hs` | Return `{balance, walletBalance}` |

#### delinkWallet

| Step | Action | File | Details |
|------|--------|------|---------|
| 1 | API Call → POST `/v3/merchant/token/unlink` | `Flow.hs` | Delink wallet with `{merchantId, mobileNumber}` |
| 2 | Parse `PhonePeDelinkResponse` | `Flow.hs` | Return delink status |

#### directDebit

| Step | Action | File | Details |
|------|--------|------|---------|
| 1 | API Call → POST `/v3/wallet/debit` | `Flow.hs` | Direct wallet debit |
| 2 | Parse `PhonePeDirectDebitResponse` | `Flow.hs` | Return debit status |

#### initiateTopup

| Step | Action | File | Details |
|------|--------|------|---------|
| 1 | API Call → POST `/v3/wallet/topup` | `Flow.hs` | Wallet top-up |
| 2 | Parse `PhonePeTopupResponse` | `Flow.hs` | Return topup status |

---

### 5.22 Flow: sendCollectRequest

**File**: `euler-api-txns/euler-x/src-generated/Gateway/PhonePe/Flow.hs`
**Purpose**: Send UPI collect request to customer's VPA
**Trigger**: UPI collect payment initiation

| Step | Action | File | Details |
|------|--------|------|---------|
| 1 | Build collect request | `Flow.hs` | Include VPA, amount, transactionId |
| 2 | POST to UPI collect endpoint (V3 mercury collect) | `Flow.hs` | Send collect request |
| 3 | Parse response | `Flow.hs` | Return collect status / deep-link |

---

### 5.23 Data Transformations

| # | From | To | Function | File | Logic |
|---|------|----|----------|------|-------|
| 1 | Raw request body | Base64-encoded body | — | `Transforms.hs` | Standard base64 encoding of JSON body |
| 2 | base64Body + apiPath + saltKey | HMAC SHA256 hex | `getPhonePeSalt` / checksum fn | `Transforms.hs` L699–707, L1499–1500 | `sha256(concat)` → hex string |
| 3 | HMAC hex + keyIndex | X-VERIFY header value | — | `Transforms.hs` | `hmacHex + "###" + keyIndex` |
| 4 | PhonePe `state` string | Internal `TxnStatus` | — | `Flow.hs` | See Section 7 mapping table |
| 5 | PhonePe mandate `state` string | Internal `MandateStatus` | `mapMandateStatus` | `Flows/Mandate.hs` | See Section 7 mapping table |
| 6 | Plain card number | `encryptedCardNumber` | RSA encrypt | `Flow.hs` | RSA public key from `phonepePublicKey` |
| 7 | Plain CVV | `encryptedCvv` | RSA encrypt | `Flow.hs` | RSA public key from `phonepePublicKey` |
| 8 | Plain token | `encryptedToken` | RSA encrypt | `Flow.hs` | RSA public key from `phonepePublicKey` |
| 9 | OAuth access_token | `O-Bearer {token}` header | — | `Transforms.hs` L1856–1879 | String concatenation |
| 10 | Redirect URL string | payment_token | — | `Transforms.hs` L1856–1879 | Split on `"token="`, take second part |
| 11 | payment_token | `Bearer {token}` + `x-auth-token` headers | — | `Transforms.hs` L1856–1879 | String formatting |
| 12 | deviceInfo | X-BROWSER-FINGERPRINT | — | `Transforms.hs` | `sha256(deviceInfo)` |
| 13 | V2 sync path + merchantId + transactionId + saltKey | X-VERIFY (sync) | `makePhonePeNewSyncHeader` | `Transforms.hs` | `sha256(apiPath + merchantId + "/" + tid + saltKey) + "###" + keyIndex` |

---

## 6. Error Handling

### 6.1 API Call Error Handling

| # | Error Type | Handling | Fallback | File |
|---|-----------|----------|----------|------|
| 1 | HTTP call returns `Left (error)` | Log error, return `EulerError` with PhonePe error message | None — propagated to caller | `Flow.hs` |
| 2 | HTTP 4xx error response | Parse `PhonePeErrorResponse { success=false, code, message }` → propagate as gateway error | None | `Flow.hs` |
| 3 | HTTP 5xx error | Treat as `GATEWAY_ERROR` → return `TxnStatus=AuthorizationFailed` | None | `Flow.hs` |
| 4 | Connection failure | Return `Left "Gateway connection failed"` | None | `Flow.hs` |
| 5 | Timeout (408/504) | Return `TxnStatus=Pending` (async resolution possible) | None — merchant must sync | `Flow.hs` |
| 6 | `txnId > 38 chars` (`isTxnlessThan38Char` guard) | Return `Left INVALID_TRANSACTION_ID_LENGTH` immediately, no API call made | None | `Flow.hs` |
| 7 | OAuth token request failure | Return `Left EulerError`, entire checkout flow aborted | None | `Flow.hs` |
| 8 | Webhook base64 decode failure | Return `Left "INVALID_WEBHOOK_PAYLOAD"` | None — webhook rejected | `Flow.hs` |
| 9 | Webhook HMAC verification failure | Return `Left "WEBHOOK_SIGNATURE_MISMATCH"` | None — webhook rejected | `Flow.hs` |
| 10 | Webhook JSON parse failure | Return `Left "WEBHOOK_PARSE_ERROR"` | None — webhook rejected | `Flow.hs` |
| 11 | VPA verification failure | `PhonePeVerifyVpaFailResponse` → return `isValid=false` (no error thrown) | None | `Flow.hs` |
| 12 | Insufficient wallet balance | Code `INSUFFICIENT_BALANCE` → return wallet error | None | `Flow.hs` |
| 13 | OTP mismatch | Code `INVALID_OTP` → return OTP error | None | `Flow.hs` |
| 14 | Wallet account not linked | Code `ACCOUNT_NOT_FOUND` → return link error | None | `Flow.hs` |
| 15 | Capture on non-authorized payment | Code `PAYMENT_NOT_AUTHORIZED` → return error | None | `Flow.hs` |
| 16 | Double capture attempt | Code `TRANSACTION_ALREADY_COMPLETED` → return error | None | `Flow.hs` |
| 17 | Mandate SUSPENDED/PAUSED | Return `MANDATE_SUSPENDED` error (no execute call made) | None | `Flows/Mandate.hs` |
| 18 | Mandate REVOKED/CANCELLED/EXPIRED | Return `MANDATE_REVOKED` error (no execute call made) | None | `Flows/Mandate.hs` |

### 6.2 HTTP Status Code Handling

| HTTP Status | Handling | Response to Caller |
|-------------|----------|--------------------|
| 200 | Parse response body as ADT success variant | Success response with transaction/subscription data |
| 400 | Parse as `PhonePeErrorResponse` → return error with `code` + `message` | `Left EulerError` with PhonePe error code and message |
| 401 | Auth failure → log + return `AUTHENTICATION_FAILED` error | `Left EulerError` with auth failure message |
| 404 | Transaction not found → return NOT_FOUND / `TxnStatus=AuthorizationFailed` | `Left EulerError` or `TxnStatus=AuthorizationFailed` |
| 408/504 | Timeout → return `TxnStatus=Pending` | `TxnStatus=Pending` (payment may complete asynchronously) |
| 500 | Server error → return `GATEWAY_ERROR` | `Left EulerError` with GATEWAY_ERROR |
| Connection Failure | Return `GATEWAY_UNREACHABLE` | `Left "Gateway connection failed"` |

### 6.3 Timeout & Retry

- **Timeout Mechanism**: Handled at generic HTTP client layer, not connector-specific code
- **Default Timeout**: Not configured in connector-specific code
- **Retry Enabled**: No
- **Max Retries**: N/A
- **Retry Strategy**: N/A — no retry configured at connector level

### 6.4 Error Response Type

**Type**: `PhonePeErrorResponse` — `euler-api-txns/euler-x/src-generated/Gateway/PhonePe/Types.hs`

| # | Field Name | Type | JSON Key | Description |
|---|------------|------|----------|-------------|
| 1 | `success` | Bool | `success` | Always `false` for errors |
| 2 | `code` | Text | `code` | PhonePe error code (e.g., `PAYMENT_ERROR`) |
| 3 | `message` | Text | `message` | Human-readable error message |
| 4 | `data` | Maybe Value | `data` | Optional additional error data |

**Type**: `PhonePeV2ErrorResponse` — `euler-api-txns/euler-x/src-generated/Gateway/PhonePe/Types.hs`

| # | Field Name | Type | JSON Key | Description |
|---|------------|------|----------|-------------|
| 1 | `success` | Bool | `success` | Always `false` for errors |
| 2 | `code` | Text | `code` | V2 error code |
| 3 | `message` | Text | `message` | Human-readable error message |
| 4 | `data` | Maybe PhonepeV2Data | `data` | Optional V2 error data object |

**Type**: `PhonePeCheckErrorResponse` — `euler-api-txns/euler-x/src-generated/Gateway/PhonePe/Types.hs`

| # | Field Name | Type | JSON Key | Description |
|---|------------|------|----------|-------------|
| 1 | `success` | Bool | `success` | Always `false` |
| 2 | `code` | Text | `code` | Error code |
| 3 | `message` | Text | `message` | Error message |

### 6.5 Error Code Mappings

| # | Source Error (PhonePe code) | Target Error | HTTP Status | Retry-able | Description |
|---|----------------------------|-------------|-------------|-----------|-------------|
| 1 | `PAYMENT_SUCCESS` | Charged | 200 | No | Payment completed successfully |
| 2 | `PAYMENT_ERROR` | AuthorizationFailed | 200/400 | No | General payment failure |
| 3 | `PAYMENT_PENDING` | Pending | 200 | Yes (sync later) | Payment in progress |
| 4 | `TRANSACTION_NOT_FOUND` | AuthorizationFailed / NOT_FOUND | 404 | No | Transaction ID not found at PhonePe |
| 5 | `AUTHORIZATION_FAILED` | AUTHENTICATION_FAILED | 401 | No | Auth credentials invalid |
| 6 | `INVALID_TRANSACTION_ID` | INVALID_TRANSACTION_ID_LENGTH | 400 | No | Transaction ID format/length invalid |
| 7 | `INSUFFICIENT_BALANCE` | wallet error | 200/400 | No | Wallet balance too low |
| 8 | `INVALID_OTP` | OTP error | 200/400 | Yes (retry OTP) | OTP mismatch |
| 9 | `ACCOUNT_NOT_FOUND` | link error | 200/400 | No | Wallet/account not linked |
| 10 | `PAYMENT_NOT_AUTHORIZED` | AuthorizationFailed | 200/400 | No | Capture on non-authorized payment |
| 11 | `TRANSACTION_ALREADY_COMPLETED` | AuthorizationFailed | 200/400 | No | Double capture attempt |
| 12 | `TIMED_OUT` | Pending | 408/504 | Yes (sync later) | Request timed out |

---

## 7. Status Mappings

### 7.1 TxnStatus (Internal)

**Source**: `euler-api-txns/dbTypes/src-generated/EC/TxnDetail/Types.hs:285-311`
**Project**: euler-api-txns

| # | Constructor | JSON Wire Value | Description |
|---|-------------|----------------|-------------|
| 1 | Started | `"STARTED"` | Transaction started |
| 2 | AuthorizationFailed | `"AUTHORIZATION_FAILED"` | Authorization failed |
| 3 | JuspayDeclined | `"JUSPAY_DECLINED"` | Declined by Juspay |
| 4 | Pending | `"PENDING"` | Pending resolution |
| 5 | Failure | `"FAILURE"` | General failure |
| 6 | Charged | `"CHARGED"` | Payment successful |
| 7 | Voided | `"VOIDED"` | Pre-auth voided |
| 8 | Authorizing | `"AUTHORIZING"` | In-progress authorization |
| 9 | Authorized | `"AUTHORIZED"` | Pre-auth authorized |
| 10 | CODInitiated | `"COD_INITIATED"` | COD payment initiated |
| 11 | VoiceInitiated | `"VOICE_INITIATED"` | Voice payment initiated |
| 12 | AutoRefunded | `"AUTO_REFUNDED"` | Auto-refunded |
| 13 | PartialCharged | `"PARTIAL_CHARGED"` | Partially charged |
| 14 | ToBeCharged | `"TO_BE_CHARGED"` | Awaiting charge |
| 15 | NbInitiated | `"NB_INITIATED"` | Net banking initiated |
| 16 | ViesInitiated | `"VIES_INITIATED"` | VIES initiated |
| 17 | InvoiceExpired | `"INVOICE_EXPIRED"` | Invoice expired |
| 18 | Declined | `"DECLINED"` | Declined |
| 19 | AttemptedCharged | `"ATTEMPTED_CHARGED"` | Attempted charge |
| 20 | Dropped | `"DROPPED"` | Dropped |
| 21 | NbConfirmationPending | `"NB_CONFIRMATION_PENDING"` | NB confirmation pending |
| 22 | JuspayPending | `"JUSPAY_PENDING"` | Juspay-side pending |
| 23 | PendingVbv | `"PENDING_VBV"` | Pending VBV |
| 24 | CODConfirmationPending | `"COD_CONFIRMATION_PENDING"` | COD confirmation pending |

### 7.2 MandateStatus (Internal)

**Source**: `euler-api-txns/dbTypes/src-generated/EC/Mandate/Types.hs:332-344`
**Project**: euler-api-txns

| # | Constructor | JSON Wire Value | Description |
|---|-------------|----------------|-------------|
| 1 | MandateCreated | `"CREATED"` | Mandate created |
| 2 | MandateActive | `"ACTIVE"` | Mandate active |
| 3 | MandatePaused | `"PAUSED"` | Mandate paused |
| 4 | MandateRevoked | `"REVOKED"` | Mandate revoked |
| 5 | MandateCancelled | `"CANCELLED"` | Mandate cancelled |
| 6 | MandateExpired | `"EXPIRED"` | Mandate expired |
| 7 | MandateFailed | `"FAILED"` | Mandate failed |
| 8 | MandateConfirmed | `"CONFIRMED"` | Mandate confirmed |
| 9 | MandateInactive | `"INACTIVE"` | Mandate inactive |
| 10 | MandatePending | `"PENDING"` | Mandate pending |

### 7.3 RefundStatus (Internal)

**Source**: `euler-api-txns/dbTypes/src-generated/EC/Refund/Types.hs:85-91`
**Project**: euler-api-txns

| # | Constructor | JSON Wire Value | Description |
|---|-------------|----------------|-------------|
| 1 | RefundSuccess | `"SUCCESS"` | Refund completed |
| 2 | RefundFailed | `"FAILED"` | Refund failed |
| 3 | RefundPending | `"PENDING"` | Refund in progress |
| 4 | RefundManualReview | `"MANUAL_REVIEW"` | Requires manual review |

### 7.4 Status Mapping Table — PhonePe Transaction State → Internal TxnStatus

**Direction**: PhonePe `state` string → Internal `TxnStatus`
**Mapping File**: `euler-api-txns/euler-x/src-generated/Gateway/PhonePe/Flow.hs`

| # | Source Status (PhonePe) | Target Status (Internal) | Condition |
|---|------------------------|--------------------------|-----------|
| 1 | `"PAYMENT_SUCCESS"` | Charged | Exact match |
| 2 | `"SUCCESS"` | Charged | Exact match |
| 3 | `"PAYMENT_PENDING"` | Pending | Exact match |
| 4 | `"PENDING"` | Pending | Exact match |
| 5 | `"PAYMENT_ERROR"` | AuthorizationFailed | Exact match |
| 6 | `"FAILED"` | AuthorizationFailed | Exact match |
| 7 | `"ERROR"` | AuthorizationFailed | Exact match |
| 8 | `"PAYMENT_CANCELLED"` | AuthorizationFailed | Exact match |
| 9 | `"PAYMENT_DECLINED"` | AuthorizationFailed | Exact match |
| 10 | `"TIMED_OUT"` | Pending | Exact match |
| 11 | (any unknown value) | AuthorizationFailed | Default fallback |

### 7.5 Status Mapping Table — PhonePe Mandate State → Internal MandateStatus

**Direction**: PhonePe mandate `state` string → Internal `MandateStatus`
**Mapping File**: `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/PhonePe/Flows/Mandate.hs` (`mapMandateStatus`)

| # | Source Status (PhonePe) | Target Status (Internal) | Condition |
|---|------------------------|--------------------------|-----------|
| 1 | `"CREATED"` | MandateCreated | Exact match |
| 2 | `"ACTIVE"` | MandateActive | Exact match |
| 3 | `"SUSPENDED"` | MandatePaused | Exact match |
| 4 | `"REVOKED"` | MandateRevoked | Exact match |
| 5 | `"CANCELLED"` | MandateCancelled (or MandateRevoked depending on source) | Exact match |
| 6 | `"PAUSED"` | MandatePaused | Exact match |
| 7 | `"EXPIRED"` | MandateExpired | Exact match |
| 8 | `"FAILED"` | MandateFailed | Exact match |
| 9 | `"CANCEL_IN_PROGRESS"` | MandateCancelled | Exact match |

---

## 8. Payment Methods

### 8.1 Supported Payment Method Types

| # | PaymentMethodType | EcPaymentMethods Variants | Example Payment Methods | Gateway Code Resolution | Notes |
|---|-------------------|--------------------------|------------------------|------------------------|-------|
| 1 | UPI | UPI_COLLECT, UPI_PAY (UPI_INTENT), UPI_QR | PhonePe UPI, any UPI ID | Based on sub-type (collect/intent/QR) | isPhonepeIntegrationV2 determines V2 vs V3 endpoint |
| 2 | WALLET | WALLET (PhonePe) | PhonePe Wallet | Direct wallet debit/topup/link OTP | Requires mobile number; OTP-based linking |
| 3 | CARD | CARD | Credit/Debit cards | RSA-encrypted fields sent to V2 hermes | Card fields encrypted with `phonepePublicKey`; V2 hermes endpoint |
| 4 | NB | NB (bank code) | Net banking (all banks) | Bank code in paymentInstrument | V2 hermes NB redirect |
| 5 | PRE_AUTH | — | Pre-authorized card | auth/capture/void flow | Auth then Capture or Cancel via separate API calls |
| 6 | MANDATE/RECURRING | — | UPI recurring mandate | Subscription create → auth init → debit execute | Two services involved: txns for create/auth, gateway for execute |

### 8.2 Payment Method Transformation Chain

| Step | Operation | Function | File | Input | Output |
|------|-----------|----------|------|-------|--------|
| 1 | Extract payment type from request | — | `Flow.hs` | PaymentInstrument.type string | UPI/WALLET/CARD/NB/PRE_AUTH/RECURRING |
| 2 | Route to sub-flow | — | `Flow.hs` | PaymentMethodType + sub-type flags | Specific request builder function |
| 3 | Build payment instrument | — | `Transforms.hs` | Source payment data | `PhonePeNBPaymentInstrument` / `PhonePeCardPaymentInstrument` / UPI instrument |
| 4 | Encrypt if card | RSA encrypt | `Flow.hs` | Plain card fields | Encrypted card fields (`encryptedCardNumber`, `encryptedCvv`, `encryptedToken`) |

### 8.3 Payment Method Enums

#### PaymentMethodType — `euler-api-txns/euler-x/src-generated/Gateway/PhonePe/Types.hs`

| # | Constructor | Carries Data | Description |
|---|-------------|-------------|-------------|
| 1 | WALLET | No | PhonePe wallet payment |
| 2 | UPI | No | UPI payment (collect/intent/QR) |
| 3 | NB | No | Net banking |
| 4 | CARD | No | Card payment (credit/debit) |
| 5 | PAYLATER | No | Pay later / BNPL |
| 6 | CONSUMER_FINANCE | No | Consumer finance |
| 7 | REWARD | No | Reward points |
| 8 | CASH | No | Cash payment |
| 9 | AADHAAR | No | Aadhaar-based payment |
| 10 | PAPERNACH | No | Paper NACH mandate |
| 11 | PAN | No | PAN-based payment |
| 12 | MERCHANT_CONTAINER | No | Merchant container |
| 13 | Virtual_Account | No | Virtual account |
| 14 | OTC | No | Over the counter |
| 15 | RTP | No | Real-time payment |
| 16 | CRYPTO | No | Cryptocurrency |
| 17 | CARD_QR | No | Card QR code |
| 18 | CBDC | No | Central bank digital currency |
| 19 | UNKNOWN | Text | Fallback for unrecognized types |

#### EcPaymentMethods — `euler-api-txns/euler-x/src-generated/Gateway/PhonePe/Types.hs`

| # | Constructor | Carries Data | Description |
|---|-------------|-------------|-------------|
| 1 | UPI_COLLECT | No | UPI collect request (VPA-based) |
| 2 | UPI_PAY | No | UPI pay/push (intent) |
| 3 | UPI_QR | No | UPI QR code display |
| 4 | UPI_INAPP | No | UPI in-app |
| 5 | CARD | Text (card brand) | Card payment with specific brand |
| 6 | NB | Text (bank code) | Net banking with specific bank |
| 7 | WALLET | Text (wallet name) | Wallet with specific provider (PhonePe) |
| 8 | CONSUMER_FINANCE | Text (provider) | Consumer finance with specific provider |
| 9 | AADHAAR | Text (identifier) | Aadhaar-based with identifier |
| 10 | PAN | Text (identifier) | PAN-based with identifier |
| 11 | RTP | Text (identifier) | Real-time payment with identifier |

### 8.4 DB Tables

#### payment_method

| # | Column | Type | Description |
|---|--------|------|-------------|
| 1 | id | Maybe Int | Primary key |
| 2 | name | Text | Payment method name (e.g., "VISA") |
| 3 | _type | Text | Payment method type (e.g., "CARD") |
| 4 | description | Text | Human-readable description |
| 5 | sub_type | Maybe Text | Sub-type (e.g., "CREDIT", "DEBIT") |
| 6 | juspay_bank_code_id | Maybe Int | FK to bank code table |
| 7 | display_name | Maybe Text | Display name |
| 8 | nick_name | Maybe Text | Short name |
| 9 | dsl | Maybe Text | DSL configuration |

#### gateway_payment_method

| # | Column | Type | Description |
|---|--------|------|-------------|
| 1 | _id | Maybe Text | Primary key |
| 2 | payment_method_id | Int | FK to payment_method.id |
| 3 | gateway | Text | Gateway identifier (`PHONEPE`) |
| 4 | gateway_code | Text | Gateway-specific payment method code |
| 5 | supported_currencies | Maybe Text | Comma-separated currency codes |

### 8.5 Payment Method Fields in Request/Response

**Request fields**:

| # | Field | JSON Key | Type | Present | Description |
|---|-------|----------|------|---------|-------------|
| 1 | payment_method_type | `type` (in paymentInstrument) | Text | Yes | Maps to UPI_INTENT / UPI_COLLECT / UPI_QR / CARD / NB / etc. |
| 2 | payment_method | `targetApp` / `bankId` / card brand | Maybe Text | Yes | Specific instrument (e.g., "PHONEPE", "HDFC", "VISA") |

**Response fields**:

| # | Field | JSON Key | Type | Present | Description |
|---|-------|----------|------|---------|-------------|
| 1 | payment_method_type | `paymentInstrument.type` | Maybe Text | Yes | Echoed back — instrument type used |
| 2 | payment_method | `paymentInstrument` (nested) | Maybe Text | Yes | Echoed back — instrument details (UTR, bank ID, etc.) |

---

## 9. Completeness Verification

| Check | Result |
|-------|--------|
| Request fields in source | 100+ (across 20+ request types) |
| Request fields documented | Yes — all major request types documented with field tables |
| Response fields in source | 50+ (across 15+ response ADTs) |
| Response fields documented | Yes — all major response ADTs documented with variants |
| All nested types expanded | Yes — DeviceContext, PaymentInstrument, PaymentFlow, SdkParams, webhook types |
| All enum values listed | Yes — TxnStatus (24), MandateStatus (10), RefundStatus (4), PaymentMethodType (19), EcPaymentMethods (11) |
| All flows documented | Yes — 6 gateway flows + 19 txns flows (25 total) |
| All error paths documented | Yes — 18 error handling cases in Section 6.1 |
| All status values listed | Yes — PhonePe wire values, TxnStatus, MandateStatus, RefundStatus |
| Payment methods documented | Yes |
| Payment method enums complete | Yes |
| Payment method DB tables documented | Yes |
| Missing items | none |

---

## 10. Source File References

| # | File | Lines Read | Purpose |
|---|------|-----------|---------|
| 1 | `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/PhonePe/Routes.hs` | Full | Base URL resolution logic (`phonePeBaseUrl`), gateway-side API routes |
| 2 | `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/PhonePe/Flows/Mandate.hs` | Full | Gateway-side mandate flows: checkMandateStatusAndExecuteMandate, initSendNotification, sendNotification, executeMandate, revokeMandate, checkMandateStatus |
| 3 | `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/PhonePe/Types.hs` | Full | Gateway-side request/response types: PhonePeCreateSubscriptionRequest, PhonePeDebitInitRequest, PhonePeDebitExecuteRequest, PhonePeCancelSubscriptionRequest, PhonePeSubscriptionStatusResponse, PhonePeDebitInitResponse, PhonePeDebitExecuteResponse |
| 4 | `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/PhonePe/Transforms.hs` | Full | Gateway-side auth header construction |
| 5 | `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/PhonePe/Flows.hs` | Full | Gateway-side flow orchestration |
| 6 | `euler-api-txns/euler-x/src-generated/Gateway/PhonePe/Endpoints.hs` | Full | All txns-side endpoint URLs (UAT + PROD for all 34 endpoint types) |
| 7 | `euler-api-txns/euler-x/src-generated/Gateway/PhonePe/Flow.hs` | Full | All 19 txns-side flows: createSubscription, getSdkParams, initiateTxn, initiatePhonePeNBnCardTxn, syncWithGateway, initRefundRequest, initPhonepeRefundSync, extractWebHookEvent, verifyWebhookResponse, verifyMandateStatusWebhook, sendCollectRequest, verifyVpa, initiateCaptureRequest, initiateVoidRequest, checkMandateStatus, wallet flows |
| 8 | `euler-api-txns/euler-x/src-generated/Gateway/PhonePe/Transforms.hs` | L699–707, L1499–1500, L1856–1879 | HMAC auth: `getPhonePeSalt`, `getCheckSumforV2API`, `makePhonePeNewSyncHeader`; OAuth flow |
| 9 | `euler-api-txns/euler-x/src-generated/Gateway/PhonePe/Types.hs` | Full | All txns-side request/response types: PhonePeTransactionRequest, PhonePeSdkLessIntent, PhonepeCheckTransactionStatusRequest, PhonepeV4CheckTransactionStatusRequest, PhonepeRefundRequest, TriggerOtp, VerifyOtp, BalanceCheck, TopupRequest, directDebitRequest, delinkWalletRequest, AuthApiRequest, AuthStatusRequest, captureRequest, cancelAuthRequest, createSubscriptionRequest, submitAuthRequest, PhonePeV2RefundRequest, V2PhonepeSyncResponse, PhonePeNBnCardRequestBody, PhonePeNewCardHostEndpoint, PhonePeV2VerifyVpaRequest, PhonepeAuthTokenRequest/Response, PhonePeCreatePaymentRequest, PhonepeCheckoutRequest/StatusRequest, IRCTC types, webhook types, PhonepeDetails, SdkParams |
| 10 | `euler-api-txns/dbTypes/src-generated/EC/TxnDetail/Types.hs` | L285–311 | Internal TxnStatus enum (24 constructors) |
| 11 | `euler-api-txns/dbTypes/src-generated/EC/Mandate/Types.hs` | L332–344 | Internal MandateStatus enum (10 constructors) |
| 12 | `euler-api-txns/dbTypes/src-generated/EC/Refund/Types.hs` | L85–91 | Internal RefundStatus enum (4 constructors) |

---

**Generated by**: Euler Connector Tech Spec Workflow
**Date**: 2026-03-26
