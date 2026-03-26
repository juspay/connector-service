# LAZYPAY Connector — Technical Specification

**Generated from source code analysis**
**Repos:** `euler-api-gateway` | `euler-api-txns`
**Date:** 2026-03-26

---

## Table of Contents

1. [Connector Overview](#1-connector-overview)
2. [Base URLs & Authentication](#2-base-urls--authentication)
3. [Account Configuration](#3-account-configuration)
4. [Flows & Sub-Flows](#4-flows--sub-flows)
5. [Request / Response Types](#5-request--response-types)
6. [Shared Model Types](#6-shared-model-types)
7. [Error Handling & Status Mapping](#7-error-handling--status-mapping)
8. [EMI / CardlessCOF Support](#8-emi--cardlesscof-support)
9. [txns-side (euler-api-txns) Integration](#9-txns-side-euler-api-txns-integration)
10. [Source File Index](#10-source-file-index)

---

## 1. Connector Overview

| Property | Value |
|----------|-------|
| Connector name | `LAZYPAY` |
| Gateway type | Buy-Now-Pay-Later (BNPL) + Wallet + Cardless EMI |
| Payment methods supported | LAZYPAY (wallet/BNPL), LAZYPAY_CLEMI (Cardless EMI) |
| Txn ID prefix | `LP` (generated via `generateUniqueId LAZYPAY`) |
| Amount format | `EffectiveAmount` / `TotalAmount` (in paise/cents as text) |
| Currency | INR only |
| Direction | gateway → LazyPay external API (DIRECTION: A) |

### Key Capabilities

- **Payment Eligibility Check** — checks user's LazyPay credit limit/eligibility
- **Initiate Payment** — creates a payment order; returns a checkout redirect URL
- **Make Payment (Pay with OTP)** — submits OTP to complete payment
- **Cancel Payment** — cancels an in-progress transaction
- **Auto Debit (Direct Debit)** — initiates payment without OTP via stored mandate
- **Trigger OTP / Token Initiation** — sends OTP to link a customer's LazyPay account
- **Validate OTP / Link Customer** — validates OTP and retrieves wallet access token
- **Resend OTP** — resends OTP for in-progress transaction
- **Enquiry / Transaction Sync** — polls LazyPay for transaction status
- **Refund** — initiates a refund against a completed transaction
- **Refund Sync** — polls refund status
- **Get Token (Refresh Token)** — refreshes wallet access token via CitrusPay OAuth
- **EMI Plans** — fetches cardless EMI plans for a user

---

## 2. Base URLs & Authentication

### 2.1 LazyPay API Base URL

| Environment | Scheme | Host | Port | Base Path |
|-------------|--------|------|------|-----------|
| Production | HTTPS | `api.lazypay.in` | 443 | `/api/lazypay` |
| Sandbox | HTTPS | `sboxapi.lazypay.in` | 443 | `/api/lazypay` |

**Full production base:** `https://api.lazypay.in/api/lazypay`
**Full sandbox base:** `https://sboxapi.lazypay.in/api/lazypay`

Source: `Routes.hs:161-173` — `lazyPayBaseUrl`

### 2.2 LazyPay COF (Cardless EMI) Base URL

| Environment | Scheme | Host | Port | Base Path |
|-------------|--------|------|------|-----------|
| Production | HTTPS | `api.lazypay.in` | 443 | `api/lazypay/cof` |
| Sandbox | HTTPS | `sboxapi.lazypay.in` | 443 | `api/lazypay/cof` |

Source: `Routes.hs:187-198` — `lazypayCofBaseUrl`

### 2.3 CitrusPay OAuth Base URL (for token refresh)

| Environment | Scheme | Host | Port | Base Path |
|-------------|--------|------|------|-----------|
| Production | HTTPS | `admin.citruspay.com` | 443 | `` (empty) |
| Sandbox | HTTPS | `sandboxadmin.citruspay.com` | 443 | `` (empty) |

Source: `Routes.hs:174-185` — `citrusBaseUrl`

### 2.4 Authentication Mechanism

LazyPay uses **RSA-OAEP asymmetric encryption** for request signing. The merchant's `secretKey` (an RSA public key in PEM format) is used to encrypt a signature data string, and the resulting ciphertext is base64-encoded and sent as the `signature` header.

**Signature generation:**
```
publicKey = RSA.parsePublicKey(accountDetails.secretKey)
signatureBytes = RSA.OAEP.encrypt(publicKey, signatureDataString.encode("UTF-8"))
signature = base64Encode(signatureBytes)
```

Source: `Utils/Gateway/LazyPay.hs:19-32` — `generateSignature`

**For EMI/CLEMI flows only** — HMAC-SHA1 is used instead:
```
signature = HMAC-SHA1(secretKey, signatureDataString).hex()
```
Source: `Transforms/Emi.hs:51-54` — `createLazypaySignature`

### 2.5 Per-API Signature Data Strings

| Flow | Signature Data Format |
|------|-----------------------|
| Eligibility (v2) | `{mobile}{email}{amount}{currency}` |
| Initiate Payment | `merchantAccessKey={accessKey}&transactionId={txnId}&amount={amount}` |
| Trigger OTP | `merchantAccessKey={accessKey}&mobile={mobile}&email={email}` |
| Validate OTP (Link Customer) | `merchantAccessKey={accessKey}&mobile={mobile}&email={email}&otp={otp}` |
| Direct Debit | `merchantAccessKey={accessKey}&transactionId={txnId}&amount={amount}` |
| Resend OTP | `merchantAccessKey={accessKey}&merchantTxnId={txnId}` |
| Enquiry / Sync | `merchantAccessKey={accessKey}&merchantTxnId={txnId}` |
| Refund | `merchantAccessKey={accessKey}&merchantTxnId={txnId}&amount={amount}` |
| EMI Customer Status | `merchantAccessKey={accessKey}&mobile={mobile}` (HMAC-SHA1) |
| EMI Payment Eligibility v7 | `{mobile}{amount}INR` (HMAC-SHA1) |

### 2.6 Request Headers

| API | Headers |
|-----|---------|
| Payment Eligibility (v2) | `accessKey: <key>`, `signature: <sig>` |
| Initiate Payment (v2) | `accessKey: <key>`, `signature: <sig>` |
| Token Initiate | `accessKey: <key>`, `signature: <sig>` |
| Validate OTP | `accessKey: <key>`, `signature: <sig>` |
| Make Payment (v0/pay) | `Signature: <sig>` |
| Cancel Payment (v0/pay) | `Signature: <sig>` |
| Auto Debit (v0/pay) | `Authorization: <auth>`, `Signature: <sig>` |
| Resend OTP (v0) | `Signature: <sig>` |
| Enquiry (v0) | `accessKey: <key>`, `signature: <sig>` |
| Refund (v0) | `accessKey: <key>`, `signature: <sig>` |
| Customer Status (COF) | `accessKey: <key>`, `signature: <sig>`, `platform: ""`, `userIPAddress: ""` |
| Payment Eligibility v7 | `accessKey: <key>`, `signature: <sig>`, `platform: ""`, `userIPAddress: ""` |

---

## 3. Account Configuration

The merchant gateway account (`MerchantGatewayAccount`) JSON is decoded into one of two record types depending on the flow:

### 3.1 Standard `LazyPayDetails`

Used by all standard flows (initiate, eligibility, direct debit, refund, sync, OTP flows).

```haskell
data LazyPayDetails = LazyPayDetails
  { accessKey    :: Text   -- RSA public-key-based access key for request signing
  , secretKey    :: Text   -- RSA public key (PEM format) for signature generation
  , clientId     :: Text   -- OAuth client ID (for CitrusPay token refresh)
  , clientSecret :: Text   -- OAuth client secret (for CitrusPay token refresh)
  }
```

Source: `Types/Common.hs:37-44`

### 3.2 EMI `LazyPayDetailsEmi`

Used exclusively by EMI (CLEMI) flows — separate account credentials.

```haskell
data LazyPayDetailsEmi = LazyPayDetailsEmi
  { accessKey     :: Text   -- Merchant access key for COF/EMI APIs
  , secretKey     :: Text   -- HMAC-SHA1 secret key
  , subMerchantId :: Text   -- Sub-merchant identifier for COF eligibility
  }
```

Source: `Types/API/Emi.hs:39-46`

### 3.3 `AuthDetails` (Wallet Auth, stored per WalletAccount)

```haskell
data AuthDetails = AuthDetails
  { accessToken       :: Text         -- Current OAuth access token
  , accessTokenExpiry :: Text         -- Expiry timestamp
  , refreshToken      :: Text         -- OAuth refresh token (for CitrusPay refresh)
  , referenceId       :: Maybe Text
  }
```

Source: `Types/Models/AuthDetails.hs:10-17`

---

## 4. Flows & Sub-Flows

All flows reside in `euler-api-gateway` under:
`gateway/src/Euler/API/Gateway/Gateway/LAZYPAY/Flows/`

### 4.1 Flow: Initiate Payment

**Entry:** `initiatePayment :: API.InitiateTransaction -> L.Flow API.PaymentResponse`
**Source:** `Flows/Initiate.hs`

**Steps:**
1. Validate: customer must be present (`ITVerificationPayload customer`)
2. Decode account: `getLazyPayAccountDetails merchantGatewayAccount`
3. Construct request: `makeInitiatePaymentRequest customer request mbCellSelector webhookUrl`
   - Sets `eligibilityResponseId = ""`
   - Maps `merchantTxnId` from `txnDetail.txnId`
   - Resolves amount via MoneyFramework or legacy
   - Maps billing address
   - Sets `notifyUrl` and `returnUrl` from webhook utilities
4. Generate signature: RSA-OAEP over `merchantAccessKey={key}&transactionId={txnId}&amount={amount}`
5. Call: `POST /api/lazypay/v2/payment/initiate`
6. Handle response:
   - **Success (`LazyPaySuccess`):** Extract `checkoutPageUrl` → return `GatewayRedirect` with GET method
   - **Error (`LazyPayError`):** Parse `errorCode` + `message` → return `PaymentRespError` with `AuthenticationFailed`
   - **Client error:** → return `PaymentRespError` with `AuthenticationFailed`

**ApiTag:** `GW_INIT_TXN`

---

### 4.2 Flow: Payment Eligibility (BNPL/Wallet, v2)

**Entry:** `checkEligibility :: MerchantGatewayAccount -> API.CheckWalletEligibility -> L.Flow API.WalletEligibilityResponse`
**Source:** `Flows/Eligibility.hs`

**Two sub-flows depending on payment method:**

#### 4.2.1 Standard PM (not LAZYPAY_CLEMI)
1. Decode account via `getLazyPayAccountDetails`
2. Build signature: `{mobile}{email}{amount}INR` → RSA-OAEP
3. Call: `POST /api/lazypay/v2/payment/eligibility`
4. Map each payment method against the response:
   - `LazyPaySuccess`: Use `txnEligibility` boolean, map `code` to `EligibilityStatus`
   - `LazyPayError`: `isEligible = False`, map `errorCode` to status

#### 4.2.2 LAZYPAY_CLEMI
1. Decode EMI account via `getLazyPayAccountDetailsEmi`
2. Build HMAC-SHA1 signature: `merchantAccessKey={key}&mobile={mobile}`
3. Call: `GET /api/lazypay/cof/customer-status?mobile={mobile}`
4. Map response:
   - `SuccessResp`: `isEligible = preApprovalStatus || ntbEligible`
   - `FailureResp`: map error to `PG_ERROR`
5. Returns `WalletEligibility` with `paymentMethod = "LAZYPAY_CLEMI"`, `paymentMethodType = "CONSUMER_FINANCE"`

**ApiTag:** `GW_WALLET_ELIGIBILITY`

---

### 4.3 Flow: Direct Debit (Auto Debit)

**Entry:** `directDebit :: API.DirectDebit -> L.Flow API.TransactionResponse`
**Source:** `Flows/DirectDebit.hs`

**Steps:**
1. Validate: customer must be present
2. Decode account via `getLazyPayAccountDetails`
3. Build signature: `merchantAccessKey={key}&transactionId={txnId}&amount={amount}` → RSA-OAEP
4. Get `returnUrl` from webhook utilities
5. Build `AutoDebitRequest` with `paymentMode = AUTO_DEBIT`
6. Call: `POST /api/lazypay/v0/payment/pay` (AutoDebit route)
7. Handle response:
   - **Success (`LazyPaySuccess`):** returns `TransactionResponse` with `txnStatus = AuthenticationFailed` (TODO note in code: should be based on responseData)
   - **Error (`LazyPayError`):** returns failure `TransactionResponse`

**ApiTag:** `GW_INIT_DIRECT_DEBIT`

---

### 4.4 Flow: Trigger OTP (Token Initiation)

**Entry:** `triggerOTP :: API.TriggerOTP -> L.Flow API.OTPResponse`
**Source:** `Flows/TriggerOTP.hs`

**Steps:**
1. Decode account via `getLazyPayAccountDetails`
2. Build signature: `merchantAccessKey={key}&mobile={mobile}&email={email}` → RSA-OAEP
3. Build `InitiateTokenRequest` from customer + merchant source
4. Call: `POST /api/lazypay/token/initiate`
5. Handle response:
   - **Success (`LazyPaySuccess Void`):** return `OTPResponse` with empty errorCode/message
   - **Error (`LazyPayError`):** return `OTPResponse` with `errorCode` and `message`
   - **Client error:** extract error details into `OTPResponse`

**ApiTag:** `GW_TRIGGER_OTP`

---

### 4.5 Flow: Link Customer (Validate OTP)

**Entry:** `linkCustomer :: API.LinkWithOTP -> L.Flow API.OTPResponse`
**Source:** `Flows/LinkCustomer.hs`

**Steps:**
1. Decode account via `getLazyPayAccountDetails`
2. Build signature: `merchantAccessKey={key}&mobile={mobile}&email={email}&otp={otp}` → RSA-OAEP
3. Build `ValidateOTPRequest` from customer + OTP + merchant source
4. Call: `POST /api/lazypay/token/validateOTP`
5. Handle response:
   - **Success (`LazyPaySuccess ValidateOTPResponse`):** Store `accessToken`, `refreshToken`, expiry in `WalletAccount.authenticationDetails` (serialized as `AuthDetails` JSON)
   - **Error (`LazyPayError`):** return `OTPResponse` with error code/message
   - **Client error:** return `OTPResponse` with client error details

**ApiTag:** `GW_VERIFY_OTP`

---

### 4.6 Flow: Resend OTP

**Entry:** `resendOTP :: API.ResendOTP -> L.Flow API.ResendOTPResponse`
**Source:** `Flows/ResendOTP.hs`

**Steps:**
1. Decode account via `getLazyPayAccountDetails`
2. Get `txnId` from `txnDetail` using LAZYPAY txn identifier logic
3. Build signature: `merchantAccessKey={key}&merchantTxnId={txnId}` → RSA-OAEP
4. Build `ResendOTPRequest { txnRefNo = txnId }`
5. Call: `POST /api/lazypay/v0/resendOtp`
6. Handle response:
   - **Success (`LazyPaySuccess`):** `isSuccessful = resp.status`, `isResendEnabled = attemptsRemaining > 0`, `isSubmitEnabled = True`
   - **Error (`LazyPayError`):** return fail response
   - **Client error:** return fail response

**ApiTag:** `GW_RESEND_OTP`

---

### 4.7 Flow: Enquiry / Transaction Sync

**Entry:** `syncTransaction :: API.TransactionSync -> L.Flow API.SyncResponse`
**Source:** `Flows/Enquiry.hs`

**Steps:**
1. Call `initiateEnquiry GW_TXN_SYNC request (Just True) request.isForceSync`
   - Decode account, build signature: `merchantAccessKey={key}&merchantTxnId={txnId}`
   - Call: `GET /api/lazypay/v0/enquiry?merchantTxnId={txnId}&isSale=true`
2. Handle response:
   - **Success (`EnquiryResponse [objects]`):** return `SyncResponse` with `Authorized`
   - **Error (`LazyPayError`):** return `AuthorizationFailed`
   - **Client error:** return `AuthorizationFailed`

Note: Integrity framework checks skip amount/currency/txnId verification (all set to `True`).

**ApiTag:** `GW_TXN_SYNC`

---

### 4.8 Flow: Refund Sync

**Entry:** `syncRefund :: API.RefundSync -> L.Flow API.RefundSyncResponse`
**Source:** `Flows/Enquiry.hs`

**Steps:**
1. Validate `refund.referenceId.refundReferenceId` exists (throws `MISSING_REFERENCE_ID` if missing)
2. Call `initiateEnquiry GW_REFUND_SYNC request (Just False) Nothing`
   - Same enquiry API as txn sync but `isSale=false`
3. Handle response:
   - **Success:** Filter `EnquiryRefundResponseObject` list by `lpTxnId == refundReferenceId`
   - Map `EnquiryRefundStatus` to `Refund.RefundStatus` via `mapRefundStatus`
   - **Error:** Set `Refund.status = Failure`

**ApiTag:** `GW_REFUND_SYNC`

---

### 4.9 Flow: Initiate Refund

**Entry:** `initiateRefund :: API.InitiateRefund -> L.Flow API.RefundResponse`
**Source:** `Flows/Refund.hs`

**Steps:**
1. Decode account via `getLazyPayAccountDetails`
2. Get `txnId` from `txnDetail` using LAZYPAY txn identifier logic
3. Compute `amount` (MoneyFramework or legacy paise text)
4. Build signature: `merchantAccessKey={key}&merchantTxnId={txnId}&amount={amount}` → RSA-OAEP
5. Build `RefundRequest { merchantTxnId = txnId, amount = Amount { value = amount, currency = "INR" } }`
6. Call: `POST /api/lazypay/v0/refund`
7. Handle response:
   - **Success (`RefundResponse EnquiryRefundResponseObject`):** Map `status` to `Refund.RefundStatus`, set `referenceId = lpTxnId`
   - **Gateway error (`LazyPayError`):** `Refund.status = TransactionFailure`
   - **Client error:** `Refund.status = TransactionFailure`

**ApiTag:** `GW_INIT_REFUND`

---

### 4.10 Flow: Get Token (Refresh Token)

**Entry:** `getToken :: API.GetWalletToken -> L.Flow API.GetWalletTokenResponse`
**Source:** `Flows/GetToken.hs`

**Steps:**
1. Decode account via `getLazyPayAccountDetails`
2. Decode wallet auth details from `walletAccount.authenticationDetails`
3. Build `GetRefreshTokenRequest`:
   - `clientId` = account's clientId
   - `clientSecret` = account's clientSecret
   - `grantType = "refresh_token"`
   - `refreshToken` = from wallet account auth details
4. Call CitrusPay: `POST https://admin.citruspay.com/oauth/token`
5. Handle response:
   - **Success:** Extract `accessToken`, `refreshToken`, `expiresIn` → store as new `AuthDetails` in `WalletAccount`; return `Token accessToken`
   - **Client error:** return `makeGetTokenResponse Nothing walletAccount FAILURE`

**ApiTag:** `GW_REFRESH_WALLET_TOKEN`

---

### 4.11 Flow: EMI Plans

**Entry:** `getEmiPlans :: MerchantGatewayAccount -> EMI.GetEmiPlansRequest -> L.Flow (Either EMI.GetEmiPlansError [EMI.EmiPlan])`
**Source:** `Flows/Emi.hs`

**Steps:**
1. Validate: `mobileNumber` must be present (returns `InvalidDataProvided` error if absent)
2. Decode EMI account via `getLazyPayAccountDetailsEmi`
3. Build HMAC-SHA1 signature: `merchantAccessKey={key}&mobile={mobile}`
4. Call: `GET /api/lazypay/cof/customer-status?mobile={mobile}`
5. On success, compute eligibility signature: `{mobile}{amount}INR` (HMAC-SHA1)
6. Build `LazypayEligibilityRequest` and call: `POST /api/lazypay/v7/payment/eligibility`
7. Extract `cof.emiPlans` from response
8. Map each `Emi.EmiPlan` to `API.EmiPlan`:
   - `bank = "LAZYPAY"`, `cardType = Cardless "Cardless"`
   - Maps `subventionTag: "NCEMI"` → `NoCost`, `"LCEMI"` → `LowCost`, other → `Standard`
   - Converts doubles to `Money`

**ApiTags:** `GW_GET_EMI_ELIGIBILITY` (customer status), `GW_GET_EMI_DETAILS` (eligibility v7)

---

## 5. Request / Response Types

### 5.1 Payment Eligibility (v2)

**Endpoint:** `POST /api/lazypay/v2/payment/eligibility`
**Headers:** `accessKey`, `signature`

#### Request: `PaymentEligibilityRequest`

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `userDetails` | `UserDetails` | Yes | mobile, email, firstName, lastName |
| `amount` | `Amount` | Yes | `{value: Text, currency: "INR"}` |
| `address` | `Maybe Address` | No | |
| `productSkuDetails` | `Maybe [ProductSKUDetails]` | No | |
| `source` | `Maybe Text` | No | Merchant ID as text |
| `customParams` | `Maybe CustomParams` | No | |

#### Response: `PaymentEligibilityResponse`

| Field | Type | Notes |
|-------|------|-------|
| `txnEligibility` | `Bool` | Whether transaction is eligible |
| `reason` | `Text` | Human-readable reason |
| `code` | `ErrorCode` | LP error code (e.g., `LP_ELIGIBLE`) |
| `userEligibility` | `Bool` | Whether user is eligible |
| `emailRequired` | `Bool` | |
| `eligibilityResponseId` | `Text` | Used in subsequent initiate request |

---

### 5.2 Initiate Payment (v2)

**Endpoint:** `POST /api/lazypay/v2/payment/initiate`
**Headers:** `accessKey`, `signature`

#### Request: `InitiatePaymentRequest`

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `eligibilityResponseId` | `Text` | Yes | From eligibility response (set to `""` in current impl) |
| `merchantTxnId` | `Text` | Yes | Merchant transaction ID |
| `userDetails` | `UserDetails` | Yes | |
| `amount` | `Amount` | Yes | `{value: Text, currency: "INR"}` |
| `address` | `Address` | Yes | Billing address |
| `productSkuDetails` | `Maybe ProductSKUDetails` | No | Currently `Nothing` |
| `source` | `Text` | Yes | Merchant ID as text |
| `customParams` | `CustomParams` | Yes | All fields empty in current impl |
| `notifyUrl` | `Text` | Yes | Webhook/notify URL |
| `returnUrl` | `Text` | Yes | Return/webhook URL |

#### Response: `InitiatePaymentResponse`

| Field | Type | Notes |
|-------|------|-------|
| `txnRefNo` | `Text` | LazyPay transaction reference number |
| `paymentModes` | `Text` | Available payment modes |
| `lpTxnId` | `Text` | LazyPay internal transaction ID |
| `checkoutPageUrl` | `Text` | **URL to redirect user to** (used in `GatewayRedirect`) |

**On success:** Returns `GatewayRedirect` with GET redirect to `checkoutPageUrl`.

---

### 5.3 Token Initiate (Trigger OTP)

**Endpoint:** `POST /api/lazypay/token/initiate`
**Headers:** `accessKey`, `signature`

#### Request: `InitiateTokenRequest`

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `userDetails` | `UserDetails` | Yes | Customer details |
| `source` | `Maybe Text` | No | Merchant ID as text |
| `customParams` | `Maybe CustomParams` | No | Currently `Nothing` |

#### Response: `LazyPayResponse Void`

Returns either `LazyPaySuccess Void` (no payload) or `LazyPayError`.

---

### 5.4 Validate OTP (Link Customer)

**Endpoint:** `POST /api/lazypay/token/validateOTP`
**Headers:** `accessKey`, `signature`

#### Request: `ValidateOTPRequest`

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `userDetails` | `UserDetails` | Yes | Customer details |
| `otp` | `Text` | Yes | OTP entered by user |
| `source` | `Maybe Text` | No | Merchant ID as text |
| `customParams` | `Maybe CustomParams` | No | |

#### Response: `ValidateOTPResponse`

| Field | Type | Notes |
|-------|------|-------|
| `accessToken` | `Text` | OAuth access token |
| `tokenType` | `Text` | Token type (e.g., "Bearer") |
| `refreshToken` | `Text` | OAuth refresh token |
| `expiresIn` | `Integer` | Token expiry in seconds |
| `scope` | `Text` | OAuth scope |

JSON is parsed using `snakeCaseOption` (snake_case keys).

---

### 5.5 Make Payment (Pay with OTP)

**Endpoint:** `POST /api/lazypay/v0/payment/pay`
**Headers:** `Signature`

#### Request: `MakePaymentRequest`

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `paymentMode` | `PaymentMode` | Yes | `OTP` or `AUTO_DEBIT` |
| `txnRefNo` | `Text` | Yes | LazyPay txn reference |
| `otp` | `Text` | Yes | OTP value |

#### Response: `MakePaymentResponse`

| Field | Type | Notes |
|-------|------|-------|
| `transactionId` | `Text` | |
| `merchantOrderId` | `Text` | |
| `amount` | `Text` | |
| `currency` | `Text` | |
| `accessToken` | `Text` | |
| `signature` | `Text` | |
| `responseData` | `Text` | |
| `attemptsRemaining` | `Text` | |

---

### 5.6 Cancel Payment

**Endpoint:** `POST /api/lazypay/v0/payment/pay`
**Headers:** `Signature`

#### Request: `CancelPaymentRequest`

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `txnRefNo` | `Text` | Yes | LazyPay txn reference |
| `cancelTxn` | `Int` | Yes | Send `1` to cancel |

#### Response: `CancelPaymentResponse`

| Field | Type | Notes |
|-------|------|-------|
| `transactionId` | `Text` | |
| `merchantOrderId` | `Text` | |
| `amount` | `Text` | |
| `currency` | `Text` | |
| `signature` | `Text` | |
| `responseData` | `Text` | |

**ApiTag:** `GW_CANCEL_TXN`

---

### 5.7 Auto Debit (Direct Debit)

**Endpoint:** `POST /api/lazypay/v0/payment/pay`
**Headers:** `Authorization`, `Signature`

#### Request: `AutoDebitRequest`

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `paymentMode` | `PaymentMode` | Yes | `AUTO_DEBIT` |
| `merchantTxnId` | `Text` | Yes | |
| `userDetails` | `UserDetails` | Yes | |
| `amount` | `Amount` | Yes | `{value, currency}` |
| `address` | `Address` | Yes | Billing address |
| `productSkuDetails` | `Maybe ProductSKUDetails` | No | Currently `Nothing` |
| `notifyUrl` | `Text` | Yes | |
| `returnUrl` | `Text` | Yes | |
| `source` | `Text` | Yes | Merchant ID |

#### Response: `AutoDebitResponse`

| Field | Type | Notes |
|-------|------|-------|
| `transactionId` | `Text` | |
| `merchantOrderId` | `Text` | |
| `amount` | `Int` | |
| `currency` | `Text` | |
| `signature` | `Text` | |
| `responseData` | `Text` | Alphanumeric (TODO: may contain nested structure) |

**ApiTag:** `GW_INIT_DIRECT_DEBIT`

---

### 5.8 Resend OTP

**Endpoint:** `POST /api/lazypay/v0/resendOtp`
**Headers:** `Signature`

#### Request: `ResendOTPRequest`

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `txnRefNo` | `Text` | Yes | LazyPay txn reference |

#### Response: `ResendOTPResponse`

| Field | Type | Notes |
|-------|------|-------|
| `status` | `Bool` | True if OTP resent successfully |
| `otpType` | `OTPType` | `"m-otp"` (Mobile) or `"e-otp"` (Email) |
| `attemptsRemaining` | `Int` | Remaining resend attempts |

**ApiTag:** `GW_RESEND_OTP`

---

### 5.9 Enquiry (Transaction / Refund Status)

**Endpoint:** `GET /api/lazypay/v0/enquiry?merchantTxnId={txnId}&isSale={bool}`
**Headers:** `accessKey`, `signature`

#### Response: `EnquiryResponse`

Wraps a list of `EnquiryRefundResponseObject`:

| Field | Type | Notes |
|-------|------|-------|
| `status` | `EnquiryRefundStatus` | See §7.3 for status values |
| `respMessage` | `Text` | Human-readable message |
| `lpTxnId` | `Text` | LazyPay transaction ID |
| `txnType` | `Maybe EnquiryTransactionType` | `REFUND` or `SALE` |
| `txnDateTime` | `Text` | |
| `amount` | `Text` | |

**ApiTags:** `GW_TXN_SYNC` (isSale=true), `GW_REFUND_SYNC` (isSale=false)

---

### 5.10 Refund

**Endpoint:** `POST /api/lazypay/v0/refund`
**Headers:** `accessKey`, `signature`

#### Request: `RefundRequest`

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `merchantTxnId` | `Text` | Yes | Original transaction ID |
| `amount` | `Amount` | Yes | `{value: Text, currency: "INR"}` |

#### Response: `RefundResponse`

Wraps a single `EnquiryRefundResponseObject`:

| Field | Type | Notes |
|-------|------|-------|
| `status` | `EnquiryRefundStatus` | |
| `respMessage` | `Text` | |
| `lpTxnId` | `Text` | Stored as `Refund.referenceId` |
| `txnType` | `Maybe EnquiryTransactionType` | |
| `txnDateTime` | `Text` | |
| `amount` | `Text` | |

**ApiTag:** `GW_INIT_REFUND`

---

### 5.11 Get Refresh Token (CitrusPay OAuth)

**Endpoint:** `POST https://admin.citruspay.com/oauth/token`
**Auth:** None (credentials in body)

#### Request: `GetRefreshTokenRequest`

| Field | Type | Notes |
|-------|------|-------|
| `clientId` | `Text` | From account config |
| `clientSecret` | `Text` | From account config |
| `grantType` | `Text` | Always `"refresh_token"` |
| `refreshToken` | `Text` | From stored `AuthDetails` |

JSON uses `snakeCaseOption`.

#### Response: `GetRefreshTokenResponse`

| Field | Type | Notes |
|-------|------|-------|
| `accessToken` | `Text` | New access token |
| `tokenType` | `Text` | |
| `refreshToken` | `Text` | New refresh token |
| `expiresIn` | `Integer` | Seconds until expiry |
| `scope` | `Text` | |
| `clientType` | `Text` | |
| `prepaidPayToken` | `PrepaidPayToken` | Nested token object |

JSON uses `snakeCaseOption`.

**ApiTag:** `GW_REFRESH_WALLET_TOKEN`

---

### 5.12 Customer Status (COF / CLEMI)

**Endpoint:** `GET /api/lazypay/cof/customer-status?mobile={mobile}`
**Headers:** `accessKey`, `signature`, `platform: ""`, `userIPAddress: ""`

#### Response: `CustomerStatusResult`

Sum type, parsed by trying `SuccessResp` then `FailureResp`:

**`CustomerStatusResponse`** (success):

| Field | Type | Notes |
|-------|------|-------|
| `customerInfoRequired` | `Maybe Bool` | |
| `preApprovalStatus` | `Maybe Bool` | Pre-approved for CLEMI |
| `onboardingRequired` | `Maybe Bool` | |
| `availableLimit` | `Maybe Double` | Available credit limit |
| `ntbEligible` | `Maybe Bool` | New-to-business eligible |

**Eligibility check:** `isEligible = preApprovalStatus || ntbEligible`

**`Error`** (failure):

| Field | Type | Notes |
|-------|------|-------|
| `path` | `Maybe Text` | |
| `status` | `Maybe Int` | HTTP status |
| `message` | `Text` | |
| `error` | `Maybe Text` | |
| `errorCode` | `Text` | |
| `timestamp` | `Maybe Int` | |

**ApiTag:** `GW_GET_EMI_ELIGIBILITY`

---

### 5.13 Payment Eligibility v7 (COF / CLEMI EMI Plans)

**Endpoint:** `POST /api/lazypay/v7/payment/eligibility`
**Headers:** `accessKey`, `signature`, `platform: ""`, `userIPAddress: ""`

#### Request: `LazypayEligibilityRequest`

| Field | Type | Notes |
|-------|------|-------|
| `userDetails` | `UserDetails` (EMI) | `{ mobile: Text }` |
| `amount` | `Amount` (EMI) | `{ value: Text, currency: "INR" }` |
| `customParams` | `CustomParams` (EMI) | `{ subMerchantId: Text }` |
| `source` | `Text` | Always `"website"` |

#### Response: `PaymentEligibilityResult`

Sum type, parsed by trying `EligibilitySuccess` then `EligibilityFailure`:

**`PaymentEligibilityResponse`** (success):

| Field | Type | Notes |
|-------|------|-------|
| `bnpl` | `Maybe BnplInfo` | BNPL eligibility info |
| `cof` | `CofInfo` | COF/EMI info including plans |
| `eligibilityResponseId` | `Maybe Text` | |
| `customParams` | `CustomParams` | |
| `existingUser` | `Maybe Bool` | |

**`CofInfo`**:

| Field | Type | Notes |
|-------|------|-------|
| `txnEligibility` | `Maybe Bool` | |
| `reason` | `Maybe Text` | |
| `code` | `Maybe Text` | |
| `availableLimit` | `Maybe Double` | |
| `emiPlans` | `Maybe [EmiPlan]` | List of EMI plans |

**`EmiPlan`**:

| Field | Type | Notes |
|-------|------|-------|
| `interestRate` | `Double` | Annual interest rate |
| `tenure` | `Int` | Months |
| `emi` | `Double` | Monthly installment |
| `totalInterestAmount` | `Double` | |
| `principal` | `Double` | |
| `totalProcessingFee` | `Double` | |
| `processingFeeGst` | `Double` | |
| `totalPayableAmount` | `Double` | |
| `firstEmiDueDate` | `Maybe Text` | |
| `subventionTag` | `Maybe Text` | `"NCEMI"` = No Cost, `"LCEMI"` = Low Cost |
| `discountedInterestAmount` | `Double` | |

**ApiTag:** `GW_GET_EMI_DETAILS`

---

## 6. Shared Model Types

### 6.1 `UserDetails`

```haskell
data UserDetails = UserDetails
  { _mobile    :: Text   -- JSON key: "mobile"
  , _email     :: Text   -- JSON key: "email"
  , _firstName :: Text   -- JSON key: "firstName"
  , _lastName  :: Text   -- JSON key: "lastName"
  }
```

Uses `stripLensPrefixOptions` for JSON serialization (strips leading `_`).
Source: `Types/Models/UserDetails.hs`

### 6.2 `Amount`

```haskell
data Amount = Amount
  { value    :: Text   -- Amount in paise (cents) as string
  , currency :: Text   -- Always "INR"
  }
```

Source: `Types/Models/Amount.hs`

### 6.3 `Address`

```haskell
data Address = Address
  { street1 :: Text
  , street2 :: Maybe Text
  , city    :: Text
  , state   :: Text
  , country :: Text
  , zip     :: PII.PII   -- PII-tagged postal code
  }
```

Source: `Types/Models/Address.hs`

### 6.4 `PaymentMode`

```haskell
data PaymentMode = OTP | AUTO_DEBIT
```

Source: `Types/Models/PaymentMode.hs`

### 6.5 `ProductSKUDetails`

```haskell
data ProductSKUDetails = ProductSKUDetails
  { productId   :: Text
  , description :: Text
  , attributes  :: Attribute
  , imageUrl    :: Text
  , shippable   :: Bool
  , skus        :: [SKU]
  }

data Attribute = Attribute
  { size          :: Maybe Text
  , color         :: Maybe Text
  , itemsselected :: Maybe Text
  , amount        :: Maybe Text
  }

data SKU = SKU
  { skuId      :: Text
  , price      :: Int
  , attributes :: Attribute
  }
```

Source: `Types/Models/ProductSKUDetails.hs`

### 6.6 `CustomParams`

```haskell
data CustomParams = CustomParams
  { _previoustxncount  :: Text   -- "previoustxncount"
  , _onboardingdate    :: Text   -- "onboardingdate"
  , _usersignupdetails :: Text   -- "usersignupdetails"
  , _IPaddress         :: Text   -- "IPaddress"
  , _UserAgent         :: Text   -- "UserAgent"
  , _DeviceInfo        :: Text   -- "DeviceInfo"
  }
```

All fields are empty strings in current implementation.

### 6.7 `PrepaidPayToken`

```haskell
data PrepaidPayToken = PrepaidPayToken
  { accessToken      :: Text
  , tokenType        :: Text
  , expiresIn        :: Int
  , scope            :: Text
  , outerAccessToken :: Text
  , clientType       :: Text
  }
```

Uses `snakeCaseOption`.

---

## 7. Error Handling & Status Mapping

### 7.1 Generic Response Wrapper

```haskell
data LazyPayResponse body
  = LazyPaySuccess body
  | LazyPayError LazyPayErrorResponse
```

**Parsing logic:** If JSON object contains key `"error"`, parse as `LazyPayError`; otherwise parse as `LazyPaySuccess`.

Source: `Types/API/Response.hs:24-35`

### 7.2 `LazyPayErrorResponse`

| Field | Type | Notes |
|-------|------|-------|
| `timestamp` | `Int64` | Unix timestamp |
| `status` | `Int` | HTTP status code |
| `error` | `Text` | Error type string |
| `message` | `Text` | Human-readable error message |
| `path` | `Text` | API path that produced the error |
| `errorCode` | `ErrorCode` | Structured error code (see §7.3) |

### 7.3 `ErrorCode` Enum (LazyPay-defined)

| ErrorCode | Meaning |
|-----------|---------|
| `LP_ELIGIBLE` | User is eligible |
| `LP_USER_BLOCKED` | User is blocked |
| `LP_USER_OPTED_OUT` | User has opted out |
| `LP_USER_INELIGIBLE` | User is ineligible |
| `LP_INSUFFICIENT_BALANCE` | Insufficient credit balance |
| `LP_MERCHANT_DISABLED` | Merchant is disabled |
| `LP_EXCEEDS_MER_MAX_TXN_LIMIT` | Exceeds merchant max transaction limit |
| `LP_EXCEEDS_USER_MAX_TXN_LIMIT` | Exceeds user max transaction limit |
| `LP_PRODUCT_SKU_DETAILS_REQUIRED` | Product SKU details missing |
| `LP_ADDRESS_DETAILS_REQUIRED` | Address details missing |
| `LP_MOBILE_ALREADY_LINKED` | Mobile already linked |
| `LP_SIGNATURE_REQUIRED` | Signature missing |
| `LP_SIGNATURE_MISMATCH` | Signature verification failed |
| `LP_INVALID_ACCESS_KEY` | Invalid access key |
| `LP_INVALID_EMAIL` | Invalid email |
| `LP_INVALID_MOBILE` | Invalid mobile number |
| `LP_USER_DETAILS_REQUIRED` | User details missing |
| `LP_INVALID_FIRSTNAME` | Invalid first name |
| `LP_INVALID_LASTNAME` | Invalid last name |
| `LP_BILL_OVER_DUES` | User has outstanding dues |
| `LP_MTX_NOT_FOUND` | Merchant transaction not found |
| `LP_SALE_TXN_FAILED` | Sale transaction failed |
| `LP_SALE_TXN_DISPUTED` | Sale transaction disputed |
| `LP_TXN_REF_NO_REQUIRED` | Transaction reference number required |
| `LP_INVALID_PAYMENT_MODE` | Invalid payment mode |
| `LP_INVALID_TXN_REF_NO` | Invalid transaction reference number |
| `LP_OTP_REQUIRED` | OTP is required |
| `LP_INCORRECT_OTP` | OTP is incorrect |
| `LP_ACCOUNT_LOCKED` | Account is locked |
| `LP_TXN_TIMED_OUT` | Transaction timed out |
| `LP_INVALID_PAY_REQUEST` | Invalid payment request |
| `LP_ACCESS_DENIED` | Access denied |
| `LP_DUPLICATE_TRANSACTION_REQUEST` | Duplicate transaction |
| `LP_RISK_RULE_VIOLATION` | Risk rule violation |
| `LP_PAY_PARAMS_REQUIRED` | Payment params missing |
| `LP_SUCCESS_TXN_EXISTS` | Successful transaction already exists |
| `LP_TXN_EXPIRED` | Transaction expired |
| `LP_MAX_OTP_GEN_EXCEEDED` | Max OTP generation attempts exceeded |
| `LP_VELOCITY_CHECK_FAILED` | Velocity check failed |
| `LP_EMAIL_REQUIRED` | Email is required |
| `LP_MERCHANT_NOT_AUTO_DEBIT` | Merchant not configured for auto debit |

### 7.4 Eligibility Status Mapping (`ErrorCode` → `API.EligibilityStatus`)

| LazyPay `ErrorCode` | Euler `EligibilityStatus` |
|--------------------|--------------------------|
| `LP_ELIGIBLE` | `SUCCESS` |
| `LP_USER_BLOCKED` | `UNAUTHORIZED` |
| `LP_USER_OPTED_OUT` | `INVALID_DATA` |
| `LP_USER_INELIGIBLE` | `USER_NOT_FOUND` |
| `LP_INSUFFICIENT_BALANCE` | `INSUFFICIENT_FUNDS` |
| `LP_MERCHANT_DISABLED` | `NOT_ACCESSIBLE` |
| `LP_EXCEEDS_MER_MAX_TXN_LIMIT` | `INVALID_DATA` |
| `LP_EXCEEDS_USER_MAX_TXN_LIMIT` | `INVALID_DATA` |
| `LP_PRODUCT_SKU_DETAILS_REQUIRED` | `INVALID_DATA` |
| `LP_ADDRESS_DETAILS_REQUIRED` | `INVALID_DATA` |
| `LP_MOBILE_ALREADY_LINKED` | `INVALID_DATA` |
| `LP_USER_DETAILS_REQUIRED` | `INVALID_DATA` |
| `LP_SIGNATURE_REQUIRED` | `INVALID_DATA` |
| `LP_SIGNATURE_MISMATCH` | `INVALID_DATA` |
| `LP_INVALID_ACCESS_KEY` | `INVALID_DATA` |
| `LP_INVALID_EMAIL` | `INVALID_DATA` |
| `LP_INVALID_MOBILE` | `INVALID_DATA` |
| `LP_INVALID_FIRSTNAME` | `INVALID_DATA` |
| `LP_INVALID_LASTNAME` | `INVALID_DATA` |
| `LP_BILL_OVER_DUES` | `PENDING_DUES` |
| _(all others)_ | `ERROR` |

Source: `Transforms/Eligibility.hs:48-69`

### 7.5 Refund/Enquiry Status Mapping (`EnquiryRefundStatus` → `Refund.RefundStatus`)

| LazyPay `EnquiryRefundStatus` | Euler `RefundStatus` |
|-------------------------------|----------------------|
| `SUCCESS` | `Success` |
| `FAIL` | `Failure` |
| `IN_PROGRESS` | `Pending` |
| `DISPUTE_RESOLVED` | `ManualReview` |
| `REFUND_ON_DISPUTE` | `Pending` |
| `CHECKOUT_PAGE_RENDERED` | `ManualReview` |
| `FORWARDED` | `ManualReview` |
| `CANCELLED` | `ManualReview` |
| `SELF_INVITE_OTP` | `ManualReview` |
| `REFUND_SUCCESS` | `Success` |
| `REFUND_FAILED` | `Failure` |

Source: `Transforms/Refund.hs:31-42`

### 7.6 Internal Error Types

```haskell
data LazyPaySError
  = SApiCallError ClientError TxnStatus  -- HTTP client-level error
  | SSyncError LazyPayErrorResponse      -- LazyPay-level sync error
```

Used in class-based sync flow.

### 7.7 Error Propagation Pattern

All flows follow a consistent error propagation pattern:

1. **`Left ClientError`** (HTTP/network failure):
   - Calls `Utils.handleClientError clientError` to extract `errType`, `errorMessage`, `errorResponse`
   - Maps to `PaymentGatewayInfo` with `respType = PG_ERROR`
   - Sets transaction status to `AuthenticationFailed` (payment) or `Failure` (refund)

2. **`Right (LazyPayError LazyPayErrorResponse)`** (gateway-level error):
   - Extracts `errorCode` and `message` from `LazyPayErrorResponse`
   - Sets transaction status to `AuthenticationFailed` (payment)
   - Serializes error response as JSON text for `responseXml`

3. **Missing mandatory fields** (pre-flight validation):
   - `MISSING_CUSTOMER` → throws with `BAD_REQUEST_CUSTOMER_IS_NOTHING`
   - `MISSING_REFERENCE_ID` → throws with `REFERENCE_ID_NOT_PROVIDED`
   - `MISSING_AUTH_DETAILS` → throws with `AUTH_DETAILS_NOT_PROVIDED`
   - `MERCHANT_GATEWAY_ACCOUNT_DETAILS_DECODE_ERROR` → throws on bad JSON
   - `INVALID_PUBLIC_KEY` / `ENCRYPTION_ERROR` → throws on bad RSA key or encryption failure

---

## 8. EMI / CardlessCOF Support

### 8.1 Architecture

LazyPay EMI (CLEMI) uses a separate set of credentials (`LazyPayDetailsEmi`) and a different authentication mechanism (HMAC-SHA1 instead of RSA-OAEP).

### 8.2 CLEMI Eligibility Flow

```
getEmiPlans / checkEligibility (CLEMI)
  ↓ HMAC-SHA1 signature
  → GET /cof/customer-status       [CustomerStatusResult]
  ↓ if eligible (preApproval || ntbEligible)
  → POST /v7/payment/eligibility   [PaymentEligibilityResult]
  ↓ Extract cof.emiPlans
  → map to [API.EmiPlan]
```

### 8.3 EMI Plan Mapping

| LazyPay Field | Euler Field | Notes |
|--------------|-------------|-------|
| `interestRate` | `interestRate` | Multiplied by 10000 (floor) |
| `tenure` | `tenure` | |
| `emi` | `monthlyPayment` | `Money.fromDouble` |
| `totalInterestAmount` | `interestAmount` | `Money.fromDouble` |
| `totalProcessingFee` | `additionalFees` | `Money.fromDouble` |
| `totalPayableAmount` | `totalCost` | `Money.fromDouble` |
| `subventionTag = "NCEMI"` | `emiType = NoCost` | with `interestDiscountAmount` |
| `subventionTag = "LCEMI"` | `emiType = LowCost` | with `interestDiscountAmount` |
| _(other/absent)_ | `emiType = Standard` | |
| `bank = "LAZYPAY"` | `bank` | |
| `cardType = Cardless "Cardless"` | `cardType` | |

### 8.4 COF Route

The COF (Cardless on File) base URL is separate from the standard LazyPay API:
- Prod: `https://api.lazypay.in/api/lazypay/cof`
- Sandbox: `https://sboxapi.lazypay.in/api/lazypay/cof`

---

## 9. txns-side (euler-api-txns) Integration

### 9.1 Files in `euler-api-txns`

| File | Purpose |
|------|---------|
| `euler-x/src-generated/Gateway/LazyPay/Types.hs` | PureScript-generated type definitions for txns-side flows |
| `euler-x/src-generated/Gateway/LazyPay/Flow.hs` | txns-side payment flow logic |
| `euler-x/src-generated/Gateway/LazyPay/Transforms.hs` | txns-side data transforms |
| `oltp/src-generated/Product/OLTP/Eligibility.hs` | References LAZYPAY for eligibility routing |
| `oltp/src-generated/Product/OLTP/Transaction.hs` | References LAZYPAY for transaction routing |
| `oltp/src-generated/TransactionHelper.hs` | LAZYPAY-specific helper logic |
| `euler-x/src-generated/Gateway/CommonGateway.hs` | Shared gateway dispatch |
| `ecPrelude/src/Config/Shims.hs` | Config shims (feature flags) |

### 9.2 Money Calculation (txns-side)

```haskell
instance Money LAZYPAY where
  amountFormat LAZYPAY = EffectiveAmount
  amountCalculationLogic LAZYPAY = TotalAmount
```

Source: `Gateway/LazyPay/Types.hs:165-167`

### 9.3 txns-side Types (selected)

The txns-side uses a PureScript-generated newtype-wrapped style. Key types include:

- **`EligibityRequest`** / **`EligibitySuccessResponse`**: v2 eligibility
- **`InitiatePayRequest`** / **`InitiatePaySuccessResponse`**: initiate payment
- **`PayWithOtpRequest`** / **`PayWithOtpResponse`**: make payment with OTP
- **`AutodebitpayRequest`** / **`AutodebitSuccesspayResponse`**: auto debit
- **`LazyPayRefundRequest`** / **`RefundSuccessResponse`**: refund
- **`InquiryRequest`** / **`InquirySuccessResponseType`**: enquiry (txn sync)
- **`ValidateOTPRequest`** / **`ValidateOTPSuccessResponse`**: OTP validation
- **`CustLinkLazyPayRequest`**: customer link (trigger OTP from txns side)
- **`CreateOrderRequest`** / **`CreateOrderSuccessResponse`**: EMI order creation
- **`PaymentEligibilityRequest`** / **`PaymentEligibilitySuccessResponse`**: CLEMI eligibility
- **`CustomerStatusRequest`** / **`CustomerStatusSuccessResponse`**: CLEMI customer status
- **`LazyPayGatewayAuthReqParams`**: 2FA auth req params `{ txnRefNo, resendOTPAllowed, submitOTPAllowed }`
- **`LazypayMetaData`**: metadata for bill-pay accounts `{ __LAZYPAY_58_billPayAccountId, __LAZYPAY_58_circleCode, __LAZYPAY_58_subscriberId }`

### 9.4 Webhook / Callback Types

```haskell
data CustomerWebhookResponse = CustomerWebhookResponse
  { merchantTxnId :: Text
  , status        :: Text
  , token         :: Maybe Token
  }

data Token = Token
  { access_token :: Text
  , expires_in   :: Number
  }
```

### 9.5 RedirectFlow Response (from txns webhook handler)

```haskell
data RedirectFlowSuccResponse
  { _TxStatus, _TxId, _TxRefNo, pgTxnNo, pgRespCode, _TxMsg
  , amount, authIdCode, issuerRefNo
  , transactionId, paymentMode, _TxGateway, currency
  , signature, ... (various optional fields)
  }
```

---

## 10. Source File Index

### euler-api-gateway

| File | Purpose |
|------|---------|
| `LAZYPAY/Routes.hs` | API types, base URLs, call wrappers |
| `LAZYPAY/Flows.hs` | Re-exports all flow modules |
| `LAZYPAY/Transforms.hs` | Re-exports all transform modules |
| `LAZYPAY/Instances.hs` | TypeClass instances for `BasicGatewayFlow` |
| `LAZYPAY/Flows/Initiate.hs` | Payment initiation flow |
| `LAZYPAY/Flows/Eligibility.hs` | Wallet eligibility check flow |
| `LAZYPAY/Flows/DirectDebit.hs` | Auto debit flow |
| `LAZYPAY/Flows/TriggerOTP.hs` | OTP trigger flow |
| `LAZYPAY/Flows/LinkCustomer.hs` | OTP validation / customer link flow |
| `LAZYPAY/Flows/ResendOTP.hs` | OTP resend flow |
| `LAZYPAY/Flows/Enquiry.hs` | Transaction sync and refund sync flow |
| `LAZYPAY/Flows/Refund.hs` | Refund initiation flow |
| `LAZYPAY/Flows/GetToken.hs` | Token refresh flow |
| `LAZYPAY/Flows/Emi.hs` | EMI plans fetch flow |
| `LAZYPAY/Transforms/Common.hs` | Shared transforms (account decode, customer → UserDetails, money → Amount, address) |
| `LAZYPAY/Transforms/Initiate.hs` | Signature and request for initiate payment |
| `LAZYPAY/Transforms/Eligibility.hs` | Signature, request, and status mapping for eligibility |
| `LAZYPAY/Transforms/DirectDebit.hs` | Signature and request for auto debit |
| `LAZYPAY/Transforms/TriggerOTP.hs` | Signature and request for trigger OTP |
| `LAZYPAY/Transforms/LinkCustomer.hs` | Signature and request for validate OTP |
| `LAZYPAY/Transforms/ResendOTP.hs` | Transforms for resend OTP (inline in Flows file) |
| `LAZYPAY/Transforms/Enquiry.hs` | Signature for enquiry |
| `LAZYPAY/Transforms/Refund.hs` | Signature, request, and status mapping for refund |
| `LAZYPAY/Transforms/GetToken.hs` | Request transform for CitrusPay token refresh |
| `LAZYPAY/Transforms/Emi.hs` | HMAC signature, EMI account decode, EMI plan mapping |
| `LAZYPAY/Types/Common.hs` | LAZYPAY gateway type, LazyPayDetails, TxnIdentifier |
| `LAZYPAY/Types/API.hs` | Re-exports all API type modules |
| `LAZYPAY/Types/API/InitiatePayment.hs` | InitiatePaymentRequest/Response |
| `LAZYPAY/Types/API/PaymentEligibility.hs` | PaymentEligibilityRequest/Response |
| `LAZYPAY/Types/API/AutoDebit.hs` | AutoDebitRequest/Response |
| `LAZYPAY/Types/API/MakePayment.hs` | MakePaymentRequest/Response |
| `LAZYPAY/Types/API/CancelPayment.hs` | CancelPaymentRequest/Response |
| `LAZYPAY/Types/API/ResendOTP.hs` | ResendOTPRequest/Response |
| `LAZYPAY/Types/API/EnquiryRefund.hs` | RefundRequest, EnquiryResponse, RefundResponse, status types |
| `LAZYPAY/Types/API/TokenInitiate.hs` | InitiateTokenRequest |
| `LAZYPAY/Types/API/ValidateOTP.hs` | ValidateOTPRequest/Response |
| `LAZYPAY/Types/API/GetRefreshToken.hs` | GetRefreshTokenRequest/Response |
| `LAZYPAY/Types/API/Response.hs` | LazyPayResponse, ErrorCode, LazyPayErrorResponse |
| `LAZYPAY/Types/API/Emi.hs` | EMI-specific types: LazyPayDetailsEmi, CustomerStatusResult, LazypayEligibilityRequest, etc. |
| `LAZYPAY/Types/Models/UserDetails.hs` | UserDetails model |
| `LAZYPAY/Types/Models/Amount.hs` | Amount model |
| `LAZYPAY/Types/Models/Address.hs` | Address model |
| `LAZYPAY/Types/Models/PaymentMode.hs` | PaymentMode enum |
| `LAZYPAY/Types/Models/ProductSKUDetails.hs` | ProductSKUDetails, Attribute, CustomParams, SKU |
| `LAZYPAY/Types/Models/PrepaidPayToken.hs` | PrepaidPayToken |
| `LAZYPAY/Types/Models/AuthDetails.hs` | AuthDetails (stored in WalletAccount) |
| `Utils/Gateway/LazyPay.hs` | `generateSignature` (RSA-OAEP), `transformResponseToAuthDetails` |

### euler-api-txns

| File | Purpose |
|------|---------|
| `euler-x/src-generated/Gateway/LazyPay/Types.hs` | All txns-side type definitions and RestEndpoint instances |
| `euler-x/src-generated/Gateway/LazyPay/Flow.hs` | txns-side payment processing logic |
| `euler-x/src-generated/Gateway/LazyPay/Transforms.hs` | txns-side data transforms |
| `oltp/src-generated/Product/OLTP/Eligibility.hs` | LAZYPAY eligibility routing |
| `oltp/src-generated/Product/OLTP/Transaction.hs` | LAZYPAY transaction routing |
| `oltp/src-generated/TransactionHelper.hs` | LAZYPAY helper functions |
| `euler-x/src-generated/Gateway/CommonGateway.hs` | CommonGateway dispatch (LAZYPAY entry) |
| `ecPrelude/src/Config/Shims.hs` | Feature flags / config shims |

---

## Known Gaps / TODOs (from Source Code)

1. **`InitiatePaymentRequest.eligibilityResponseId`** is always set to `""` — eligibility response ID is not being threaded through from the eligibility response.
2. **`AutoDebitResponse.responseData`** is documented as alphanumeric but may contain nested structure; not parsed.
3. **`DirectDebit` success response** sets `txnStatus = AuthenticationFailed` — this appears to be incorrect and has a `TODO` comment noting it should be based on `responseData`.
4. **`productSkuDetails`** is always `Nothing` in initiate and direct debit requests — not mapped from order data.
5. **`customParams`** is always zeroed out — not populated from order metadata.
6. **Amount precision**: TODO comments note amount should be "up to two decimal points".
7. **`getCustomerStatus`** / `callPaymentEligibilityV7API` pass empty strings for `platform` and `userIPAddress` headers.
8. **`makePayment`** and **`cancelPayment`** flow functions are defined in Routes.hs but no corresponding `Flows/` implementation files exist — these are called directly (possibly from txns-side only).
