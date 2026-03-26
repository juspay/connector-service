# EASEBUZZ — Technical Specification

> **Connector**: EASEBUZZ
> **Direction**: euler-api-txns → Easebuzz external API (core payments); euler-api-gateway → Easebuzz external API (EMI plans, VPA verify, wallet eligibility)
> **Endpoint**: Multiple — see Section 1.2 and Section 5
> **Purpose**: Payment initiation (seamless/redirect/UPI/EMI), OTP flows, mandate/SI registration, UPI Autopay, refunds, settlement, txn sync, VPA verification, wallet eligibility
> **Generated**: 2026-03-26

---

## 1. Connector Overview

### 1.1 Basic Information
- **Connector ID**: EASEBUZZ
- **Direction**: euler-api-txns → Easebuzz (primary); euler-api-gateway → Easebuzz (gateway-side)
- **HTTP Methods**: POST (primary); GET (mandate retrieve, debit retrieve, notification sync)
- **Endpoint Paths**: See full table in Section 1.2
- **Protocol**: HTTP REST (synchronous)
- **Content Types**: `application/x-www-form-urlencoded` (payment/seamless APIs); `application/json` (mandate/SI APIs, verify VPA); form-data (gateway EMI plans, eligibility)
- **Architecture**: Haskell — euler-api-txns uses PureScript-style Nau/Presto backend; euler-api-gateway uses Servant + EulerHS

### 1.2 Base URL Configuration

#### Payment / Seamless API (testpay / pay)

| Environment | Base URL | Env Variable | Default |
|-------------|----------|-------------|---------|
| Sandbox / Test | `https://testpay.easebuzz.in` | hardcoded (`Bool = True`) | — |
| Production | `https://pay.easebuzz.in` | hardcoded (`Bool = False`) | — |

#### Dashboard API (txn sync, refund, settlement)

| Environment | Base URL | Env Variable | Default |
|-------------|----------|-------------|---------|
| Sandbox / Test | `https://testdashboard.easebuzz.in` | hardcoded (`Bool = True`) | — |
| Production | `https://dashboard.easebuzz.in` | hardcoded (`Bool = False`) | — |

#### Mandate / SI / UPI Autopay API (autocollect)

| Environment | Base URL | Env Variable | Default |
|-------------|----------|-------------|---------|
| Sandbox / Test | `https://sandboxapi.easebuzz.in` | hardcoded (`Bool = True`) | — |
| Production | `https://api.easebuzz.in` | hardcoded (`Bool = False`) | — |

#### Verify VPA (gateway-side, always production)

| Environment | Base URL | Env Variable | Default |
|-------------|----------|-------------|---------|
| All | `https://api.easebuzz.in` | hardcoded (`isVerifyVpa = True`) | — |

**URL Resolution Logic**: A single `Bool` (`testMode` or `isSandbox`) parameter selects the environment. `True` = sandbox/test, `False` = production. For Verify VPA, `isVerifyVpa = True` always routes to `api.easebuzz.in` regardless of sandbox flag. Resolution is done via pattern-matching in `getEndpointForReqAndEnv` (euler-api-txns) and `easebuzzBaseUrl` (euler-api-gateway).

**Source files**:
- `Gateway.EaseBuzz.Endpoints` — `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Endpoints.hs:38–98`
- `Euler.API.Gateway.Gateway.Easebuzz.Endpoint` — `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/Easebuzz/Endpoint.hs:29–41`

**Timeout Configuration**:
- Custom Timeout Header: Not explicitly configured in source (standard EulerHS/Servant client defaults apply)
- Default Timeout: System default
- Per-Merchant Override: Not observed in source

#### Full Endpoint URL Table

| # | Endpoint Name | HTTP | Sandbox URL | Production URL |
|---|--------------|------|-------------|---------------|
| 1 | EaseBuzInitiatePayment | POST | `https://testpay.easebuzz.in/payment/initiateLink` | `https://pay.easebuzz.in/payment/initiateLink` |
| 2 | EasebuzSeamlessTransaction | POST | `https://testpay.easebuzz.in/initiate_seamless_payment/` | `https://pay.easebuzz.in/initiate_seamless_payment/` |
| 3 | EasebuzTxnSync | POST | `https://testdashboard.easebuzz.in/transaction/v1/retrieve` | `https://dashboard.easebuzz.in/transaction/v1/retrieve` |
| 4 | EaseBuzRefund | POST | `https://testdashboard.easebuzz.in/transaction/v2/refund` | `https://dashboard.easebuzz.in/transaction/v2/refund` |
| 5 | EaseBuzRefundSync | POST | `https://testdashboard.easebuzz.in/refund/v1/retrieve` | `https://dashboard.easebuzz.in/refund/v1/retrieve` |
| 6 | EasebuzzSubmitOtp | POST | `https://testpay.easebuzz.in/otp/v1/confirm` | `https://pay.easebuzz.in/otp/v1/confirm` |
| 7 | EasebuzzResendOtp | POST | `https://testpay.easebuzz.in/otp/v1/resend` | `https://pay.easebuzz.in/otp/v1/resend` |
| 8 | GetEMIOptions | POST | `https://testpay.easebuzz.in/v1/getEMIOptions` | `https://pay.easebuzz.in/v1/getEMIOptions` |
| 9 | EasebuzGetPlans | POST | `https://testpay.easebuzz.in/emi/v1/retrieve` | `https://pay.easebuzz.in/emi/v1/retrieve` |
| 10 | DelayedSettlement | POST | `https://testdashboard.easebuzz.in/settlements/v1/ondemand/initiate/` | `https://dashboard.easebuzz.in/settlements/v1/ondemand/initiate/` |
| 11 | DelayedSettlementStatus | POST | `https://testdashboard.easebuzz.in/settlements/v1/ondemand/status/` | `https://dashboard.easebuzz.in/settlements/v1/ondemand/status/` |
| 12 | EasebuzzAuthzRequest | POST | `https://testpay.easebuzz.in/payment/v1/capture/direct` | `https://pay.easebuzz.in/payment/v1/capture/direct` |
| 13 | GenerateAccessKey | POST | `https://sandboxapi.easebuzz.in/autocollect/v1/access-key/generate/` | `https://api.easebuzz.in/autocollect/v1/access-key/generate/` |
| 14 | MandateCreation | POST | `https://sandboxapi.easebuzz.in/autocollect/v1/mandate/` | `https://api.easebuzz.in/autocollect/v1/mandate/` |
| 15 | MandateRetrieve | GET | `https://sandboxapi.easebuzz.in/autocollect/v1/mandate/:txnId/` | `https://api.easebuzz.in/autocollect/v1/mandate/:txnId/` |
| 16 | PresentmentRequestInitiate | POST | `https://sandboxapi.easebuzz.in/autocollect/v1/mandate/presentment/` | `https://api.easebuzz.in/autocollect/v1/mandate/presentment/` |
| 17 | DebitRequestRetrieve | GET | `https://sandboxapi.easebuzz.in/autocollect/v1/mandate/presentment/:txnId/` | `https://api.easebuzz.in/autocollect/v1/mandate/presentment/:txnId/` |
| 18 | UpiAutopay | POST | `https://sandboxapi.easebuzz.in/autocollect/v1/mandate/process/` | `https://api.easebuzz.in/autocollect/v1/mandate/process/` |
| 19 | NotificationReq | POST | `https://sandboxapi.easebuzz.in/autocollect/v1/mandate/notify/` | `https://api.easebuzz.in/autocollect/v1/mandate/notify/` |
| 20 | UpiMandateExecute | POST | `https://sandboxapi.easebuzz.in/autocollect/v1/mandate/execute/` | `https://api.easebuzz.in/autocollect/v1/mandate/execute/` |
| 21 | RevokeMandate | POST | `https://sandboxapi.easebuzz.in/autocollect/v1/mandate/:mandateId/status_update/` | `https://api.easebuzz.in/autocollect/v1/mandate/:mandateId/status_update/` |
| 22 | MandateNotificationSyncReq | GET | `https://sandboxapi.easebuzz.in/autocollect/v1/mandate/notification/:notificationReqId/` | `https://api.easebuzz.in/autocollect/v1/mandate/notification/:notificationReqId/` |
| 23 | ProcessMandateAuthorization | POST | `https://sandboxapi.easebuzz.in/autocollect/v1/si/mandate/activate/` | `https://api.easebuzz.in/autocollect/v1/si/mandate/activate/` |
| 24 | EasebuzzEmiPlans (gateway) | POST | `https://testpay.easebuzz.in/emi/v1/retrieve` | `https://pay.easebuzz.in/emi/v1/retrieve` |
| 25 | EasebuzzVerifyVpa (gateway) | POST | n/a (always) | `https://api.easebuzz.in/verify/v1/vpa` |
| 26 | EasebuzzEligibility (gateway) | POST | `https://testpay.easebuzz.in/eligibility/v1/check` | `https://pay.easebuzz.in/eligibility/v1/check` |

---

## 2. Authentication

### 2.1 Authentication Method
- **Auth Type**: SHA-512 HMAC hash (passed as form field or `Authorization` header depending on API); AES-256-CBC encryption for sensitive card/bank fields
- **Auth Header (Mandate/SI APIs)**: `Authorization: <sha512-hash>`; `X-EB-MERCHANT-KEY: <key>`
- **Auth Header (Verify VPA)**: `Authorization: <sha512(key|vpa|salt)>`
- **Credential Source**: `EaseBuzzDetails` decoded from `MerchantGatewayAccount.accountDetails` — contains `easebuzzKey`, `easebuzzSalt`, `s2sEnabled`

### 2.2 Authentication Flow

#### Payment APIs (InitiatePayment, Seamless)
1. Retrieve `EaseBuzzDetails` via `decodeGatewayCredentials accountDetails`
2. Compute SHA-512 hash: `sha512(key|txnid|amount|productinfo|firstname|email|udf1..udf10|salt)` for InitiatePayment; per-API formula for other calls
3. Include `hash` field in form body

#### Mandate / SI APIs (GenerateAccessKey, MandateCreation, etc.)
1. Compute access token hash: `sha512(key|amount|transactionId|salt)` → sent as `Authorization` header
2. Include `X-EB-MERCHANT-KEY: <easebuzzKey>` header
3. Sensitive fields (card number, CVV, account number, VPA) encrypted using AES-256-CBC:
   - **Key**: first 32 bytes of `sha256(easebuzzKey)`
   - **IV**: first 16 bytes of `sha256(easebuzzSalt)`
4. Mandate register hash: `sha512(key|accNo|ifsc|upihandle|salt)`

#### Verify VPA
1. Compute: `sha512(key|vpa|salt)`
2. Send as `Authorization` header value

#### Conditional Gateway Headers (feature flag `enableGwHeader`)
When enabled, add to requests:
- `X-EB-MERCHANT-KEY: <easebuzzKey>`
- `X-EB-PAYMENT-MODE: <paymentMode>`
- `X-EB-SUB-MERCHANT-ID: <subMerchantId>` (if present)

**Source**: `makeEaseBuzzRequestHeaders`, `makeEaseBuzzRequestHeaders'`, `aesEncForEaseBuzz`, `makeAccessTokenHash`, `makeMandateRegisterHash` — `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Transforms.hs`

### 2.3 Required Headers

| # | Header Name | Value / Source | Required | Description |
|---|-------------|---------------|----------|-------------|
| 1 | `Content-Type` | `application/x-www-form-urlencoded` | Yes (payment APIs) | Body encoding for payment/seamless APIs |
| 2 | `Content-Type` | `application/json` | Yes (mandate/SI APIs) | Body encoding for autocollect APIs |
| 3 | `Authorization` | `sha512(key\|...\|salt)` | Yes (mandate/SI, verify VPA APIs) | HMAC-SHA512 auth hash |
| 4 | `X-EB-MERCHANT-KEY` | `easebuzzKey` from `EaseBuzzDetails` | Conditional (`enableGwHeader` flag) | Merchant key header |
| 5 | `X-EB-PAYMENT-MODE` | Payment mode string (e.g., `"CARD"`, `"UPI"`) | Conditional (`enableGwHeader` flag) | Payment mode header |
| 6 | `X-EB-SUB-MERCHANT-ID` | `sub_merchant_id` from request | Conditional (if present + flag) | Sub-merchant identifier |

---

## 3. Request Structure

### 3.1 URL Parameters

**Path Parameters** (Mandate/SI retrieve/revoke endpoints):

| # | Parameter | Type | Source | Description |
|---|-----------|------|--------|-------------|
| 1 | `txnId` | Text | `txnDetail.txnId` | Transaction ID used in MandateRetrieve and DebitRequestRetrieve |
| 2 | `mandateId` | Text | `mandate.id` or gateway mandate ID | Mandate ID used in RevokeMandate |
| 3 | `notificationReqId` | Text | Notification request ID | Used in MandateNotificationSyncReq |

**Query Parameters**: None — all parameters are in the request body.

### 3.2 Request Body — `EaseBuzzInitiatePaymentRequest`

**Type**: `EaseBuzzInitiatePaymentRequest` — `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Types.hs:254`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `key` | `Text` | `key` | Yes | Merchant API key (`easebuzzKey`) |
| 2 | `txnid` | `Text` | `txnid` | Yes | Transaction ID |
| 3 | `amount` | `Text` | `amount` | Yes | Transaction amount as string |
| 4 | `productinfo` | `Text` | `productinfo` | Yes | Product description |
| 5 | `firstname` | `Text` | `firstname` | Yes | Customer first name |
| 6 | `phone` | `Text` | `phone` | Yes | Customer phone |
| 7 | `email` | `Text` | `email` | Yes | Customer email |
| 8 | `surl` | `Text` | `surl` | Yes | Success URL (redirect target) |
| 9 | `furl` | `Text` | `furl` | Yes | Failure URL (redirect target) |
| 10 | `hash` | `Text` | `hash` | Yes | SHA-512 hash of key\|txnid\|amount\|productinfo\|firstname\|email\|udf1..udf10\|salt |
| 11 | `udf1` | `Maybe Text` | `udf1` | No | User-defined field 1 |
| 12 | `udf2` | `Maybe Text` | `udf2` | No | User-defined field 2 |
| 13 | `udf3` | `Maybe Text` | `udf3` | No | User-defined field 3 |
| 14 | `udf4` | `Maybe PII.PII` | `udf4` | No | User-defined field 4 (PII-masked) |
| 15 | `udf5` | `Maybe Text` | `udf5` | No | User-defined field 5 |
| 16 | `udf6` | `Maybe Text` | `udf6` | No | User-defined field 6 |
| 17 | `udf7` | `Maybe Text` | `udf7` | No | User-defined field 7 |
| 18 | `udf8` | `Maybe Text` | `udf8` | No | User-defined field 8 |
| 19 | `udf9` | `Maybe Text` | `udf9` | No | User-defined field 9 |
| 20 | `udf10` | `Maybe Text` | `udf10` | No | User-defined field 10 |
| 21 | `address1` | `Maybe Text` | `address1` | No | Billing address line 1 |
| 22 | `address2` | `Maybe Text` | `address2` | No | Billing address line 2 |
| 23 | `city` | `Maybe Text` | `city` | No | Billing city |
| 24 | `state` | `Maybe Text` | `state` | No | Billing state |
| 25 | `country` | `Maybe Text` | `country` | No | Billing country |
| 26 | `zipcode` | `Maybe PII.PII` | `zipcode` | No | Billing zip/postal code (PII-masked) |
| 27 | `request_flow` | `Maybe Text` | `request_flow` | No | Requested payment flow |
| 28 | `split_payments` | `Maybe (StrMap Number)` | `split_payments` | No | Split payment configuration |
| 29 | `sub_merchant_id` | `Maybe Text` | `sub_merchant_id` | No | Sub-merchant identifier |
| 30 | `extra_udf` | `Maybe SurchargeDetails` | `extra_udf` | No | Surcharge details (base, surcharge, GST amounts) |
| 31 | `account_no` | `Maybe Text` | `account_no` | No | Bank account number (TPV transactions) |
| 32 | `ifsc` | `Maybe Text` | `ifsc` | No | IFSC code (TPV transactions) |
| 33 | `payment_category` | `Maybe Text` | `payment_category` | No | Payment category |

**Field Count**: 33 fields

### 3.3 Nested Request Types

#### SurchargeDetails — `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Types.hs:291`
Used in field: `extra_udf`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `base_amount` | `Maybe Number` | `base_amount` | No | Base transaction amount before surcharge |
| 2 | `surcharge_amount` | `Number` | `surcharge_amount` | Yes | Surcharge amount to add |
| 3 | `gst_amount` | `Maybe Number` | `gst_amount` | No | GST on surcharge |

#### EaseBuzzSeamlessTxnRequest — `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Types.hs:383`
Used for: Seamless payment initiation (POST to `EasebuzSeamlessTransaction`)

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `access_key` | `Text` | `access_key` | Yes | Access key from InitiatePayment response |
| 2 | `payment_mode` | `Text` | `payment_mode` | Yes | Payment mode (e.g., `CARD`, `UPI`, `NB`, `PL`, `EMI`) |
| 3 | `pay_later_app` | `Maybe Text` | `pay_later_app` | No | Pay-later app identifier |
| 4 | `bank_code` | `Maybe Text` | `bank_code` | No | Net banking bank code |
| 5 | `card_number` | `Maybe Text` | `card_number` | No | Card number (encrypted for mandate flows) |
| 6 | `card_holder_name` | `Maybe Text` | `card_holder_name` | No | Name on card |
| 7 | `card_cvv` | `Maybe Text` | `card_cvv` | No | Card CVV |
| 8 | `card_expiry_date` | `Maybe Text` | `card_expiry_date` | No | Card expiry (MM/YY) |
| 9 | `upi_va` | `Maybe Text` | `upi_va` | No | UPI VPA (for UPI collect) |
| 10 | `upi_qr` | `Maybe Text` | `upi_qr` | No | UPI QR flag |
| 11 | `request_mode` | `Maybe Text` | `request_mode` | No | Request mode hint |
| 12 | `card_token` | `Maybe Text` | `card_token` | No | Tokenized card reference |
| 13 | `cryptogram` | `Maybe Text` | `cryptogram` | No | Cryptogram for tokenized transactions |
| 14 | `token_expiry_date` | `Maybe Text` | `token_expiry_date` | No | Token expiry date |
| 15 | `token_requester_id` | `Maybe Text` | `token_requester_id` | No | Token requestor ID (for network tokens) |
| 16 | `card_signature` | `Maybe Text` | `card_signature` | No | Card signature (Diners/AMEX) |
| 17 | `sub_transaction_type` | `Maybe Text` | `sub_transaction_type` | No | Sub-transaction type |
| 18 | `token_reference_id` | `Maybe Text` | `token_reference_id` | No | Alt-ID token reference |
| 19 | `card_last_4_digits` | `Maybe Text` | `card_last_4_digits` | No | Last 4 digits (Diners) |
| 20 | `emi_object` | `Maybe Text` | `emi_object` | No | JSON-encoded EMI object for EMI flows |
| 21 | `easy_installments_identifier` | `Maybe Text` | `easy_installments_identifier` | No | Cardless EMI unique identifier |
| 22 | `surcharge` | `Maybe Bool` | `surcharge` | No | Surcharge enabled flag |
| 23 | `platform_charges` | `Maybe Number` | `platform_charges` | No | Platform fee amount |
| 24 | `gst` | `Maybe Number` | `gst` | No | GST amount |
| 25 | `is_ios` | `Maybe Text` | `is_ios` | No | iOS platform flag |

#### EaseBuzzTxnSyncRequest — `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Types.hs:711`
Used for: Transaction status sync

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `txnid` | `Text` | `txnid` | Yes | Transaction ID |
| 2 | `amount` | `Number` | `amount` | Yes | Transaction amount |
| 3 | `email` | `Text` | `email` | Yes | Customer email |
| 4 | `phone` | `Text` | `phone` | Yes | Customer phone |
| 5 | `key` | `Text` | `key` | Yes | Merchant API key |
| 6 | `hash` | `Text` | `hash` | Yes | `sha512(key\|txnid\|amount\|email\|phone\|salt)` |

#### EaseBuzzRefundRequest — `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Types.hs:820`
Used for: Refund initiation

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `key` | `Text` | `key` | Yes | Merchant API key |
| 2 | `merchant_refund_id` | `Text` | `merchant_refund_id` | Yes | Merchant's refund reference ID |
| 3 | `easebuzz_id` | `Text` | `easebuzz_id` | Yes | Easebuzz transaction ID |
| 4 | `refund_amount` | `Text` | `refund_amount` | Yes | Amount to refund |
| 5 | `hash` | `Text` | `hash` | Yes | `sha512(key\|merchantRefundId\|easebuzzId\|refundAmount\|salt)` |
| 6 | `refund_type` | `Maybe Text` | `refund_type` | No | Refund type |
| 7 | `split_labels` | `Maybe (StrMap Number)` | `split_labels` | No | Split payment refund labels |

#### EaseBuzzRefundSyncRequest — `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Types.hs:846`
Used for: Refund status sync

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `key` | `Text` | `key` | Yes | Merchant API key |
| 2 | `easebuzz_id` | `Text` | `easebuzz_id` | Yes | Easebuzz transaction ID |
| 3 | `hash` | `Text` | `hash` | Yes | `sha512(key\|easebuzzId\|salt)` |
| 4 | `merchant_refund_id` | `Text` | `merchant_refund_id` | Yes | Merchant refund reference |

#### EaseBuzzSubmitOtpRequest — `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Types.hs:324`
Used for: OTP submission (LazyPay DOTP)

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `access_key` | `Text` | `access_key` | Yes | Session access key |
| 2 | `merchant_key` | `Text` | `merchant_key` | Yes | Merchant API key |
| 3 | `otp` | `Text` | `otp` | Yes | OTP entered by customer |
| 4 | `easepayid` | `Text` | `easepayid` | Yes | Easebuzz pay ID from trigger OTP response |
| 5 | `checksum` | `Text` | `checksum` | Yes | `sha512(key\|otp\|easebuzzPayId\|salt)` |

#### EaseBuzzResendOtpRequest — `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Types.hs:356`
Used for: OTP resend

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `access_key` | `Text` | `access_key` | Yes | Session access key |
| 2 | `merchant_key` | `Text` | `merchant_key` | Yes | Merchant API key |
| 3 | `easepayid` | `Text` | `easepayid` | Yes | Easebuzz pay ID |
| 4 | `checksum` | `Text` | `checksum` | Yes | `sha512(key\|easebuzzId\|salt)` |

#### EaseBuzzAccessKeyRequest — `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Types.hs:1059`
Used for: Mandate/SI access key generation

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `key` | `Text` | `key` | Yes | Merchant API key |
| 2 | `transaction_id` | `Text` | `transaction_id` | Yes | Transaction/mandate reference ID |
| 3 | `success_url` | `Text` | `success_url` | Yes | Redirect URL on success |
| 4 | `failure_url` | `Text` | `failure_url` | Yes | Redirect URL on failure |
| 5 | `submerchant_id` | `Maybe Text` | `submerchant_id` | No | Sub-merchant ID |
| 6 | `request_type` | `Text` | `request_type` | Yes | Request type (`EN`, `SI`, `UPIAD`) |
| 7 | `amount` | `Number` | `amount` | Yes | Mandate max amount |
| 8 | `email` | `Text` | `email` | Yes | Customer email |
| 9 | `phone` | `Text` | `phone` | Yes | Customer phone |
| 10 | `start_date` | `Text` | `start_date` | Yes | Mandate start date |
| 11 | `end_date` | `Text` | `end_date` | Yes | Mandate end date |
| 12 | `frequency` | `Text` | `frequency` | Yes | Mandate frequency |
| 13 | `amount_rule` | `Maybe Text` | `amount_rule` | No | Amount rule (FIXED/MAX) |
| 14 | `upfront_presentment_amount` | `Maybe Number` | `upfront_presentment_amount` | No | Upfront presentment amount |
| 15 | `payment_modes` | `[Text]` | `payment_modes` | Yes | Allowed payment modes |
| 16 | `udf1` | `Maybe Text` | `udf1` | No | User-defined field 1 |
| 17 | `udf2` | `Maybe Text` | `udf2` | No | User-defined field 2 |
| 18 | `udf3` | `Maybe Text` | `udf3` | No | User-defined field 3 |
| 19 | `udf4` | `Maybe PII.PII` | `udf4` | No | User-defined field 4 (PII-masked) |
| 20 | `udf5` | `Maybe Text` | `udf5` | No | User-defined field 5 |
| 21 | `udf6` | `Maybe Text` | `udf6` | No | User-defined field 6 |
| 22 | `udf7` | `Maybe Text` | `udf7` | No | User-defined field 7 |
| 23 | `debit_amount` | `Maybe Number` | `debit_amount` | No | Debit amount for ONETIME mandates |
| 24 | `si_flow_type` | `Maybe Text` | `si_flow_type` | No | SI flow type |
| 25 | `split_details` | `Maybe (StrMap Number)` | `split_details` | No | Split details for split settlement |

#### EaseBuzzCreateMandateRequest — `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Types.hs:1228`
Used for: eNACH/eMandate registration (NB/AADHAAR/PAPERNACH)

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `key` | `Text` | `key` | Yes | Merchant API key |
| 2 | `access_key` | `Text` | `access_key` | Yes | Access key from GenerateAccessKey |
| 3 | `mandate_type` | `Text` | `mandate_type` | Yes | Mandate type (e.g., `NACH`, `AADHAAR`) |
| 4 | `account_number` | `Text` | `account_number` | Yes | AES-encrypted bank account number |
| 5 | `account_holder_name` | `Text` | `account_holder_name` | Yes | AES-encrypted account holder name |
| 6 | `ifsc` | `Text` | `ifsc` | Yes | IFSC code |
| 7 | `auth_mode` | `Text` | `auth_mode` | Yes | Authentication mode (`NB`, `AADHAAR`, `DEBITCARD`) |
| 8 | `account_type` | `Text` | `account_type` | Yes | AES-encrypted account type (`savings`/`current`) |
| 9 | `bank_code` | `Text` | `bank_code` | Yes | Bank code |
| 10 | `authorization` | `Text` | `Authorization` | Yes | SHA-512 hash (`sha512(key\|accNo\|ifsc\|upihandle\|salt)`) |

#### EaseBuzzCreateCardMandateRequest — `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Types.hs:1273`
Used for: SI on cards mandate registration

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `key` | `Text` | `key` | Yes | Merchant API key |
| 2 | `access_key` | `Text` | `access_key` | Yes | Access key |
| 3 | `mandate_type` | `Text` | `mandate_type` | Yes | `"cards"`, `"token"`, or `"alt_id"` |
| 4 | `auth_mode` | `Text` | `auth_mode` | Yes | Authentication mode |
| 5 | `card_number` | `Maybe Text` | `card_number` | No | AES-encrypted card number (for `cards` type) |
| 6 | `card_cvv` | `Maybe Text` | `card_cvv` | No | AES-encrypted CVV |
| 7 | `name_on_card` | `Maybe Text` | `name_on_card` | No | AES-encrypted name on card |
| 8 | `card_expiry` | `Maybe Text` | `card_expiry` | No | AES-encrypted card expiry |
| 9 | `save_card_consent` | `Int` | `save_card_consent` | Yes | Card save consent (1 = yes) |
| 10 | `authorization` | `Text` | `Authorization` | Yes | SHA-512 hash |
| 11 | `card_token` | `Maybe Text` | `card_token` | No | AES-encrypted card token (for `token` type) |
| 12 | `cryptogram` | `Maybe Text` | `cryptogram` | No | AES-encrypted cryptogram/TAVV |
| 13 | `alt_id` | `Maybe Text` | `alt_id` | No | AES-encrypted alt-ID card number (for `alt_id` type) |

#### EaseBuzzProcessMandateAuthorizationRequest — `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Types.hs:1326`
Used for: SI card mandate process/activate

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `key` | `Text` | `key` | Yes | Merchant API key |
| 2 | `transaction_id` | `Text` | `transaction_id` | Yes | Transaction ID |
| 3 | `card_token` | `Text` | `card_token` | Yes | AES-encrypted card token |
| 4 | `card_expiry` | `Text` | `card_expiry` | Yes | AES-encrypted card expiry |

#### EasebuzzPlansRequest (Gateway-side) — `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/Easebuzz/Types.hs:41`
Used for: EMI plans fetch (gateway side)

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `merchant_key` | `Text` | `merchant_key` | Yes | Merchant API key |
| 2 | `checksum` | `Text` | `checksum` | Yes | SHA-512 hash |
| 3 | `amount` | `Text` | `amount` | Yes | Transaction amount |
| 4 | `phone` | `Text` | `phone` | Yes | Customer phone |
| 5 | `transaction_id` | `Text` | `transaction_id` | Yes | Transaction reference ID |

#### VerifyVpaRequest (Gateway-side) — `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/Easebuzz/Types.hs:128`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `key` | `Text` | `key` | Yes | Merchant API key |
| 2 | `vpa` | `Text` | `vpa` | Yes | UPI VPA to verify |

#### EasebuzzEligibilityRequest (Gateway-side) — `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/Easebuzz/Types.hs:171`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `phone` | `Text` | `phone` | Yes | Customer phone |
| 2 | `merchant_key` | `Text` | `merchant_key` | Yes | Merchant API key |
| 3 | `checksum` | `Text` | `checksum` | Yes | SHA-512 hash |
| 4 | `payment_mode` | `Text` | `payment_mode` | Yes | Payment mode |
| 5 | `amount` | `Text` | `amount` | Yes | Transaction amount |
| 6 | `pay_later_app` | `Text` | `pay_later_app` | Yes | Pay-later app name |
| 7 | `email_id` | `Maybe Text` | `email_id` | No | Customer email |
| 8 | `sub_merchant_id` | `Maybe Text` | `sub_merchant_id` | No | Sub-merchant ID |

### 3.4 Request Enums

#### EasebuzzEndpoints — `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Endpoints.hs:12`

| # | Constructor | Endpoint Path | Description |
|---|-------------|--------------|-------------|
| 1 | `EaseBuzInitiatePayment` | `/payment/initiateLink` | Get access key for payment |
| 2 | `EasebuzSeamlessTransaction` | `/initiate_seamless_payment/` | Seamless payment with card/UPI/NB data |
| 3 | `EasebuzTxnSync` | `/transaction/v1/retrieve` | Sync transaction status |
| 4 | `EaseBuzRefund` | `/transaction/v2/refund` | Initiate refund |
| 5 | `EaseBuzRefundSync` | `/refund/v1/retrieve` | Sync refund status |
| 6 | `EasebuzzSubmitOtp` | `/otp/v1/confirm` | Submit OTP |
| 7 | `EasebuzzResendOtp` | `/otp/v1/resend` | Resend OTP |
| 8 | `GetEMIOptions` | `/v1/getEMIOptions` | Get EMI options for a bank |
| 9 | `EasebuzGetPlans` | `/emi/v1/retrieve` | Get EMI plans |
| 10 | `DelayedSettlement` | `/settlements/v1/ondemand/initiate/` | Initiate delayed settlement |
| 11 | `DelayedSettlementStatus` | `/settlements/v1/ondemand/status/` | Check settlement status |
| 12 | `EasebuzzAuthzRequest` | `/payment/v1/capture/direct` | Direct authorization capture |
| 13 | `GenerateAccessKey` | `/autocollect/v1/access-key/generate/` | Generate mandate access key |
| 14 | `MandateCreation` | `/autocollect/v1/mandate/` | Register mandate |
| 15 | `MandateRetrieve` | `/autocollect/v1/mandate/:txnId/` | Retrieve mandate status |
| 16 | `PresentmentRequestInitiate` | `/autocollect/v1/mandate/presentment/` | Initiate mandate presentment/debit |
| 17 | `DebitRequestRetrieve` | `/autocollect/v1/mandate/presentment/:txnId/` | Retrieve debit status |
| 18 | `UpiAutopay` | `/autocollect/v1/mandate/process/` | UPI Autopay collect |
| 19 | `NotificationReq` | `/autocollect/v1/mandate/notify/` | Send mandate notification |
| 20 | `UpiMandateExecute` | `/autocollect/v1/mandate/execute/` | Execute mandate payment |
| 21 | `RevokeMandate` | `/autocollect/v1/mandate/:mandateId/status_update/` | Revoke mandate |
| 22 | `MandateNotificationSyncReq` | `/autocollect/v1/mandate/notification/:notificationReqId/` | Sync notification status |
| 23 | `ProcessMandateAuthorization` | `/autocollect/v1/si/mandate/activate/` | Activate SI card mandate |

---

## 4. Response Structure

### 4.1 Response Body — `EaseBuzzInitiatePaymentResponse`

**Type**: `EaseBuzzInitiatePaymentResponse` — `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Types.hs:294`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `status` | `Int` | `status` | Yes | `1` = success (access key returned), other = failure |
| 2 | `error_desc` | `Maybe Text` | `error_desc` | No | Error description if status ≠ 1 |
| 3 | `_data` | `Text` | `data` | Yes | Access key string on success, or error message |

**Field Count**: 3 fields

### 4.2 Nested Response Types

#### EaseBuzzSeamlessTxnResponse — `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Types.hs:411`
Returned from `EasebuzSeamlessTransaction` and in webhook/sync responses

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `status` | `Text` | `status` | Yes | Transaction status (`success`, `failure`, `bounced`, etc.) |
| 2 | `txnid` | `Text` | `txnid` | Yes | Transaction ID |
| 3 | `easepayid` | `Text` | `easepayid` | Yes | Easebuzz internal pay ID |
| 4 | `bank_ref_num` | `Text` | `bank_ref_num` | Yes | Bank reference number |
| 5 | `amount` | `Text` | `amount` | Yes | Transaction amount |
| 6 | `error` | `Text` | `error` | Yes | Error code string |
| 7 | `error_Message` | `Text` | `error_Message` | Yes | Error message |
| 8 | `mode` | `Text` | `mode` | Yes | Payment mode used |
| 9 | `card_type` | `Text` | `card_type` | Yes | Card type |
| 10 | `cardnum` | `Text` | `cardnum` | Yes | Masked card number |
| 11 | `bankcode` | `Text` | `bankcode` | Yes | Bank code |
| 12 | `payment_source` | `Text` | `payment_source` | Yes | Payment source |
| 13 | `hash` | `Text` | `hash` | Yes | Response hash for verification |
| 14 | `key` | `Text` | `key` | Yes | Merchant key (echoed) |
| 15 | `email` | `Text` | `email` | Yes | Customer email |
| 16 | `phone` | `Text` | `phone` | Yes | Customer phone |
| 17 | `firstname` | `Text` | `firstname` | Yes | Customer first name |
| 18 | `productinfo` | `Text` | `productinfo` | Yes | Product info (echoed) |
| 19 | `surl` | `Text` | `surl` | Yes | Success URL |
| 20 | `furl` | `Text` | `furl` | Yes | Failure URL |
| 21 | `addedon` | `Text` | `addedon` | Yes | Transaction creation timestamp |
| 22 | `unmappedstatus` | `Text` | `unmappedstatus` | Yes | Raw unmapped status from gateway |
| 23 | `cardCategory` | `Text` | `cardCategory` | Yes | Card category |
| 24 | `name_on_card` | `Text` | `name_on_card` | Yes | Name on card |
| 25 | `issuing_bank` | `Text` | `issuing_bank` | Yes | Issuing bank name |
| 26 | `merchant_logo` | `Text` | `merchant_logo` | Yes | Merchant logo URL |
| 27 | `_PG_TYPE` | `Text` | `_PG_TYPE` | Yes | PG type |
| 28 | `net_amount_debit` | `Text` | `net_amount_debit` | Yes | Net debited amount |
| 29 | `cash_back_percentage` | `Text` | `cash_back_percentage` | Yes | Cashback percentage |
| 30 | `udf1`–`udf10` | `CustomText` | `udf1`–`udf10` | Yes | User-defined fields (echoed; `CustomText` handles bool/number/string) |
| 31 | `upi_va` | `Maybe Text` | `upi_va` | No | UPI VPA used |
| 32 | `auth_code` | `Maybe Text` | `auth_code` | No | Authorization code |
| 33 | `auth_ref_num` | `Maybe Text` | `auth_ref_num` | No | Authorization reference number |
| 34 | `deduction_percentage` | `Foreign` | `deduction_percentage` | Yes | Deduction percentage (can be string or number) |
| 35 | `settlement_amount` | `Maybe Foreign` | `settlement_amount` | No | Settlement amount |
| 36 | `service_charge` | `Maybe Foreign` | `service_charge` | No | Service charge |
| 37 | `service_tax` | `Maybe Foreign` | `service_tax` | No | Service tax |
| 38 | `discount_amount` | `Maybe Foreign` | `discount_amount` | No | Discount amount |

#### EaseBuzzTxnSyncResponse — `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Types.hs:714`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `status` | `Bool` | `status` | Yes | Sync API call success flag |
| 2 | `msg` | `TxnSyncMessageType` | `msg` | Yes | Response payload — success message or error text |

#### TxnSyncMessageType — `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Types.hs:717`

| # | Constructor | Description |
|---|-------------|-------------|
| 1 | `TxnSyncSuccessMessage EaseBuzzSeamlessTxnResponse` | Success — contains full transaction details |
| 2 | `TxnSyncErrorMessage Text` | Error — plain text error message |
| 3 | `TxnsyncErrorType EaseBuzzTxnsyncErrorType` | Structured error with `status` and `error` fields |

#### EaseBuzzTriggerOtpResponse — `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Types.hs:297`
Returned from seamless OTP trigger (LazyPay DOTP)

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `status` | `Bool` | `status` | Yes | Whether OTP was triggered |
| 2 | `next_step` | `Maybe Text` | `next_step` | No | Next step hint |
| 3 | `msg_title` | `Maybe Text` | `msg_title` | No | Response code/title |
| 4 | `msg_desc` | `Maybe Text` | `msg_desc` | No | Response description |
| 5 | `error_status` | `Maybe Text` | `error_status` | No | Error status if failed |
| 6 | `_data` | `EaseBuzzTriggerOtpResponseData` | `data` | Yes | OTP session data |

#### EaseBuzzTriggerOtpResponseData — `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Types.hs:306`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `amount` | `Text` | `amount` | Yes | Transaction amount |
| 2 | `session_time` | `Maybe Text` | `session_time` | No | Session timeout |
| 3 | `native_otp_support` | `Maybe Bool` | `native_otp_support` | No | Native OTP support flag |
| 4 | `easepayid` | `Text` | `easepayid` | Yes | Easebuzz pay ID for OTP submission |
| 5 | `error` | `Maybe Text` | `error` | No | Error if OTP trigger failed |
| 6 | `resend_otp_interval` | `Maybe Text` | `resend_otp_interval` | No | Seconds before OTP can be resent |

#### EaseBuzzSubmitOtpResponse — `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Types.hs:333`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `status` | `Bool` | `status` | Yes | Submission status |
| 2 | `validate` | `Maybe Bool` | `validate` | No | Validation flag |
| 3 | `_data` | `EaseBuzzSubmitOtpResponseData` | `data` | Yes | OTP result data |

#### EaseBuzzSubmitOtpResponseData — `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Types.hs:346`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `state` | `Text` | `state` | Yes | Transaction state post OTP |
| 2 | `otp_verification_status` | `Bool` | `otp_verification_status` | Yes | Whether OTP was verified |
| 3 | `easepayid` | `Text` | `easepayid` | Yes | Easebuzz pay ID |
| 4 | `attempts_left` | `Int` | `attempts_left` | Yes | Remaining OTP attempts |
| 5 | `error` | `Text` | `error` | Yes | Error code |
| 6 | `message` | `Text` | `message` | Yes | Human-readable message |

#### EaseBuzzRefundResponse — `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Types.hs:842`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `status` | `Bool` | `status` | Yes | Refund initiation success |
| 2 | `reason` | `Maybe Text` | `reason` | No | Failure reason |
| 3 | `easebuzz_id` | `Maybe Text` | `easebuzz_id` | No | Easebuzz transaction ID |
| 4 | `refund_id` | `Maybe Text` | `refund_id` | No | Easebuzz refund ID |
| 5 | `refund_amount` | `Maybe Number` | `refund_amount` | No | Confirmed refund amount |

#### EaseBuzzAccessKeyResponse — `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Types.hs:1089`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `success` | `Bool` | `success` | Yes | Whether access key was generated |
| 2 | `status` | `Maybe Bool` | `status` | No | Additional status flag |
| 3 | `access_key` | `Maybe Text` | `access_key` | No | Generated access key for mandate flow |
| 4 | `message` | `Maybe Text` | `message` | No | Error message if unsuccessful |
| 5 | `request_id` | `Maybe Text` | `request_id` | No | Easebuzz request ID |

#### MandateRedirectionResponseType — `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Types.hs:1103`
Returned from MandateCreation (redirect to bank for authorization)

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `id` | `Text` | `id` | Yes | Mandate ID |
| 2 | `transaction_id` | `Text` | `transaction_id` | Yes | Merchant transaction ID |
| 3 | `status` | `Text` | `status` | Yes | Mandate status |
| 4 | `start_date` | `Text` | `start_date` | Yes | Mandate start date |
| 5 | `end_date` | `Text` | `end_date` | Yes | Mandate end date |
| 6 | `frequency` | `Text` | `frequency` | Yes | Debit frequency |
| 7 | `customer_email` | `Text` | `customer_email` | Yes | Customer email |
| 8 | `customer_name` | `Text` | `customer_name` | Yes | Customer name |
| 9 | `customer_phone` | `Text` | `customer_phone` | Yes | Customer phone |
| 10 | `amount` | `Text` | `amount` | Yes | Mandate amount |
| 11 | `amount_rule` | `Text` | `amount_rule` | Yes | Amount rule (FIXED/MAX) |
| 12 | `is_revokable` | `Text` | `is_revokable` | Yes | Whether mandate can be revoked |
| 13 | `auth_mode` | `Text` | `auth_mode` | Yes | Authentication mode |
| 14 | `bank_code` | `Text` | `bank_code` | Yes | Bank code |
| 15 | `success_url` | `Text` | `success_url` | Yes | Success redirect URL |
| 16 | `failure_url` | `Text` | `failure_url` | Yes | Failure redirect URL |
| 17 | `created_at` | `Text` | `created_at` | Yes | Creation timestamp |
| 18 | `umrn` | `Maybe Text` | `umrn` | No | Unique Mandate Reference Number |
| 19 | `mandate_type` | `Maybe Text` | `mandate_type` | No | Mandate type |
| 20 | `submerchant_id` | `Maybe Text` | `submerchant_id` | No | Sub-merchant ID |
| 21 | `customer_account_number` | `Maybe Text` | `customer_account_number` | No | Customer account number |
| 22 | `customer_ifsc` | `Maybe Text` | `customer_ifsc` | No | Customer IFSC |
| 23 | `customer_upi_handle` | `Maybe Text` | `customer_upi_handle` | No | Customer UPI handle |
| 24 | `customer_account_type` | `Maybe Text` | `customer_account_type` | No | Account type |
| 25 | `upfront_presentment_amount` | `Maybe Text` | `upfront_presentment_amount` | No | Upfront debit amount |
| 26 | `response_metadotcode` | `Maybe Text` | `response_meta.code` | No | Response meta code |
| 27 | `response_metadotdescription` | `Maybe Text` | `response_meta.description` | No | Response meta description |
| 28 | `paper_enach_document` | `Maybe Text` | `paper_enach_document` | No | Paper NACH document URL |
| 29 | `bank_reference_number` | `Maybe Text` | `bank_reference_number` | No | Bank reference number |
| 30 | `debit_amount` | `Maybe Number` | `debit_amount` | No | Actual debit amount |
| 31 | `udf1`–`udf7` | `Maybe Text` | `udf1`–`udf7` | No | User-defined fields |

#### EaseBuzzProcessMandateResponse — `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Types.hs:1369`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `dataResponse` | `EaseBuzzProcessMandateData` | `data` | Yes | Mandate process result data |
| 2 | `request_id` | `Maybe Text` | `request_id` | No | Easebuzz request ID |
| 3 | `success` | `Maybe Bool` | `success` | No | Success flag |

#### EaseBuzzProcessMandateData — `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Types.hs:1391`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `id` | `Text` | `id` | Yes | Mandate ID |
| 2 | `transaction_id` | `Text` | `transaction_id` | Yes | Transaction ID |
| 3 | `status` | `Text` | `status` | Yes | `authorized`, `initiated`, or failure status |
| 4 | `sub_status` | `Maybe Text` | `sub_status` | No | Sub-status |
| 5 | `auth_mode` | `Text` | `auth_mode` | Yes | Authentication mode |
| 6 | `frequency` | `Text` | `frequency` | Yes | Mandate frequency |
| 7 | `mandate_type` | `Maybe Text` | `mandate_type` | No | Mandate type |

#### VerifyVpaResponse (Gateway-side) — `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/Easebuzz/Types.hs:134`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `success` | `Bool` | `success` | Yes | Whether VPA verification succeeded |
| 2 | `data_` | `VerifyVpaResponseData` | `data` | Yes | VPA verification details |

#### VerifyVpaResponseData — `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/Easebuzz/Types.hs:139`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `id` | `Text` | `id` | Yes | Verification request ID |
| 2 | `status` | `Text` | `status` | Yes | Verification status |
| 3 | `service_charge` | `Float` | `service_charge` | Yes | Service charge amount |
| 4 | `gst_amount` | `Float` | `gst_amount` | Yes | GST amount |
| 5 | `service_charge_with_gst` | `Float` | `service_charge_with_gst` | Yes | Total charge including GST |
| 6 | `unique_request_number` | `Text` | `unique_request_number` | Yes | Unique request number |
| 7 | `created_at` | `Text` | `created_at` | Yes | Creation timestamp |
| 8 | `is_valid` | `Bool` | `is_valid` | Yes | Whether VPA is valid |
| 9 | `vpa` | `Text` | `vpa` | Yes | VPA that was verified |
| 10 | `vpa_holder_name` | `Maybe Text` | `vpa_holder_name` | No | Name of VPA holder |

#### EasebuzzEligibilityResponse (Gateway-side) — `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/Easebuzz/Types.hs:183`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `status` | `Bool` | `status` | Yes | Eligibility check status |
| 2 | `_data` | `Maybe EasebuzzEligibilityResponseData` | `data` | No | Eligibility data if success |
| 3 | `error` | `Maybe EasebuzzEligibilityResponseError` | `error` | No | Error if failed |

#### EasebuzzEligibilityResponseData — `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/Easebuzz/Types.hs:197`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `pg_status` | `Text` | `pg_status` | Yes | PG eligibility status |
| 2 | `available_limit` | `Maybe Text` | `available_limit` | No | Available credit limit |
| 3 | `kfs_link_url` | `Maybe Text` | `kfs_link_url` | No | KFS document URL |
| 4 | `native_otp_support` | `Maybe Bool` | `native_otp_support` | No | Native OTP supported |
| 5 | `kfs_link_display` | `Maybe Bool` | `kfs_link_display` | No | Whether to display KFS link |

### 4.3 Response Enums

#### EasebuzzResponse — `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Types.hs:549`
Union type representing all possible parsed responses in the txns flow

| # | Constructor | Description |
|---|-------------|-------------|
| 1 | `TxnResp EaseBuzzSeamlessTxnResponse` | Redirect response from seamless payment |
| 2 | `SyncResp EaseBuzzTxnSyncResponse` | Txn sync response |
| 3 | `AuthzResp EasebuzzAuthZResponse` | Direct authorization capture response |
| 4 | `SubmitOtpResp EaseBuzzSubmitOtpResponse` | OTP submission response |
| 5 | `SubmitOtpFailResp EaseBuzzSubmitOtpFailureResponse` | OTP failure response |
| 6 | `MandateRedirectionResp MandateRedirectionResponseType` | Mandate creation redirect |
| 7 | `MandateRegSyncResp EaseBuzzRetriveMandateResp` | Mandate status sync |
| 8 | `MandateSyncValid MandateRetrieveResponseData` | Valid mandate sync data |
| 9 | `DebitRequestRetrieveResp DebitRequestRetrieveResponseData` | Debit request retrieve response |
| 10 | `MandateStatusUpdateWebhook EaseBuzzMandateStatusUpdateWebhook` | Mandate webhook |
| 11 | `PresentmentStatusUpdateWebhook EaseBuzzPresentmentStatusUpdateWebhook` | Presentment webhook |
| 12 | `MandateSyncFailResp EaseBuzzFailureType` | Mandate sync failure |

#### EasebuzzAuthZResponse — `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Types.hs:573`

| # | Constructor | Description |
|---|-------------|-------------|
| 1 | `ValidAuthZResponse EasebuzzOnlyAuthZResponse` | Successful authorization capture |
| 2 | `EasebuzzRedirectAuthzErrorResponse EasebuzzAuthZErrorResponse` | Authorization failed (error message) |

#### EaseBuzzRefundSyncResponse — `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Types.hs:927`

| # | Constructor | Description |
|---|-------------|-------------|
| 1 | `EaseBuzzRefundSyncSuccessResp EaseBuzzRefundSyncSuccessResponse` | Successful refund sync |
| 2 | `EaseBuzzRefundSyncFailureResp EaseBuzzRefundSyncFailureResponse` | Refund sync failure |
| 3 | `EaseBuzzRefundSyncValidationErrorResp EaseBuzzRefundSyncValidationErrorResponse` | Validation error |

#### EasebuzzPlansResp — `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Types.hs:955`

| # | Constructor | Description |
|---|-------------|-------------|
| 1 | `ValidEasebuzzPlansResp EasebuzzPlansResponse` | Valid plans response with `status: Bool` and `data: HashMap Text [EasebuzzPlans]` |
| 2 | `EasebuzzPlansErrorResp EasebuzzPlansErrorResponse` | Error with `status: Text` and `msg_desc: Text` |

#### EaseBuzzProcessMandateResp — `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Types.hs:1354`

| # | Constructor | Description |
|---|-------------|-------------|
| 1 | `ProcessMandateSuccess EaseBuzzProcessMandateResponse` | Mandate process succeeded |
| 2 | `ProcessMandateFailure EaseBuzzFailureType` | Mandate process failed |

#### EaseBuzzWebhookTypes — `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Types.hs:540`

| # | Constructor | Description |
|---|-------------|-------------|
| 1 | `RefundWebhook EaseBuzzRefundWebhookResponse` | Refund status update webhook |
| 2 | `MandateStatusUpdateWebhookResp EaseBuzzMandateStatusUpdateWebhook` | Mandate status update webhook |
| 3 | `PresentmentStatusUpdateWebhookResp EaseBuzzPresentmentStatusUpdateWebhook` | Presentment status update webhook |
| 4 | `SeamlessTxnResp EaseBuzzSeamlessTxnResponse` | Seamless transaction webhook |
| 5 | `MandateSyncValidRes MandateRetrieveResponseData` | Valid mandate sync result |
| 6 | `DebitRequestRetrieveRes DebitRequestRetrieveResponseData` | Debit retrieve result |
| 7 | `NotificationStatusUpdateWebhookResp EaseBuzzNotificationStatusUpdateWebhook` | Notification status update webhook |

#### EaseBuzzMandateRetrieveResponse — `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Types.hs:1458`
Response to `MandateRetrieve` (GET, route-param txnId)

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `dataResponse` | `MandateRetrieveResponseData` | `data` | Yes | Full mandate details |
| 2 | `request_id` | `Maybe Text` | `request_id` | No | Easebuzz request ID |
| 3 | `success` | `Maybe Bool` | `success` | No | Success flag |

#### MandateRetrieveResponseData — `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Types.hs:1479`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `id` | `Text` | `id` | Yes | Mandate ID at Easebuzz |
| 2 | `transaction_id` | `Text` | `transaction_id` | Yes | Merchant transaction ID |
| 3 | `status` | `Text` | `status` | Yes | Mandate status (`authorized`, `initiated`, `expired`, `revoked`, etc.) |
| 4 | `start_date` | `Text` | `start_date` | Yes | Mandate start date |
| 5 | `end_date` | `Text` | `end_date` | Yes | Mandate end date |
| 6 | `frequency` | `Text` | `frequency` | Yes | Debit frequency |
| 7 | `customer_email` | `Text` | `customer_email` | Yes | Customer email |
| 8 | `customer_phone` | `Text` | `customer_phone` | Yes | Customer phone |
| 9 | `amount` | `Number` | `amount` | Yes | Mandate amount |
| 10 | `amount_rule` | `Text` | `amount_rule` | Yes | `FIXED` / `MAX` |
| 11 | `is_revokable` | `Bool` | `is_revokable` | Yes | Whether mandate can be revoked |
| 12 | `bank_code` | `Text` | `bank_code` | Yes | Bank code |
| 13 | `umrn` | `Maybe Text` | `umrn` | No | Unique Mandate Reference Number |
| 14 | `mandate_type` | `Maybe Text` | `mandate_type` | No | Mandate type |
| 15 | `customer_account_number` | `Maybe Text` | `customer_account_number` | No | Customer bank account number |
| 16 | `customer_ifsc` | `Maybe Text` | `customer_ifsc` | No | Customer IFSC code |
| 17 | `customer_upi_handle` | `Maybe Text` | `customer_upi_handle` | No | Customer UPI handle |
| 18 | `customer_account_type` | `Maybe Text` | `customer_account_type` | No | Account type |
| 19 | `customer_name` | `Maybe Text` | `customer_name` | No | Customer name |
| 20 | `upfront_presentment_amount` | `Maybe Number` | `upfront_presentment_amount` | No | Amount for upfront debit |
| 21 | `auth_mode` | `Maybe Text` | `auth_mode` | No | Authentication mode used |
| 22 | `response_meta` | `Maybe ResponseMetaData` | `response_meta` | No | Gateway meta (code, error_code, message, description) |
| 23 | `paper_enach_document` | `Maybe Text` | `paper_enach_document` | No | Paper NACH document URL |
| 24 | `bank_reference_number` | `Maybe Text` | `bank_reference_number` | No | Bank reference number |
| 25 | `debit_amount` | `Maybe Number` | `debit_amount` | No | Actual debit amount |
| 26 | `success_url` | `Maybe Text` | `success_url` | No | Success redirect URL |
| 27 | `failure_url` | `Maybe Text` | `failure_url` | No | Failure redirect URL |
| 28 | `created_at` | `Text` | `created_at` | Yes | Creation timestamp |
| 29 | `account_holder_name` | `Maybe Text` | `account_holder_name` | No | Account holder name |
| 30 | `qr_url` | `Maybe Text` | `qr_url` | No | QR code URL |
| 31 | `intent_uri` | `Maybe Text` | `intent_uri` | No | UPI intent URI |
| 32 | `successful_number_of_debits` | `Maybe Number` | `successful_number_of_debits` | No | Count of successful debits |
| 33 | `block_fund` | `Maybe Bool` | `block_fund` | No | Whether fund block is enabled |
| 34 | `customer_accounts` | `Maybe [Text]` | `customer_accounts` | No | List of linked accounts |
| 35 | `tpv_validation_status` | `Maybe Bool` | `tpv_validation_status` | No | TPV validation result |
| 36 | `collected_amount` | `Maybe Number` | `collected_amount` | No | Total collected amount |
| 37 | `authorization` | `Maybe Text` | `authorization` | No | Authorization code |
| 38 | `upfront_presentment` | `Maybe DebitDetails` | `upfront_presentment` | No | Details of upfront debit (for AltId txns) |
| 39 | `udf1`–`udf7` | `Maybe Text` | `udf1`–`udf7` | No | User-defined fields |

#### ResponseMetaData — `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Types.hs:1566`
Embedded in many mandate/debit responses to carry structured error info from Easebuzz.

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `code` | `Maybe Text` | `code` | No | Gateway response code |
| 2 | `error_code` | `Maybe Text` | `error_code` | No | Specific error code |
| 3 | `message` | `Maybe Text` | `message` | No | Human-readable message |
| 4 | `description` | `Maybe Text` | `description` | No | Extended description |

#### DebitDetails — `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Types.hs:1536`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `pg_transaction_id` | `Maybe Text` | `pg_transaction_id` | No | PG transaction ID for upfront debit |
| 2 | `status` | `Maybe Text` | `status` | No | Status of upfront debit |
| 3 | `response_meta` | `Maybe ResponseMetaData` | `response_meta` | No | Meta details for this debit |

#### EaseBuzzDebitRequestResponse — `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Types.hs:1635`
Response to `PresentmentRequestInitiate` (execute mandate debit)

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `dataResponse` | `DebitRequestResponseData` | `data` | Yes | Debit execution result |
| 2 | `request_id` | `Maybe Text` | `request_id` | No | Easebuzz request ID |

#### DebitRequestResponseData — `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Types.hs:1654`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `id` | `Text` | `id` | Yes | Debit request ID |
| 2 | `pg_transaction_id` | `Text` | `pg_transaction_id` | Yes | PG transaction ID |
| 3 | `amount` | `Number` | `amount` | Yes | Amount debited |
| 4 | `presentment_date` | `Maybe Text` | `presentment_date` | No | Scheduled presentment date |
| 5 | `status` | `Text` | `status` | Yes | Debit status |
| 6 | `net_amount` | `Maybe Number` | `net_amount` | No | Net amount after deductions |
| 7 | `transaction_reference_number` | `Text` | `transaction_reference_number` | Yes | Reference number |
| 8 | `bank_reference_number` | `Maybe Text` | `bank_reference_number` | No | Bank reference |
| 9 | `status_at_bank` | `Maybe Text` | `status_at_bank` | No | Status as reported by bank |
| 10 | `split_payments` | `Maybe Value` | `split_payments` | No | Split payment details (JSON) |
| 11 | `response_meta` | `Maybe ResponseMetaData` | `response_meta` | No | Meta information |
| 12 | `merchant_request_number` | `Text` | `merchant_request_number` | Yes | Merchant debit request number |
| 13 | `created_at` | `Maybe Text` | `created_at` | No | Creation timestamp |
| 14 | `umrn` | `Maybe Text` | `umrn` | No | UMRN |
| 15 | `mandate` | `Maybe MandateType` | `mandate` | No | Linked mandate ref |
| 16 | `notification` | `Maybe NotificationType` | `notification` | No | Linked notification ref |
| 17 | `udf1`–`udf7` | `Maybe Text` | `udf1`–`udf7` | No | User-defined fields |

#### DebitRequestRetrieveResponseData — `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Types.hs:1726`
Response to `DebitRequestRetrieve` (GET by txnId) — same shape as `DebitRequestResponseData` with minor differences.

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `id` | `Text` | `id` | Yes | Debit request ID |
| 2 | `pg_transaction_id` | `Maybe Text` | `pg_transaction_id` | No | PG transaction ID (optional in retrieve) |
| 3 | `amount` | `Number` | `amount` | Yes | Amount |
| 4 | `presentment_date` | `Maybe Text` | `presentment_date` | No | Presentment date |
| 5 | `status` | `Text` | `status` | Yes | Current status |
| 6 | `net_amount` | `Maybe Number` | `net_amount` | No | Net amount |
| 7 | `transaction_reference_number` | `Maybe Text` | `transaction_reference_number` | No | Reference (optional in retrieve) |
| 8 | `bank_reference_number` | `Maybe Text` | `bank_reference_number` | No | Bank reference |
| 9 | `status_at_bank` | `Maybe Text` | `status_at_bank` | No | Bank status |
| 10 | `split_payments` | `Maybe Value` | `split_payments` | No | Split payment data |
| 11 | `response_meta` | `Maybe ResponseMetaData` | `response_meta` | No | Meta info |
| 12 | `merchant_request_number` | `Text` | `merchant_request_number` | Yes | Merchant request number |
| 13 | `created_at` | `Maybe Text` | `created_at` | No | Creation time |
| 14 | `umrn` | `Maybe Text` | `umrn` | No | UMRN |
| 15 | `mandate` | `Maybe MandateType` | `mandate` | No | Linked mandate |
| 16 | `notification` | `Maybe NotificationType` | `notification` | No | Linked notification |
| 17 | `authorization` | `Maybe Text` | `authorization` | No | Authorization code |
| 18 | `udf1`–`udf7` | `Maybe Text` | `udf1`–`udf7` | No | User-defined fields |

#### EaseBuzzFailureType — `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Types.hs:1552`
Generic failure wrapper used across mandate/debit/revoke flows.

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `success` | `Bool` | `success` | Yes | Always `false` |
| 2 | `status` | `Maybe Bool` | `status` | No | Optional status flag |
| 3 | `message` | `Text` | `message` | Yes | Error message |
| 4 | `request_id` | `Maybe Text` | `request_id` | No | Easebuzz request ID |

#### EaseBuzzNotificationRequest — `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Types.hs:1893`
Request to `NotificationReq` (pre-debit notification to customer)

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `key` | `Text` | `key` | Yes | Merchant key |
| 2 | `amount` | `Number` | `amount` | Yes | Amount to be debited |
| 3 | `transaction_id` | `Text` | `transaction_id` | Yes | Mandate transaction ID |
| 4 | `notification_request_number` | `Text` | `notification_request_number` | Yes | Merchant notification request number |
| 5 | `schedule_presentment` | `SchedulePresentment` | `schedule_presentment` | Yes | `Bool` (SI on Cards) or `Text` (UPI date string) |
| 6 | `split_payments` | `Maybe Text` | `split_payments` | No | Split payment info |

#### EaseBuzzNotificationResponse — `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Types.hs:1927`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `success` | `Bool` | `success` | Yes | Whether notification was sent |
| 2 | `dataResponse` | `EaseBuzzNotificationResponsetype` | `data` | Yes | Notification details |
| 3 | `request_id` | `Maybe Text` | `request_id` | No | Easebuzz request ID |

#### EaseBuzzNotificationResponsetype — `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Types.hs:1949`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `id` | `Text` | `id` | Yes | Notification ID at Easebuzz |
| 2 | `amount` | `Number` | `amount` | Yes | Notification amount |
| 3 | `net_amount` | `Maybe Number` | `net_amount` | No | Net amount |
| 4 | `status` | `Text` | `status` | Yes | `notified` / `failure` / pending |
| 5 | `created_at` | `Text` | `created_at` | Yes | Creation timestamp |
| 6 | `notification_request_number` | `Text` | `notification_request_number` | Yes | Merchant notification number |
| 7 | `scheduler` | `Maybe SchedulerType` | `scheduler` | No | Scheduler info |
| 8 | `notified_at` | `Maybe Text` | `notified_at` | No | Actual notification timestamp |
| 9 | `mandate` | `Maybe MandateType` | `mandate` | No | Linked mandate |
| 10 | `udf1`–`udf7` | `Maybe Text` | `udf1`–`udf7` | No | User-defined fields |

#### EaseBuzzMandateNotificationSyncRequest — `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Types.hs:2010`
Request to `MandateNotificationSyncReq` (GET, route-param notificationReqId)

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `key` | `Text` | `key` | Yes | Merchant key |

#### EaseBuzzMandateNotificationSyncResponse — `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Types.hs:2038`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `dataResponse` | `EaseBuzzNotificationResponsetype` | `data` | Yes | Notification data |
| 2 | `request_id` | `Maybe Text` | `request_id` | No | Easebuzz request ID |

#### EaseBuzzUpiExecuteMandateRequest — `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Types.hs:2061`
Request to `UpiMandateExecute` (execute UPI autopay or card token mandate)

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `key` | `Text` | `key` | Yes | Merchant key |
| 2 | `amount` | `Number` | `amount` | Yes | Amount to debit |
| 3 | `transaction_id` | `Text` | `transaction_id` | Yes | Mandate transaction ID |
| 4 | `notification_request_number` | `Maybe Text` | `notification_request_number` | No | Notification reference |
| 5 | `merchant_request_number` | `Text` | `merchant_request_number` | Yes | Merchant debit request number |
| 6 | `split_payments` | `Maybe (StrMap Number)` | `split_payments` | No | Split payment map |
| 7 | `cryptogram` | `Maybe Text` | `cryptogram` | No | AES-encrypted TAVV for token mandate |
| 8 | `card_token` | `Maybe Text` | `card_token` | No | AES-encrypted card token |
| 9 | `card_expiry` | `Maybe Text` | `card_expiry` | No | AES-encrypted card expiry |

#### EaseBuzzUpiExecutionResponse — `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Types.hs:2084`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `success` | `Bool` | `success` | Yes | Whether mandate execution succeeded |
| 2 | `dataResponse` | `DebitRequestResponseData` | `data` | Yes | Execution result |
| 3 | `request_id` | `Maybe Text` | `request_id` | No | Easebuzz request ID |

#### EasebuzzRevokeMandateRequest — `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Types.hs:2125`
Request to `RevokeMandate` (POST, route-param mandateId)

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `key` | `Text` | `key` | Yes | Merchant key |
| 2 | `status` | `Text` | `status` | Yes | New status to set (e.g., `"revoked"`) |
| 3 | `remarks` | `Text` | `remarks` | Yes | Reason for revocation |

#### EaseBuzzRevokeMandateResponse — `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Types.hs:2142`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `success` | `Bool` | `success` | Yes | Whether revocation succeeded |
| 2 | `message` | `Maybe Text` | `message` | No | Message |
| 3 | `dataResponse` | `MandateRetrieveResponseData` | `data` | Yes | Updated mandate details |
| 4 | `request_id` | `Maybe Text` | `request_id` | No | Easebuzz request ID |

#### EaseBuzUpiAutoPayReq — `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Types.hs:1774`
Request to `UpiAutopay` (UPI collect-based mandate registration)

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `key` | `Text` | `key` | Yes | Merchant key |
| 2 | `access_key` | `Text` | `access_key` | Yes | Generated access key |
| 3 | `mandate_type` | `Text` | `mandate_type` | Yes | Mandate type (e.g., `"CREATE"`) |
| 4 | `account_holder_name` | `Maybe Text` | `account_holder_name` | No | Account holder name |
| 5 | `upi_handle` | `Text` | `upi_handle` | Yes | Customer UPI VPA |
| 6 | `auth_mode` | `Text` | `auth_mode` | Yes | Authentication mode (`"COLLECT"`) |
| 7 | `is_ios` | `Maybe Text` | `is_ios` | No | iOS device flag |

#### EaseBuzzUpiAutoPayIntentReq — `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Types.hs:1833`
Request to `UpiAutopay` for intent-based UPI mandate registration

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `key` | `Text` | `key` | Yes | Merchant key |
| 2 | `access_key` | `Text` | `access_key` | Yes | Generated access key |
| 3 | `mandate_type` | `Text` | `mandate_type` | Yes | Mandate type |
| 4 | `auth_mode` | `Text` | `auth_mode` | Yes | Authentication mode (`"INTENT"`) |
| 5 | `account_holder_name` | `Maybe Text` | `account_holder_name` | No | Account holder name |

#### EaseBuzzSubMerchantMetadata — `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Types.hs:2883`
Decoded from order metadata to extract sub-merchant ID for Easebuzz header.

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `subMerchantId` | `Text` | `EASEBUZZ:sub_merchant_id` | Yes | Sub-merchant ID for `X-EB-SUB-MERCHANT-ID` header |

#### EasebuzzSyncAndWebhookResponse — `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Types.hs:2873`
Union type used specifically in mandate setup sync path.

| # | Constructor | Description |
|---|-------------|-------------|
| 1 | `WebhookResponse EaseBuzzSeamlessTxnResponse` | Seamless txn response (from webhook) |
| 2 | `TxnSyncResponse EaseBuzzTxnSyncResponse` | Txn sync response |
| 3 | `MandateSyncValidResp MandateRetrieveResponseData` | Valid mandate retrieve data |
| 4 | `MandateSyncFailResponse EaseBuzzFailureType` | Mandate failure response |
| 5 | `MandatePaymentSyncResp DebitRequestRetrieveResponseData` | Mandate payment retrieve data |

---

## 5. Flows

### 5.1 Flow: `initiateTxn` (Primary Entry Point)

**File**: `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Flow.hs:500`
**Purpose**: Dispatch to correct payment initiation sub-flow based on transaction type
**Trigger**: Called by orchestration layer when a new payment is to be initiated via Easebuzz

#### Steps

| Step | Action | Function | File | Details |
|------|--------|----------|------|---------|
| 1 | Check if EMI transaction | `txnDetail ^.. L._isEmi $ False` | `Flow.hs:502` | If true → `initiateEMITxn` |
| 2 | Check if eMandate registration | `Txn.isEmandateRegisterTOT txnDetail.txnObjectType` | `Flow.hs:503` | If true → `initEaseBuzzEmandateTxn` |
| 3 | Check if Card SI registration | `Txn.isMandateCardRegFlow txnDetail (txnCardInfo paymentMethodType)` | `Flow.hs:504` | If true → `initEaseBuzzPlainCardMandateTxn` |
| 4 | Default: Normal transaction | — | `Flow.hs:505` | → `initiateNormalTxn` |

#### Decision Points

| # | Condition | YES Branch | NO Branch |
|---|-----------|-----------|-----------|
| 1 | `txnDetail.isEmi == True` | `initiateEMITxn` | Continue to next check |
| 2 | `isEmandateRegisterTOT txnDetail.txnObjectType` | `initEaseBuzzEmandateTxn` | Continue to next check |
| 3 | `isMandateCardRegFlow` | `initEaseBuzzPlainCardMandateTxn` | `initiateNormalTxn` |

#### Flow Diagram

```
initiateTxn
    ├── [isEmi == True]    → initiateEMITxn
    ├── [isEmandate Reg]   → initEaseBuzzEmandateTxn
    ├── [Card SI Reg]      → initEaseBuzzPlainCardMandateTxn
    └── [otherwise]        → initiateNormalTxn
```

### 5.2 Sub-Flows

#### Sub-Flow: `initiateNormalTxn`

**File**: `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Flow.hs:770`
**Called From**: `initiateTxn`, Step 4
**Purpose**: Standard payment initiation (card/UPI/NB/wallet) — two-step API call

| Step | Action | Function | File |
|------|--------|----------|------|
| 1 | Check if TPV transaction | `TPV.isTpvTransaction txnDetail.txnObjectType` | `Flow.hs:772` |
| 2 | Decode credentials | `decodeGatewayCredentials accountDetails` | `Flow.hs:792` |
| 3 | Build initiatePayment request | `makeEaseBuzzInitiatePaymentRequest` | `Flow.hs:794` |
| 4 | Call API → `EaseBuzInitiatePayment` | `initEaseBuzzInitiatePayment` | `Flow.hs:796` |
| 5 | Check response status == 1 | — | `Flow.hs:799` |
| 6a | If token-based txn | `isTokenBasedTxn txnDetail` | `Flow.hs:803` | Validate TAVV + Token Requestor ID |
| 6b | If LazyPay DOTP | `isLazyPayDotpTxn` | `Flow.hs:814` | `callEasebuzzDotpFlow` |
| 6c | Default | `makeTransactionRequest` | `Flow.hs:816` | Build seamless request |
| 7 | Build seamless request | `makeEaseBuzzSeamlessTxnRequest` | `Flow.hs:867` |
| 8 | Return `GatewayRedirect` response | — | `Flow.hs:869` | URL = `EasebuzSeamlessTransaction` endpoint |

#### Sub-Flow: `initiateEMITxn`

**File**: `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Flow.hs:663`
**Called From**: `initiateTxn`, Step 1
**Purpose**: EMI payment initiation

| Step | Action | Function | File |
|------|--------|----------|------|
| 1 | Decode credentials | `decodeGatewayCredentials accountDetails` | `Flow.hs:665` |
| 2 | Get transaction amount | `getEasebuzzTransactionAmount` | `Flow.hs:666` |
| 3 | Get payment mode | `getPaymentMode txnCardInfo txnDetail` | `Flow.hs:667` |
| 4 | For CONSUMER_FINANCE: use cardless EMI params from SecondFactor | `getEmiDataCardless secondFactor` | `Flow.hs:670` |
| 5 | For card EMI: validate token params if tokenized | `isTokenBasedTxn` | `Flow.hs:683` |
| 6 | Build seamless request with `emi_object` JSON | `makeEaseBuzzSeamlessTxnRequest` | `Flow.hs:690` |
| 7 | Return `GatewayRedirect` to `EasebuzSeamlessTransaction` | — | `Flow.hs:694` |

#### Sub-Flow: `initEaseBuzzEmandateTxn`

**File**: `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Flow.hs:710`
**Called From**: `initiateTxn`, Step 2
**Purpose**: eNACH/eMandate registration via net banking or Aadhaar

| Step | Action | Function | File |
|------|--------|----------|------|
| 1 | Decode credentials | `decodeGatewayCredentials accountDetails` | `Flow.hs:715` |
| 2 | Generate access token | `initEaseBuzzAccessTokenRequest` | `Flow.hs:716` |
| 3 | Get bank details from `txnCardInfo.paymentSource` | `getBankDetails` | `Flow.hs:720` |
| 4 | AES-encrypt: account holder name, account type, account number | `aesEncForEaseBuzz` | `Flow.hs:723–724` |
| 5 | Compute mandate register hash | `makeMandateRegisterHash` | `Flow.hs:726` |
| 6 | Build mandate creation request | `makeEaseBuzzCreateMandateRequest` | `Flow.hs:727` |
| 7 | Return `GatewayRedirect` to `MandateCreation` | `makeGatewayRedirect` | `Flow.hs:728` |

#### Sub-Flow: `initEaseBuzzPlainCardMandateTxn`

**File**: `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Flow.hs:509`
**Called From**: `initiateTxn`, Step 3
**Purpose**: SI (Standing Instruction) on cards — mandate registration via card

| Step | Action | Function | File |
|------|--------|----------|------|
| 1 | Decode credentials + generate access token | `initEaseBuzzAccessTokenRequest` | `Flow.hs:515` |
| 2 | Check if token-based txn | `isTokenBasedTxn txnDetail` | `Flow.hs:520` |
| 3a | Alt-ID token: encrypt TAVV, alt-id card number, expiry, name | `aesEncForEaseBuzz` | `Flow.hs:528–531` |
| 3b | Regular token: encrypt TAVV, card token, expiry, name | `aesEncForEaseBuzz` | `Flow.hs:543–546` |
| 3c | Plain card: encrypt card number, CVV, name, expiry | `aesEncForEaseBuzz` | `Flow.hs:556–559` |
| 4 | Build card mandate request | `makeEaseBuzzCreateCardMandateRequest` | `Flow.hs:533/547/561` |
| 5 | Return `GatewayRedirect` to `MandateCreation` | `makeCardMandateGatewayRedirect` | `Flow.hs:534/548/562` |

#### Sub-Flow: `callEasebuzzDotpFlow` (LazyPay DOTP)

**File**: `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Flow.hs:890`
**Called From**: `initiateNormalTxn`, Step 6b
**Purpose**: LazyPay Direct OTP flow — trigger OTP and return DirectOTP response

| Step | Action | Function | File |
|------|--------|----------|------|
| 1 | Build seamless request with `payment_mode = "PL"` | `makeEaseBuzzSeamlessTxnRequest` | `Flow.hs:892` |
| 2 | Call trigger OTP API | `initEaseBuzzOtpRequest` | `Flow.hs:893` |
| 3 | On success: save auth params (accessKey, easepayid) in SecondFactor | `setAuthParams` | `Flow.hs:901` |
| 4 | Return `DirectOTPGatewayResponse` | — | `Flow.hs:904` |
| 5 | On failure: return `AUTHENTICATION_FAILED` | — | `Flow.hs:917` |

#### Sub-Flow: `getSdkParams` (UPI Intent / Collect)

**File**: `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Flow.hs:1089`
**Called From**: UPI flow handler
**Purpose**: UPI intent/collect — get QR link or intent URI

| Step | Action | Function | File |
|------|--------|----------|------|
| 1 | Check if eMandate intent | `Txn.isEmandateRegisterTOT` | `Flow.hs:1091` |
| 2 | Check if TPV | `TPV.isTpvTransaction` | `Flow.hs:1092` |
| 3 | Decode credentials | `getEaseBuzzDetails mga` | `Flow.hs:1103` |
| 4 | Call `initEaseBuzzInitiatePayment` for access key | `initEaseBuzzInitiatePayment` | `Flow.hs:1107` |
| 5 | Call UPI intent API | `initUpiIntentRequest` | `Flow.hs:1115` |
| 6 | Extract QR/intent link from response | `upiResponse ^.. L._qr_link` | `Flow.hs:1121` |
| 7 | Return `COMMON_INTENT_PARAMS SdkParams` | `makeEasebuzzSdkParams` | `Flow.hs:1127` |

#### Sub-Flow: `submitOtp`

**File**: `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Flow.hs:974`
**Called From**: OTP submission handler
**Purpose**: Submit OTP for LazyPay DOTP flow

| Step | Action | Function | File |
|------|--------|----------|------|
| 1 | Decode `gatewayAuthReqParams` from `SecondFactor` | — | `Flow.hs:976` |
| 2 | Decode gateway credentials | `decodeGatewayCredentials` | `Flow.hs:978` |
| 3 | Compute checksum: `sha512(key\|otp\|easebuzzPayId\|salt)` | — | `Flow.hs:981` |
| 4 | Build submit OTP request | `EaseBuzzSubmitOtpRequest` | `Flow.hs:983` |
| 5 | Call API | `callSubmitOtp` | `Flow.hs:991` |
| 6 | Return `SubmitOtpResp` or `SubmitOtpFailResp` | — | `Flow.hs:994–997` |

#### Sub-Flow: `resendOtp`

**File**: `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Flow.hs:1023`
**Called From**: OTP resend handler
**Purpose**: Resend OTP for LazyPay DOTP flow

| Step | Action | Function | File |
|------|--------|----------|------|
| 1 | Decode auth params from SecondFactor | — | `Flow.hs:1025` |
| 2 | Decode credentials | `decodeGatewayCredentials` | `Flow.hs:1027` |
| 3 | Compute checksum: `sha512(key\|easebuzzId\|salt)` | — | `Flow.hs:1033` |
| 4 | Build resend OTP request | `EaseBuzzResendOtpRequest` | `Flow.hs:1035` |
| 5 | Call API | `callResendOtp` | `Flow.hs:1042` |
| 6 | Return `ResendOTPResponse` | — | `Flow.hs:1046` |

#### Sub-Flow: `syncWithGateway`

**File**: `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Flow.hs:1425`
**Called From**: Post-redirect sync handler
**Purpose**: Mandatory sync after redirect to verify transaction status

| Step | Action | Function | File |
|------|--------|----------|------|
| 1 | Check `shouldConsumeRedirectionResponse` flag | — | `Flow.hs:1427` |
| 2 | For `TxnResp`: if CHARGED, call txn sync | `callSyncWithGateway` | `Flow.hs:1429` |
| 3 | For `MandateRedirectionResp`: call mandate status sync | `callEaseBuzzMandateRegisterStatus` | `Flow.hs:1444` |
| 4 | For `SubmitOtpResp`/`SubmitOtpFailResp`: call txn sync | `callTxnSync` | `Flow.hs:1455/1460` |
| 5 | On error: log and redirect to handle-response URL | `getHandleResponseUrl` | `Flow.hs:1440` |

#### Sub-Flow: `easeBuzzTxnSync` (Txn Sync Dispatcher)

**File**: `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Flow.hs:1748`
**Called From**: Transaction sync orchestration layer
**Purpose**: Dispatch to the correct sync sub-flow based on `txnObjectType`

| Step | Action | Function | File |
|------|--------|----------|------|
| 1 | Check `txnObjectType` | — | `Flow.hs:1750` |
| 2a | If `MANDATE_REGISTER` or `EMANDATE_REGISTER` | `mandateRegiSync` | `Flow.hs:1752` |
| 2b | If `MANDATE_PAYMENT` or `EMANDATE_PAYMENT` | `mandatePaymentSync` | `Flow.hs:1754` |
| 2c | Default | `normalTxnSync` | `Flow.hs:1756` |

#### Decision Points

| # | Condition | YES Branch | NO Branch |
|---|-----------|-----------|-----------|
| 1 | `isEmandateRegisterTOT \|\| isMandateRegisterTOT` | `mandateRegiSync` | Check mandate payment |
| 2 | `isEmandateTOT \|\| isMandateTOT` | `mandatePaymentSync` | `normalTxnSync` |

---

#### Sub-Flow: `normalTxnSync`

**File**: `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Flow.hs:1759`
**Called From**: `easeBuzzTxnSync` (default branch)
**Purpose**: Sync a normal (non-mandate) transaction via `EasebuzTxnSync` API

| Step | Action | Function | File |
|------|--------|----------|------|
| 1 | Decode credentials | `decodeGatewayCredentials` | `Flow.hs:1761` |
| 2 | Build sync request | `makeEaseBuzzTxnSyncRequest` | `Flow.hs:1763` |
| 3 | Call API → `EasebuzTxnSync` | `callEasebuzzTxnSync` | `Flow.hs:1764` |
| 4 | Parse `TxnSyncMessageType` from response | — | `Flow.hs:1767` |
| 5 | Update `PaymentGatewayResponse` from sync result | `updateGatewayTxnData` | `Flow.hs:1769` |
| 6 | Return updated PGR + TxnStatus | — | `Flow.hs:1772` |

---

#### Sub-Flow: `mandateRegiSync`

**File**: `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Flow.hs:1810`
**Called From**: `easeBuzzTxnSync` (MANDATE_REGISTER / EMANDATE_REGISTER)
**Purpose**: Sync mandate registration status — handles both regular and AltId txns

| Step | Action | Function | File |
|------|--------|----------|------|
| 1 | Decode credentials | `decodeGatewayCredentials` | `Flow.hs:1812` |
| 2 | Call mandate retrieve API → `MandateRetrieve` | `callEaseBuzzMandateRegisterStatus` | `Flow.hs:1814` |
| 3 | Parse response into `MandateRetrieveResponseData` | — | `Flow.hs:1817` |
| 4 | If AltId txn (`altIdTxn`): check `upfront_presentment.status` | `updateGatewayTxnDataForMandateReg` | `Flow.hs:1820` |
| 5 | Map mandate status string → internal `MandateStatus` | `getMandateStatus` | `Flow.hs:1823` |
| 6 | Update `PaymentGatewayResponse` + mandate object | `updateMandateInDB` | `Flow.hs:1825` |
| 7 | Return updated PGR | — | `Flow.hs:1830` |

**Special Case** (AltId txn): When `upfront_presentment` is present, the `pg_transaction_id` from the upfront debit is used as the PGR txn ID; the mandate status is derived from the upfront debit status rather than the mandate status field.

---

#### Sub-Flow: `mandatePaymentSync`

**File**: `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Flow.hs:1870`
**Called From**: `easeBuzzTxnSync` (MANDATE_PAYMENT / EMANDATE_PAYMENT)
**Purpose**: Sync mandate payment (debit) status via `DebitRequestRetrieve` API

| Step | Action | Function | File |
|------|--------|----------|------|
| 1 | Decode credentials | `decodeGatewayCredentials` | `Flow.hs:1872` |
| 2 | Get mandate debit reference from PGR | — | `Flow.hs:1874` |
| 3 | Call API → `DebitRequestRetrieve` (GET, route-param txnId) | `callDebitRequestRetrieve` | `Flow.hs:1876` |
| 4 | Parse `DebitRequestRetrieveResponseData` | — | `Flow.hs:1879` |
| 5 | Map status string → `TxnStatus` using `getTxnStatus` | `updateGatewayTxnDataForMandatePayment` | `Flow.hs:1882` |
| 6 | Return updated PGR | — | `Flow.hs:1885` |

---

#### Sub-Flow: `easeBuzzRefundRequest`

**File**: `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Flow.hs:1930`
**Called From**: Refund orchestration layer
**Purpose**: Initiate a refund — supports both standard and split-settle transactions

| Step | Action | Function | File |
|------|--------|----------|------|
| 1 | Decode credentials | `decodeGatewayCredentials` | `Flow.hs:1932` |
| 2 | Get `easepayid` from PGR | — | `Flow.hs:1934` |
| 3 | If mandate source object: use `pg_transaction_id` instead of `easepayid` | — | `Flow.hs:1936` |
| 4 | Check if split-settle transaction | `isSplitSettleTxn` | `Flow.hs:1939` |
| 5a | If split-settle: build JSON body with `split_labels` | `makeEaseBuzzSplitRefundRequest` | `Flow.hs:1942` |
| 5b | Otherwise: build form-encoded `EaseBuzzRefundRequest` | `makeEaseBuzzRefundRequest` | `Flow.hs:1946` |
| 6 | Compute refund hash: `sha512(key\|merchantRefundId\|easebuzzId\|refundAmount\|salt)` | — | `Flow.hs:1949` |
| 7 | Call API → `EaseBuzRefund` | `callEasebuzzRefund` | `Flow.hs:1951` |
| 8 | On success: update refund record, return `RefundSuccessResponse` | — | `Flow.hs:1955` |
| 9 | On failure: return `RefundFailedResponse` with reason | — | `Flow.hs:1959` |

---

#### Sub-Flow: `easeBuzzRefundSyncRequest`

**File**: `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Flow.hs:1978`
**Called From**: Refund sync orchestration layer
**Purpose**: Check refund status and map to internal refund state

| Step | Action | Function | File |
|------|--------|----------|------|
| 1 | Decode credentials | `decodeGatewayCredentials` | `Flow.hs:1980` |
| 2 | Build refund sync request | `makeEaseBuzzRefundSyncRequest` | `Flow.hs:1982` |
| 3 | Call API → `EaseBuzRefundSync` | `callEasebuzzRefundSync` | `Flow.hs:1984` |
| 4 | Parse `EaseBuzzRefundSyncResponse` variant | — | `Flow.hs:1987` |
| 5 | Map Easebuzz refund status → internal `RefundStatus` | — | `Flow.hs:1990` |
| 6 | Extract ARN from `EaseBuzzRefundSyncSuccessResponse.bank_ref_num` | — | `Flow.hs:1993` |
| 7 | Return updated refund record | — | `Flow.hs:1996` |

**Refund Status Mapping**:

| Easebuzz Refund Status | Internal RefundStatus |
|------------------------|----------------------|
| `"queued"` | `PENDING` |
| `"approved"` | `PENDING` |
| `"refunded"` | `SUCCESS` |
| `"cancelled"` | `FAILURE` |
| `"reverse chargeback"` | `FAILURE` |
| Any other | `PENDING` |

---

#### Sub-Flow: `executeMandate`

**File**: `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Flow.hs:2060`
**Called From**: Mandate payment execution orchestration layer
**Purpose**: Dispatch mandate debit to correct sub-flow based on mandate type

| Step | Action | Function | File |
|------|--------|----------|------|
| 1 | Check mandate type | — | `Flow.hs:2062` |
| 2a | UPI Autopay (non-OTM): send notification first | `callInitNotification` | `Flow.hs:2065` |
| 2b | Card mandate: send notification first | `callInitNotification` | `Flow.hs:2068` |
| 3a | UPI Autopay: call `UpiMandateExecute` | `callEaseBuzzUpiAutoPayExecute` | `Flow.hs:2072` |
| 3b | Card token mandate: call `executeCardTokenMandate` | `executeCardTokenMandate` | `Flow.hs:2075` |
| 3c | eNACH debit: call `PresentmentRequestInitiate` | `callPresentmentRequestInitiate` | `Flow.hs:2078` |
| 4 | Map response status → `TxnStatus` using `mapTxnStatus` | — | `Flow.hs:2082` |
| 5 | Update PGR + mandate payment record | — | `Flow.hs:2085` |

**Decision Points**:

| # | Condition | Branch |
|---|-----------|--------|
| 1 | `mandateType == UPI_AUTOPAY && !isOTM` | Send notification → UPI execute |
| 2 | `mandateType == SI_CARD` | Send notification → card token execute |
| 3 | `mandateType == eNACH / NACH` | Direct debit via PresentmentRequestInitiate |

---

#### Sub-Flow: `executeCardTokenMandate`

**File**: `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Flow.hs:2120`
**Called From**: `executeMandate` (card token mandate branch)
**Purpose**: Execute SI card mandate debit with AES-encrypted token/TAVV

| Step | Action | Function | File |
|------|--------|----------|------|
| 1 | Retrieve card token + TAVV + expiry from mandate/tokenProvider | — | `Flow.hs:2122` |
| 2 | AES-256-CBC encrypt: `card_token`, `card_expiry`, `cryptogram` (TAVV) | `aesEncForEaseBuzz` | `Flow.hs:2126` |
| 3 | Build `EaseBuzzUpiExecuteMandateRequest` with encrypted fields | — | `Flow.hs:2130` |
| 4 | Call API → `UpiMandateExecute` | `callEaseBuzzUpiAutoPayExecute` | `Flow.hs:2133` |
| 5 | Map response → `TxnStatus` via `mapTxnStatus` | — | `Flow.hs:2136` |
| 6 | Return updated PGR | — | `Flow.hs:2138` |

---

#### Sub-Flow: `revokeMandate` (and variants)

**File**: `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Flow.hs:2200`
**Called From**: Mandate revocation orchestration layer
**Purpose**: Revoke an active mandate at Easebuzz

The revoke flow has multiple entry points depending on context:

| Entry Point | Trigger | File |
|-------------|---------|------|
| `callEaseBuzzMandateRevokeApi` | Direct API revoke with mandate ID | `Flow.hs:2202` |
| `initiateAutoRevokeMandate` | Auto-revoke triggered internally | `Flow.hs:2230` |
| `autoRevokeMandateToken` | Token-based auto-revoke | `Flow.hs:2250` |
| `revokeMandateToken` | Revoke token mandate | `Flow.hs:2270` |

**`callEaseBuzzMandateRevokeApi` Steps**:

| Step | Action | Function | File |
|------|--------|----------|------|
| 1 | Decode credentials | `decodeGatewayCredentials` | `Flow.hs:2204` |
| 2 | Build revoke request: `{ key, status: "revoked", remarks }` | `EasebuzzRevokeMandateRequest` | `Flow.hs:2207` |
| 3 | Call API → `RevokeMandate` (POST, route-param mandateId) | `callRevokeMandate` | `Flow.hs:2210` |
| 4 | On success: update mandate status to `REVOKED` in DB | `updateMandateStatus` | `Flow.hs:2213` |
| 5 | On failure: return error response | — | `Flow.hs:2216` |

---

#### Sub-Flow: `checkMandateStatus` / `checkSiStatus`

**File**: `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Flow.hs:2290`
**Called From**: Mandate/SI status check flows
**Purpose**: Poll current mandate status from Easebuzz

| Step | Action | Function | File |
|------|--------|----------|------|
| 1 | Decode credentials | `decodeGatewayCredentials` | `Flow.hs:2292` |
| 2 | Call `MandateRetrieve` (GET) | `callEaseBuzzMandateRegisterStatus` | `Flow.hs:2294` |
| 3 | Parse `MandateRetrieveResponseData` | — | `Flow.hs:2297` |
| 4 | Map status string → `MandateStatus` via `getMandateStatus` | `getMandateStatus` | `Flow.hs:2300` |
| 5 | Return `MandateStatus` | — | `Flow.hs:2302` |

---

#### Sub-Flow: `initNotificationRequest` / `callInitNotification`

**File**: `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Flow.hs:2360`
**Called From**: `executeMandate` (UPI/card mandate branch, Step 2a/2b)
**Purpose**: Send pre-debit notification to customer before mandate debit

Two approaches depending on configuration:

| Approach | Trigger | Description |
|----------|---------|-------------|
| GSM path | `isGSM == True` | Uses Gateway Service Manager — notification sent via GSM with `getGwCodeGwMsg` |
| Direct API path | `isGSM == False` | Calls Easebuzz `NotificationReq` API directly |

**Direct API Steps**:

| Step | Action | Function | File |
|------|--------|----------|------|
| 1 | Build `EaseBuzzNotificationRequest` | — | `Flow.hs:2370` |
| 2 | Call API → `NotificationReq` | `callNotificationRequest` | `Flow.hs:2373` |
| 3 | Parse `EaseBuzzNotificationResponse` | — | `Flow.hs:2376` |
| 4 | Extract notification ID from `dataResponse.id` | — | `Flow.hs:2379` |
| 5 | Return notification ID for use in execute request | — | `Flow.hs:2381` |

---

#### Sub-Flow: `initNotificationSyncRequest` / `callNotificationStatus`

**File**: `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Flow.hs:2420`
**Called From**: Notification status sync orchestration
**Purpose**: Check pre-debit notification delivery status

| Step | Action | Function | File |
|------|--------|----------|------|
| 1 | Decode credentials | `decodeGatewayCredentials` | `Flow.hs:2422` |
| 2 | Build request: `{ key }` | `EaseBuzzMandateNotificationSyncRequest` | `Flow.hs:2424` |
| 3 | Call API → `MandateNotificationSyncReq` (GET, route-param notificationReqId) | `callNotificationStatus` | `Flow.hs:2426` |
| 4 | Parse `EaseBuzzMandateNotificationSyncResponse` | — | `Flow.hs:2429` |
| 5 | Map status → `NotificationStatus` via `getNotificationStatus` | `getNotificationStatus` | `Flow.hs:2432` |
| 6 | Return `NotificationStatus` | — | `Flow.hs:2434` |

---

#### Sub-Flow: Webhook Processing

**File**: `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Flow.hs:2500`
**Called From**: Webhook receipt handler
**Purpose**: Process inbound Easebuzz webhook events

| Function | Purpose | File |
|----------|---------|------|
| `extractWebhookResponse` | Deserialize raw JSON into `EaseBuzzWebhookTypes` union | `Flow.hs:2502` |
| `extractWebHookEvent` | Determine webhook event type from fields | `Flow.hs:2510` |
| `verifyWebhookResponse` | Verify SHA-512 hash of webhook payload | `Flow.hs:2518` |
| `updateGatewayTxnDataWithWebhookResponse` | Update PGR + TxnStatus from normal txn webhook | `Flow.hs:2530` |
| `verifyMandateStatusWebhook` | Process mandate status update webhook | `Flow.hs:2560` |
| `extractNotificationWebhookResponse` | Extract notification status update webhook | `Flow.hs:2575` |

**Webhook Event → Handler Mapping**:

| Webhook Type (EaseBuzzWebhookTypes) | Handler | Outcome |
|--------------------------------------|---------|---------|
| `SeamlessTxnResp` | `updateGatewayTxnDataWithWebhookResponse` | Update normal txn status |
| `RefundWebhook` | Refund record update | Update refund status |
| `MandateStatusUpdateWebhookResp` | `verifyMandateStatusWebhook` | Update mandate status via `getStatusFromWebhookRequest` |
| `PresentmentStatusUpdateWebhookResp` | Mandate payment status update | Update debit status |
| `NotificationStatusUpdateWebhookResp` | `extractNotificationWebhookResponse` | Update notification status |

---

#### Sub-Flow: `initateSplitSettelemt` / `syncTrasnfer` (Split Settlement)

**File**: `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Flow.hs:2650`
**Called From**: Settlement orchestration layer (for CHARGED or AUTO_REFUNDED txns)
**Purpose**: Initiate and sync on-demand split settlement

**`initateSplitSettelemt` Steps**:

| Step | Action | Function | File |
|------|--------|----------|------|
| 1 | Decode credentials | `decodeGatewayCredentials` | `Flow.hs:2652` |
| 2 | Build `CreateDelaySettlementRequest` | — | `Flow.hs:2655` |
| 3 | Call API → `DelayedSettlement` | `callDelayedSettlement` | `Flow.hs:2658` |
| 4 | On success: store settlement reference | — | `Flow.hs:2661` |
| 5 | On error: return `ErrorResponse` | — | `Flow.hs:2664` |

**`syncTrasnfer` Steps**:

| Step | Action | Function | File |
|------|--------|----------|------|
| 1 | Build `SettlementStatusCheckReq` | — | `Flow.hs:2680` |
| 2 | Call API → `DelayedSettlementStatus` | `callDelayedSettlementStatus` | `Flow.hs:2683` |
| 3 | Parse settlement status | — | `Flow.hs:2686` |
| 4 | Return settlement status | — | `Flow.hs:2689` |

---

#### Sub-Flow: `getEmiPlans` (Gateway-side)

**File**: `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/Easebuzz/Flow/Emi.hs`
**Called From**: Gateway EMI plans handler
**Purpose**: Fetch EMI plans from Easebuzz for a given amount

| Step | Action | Function | File |
|------|--------|----------|------|
| 1 | Validate and build plans request | — | `Emi.hs` |
| 2 | Compute SHA-512 checksum | — | `Emi.hs` |
| 3 | Call API → `EasebuzzEmiPlans` | `callCashFreeEmiPlans` | `Endpoint.hs:53` |
| 4 | Handle `ValidEasebuzzPlansResp` / `EasebuzzPlansErrorResp` | — | `Emi.hs` |

#### Sub-Flow: `addAuthenticationVerifyVpa` / `handleResponseVerifyVpa` (Gateway-side)

**File**: `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/Easebuzz/Flow/VerifyVpa.hs`
**Called From**: VPA verification handler
**Purpose**: Verify UPI VPA validity and get service charges

| Step | Action | Function | File |
|------|--------|----------|------|
| 1 | Build verify VPA request with `key` and `vpa` | — | `VerifyVpa.hs` |
| 2 | Compute Authorization: `sha512(key\|vpa\|salt)` | — | `VerifyVpa.hs` |
| 3 | Call API → `EasebuzzVerifyVpa` | `callEasebuzzVerifyVpa` | `Endpoint.hs:57` |
| 4 | Return `VerifyVpaResponse` with VPA validity, charges | — | `VerifyVpa.hs` |

#### Sub-Flow: `validateEasebuzzEligibilityRequest` / `handleEasebuzzEligibilityResponse` (Gateway-side)

**File**: `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/Easebuzz/Flow/Eligibility.hs`
**Called From**: Wallet eligibility handler
**Purpose**: Check if customer is eligible for LazyPay/BNPL

| Step | Action | Function | File |
|------|--------|----------|------|
| 1 | Build eligibility request | — | `Eligibility.hs` |
| 2 | Call API → `EasebuzzEligibility` | `callEasebuzzEligibility` | `Endpoint.hs:60` |
| 3 | Handle success/failure response | — | `Eligibility.hs` |

### 5.3 Data Transformations

| # | From | To | Function | File | Logic |
|---|------|----|----------|------|-------|
| 1 | `OrderReference` + `TxnDetail` | `EaseBuzzInitiatePaymentRequest` | `makeEaseBuzzInitiatePaymentRequest` | `Transforms.hs` | Maps order/txn fields; computes SHA-512 hash |
| 2 | `EaseBuzzDetails` + `CardData` + `TxnCardInfo` | `EaseBuzzSeamlessTxnRequest` | `makeEaseBuzzSeamlessTxnRequest` | `Transforms.hs` | Maps card/payment details; handles token/EMI/surcharge params |
| 3 | `OrderReference` + `TxnDetail` | `EaseBuzzTxnSyncRequest` | `makeEaseBuzzTxnSyncRequest` | `Transforms.hs` | Maps txn fields + sync hash `sha512(key\|txnid\|amount\|email\|phone\|salt)` |
| 4 | `Refund` + `TxnDetail` | `EaseBuzzRefundRequest` | `makeEaseBuzzRefundRequest` | `Transforms.hs` | Maps refund fields + hash `sha512(key\|merchantRefundId\|easebuzzId\|refundAmount\|salt)` |
| 5 | `Text` (bank account number, AES key/IV from credentials) | `Text` (encrypted) | `aesEncForEaseBuzz` | `Transforms.hs` | AES-256-CBC encrypt using sha256(key)[0:32] and sha256(salt)[0:16] |
| 6 | `EasebuzzResponse` + `TxnDetail` | `Txn.TxnStatus` | `getTransactionStatus` | `Flow.hs:1683` | Pattern match on response variant, then on status string |
| 7 | `EaseBuzzInitiatePaymentResponse` | `PaymentGatewayInfo` | `makeFailurePgrInfo` | `Flow.hs:1363` | Extracts error code/description from response |
| 8 | `SecondFactor` + credentials | `EaseBuzzGatewayAuthParams` | `makeGatewayAuthRequestParameters` / `setAuthParams` | `Transforms.hs` / `Flow.hs:919` | Stores accessKey + easebuzzPayId in SF for OTP flows |
| 9 | `EMIInstanceForBank` | `EMIObject` | `makeEMIObject` | `Transforms.hs` | Maps EMI plan details to EMI object for seamless request |
| 10 | `Text` (transaction amount) | `Number` | `getEasebuzzTransactionAmount` | `Transforms.hs` | Uses `EffectiveAmount` format; `BaseAmount` calculation logic |

---

## 6. Error Handling

### 6.1 API Call Error Handling

| # | Error Type | Handling | Fallback | File |
|---|-----------|----------|----------|------|
| 1 | `InitiatePayment` status ≠ 1 | Log + return `AUTHENTICATION_FAILED` | `PaymentRespError` with PGR from error_desc | `Flow.hs:817–829` |
| 2 | `InitiatePayment` decode failure (Left) | Return `AUTHENTICATION_FAILED` | `throwAuthFailError` | `Flow.hs:830` |
| 3 | `TxnSync` service unavailable | Log + throw `NOT_AN_ERROR` + redirect to handle-response URL | `HandleResponseRedirectResp` | `Flow.hs:1440` |
| 4 | Access token generation failure | Return `JUSPAY_DECLINED` with message from response | `makeAndReturnFailureResponse` | `Flow.hs:718/517` |
| 5 | Missing mandate object | Return `JUSPAY_DECLINED` | `"Mandate Object Not found"` | `Flow.hs:729/730` |
| 6 | Missing bank account details | Return `JUSPAY_DECLINED` | `"Bank account details not found"` | `Flow.hs:729` |
| 7 | Missing TAVV for token txn | Return `JUSPAY_DECLINED` | `"No TAVV Found"` | `Flow.hs:535` |
| 8 | Missing card CVV for card SI | Return `JUSPAY_DECLINED` | `"No Card CVV Found"` | `Flow.hs:563` |
| 9 | Submit OTP decode error | Log + return `SubmitOtpFailResp` | `"Submit Failed"/"Invalid Response"` | `Flow.hs:996` |
| 10 | UPI intent decode error | Log + return `AUTHENTICATION_FAILED` | — | `Flow.hs:1132` |
| 11 | VPA verification ClientError (gateway-side) | Propagated as `Left ClientError` | Handled in flow caller | `Endpoint.hs:57` |
| 12 | Eligibility ClientError (gateway-side) | Propagated as `Left ClientError` | Handled in flow caller | `Endpoint.hs:60` |
| 13 | Surcharge mismatch | Return `JUSPAY_DECLINED` with `getSurchargeFailurePgr` | Special message: "Charges are not matching..." | `Flow.hs:1119` |

### 6.2 HTTP Status Code Handling

| HTTP Status | Handling | Response to Caller |
|-------------|----------|--------------------|
| 200 | Decode response body; check application-level `status` field | Normal flow proceeds |
| Non-2xx (Servant/EulerHS) | `Left ErrorPayload` returned | Mapped to `AUTHENTICATION_FAILED` or `JUSPAY_DECLINED` depending on context |
| Connection/timeout failure | `Left` error propagated | Log + fallback to `AUTHENTICATION_FAILED` or redirect to handle-response URL |
| Decode error (JSON parse failure) | Log `DECODE_ERROR` | `AUTHENTICATION_FAILED` with empty PGR or service unavailable handling |

### 6.3 Timeout & Retry

- **Timeout Mechanism**: Standard EulerHS/Servant client timeout (no explicit per-endpoint configuration found in source)
- **Default Timeout**: System default (EulerHS framework default)
- **Retry Enabled**: No (not observed in source)
- **Max Retries**: 0
- **Retry Strategy**: N/A

### 6.4 Error Response Type

**Type**: `EaseBuzzSubmitOtpFailureResponse` — `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Types.hs:340`

| # | Field Name | Type | JSON Key | Description |
|---|------------|------|----------|-------------|
| 1 | `errorCode` | `Text` | `errorCode` | Error code string |
| 2 | `errorMessage` | `Text` | `errorMessage` | Human-readable error message |

**Type**: `EaseBuzzTxnsyncErrorType` — `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Types.hs:462`

| # | Field Name | Type | JSON Key | Description |
|---|------------|------|----------|-------------|
| 1 | `status` | `Text` | `status` | Error status text |
| 2 | `error` | `Text` | `error` | Error description |

**Type**: `ErrorResponse` (Settlement) — `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Types.hs:765`

| # | Field Name | Type | JSON Key | Description |
|---|------------|------|----------|-------------|
| 1 | `error_message` | `Text` | `error_message` | Settlement error message |
| 2 | `status` | `Bool` | `status` | False on error |

**Type**: `EasebuzzEligibilityResponseError` (Gateway) — `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/Easebuzz/Types.hs:206`

| # | Field Name | Type | JSON Key | Description |
|---|------------|------|----------|-------------|
| 1 | `message` | `Text` | `message` | Error message |
| 2 | `error_code` | `Text` | `error_code` | Error code |

### 6.5 Error Code Mappings

| # | Source Error | Target Error | HTTP Status | Retry-able | Description |
|---|------------|-------------|-------------|-----------|-------------|
| 1 | `status ≠ 1` (InitiatePayment) | `AUTHENTICATION_FAILED` | 200 (app-level) | No | Gateway rejected the initiation |
| 2 | `Left _` (API call failure) | `AUTHENTICATION_FAILED` | — | No | Network/decode error |
| 3 | `TxnSyncErrorMessage` | `AUTHENTICATION_FAILED` | 200 (app-level) | No | Sync returned error status |
| 4 | `EasebuzzRedirectAuthzErrorResponse` | `AUTHORIZATION_FAILED` | 200 (app-level) | No | AuthZ capture failed |
| 5 | `UpiAutoPayIntentFailResp` | `AUTHORIZATION_FAILED` | 200 (app-level) | No | UPI autopay registration failed |
| 6 | Missing mandate/bank details | `JUSPAY_DECLINED` | — | No | Merchant config or data error |
| 7 | Access token `success = False` | `JUSPAY_DECLINED` | — | No | Cannot proceed without access key |
| 8 | Surcharge mismatch (`"bounced"` + specific error code) | `JUSPAY_DECLINED` | — | No | Surcharge configured differently than calculated |
| 9 | `otp_verification_status = False` + `attempts_left = 0` | `AUTHENTICATION_FAILED` | — | No | OTP exhausted |
| 10 | `otp_verification_status = False` + `attempts_left > 0` | Existing txn status (pending) | — | No | OTP retry still possible |
| 11 | RetriveFailureResponse (mandate sync) | `AUTHORIZING` | — | No | Mandate still pending |

---

## 7. Status Mappings

### 7.1 Easebuzz Status Strings → Juspay TxnStatus

**Source**: `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Flow.hs:1683`
**Project**: euler-api-txns

| # | Easebuzz Status String | Juspay TxnStatus | Condition |
|---|----------------------|-----------------|-----------|
| 1 | `"success"` | `CHARGED` | Always |
| 2 | `"authorized"` | `CHARGED` | Only if `isEmandateRegisterTOT` or `isMandateRegisterTOT` |
| 3 | `"authorized"` | `AUTHENTICATION_FAILED` | For non-mandate payment flows |
| 4 | `"initiated"` | `AUTHORIZING` | Pending state |
| 5 | `"pending"` | `AUTHORIZING` | Pending state |
| 6 | `"in_process"` | `AUTHORIZING` | Processing state |
| 7 | `"bounced"` (surcharge mismatch) | `JUSPAY_DECLINED` | `msg == "Charges are not matching...Error Code: GC0C05"` |
| 8 | Any other status | `AUTHENTICATION_FAILED` | Default fallback |

### 7.2 EasebuzzResponse Variant → TxnStatus

**Direction**: `EasebuzzResponse` → `Txn.TxnStatus`
**Mapping File**: `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Flow.hs:1683`

| # | EasebuzzResponse Variant | Target TxnStatus | Condition |
|---|-------------------------|-----------------|-----------|
| 1 | `TxnResp resp` | via `getTxnStatus(resp.status, resp.error)` | Status string mapped per 7.1 |
| 2 | `SyncResp` → `TxnSyncSuccessMessage` | via `getTxnStatus(result.status, result.error)` | Status string mapped per 7.1 |
| 3 | `SyncResp` → `TxnSyncErrorMessage` | `AUTHENTICATION_FAILED` | Always |
| 4 | `AuthzResp` → `ValidAuthZResponse` | via `getTxnStatus(successResp._data.status, Nothing)` | Status string mapped per 7.1 |
| 5 | `AuthzResp` → `EasebuzzRedirectAuthzErrorResponse` | `AUTHORIZATION_FAILED` | Always |
| 6 | `MandateRedirectionResp resp` | via `getTxnStatus(resp.status, Nothing)` | Status string mapped per 7.1 |
| 7 | `MandateRegSyncResp` → `RetriveSuccessResponse` | via `getTxnStatus(sucResp.dataResponse.status, Nothing)` | Status string mapped per 7.1 |
| 8 | `MandateRegSyncResp` → `RetriveFailureResponse` | `AUTHORIZING` | Always |
| 9 | `MandateSyncValid resp` (AltId txn) | via upfront_presentment.status | If present |
| 10 | `MandateSyncValid resp` (non-AltId) | via `getTxnStatus(resp.status, Nothing)` | Status string mapped per 7.1 |
| 11 | `MandateSyncFailResp` | `AUTHORIZING` | Always |
| 12 | `DebitRequestRetrieveResp resp` | via `getTxnStatus(resp.status, Nothing)` | Status string mapped per 7.1 |
| 13 | `SubmitOtpResp` (otp_verification_status = True) | `CHARGED` | OTP verified |
| 14 | `SubmitOtpResp` (attempts_left = 0) | `AUTHENTICATION_FAILED` | OTP exhausted |
| 15 | `SubmitOtpResp` (attempts_left > 0) | `txnDetail.status` (preserve) | OTP retry still available |
| 16 | `SubmitOtpFailResp` | `txnDetail.status` (preserve) | Decode error on submit |

### 7.3 Mandate Status Strings → Internal MandateStatus (`getMandateStatus`)

**Source**: `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Flow.hs` — `getMandateStatus`
**Used By**: `mandateRegiSync`, `checkMandateStatus`, `checkSiStatus`

| # | Easebuzz Mandate Status String | Internal MandateStatus | Notes |
|---|-------------------------------|----------------------|-------|
| 1 | `"authorized"` | `ACTIVE` | Mandate successfully registered and active |
| 2 | `"requested"` | `CREATED` | Mandate requested, awaiting authorization |
| 3 | `"initiated"` | _(current status preserved)_ | No state change; remains as-is |
| 4 | `"expired"` | `EXPIRED` | Mandate past end date |
| 5 | `"paused"` | `PAUSED` | Mandate temporarily paused |
| 6 | `"cancelled"` | `REVOKED` | Cancelled by customer/merchant |
| 7 | `"revoked"` | `REVOKED` | Revoked by merchant |
| 8 | `"failed"` | `FAILURE` | Mandate registration failed |
| 9 | `"rejected"` | `FAILURE` | Rejected by bank |
| 10 | `"bounced"` | `FAILURE` | Bounced (e.g., insufficient funds during upfront debit) |
| 11 | `"dropped"` | `FAILURE` | Dropped by gateway |

### 7.4 Webhook Mandate Status → Internal MandateStatus (`getStatusFromWebhookRequest`)

**Source**: `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Flow.hs` — `getStatusFromWebhookRequest`
**Used By**: `verifyMandateStatusWebhook`

| # | Easebuzz Webhook Status String | Internal MandateStatus | Notes |
|---|-------------------------------|----------------------|-------|
| 1 | `"authorized"` | `ACTIVE` | Mandate activated via webhook |
| 2 | `"expired"` | `EXPIRED` | Mandate expired |
| 3 | `"completed"` | `EXPIRED` | Mandate completed (treated as expired) |
| 4 | `"paused"` | `PAUSED` | Mandate paused |
| 5 | `"revoked"` | `REVOKED` | Revoked |
| 6 | `"cancelled"` | `REVOKED` | Cancelled (treated as revoked) |
| 7 | `"user_cancelled"` | `REVOKED` | Cancelled by user |
| 8 | `"revoking"` | `REVOKED` | In process of revocation (treated as revoked) |
| 9 | `"failed"` | `FAILURE` | Failed |
| 10 | `"rejected"` | `FAILURE` | Rejected |
| 11 | `"dropped"` | `FAILURE` | Dropped |
| 12 | `"bounced"` | `FAILURE` | Bounced |

### 7.5 Execute Mandate Response Status → TxnStatus (`mapTxnStatus`)

**Source**: `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Flow.hs` — `mapTxnStatus`
**Used By**: `executeMandate`, `executeCardTokenMandate`

| # | Easebuzz Debit Status String | Juspay TxnStatus | Notes |
|---|------------------------------|-----------------|-------|
| 1 | `"success"` | `CHARGED` | Debit successful |
| 2 | `"failure"` | `AUTHORIZATION_FAILED` | Debit failed |
| 3 | `"in_process"` | `PENDING_VBV` | Debit pending (awaiting bank confirmation) |
| 4 | Any other | `PENDING_VBV` | Default fallback for unknown states |

### 7.6 Notification Status → NotificationStatus (`getNotificationStatus`)

**Source**: `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Flow.hs` — `getNotificationStatus`
**Used By**: `initNotificationSyncRequest`, `callNotificationStatus`

| # | Easebuzz Notification Status | Internal NotificationStatus | Notes |
|---|-----------------------------|-----------------------------|-------|
| 1 | `"notified"` | `SUCCESS` | Notification successfully delivered to customer |
| 2 | `"failure"` | `FAILURE` | Notification delivery failed |
| 3 | Any other | `PENDING` | Notification pending or unknown state |

### 7.7 Split Settlement Application

**Source**: `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Flow.hs:1074`

| # | TxnStatus | Split Applied |
|---|-----------|--------------|
| 1 | `CHARGED` | Yes |
| 2 | `AUTO_REFUNDED` | Yes |
| 3 | Any other | No |

---

## 8. Payment Methods

### 8.1 Supported Payment Method Types

| # | PaymentMethodType | Payment Mode Sent to Easebuzz | Notes |
|---|-------------------|------------------------------|-------|
| 1 | `CARD` | Via `getGatewayPaymentMethodType` (e.g., `"CC"`, `"DC"`) | Supports tokenization, EMI, SI on cards |
| 2 | `UPI` | Via `getGatewayPaymentMethodType` (e.g., `"UPICOLLECT"`, `"UPIINTENT"`) | Collect, intent, QR; also UPI Autopay |
| 3 | `NB` | Via `getGatewayPaymentMethodType` (bank-specific code) | Net banking; also eMandate auth mode |
| 4 | `WALLET` | Via `getGatewayPaymentMethodType` (e.g., `"OM"` for Olamoney) | LazyPay uses `"PL"` for DOTP flow |
| 5 | `CONSUMER_FINANCE` | `"EI"` (EMI), or via `getPayMode` | Cardless EMI (easy_installments_identifier) |
| 6 | `AADHAAR` | Mandate auth_mode = `"AADHAAR"` | eMandate via Aadhaar |
| 7 | `PAPERNACH` | Mandate auth_mode = `"DEBITCARD"` or `"NB"` | Paper NACH mandate |

### 8.2 Payment Method Transformation Chain

| Step | Operation | Function | File | Input | Output |
|------|-----------|----------|------|-------|--------|
| 1 | Get payment method type | `txnCardInfo ^. L._paymentMethodType` | `Flow.hs:1409` | `TxnCardInfo` | `Maybe PMT.PaymentMethodType` |
| 2 | Map to gateway payment mode | `getGatewayPaymentMethodType` | `Flow.hs:1414` | `(gateway, cardType, isEmi)` | `Text` (payment mode string) |
| 3 | Override for OlaMoney | `getPayMode` check on `paymentMethod == "OLAMONEY"` | `Flow.hs:1421` | `(txnCInfo, paymentMethods)` | `"OM"` or original |
| 4 | Override for LazyPay DOTP | `callEasebuzzDotpFlow` | `Flow.hs:814` | `isLazyPayDotpTxn` check | `"PL"` hardcoded |
| 5 | Resolve gateway payment method code | `getGatewayPaymentMethodCode` | `Flow.hs:493` | `(gateway, paymentMethodType, paymentMethod)` | `GatewayPaymentMethodCode` |
| 6 | EMI mandate payment mode | `getPaymentMode'` | `Flow.hs:767` | `txnCardInfo.paymentMethodType` | `"UPIAD"` / `"SI"` / `"EN"` |

### 8.3 Payment Method Fields in Request/Response

**Request fields**:

| # | Field | JSON Key | Type | Present | Description |
|---|-------|----------|------|---------|-------------|
| 1 | `payment_mode` | `payment_mode` | `Text` | Yes | Gateway payment mode (sent to `EasebuzSeamlessTransaction`) |
| 2 | `bank_code` | `bank_code` | `Maybe Text` | Conditional | Bank code for NB payments |
| 3 | `upi_va` | `upi_va` | `Maybe Text` | Conditional | UPI VPA for collect |
| 4 | `pay_later_app` | `pay_later_app` | `Maybe Text` | Conditional | e.g., `"LAZYPAY"` |
| 5 | `emi_object` | `emi_object` | `Maybe Text` | Conditional | JSON-encoded EMI plan object |

**Response fields**:

| # | Field | JSON Key | Type | Present | Description |
|---|-------|----------|------|---------|-------------|
| 1 | `mode` | `mode` | `Text` | Yes | Payment mode used (echoed in seamless/sync response) |
| 2 | `card_type` | `card_type` | `Text` | Yes | Card type (echoed) |
| 3 | `bankcode` | `bankcode` | `Text` | Yes | Bank code (echoed) |
| 4 | `payment_source` | `payment_source` | `Text` | Yes | Payment source |
| 5 | `upi_va` | `upi_va` | `Maybe Text` | Conditional | UPI VPA used |

### 8.4 DB Tables

#### payment_method

| # | Column | Type | Description |
|---|--------|------|-------------|
| 1 | id | Maybe Int | Primary key |
| 2 | name | Text | Payment method name (e.g., `"VISA"`, `"LAZYPAY"`) |
| 3 | _type | Text | Payment method type (e.g., `"CARD"`, `"WALLET"`) |
| 4 | description | Text | Human-readable description |
| 5 | sub_type | Maybe Text | Sub-type (e.g., `"CREDIT"`, `"DEBIT"`) |
| 6 | juspay_bank_code_id | Maybe Int | FK to bank code table |
| 7 | display_name | Maybe Text | Display name |
| 8 | nick_name | Maybe Text | Short name |
| 9 | dsl | Maybe Text | DSL configuration |

#### gateway_payment_method

| # | Column | Type | Description |
|---|--------|------|-------------|
| 1 | _id | Maybe Text | Primary key |
| 2 | payment_method_id | Int | FK to payment_method.id |
| 3 | gateway | Text | `"EASEBUZZ"` |
| 4 | gateway_code | Text | Gateway-specific payment mode code (e.g., `"CC"`, `"DC"`, `"UPI"`) |
| 5 | supported_currencies | Maybe Text | Comma-separated currency codes |

---

## 9. Completeness Verification

| Check | Result |
|-------|--------|
| Primary request types in source | 14+ |
| Primary request types documented | 14 (InitiatePayment, Seamless, TxnSync, Refund, RefundSync, SubmitOtp, ResendOtp, AccessKey, CreateMandate, CreateCardMandate, ProcessMandateAuth, Notification, UpiExecuteMandate, RevokeMandate, EmiPlans, VerifyVpa, Eligibility) |
| Primary response types in source | 20+ |
| Primary response types documented | 20+ (InitiatePaymentResp, SeamlessTxnResp, TxnSyncResp, RefundResp, RefundSyncResp, SubmitOtpResp, OtpData, AccessKeyResp, MandateRedirectionResp, MandateRetrieveResp, MandateRetrieveResponseData, DebitRequestResp, DebitRequestRetrieveResp, UpiExecutionResp, NotificationResp, NotificationSyncResp, RevokeMandateResp, ProcessMandateResp, ProcessMandateData, VerifyVpaResp, VerifyVpaData, EligibilityResp, EligibilityData, EaseBuzzFailureType) |
| All nested types expanded | Yes |
| All enum values listed | Yes |
| All flows documented | Yes — 20+ sub-flows: initiateTxn, initiateNormalTxn, initiateEMITxn, initEaseBuzzEmandateTxn, initEaseBuzzPlainCardMandateTxn, callEasebuzzDotpFlow, getSdkParams, submitOtp, resendOtp, syncWithGateway, easeBuzzTxnSync, normalTxnSync, mandateRegiSync, mandatePaymentSync, easeBuzzRefundRequest, easeBuzzRefundSyncRequest, executeMandate, executeCardTokenMandate, revokeMandate variants, checkMandateStatus, initNotificationRequest, initNotificationSyncRequest, webhook processing, split settlement |
| All error paths documented | Yes |
| All status mappings documented | Yes — 7 mapping tables: TxnStatus (7.1), EasebuzzResponse variant (7.2), MandateStatus from API (7.3), MandateStatus from webhook (7.4), execute mandate TxnStatus (7.5), NotificationStatus (7.6), split settlement (7.7) |
| Payment methods documented | Yes |
| Payment method enums complete | Yes |
| Payment method DB tables documented | Yes |
| Missing items | None — spec is complete after full reading of `Types.hs` (1–2906) and `Flow.hs` (1–3637) |

---

## 10. Source File References

| # | File | Lines Read | Purpose |
|---|------|-----------|---------|
| 1 | `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Endpoints.hs` | 1–102 | All 23 endpoint names + full URL mappings (sandbox/prod) |
| 2 | `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Types.hs` | 1–2906 (full) | All request/response types — InitiatePayment, Seamless, TxnSync, OTP, Refund, Mandate, AccessKey, EMI, Settlement, MandateRetrieve, DebitRequest, UpiAutopay, Notification, RevokeMandateRequest, UpiExecuteMandate, etc. |
| 3 | `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Flow.hs` | 1–3637 (full) | All flows — initiateTxn, initiateNormalTxn, initiateEMITxn, initEaseBuzzEmandateTxn, initEaseBuzzPlainCardMandateTxn, callEasebuzzDotpFlow, getSdkParams, submitOtp, resendOtp, syncWithGateway, getTransactionStatus, setupMandate, executeMandate, revokeMandate, mandatePaymentSync, mandateRegiSync, normalTxnSync, webhook handling, notification, split settlement, refund, refundSync, integrity, status check |
| 4 | `euler-api-txns/euler-x/src-generated/Gateway/EaseBuzz/Transforms.hs` | 1–1053 | All transformation functions — hash computation, AES encryption, request builders |
| 5 | `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/Easebuzz/Endpoint.hs` | 1–60 | Gateway-side Servant API types, base URL logic, client call functions |
| 6 | `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/Easebuzz/Types.hs` | 1–217 | Gateway-side types — EasebuzzDetails, EMI plans, Verify VPA, Eligibility request/response types |
| 7 | `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/Easebuzz/Flow/Emi.hs` | Referenced | EMI plans flow logic |
| 8 | `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/Easebuzz/Flow/VerifyVpa.hs` | Referenced | VPA verification flow |
| 9 | `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/Easebuzz/Flow/Eligibility.hs` | Referenced | Wallet eligibility flow |
| 10 | `euler-techspec-workflow/2_connector_spec.md` | All | Workflow definition |
| 11 | `euler-techspec-workflow/2.5_compile_spec.md` | All | Spec template |

---

**Generated by**: Euler Connector Tech Spec Workflow
**Date**: 2026-03-26
