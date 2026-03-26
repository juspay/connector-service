# PineLabs Payment Gateway — Technical Specification

> **Connectors covered:** `PineLabs` (online/UPI/card/NB/wallet) and `PineLabsOffline` (EDC/physical terminal)
> **Source repos:**
> - Gateway: `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/PineLabs/`
> - Gateway (offline): `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/PineLabsOffline/`
> - Txns: `euler-api-txns/euler-x/src-generated/Gateway/PineLabs/`

---

## Table of Contents

1. [Overview](#1-overview)
2. [Base URLs](#2-base-urls)
3. [Authentication & Request Signing](#3-authentication--request-signing)
4. [Credentials / Account Fields](#4-credentials--account-fields)
5. [Payment Method Codes](#5-payment-method-codes)
6. [Flows — PineLabs (Online)](#6-flows--pinelabs-online)
   - 6.1 [Authenticate / InitiatePay (Card, NB, Wallet, Consumer Finance)](#61-authenticate--initiatepay-card-nb-wallet-consumer-finance)
   - 6.2 [UPI Intent](#62-upi-intent)
   - 6.3 [UPI Collect](#63-upi-collect)
   - 6.4 [EMI Plans](#64-emi-plans)
   - 6.5 [Offer List](#65-offer-list)
   - 6.6 [EMI Scheme Validation (Pre-Txn Validator)](#66-emi-scheme-validation-pre-txn-validator)
   - 6.7 [IMEI Validation (v1 & v2)](#67-imei-validation-v1--v2)
   - 6.8 [Tokenised Card Payment](#68-tokenised-card-payment)
   - 6.9 [Submit OTP (DC-EMI / OTP Flow)](#69-submit-otp-dc-emi--otp-flow)
   - 6.10 [Transaction Sync](#610-transaction-sync)
   - 6.11 [Webhook Sync](#611-webhook-sync)
   - 6.12 [Webhook Verify / Integrity](#612-webhook-verify--integrity)
   - 6.13 [Refund](#613-refund)
   - 6.14 [Refund Sync](#614-refund-sync)
7. [Flows — PineLabsOffline (EDC)](#7-flows--pinelabsoffline-edc)
   - 7.1 [Transaction (UploadBilledTransaction)](#71-transaction-uploadbilledtransaction)
   - 7.2 [Order Status Sync (GetCloudBasedTxnStatus)](#72-order-status-sync-getcloudbasedtxnstatus)
   - 7.3 [GetStatus](#73-getstatus)
8. [Request / Response Type Reference](#8-request--response-type-reference)
9. [Status & Error Code Mapping](#9-status--error-code-mapping)
10. [Bank Code Mapping (EMI)](#10-bank-code-mapping-emi)
11. [Known Issues / TODOs](#11-known-issues--todos)

---

## 1. Overview

PineLabs exposes two distinct integration modes:

| Connector | Mode | Primary use |
|---|---|---|
| **PineLabs** | Online (server-to-server + redirect/seamless) | Cards, NB, UPI, Wallets, EMI, Consumer Finance |
| **PineLabsOffline** | EDC / Cloud-based terminal | Physical card-present payments via PineLabs POS terminals |

The online connector is a two-step flow:

1. **AcceptPayment** — creates a session, returns a `token` (session token).
2. **ProcessPayment** (or **ProcessTokenPayment** for network tokens) — executes the payment against the session token.

Order status enquiry and refunds are independent REST calls using form-urlencoded payloads signed with HMAC-SHA256.

---

## 2. Base URLs

### 2.1 PineLabs (Online)

| Environment | Base URL |
|---|---|
| Sandbox / UAT | `https://uat.pinepg.in/api` |
| Production | `https://pinepg.in/api` |

Full endpoint URLs (from `Env.hs`):

| Endpoint key | Method | URL (sandbox) | URL (production) | Content-Type |
|---|---|---|---|---|
| `AcceptPayment` | POST | `https://uat.pinepg.in/api/v2/accept/payment` | `https://pinepg.in/api/v2/accept/payment` | `application/json` |
| `ProcessPayment` | POST | `https://uat.pinepg.in/api/v2/process/payment?token=:sessionToken` | `https://pinepg.in/api/v2/process/payment?token=:sessionToken` | `application/json` |
| `ProcessTokenPayment` | POST | `https://uat.pinepg.in/api/v2/process/payment/card/tokenize?token=:sessionToken` | `https://pinepg.in/api/v2/process/payment/card/tokenize?token=:sessionToken` | `application/json` |
| `OrderStatus` | POST | `https://uat.pinepg.in/api/PG` | `https://pinepg.in/api/PG` | `application/x-www-form-urlencoded` |
| `RefundRequest` | POST | `https://uat.pinepg.in/api/PG/V2` | `https://pinepg.in/api/PG/V2` | `application/x-www-form-urlencoded` |
| `EMICalculator` | POST | `https://uat.pinepg.in/api/v3/emi/calculator` | `https://pinepg.in/api/v3/emi/calculator` | `application/json` |
| `EMIValidator` | POST | `https://uat.pinepg.in/api/v3/scheme/validation` | `https://pinepg.in/api/v3/scheme/validation` | `application/json` |
| `IMEIValidator` | POST | `https://uat.pinepg.in:8059/api/IMEIValidation` | `https://pinepg.in:8059/api/IMEIValidation` | `application/x-www-form-urlencoded` |
| `IMEIValidatorV2` | POST | `https://uat.pinepg.in:8059/api/v2IMEIValidation/DoIMEIOperation` | `https://pinepg.in:8059/api/v2IMEIValidation/DoIMEIOperation` | `application/json` |
| `TransactionStatus` (redirect) | GET | `https://uat.pinepg.in/PinePGRedirect` | `https://pinepg.in/PinePGRedirect` | — |

> **Route parameter:** `:sessionToken` is substituted from the `token` field returned by AcceptPayment.

### 2.2 PineLabsOffline (EDC)

| Environment | Base URL |
|---|---|
| **Both sandbox and production** | `https://plutuscloudserviceuat.in:8201/API/CloudBasedIntegration` |

> ⚠️ **BUG/TODO:** Both environments use the same UAT URL. Production URL is missing. See [Known Issues](#11-known-issues--todos).

| Endpoint key | Path | Method |
|---|---|---|
| `UploadBilledTransaction` | `/V1/UploadBilledTransaction` | POST |
| `GetCloudBasedTxnStatus` | `/V1/GetCloudBasedTxnStatus` | POST |

---

## 3. Authentication & Request Signing

### 3.1 AcceptPayment — X-VERIFY Header

```
1. Build AcceptPaymentRequestParams as JSON.
2. Base64-encode the JSON string → base64Payload
3. Compute HMAC-SHA256(base64Payload, secureSecret) → hex-encoded uppercase string → hashValue
4. Send:
     - Request body: {"request": "<base64Payload>"}
     - Header: X-VERIFY: <hashValue>
```

Source: `Transforms.hs::makeAcceptPaymentRequestParams`, `Flow.hs::authenticateRequest`

### 3.2 OrderStatus & Refund — ppc_DIA_SECRET

```
1. Build the request payload as a key=value object.
2. Convert to URL query string format (json2QueryString / jsonToQueryString).
3. Sort the query string alphabetically (URL.sortQueryString).
4. Compute HMAC-SHA256(sortedQueryString, secureSecret) → hex-encoded uppercase string.
5. Add to request:
     ppc_DIA_SECRET      = <hmac_hex>
     ppc_DIA_SECRET_TYPE = "SHA256"
```

Source: `Flow.hs::getPgStatus`, `Flow.hs::initPineLabsRefundApiRequestW`

### 3.3 Webhook Response Verification

```
1. Parse the inbound webhook (form-urlencoded POST or redirect params).
2. Compute HMAC-SHA256 over the JSON-encoded response body using secureSecret
   (via responseHasherPinelabs).
3. Compare with ppc_DIA_SECRET field from the webhook.
4. Also verify:
   - ppc_UniqueMerchantTxnID matches the stored txnId.
   - ppc_Amount matches the expected amount (rounded, in paise).
```

Source: `Flow.hs::pineLabsVerifyMessage`, `Flows/Webhook.hs`

### 3.4 PineLabsOffline — securityToken

No HMAC signing. The `securityToken` credential is included directly in the request body JSON as-is.

---

## 4. Credentials / Account Fields

### 4.1 PineLabs (Online) — `PineLabsDetails`

| Field | Type | Description |
|---|---|---|
| `ppcMerchantID` | `Text` | Merchant ID assigned by PineLabs |
| `ppcMerchantAccessCode` | `Text` | Merchant access code |
| `secureSecret` | `Text` | Secret key used for HMAC-SHA256 signing of all API calls |
| `bajajSchemeCode` | `Maybe Text` | Scheme code for Bajaj Finserv EMI offers |
| `oemName` | `Maybe Text` | OEM name used for EMI discount attribution |

Source: `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/PineLabs/Types.hs`

### 4.2 PineLabsOffline (EDC) — `PineLabsOfflineAccountDetails`

| Field | Type | Description |
|---|---|---|
| `securityToken` | `Text` | Security token sent in every request body (no HMAC) |
| `merchantID` | `Int` | Numeric merchant ID |

Source: `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/PineLabsOffline/Types/Common.hs`

---

## 5. Payment Method Codes

The `payment_mode` field in `TransactionDetails` is determined by `getPaymentMethodCode`:

| Payment Method Type | Condition | `payment_mode` |
|---|---|---|
| NB (Net Banking) | — | `"3"` |
| UPI | — | `"10"` |
| WALLET | — | `"11"` |
| CARD | Offer applied | `"4"` |
| CARD | Bajaj (`paymentMethod == "BAJAJ"`) | `"7"` |
| CARD | Not EMI | `"1"` |
| CARD | DC-EMI (OTP flow: HDFC/KOTAK/ICICI/KOTAK MAHINDRA + DEBIT) | `"14"` |
| CARD | Cardless EMI (CAPITALFLOAT_CLEMI, HDFC_CLEMI, ICICI_CLEMI, SBI_CLEMI) or OTP flow | `"19"` |
| CARD | Standard EMI | `"4"` |
| CONSUMER_FINANCE | Cardless EMI methods | `"14"` / `"19"` (same rules as CARD EMI) |
| CONSUMER_FINANCE | Other | `"7"` |
| Other | — | `"0"` |

`navigation_mode` is always `7`. `transaction_type` is always `1`.

---

## 6. Flows — PineLabs (Online)

### 6.1 Authenticate / InitiatePay (Card, NB, Wallet, Consumer Finance)

**Gateway flow:** `Flow.hs::authenticateRequest` → `initPaymentApi`

**Step 1 — AcceptPayment**

```
POST /api/v2/accept/payment
Content-Type: application/json
X-VERIFY: <hmac_sha256_of_base64_payload>

Body: {"request": "<base64(JSON(AcceptPaymentRequestParams))>"}
```

`AcceptPaymentRequestParams` fields:

| Field | Source |
|---|---|
| `merchant_data.merchant_id` | `ppcMerchantID` |
| `merchant_data.merchant_access_code` | `ppcMerchantAccessCode` |
| `merchant_data.unique_merchant_txn_id` | `txnDetail.txnId` |
| `merchant_data.merchant_return_url` | Static response URL |
| `payment_data.amount` | Amount in paise (integer) |
| `txn_data.navigation_mode` | `7` (always) |
| `txn_data.transaction_type` | `1` (always) |
| `txn_data.payment_mode` | See §5 |
| `txn_data.time_stamp` | Current Unix timestamp |
| `customer_data.email_id` | `orderReference.customerEmail` |
| `customer_data.first_name` | From `Customer` or `OrderAddress` |
| `customer_data.last_name` | From `Customer` or `OrderAddress` |
| `customer_data.mobile_no` | `orderReference.customerPhone` (cleaned) |
| `customer_data.customer_id` | `orderReference.customerId` |
| `customer_data.billing_data` | `OrderAddress` (billing) |
| `customer_data.shipping_data` | `OrderAddress` (shipping) |
| `udf_data.udf_field_1..4` | `orderReference.udf1..4` |
| `udf_data.udf_field_5` | `omv2.ipAddress` |
| `product_details` | `[ProductData]` (only if EMI or offer applied) |

**Response — Success (SeamlessResponse):**

```json
{
  "response": {
    "token": "<session_token>",
    "amount": <amount_in_paise>,
    ...
  }
}
```

**Response — Failure (FailureResponse):**

```json
{
  "response_code": <int>,
  "response_message": "<string>"
}
```

On failure → return `AUTHENTICATION_FAILED` with the gateway's `response_code` and `response_message`.

---

**Step 2 — ProcessPayment**

```
POST /api/v2/process/payment?token=<sessionToken>
Content-Type: application/json

Body: ProcessPaymentRequest
```

`ProcessPaymentRequest` is built by `makePaymentRequest`. All fields are optional (nullable); only the relevant payment-method fields are populated:

| Payment Method | Populated fields |
|---|---|
| NB (non-TPV) | `netbanking_data.pay_code` |
| NB (TPV) | `netbanking_data.pay_code` + `tpv_data.account_number` |
| WALLET | `wallet_data.wallet_code`, `wallet_data.mobile_number` |
| CARD (standard) | `card_data` (number, expiry, holder name, CVV) |
| CARD (DC-EMI OTP flow) | `card_data` (number only; no expiry/name/CVV), `merchant_data`, `payment_data` |
| CARD (standard EMI) | `card_data` + `emi_data` |
| CARD (Bajaj) | `nbfc_data.vendor_name`, `nbfc_data.bfl_data` (scheme_code, card_number, tenure, terms_agreed) |
| CONSUMER_FINANCE (cardless) | `pan_validation`, `additional_data.mobile_no`, `emi_data` |
| CONSUMER_FINANCE (other) | `nbfc_data.vendor_name`, `nbfc_data.bfl_data.zestMoney_data.mobile_no` |
| UPI | `upi_data.vpa`, `upi_data.mobile_number`, `upi_data.upi_option` (`"GPAY"` for GooglePay else `"UPI"`) |
| `additional_data.mobile_no` | Sent for all CARD flows |

**DC-EMI OTP Flow Trigger:** Triggered when `isEmi == True` AND `shouldUseOTPFlow == True`. `shouldUseOTPFlow` returns `True` when card issuer is one of `HDFC BANK`, `KOTAK BANK`, `KOTAK MAHINDRA BANK`, `ICICI BANK` AND `cardType == "DEBIT"`.

**ProcessPayment Responses:**

| Response variant | Description | Action |
|---|---|---|
| `OTPResponse` | OTP / DOTP page required | Return `ShowDotpPage` with redirect/OTP params |
| `RedirectResponse` | 3DS / redirect required | Return `GatewayRedirect` with redirect URL |
| `RedirectFailureResponse` | Payment rejected | Return `PaymentRespError` with `AUTHENTICATION_FAILED` |

---

### 6.2 UPI Intent

**Gateway flow:** `Flows/UpiIntent.hs`

Uses the same two-step AcceptPayment → ProcessPayment sequence. In ProcessPayment:

```json
{
  "upi_data": {
    "upi_option": "UPI",
    "mobile_number": "<customer_mobile>"
  }
}
```

The intent-specific field is that `vpa` is omitted (null), and `upi_option = "UPI"`.

**Response handling:**
- On success: extract `deepLink` from the ProcessPayment response, return SDK params with the deep link for UPI app redirect.
- On failure: return `AUTHENTICATION_FAILED`.

---

### 6.3 UPI Collect

**Gateway flow:** `Flows/UpiCollect.hs`

Same two-step flow. In ProcessPayment:

```json
{
  "upi_data": {
    "vpa": "<customer_vpa>",
    "mobile_number": "<customer_mobile>",
    "upi_option": "UPI"
  }
}
```

**Response handling:**
- On `OTPResponse` / `RedirectResponse`: return `PendingVBV` (waiting for customer to approve collect request).
- On failure: return `AuthenticationFailed`.

---

### 6.4 EMI Plans

**Gateway flow:** `Flow.hs::getEmiPlans` + `Flows/Emi.hs`

```
POST /api/v3/emi/calculator
Content-Type: application/json

Body: EMICalculatorRequest
```

`EMICalculatorRequest` fields:

| Field | Value |
|---|---|
| `merchant_data.merchant_id` | `ppcMerchantID` |
| `merchant_data.merchant_access_code` | `ppcMerchantAccessCode` |
| `payment_data.amount` | Amount in paise |
| `product_details` | `[ProductData]` from `gateway_data.PINELABS.productInfo` |

**Retry logic:** If the first call fails, it is automatically retried once (see `getEMICalculatorResponse`).

**Response handling:**

- `EMIList`: Contains `issuer` array of `BankEmiList`. Each bank has a list of `EmiTenure`.
- `ErrorData`: Log and return empty list.

**EMI data normalization (`handleEmiPlans` / `makeEmiResponse`):**

| Raw field | Transformation | Output field |
|---|---|---|
| `monthly_installment` | `/ 100.0`, rounded to 2dp | `emi_amount` |
| `bank_interest_rate` | `/ 10000.0` | `interest` / `interest_percentage` |
| `interest_amount` | `/ 100.0` | `interest_amount` |
| `offer_amount` | `/ 100.0`, rounded to 2dp | `offer_amount` |
| `loan_amount` | `/ 100.0`, rounded to 2dp | In metadata |
| `auth_amount` | `/ 100.0`, rounded to 2dp | In metadata |
| `product_amount` | `/ 100.0`, rounded to 2dp | In metadata `product_details` |
| `subvention_cashback_discount` | `/ 100.0` | In metadata |
| `product_discount` | `/ 100.0` | In metadata |
| `subvention_cashback_discount_percentage` | `/ 10000.0` | In metadata |
| `product_discount_percentage` | `/ 10000.0` | In metadata |
| `bank_interest_rate_percentage` | `/ 10000.0` | In metadata |
| `bank_interest_rate` | `/ 100.0` (metadata) | In metadata |
| `total_amount` | `(monthly_installment / 100) × tenure`, rounded | `total_amount` |

**EMI Type determination (`getEmiType`):**

| `subvention_type` in product_details | EMI Type |
|---|---|
| `1` | `NO_COST_EMI` |
| `2` | `LOW_COST_EMI` |
| `3` | `STANDARD_EMI` (or `STANDARD_EMI_SPLIT` if split EMI) |
| Other | `UNKNOWN` (filtered out from results) |

**Bank code normalization:** Uses `pineLabsBankCodes` from `ServiceConfiguration` (key `pineLabsBankCodeMapping`). If not found there, falls back to `emiCodeMap`:

| PineLabs issuer name | Internal bank code |
|---|---|
| `HDFC` | `HDFC` |
| `HDFC Bank Debit Card` | `HDFCDC` |
| `AXIS` | `AXIS` |
| `Axis Debit` | `AXISDC` |
| `AMEX` | `AMEX` |
| `CITI` | `CITI` |
| `HSBC` | `HSBC` |
| `ICICI` | `ICICI` |
| `Indusind_Bank` | `INDUSIND` |
| `KOTAK` | `KOTAK` |
| `SBI` | `SBI` |
| `BOB_Financial` | `BOB` |
| `RBL_Bank` | `RBL` |
| `STANDARD_CHARTERED_BANK` | `SCB` |
| `ICICI Debit` | `ICICIDC` |
| `YES` | `YES` |
| `Kotak Debit` | `KOTAKDC` |

---

### 6.5 Offer List

**Gateway flow:** `Flows/Offer.hs`

Reuses the EMI Calculator API but with `tenure = 1` to get available offers (0-month EMI = instant discount).

Returns a list of `OfferBank` records derived from the EMI calculator response.

---

### 6.6 EMI Scheme Validation (Pre-Txn Validator)

**Gateway flow:** `Flow.hs` — EMI validator pre-transaction check

```
POST /api/v3/scheme/validation
Content-Type: application/json

Body: EMIValidatorRequest
```

`EMIValidatorRequest` fields:

| Field | Source |
|---|---|
| `merchant_data.merchant_id` | `ppcMerchantID` |
| `merchant_data.merchant_access_code` | `ppcMerchantAccessCode` |
| `payment_data.amount` | Amount in paise |
| `card_data.card_number` | Card number (non-token flows) |
| `tokenize_card_data` | Token fields (token-based flows) |
| `emi_data` | `EmiTenure` (scheme, tenure, etc.) |
| `additional_data.mobile_no` | Cleaned customer phone |
| `pan_validation` | PAN data (if applicable) |

**Responses:**

| Response variant | Description |
|---|---|
| `EmiValdationResp` | Validation successful — proceed with payment |
| `FAILEDResponse` | Scheme validation failed |
| `OutDatedResponse` | Outdated scheme — retry or show error |

---

### 6.7 IMEI Validation (v1 & v2)

Used for device/IMEI-based EMI financing.

**v1 endpoint:**
```
POST https://[uat.]pinepg.in:8059/api/IMEIValidation
Content-Type: application/x-www-form-urlencoded

_PinePGTransactionId=<txn_id>&_IMEI=<imei>&_TransactionType=<type>
```

`PineLabsIMEIValidatorRequest` fields:

| Field | Description |
|---|---|
| `_PinePGTransactionId` | PineLabs transaction ID |
| `_IMEI` | Device IMEI number |
| `_TransactionType` | Transaction type code |
| `_IMEIValidationOverride` | Optional override flag |
| `_UserName` | Optional username |
| `_AccessCode` | Optional access code |

**v2 endpoint:**
```
POST https://[uat.]pinepg.in:8059/api/v2IMEIValidation/DoIMEIOperation
Content-Type: application/json

Body: PineLabsIMEIValidatorRequestV2
```

`PineLabsIMEIValidatorRequestV2` fields:

| Field | Description |
|---|---|
| `merchant_data.merchant_id` | `ppcMerchantID` |
| `merchant_data.merchant_access_code` | `ppcMerchantAccessCode` |
| `txn_data.pine_pg_txn_id` | PineLabs transaction ID |
| `product_imei_details` | `[ProductImeiDetails]` (IMEI per product) |
| `imei_request_type` | Request type string |

---

### 6.8 Tokenised Card Payment

**Gateway flow:** `Flow.hs::initProcessTokenPaymentRequest`

Used when `isTokenBasedTxn txn == True`.

```
POST /api/v2/process/payment/card/tokenize?token=<sessionToken>
Content-Type: application/json

Body: ProcessTokenPaymentRequest
```

`ProcessTokenPaymentRequest` fields:

| Field | Present when |
|---|---|
| `tokenize_card_data` | Non-Rupay-AltId token-based txn |
| `card_meta_data` | Non-Rupay-AltId token-based txn |
| `card_data` | Rupay AltId txn |
| `emi_data` | EMI flows |
| `merchant_data` | Non-EMI flows only |
| `payment_data` | Non-EMI flows only |
| `additional_data.mobile_no` | Non-EMI flows only |

`TokenizeCardData` fields:

| Field | Notes |
|---|---|
| `token` | `cardData.cardNumber` (the token) |
| `expiration_month` | Card expiry month |
| `expiration_year` | Card expiry year |
| `cryptogram` | `cardData.tavv` — omitted for issuer-repeat txns |
| `cvv` | `cardData.cardSecurityCode` — omitted for CVV-less txns |
| `par` | Payment Account Reference |
| `token_transaction_type` | Token type from card info |
| `last4Digit` | Sent only for Diners or EMI flows |
| `token_referenceId` | Sent only for Diners |
| `token_request_merchant_id` | Sent only for Diners |

---

### 6.9 Submit OTP (DC-EMI / OTP Flow)

Used to submit OTP for DC-EMI (debit card EMI) transactions.

```
POST <api_url_from_previous_response>
Content-Type: application/json

Body: {"otp": "<otp_entered_by_user>"}
```

`api_url` is extracted from the `DOTPResponse` / `CaptureTransactionResp` returned by ProcessPayment.

**Responses:**

| Response variant | Description |
|---|---|
| `OTPVerifiedResp` | OTP verified, proceed |
| `FailedResp` | OTP verification failed |

---

### 6.10 Transaction Sync

**Gateway flow:** `Flow.hs::pineLabsTxnSync` / `syncWithGateway`

```
POST /api/PG
Content-Type: application/x-www-form-urlencoded

ppc_MerchantID=...&ppc_MerchantAccessCode=...&ppc_TransactionType=3
&ppc_UniqueMerchantTxnID=<txnId>&ppc_DIA_SECRET=<hmac>&ppc_DIA_SECRET_TYPE=SHA256
```

Full `PineLabsInquiryApiRequest` fields:

| Field | Value |
|---|---|
| `ppc_MerchantID` | `ppcMerchantID` |
| `ppc_MerchantAccessCode` | `ppcMerchantAccessCode` |
| `ppc_TransactionType` | `3` (order status query) |
| `ppc_UniqueMerchantTxnID` | `txnDetail.txnId` |
| `ppc_DIA_SECRET` | HMAC-SHA256 of sorted query string |
| `ppc_DIA_SECRET_TYPE` | `"SHA256"` |

**Response variants** (`StatusResp`):

| Variant | Condition | Action |
|---|---|---|
| `ValidStatusResponse` | `ppc_PinePGTxnStatus == "7" && ppc_Parent_TxnStatus == "4"` | `CHARGED` |
| `ValidStatusResponse` | `ppc_PinePGTxnStatus == "7" && ppc_Parent_TxnStatus == "-7" or "-10" or "-6"` | `AUTHORIZATION_FAILED` |
| `StatusErrorResponse` | Same status conditions | Same mapping |
| `ErrorResponse` | Any error | Logged; no status change |

**isPendingTransaction logic:**

A transaction is considered pending if `ppc_PinePGTxnStatus != "7"` OR if `ppc_PinePGTxnStatus == "7"` and `ppc_Parent_TxnStatus` is NOT in `["4", "6", "9", "-7", "-6", "-10"]`.

**Integrity validation (validateStatusResponse):**

- Verifies `ppc_UniqueMerchantTxnID` matches stored txnId.
- Verifies `ppc_Amount` (in paise) matches order amount.
- Optionally verifies masked card number (`ppc_MaskedCardNumber`) via `verifyPaymentInstrument`.

---

### 6.11 Webhook Sync

**Gateway flow:** `Flows/Webhook.hs` (sync function)

PineLabs posts a form-urlencoded redirect (or webhook) to the merchant's `merchant_return_url`.

The sync handler:
1. Parses the query string / form body.
2. Extracts `ppc_UniqueMerchantTxnID` → matches to internal txn.
3. Returns the raw response for further processing.

Key fields in `RedirectionResponse`:

| Field | Description |
|---|---|
| `ppc_UniqueMerchantTxnID` (`merchantTranId`) | Internal txn ID |
| `ppc_Amount` (`amountInPaise`) | Amount in paise |
| `ppc_PinePGTxnStatus` (`pine_pg_txn_status`) | Status code |
| `ppc_TxnResponseCode` (`txn_response_code`) | Response code |
| `ppc_TxnResponseMessage` (`txn_response_msg`) | Response message |
| `ppc_DIA_SECRET` (`diaSecret`) | HMAC checksum for verification |
| `pine_pg_transaction_id` | PineLabs internal txn ID |
| `masked_card_number` | Masked card (for integrity check) |
| `rrn` | Retrieval Reference Number |
| `auth_code` | Authorization code |

---

### 6.12 Webhook Verify / Integrity

**Gateway flow:** `Flow.hs::verifyMessageIntegrityV2` + `pineLabsVerifyMessage`

For `RedirectionResp`:
```
1. Extract ppc_DIA_SECRET (actualHash) from redirect params.
2. Recompute: responseHasherPinelabs(JSON(response), secureSecret) → computedHash.
3. Verify computedHash == actualHash.
4. Verify amount integrity and card number (optional).
```

For `SyncSuccessResponse`:
```
Delegates to validateStatusResponse (same as §6.10 integrity check).
```

**getTransactionStatus mapping from RedirectionResp:**

| `pine_pg_txn_status` | Internal Status |
|---|---|
| `"4"` | `CHARGED` |
| `"-7"` | `AUTHORIZATION_FAILED` |
| `"-10"` | `AUTHORIZATION_FAILED` |
| `"-6"` | `AUTHORIZATION_FAILED` |
| Other | Unchanged (current txn status) |

---

### 6.13 Refund

**Gateway flow:** `Flow.hs::initPineLabsRefundApiRequestW`

```
POST /api/PG/V2
Content-Type: application/x-www-form-urlencoded

ppc_MerchantID=...&ppc_MerchantAccessCode=...&ppc_TransactionType=4
&ppc_PinePGTransactionID=<epg_txn_id>&ppc_AmountToRefund=<amount_in_paise>
&ppc_UniqueRefundID=<refund_id>&ppc_DIA_SECRET=<hmac>&ppc_DIA_SECRET_TYPE=SHA256
[&ppc_ProductDetails=<base64_encoded_imei_details>]  (if IMEI refund)
```

`PineLabsRefundApiRequest` fields:

| Field | Value |
|---|---|
| `ppc_MerchantID` | `ppcMerchantID` |
| `ppc_MerchantAccessCode` | `ppcMerchantAccessCode` |
| `ppc_TransactionType` | `4` (refund) |
| `ppc_PinePGTransactionID` | From PGR: `pine_pg_transaction_id` or `ppc_PinePGTransactionID` |
| `ppc_AmountToRefund` | Refund amount in paise |
| `ppc_UniqueRefundID` | Internal refund unique ID |
| `ppc_DIA_SECRET` | HMAC-SHA256 of sorted query string |
| `ppc_DIA_SECRET_TYPE` | `"SHA256"` |
| `ppc_ProductDetails` | Base64-encoded IMEI product details (IMEI refunds only) |

**IMEI Refund flow:**
- Fetches IMEI details from the refund's `internalTrackingInfo.gatewayHelperData` (or encrypted `productDetailsEnc`).
- Updates `OrderBasket.basketItemList` IMEI statuses:
  - On SUCCESS: `UNBLOCKING_INITIATED`
  - On FAILURE: `ERROR`
  - On PENDING: unchanged

**`PineLabsRefundApiResponse` fields:**

| Field | Description |
|---|---|
| `ppc_PinePGTxnStatus` | Refund status code |
| `ppc_TxnResponseCode` | Response code |
| `ppc_TxnResponseMessage` | Response message |
| `ppc_PinePGTransactionID` | PineLabs refund transaction ID |

**Refund status mapping (`pineLabsRefundStatus`):**

| `ppc_PinePGTxnStatus` | Refund status |
|---|---|
| `"6"` | `SUCCESS` |
| `"-7"` | `FAILURE` |
| Other | `PENDING` |

**Known refund error messages (`listOfErrorMessages`):**

- `REFUND PROCESS FAILED`
- `ENHANCED AUTHORIZATION SECURITY CHECK FAILED`
- `AMOUNT LEFT AFTER REFUND IS LESS THAN THE MINIMUM ALLOWED TXN AMOUNT`
- `PARTIAL REFUND NOT ALLOWED`
- `NO REFUND ALLOWED.ALL THE CAPTURED AMOUNT HAS BEEN REFUNDED`
- `REQUEST ID NOT VALID`
- `REQUEST NOT UNIQUE`
- `ALREADY REFUNDED`
- `TRANSACTION NOT AVAILABLE`
- `DATA MISSING`
- `INVALID DATA`
- `CORRUPT DATA`
- `REFUND NOT ENABLED`
- `RETRY LIMIT EXCEEDED`
- `CORRPUT INPUT DATA` *(typo in source)*
- `INSUFFICIENT FUND`
- `FAILURE`

---

### 6.14 Refund Sync

**Gateway flow:** `Flow.hs::initPineLabsRefundSync`

Uses the same `OrderStatus` endpoint (`/api/PG`) with the `refund.uniqueRequestId` as `ppc_UniqueMerchantTxnID`.

**Refund sync status mapping (`updateStatus`):**

| `ppc_PinePGTxnStatus` | `ppc_Parent_TxnStatus` | Refund Status |
|---|---|---|
| `"7"` | `"6"` | `SUCCESS` |
| `"7"` | `"-7"` | `FAILURE` |
| Other | Any | Unchanged |

**Fields updated on the Refund record:**

| Field | Source |
|---|---|
| `status` | From mapping above |
| `processed` | Always `True` |
| `sentToGateway` | `True` |
| `errorMessage` | `ppc_ParentTxnResponseMessage` (or fallback) |
| `referenceId` | `ppc_PinePGTransactionID` |
| `responseCode` | `ppc_ParentTxnResponseCode` (or fallback) |
| `refundArn` | `ppc_RRN` or `ppc_ARN` (whichever is non-empty) |

---

## 7. Flows — PineLabsOffline (EDC)

### 7.1 Transaction (UploadBilledTransaction)

**Gateway flow:** `Flows/Transaction.hs`

```
POST https://plutuscloudserviceuat.in:8201/API/CloudBasedIntegration/V1/UploadBilledTransaction
Content-Type: application/json

Body: MakePaymentRequest
```

`MakePaymentRequest` fields:

| Field | Description |
|---|---|
| `TerminalID` | Terminal identifier |
| `MerchantID` | `merchantID` from credentials |
| `SecurityToken` | `securityToken` from credentials |
| `TransactionNumber` | Unique transaction number |
| `SequenceNumber` | Sequence number |
| `AllowEDC` | Boolean — allow EDC |
| `Amount` | Amount in paise |
| `OriginalAmount` | Original amount |
| `InvoiceNumber` | Invoice number |
| `TransactionType` | Type of EDC transaction |

**Response (`MakePaymentResponse` / `MakeOrderStatusResponse`):**

| Field | Description |
|---|---|
| `ResponseCode` | Gateway response code |
| `ResponseMessage` | Human-readable message |
| `PlutusTransactionReferenceID` | PineLabs terminal transaction reference ID |
| `ExternalTransactionID` | External / merchant transaction ID |
| `TransactionDate` | Date of transaction |
| `TransactionTime` | Time of transaction |

---

### 7.2 Order Status Sync (GetCloudBasedTxnStatus)

**Gateway flow:** `Flows/Sync.hs`

```
POST https://plutuscloudserviceuat.in:8201/API/CloudBasedIntegration/V1/GetCloudBasedTxnStatus
Content-Type: application/json

Body:
{
  "MerchantID": <merchantID>,
  "SecurityToken": "<securityToken>",
  "PlutusTransactionReferenceID": "<reference_id>",
  "ExternalTransactionID": "<external_txn_id>"
}
```

**Response:**

Same structure as `MakeOrderStatusResponse` above. Response polling continues while `ResponseMessage` indicates a pending state.

---

### 7.3 GetStatus

**Gateway flow:** `Flows/GetStatus.hs`

Wraps the Sync flow and returns a typed payment status:

| Condition | Status |
|---|---|
| `ResponseMessage == "TXN APPROVED"` | `Charged` / payment successful |
| Otherwise | Not successful |

---

## 8. Request / Response Type Reference

### 8.1 AcceptPaymentRequest

```
AcceptPaymentRequest
  request :: Text  -- Base64-encoded JSON of AcceptPaymentRequestParams
```

### 8.2 AcceptPaymentRequestParams

```
AcceptPaymentRequestParams
  merchant_data    :: MerchantDetails
  payment_data     :: PaymentDetails        -- {amount :: Int}
  txn_data         :: TransactionDetails
  customer_data    :: Maybe CustomerDetails
  udf_data         :: Maybe UserDefinedParams
  product_details  :: Maybe [ProductData]

MerchantDetails
  merchant_id             :: Text
  merchant_access_code    :: Text
  unique_merchant_txn_id  :: Text
  merchant_return_url     :: Text

TransactionDetails
  navigation_mode :: Int   -- always 7
  transaction_type :: Int  -- always 1
  payment_mode     :: Text -- see §5
  time_stamp       :: Int  -- Unix timestamp

CustomerDetails
  email_id      :: Maybe Text
  first_name    :: Maybe Text
  last_name     :: Maybe Text
  mobile_no     :: Maybe Text
  customer_id   :: Maybe Text
  billing_data  :: Maybe BillingInfo
  shipping_data :: Maybe ShippingInfo

BillingInfo / ShippingInfo
  address1 :: Maybe Text
  address2 :: Maybe Text
  address3 :: Maybe Text
  pincode  :: Maybe Text
  city     :: Maybe Text
  state    :: Maybe Text
  country  :: Maybe Text
  -- ShippingInfo additionally:
  first_name :: Maybe Text
  last_name  :: Maybe Text
  mobile_no  :: Maybe Text

UserDefinedParams
  udf_field_1 :: Maybe Text
  udf_field_2 :: Maybe Text
  udf_field_3 :: Maybe Text
  udf_field_4 :: Maybe Text
  udf_field_5 :: Maybe Text  -- IP address

ProductData
  product_amount :: Number
  product_code   :: Text
```

### 8.3 ProcessPaymentRequest

```
ProcessPaymentRequest
  card_data        :: Maybe CardDetails
  emi_data         :: Maybe EmiTenure
  netbanking_data  :: Maybe NetBankingDetails
  wallet_data      :: Maybe WalletDetails
  upi_data         :: Maybe UpiInfo
  nbfc_data        :: Maybe NDFCInfo
  additional_data  :: Maybe UserMobileNumber
  tpv_data         :: Maybe BankAccountDetails
  merchant_data    :: Maybe MerchantCredential
  payment_data     :: Maybe PaymentDetails
  pan_validation   :: Maybe PanData

CardDetails
  card_number      :: Maybe Text
  card_expiry_year :: Maybe Text
  card_expiry_month :: Maybe Text
  card_holder_name :: Maybe Text
  cvv              :: Maybe Text

NetBankingDetails
  pay_code :: Text  -- gateway payment method code

WalletDetails
  wallet_code    :: Text
  mobile_number  :: Maybe Text

UpiInfo
  vpa          :: Maybe Text
  mobile_number :: Maybe Text
  upi_option   :: Maybe Text  -- "UPI" or "GPAY"

NDFCInfo
  vendor_name :: Text
  bfl_data    :: Maybe BFLInfo

BFLInfo
  scheme_code              :: Maybe Text
  card_number              :: Maybe Text
  tenure_in_months         :: Maybe Int
  is_terms_conditions_agreed :: Maybe Bool
  zestMoney_data           :: Maybe UserMobileNumber

BankAccountDetails
  account_number :: Maybe Text
```

### 8.4 PineLabsInquiryApiRequest

```
PineLabsInquiryApiRequest
  ppc_MerchantID          :: Text
  ppc_MerchantAccessCode  :: Text
  ppc_TransactionType     :: Text    -- "3"
  ppc_UniqueMerchantTxnID :: Text
  ppc_DIA_SECRET          :: Maybe Text
  ppc_DIA_SECRET_TYPE     :: Maybe Text  -- "SHA256"
```

### 8.5 PineLabsInquiryApiResponse (ValidStatusResponse)

```
PineLabsInquiryApiResponse
  ppc_MerchantID              :: Text
  ppc_MerchantAccessCode      :: Text
  ppc_TransactionType         :: Text
  ppc_UniqueMerchantTxnID     :: Text
  ppc_Amount                  :: Text         -- in paise
  ppc_PinePGTxnStatus         :: Text
  ppc_Parent_TxnStatus        :: Text
  ppc_ParentTxnResponseCode   :: Text
  ppc_ParentTxnResponseMessage :: Text
  ppc_TxnResponseCode         :: Text
  ppc_TxnResponseMessage      :: Text
  ppc_PinePGTransactionID     :: Text
  ppc_MaskedCardNumber        :: Maybe Text
  ppc_RRN                     :: Maybe Text
  ppc_ARN                     :: Maybe Text
  ppc_AuthCode                :: Maybe Text
  ppc_EMIPrincipalAmount      :: Maybe Text
  ppc_EMIAmountPayableEachMonth :: Maybe Text
  ppc_EMITenureMonth          :: Maybe Text
  ppc_TxnAdditionalInfo       :: Maybe Text   -- Base64-encoded JSON
  ppc_EMICashBackType         :: Maybe Text
  ppc_Is_BankEMITransaction   :: Maybe Text   -- "1" = true
  ppc_Is_BrandEMITransaction  :: Maybe Text   -- "1" = true
```

### 8.6 PineLabsRefundApiRequest

```
PineLabsRefundApiRequest
  ppc_MerchantID          :: Text
  ppc_MerchantAccessCode  :: Text
  ppc_TransactionType     :: Text     -- "4"
  ppc_PinePGTransactionID :: Text
  ppc_AmountToRefund      :: Text     -- in paise
  ppc_UniqueRefundID      :: Text
  ppc_DIA_SECRET          :: Maybe Text
  ppc_DIA_SECRET_TYPE     :: Maybe Text  -- "SHA256"
  ppc_ProductDetails      :: Maybe Text  -- Base64-encoded IMEI details
```

### 8.7 PineLabsRefundApiResponse

```
PineLabsRefundApiResponse
  ppc_PinePGTxnStatus    :: Text
  ppc_TxnResponseCode    :: Text
  ppc_TxnResponseMessage :: Text
  ppc_PinePGTransactionID :: Text
```

### 8.8 EMICalculatorRequest

```
EMICalculatorRequest
  merchant_data   :: MerchantCredential
  payment_data    :: PaymentDetails
  product_details :: [ProductData]

MerchantCredential
  merchant_id          :: Text
  merchant_access_code :: Text
```

### 8.9 EMIValidatorRequest

```
EMIValidatorRequest
  merchant_data      :: MerchantCredential
  payment_data       :: PaymentDetails
  card_data          :: Maybe EmiValidatorCardDetails
  tokenize_card_data :: Maybe TokenizeCardData
  emi_data           :: EmiTenure
  additional_data    :: Maybe UserMobileNumber
  pan_validation     :: Maybe PanData
```

### 8.10 RedirectionResponse (Webhook / Redirect)

```
RedirectionResponse
  merchantTranId       :: Text    -- ppc_UniqueMerchantTxnID
  amountInPaise        :: Text    -- ppc_Amount
  pine_pg_txn_status   :: Text    -- ppc_PinePGTxnStatus (redirect status)
  txn_response_code    :: Text    -- ppc_TxnResponseCode
  txn_response_msg     :: Text    -- ppc_TxnResponseMessage
  diaSecret            :: Text    -- ppc_DIA_SECRET
  pine_pg_transaction_id :: Text  -- PineLabs internal txn ID
  masked_card_number   :: Maybe Text
  rrn                  :: Maybe Text
  auth_code            :: Maybe Text
```

### 8.11 ProcessTokenPaymentRequest

```
ProcessTokenPaymentRequest
  tokenize_card_data :: Maybe TokenizeCardData
  card_meta_data     :: Maybe CardMetaData
  card_data          :: Maybe CardDataPayload
  emi_data           :: Maybe EmiTenure
  merchant_data      :: Maybe MerchantCredential
  payment_data       :: Maybe PaymentDetails
  additional_data    :: Maybe UserMobileNumber

TokenizeCardData
  token                    :: Maybe Text
  expiration_month         :: Maybe Text
  expiration_year          :: Maybe Text
  cryptogram               :: Maybe Text   -- TAVV; null for issuer repeat
  cvv                      :: Maybe Text   -- null for CVV-less
  par                      :: Maybe Text
  token_transaction_type   :: Maybe Text
  last4Digit               :: Maybe Text   -- Diners or EMI only
  token_referenceId        :: Maybe Text   -- Diners only
  token_request_merchant_id :: Maybe Text  -- Diners only

CardMetaData
  issuer_name :: Maybe Text
  scheme_name :: Maybe Text
  card_type   :: Maybe Text

CardDataPayload
  card_number       :: Maybe Text
  card_expiry_year  :: Maybe Text
  card_expiry_month :: Maybe Text
  card_holder_name  :: Maybe Text
  last4Digit        :: Maybe Text
  cvv               :: Maybe Text
```

---

## 9. Status & Error Code Mapping

### 9.1 Transaction Status (`ppc_PinePGTxnStatus` / `pine_pg_txn_status`)

#### From Redirect (RedirectionResp)

| `pine_pg_txn_status` | Internal TxnStatus |
|---|---|
| `"4"` | `CHARGED` |
| `"-7"` | `AUTHORIZATION_FAILED` |
| `"-10"` | `AUTHORIZATION_FAILED` |
| `"-6"` | `AUTHORIZATION_FAILED` |
| Other | Unchanged |

#### From Sync (ValidStatusResponse / StatusErrorResponse)

| `ppc_PinePGTxnStatus` | `ppc_Parent_TxnStatus` | Internal TxnStatus |
|---|---|---|
| `"7"` | `"4"` | `CHARGED` |
| `"7"` | `"-7"` | `AUTHORIZATION_FAILED` |
| `"7"` | `"-10"` | `AUTHORIZATION_FAILED` |
| `"7"` | `"-6"` | `AUTHORIZATION_FAILED` |
| Other | Any | Unchanged |

#### Terminal / Settled Codes (for `isPendingTransaction`)

| Code | Meaning |
|---|---|
| `"4"` | Success / Captured |
| `"6"` | Refunded |
| `"9"` | Settled |
| `"-7"` | Authorization Failed |
| `"-6"` | Authorization Failed |
| `"-10"` | Authorization Failed |

### 9.2 Refund Status

#### Immediate Refund Response (`ppc_PinePGTxnStatus` in refund response)

| Code | Refund Status |
|---|---|
| `"6"` | `SUCCESS` |
| `"-7"` | `FAILURE` |
| Other | `PENDING` |

#### Refund Sync Response

| `ppc_PinePGTxnStatus` | `ppc_Parent_TxnStatus` | Refund Status |
|---|---|---|
| `"7"` | `"6"` | `SUCCESS` |
| `"7"` | `"-7"` | `FAILURE` |
| Other | Any | Unchanged |

### 9.3 PineLabsOffline Status

| `ResponseMessage` | Status |
|---|---|
| `"TXN APPROVED"` | `Charged` / Payment successful |
| Other | Not successful |

### 9.4 isPaymentSuccessful Conditions

```
ValidStatusResponse:   ppc_PinePGTxnStatus == "7" && ppc_Parent_TxnStatus == "4"
StatusErrorResponse:   isJust ppc_Amount && ppc_PinePGTxnStatus == "7" && ppc_Parent_TxnStatus == Just "4"
ErrorResponse:         False
```

---

## 10. Bank Code Mapping (EMI)

Bank code mapping is loaded at runtime from `ServiceConfiguration` using key `pineLabsBankCodeMapping` (and `pinelabsBankMappingForOffer` for offers). The fallback static map is `emiCodeMap`:

| PineLabs issuer name | Internal bank code |
|---|---|
| `HDFC` | `HDFC` |
| `HDFC Bank Debit Card` | `HDFCDC` |
| `AXIS` | `AXIS` |
| `Axis Debit` | `AXISDC` |
| `AMEX` | `AMEX` |
| `CITI` | `CITI` |
| `HSBC` | `HSBC` |
| `ICICI` | `ICICI` |
| `Indusind_Bank` | `INDUSIND` |
| `KOTAK` | `KOTAK` |
| `SBI` | `SBI` |
| `BOB_Financial` | `BOB` |
| `RBL_Bank` | `RBL` |
| `STANDARD_CHARTERED_BANK` | `SCB` |
| `ICICI Debit` | `ICICIDC` |
| `YES` | `YES` |
| `Kotak Debit` | `KOTAKDC` |

---

## 11. Known Issues / TODOs

### 11.1 PineLabsOffline: Production URL Missing

**Severity:** High / Bug

Both sandbox and production environments for `PineLabsOffline` use the same UAT URL:
```
https://plutuscloudserviceuat.in:8201/API/CloudBasedIntegration
```

Source: `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/PineLabsOffline/Routes.hs`

The production URL (`plutuscloudservice.in` or equivalent) should be configured separately.

---

### 11.2 Untranspiled Functions in Transforms.hs

Source: `euler-api-txns/euler-x/src-generated/Gateway/PineLabs/Transforms.hs` (bottom comment block)

```
-- Untranspiled names from Gateway.PineLabs.Transforms:
--  - getMobileNumber
--  - makeBFLInfo
```

These two functions exist in the original PureScript source but were not transpiled to Haskell. Any code paths that relied on these may be broken or were replaced by inline logic.

---

### 11.3 `isProcessed` Always Returns True

Source: `Flow.hs::isProcessed`

```haskell
isProcessed :: Text -> Bool
isProcessed status = True
```

This function ignores its input and always marks a refund as processed regardless of the actual `ppc_TxnResponseMessage`. This may cause refunds that are still `PENDING` or `FAILURE` to be incorrectly flagged as processed.

---

### 11.4 Typo in Error Message

Source: `Flow.hs::listOfErrorMessages`

`"CORRPUT INPUT DATA"` should be `"CORRUPT INPUT DATA"`. This must match the exact string returned by PineLabs API; if PineLabs returns `"CORRUPT INPUT DATA"` this entry will never match.

---

### 11.5 EMI Calculator Retry Logic is Unconditional

Source: `Flow.hs::getEMICalculatorResponse`

```haskell
getEMICalculatorResponse req mga = do
  response <- initEMICalculatorRequest ...
  case response of
    Right _ -> pure response
    Left _  -> initEMICalculatorRequest ...  -- unconditional retry on ANY error
```

The retry happens on all errors (network, auth, 5xx, 4xx) without distinction. A 4xx error will be retried unnecessarily.

---

### 11.6 `ppc_PinePGTxnStatus == "9"` Not Mapped to a TxnStatus

Status code `"9"` (Settled) is listed in `successAndFailureCodes` (used by `isPendingTransaction`) but is not handled in `getTransactionStatus` or `isPaymentSuccessful`. A transaction with status `"9"` will leave the internal transaction status unchanged.

---

### 11.7 OEM Name Logic for Discount Attribution

Source: `Flow.hs::updateDetailsInBasketInfo`

```haskell
let oemName = if (oemMga == productDetail.oem_name && productDetail.oem_name /= Nothing)
              then (Just "MERCHANT")
              else productDetail.oem_name
```

If the MGA's `oemName` matches the product's `oem_name`, the basket entry's `oemName` is set to `"MERCHANT"` instead of the actual OEM name. This affects settlement split reporting.

---

*Spec generated from source code as of the date of this document. Refer to the source files directly for the most current field types and validation logic.*
