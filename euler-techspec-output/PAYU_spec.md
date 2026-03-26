# PAYU — Technical Specification

> **Connector**: PAYU
> **Direction**: BOTH (euler-api-gateway AND euler-api-txns call PayU external APIs directly)
> **Purpose**: Payment gateway connector supporting card, UPI, net banking, wallet, BNPL, EMI, mandate/recurring payments, settlements, tokenization, 3DS2, and OTP flows
> **Generated**: 2026-03-26

---

## 1. Connector Overview

### 1.1 Basic Information

- **Connector ID**: PAYU
- **Direction**: BOTH — both `euler-api-gateway` and `euler-api-txns` call PayU's external APIs directly
- **Protocol**: HTTPS (port 443)
- **Content Type**: `application/x-www-form-urlencoded` (standard); `application/json` (delink wallet, LinkAndPay)
- **Architecture**: Haskell (Servant + Warp)
- **Authentication**: HMAC-SHA512 hash embedded in request body (not HTTP header)
- **Timeout**: 45,000 ms standard; force-sync timeout sourced from Redis key `customTimeoutForForceSync "PAYU"` or `defaultPayuForceSyncTimeoutInMS`
- **Retry**: None configured

### 1.2 Base URL Configuration

#### Gateway-side Base URLs (`Routes.hs:50-61`, function `payuBaseUrl`)

| Environment | Base URL | Condition |
|-------------|----------|-----------|
| Sandbox (standard) | `https://test.payu.in/merchant/postservice.php?form=2` | `isSandbox=true`, `isLinkAndPay=false` |
| Production (standard) | `https://info.payu.in/merchant/postservice.php?form=2` | `isSandbox=false`, `isLinkAndPay=false` |
| Sandbox (LinkAndPay EMI) | `https://test.payu.in/info/linkAndPay/get_emi_checkout_details` | `isSandbox=true`, `isLinkAndPay=true` |
| Production (LinkAndPay EMI) | `https://info.payu.in/linkAndPay/get_emi_checkout_details` | `isSandbox=false`, `isLinkAndPay=true` |

**URL Resolution Logic**: `isSandbox` flag selects host (`test.payu.in` vs `info.payu.in`); `isLinkAndPay` flag selects path suffix.

#### Txns-side Base URLs (`Endpoints.hs:11-71`, function `getEndpointForReq`)

| Request Type | Test URL | Production URL |
|---|---|---|
| `PayuTransactionRequest` | `https://test.payu.in/_payment` | `https://secure.payu.in/_payment` |
| `PayuAuthZRequest` | `https://test.payu.in/_payment` | `https://secure.payu.in/_payment` |
| `PayuUpiTransactionRequest` | `https://test.payu.in/_payment` | `https://secure.payu.in/_payment` |
| `PayuAuthorizeTransaction` | `https://test.payu.in/AuthorizeTransaction.php` | `https://secure.payu.in/AuthorizeTransaction.php` |
| `PayuFetchAuthNParamsRequest` | `https://test.payu.in/decoupled/AuthData?referenceId={referenceId}` | `https://secure.payu.in/decoupled/AuthData?referenceId={referenceId}` |
| `PayuVerifyPaymentRequest` | `https://test.payu.in/merchant/postservice.php?form=2` | `https://info.payu.in/merchant/postservice.php?form=2` |
| `PayuRefundRequest` | `https://test.payu.in/merchant/postservice.php?form=2` | `https://info.payu.in/merchant/postservice.php?form=2` |
| `PayuCaptureRequest` | `https://test.payu.in/merchant/postservice.php?form=2` | `https://info.payu.in/merchant/postservice.php?form=2` |
| `PayuVoidRequest` | `https://test.payu.in/merchant/postservice.php?form=2` | `https://info.payu.in/merchant/postservice.php?form=2` |
| `PayuCaptureOrVoidSyncRequest` | `https://test.payu.in/merchant/postservice.php?form=2` | `https://info.payu.in/merchant/postservice.php?form=2` |
| `PayuExerciseMandateRequest` | `https://test.payu.in/merchant/postservice.php?form=2` | `https://info.payu.in/merchant/postservice.php?form=2` |
| `PayuMandatePreDebitNotificationRequest` | `https://test.payu.in/merchant/postservice.php?form=2` | `https://info.payu.in/merchant/postservice.php?form=2` |
| `PayuUpiMandateRevokeRequest` | `https://test.payu.in/merchant/postservice.php?form=2` | `https://info.payu.in/merchant/postservice.php?form=2` |
| `PayuMandateStatusRequest` | `https://test.payu.in/merchant/postservice.php?form=2` | `https://info.payu.in/merchant/postservice.php?form=2` |
| `PayuRefundArnSyncRequest` | `https://test.payu.in/merchant/postservice.php?form=2` | `https://info.payu.in/merchant/postservice.php?form=2` |
| `PayuSplitSettlementRequest` | `https://test.payu.in/merchant/postservice.php?form=2` | `https://info.payu.in/merchant/postservice.php?form=2` |
| `PayuGetSplitInfoRequest` | `https://test.payu.in/merchant/postservice.php?form=2` | `https://info.payu.in/merchant/postservice.php?form=2` |
| `PayuPreDebitNotificationStatusRequest` | `https://test.payu.in/merchant/postservice.php?form=2` | `https://info.payu.in/merchant/postservice.php?form=2` |
| `PayuTokenUpdateRequest` | `https://test.payu.in/merchant/postservice?form=2` | `https://info.payu.in/merchant/postservice?form=2` |
| `PayuSurchargeRequest` | `https://test.payu.in/merchant/postservice?form=2` | `https://info.payu.in/merchant/postservice?form=2` |
| `PayuOtpTriggerRequest` (LinkAndPay OTP) | `https://test.payu.in/ResponseHandler.php` | varies |
| `PayuDelinkRequest` | `/info/linkAndPay/delinkInstrument` | `/linkAndPay/delinkInstrument` |
| `GetVpa` | (prod only) | `https://info.payu.in/payment-mode/v1/upi/vpa?upiNumber={upiNumber}` |
| `PayuInitiatePushPayRequest` | varies | varies |

**Timeout Configuration**:
- Standard timeout header: `X-Euler-CustomTimeout: 45000`
- Force-sync timeout: sourced from Redis (`customTimeoutForForceSync "PAYU"`) or `defaultPayuForceSyncTimeoutInMS`
- Per-merchant override: Yes (via Redis key)

---

## 2. Authentication

### 2.1 Authentication Method

- **Auth Type**: HMAC-SHA512 signature
- **Auth Location**: Request body field `hash` (not an HTTP header)
- **Credential Source**: `MerchantGatewayAccount` → `PayuDetails` (fields `payuMerchantKey` + `payuSalt`)

### 2.2 Credential Fields — `PayuDetails` (`dbTypes/EC/MerchantGatewayAccount/Types.hs:524`)

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `payuSalt` | Text | Signing salt used in all HMAC hash computations |
| 2 | `payuMerchantKey` | Text | Merchant key sent as `key` in all requests |
| 3 | `s2sEnabled` | Bool | Enable S2S payment flow |
| 4 | `isPreAuthEnabled` | Bool | Enable pre-authorization (two-step capture) |
| 5 | `cardDirectOtpEnabled` | Bool | Enable direct OTP for card payments |
| 6 | `googlePayCardPaymentsEnabled` | Bool | Enable Google Pay card payments |
| 7 | `waitingPageExpiryInSeconds` | Maybe Int | Waiting page expiry override |
| 8 | `disableMandatePreDebitNotification` | Bool | Disable pre-debit notification for mandates |
| 9 | `shouldPassUserToken` | Bool | Pass user token in payment request |
| 10 | `shouldPassMandateSeqNumber` | Bool | Pass mandate sequence number |
| 11 | `shouldUsePayuAPIVersion20` | Bool | Use PayU API version 2.0 |
| 12 | `skipSubventionValidation` | Bool | Skip subvention validation |
| 13 | `gatewayMerchantName` | Maybe Text | Gateway merchant name override |
| 14 | `mccEnabled` | Bool | Enable MCC (merchant category code) |

### 2.3 Hash Formulas

| # | Hash Type | Formula | Source |
|---|-----------|---------|--------|
| 1 | Standard (`makePayuHash`) | `SHA512(key \| command \| var1 \| salt)` | `txns Transforms.hs:254-260` |
| 2 | Settlement | `SHA512(key \| "get_settlement_details" \| date \| salt)` | `gateway Transforms.hs:44-53` |
| 3 | DC EMI eligibility | `SHA512(key \| command \| encodeJson(var1Payload) \| salt)` | `gateway Transforms.hs:76-81` |
| 4 | Verify payment (`makePayuVerifyHash`) | `SHA512(key \| command \| txnId \| salt)` | `txns Transforms.hs:1937-1946` |
| 5 | Mandate exercise | `SHA512(key \| "si_transaction" \| encodeJSON(payUMandateTokenType) \| salt)` | `txns Transforms.hs:1971` |

### 2.4 Required Headers

| # | Header Name | Value / Source | Required | Context |
|---|-------------|---------------|----------|---------|
| 1 | `Content-Type` | `application/x-www-form-urlencoded` | Yes | Standard requests (`makePayuHeader`) |
| 2 | `X-Euler-CustomTimeout` | `45000` | Yes | Standard requests |
| 3 | `Content-Type` | `application/json` | Yes | Delink wallet requests |
| 4 | `Date` | `{current date}` | Yes | Delink wallet requests |
| 5 | `Authorization` | `{authValue}` | Yes | Delink wallet requests |
| 6 | `x-credential-username` | `{payuMerchantKey}` | Yes | LinkAndPay requests |
| 7 | `Content-Type` | `application/x-www-form-urlencoded` | Yes | Verify payment requests |
| 8 | `X-Euler-CustomTimeout` | from Redis or `defaultPayuForceSyncTimeoutInMS` | Conditional | Force-sync verify payment |

---

## 3. Request Structure

### 3.1 PayU Commands Reference

All standard (non-payment) requests send a `command` field in the POST body that determines the operation:

| # | Command | Operation | Endpoint |
|---|---------|-----------|----------|
| 1 | `"get_settlement_details"` | Settlement data fetch | `/merchant/postservice.php?form=2` |
| 2 | `"get_checkout_details"` | DC EMI / BNPL eligibility | `/merchant/postservice.php?form=2` |
| 3 | `"getEmiAmountAccordingToInterest"` | EMI plans fetch | `/merchant/postservice.php?form=2` |
| 4 | `"get_payment_instrument"` | Get tokenized card details | `/merchant/postservice.php?form=2` |
| 5 | `"get_payment_details"` | Get token TAVV/ECI/PAR details | `/merchant/postservice.php?form=2` |
| 6 | `"capture_transaction"` | Capture pre-authorized payment | `/merchant/postservice.php?form=2` |
| 7 | `"cancel_refund_transaction"` | Void or refund | `/merchant/postservice.php?form=2` |
| 8 | `"check_action_status"` | Capture/void status sync | `/merchant/postservice.php?form=2` |
| 9 | `"getAllRefundsFromTxnIds"` | Refund ARN sync | `/merchant/postservice.php?form=2` |
| 10 | `"aggregator_check_action_status_txnid"` | Refund ARN sync / split settlement info | `/merchant/postservice.php?form=2` |
| 11 | `"verify_payment"` | Transaction sync / verify | `/merchant/postservice.php?form=2` |
| 12 | `"si_transaction"` | Mandate exercise (recurring) | `/merchant/postservice.php?form=2` |
| 13 | `"pre_debit_SI"` | Mandate pre-debit notification | `/merchant/postservice.php?form=2` |
| 14 | `"update_SI"` | Mandate token update | `/merchant/postservice?form=2` |
| 15 | `"upi_mandate_revoke"` | UPI mandate revoke | `/merchant/postservice.php?form=2` |
| 16 | `"upi_mandate_status"` / `"check_mandate_status"` | Mandate status check | `/merchant/postservice.php?form=2` |
| 17 | `"validateVPA"` | UPI VPA validation | `/merchant/postservice.php?form=2` |
| 18 | `"get_additional_charge"` | Surcharge check | `/merchant/postservice?form=2` |
| 19 | `"payment_split"` | Split settlement | `/merchant/postservice.php?form=2` |

### 3.2 PayuTransactionRequest — Txns `Types.hs`

Primary payment initiation request posted to `/_payment`.

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `key` | Text | Merchant key |
| 2 | `txnid` | Text | Transaction ID |
| 3 | `amount` | Text | Amount (decimal string) |
| 4 | `productinfo` | Text | Product description |
| 5 | `firstname` | Text | Customer first name |
| 6 | `email` | Text | Customer email |
| 7 | `phone` | Text | Customer phone |
| 8 | `surl` | Text | Success redirect URL |
| 9 | `furl` | Text | Failure redirect URL |
| 10 | `hash` | Text | HMAC-SHA512 signature |
| 11 | `pg` | Maybe Text | Payment gateway code (e.g. `"CC"`, `"NB"`, `"UPI"`) |
| 12 | `bankcode` | Maybe Text | Bank/instrument code |
| 13 | `udf1`–`udf10` | Maybe Text | User-defined fields 1–10 |
| 14 | `card_number` | Maybe Text | Card number (PAN) |
| 15 | `name_on_card` | Maybe Text | Cardholder name |
| 16 | `card_expiry_year` | Maybe Text | Card expiry year |
| 17 | `card_expiry_month` | Maybe Text | Card expiry month |
| 18 | `card_cvv` | Maybe Text | Card CVV |
| 19 | `store_card` | Maybe Text | Store card flag |
| 20 | `cardToken` | Maybe Text | Stored card token |
| 21 | `user_token` | Maybe Text | User token |
| 22 | `txn_s2s_flow` | Maybe Text | S2S flow type (`"1"`, `"2"`, `"3"`, `"4"`) |
| 23 | `api_version` | Maybe Text | API version |
| 24 | `bankref_num` | Maybe Text | Bank reference number |
| 25 | `enforce_paymethod` | Maybe Text | Enforce payment method |
| 26 | `paymentType` | Maybe Text | Payment type |
| 27 | `offer_key` | Maybe Text | Offer/coupon key |
| 28 | `coupon_code` | Maybe Text | Coupon code |
| 29 | `create_account` | Maybe Text | Create account flag |
| 30 | `login_id` | Maybe Text | Login ID |
| 31 | `is_mobile` | Maybe Text | Mobile flag |
| 32 | `upi_vpa` | Maybe Text | UPI VPA address |
| 33 | `webhook_url` | Maybe Text | Webhook callback URL |
| 34 | `paymentSubType` | Maybe Text | Payment sub-type |
| 35 | `userDefinedField1`–`userDefinedField10` | Maybe Text | Additional user-defined fields |
| 36 | `sourceId` | Maybe Text | Source identifier |
| 37 | `si` | Maybe Text | Standing instruction flag |
| 38 | `si_details` | Maybe Text | Standing instruction details (JSON) |
| 39 | `splitPaymentDetails` | Maybe Text | Split payment details |
| 40 | `additionalCharges` | Maybe Text | Additional charges |
| 41 | `paymentMode` | Maybe Text | Payment mode |
| 42 | `notifyUrl` | Maybe Text | Notification URL |

### 3.3 PayuUpiTransactionRequest — Txns `Types.hs`

UPI-specific payment request posted to `/_payment`.

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `key` | Text | Merchant key |
| 2 | `txnid` | Text | Transaction ID |
| 3 | `amount` | Text | Amount |
| 4 | `productinfo` | Text | Product description |
| 5 | `firstname` | Text | Customer first name |
| 6 | `email` | Text | Customer email |
| 7 | `phone` | Text | Customer phone |
| 8 | `surl` | Text | Success redirect URL |
| 9 | `furl` | Text | Failure redirect URL |
| 10 | `hash` | Text | HMAC-SHA512 signature |
| 11 | `pg` | Text | Payment gateway (`"UPI"`) |
| 12 | `bankcode` | Maybe Text | UPI bank/app code |
| 13 | `udf1`–`udf5` | Maybe Text | User-defined fields 1–5 |
| 14 | `upi_vpa` | Maybe Text | UPI VPA address |
| 15 | `api_version` | Maybe Text | API version |
| 16 | `webhook_url` | Maybe Text | Webhook URL |
| 17 | `txn_s2s_flow` | Maybe Text | S2S flow type |
| 18 | `notifyUrl` | Maybe Text | Notification URL |

### 3.4 PayuVerifyPaymentRequest — Txns `Types.hs`

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `key` | Text | Merchant key |
| 2 | `command` | Text | `"verify_payment"` |
| 3 | `var1` | Text | Transaction ID (txnId) |
| 4 | `hash` | Text | `SHA512(key \| command \| txnId \| salt)` |

### 3.5 PayuRefundRequest — Txns `Types.hs`

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `key` | Text | Merchant key |
| 2 | `command` | Text | `"cancel_refund_transaction"` |
| 3 | `var1` | Text | PayU payment ID (mihpayid) |
| 4 | `var2` | Text | Refund amount |
| 5 | `var3` | Text | Transaction ID |
| 6 | `hash` | Text | HMAC-SHA512 signature |

### 3.6 PayuCaptureRequest — Txns `Types.hs`

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `key` | Text | Merchant key |
| 2 | `command` | Text | `"capture_transaction"` |
| 3 | `var1` | Text | PayU payment ID (mihpayid) |
| 4 | `var2` | Text | Amount to capture |
| 5 | `hash` | Text | HMAC-SHA512 signature |

### 3.7 PayuVoidRequest — Txns `Types.hs`

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `key` | Text | Merchant key |
| 2 | `command` | Text | `"cancel_refund_transaction"` |
| 3 | `var1` | Text | PayU payment ID (mihpayid) |
| 4 | `hash` | Text | HMAC-SHA512 signature |

### 3.8 PayuCaptureOrVoidSyncRequest — Txns `Types.hs`

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `key` | Text | Merchant key |
| 2 | `command` | Text | `"check_action_status"` |
| 3 | `var1` | Text | PayU payment ID (mihpayid) |
| 4 | `hash` | Text | HMAC-SHA512 signature |

### 3.9 PayuExerciseMandateRequest (SI Transaction) — Txns `Types.hs`

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `key` | Text | Merchant key |
| 2 | `command` | Text | `"si_transaction"` |
| 3 | `var1` | Text | JSON-encoded mandate token type |
| 4 | `hash` | Text | `SHA512(key \| "si_transaction" \| encodeJSON(payUMandateTokenType) \| salt)` |

### 3.10 PayuMandateStatusRequest — Txns `Types.hs`

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `key` | Text | Merchant key |
| 2 | `command` | Text | `"upi_mandate_status"` or `"check_mandate_status"` |
| 3 | `var1` | Text | Mandate identifier |
| 4 | `hash` | Text | HMAC-SHA512 signature |

### 3.11 PayuUpiMandateRevokeRequest — Txns `Types.hs`

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `key` | Text | Merchant key |
| 2 | `command` | Text | `"upi_mandate_revoke"` |
| 3 | `var1` | Text | Mandate identifier |
| 4 | `hash` | Text | HMAC-SHA512 signature |

### 3.12 PayuMandatePreDebitNotificationRequest — Txns `Types.hs`

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `key` | Text | Merchant key |
| 2 | `command` | Text | `"pre_debit_SI"` |
| 3 | `var1` | Text | Notification payload |
| 4 | `hash` | Text | HMAC-SHA512 signature |

### 3.13 PayuTokenUpdateRequest — Txns `Types.hs`

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `key` | Text | Merchant key |
| 2 | `command` | Text | `"update_SI"` |
| 3 | `var1` | Text | Token update payload |
| 4 | `hash` | Text | HMAC-SHA512 signature |

### 3.14 PayuSurchargeRequest — Txns `Types.hs`

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `key` | Text | Merchant key |
| 2 | `command` | Text | `"get_additional_charge"` |
| 3 | `var1` | Text | Payment method info |
| 4 | `var2` | Text | Amount |
| 5 | `hash` | Text | HMAC-SHA512 signature |

### 3.15 PayuSplitSettlementRequest — Txns `Types.hs`

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `key` | Text | Merchant key |
| 2 | `command` | Text | `"payment_split"` |
| 3 | `var1` | Text | Split payload |
| 4 | `hash` | Text | HMAC-SHA512 signature |

### 3.16 PayuRefundArnSyncRequest — Txns `Types.hs`

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `key` | Text | Merchant key |
| 2 | `command` | Text | `"getAllRefundsFromTxnIds"` |
| 3 | `var1` | Text | Transaction ID list |
| 4 | `hash` | Text | HMAC-SHA512 signature |

### 3.17 PayuFetchAuthNParamsRequest — Txns `Types.hs`

Path parameter request to `/decoupled/AuthData?referenceId={referenceId}`.

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `referenceId` | Text | 3DS reference ID (path/query param) |

### 3.18 PayuAuthorizeTransaction (VCO) — Txns `Types.hs`

Posted to `/AuthorizeTransaction.php`.

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `key` | Text | Merchant key |
| 2 | `txnid` | Text | Transaction ID |
| 3 | `amount` | Text | Amount |
| 4 | `productinfo` | Text | Product description |
| 5 | `firstname` | Text | Customer first name |
| 6 | `email` | Text | Customer email |
| 7 | `phone` | Text | Customer phone |
| 8 | `hash` | Text | HMAC-SHA512 signature |
| 9 | `pg` | Maybe Text | Payment gateway code |
| 10 | `bankcode` | Maybe Text | Bank code |
| 11 | `card_number` | Maybe Text | Card number |
| 12 | `name_on_card` | Maybe Text | Cardholder name |
| 13 | `card_expiry_year` | Maybe Text | Expiry year |
| 14 | `card_expiry_month` | Maybe Text | Expiry month |
| 15 | `card_cvv` | Maybe Text | CVV |
| 16 | `store_card` | Maybe Text | Store card flag |
| 17 | `cardToken` | Maybe Text | Card token |
| 18 | `user_token` | Maybe Text | User token |
| 19 | `txn_s2s_flow` | Maybe Text | S2S flow type |
| 20 | `api_version` | Maybe Text | API version |
| 21 | `bankref_num` | Maybe Text | Bank reference number |
| 22 | `enforce_paymethod` | Maybe Text | Enforce payment method |

### 3.19 Gateway-side Request Types

#### SettlementRequest — Gateway `Types.hs`

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `key` | Text | Merchant key |
| 2 | `command` | Text | `"get_settlement_details"` |
| 3 | `var1` | Text | Date |
| 4 | `hash` | Text | `SHA512(key \| "get_settlement_details" \| date \| salt)` |

#### PayUEmiPlansRequest — Gateway `Types.hs`

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `key` | Text | Merchant key |
| 2 | `command` | Text | `"getEmiAmountAccordingToInterest"` |
| 3 | `var1` | Text | EMI query params |
| 4 | `hash` | Text | HMAC-SHA512 signature |

#### PayuDcEmiEligibilityRequest — Gateway `Types.hs`

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `key` | Text | Merchant key |
| 2 | `command` | Text | `"get_checkout_details"` |
| 3 | `var1` | Text | JSON-encoded payload |
| 4 | `hash` | Text | `SHA512(key \| command \| encodeJson(var1Payload) \| salt)` |

**Nested `PayuDcEmiEligibilityRequestPayload`**:

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `payer_emi_amount` | Text | EMI amount |
| 2 | `tenure` | Text | EMI tenure (months) |
| 3 | `card_number` | Text | Card number |
| 4 | `product_code` | Text | Product code |

#### PayuBNPLEligibilityRequest — Gateway `Types.hs`

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `key` | Text | Merchant key |
| 2 | `command` | Text | `"get_checkout_details"` |
| 3 | `var1` | Text | Phone + amount payload |
| 4 | `hash` | Text | HMAC-SHA512 signature |

#### PayuGetCardDetailsRequest — Gateway `Types.hs`

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `key` | Text | Merchant key |
| 2 | `command` | Text | `"get_payment_instrument"` |
| 3 | `var1` | Text | Card token identifier |
| 4 | `hash` | Text | HMAC-SHA512 signature |

#### PayuGetTokenDetailsRequest — Gateway `Types.hs`

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `key` | Text | Merchant key |
| 2 | `command` | Text | `"get_payment_details"` |
| 3 | `var1` | Text | Token identifier |
| 4 | `hash` | Text | HMAC-SHA512 signature |

#### PayuLinkAndPayEligibilityRequest — Gateway `Types.hs`

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `key` | Text | Merchant key |
| 2 | `command` | Text | Eligibility command |
| 3 | `var1` | Text | Eligibility payload |
| 4 | `hash` | Text | HMAC-SHA512 signature |

#### PayuDelinkRequest — Gateway `Types.hs`

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `instrumentId` | Text | Instrument/wallet ID to delink |
| 2 | `user_token` | Text | User token |

Headers: `Content-Type: application/json`, `Date: {date}`, `Authorization: {authValue}`, `x-credential-username: {key}`

### 3.20 S2S Flow Type Selection (`Transforms.hs:1033-1047`)

The `txn_s2s_flow` field in payment requests is determined by:

| # | Condition | `txn_s2s_flow` Value |
|---|-----------|----------------------|
| 1 | `isDirectAuthorization = True` | `"3"` |
| 2 | `isTxnS2SFlow4Enabled && isDirectOTPTxn` | `"4"` |
| 3 | `isTxnS2SFlow4Enabled && s2sEnabled` | `"4"` |
| 4 | `s2sEnabled && isEmandateRegister` | `"4"` |
| 5 | `isDirectOTPTxn` | `"2"` |
| 6 | `s2sEnabled` | `"1"` |
| 7 | default | `"1"` |

---

## 4. Response Structure

### 4.1 PayUResponseReq — 57 fields (Webhook / Redirect Response) — Txns `Types.hs`

Used for incoming webhook callbacks and redirect responses from PayU.

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `txnid` | Maybe Text | Internal transaction ID |
| 2 | `mihpayid` | Maybe Text | PayU payment ID |
| 3 | `amount` | Maybe Text | Transaction amount |
| 4 | `discount` | Maybe Text | Discount applied |
| 5 | `net_amount_debit` | Maybe Text | Net amount debited |
| 6 | `mode` | Maybe Text | Payment mode |
| 7 | `status` | Maybe Text | Status: `"success"`, `"failure"`, `"pending"`, `"error"` |
| 8 | `unmappedstatus` | Maybe Text | Raw PayU status: `"auth"`, `"captured"`, `"cancelled"`, etc. |
| 9 | `firstname` | Maybe Text | Customer first name |
| 10 | `lastname` | Maybe Text | Customer last name |
| 11 | `address1` | Maybe Text | Address line 1 |
| 12 | `address2` | Maybe Text | Address line 2 |
| 13 | `city` | Maybe Text | City |
| 14 | `state` | Maybe Text | State |
| 15 | `country` | Maybe Text | Country |
| 16 | `zipcode` | Maybe Text | ZIP code |
| 17 | `email` | Maybe Text | Customer email |
| 18 | `phone` | Maybe Text | Customer phone |
| 19 | `udf1` | Maybe Text | User-defined field 1 |
| 20 | `udf2` | Maybe Text | User-defined field 2 |
| 21 | `udf3` | Maybe Text | User-defined field 3 |
| 22 | `udf4` | Maybe Text | User-defined field 4 |
| 23 | `udf5` | Maybe Text | User-defined field 5 |
| 24 | `udf6` | Maybe Text | User-defined field 6 |
| 25 | `udf7` | Maybe Text | User-defined field 7 |
| 26 | `udf8` | Maybe Text | User-defined field 8 |
| 27 | `udf9` | Maybe Text | User-defined field 9 |
| 28 | `udf10` | Maybe Text | User-defined field 10 |
| 29 | `productinfo` | Maybe Text | Product description |
| 30 | `pg_type` | Maybe Text | Payment gateway type |
| 31 | `bank_ref_num` | Maybe Text | Bank reference number |
| 32 | `bankcode` | Maybe Text | Bank code |
| 33 | `error` | Maybe Text | Error code |
| 34 | `error_code` | Maybe Text | Detailed error code |
| 35 | `error_Message` | Maybe Text | Error message |
| 36 | `field1` | Maybe Text | PayU field 1 |
| 37 | `field2` | Maybe Text | PayU field 2 |
| 38 | `field3` | Maybe Text | PayU field 3 |
| 39 | `field4` | Maybe Text | PayU field 4 |
| 40 | `field5` | Maybe Text | PayU field 5 |
| 41 | `field6` | Maybe Text | PayU field 6 |
| 42 | `field7` | Maybe Text | PayU field 7 |
| 43 | `field8` | Maybe Text | PayU field 8 |
| 44 | `field9` | Maybe Text | PayU field 9 (often error description) |
| 45 | `error_description` | Maybe Text | Extended error description |
| 46 | `cardToken` | Maybe Text | Stored card token |
| 47 | `nameOnCard` | Maybe Text | Name on card |
| 48 | `cardCategory` | Maybe Text | Card category |
| 49 | `hash` | Maybe Text | Response hash for verification |
| 50 | `additionalCharges` | Maybe Text | Additional charges |
| 51 | `paymentSubType` | Maybe Text | Payment sub-type |
| 52–57 | (additional fields) | Maybe Text | Gateway-specific extended fields |

### 4.2 PayuCaptureOrVoidSyncResponse / PayuCaptureOrVoidSyncResponse2 — Txns `Types.hs`

Response to `check_action_status` command.

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `payuId` | Maybe Text | PayU payment ID |
| 2 | `status` | Maybe Text | Status of capture/void action |
| 3 | `amount` | Maybe Text | Amount |
| 4 | `message` | Maybe Text | Status message |
| 5 | `requestId` | Maybe Text | Request ID |
| 6 | `error_code` | Maybe Text | Error code |
| 7 | `error_description` | Maybe Text | Error description |

### 4.3 PayUExerciseMandateResponse — Txns `Types.hs`

Response to `si_transaction` (mandate exercise).

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `status` | Maybe Text | Response status |
| 2 | `message` | Maybe Text | Status message |
| 3 | `mandateDetails` | Maybe PayUMandateResponseDetailsType | Mandate details object |
| 4 | `paymentMode` | Maybe Text | Payment mode used |
| 5 | `unmappedstatus` | Maybe Text | Raw PayU status |
| 6 | `field1`–`field9` | Maybe Text | PayU fields 1–9 |
| 7 | `bank_ref_num` | Maybe Text | Bank reference number |
| 8 | `error_code` | Maybe Text | Error code |
| 9 | `error_Message` | Maybe Text | Error message |
| 10 | `mihpayid` | Maybe Text | PayU payment ID |
| 11 | `txnid` | Maybe Text | Transaction ID |
| 12 | `amount` | Maybe Text | Amount |

#### Nested: PayUMandateResponseDetailsType

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `umrn` | Maybe Text | Unique mandate reference number |
| 2 | `mandate_amount` | Maybe Text | Mandate amount |
| 3 | `billing_amount` | Maybe Text | Billing amount |
| 4 | `billing_cycle` | Maybe Text | Billing cycle (e.g. `"MONTHLY"`) |
| 5 | `billing_interval` | Maybe Text | Billing interval |
| 6 | `start_date` | Maybe Text | Mandate start date |
| 7 | `end_date` | Maybe Text | Mandate end date |
| 8 | `paymentMechanism` | Maybe Text | Payment mechanism |
| 9 | `mandate_id` | Maybe Text | Mandate ID |

### 4.4 OTP Response Types — Txns `Types.hs`

#### PayuTriggerOTPResponse / PayUOtpTriggerResponse / PayUOtpTriggerResponseResult

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `status` | Maybe Text | OTP trigger status |
| 2 | `result` | Maybe PayUOtpTriggerResponseResult | Result object |
| 3 | `error` | Maybe Text | Error code |
| 4 | `message` | Maybe Text | Status message |
| 5 | `bank_ref_num` | Maybe Text | Bank reference number |

**`PayUOtpTriggerResponseResult`** fields: `status`, `error`, `bank_ref_num`

#### PayUOtpSubmitResponse / PayUOtpSubmissionResponseV4 / PayuOtpErrorResp

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `status` | Maybe Text | Submission status (`"success"` / other) |
| 2 | `result` | Maybe OtpResult | Result object with `status`, `error`, `bank_ref_num` |
| 3 | `metaData` | Maybe OtpMeta | Metadata with `statusCode`, `message` (V4) |

#### PayuResendOTPResponse / PayUResendOTpResponse / PayUResendOTpResponseV4

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `status` | Maybe Text | Resend status |
| 2 | `message` | Maybe Text | Status message |
| 3 | `result` | Maybe Text | Result data |
| 4 | `data` | Maybe Text | Additional data (V4) |

### 4.5 PayUPaymentResponse ADT — Txns `Types.hs:936-947`

Union type wrapping all possible payment response variants:

| # | Constructor | Description |
|---|-------------|-------------|
| 1 | `OtpSubmitResp` | OTP submission response |
| 2 | `PayuSyncSuccessResponse` | S2S sync success response |
| 3 | `PayURedirectResponse` | Redirect-based success response |
| 4 | `PayuSyncErrorResponse` | S2S sync error response |
| 5 | `PayURedirectErrorResponse` | Redirect-based error response |
| 6 | `OtpErrorResponse` | OTP error response |
| 7 | `OtpSubmitRespV4` | OTP submission response V4 |
| 8 | `PayuAuthZOnlyResp` | Authorization-only response (VCO) |
| 9 | `OtpSubmitErrorResponseV4` | OTP submission error V4 |
| 10 | `PayuDirectDebitResponse` | Direct debit response |

### 4.6 PayuRefundResp ADT — Txns `Types.hs:848-852`

| # | Constructor | Description |
|---|-------------|-------------|
| 1 | `SuccessRefundFetch PayuRefundStatusResponse` | Successful refund status response |
| 2 | `SplitRefundFetch PayuSplitRefundStatusResponse` | Split refund status response |
| 3 | `FailureRefundResponse PayuErrorRefundResp` | Refund error response |

### 4.7 PayuVerifyVPAResponse — Txns `Types.hs`

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `IsValid` | VPAValidType | VPA validity (Int or String) |
| 2 | `IsUPINumber` | Maybe Bool | Whether it is a UPI number |
| 3 | `payerAccountName` | Maybe Text | Account holder name |
| 4 | `upiNumber` | Maybe Text | UPI number |
| 5 | `payerAccountScheme` | Maybe Text | Payment scheme |

### 4.8 Mandate-related Response Types — Txns `Types.hs`

#### PayuMandateStatusResponse

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `status` | Maybe Text | Mandate status string |
| 2 | `message` | Maybe Text | Status message |
| 3 | `umrn` | Maybe Text | Unique mandate reference number |
| 4 | `mandate_amount` | Maybe Text | Mandate amount |
| 5 | `billing_cycle` | Maybe Text | Billing cycle |
| 6 | `billing_interval` | Maybe Text | Billing interval |
| 7 | `mandate_id` | Maybe Text | Mandate ID |
| 8 | `paymentMechanism` | Maybe Text | Payment mechanism |

#### UpdateToTokenResp

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `status` | Maybe Int | Update status (1 = success) |
| 2 | `message` | Maybe Text | Status message |
| 3 | `data` | Maybe Text | Additional data |
| 4 | `error_code` | Maybe Text | Error code |

#### PayuCancelRecurringResponse

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `status` | Maybe Text | Revoke status |
| 2 | `action` | Maybe Text | Action performed |
| 3 | `message` | Maybe Text | Status message |

### 4.9 Push Pay / UPI Collect Response — Txns `Types.hs`

#### PayUPushPayResponse

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `status` | Maybe Text | Response status |
| 2 | `result` | Maybe Text | Result data |
| 3 | `error_code` | Maybe Text | Error code |
| 4 | `error_description` | Maybe Text | Error description |

### 4.10 Notification Response — Txns `Types.hs`

#### PayuPreDebitNotificationResponse

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `status` | Maybe Text | Notification status |
| 2 | `message` | Maybe Text | Status message |
| 3 | `data` | Maybe Text | Notification data |

### 4.11 3DS Authentication Response Types — Txns `Types.hs`

#### PayuFetchAuthNParamsResponse / PayuAuthenticationParams

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `status` | Maybe Text | Response status |
| 2 | `message` | Maybe Text | Status message |
| 3 | `result` | Maybe AuthNResult | Authentication parameters |

**Nested `AuthNResult`** fields: `referenceId`, `gatewayAuthReqParams`, `authenticationParams` (with 3DS server trans IDs, ACS details)

#### PayuGetThreeDsParamsTxnResponse / PostToBank / BinData / AcsRenderingType

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `threeDSServerTransID` | Maybe Text | 3DS server transaction ID |
| 2 | `acsTransID` | Maybe Text | ACS transaction ID |
| 3 | `acsSignedContent` | Maybe Text | ACS signed content |
| 4 | `dsTransID` | Maybe Text | Directory server transaction ID |
| 5 | `acsURL` | Maybe Text | ACS URL |
| 6 | `bin_data` | Maybe BinData | BIN-level data |
| 7 | `acsRenderingType` | Maybe AcsRenderingType | ACS rendering type |

**Nested `BinData`** fields: `token_requestor_id`, `card_range_id`, `directory_server_id`

**Nested `AcsRenderingType`** fields: `acsInterface`, `acsUiTemplate`

### 4.12 Surcharge / Settlement / Split Response Types

#### PayuSurchargeResponse — Txns `Types.hs`

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `status` | Maybe Text | Status |
| 2 | `message` | Maybe Text | Message |
| 3 | `result` | Maybe SurchargeResult | Surcharge amounts per payment method |

#### SettlementResponse — Gateway `Types.hs`

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `status` | Text | `"1"` (success), `"ERROR"`, or `"FAILURE"` |
| 2 | `settlement_payload` | Text | Settlement data or error message |

#### PayuSplitSettlementResponse / PayuGetSplitInfoResponse — Txns `Types.hs`

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `status` | Maybe Text | `"SUCCESS"` or `"FAILED"` |
| 2 | `code` | Maybe Text | Error code |
| 3 | `message` | Maybe Text | Status message |
| 4 | `data` | Maybe Value | Split data |

### 4.13 Gateway-side Response Types

#### PayuGetCardDetailsResponse — Gateway `Types.hs`

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `status` | Maybe Text | Status |
| 2 | `message` | Maybe Text | Message |
| 3 | `result` | Maybe CardDetailsResult | Tokenized card details |

#### PayuGetTokenDetailsResponse — Gateway `Types.hs`

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `status` | Maybe Text | Status |
| 2 | `message` | Maybe Text | Message |
| 3 | `result` | Maybe TokenDetailsResult | TAVV, ECI, PAR, card details |

#### PayUEmiPlansResponse — Gateway `Types.hs`

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `status` | Maybe Text | Status |
| 2 | `data` | Maybe EmiData | Map of EMI plans per bank/tenure |

#### PayuBNPLEligibilityResponse / PayuLinkAndPayEligibilityResponse / PayuEligibilityResp — Gateway `Types.hs`

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `status` | Maybe Text | Status |
| 2 | `message` | Maybe Text | Message |
| 3 | `result` | Maybe Value | Eligibility details |

#### PayuDelinkResp — Gateway `Types.hs`

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `status` | Maybe Text | Delink status |
| 2 | `message` | Maybe Text | Message |
| 3 | `data` | Maybe Value | Delink data |

### 4.14 Webhook Response Types — Txns `Types.hs`

#### WebhookResponse (union)

| # | Constructor | Description |
|---|-------------|-------------|
| 1 | `PayuRefundWebhookResp` | Refund webhook payload |
| 2 | `PayuUpiMandateStatusWebhook` | UPI mandate status webhook |
| 3 | `PayuCardMandateStatusWebhook` | Card mandate status webhook |

#### PayuRefundWebhookResp

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `txnid` | Maybe Text | Transaction ID |
| 2 | `mihpayid` | Maybe Text | PayU payment ID |
| 3 | `amount` | Maybe Text | Transaction amount |
| 4 | `status` | Maybe Text | Refund status |
| 5 | `refundId` | Maybe Text | Refund ID |
| 6 | `refundAmount` | Maybe Text | Refund amount |
| 7 | `error_code` | Maybe Text | Error code |
| 8 | `error_Message` | Maybe Text | Error message |

#### PayuAuthenticationWehookParams

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `referenceId` | Maybe Text | 3DS reference ID |
| 2 | `identifierValue` | Maybe Text | Identifier value |
| 3 | `authenticationParams` | Maybe Value | Authentication parameters |

### 4.15 PgErrorInfo Extraction from Response (`Flow.hs:4358-4400`)

| # | Response Type | `error_code` Source | `error_description` Source |
|---|---|---|---|
| 1 | `OtpSubmitResp` (non-success) | `resp.result.error` | `getErrorMsg result` |
| 2 | `PayuSyncSuccessResponse` (non-success/pending) | `status` field | `error_Message` or `field9` |
| 3 | `PayURedirectResponse` (non-success/pending) | `status` field | `error_Message` or `field9` |
| 4 | `PayuSyncErrorResponse` | Nothing | Nothing |
| 5 | `PayURedirectErrorResponse` | `error_code` | `error_description` |
| 6 | `OtpErrorResponse` | `error` | `message` |
| 7 | `OtpSubmitRespV4` (non-success/pending) | `result.error` | `getErrorMsg result` |
| 8 | `PayuAuthZOnlyResp` (non-captured) | `result.error` | `getErrorMsg result` |
| 9 | `OtpSubmitErrorResponseV4` | `metaData.statusCode` | `metaData.message` |

---

## 5. Flows

### 5.1 Gateway-side Flows

#### Flow 1: `checkEligibility` — `Eligibility.hs`

**Purpose**: Check BNPL or LinkAndPay eligibility for a customer/instrument.
**Trigger**: Gateway eligibility API call.

| Step | Action | Details |
|------|--------|---------|
| 1 | Decode `PayUAccountDetails` from `MerchantGatewayAccount` | Extracts key, salt, sandbox flag |
| 2 | Build eligibility request | `PayuBNPLEligibilityRequest` or `PayuLinkAndPayEligibilityRequest` |
| 3 | Compute HMAC-SHA512 hash | `makePayuHash` |
| 4 | POST to PayU eligibility endpoint | `payuBaseUrl` with `isLinkAndPay` flag |
| 5 | Parse response | `PayuBNPLEligibilityResponse` or `PayuLinkAndPayEligibilityResponse` |

**Decision Points**:

| Condition | YES Branch | NO Branch |
|-----------|-----------|-----------|
| API call returns `Left _` | Return `[]` (empty list) | Parse and return eligibility result |

#### Flow 2: `getEmiPlans` / `getEmiPlans'` — `Emi.hs:82-183`

**Purpose**: Fetch EMI plans from DB cache or PayU API.
**Trigger**: EMI plan lookup request.

| Step | Action | Details |
|------|--------|---------|
| 1 | Check DB for cached EMI plans | Query `emi_plan` table |
| 2 | If cache miss, build `PayUEmiPlansRequest` | command = `"getEmiAmountAccordingToInterest"` |
| 3 | Compute HMAC-SHA512 hash | `makePayuHash` |
| 4 | POST to PayU merchant post service | `payuBaseUrl` |
| 5 | Parse `PayUEmiPlansResponse` | Extract bank-wise EMI details |
| 6 | DC EMI eligibility check | Calls `PayuDcEmiEligibilityRequest` if needed |

**Decision Points**:

| Condition | YES Branch | NO Branch |
|-----------|-----------|-----------|
| Plans found in DB | Return cached plans | Call PayU API |
| API returns `Left err` | Return `Left (GatewayError { errorCode = "500", errorReason = show err })` | Return plans |
| DC EMI eligibility error | Return `[]` | Return eligibility result |

#### Flow 3: `getGatewayCardDetails` — `GetCardDetails.hs:26,101-110`

**Purpose**: Fetch tokenized card details from PayU.
**Trigger**: Card token detail lookup.

| Step | Action | Details |
|------|--------|---------|
| 1 | Decode `PayUAccountDetails` | Get key, salt |
| 2 | Build `PayuGetCardDetailsRequest` | command = `"get_payment_instrument"` |
| 3 | Compute hash | `makePayuHash` |
| 4 | POST to PayU | `/merchant/postservice.php?form=2` |
| 5 | Parse `PayuGetCardDetailsResponse` | Extract card details |

**Decision Points**:

| Condition | YES Branch | NO Branch |
|-----------|-----------|-----------|
| API returns `Left err` | `makeFailureGetGwCardsResponse err` via `Utils.handleClientError` | Return card details |

#### Flow 4: `getGatewayTokenDetails` — `GetTokenDetails.hs:29-33`

**Purpose**: Fetch token-level details (TAVV, ECI, PAR) from PayU.

| Step | Action | Details |
|------|--------|---------|
| 1 | Decode `PayUAccountDetails` | On decode error: `makeFailureGetGwCardsResponse "ACCOUNT_DETAILS_DECODE_ERROR"` |
| 2 | Build `PayuGetTokenDetailsRequest` | command = `"get_payment_details"` |
| 3 | Compute hash | `makePayuHash` |
| 4 | POST to PayU | `/merchant/postservice.php?form=2` |
| 5 | Parse `PayuGetTokenDetailsResponse` | Extract TAVV/ECI/PAR |

**Decision Points**:

| Condition | YES Branch | NO Branch |
|-----------|-----------|-----------|
| Account decode error | `makeFailureGetGwCardsResponse "ACCOUNT_DETAILS_DECODE_ERROR"` | Continue |
| API returns `Left err` | `makeFailureGetGwCardsResponse errResp.errType errResp.errorMessage` | Return token details |

#### Flow 5: `getSettlements` — `Settlements.hs:38-60`

**Purpose**: Fetch settlement data for a given date.

| Step | Action | Details |
|------|--------|---------|
| 1 | Decode `PayUAccountDetails` | Get key, salt |
| 2 | Build `SettlementRequest` | command = `"get_settlement_details"`, var1 = date |
| 3 | Compute settlement hash | `SHA512(key \| "get_settlement_details" \| date \| salt)` |
| 4 | POST to PayU | `/merchant/postservice.php?form=2` |
| 5 | Check `res.status` | Must equal `"1"` for success |

**Decision Points**:

| Condition | YES Branch | NO Branch |
|-----------|-----------|-----------|
| API returns `Left err` | `{ status = "ERROR", settlement_payload = errorMessage }` | Check status |
| `res.status /= "1"` | `{ status = "FAILURE", ... }` | `{ status = "SUCCESS", ... }` |

---

### 5.2 Txns-side Flows

#### Flow 1: `initiateTxn` / `initiateTransaction` — `Flow.hs`

**Purpose**: Main transaction initiation entry point.
**Trigger**: New payment transaction request.

| Step | Action | Details |
|------|--------|---------|
| 1 | Load merchant gateway account | `PayuDetails` from DB |
| 2 | Determine payment method | `getPgAndbankCode` → PayU `pg` + `bankCode` |
| 3 | Determine S2S flow type | `txn_s2s_flow` from `Transforms.hs:1033-1047` |
| 4 | Branch: DOTP or standard | `isDirectOTPTxn` flag |
| 5a | DOTP branch | Build `PayuTransactionRequest`, POST to `/_payment` |
| 5b | Standard S2S branch | Build request based on payment method, POST to appropriate endpoint |
| 6 | Handle response | Dispatch to `handlePayUTxnTesponse` |

**Decision Points**:

| Condition | YES Branch | NO Branch |
|-----------|-----------|-----------|
| `isDirectOTPTxn` | DOTP flow | Standard S2S flow |
| UPI payment | `PayuUpiTransactionRequest` to `/_payment` | Card/NB/Wallet request |
| `HTTP_504`/`HTTP_503` | `throwUpstreamGatewayError` | Continue |
| `HTTP_5XX` | Construct `PayURedirectErrorResponse` | Continue |
| Other HTTP error | `markAuthorizationFailedAndThrowError` | Continue |

#### Flow 2: `handlePayUTxnTesponse` — `Flow.hs`

**Purpose**: Dispatch payment response based on HTTP code and response type.

| Step | Action | Details |
|------|--------|---------|
| 1 | Check HTTP response code | 200, 302, or other |
| 2 | Parse response body | Decode to `PayUPaymentResponse` ADT |
| 3 | Dispatch on response type | `PayuSyncSuccessResponse`, `PayURedirectResponse`, error variants, OTP variants |
| 4 | Map to `TxnStatus` | Per response → status mapping table |
| 5 | Update transaction | Persist status, gateway data |

#### Flow 3: `captureTxn` — `Flow.hs:1453`

**Purpose**: Capture a pre-authorized payment.

| Step | Action | Details |
|------|--------|---------|
| 1 | Build `PayuCaptureRequest` | command = `"capture_transaction"`, var1 = payuId, var2 = amount |
| 2 | Compute hash | `makePayuHash` |
| 3 | POST to PayU | `/merchant/postservice.php?form=2` |
| 4 | Parse response | Check status |

**Decision Points**:

| Condition | Result |
|-----------|--------|
| `Left err` | `throwErr CAPTURE_PROCESSING_FAILED` |
| Success | Update txn to `CHARGED` |

#### Flow 4: `voidTxn` — `Flow.hs:1478`

**Purpose**: Void a pre-authorized payment.

| Step | Action | Details |
|------|--------|---------|
| 1 | Build `PayuVoidRequest` | command = `"cancel_refund_transaction"`, var1 = payuId |
| 2 | Compute hash | `makePayuHash` |
| 3 | POST to PayU | `/merchant/postservice.php?form=2` |
| 4 | Parse response | Check status |

**Decision Points**:

| Condition | Result |
|-----------|--------|
| `Left err` | `throwErr VOID_PROCESSING_FAILED` |
| Success | Update txn to `VOIDED` |

#### Flow 5: `payUCaptureVoidTxnSync` — `Flow.hs`

**Purpose**: Sync capture/void status with PayU.

| Step | Action | Details |
|------|--------|---------|
| 1 | Build `PayuCaptureOrVoidSyncRequest` | command = `"check_action_status"` |
| 2 | POST to PayU | `/merchant/postservice.php?form=2` |
| 3 | Parse `PayuCaptureOrVoidSyncResponse` | Check status |
| 4 | On 504/503/Socket timeout | `getResponseForSyncFailureCaseHandling` → `PayUErrorResponse` |

#### Flow 6: `verifyPayment` / `getPayUTxnStatusResponse` — `Flow.hs`

**Purpose**: Verify/sync payment status with PayU.

| Step | Action | Details |
|------|--------|---------|
| 1 | Build `PayuVerifyPaymentRequest` | command = `"verify_payment"`, var1 = txnId |
| 2 | Compute `makePayuVerifyHash` | `SHA512(key \| command \| txnId \| salt)` |
| 3 | Set custom timeout header | from Redis or `defaultPayuForceSyncTimeoutInMS` |
| 4 | POST to PayU | `/merchant/postservice.php?form=2` |
| 5 | Parse response | Map to `TxnStatus` |

#### Flow 7: `submitOtp` — `Flow.hs:~4276-4282`

**Purpose**: Submit OTP for card payment.

| Step | Action | Details |
|------|--------|---------|
| 1 | Build OTP submit request | OTP value + transaction context |
| 2 | POST to PayU OTP endpoint | ResponseHandler.php (LinkAndPay) |
| 3 | Parse response | `OtpSubmitResp` or `OtpSubmitRespV4` |

**Decision Points**:

| Error | Result |
|-------|--------|
| `HTTP_504`/`HTTP_503` | `throwUpstreamGatewayError` |
| Other error | `defaultThrowECException SUBMIT_OTP_FAILED` |

#### Flow 8: `resendOtp` — `Flow.hs:4635-4643`

**Purpose**: Resend OTP for card payment.

| Error | Result |
|-------|--------|
| `HTTP_504`/`HTTP_503` | `throwUpstreamGatewayError` |
| Socket timeout | `throwUpstreamGatewayError` |
| Other HTTP/Socket/Payload | `defaultResendOTPResponse` (soft failure) |

#### Flow 9: `setupMandate` — `Flow.hs`

**Purpose**: Register a new mandate (standing instruction).

| Step | Action | Details |
|------|--------|---------|
| 1 | Build `PayuTransactionRequest` with SI fields | `si = "1"`, `si_details = JSON` |
| 2 | Set `billingCycle` and `billingInterval` | From mandate frequency mapping |
| 3 | POST to `/_payment` | Standard payment flow |
| 4 | Parse mandate registration response | Check `unmappedstatus`, `mihpayid` |

#### Flow 10: `executeMandate` — `Flow.hs`

**Purpose**: Exercise a registered mandate (recurring debit).

| Step | Action | Details |
|------|--------|---------|
| 1 | Build `PayuExerciseMandateRequest` | command = `"si_transaction"`, var1 = encoded mandate token |
| 2 | Compute mandate hash | `SHA512(key \| "si_transaction" \| encodeJSON(payUMandateTokenType) \| salt)` |
| 3 | POST to PayU | `/merchant/postservice.php?form=2` |
| 4 | Parse `PayUExerciseMandateResponse` | Map status |

#### Flow 11: `revokeMandateToken` — `Flow.hs:5608-5614, 5763-5769`

**Purpose**: Revoke a mandate token with PayU.

| Error | Handler | Result |
|-------|---------|--------|
| `HTTP_504`/`HTTP_503`/`Socket _` | `verifyMandateStatusWithPG authPayuId` | Sync fallback |
| `Payload _` | `mkMandateRevokeSuccessResponse (mandate ^. _status) (Just "GATEWAY_REVOKE_FAILED") ...` | Mark revoke failed |

#### Flow 12: `checkMandateStatus` — `Flow.hs`

**Purpose**: Check mandate status with PayU.

| Step | Action | Details |
|------|--------|---------|
| 1 | Build `PayuMandateStatusRequest` | command = `"upi_mandate_status"` or `"check_mandate_status"` |
| 2 | POST to PayU | `/merchant/postservice.php?form=2` |
| 3 | Parse response | Map PayU status string to `MandateStatus` |

#### Flow 13: `updateTokenDetailsWithPG` — `Flow.hs:5381-5408`

**Purpose**: Update token details with PayU.

| Step | Action | Details |
|------|--------|---------|
| 1 | Build `PayuTokenUpdateRequest` | command = `"update_SI"` |
| 2 | POST to PayU | `/merchant/postservice?form=2` |
| 3 | Check `res.status == 1` or `res.message == "Already PMU Updated"` | → `SUCCESS` |
| 4 | On `Left err` or decode error | → `FAIL` |

#### Flow 14: `callInitNotification` — `Flow.hs:5112-5122`

**Purpose**: Send pre-debit notification for mandate.

| Step | Action | Details |
|------|--------|---------|
| 1 | Build `PayuMandatePreDebitNotificationRequest` | command = `"pre_debit_SI"` |
| 2 | POST to PayU | `/merchant/postservice.php?form=2` |
| 3 | Check status in `["success","1"]` | Success branch |

**Decision Points**:

| Condition | Result |
|-----------|--------|
| `Left err` | `GatewayNotificationFailure { status = Notify.FAILURE, errorCode = "JP_801" }` |
| Status not in `["success","1"]` | `markNotifyFailure` |

#### Flow 15: `initPayuRefundRequestApi` / `RefundResponseHandler` — `RefundResponseHandler.hs:125-248`

**Purpose**: Initiate and process refund.

| Step | Action | Details |
|------|--------|---------|
| 1 | Build `PayuRefundRequest` | command = `"cancel_refund_transaction"` |
| 2 | POST to PayU | `/merchant/postservice.php?form=2` |
| 3 | Parse `PayuRefundResp` ADT | `SuccessRefundFetch`, `SplitRefundFetch`, or `FailureRefundResponse` |
| 4 | Map to `RefundStatus` | Per mapping table |

**Error Handling**:

| Error | Result |
|-------|--------|
| `Left (Socket x)` | `PENDING` with `"Gateway Timed Out"` message |
| `Left err` (other) | `PENDING` (decode failed) |
| `FailureRefundResponse "DB_EXCEPTION_ERROR_SLAVE"` | `PENDING` |
| `FailureRefundResponse "Requests limit reached"` | `PENDING` |
| `FailureRefundResponse "No Refunds Found"` | `REFUND_NOT_FOUND` (404) |

#### Flow 16: `getThreeDSAuthenticationParams` — `Flow.hs:5796-5821`

**Purpose**: Fetch 3DS authentication parameters from PayU.

| Error | Result |
|-------|--------|
| `Left err` (HTTP/decode) | `Left (makePaymentGatewayInfo "Something went wrong" "Invalid Response" ...)` |
| `referenceId` missing | `Left (makePaymentGatewayInfo "Something went wrong" "Mandatory params missing" ...)` |
| `gatewayAuthReqParams` missing | `Left (makePaymentGatewayInfo ...)` |
| `ErrorAuthNParamsResponse` | `Left PaymentGatewayInfo` |

#### Flow 17: `extractPayUAuthenticationWebhook` — `Flow.hs:5851-5895`

**Purpose**: Parse 3DS authentication webhook from PayU.

| Error | Result |
|-------|--------|
| `Left err` on decode | Returns `{ identifierValue = Nothing, authenticationParams = Nothing, errorDetails = Just { errorCode = "Decode Failure", errorMsg = "UnExpected Payload Received From PAYU" } }` |

#### Flow 18: `sendCollectRequest` — `Flow.hs`

**Purpose**: Initiate UPI Collect request.

| Step | Action | Details |
|------|--------|---------|
| 1 | Build `PayuUpiTransactionRequest` | pg = `"UPI"`, upi_vpa = customer VPA |
| 2 | POST to `/_payment` | UPI collect flow |
| 3 | Parse `Payus2sUpiCollectValidResp` or `ErrorResponse` | Map to status |

#### Flow 19: `initiatePushPayTransaction` — `Flow.hs:4864-4944`

**Purpose**: Initiate UPI push pay transaction.

| Response | Condition | Result |
|----------|-----------|--------|
| `ErrorResponse` | — | `AUTHENTICATION_FAILED` |
| Collect resp + success + result pending | — | PENDING (no webhook) |
| Collect resp + success + other result | — | `AUTHORIZATION_FAILED` |
| `Left err` | — | `isPgStatusUnknown = True` |
| Unexpected type | — | `PENDING_VBV` |

#### Flow 20: `getSdkParams` — `Flow.hs`

**Purpose**: Get SDK parameters for UPI Intent / Google Pay.

| Step | Action | Details |
|------|--------|---------|
| 1 | Determine intent type | UPI Intent or GPay |
| 2 | Build intent request | PayuTransactionRequest with `paymentSubType` |
| 3 | POST to `/_payment` | |
| 4 | Parse intent response | On decode fail: `INTENT_RESPONSE_DECODE_ERROR` |

#### Flow 21: `validateThreeDsParamAndMakePayment` — `Flow.hs`

**Purpose**: 3DS2 SDK payment with authentication params.

| Step | Action | Details |
|------|--------|---------|
| 1 | Fetch 3DS params | `getThreeDSAuthenticationParams` |
| 2 | Build payment request with 3DS data | Include ACS params |
| 3 | POST to PayU | `/_payment` or `AuthorizeTransaction.php` |
| 4 | Handle response | Standard response dispatch |

#### Flow 22: `callAuthorizeApi` / `getAuthorizationResponseFromPG` — `Flow.hs:4752-4798`

**Purpose**: VCO (Visa Checkout) authorization flow.

| Response | Result |
|----------|--------|
| `Left err` (decode fail) | `AUTHORIZATION_FAILED` via `decodeFailureHandler` |
| `PayuViesInvalidResponse` | `AUTHORIZATION_FAILED` |
| `PayuViesValidResp` status `"SUCCESS"` | `CHARGED` |
| `PayuViesValidResp` other status | `AUTHORIZATION_FAILED` |

#### Flow 23: `verifyMessageIntegrityV2` / IntegrityFramework — `Flow.hs:6092-6178`

**Purpose**: Verify message integrity for webhook/redirect responses.

| Response | PayU `status` | Result |
|----------|---------------|--------|
| `PayuSyncSuccessResponse` | `"success"` | `PENDING_VBV` (trigger sync) |
| `PayuSyncSuccessResponse` | other | `AUTHORIZATION_FAILED` |
| `PayURedirectResponse` | `"success"` | `PENDING_VBV` |
| `PayURedirectResponse` | other | `AUTHORIZATION_FAILED` |
| `PayURedirectErrorResponse` | — | `AUTHORIZATION_FAILED` |
| IntegrityV2 + status `"success"` + `"captured"` | — | `CHARGED` |
| IntegrityV2 + status `"pending"` + keepAsPending | — | `PENDING_VBV` |
| Decode fail | `Left err` | `PG_RESPONSE_DECODE_ERROR` |
| status == 0 | — | `INVALID_WEBHOOK_RESPONSE` |

#### Flow 24: `initiateSplitSettlement` — `Flow.hs:6485-6513`

**Purpose**: Initiate split settlement.

| Error | Result |
|-------|--------|
| `PayuSplitSettlementFailure` | `{ status = "FAILED", code = error_code, message = error_desc }` |
| `Left err` | `{ status = show err }` |
| `maybePgXML = Nothing` | `{ status = "FAILED", message = "PayuId Not Available" }` |

#### Flow 25: `delinkWallet` — `Flow.hs:6348-6355`

**Purpose**: Delink wallet instrument from LinkAndPay.

| Error | Result |
|-------|--------|
| `Left err` | `DirectWalletRespError { errorCode = inValidResponse, errorMessage = "Unknown" }` |

#### Flow 26: `getVpa` — `Flow.hs`

**Purpose**: Validate a UPI VPA.

| Step | Action | Details |
|------|--------|---------|
| 1 | GET `https://info.payu.in/payment-mode/v1/upi/vpa?upiNumber={vpa}` | Production only |
| 2 | Parse `PayuVpaGetResp` | `IsValid` field (VPAValidType: Int or String) |

#### Flow 27: `directDebit` — `Flow.hs:6312-6319`

**Purpose**: LinkAndPay direct debit.

| Error | Result |
|-------|--------|
| `Left err` | Log error, then `getHandleResponseUrl` (redirect fallback) |

#### Flow 28: `callTxnSync` — `Flow.hs`

**Purpose**: Force-sync transaction status with PayU.

| Step | Action | Details |
|------|--------|---------|
| 1 | Build `PayuVerifyPaymentRequest` | Use custom timeout from Redis |
| 2 | POST to PayU | `/merchant/postservice.php?form=2` |
| 3 | On 504/503/Socket timeout | `getResponseForSyncFailureCaseHandling` |

#### Flow 29: `initMandateMigrateRequest` — `Flow.hs:6249-6254`

**Purpose**: Migrate mandate to new token format.

| Response | Result |
|----------|--------|
| `MandateStatusCheckFailureResponse` | `AUTHORIZATION_FAILED` / `Mandate.FAILURE` |
| Unexpected response | `AUTHORIZATION_FAILED` / `Mandate.FAILURE` |

#### Flow 30: Refund ARN Sync — `Flow.hs:4971-5007`

**Purpose**: Sync refund ARN (bank reference) from PayU.

| Error | Result |
|-------|--------|
| `Left err` | `monitorRefundDecodeFailure "SYNC_REFUND_ARN_DECODE_FAILURE"` + `Nothing` ARN |

### 5.3 Data Transformations

| # | From | To | Function | File | Logic |
|---|------|----|----------|------|-------|
| 1 | `MandateFrequency` | PayU `billingCycle` + `billingInterval` | (inline) | `txns Transforms.hs:1196-1207` | Frequency → billing cycle/interval mapping |
| 2 | Payment method type + card type | PayU `pg` + `bankCode` | `getPgAndbankCode` | `Flow.hs` | Payment routing table |
| 3 | Internal app code | PayU UPI app name | (inline) | `txns Transforms.hs:1441-1449` | e.g. `"JP_PHONEPE"` → `"phonepe"` |
| 4 | `MandateAmountRule` | PayU amount rule | (inline) | `txns Transforms.hs:1163-1167` | `FIXED` → `"EXACT"`, `VARIABLE` → `"MAX"` |
| 5 | PayU card brand code | Internal brand name | (inline) | `gateway Transforms.hs:263-273` | e.g. `"MAST"` → `"MASTERCARD"` |
| 6 | `isExpired` string | Token status | (inline) | `gateway Transforms.hs:293-298` | `"0"/"false"` → `"ACTIVE"`, else `"INACTIVE"` |
| 7 | PayU UPI mode | Internal card type + isUPIAccount | (inline) | `Flow.hs:5923-5930` | `"UPICC"` → `"CREDIT_CARD"`, etc. |
| 8 | PayU status + unmappedstatus | `TxnStatus` | (dispatch) | `Flow.hs` | See Section 7 status mapping tables |
| 9 | PayU refund status | `RefundStatus` | (inline) | `RefundResponseHandler.hs` | Int/String → FAILURE/PENDING/SUCCESS |
| 10 | PayU mandate status string | `MandateStatus` | (inline) | `Flow.hs:5706-5717` | `"active"` → `ACTIVE`, etc. |

---

## 6. Error Handling

### 6.1 Error Type Hierarchy

PayU flows use the `EulerError` ADT with three primary variants:

| # | Variant | Sub-variants | Description |
|---|---------|-------------|-------------|
| 1 | `API httpError` | `HTTP_503`, `HTTP_504`, `HTTP_5XX`, others | HTTP-level errors from PayU |
| 2 | `Socket socketError` | `Operation timeoutError`, others | Network/socket-level errors |
| 3 | `Payload payload` | any decode/unexpected payload | Response parse/decode failures |

### 6.2 API Call Error Handling

#### Authorization / S2S / OTP Flows (`Flow.hs:1390-1394, 2881-2885, 4253-4257, 4272-4276, 4637-4641, 5610-5614, 5765-5769`)

| # | Error Type | Handling | Fallback / Result |
|---|-----------|----------|-------------------|
| 1 | `HTTP_504` | `throwUpstreamGatewayError "upstream gateway timeout"` | Upstream timeout exception propagated |
| 2 | `HTTP_503` | `throwUpstreamGatewayError "upstream gateway service unavailable"` | Upstream unavailable exception propagated |
| 3 | `HTTP_5XX` | Construct `PayURedirectErrorResponse` | Treated as redirect error, dispatched to response handler |
| 4 | Other HTTP error | `markAuthorizationFailedAndThrowError` or `logAndReturnError` | `AUTHORIZATION_FAILED` |
| 5 | `Socket (Operation timeoutError)` | `throwUpstreamGatewayError "upstream gateway timeout"` | Upstream timeout exception propagated |
| 6 | `Socket _` (other) | `logAndReturnError` or `defaultResendOTPResponse` | Logged / soft failure |
| 7 | `Payload _` | `markAuthorizationFailedAndThrowError` or `logAndReturnError` | `AUTHORIZATION_FAILED` |

#### Sync Errors (`Transforms.hs:3372-3376`)

| # | Error Type | Handling | Result |
|---|-----------|----------|--------|
| 1 | `HTTP_504` on sync | `updateGatewayTxnData' gatewayTxnData getResponseForSyncFailureCaseHandling` | `PayUErrorResponse { error_code = gatewayTxnSyncErrorCode, error_description = gatewayTxnSyncErrorMessage }` |
| 2 | `HTTP_503` on sync | same | same |
| 3 | `Socket (Operation timeout)` on sync | same | same |

#### Capture / Void Errors (`Flow.hs:1453, 1478`)

| # | Error | Handler | Error Code |
|---|-------|---------|------------|
| 1 | `Left err` on capture | `throwErr CAPTURE_PROCESSING_FAILED (customErrorResponse500 ...)` | `CAPTURE_PROCESSING_FAILED` |
| 2 | `Left err` on void | `throwErr VOID_PROCESSING_FAILED (customErrorResponse500 ...)` | `VOID_PROCESSING_FAILED` |

#### Decode Errors (`Flow.hs:3516, 3659, 4753, 4785, 4788-4798, 5985, 6014, 6021, 6110, 6139, 6146`)

| # | Context | Error | Handler | Error Code |
|---|---------|-------|---------|------------|
| 1 | Intent response | `Left err` | `defaultThrowECException INTENT_RESPONSE_DECODE_ERROR` | `INTENT_RESPONSE_DECODE_ERROR` |
| 2 | PGR decode | `Left error` | `defaultThrowECException PG_RESPONSE_DECODE_ERROR` | `PG_RESPONSE_DECODE_ERROR` |
| 3 | VCO/AuthZ decode | `Left err` | `AUTHORIZATION_FAILED` via `decodeFailureHandler` | — |
| 4 | Integrity webhook | `Left err` | `throwErr PG_RESPONSE_DECODE_ERROR` | `PG_RESPONSE_DECODE_ERROR` |
| 5 | Integrity sync status=0 | status == 0 | `throwErr INVALID_WEBHOOK_RESPONSE` | `INVALID_WEBHOOK_RESPONSE` |
| 6 | Invalid webhook type | wrong type | `throwErr INVALID_WEBHOOK_RESPONSE` | `INVALID_WEBHOOK_RESPONSE` |

#### OTP Errors

| # | Context | Error | Handler | Error Code |
|---|---------|-------|---------|------------|
| 1 | OTP submit | `HTTP_504`/`HTTP_503` | `throwUpstreamGatewayError` | — |
| 2 | OTP submit | other error | `defaultThrowECException SUBMIT_OTP_FAILED` | `SUBMIT_OTP_FAILED` |
| 3 | Resend OTP | `HTTP_504`/`HTTP_503`/Socket timeout | `throwUpstreamGatewayError` | — |
| 4 | Resend OTP | Other HTTP/Socket/Payload | `defaultResendOTPResponse` (soft failure) | — |

#### Refund Errors (`RefundResponseHandler.hs:125-248`)

| # | Error | Handler | Result |
|---|-------|---------|--------|
| 1 | `Left (Socket x)` | `(Timeout TSync, refund # errorMessage .~ "Gateway Timed Out")` | `PENDING` with timeout message |
| 2 | `Left err` (other) | `(DecodeFailed err, makePendingRefund refund)` | `PENDING` |
| 3 | `FailureRefundResponse "DB_EXCEPTION_ERROR_SLAVE"` | → PENDING | `PENDING` |
| 4 | `FailureRefundResponse "Requests limit reached"` | → PENDING | `PENDING` |
| 5 | `FailureRefundResponse "No Refunds Found"` | responseCode `"404"` | `REFUND_NOT_FOUND` |

#### Mandate Errors (`Flow.hs:5608-5614, 5763-5769`)

| # | Error | Handler | Result |
|---|-------|---------|--------|
| 1 | `HTTP_504`/`HTTP_503` on revoke | `verifyMandateStatusWithPG authPayuId` | Sync fallback |
| 2 | `Socket _` on revoke | `verifyMandateStatusWithPG authPayuId` | Sync fallback |
| 3 | `Payload _` on revoke | `mkMandateRevokeSuccessResponse (mandate ^. _status) (Just "GATEWAY_REVOKE_FAILED") (Just "Unknown response") Nothing` | Revoke marked failed |

#### Gateway-side Errors

| # | File | Error | Handler | Result |
|---|------|-------|---------|--------|
| 1 | `Settlements.hs:38-46` | `Left err` | `{ status = "ERROR", settlement_payload = errorMessage }` | ERROR status |
| 2 | `Settlements.hs:56-60` | `res.status /= "1"` | `{ status = "FAILURE", ... }` | FAILURE status |
| 3 | `Eligibility.hs:50,56` | `Left _` | `pure []` | Empty eligibility list |
| 4 | `GetCardDetails.hs:26,101-110` | `Left err` | `makeFailureGetGwCardsResponse err` via `Utils.handleClientError` | Failure response |
| 5 | `GetTokenDetails.hs:29-33` | `Left err` | `makeFailureGetGwCardsResponse errResp.errType errResp.errorMessage` | Failure response |
| 6 | `GetTokenDetails.hs:31-33` | Account decode error | `makeFailureGetGwCardsResponse "ACCOUNT_DETAILS_DECODE_ERROR"` | Failure response |
| 7 | `Emi.hs:82-87,137-142` | `Left err` | `Left (GatewayError { errorCode = "500", errorReason = show err })` | Gateway error |
| 8 | `Emi.hs:183` | DC EMI eligibility error | `pure []` | Empty list |
| 9 | `gateway Transforms.hs:58` | `getPayUAccountDetails` Left | `throwExceptionV2 MERCHANT_GATEWAY_ACCOUNT_DETAILS_DECODE_ERROR` | Exception thrown |

#### Notification Errors (`Flow.hs:5112-5122`)

| # | Error | Handler | Result |
|---|-------|---------|--------|
| 1 | `Left err` on pre-debit notification | `GatewayNotificationFailure { status = Notify.FAILURE, errorCode = "JP_801" }` | FAILURE with error code JP_801 |
| 2 | Response status not in `["success","1"]` | `markNotifyFailure` | Notification FAILURE |

#### Surcharge Errors (`Flow.hs:6466-6480, 4829-4841`)

| # | Error | Handler | Result |
|---|-------|---------|--------|
| 1 | `Left err` from surcharge API | `(False, Nothing)` | Surcharge check silently fails |
| 2 | `SurchargeErrResp` received | `(False, Just errResp)` | Treated as invalid surcharge |
| 3 | Surcharge amount mismatch | `JUSPAY_DECLINED` with `"SURCHARGE_VERIFICATION_FAILED"` | Transaction declined |

#### Split Settlement Errors (`Flow.hs:6485-6513`)

| # | Error | Handler | Result |
|---|-------|---------|--------|
| 1 | `PayuSplitSettlementFailure` | `{ status = "FAILED", code = error_code, message = error_desc }` | FAILED with code |
| 2 | `Left err` | `{ status = show err, code = Nothing, message = show err }` | Error string |
| 3 | `maybePgXML = Nothing` | `{ status = "FAILED", message = "PayuId Not Available" }` | FAILED |

#### 3DS Authentication Errors (`Flow.hs:5796-5821`)

| # | Error | Handler | Result |
|---|-------|---------|--------|
| 1 | `Left err` (HTTP/decode) | `Left (makePaymentGatewayInfo "Something went wrong" "Invalid Response" ...)` | Gateway info error |
| 2 | `referenceId` missing | `Left (makePaymentGatewayInfo "Something went wrong" "Mandatory params missing" ...)` | Gateway info error |
| 3 | `gatewayAuthReqParams` missing | `Left (makePaymentGatewayInfo ...)` | Gateway info error |
| 4 | `ErrorAuthNParamsResponse` | `Left PaymentGatewayInfo` | Gateway info error |

#### Authentication Webhook Extraction Errors (`Flow.hs:5851-5895`)

| # | Error | Handler | Result |
|---|-------|---------|--------|
| 1 | `Left err` on decode | Returns `{ identifierValue = Nothing, authenticationParams = Nothing, errorDetails = Just { errorCode = "Decode Failure", errorMsg = "UnExpected Payload Received From PAYU" } }` | Decode failure response |

#### Mandate Migration Errors (`Flow.hs:6249-6254`)

| # | Error | Handler | Result |
|---|-------|---------|--------|
| 1 | `MandateStatusCheckFailureResponse` | → `AUTHORIZATION_FAILED` / `Mandate.FAILURE` | Both txn and mandate marked failed |
| 2 | Unexpected response | → `AUTHORIZATION_FAILED` / `Mandate.FAILURE` | Both txn and mandate marked failed |

#### Mandate Token Update Errors (`Flow.hs:5381-5408`)

| # | Error | Handler | Result |
|---|-------|---------|--------|
| 1 | Gateway params decode error | Logged + `FAIL` status | FAIL |
| 2 | `Left err` from API | `FAIL` with `err.errorMessage` | FAIL |

#### Push Pay / UPI Collect Errors (`Flow.hs:4864-4944`)

| # | Error | Handler | Result |
|---|-------|---------|--------|
| 1 | `ErrorResponse` received | → `AUTHENTICATION_FAILED` | Auth failed |
| 2 | Collect success + result pending | No change (pending) | PENDING |
| 3 | Collect success + other result | `AUTHORIZATION_FAILED` | Auth failed |
| 4 | Collect decode fail | `AUTHORIZATION_FAILED` | Auth failed |
| 5 | `Left err` | `isPgStatusUnknown = True` | Treat as pending |
| 6 | Unexpected response type | `PENDING_VBV` | VBV pending |

#### Direct Debit Errors (`Flow.hs:6312-6319`)

| # | Error | Handler | Result |
|---|-------|---------|--------|
| 1 | `Left err` | Log error, then `getHandleResponseUrl` | Redirect fallback |

#### Delink Wallet Errors (`Flow.hs:6348-6355`)

| # | Error | Handler | Result |
|---|-------|---------|--------|
| 1 | `Left err` | `DirectWalletRespError { errorCode = inValidResponse, errorMessage = "Unknown" }` | Error response |

### 6.3 HTTP Status Code Handling

| HTTP Status | Handling | Response to Caller |
|-------------|----------|--------------------|
| 200 | Success path — parse response body, dispatch on `PayUPaymentResponse` type | Parsed response mapped to `TxnStatus` |
| 302 | Redirect response — treat as `PayURedirectResponse` or `PayURedirectErrorResponse` | Redirect URL or error status |
| 503 | `throwUpstreamGatewayError "upstream gateway service unavailable"` | Upstream unavailable exception |
| 504 | `throwUpstreamGatewayError "upstream gateway timeout"` | Upstream timeout exception |
| 5XX (other) | Construct `PayURedirectErrorResponse` | Treated as redirect error |
| Other 4XX | `markAuthorizationFailedAndThrowError` or `logAndReturnError` | `AUTHORIZATION_FAILED` |
| Connection Failure | `Socket (Operation timeoutError)` → `throwUpstreamGatewayError` | Upstream timeout exception |

### 6.4 Timeout and Retry

- **Timeout Mechanism**: HTTP client timeout set via `X-Euler-CustomTimeout` header
- **Default Timeout**: 45,000 ms (standard requests)
- **Force-sync Timeout**: from Redis key `customTimeoutForForceSync "PAYU"` or `defaultPayuForceSyncTimeoutInMS`
- **Retry Enabled**: No — no retry logic is configured
- **Max Retries**: 0
- **Retry Strategy**: N/A

### 6.5 Error Code Reference

| # | Error Code | Context | File |
|---|-----------|---------|------|
| 1 | `CAPTURE_PROCESSING_FAILED` | Capture `Left err` | `Flow.hs:1453` |
| 2 | `VOID_PROCESSING_FAILED` | Void `Left err` | `Flow.hs:1478` |
| 3 | `SUBMIT_OTP_FAILED` | OTP submit non-5XX error | `Flow.hs:~4282` |
| 4 | `INTENT_RESPONSE_DECODE_ERROR` | Intent response decode fail | `Flow.hs:3516` |
| 5 | `PG_RESPONSE_DECODE_ERROR` | PGR/integrity webhook/sync decode fail | `Flow.hs:3659, 5985, 6014, 6110, 6139` |
| 6 | `INVALID_WEBHOOK_RESPONSE` | Integrity sync status=0 / invalid webhook type | `Flow.hs:6021, 6146` |
| 7 | `MERCHANT_GATEWAY_ACCOUNT_DETAILS_DECODE_ERROR` | Account details decode fail | `gateway Transforms.hs:58` |
| 8 | `JP_801` | Pre-debit notification `Left err` | `Flow.hs:5112-5122` |
| 9 | `SURCHARGE_VERIFICATION_FAILED` | Surcharge amount mismatch | `Flow.hs:4829-4841` |
| 10 | `ACCOUNT_DETAILS_DECODE_ERROR` | Token details account decode fail | `GetTokenDetails.hs:31-33` |

---

## 7. Status Mappings

### 7.1 TxnStatus — `EC/TxnDetail/Types.hs:285-311`

**Project**: euler-api-txns
**Encoding**: `defaultEnumEncode` / `defaultEnumDecode` — constructor name equals JSON wire value.

| # | Constructor | JSON Wire Value | Description |
|---|-------------|----------------|-------------|
| 1 | `STARTED` | `"STARTED"` | Transaction initiated |
| 2 | `AUTHENTICATION_FAILED` | `"AUTHENTICATION_FAILED"` | Authentication step failed |
| 3 | `JUSPAY_DECLINED` | `"JUSPAY_DECLINED"` | Declined by Juspay (e.g. surcharge mismatch) |
| 4 | `PENDING_VBV` | `"PENDING_VBV"` | Pending 3DS/VBV authentication |
| 5 | `VBV_SUCCESSFUL` | `"VBV_SUCCESSFUL"` | 3DS/VBV authentication succeeded |
| 6 | `AUTHORIZED` | `"AUTHORIZED"` | Pre-authorized (not yet captured) |
| 7 | `AUTHORIZATION_FAILED` | `"AUTHORIZATION_FAILED"` | Authorization step failed |
| 8 | `CHARGED` | `"CHARGED"` | Payment captured/charged |
| 9 | `AUTHORIZING` | `"AUTHORIZING"` | Asynchronous authorization in progress (e.g. EMANDATE_REGISTER pending) |
| 10 | `COD_INITIATED` | `"COD_INITIATED"` | Cash on delivery initiated |
| 11 | `VOIDED` | `"VOIDED"` | Pre-authorization voided |
| 12 | `VOID_INITIATED` | `"VOID_INITIATED"` | Void initiated but not confirmed |
| 13 | `NOP` | `"NOP"` | No operation |
| 14 | `CAPTURE_INITIATED` | `"CAPTURE_INITIATED"` | Capture initiated but not confirmed |
| 15 | `CAPTURE_FAILED` | `"CAPTURE_FAILED"` | Capture attempt failed |
| 16 | `VOID_FAILED` | `"VOID_FAILED"` | Void attempt failed |
| 17 | `AUTO_REFUNDED` | `"AUTO_REFUNDED"` | Auto-refunded |
| 18 | `PARTIAL_CHARGED` | `"PARTIAL_CHARGED"` | Partially charged |
| 19 | `PENDING` | `"PENDING"` | Pending (generic) |
| 20 | `FAILURE` | `"FAILURE"` | Generic failure |
| 21 | `TO_BE_CHARGED` | `"TO_BE_CHARGED"` | Scheduled for charge |
| 22 | `MERCHANT_VOIDED` | `"MERCHANT_VOIDED"` | Voided by merchant |
| 23 | `AUTO_VOIDED` | `"AUTO_VOIDED"` | Auto-voided |
| 24 | `COMPLETED` | `"COMPLETED"` | Completed |

### 7.2 RefundStatus — `EC/Refund/Types.hs:85-91`

**Project**: euler-api-txns

| # | Constructor | JSON Wire Value | Description |
|---|-------------|----------------|-------------|
| 1 | `FAILURE` | `"FAILURE"` | Refund failed |
| 2 | `MANUAL_REVIEW` | `"MANUAL_REVIEW"` | Requires manual review |
| 3 | `PENDING` | `"PENDING"` | Refund pending |
| 4 | `SUCCESS` | `"SUCCESS"` | Refund successful |

### 7.3 RefundSubStatus — `EC/Refund/Types.hs:99-110`

**Project**: euler-api-txns

| # | Constructor | JSON Wire Value | Description |
|---|-------------|----------------|-------------|
| 1 | `JUSPAY_ACCEPTED` | `"JUSPAY_ACCEPTED"` | Accepted by Juspay |
| 2 | `JUSPAY_PROCESSING` | `"JUSPAY_PROCESSING"` | Being processed by Juspay |
| 3 | `PG_PROCESSED` | `"PG_PROCESSED"` | Processed by payment gateway |
| 4 | `PG_PROCESSING` | `"PG_PROCESSING"` | Being processed by PG |
| 5 | `PG_DECLINED` | `"PG_DECLINED"` | Declined by PG |
| 6 | `BANK_PROCESSED` | `"BANK_PROCESSED"` | Processed by bank |
| 7 | `BANK_PROCESSING` | `"BANK_PROCESSING"` | Being processed by bank |
| 8 | `BANK_DECLINED` | `"BANK_DECLINED"` | Declined by bank |
| 9 | `SYNC_INITIATED` | `"SYNC_INITIATED"` | Sync initiated |

### 7.4 MandateStatus — `EC/Mandate/Types.hs:332-344`

**Project**: euler-api-txns

| # | Constructor | JSON Wire Value | Description |
|---|-------------|----------------|-------------|
| 1 | `CREATED` | `"CREATED"` | Mandate created |
| 2 | `ACTIVE` | `"ACTIVE"` | Mandate active |
| 3 | `PAUSED` | `"PAUSED"` | Mandate paused |
| 4 | `REVOKED` | `"REVOKED"` | Mandate revoked |
| 5 | `FAILURE` | `"FAILURE"` | Mandate failed |
| 6 | `PENDING` | `"PENDING"` | Mandate pending |
| 7 | `EXPIRED` | `"EXPIRED"` | Mandate expired |
| 8 | `UPDATE_PENDING` | `"UPDATE_PENDING"` | Update pending |
| 9 | `REVOKE_PENDING` | `"REVOKE_PENDING"` | Revoke pending |
| 10 | `PAUSE_PENDING` | `"PAUSE_PENDING"` | Pause pending |

### 7.5 RefundSyncStatus — `Gateway/Payu/Types.hs:2174-2181`

**Project**: euler-api-txns

| # | Constructor | JSON Wire Value | Description |
|---|-------------|----------------|-------------|
| 1 | `REFUND_FAILURE` | `"REFUND_FAILURE"` | All refunds failed |
| 2 | `REFUND_SUCCESS` | `"REFUND_SUCCESS"` | All refunds successful |
| 3 | `REFUND_PENDING` | `"REFUND_PENDING"` | All refunds pending |
| 4 | `REFUND_NOT_FOUND` | `"REFUND_NOT_FOUND"` | Refund not found at PayU |
| 5 | `REFUND_MANUAL_REVIEW` | `"REFUND_MANUAL_REVIEW"` | Mixed success/failure — needs review |

### 7.6 PayuRefundStatusType — `Gateway/Payu/Types.hs:829-833`

**Project**: euler-api-txns
**Note**: PayU returns refund status as either an integer or a string. `FromJSON` tries Int first, then Text.

| # | Constructor | Wire Format | Description |
|---|-------------|------------|-------------|
| 1 | `StatusIntType Int` | JSON integer | Integer status code from PayU |
| 2 | `StatusStringType Text` | JSON string | String status value from PayU |

### 7.7 PayuNotificationStatus — `Gateway/Payu/Types.hs:1733-1734`

**Project**: euler-api-txns
**Note**: PayU notification status can be integer or string.
**Conversion**: `valueToText`: `IntegerStatus x → show x; TextStatus y → y` (`Flow.hs:5425-5428`)

| # | Constructor | Wire Format |
|---|-------------|------------|
| 1 | `IntegerStatus Int` | JSON integer |
| 2 | `TextStatus Text` | JSON string |

### 7.8 VPAValidType — `Gateway/Payu/Types.hs:1491-1494`

**Project**: euler-api-txns
**Note**: VPA validation result can be integer or string from PayU.

| # | Constructor | Wire Format |
|---|-------------|------------|
| 1 | `IntType Int` | JSON integer |
| 2 | `StringType Text` | JSON string |

### 7.9 NotificationStatus (Notify module)

**Project**: euler-api-txns

| # | Constructor | JSON Wire Value |
|---|-------------|----------------|
| 1 | `SUCCESS` | `"SUCCESS"` |
| 2 | `PENDING` | `"PENDING"` |
| 3 | `FAILURE` | `"FAILURE"` |

---

### 7.10 PayU Response → TxnStatus Mapping Tables

#### PayuSyncSuccessResponse / PayURedirectResponse → TxnStatus (`Flow.hs`)

| # | PayU `status` | PayU `unmappedstatus` | Condition | TxnStatus |
|---|---|---|---|---|
| 1 | `"success"` | `"auth"` | `isPreAuth = true` | `AUTHORIZED` |
| 2 | `"success"` | `"captured"` | — | `CHARGED` |
| 3 | `"success"` | `"cancelled"` | `isPreAuth = true` + previously authorized | `VOIDED` |
| 4 | `"success"` | other | — | Check authZ mapping |
| 5 | `"pending"` | — | EMANDATE_REGISTER flow | `AUTHORIZING` |
| 6 | `"pending"` | — | `keepPayuTransactionsAsPending = true` | `PENDING_VBV` |
| 7 | `"failure"` / `"error"` | — | `isAuthFailure` check passes | `AUTHENTICATION_FAILED` |
| 8 | `"failure"` / `"error"` | — | `decideAuthFailFromMapping` | `AUTHORIZATION_FAILED` |

#### PayURedirectErrorResponse → TxnStatus (`Flow.hs`)

| # | `error_code` | TxnStatus |
|---|---|---|
| 1 | `"VERIFICATION_FAILED"` | `PENDING_VBV` |
| 2 | `"THREE_DS_2_OTP_CHALLENGE_FAILED"` | `AUTHENTICATION_FAILED` |
| 3 | `"PAYU_SERVER_ERROR"` | Keep existing txn status |
| 4 | other | `AUTHENTICATION_FAILED` |

#### PayuSyncErrorResponse → TxnStatus
Always: `AUTHORIZATION_FAILED`

#### OtpSubmitResp → TxnStatus (`Flow.hs`)

| # | `result.status` | Condition | TxnStatus |
|---|---|---|---|
| 1 | `"success"` | — | `CHARGED` |
| 2 | other | Auth failure check | `AUTHENTICATION_FAILED` |
| 3 | other | Otherwise | `AUTHORIZATION_FAILED` |

#### OtpSubmitRespV4 → TxnStatus (`Flow.hs`)

| # | `status` | Condition | TxnStatus |
|---|---|---|---|
| 1 | `"success"` | — | `CHARGED` |
| 2 | other | Auth failure | `AUTHENTICATION_FAILED` |
| 3 | other | Otherwise | `PENDING_VBV` |

#### OtpErrorResponse → TxnStatus (`Flow.hs`)

| # | `message` | TxnStatus |
|---|---|---|
| 1 | `"VERIFICATION_FAILED"` | `PENDING_VBV` |
| 2 | other | `AUTHENTICATION_FAILED` |

#### PayuAuthZOnlyResp → TxnStatus (VCO, `Flow.hs`)

| # | `unmappedstatus` | Condition | TxnStatus |
|---|---|---|---|
| 1 | `"captured"` | — | `CHARGED` |
| 2 | `"auth"` | `isPreAuth = true` | `AUTHORIZED` |
| 3 | `"auth"` | otherwise | Check authZ mapping |
| 4 | `"cancelled"` | `isPreAuth = true` + previously authorized | `VOIDED` |
| 5 | `"cancelled"` | otherwise | Check authZ mapping |

#### VCO GetAuthRespStatus → TxnStatus (`Flow.hs:4814-4819`)

| # | PayU `status` | TxnStatus |
|---|---|---|
| 1 | `"SUCCESS"` (case-insensitive) | `CHARGED` |
| 2 | Anything else | `AUTHORIZATION_FAILED` |

#### Push Pay / UPI Collect → TxnStatus (`Flow.hs:4864-4944`)

| # | Response | Condition | TxnStatus |
|---|---|---|---|
| 1 | `ErrorResponse` | — | `AUTHENTICATION_FAILED` |
| 2 | `Payus2sUpiCollectValidResp` + success + result pending | — | No change (PENDING) |
| 3 | `Payus2sUpiCollectValidResp` + success + other result | — | `AUTHORIZATION_FAILED` |
| 4 | `Payus2sUpiCollectValidResp` + decode fail | — | `AUTHORIZATION_FAILED` |
| 5 | `Left err` | — | `isPgStatusUnknown = True` (treat as pending) |
| 6 | Unexpected type | — | `PENDING_VBV` |

#### Integrity Framework → TxnStatus (`Flow.hs:6162-6178`)

| # | PayU `status` | `unmappedstatus` | Condition | TxnStatus |
|---|---|---|---|---|
| 1 | `"success"` | `"captured"` | — | `CHARGED` |
| 2 | `"success"` | `"auth"` | `isPreAuth = true` | `AUTHORIZED` |
| 3 | `"pending"` | — | UPI + payuPureS2S | `PENDING_VBV` |
| 4 | `"pending"` | — | `keepPayuTransactionsAsPending = true` | `PENDING_VBV` |
| 5 | other | — | — | Keep existing txn status |

#### IntegrityV2 Redirect → TxnStatus (`Flow.hs:6092-6104`)

| # | Response | PayU `status` | TxnStatus |
|---|---|---|---|
| 1 | `PayuSyncSuccessResponse` | `"success"` | `PENDING_VBV` (trigger mandatory sync) |
| 2 | `PayuSyncSuccessResponse` | other | `AUTHORIZATION_FAILED` |
| 3 | `PayURedirectResponse` | `"success"` | `PENDING_VBV` |
| 4 | `PayURedirectResponse` | other | `AUTHORIZATION_FAILED` |
| 5 | `PayURedirectErrorResponse` | — | `AUTHORIZATION_FAILED` |
| 6 | other | — | `PENDING_VBV` |

### 7.11 Refund Status Mapping (`RefundResponseHandler.hs`)

| # | PayU Value | RefundStatus |
|---|---|---|
| 1 | `StatusIntType 0` | `FAILURE` |
| 2 | `StatusIntType n` (n ≠ 0) | `PENDING` |
| 3 | `StatusStringType _` | `PENDING` |
| 4 | PayuIdDetails status `"failure"` / `"failed"` | `FAILURE` |
| 5 | PayuIdDetails status `"success"` | `SUCCESS` |
| 6 | PayuIdDetails status `"od_hit"` | `PENDING` |
| 7 | PayuIdDetails status other | `PENDING` |

#### RefundSyncStatus Aggregation

| # | Combination | RefundSyncStatus |
|---|---|---|
| 1 | All refunds success | `REFUND_SUCCESS` |
| 2 | All refunds failure | `REFUND_FAILURE` |
| 3 | All refunds pending | `REFUND_PENDING` |
| 4 | Mixed failure + success | `REFUND_MANUAL_REVIEW` |
| 5 | Mixed other | `REFUND_PENDING` |
| 6 | Not found | `REFUND_NOT_FOUND` |

### 7.12 Mandate Status Mapping (`Flow.hs:5706-5717`)

| # | PayU Mandate Status String | MandateStatus |
|---|---|---|
| 1 | `"active"` | `ACTIVE` |
| 2 | `"revoked"`, `"revoke"`, `"discarded"`, `"cancelled"`, `"cancel"`, `"0"` | `REVOKED` |
| 3 | `"pause"`, `"paused"` | `PAUSED` |
| 4 | `"completed"` | `EXPIRED` |
| 5 | Anything else | Keep existing status |

#### Mandate Revoke Decision (`Flow.hs:5648-5651, 5771-5775`)

| # | Condition | MandateStatus |
|---|---|---|
| 1 | `status == 1 && action == "MANDATE_REVOKE"` | `REVOKED` |
| 2 | `message == "Mandate already revoked"` | `REVOKED` |
| 3 | Otherwise | Keep previous status |

### 7.13 Notification Status Mapping (`Flow.hs:5107, 5135-5139, 5449`)

| # | PayU Value | Context | NotificationStatus |
|---|---|---|---|
| 1 | `"success"` or `"1"` | Pre-debit response | `SUCCESS` |
| 2 | `approvedStatus = Just "pending"` | Notify status | `PENDING` |
| 3 | Anything else for `approvedStatus` | Notify status | `SUCCESS` |
| 4 | `"1"` | Notification response | `SUCCESS` |
| 5 | other | Notification response | `FAILURE` |

### 7.14 Mandate Token Update Status (`Flow.hs:5398-5407`)

| # | Condition | UpdationStatus |
|---|---|---|
| 1 | `res.status == 1` | `SUCCESS` |
| 2 | `res.message == "Already PMU Updated"` | `SUCCESS` |
| 3 | Otherwise | `FAIL` |
| 4 | `Left err` from API | `FAIL` with `err.errorMessage` |
| 5 | Decode error | `FAIL` with decode error message |

---

## 8. Payment Methods

### 8.1 Payment Method Routing (`getPgAndbankCode` — `Flow.hs`)

Maps internal payment method type + card type to PayU `pg` (payment gateway code) and `bankCode`:

| # | `payment_method_type` | Card Type / Method | PayU `pg` | PayU `bankCode` | Notes |
|---|---|---|---|---|---|
| 1 | `WALLET` / `GOOGLEPAY` | — | `UPI` | `TEZ` or `INTENT` | GPay via UPI |
| 2 | `WALLET` / `LAZYPAY` | — | `BNPL` | `LAZYPAY` | BNPL via LazyPay |
| 3 | `NB` | — | `NB` | (bank-specific code) | Net banking |
| 4 | `NB` (emandate) | — | `ENACH` | (bank code) | E-mandate net banking |
| 5 | `UPI` | — | `UPI` | (UPI app/bank code) | UPI collect/pay |
| 6 | `CARD` | `AMEX` | `AMEX` | — | American Express |
| 7 | `CARD` | `DINERS` | `DINR` | — | Diners Club |
| 8 | `CARD` | `MAESTRO` | `MAES` | — | Maestro debit |
| 9 | `CARD` | `MASTERCARD` debit | `MAST` | — | Mastercard debit |
| 10 | `CARD` | `MASTERCARD` credit | `CC` | — | Mastercard credit |
| 11 | `CARD` | `VISA` debit | `DC` | — | Visa debit |
| 12 | `CARD` | `VISA` credit | `CC` | — | Visa credit |
| 13 | `CARD` | `RUPAY` debit | `RUPAY` | — | RuPay debit |
| 14 | `CARD` | `RUPAY` credit | `RUPAYCC` | — | RuPay credit |

### 8.2 Payment Method Code for Surcharge (`getPaymentMethodCode` — `Transforms.hs:3266-3283`)

Maps payment method to PayU surcharge API code:

| # | `PaymentMethodType` | Card Type | PayU Surcharge Code |
|---|---|---|---|
| 1 | `NB` | — | `"NB"` |
| 2 | `WALLET` | — | `"CASH"` |
| 3 | `UPI` | — | `"UPI"` |
| 4 | `CARD` | AMEX | `"AMEX"` |
| 5 | `CARD` | DINERS | `"DINR"` |
| 6 | `CARD` | RUPAY + CREDIT | `"RUPAYCC"` |
| 7 | `CARD` | RUPAY | `"RUPAY"` |
| 8 | `CARD` | VISA + CREDIT | `"CC"` |
| 9 | `CARD` | VISA | `"VISA"` |
| 10 | `CARD` | MASTERCARD + CREDIT | `"CC"` |
| 11 | `CARD` | MASTERCARD | `"MAST"` |
| 12 | `CARD` | other + CREDIT | `"CC"` |
| 13 | `CARD` | other | `"DC"` |
| 14 | other / Nothing | — | `"CASH"` |

### 8.3 UPI App Name Mapping (`Transforms.hs:1441-1449`)

Maps internal app codes to PayU UPI app names for intent flow:

| # | Internal App Code | PayU Value |
|---|---|---|
| 1 | `"JP_PHONEPE"` | `"phonepe"` |
| 2 | `"JP_GOOGLEPAY"` | `"googlepay"` |
| 3 | `"JP_BHIM"` | `"bhim"` |
| 4 | `"JP_PAYTM"` | `"paytm"` |
| 5 | `"JP_CRED"` | `"cred"` |
| 6 | `"JP_AMAZONPAY"` | `"amazonpay"` |
| 7 | `"JP_WHATSAPP"` | `"whatsapp"` |
| 8 | other | `"genericintent"` |

### 8.4 UPI Mode → Card Type Mapping (`Flow.hs:5923-5930`)

PayU UPI mode in response determines internal card type classification:

| # | PayU UPI Mode | Internal Card Type | Is UPI Account? |
|---|---|---|---|
| 1 | `"UPICC"` | `"CREDIT_CARD"` | No |
| 2 | `"UPIPPI"` | `"PREPAID_INSTRUMENT"` | No |
| 3 | `"UPICL"` | `"CREDIT_LINE"` | No |
| 4 | `"UPI"` | Nothing | Yes |
| 5 | other | Nothing | No |

### 8.5 Mandate Frequency → PayU Billing Cycle (`Transforms.hs:1196-1207`)

| # | `MandateFrequency` | PayU `billingCycle` | PayU `billingInterval` |
|---|---|---|---|
| 1 | `ONETIME` | Nothing | Nothing |
| 2 | `DAILY` | `"DAILY"` | `"1"` |
| 3 | `WEEKLY` | `"WEEKLY"` | `"1"` |
| 4 | `BIMONTHLY` | `"MONTHLY"` | `"2"` |
| 5 | `MONTHLY` | `"MONTHLY"` | `"1"` |
| 6 | `QUARTERLY` | `"MONTHLY"` | `"3"` |
| 7 | `HALFYEARLY` | `"MONTHLY"` | `"6"` |
| 8 | `YEARLY` | `"YEARLY"` | `"1"` |
| 9 | `ASPRESENTED` | `"ADHOC"` | `"1"` |
| 10 | `FORTNIGHTLY` | `"WEEKLY"` | `"2"` |
| 11 | `Nothing` | `"ADHOC"` | `"1"` |

### 8.6 Mandate Amount Rule Mapping (`Transforms.hs:1163-1167`)

| # | Internal Rule | PayU Value |
|---|---|---|
| 1 | `FIXED` | `"EXACT"` |
| 2 | `VARIABLE` | `"MAX"` |
| 3 | other | Nothing |

### 8.7 Card Brand Mapping — PayU → Internal (`gateway Transforms.hs:263-273`)

| # | PayU Value | Internal Brand |
|---|---|---|
| 1 | `"VISA"` | `"VISA"` |
| 2 | `"MAST"` | `"MASTERCARD"` |
| 3 | `"RUPAY"` | `"RUPAY"` |
| 4 | `"RUPAYCC"` | `"RUPAY"` |
| 5 | `"MAES"` | `"MAESTRO"` |
| 6 | `"SMAE"` | `"MAESTRO"` |
| 7 | `"AMEX"` | `"AMEX"` |
| 8 | `"DINR"` | `"DINERS"` |
| 9 | other / Nothing | `""` |

### 8.8 Token Status Mapping (`gateway Transforms.hs:293-298`)

| # | `isExpired` Value | Token Status |
|---|---|---|
| 1 | `"0"` or `"false"` (case-insensitive) | `"ACTIVE"` |
| 2 | otherwise | `"INACTIVE"` |

### 8.9 Payment Method Fields in Requests / Responses

**In payment requests** (`PayuTransactionRequest`):

| # | Field | JSON Key | Type | Description |
|---|-------|----------|------|-------------|
| 1 | `pg` | `pg` | Maybe Text | PayU payment gateway code (e.g. `"CC"`, `"NB"`, `"UPI"`, `"BNPL"`) |
| 2 | `bankcode` | `bankcode` | Maybe Text | Bank/instrument code (e.g. `"LAZYPAY"`, `"TEZ"`, `"HDFC"`) |
| 3 | `paymentSubType` | `paymentSubType` | Maybe Text | Payment sub-type (e.g. UPI intent type) |

**In payment responses** (`PayUResponseReq`):

| # | Field | JSON Key | Type | Description |
|---|-------|----------|------|-------------|
| 1 | `mode` | `mode` | Maybe Text | Payment mode used |
| 2 | `pg_type` | `pg_type` | Maybe Text | PG type |
| 3 | `bankcode` | `bankcode` | Maybe Text | Bank code used |
| 4 | `cardCategory` | `cardCategory` | Maybe Text | Card category |
| 5 | `paymentSubType` | `paymentSubType` | Maybe Text | Payment sub-type |

---

## 9. Completeness Verification

| Check | Result |
|-------|--------|
| Base URLs documented (gateway-side) | 4 environments (sandbox/prod × standard/LinkAndPay) |
| Base URLs documented (txns-side) | 24+ request-type-specific URLs |
| Authentication documented | Yes — HMAC-SHA512, 5 hash formulas, 14 credential fields, 8 header variants |
| Request types documented | 19 txns-side + 7 gateway-side = 26 total |
| Response types documented | 30+ types across txns and gateway |
| All flows documented | Yes — 5 gateway flows + 30 txns flows = 35 total |
| All error paths documented | Yes — 22 distinct error contexts |
| All status types listed | Yes — TxnStatus (24), RefundStatus (4), RefundSubStatus (9), MandateStatus (10), RefundSyncStatus (5), PayuRefundStatusType (2), VPAValidType (2), NotificationStatus (3) |
| All status mappings documented | Yes — 14 mapping tables |
| Payment method routing documented | Yes — 14 routes |
| UPI app mappings documented | Yes — 8 mappings |
| Mandate frequency mappings documented | Yes — 11 mappings |
| Card brand mappings documented | Yes — 9 mappings |
| Surcharge code mappings documented | Yes — 14 mappings |
| All enum values listed | Yes |
| All nested types expanded | Yes |
| File:line references | Yes — all major types and functions |
| Missing items | None identified |

---

## 10. Source File References

| # | File | Lines Read | Purpose |
|---|------|-----------|---------|
| 1 | `euler-api-txns/euler-x/src-generated/Gateway/Payu/Flow.hs` | 1–6520 (full) | All txns-side flows, error handling, status mapping, payment routing |
| 2 | `euler-api-txns/euler-x/src-generated/Gateway/Payu/Transforms.hs` | 1–3657 (full) | Hash computation, request building, data transformations |
| 3 | `euler-api-txns/euler-x/src-generated/Gateway/Payu/Types.hs` | Key sections (4542 total) | All request/response types, enums, ADTs |
| 4 | `euler-api-txns/euler-x/src-generated/Gateway/Payu/RefundResponseHandler.hs` | 1–409 (full) | Refund response processing and status mapping |
| 5 | `euler-api-txns/euler-x/src-generated/Gateway/Payu/Endpoints.hs` | 1–71 (full) | Per-request-type endpoint URL mapping |
| 6 | `euler-api-txns/dbTypes/src-generated/EC/TxnDetail/Types.hs` | TxnStatus section | TxnStatus enum (24 constructors) |
| 7 | `euler-api-txns/dbTypes/src-generated/EC/Refund/Types.hs` | 85–110 | RefundStatus (4) and RefundSubStatus (9) enums |
| 8 | `euler-api-txns/dbTypes/src-generated/EC/Mandate/Types.hs` | 332–344 | MandateStatus enum (10 constructors) |
| 9 | `euler-api-txns/dbTypes/src-generated/EC/MerchantGatewayAccount/Types.hs` | 524 | PayuDetails type (14 fields) |
| 10 | `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/PayU/Routes.hs` | 50–61 | Gateway-side base URL resolution |
| 11 | `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/PayU/Transforms.hs` | 1–298 (full) | Gateway hash computation, card brand mapping, token status |
| 12 | `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/PayU/Types.hs` | 1–954 (full) | Gateway-side request/response types |
| 13 | `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/PayU/Flows/Eligibility.hs` | Full | Eligibility flow, error handling |
| 14 | `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/PayU/Flows/Emi.hs` | Full | EMI plans flow, DC EMI eligibility |
| 15 | `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/PayU/Flows/GetCardDetails.hs` | Full | Card details flow, error handling |
| 16 | `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/PayU/Flows/GetTokenDetails.hs` | Full | Token details flow, error handling |
| 17 | `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/PayU/Flows/Settlements.hs` | 1–61 (full) | Settlement flow, error handling |

---

**Generated by**: Euler Connector Tech Spec Workflow
**Date**: 2026-03-26
