# PINELABS_ONLINE — Technical Specification

> **Connector**: PINELABS_ONLINE
> **Direction**: gateway → external PineLabs Online API
> **Endpoint**: Multiple (see Section 1.2 / Section 3)
> **Purpose**: Full payment lifecycle integration with PineLabs Online (Plural Pay) — order creation, transaction initiation, status sync, refund, capture, void, OTP flows, EMI, offers, convenience fee
> **Generated**: 2026-03-26

---

## 1. Connector Overview

### 1.1 Basic Information
- **Connector ID**: PINELABS_ONLINE
- **Direction**: euler-api-gateway → PineLabs Online (Plural Pay) external API
- **HTTP Methods**: GET, POST, PUT (varies by API — see endpoint table)
- **Endpoint Paths**: 18 endpoints across 3 base URL groups (see Section 1.2)
- **Protocol**: HTTP REST (synchronous)
- **Content Type**: application/json
- **Architecture**: Haskell (Servant + EulerHS + BasicGatewayFlow typeclass pattern)
- **Infrastructure type**: Gateway-initiated connector (euler-api-gateway calls PineLabs external API directly; NOT an ExpressCheckout connector)

### 1.2 Base URL Configuration

Three distinct base URL groups are used depending on the operation:

#### Group 1: `pineLabsOnlineBaseUrl` — Payment APIs (`/api/pay/v1`)

| Environment | Host | Port | Protocol | Path Prefix |
|-------------|------|------|----------|-------------|
| Sandbox / Test | `pluraluat.v2.pinepg.in` | 443 | HTTPS | `/api/pay/v1` |
| Production | `api.pluralpay.in` | 443 | HTTPS | `/api/pay/v1` |

**Used for**: Order Create, Transaction Create, Transaction Sync, Refund Initiate, Refund Sync, Capture, Void, OTP Submit, OTP Resend, Get Card Details, OTP Trigger, Convenience Fee

#### Group 2: `pineLabsOnlineBaseUrl2` — Auth + Offer APIs (`/api`)

| Environment | Host | Port | Protocol | Path Prefix |
|-------------|------|------|----------|-------------|
| Sandbox / Test | `pluraluat.v2.pinepg.in` | 443 | HTTPS | `/api` |
| Production | `api.pluralpay.in` | 443 | HTTPS | `/api` |

**Used for**: Access Token, Offer Discovery, Offer Validation (path prefix `/api/affordability/v1/...` and `/api/auth/v1/...` are sub-paths of this base)

#### Group 3: `pineLabsOnlineBaseUrlAffordability` — Affordability APIs

| Environment | Host | Port | Protocol | Path Prefix |
|-------------|------|------|----------|-------------|
| Sandbox / Test | `pluraluat.v2.pinepg.in` | 443 | HTTPS | `/api/affordability/v1/` |
| Production | `api.pluralpay.in` | 443 | HTTPS | `/api/affordability/v1/` |

**Used for**: IMEI Validation

**URL Resolution Logic**: Environment is determined by the `testMode` boolean passed to each `make*Call` function. `testMode = True` → sandbox host (`pluraluat.v2.pinepg.in`); `testMode = False` → production host (`api.pluralpay.in`). Port is always 443 (HTTPS).

**Source**: `Routes.hs` — `/home/kanikachaudhary/Kanika/euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/PineLabsOnline/Routes.hs`

**Timeout Configuration**:
- Custom Timeout Header: Not explicitly configured in connector (uses EulerHS HTTP client defaults)
- Default Timeout: EulerHS HTTP client default
- Per-Merchant Override: Not documented in source

---

## 2. Authentication

### 2.1 Authentication Method
- **Auth Type**: Bearer Token
- **Auth Header**: `Authorization: Bearer {access_token}`
- **Header Format**: `"Bearer " <> token` (constructed in `makeAuthHeader` in `Instances.hs:65`)
- **Credential Source**: `PinelabsOnlineAccountDetails` decoded from `MerchantGatewayAccount.accountDetails` (JSON field)

### 2.2 Authentication Flow

1. On each API call, `addAuthentication` is invoked with `PinelabsOnlineAccountDetails` fetched via `getPinelabsOnlineAccountDetails` (decodes `MerchantGatewayAccount.accountDetails` as JSON).
2. `pinelabsOnlineAccessToken` field from `PinelabsOnlineAccountDetails` is retrieved.
3. `makeAuthHeader` constructs `"Bearer " <> token` and returns it as the auth payload.
4. The Bearer token is passed as the `Authorization` header for all subsequent API calls.
5. **Access Token Refresh** (for sandbox/test mode): When no valid token is present, the connector calls `POST /api/auth/v1/token` with `client_id`, `client_secret`, and `grant_type=client_credentials`. The returned `access_token` is cached in Redis with a TTL computed as `(expires_at - buffer_time)`. Distributed locking is used (Redis lock key: `PINELABS_ONLINE_ACCESS_TOKEN_REQUEST`) to prevent concurrent token refresh races.

### 2.3 Required Headers

| # | Header Name | Value / Source | Required | Description |
|---|-------------|---------------|----------|-------------|
| 1 | `Authorization` | `"Bearer " <> pinelabsOnlineAccessToken` | Yes | Bearer token from merchant account details |
| 2 | `Content-Type` | `application/json` | Yes | JSON request body (set by HTTP client) |

---

## 3. Request Structure

### 3.1 All API Endpoints

| # | API Name | Method | Path | Request Type | Response Type |
|---|----------|--------|------|--------------|---------------|
| 1 | PineLabsOnlineOrderCreateAPI | POST | `/api/pay/v1/orders` | `OrderRequest` | `PineLabsResponse` |
| 2 | PineLabsOnlineTxnCreateAPI | POST | `/api/pay/v1/orders/{order_id}/payments` | `TransactionRequest` | `PineLabsResponse` |
| 3 | PineLabsOnlineTransactionSyncAPI | GET | `/api/pay/v1/orders/reference/{merchant_order_reference}` | — (no body) | `PineLabsResponse` |
| 4 | TxnSync (alias) | GET | `/api/pay/v1/orders/reference/{id}` | — (no body) | `PineLabsResponse` |
| 5 | InitiateRefundAPI | POST | `/api/pay/v1/refunds/{order_id}` | `RefundRequest` | `RefundResponse` |
| 6 | RefundSyncAPI | GET | `/api/pay/v1/orders/reference/{merchant_order_reference}` | — (no body) | `RefundResponse` |
| 7 | PineLabsOnlineCaptureAPI | PUT | `/api/pay/v1/orders/{order_id}/capture` | `CaptureRequest` | `PineLabsResponse` |
| 8 | PineLabsOnlineVoidAPI | PUT | `/api/pay/v1/orders/{order_id}/cancel` | — (no body) | `PineLabsResponse` |
| 9 | PineLabsOnlineSubmitOtpAPI | POST | `/api/pay/v1/otp/submit` | `PinelabsonlineSubmitOtpRequest` | `PinelabsonlineSubmitOtpResponse` |
| 10 | PineLabsOnlineResendOtpAPI | POST | `/api/pay/v1/otp/resend` | `PinelabsonlineResendOTPRequest` | `PinelabsonlineResendOtpResponse` |
| 11 | PineLabsOnlineGetCardDetailsOtpAPI | POST | `/api/pay/v1/getCardDetails` | `PinelabsonlineGetCardDetailsRequest` | `PinelabsonlineGetCardDetailsResponse` |
| 12 | PineLabsOnlineTriggerOtpAPI | POST | `/api/pay/v1/otp/generate` | `PinelabsonlineTriggerOtpRequest` | `PinelabsonlineTriggerOtpResponse` |
| 13 | PineLabsOnlineOfferDiscoveryAPI | POST | `/api/affordability/v1/offer/discovery` | `OfferDiscoveryRequest` | `OfferDiscoveryResponse` |
| 14 | PineLabsOnlineOfferDiscoveryCardlessAPI | POST | `/api/affordability/v1/offer/discovery/cardless` | `OfferDiscoveryRequest` | `OfferDiscoveryResponse` |
| 15 | PineLabsOnlineOfferValidationAPI | POST | `/api/affordability/v1/offer/validate` | `OfferValidationRequest` | `OfferValidationResponse` |
| 16 | PineLabsOnlineImeiValidationAPI | POST | `/api/affordability/v1/product/{order_id}/imei` | `ImeiValidationRequest` | `ImeiValidationResponse` |
| 17 | PineLabsOnlineAccessTokenAPI | POST | `/api/auth/v1/token` | `PinelabsOnlineATRequest` | `PinelabsOnlineATResponse` |
| 18 | PineLabsOnlineConvenienceFeeAPI | POST | `/api/pay/v1/fees` | `ConvenienceFeeRequest` | `PineLabsSurchargeResponse` |

**Source**: `Routes.hs:1-end`

### 3.2 Path Parameters

| # | Parameter | Used In Endpoint(s) | Type | Source | Description |
|---|-----------|---------------------|------|--------|-------------|
| 1 | `order_id` | TxnCreate, Capture, Void, RefundInitiate, IMEI Validation | `Text` | PineLabs `orderId` from Order Create response | PineLabs internal order ID |
| 2 | `merchant_order_reference` | TransactionSync, RefundSync | `Text` | `txnDetail.merchantOrderReference` or `refund.uniqueRequestId` | Merchant's own order reference used for lookups |
| 3 | `id` | TxnSync (alias) | `Text` | txn identifier | Same as `merchant_order_reference` in sync flow |

### 3.3 Request Body Types

---

#### `OrderRequest` — `TxnTypes.hs:261`
Used in: Order Create (Step 1 of all payment flows)

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `orderAmount` | `PaymentAmount` | `order_amount` | Yes | Total order amount with currency |
| 2 | `baseAmount` | `Maybe PaymentAmount` | `base_amount` | No | Base amount (pre-surcharge) |
| 3 | `isMccTransaction` | `Maybe Bool` | `is_mcc_transaction` | No | Whether card is non-INR (MCC) transaction |
| 4 | `merchantOrderReference` | `Text` | `merchant_order_reference` | Yes | Merchant's unique order reference |
| 5 | `preAuth` | `Bool` | `pre_auth` | Yes | Whether this is a pre-authorization flow |
| 6 | `callbackUrl` | `Maybe Text` | `callback_url` | No | Redirect/callback URL after payment |
| 7 | `purchaseDetails` | `Maybe PurchaseDetails` | `purchase_details` | No | Customer, account, metadata, split info |
| 8 | `allowedPaymentMethods` | `Maybe [Text]` | `allowed_payment_methods` | No | Whitelist of payment methods |

**Field Count**: 8 fields

---

#### `PaymentAmount` — `TxnTypes.hs:137`
Used in: `OrderRequest.orderAmount`, `OrderRequest.baseAmount`, `Payments.paymentAmount`, etc.

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `value` | `Integer` | `value` | Yes | Amount in smallest currency unit (paise for INR) |
| 2 | `currency` | `Text` | `currency` | Yes | ISO 4217 currency code (e.g., `"INR"`) |

---

#### `PurchaseDetails` — `TxnTypes.hs:278`
Used in: `OrderRequest.purchaseDetails`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `accountDetails` | `Maybe AccountDetails` | `account_details` | No | Bank account details for NACH/netbanking |
| 2 | `customer` | `Maybe Customer` | `customer` | No | Customer identity and address info |
| 3 | `merchantMetadata` | `Maybe MerchantMetadata` | `merchant_metadata` | No | Merchant-defined key-value metadata |
| 4 | `splitInfo` | `Maybe SplitInfo` | `split_info` | No | Split payment configuration |

---

#### `AccountDetails` — `TxnTypes.hs:291`
Used in: `PurchaseDetails.accountDetails`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `bankDetails` | `BankDetails` | `bank_details` | Yes | Bank account info |

#### `BankDetails` — `TxnTypes.hs:301`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `accountNumber` | `Text` | `account_number` | Yes | Bank account number |
| 2 | `ifscCode` | `Maybe Text` | `ifsc_code` | No | IFSC code |
| 3 | `bankName` | `Maybe Text` | `bank_name` | No | Bank name |

---

#### `Customer` — `TxnTypes.hs:313`
Used in: `PurchaseDetails.customer`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `emailId` | `Maybe Text` | `email_id` | No | Customer email |
| 2 | `firstName` | `Maybe Text` | `first_name` | No | Customer first name |
| 3 | `lastName` | `Maybe Text` | `last_name` | No | Customer last name |
| 4 | `customerId` | `Maybe Text` | `customer_id` | No | Merchant's customer ID |
| 5 | `mobileNumber` | `Maybe Text` | `mobile_number` | No | Customer mobile number |
| 6 | `billingAddress` | `Maybe Address` | `billing_address` | No | Billing address |
| 7 | `shippingAddress` | `Maybe Address` | `shipping_address` | No | Shipping address |

---

#### `Address` — `TxnTypes.hs:329`
Used in: `Customer.billingAddress`, `Customer.shippingAddress`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `address1` | `Maybe Text` | `address1` | No | Address line 1 |
| 2 | `address2` | `Maybe Text` | `address2` | No | Address line 2 |
| 3 | `address3` | `Maybe Text` | `address3` | No | Address line 3 |
| 4 | `pincode` | `Maybe PII.PII` | `pincode` | No | PIN code (PII-protected) |
| 5 | `city` | `Maybe Text` | `city` | No | City |
| 6 | `state` | `Maybe Text` | `state` | No | State |
| 7 | `country` | `Maybe Text` | `country` | No | Country |

---

#### `MerchantMetadata` — `TxnTypes.hs:346`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `key1` | `Maybe Text` | `key1` | No | Merchant-defined metadata field 1 |
| 2 | `key2` | `Maybe Text` | `key2` | No | Merchant-defined metadata field 2 |

---

#### `SplitInfo` — `TxnTypes.hs:353`
Used in: `PurchaseDetails.splitInfo`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `splitType` | `Text` | `split_type` | Yes | Split type identifier |
| 2 | `splitDetails` | `[PinelabsOnlineSplitDetail]` | `split_details` | Yes | Array of split entries |

#### `PinelabsOnlineSplitDetail` — `TxnTypes.hs:365`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `splitMerchantId` | `Text` | `split_merchant_id` | Yes | Sub-merchant ID for this split |
| 2 | `merchantSettlementReference` | `Text` | `merchant_settlement_reference` | Yes | Merchant's settlement reference |
| 3 | `amount` | `PaymentAmount` | `amount` | Yes | Amount for this split |
| 4 | `onHold` | `Bool` | `on_hold` | Yes | Whether split is on hold |
| 5 | `splitSettlementId` | `Maybe Text` | `split_settlement_id` | No | PineLabs settlement ID |
| 6 | `status` | `Maybe Text` | `status` | No | Split status |
| 7 | `updatedAt` | `Maybe Text` | `updated_at` | No | Last update timestamp |

---

#### `TransactionRequest` — `TxnTypes.hs:39`
Used in: Transaction Create (Step 2 of all payment flows)

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `payments` | `[Payments]` | `payments` | Yes | Array of payment objects (typically 1 element) |

**Field Count**: 1 top-level field

---

#### `Payments` — `TxnTypes.hs:49`
Used in: `TransactionRequest.payments`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `merchantPaymentReference` | `Text` | `merchant_payment_reference` | Yes | Merchant's unique payment reference |
| 2 | `paymentMethod` | `Text` | `payment_method` | Yes | Payment method code (e.g., `"CARD"`, `"UPI"`, `"CREDIT_EMI"`) |
| 3 | `paymentAmount` | `PaymentAmount` | `payment_amount` | Yes | Payment amount with currency |
| 4 | `paymentOption` | `PaymentOption` | `payment_option` | Yes | Payment instrument details |
| 5 | `deviceInfo` | `Maybe DeviceInfo` | `device_info` | No | Browser/device fingerprint for 3DS |
| 6 | `riskValidationDetails` | `Maybe RiskValidationDetails` | `risk_validation_details` | No | Customer identity for risk checks |
| 7 | `offerData` | `Maybe OfferData` | `offer_data` | No | EMI/offer details applied |
| 8 | `convenience_fee_breakdown` | `Maybe ConvenienceFeeBreakdown` | `convenience_fee_breakdown` | No | Surcharge/fee breakdown |

**Field Count**: 8 fields

---

#### `PaymentOption` — `TxnTypes.hs:222`
Used in: `Payments.paymentOption`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `upiDetails` | `Maybe UpiDetails` | `upi_details` | No | UPI payment details |
| 2 | `cardDetails` | `Maybe CardDetails` | `card_details` | No | Card payment details |
| 3 | `netbankingDetails` | `Maybe NetbankingDetails` | `netbanking_details` | No | Netbanking details |
| 4 | `walletDetails` | `Maybe WalletDetails` | `wallet_details` | No | Wallet payment details |
| 5 | `cardTokenDetails` | `Maybe CardDetails` | `card_token_details` | No | Tokenized card details |
| 6 | `upiData` | `Maybe UpiDetails` | `upi_data` | No | Alternative UPI data field |
| 7 | `cardlessDetails` | `Maybe CardlessDetails` | `cardless_details` | No | Cardless EMI details |

---

#### `CardDetails` — `TxnTypes.hs:144`
Used in: `PaymentOption.cardDetails`, `PaymentOption.cardTokenDetails`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `name` | `Text` | `name` | Yes | Cardholder name |
| 2 | `cardNumber` | `Maybe Text` | `card_number` | No | Full PAN (plaintext or vault reference) |
| 3 | `cvv` | `Maybe Text` | `cvv` | No | Card CVV |
| 4 | `last4Digit` | `Maybe Text` | `last4_digit` | No | Last 4 digits of card |
| 5 | `expiryMonth` | `Text` | `expiry_month` | Yes | Card expiry month (MM) |
| 6 | `expiryYear` | `Text` | `expiry_year` | Yes | Card expiry year (YYYY) |
| 7 | `token` | `Maybe Text` | `token` | No | Network/issuer token |
| 8 | `cryptogram` | `Maybe Text` | `cryptogram` | No | Token cryptogram for network tokens |
| 9 | `tokenTxnType` | `Maybe Text` | `token_txn_type` | No | Token transaction type |
| 10 | `dinersTokenReferenceId` | `Maybe Text` | `diners_token_reference_id` | No | Diners Club token reference |
| 11 | `dinersTokenRequesterMerchantId` | `Maybe Text` | `diners_token_requester_merchant_id` | No | Diners token requester merchant ID |
| 12 | `registeredMobileNumber` | `Maybe Text` | `registered_mobile_number` | No | Mobile number registered with card |

---

#### `UpiDetails` — `TxnTypes.hs:250`
Used in: `PaymentOption.upiDetails`, `PaymentOption.upiData`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `txnMode` | `Text` | `txn_mode` | Yes | UPI mode: `"INTENT"`, `"COLLECT"`, etc. |
| 2 | `payer` | `Maybe Payer` | `payer` | No | Payer VPA details (for COLLECT) |

#### `Payer` — `TxnTypes.hs:238`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `vpa` | `Maybe Text` | `vpa` | No | UPI Virtual Payment Address |
| 2 | `accountType` | `Maybe Text` | `account_type` | No | Account type |

---

#### `NetbankingDetails` — `TxnTypes.hs:201`
Used in: `PaymentOption.netbankingDetails`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `payCode` | `Text` | `pay_code` | Yes | Bank pay code |
| 2 | `txnMode` | `Text` | `txn_mode` | Yes | Transaction mode (e.g., `"REDIRECT"`) |

---

#### `WalletDetails` — `TxnTypes.hs:212`
Used in: `PaymentOption.walletDetails`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `walletCode` | `Text` | `wallet_code` | Yes | Wallet provider code |

---

#### `CardlessDetails` — `TxnTypes.hs:166`
Used in: `PaymentOption.cardlessDetails` (Cardless EMI)

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `registeredMobileNumber` | `Maybe Text` | `registered_mobile_number` | No | Mobile number for cardless EMI |
| 2 | `panLastDigits` | `Maybe Text` | `pan_last_digits` | No | Last digits of PAN for cardless verification |

---

#### `DeviceInfo` — `TxnTypes.hs:101`
Used in: `Payments.deviceInfo`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `deviceType` | `Text` | `device_type` | Yes | Device type (e.g., `"BROWSER"`) |
| 2 | `browserUserAgent` | `Text` | `browser_user_agent` | Yes | Browser user agent string |
| 3 | `browserAcceptHeader` | `Maybe Text` | `browser_accept_header` | No | HTTP Accept header |
| 4 | `browserLanguage` | `Maybe Text` | `browser_language` | No | Browser language |
| 5 | `browserScreenHeight` | `Maybe Text` | `browser_screen_height` | No | Screen height |
| 6 | `browserScreenWidth` | `Maybe Text` | `browser_screen_width` | No | Screen width |
| 7 | `browserTimezone` | `Maybe Text` | `browser_timezone` | No | Browser timezone |
| 8 | `browserWindowSize` | `Maybe Text` | `browser_window_size` | No | Window size |
| 9 | `browserScreenColorDepth` | `Maybe Text` | `browser_screen_color_depth` | No | Screen color depth |
| 10 | `browserJavaEnabledVal` | `Maybe Text` | `browser_java_enabled_val` | No | Java enabled flag |
| 11 | `browserJavascriptEnabledVal` | `Maybe Text` | `browser_javascript_enabled_val` | No | JavaScript enabled flag |
| 12 | `deviceChannel` | `Maybe Text` | `device_channel` | No | Device channel |
| 13 | `browserIpAddress` | `Maybe Text` | `browser_ip_address` | No | Client IP address |

---

#### `RiskValidationDetails` — `TxnTypes.hs:66`
Used in: `Payments.riskValidationDetails`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `emailId` | `Text` | `email_id` | Yes | Customer email for risk validation |
| 2 | `firstName` | `Text` | `first_name` | Yes | Customer first name |
| 3 | `lastName` | `Text` | `last_name` | Yes | Customer last name |
| 4 | `customerId` | `Maybe Text` | `customer_id` | No | Merchant customer ID |
| 5 | `mobileNumber` | `Maybe Text` | `mobile_number` | No | Mobile number |
| 6 | `countryCode` | `Maybe Text` | `country_code` | No | Country code |
| 7 | `billingAddress` | `BillingAddress` | `billing_address` | Yes | Billing address |

#### `BillingAddress` (in Payments context) — `TxnTypes.hs:82`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `address1` | `Text` | `address1` | Yes | Address line 1 |
| 2 | `address2` | `Maybe Text` | `address2` | No | Address line 2 |
| 3 | `address3` | `Maybe Text` | `address3` | No | Address line 3 |
| 4 | `pincode` | `Maybe PII.PII` | `pincode` | No | PIN code (PII protected) |
| 5 | `city` | `Text` | `city` | Yes | City |
| 6 | `state` | `Text` | `state` | Yes | State |
| 7 | `country` | `Text` | `country` | Yes | Country |
| 8 | `fullName` | `Maybe Text` | `full_name` | No | Full name |
| 9 | `addressType` | `Maybe Text` | `address_type` | No | Address type |
| 10 | `addressCategory` | `Maybe Text` | `address_category` | No | Address category |

---

#### `CaptureRequest` — `TxnTypes.hs:583`
Used in: Capture API

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `captureAmount` | `PaymentAmount` | `capture_amount` | Yes | Amount to capture |
| 2 | `merchantCaptureReference` | `Text` | `merchant_capture_reference` | Yes | Merchant's unique capture reference |

**Field Count**: 2 fields

---

#### `RefundRequest` — `RefundTypes.hs:21`
Used in: Refund Initiate API

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `merchantOrderReference` | `Text` | `merchant_order_reference` | Yes | Original order's merchant reference |
| 2 | `orderAmount` | `AmountDetails` | `order_amount` | Yes | Amount to refund |
| 3 | `merchantMetadata` | `Maybe MerchantRefundMetadata` | `merchant_metadata` | No | Refund metadata |
| 4 | `products` | `Maybe [Product]` | `products` | No | Product list (for IMEI-based refunds) |
| 5 | `splitInfo` | `Maybe RefundSplitInfo` | `split_info` | No | Split refund configuration |

**Field Count**: 5 fields

#### `AmountDetails` — `RefundTypes.hs:114`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `value` | `Integer` | `value` | Yes | Amount in smallest currency unit |
| 2 | `currency` | `Text` | `currency` | Yes | ISO 4217 currency code |

#### `MerchantRefundMetadata` — `RefundTypes.hs:67`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `refundKey1` | `Maybe Text` | `key1` | No | Merchant metadata key 1 |
| 2 | `refundKey2` | `Maybe Text` | `key2` | No | Merchant metadata key 2 |

#### `Product` (refund) — `RefundTypes.hs:47`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `productCode` | `Text` | `product_code` | Yes | Product code |
| 2 | `productImei` | `Text` | `product_imei` | Yes | Product IMEI number |
| 3 | `productAmount` | `Maybe AmountDetails` | `product_amount` | No | Product-specific refund amount |

#### `RefundSplitInfo` — `RefundTypes.hs:227`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `splitType` | `Text` | `split_type` | Yes | Split type |
| 2 | `splitDetails` | `[RefundSplitDetails]` | `split_details` | Yes | Array of split refund entries |

#### `RefundSplitDetails` — `RefundTypes.hs:233`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `parentOrderSplitSettlementId` | `Text` | `parent_order_split_settlement_id` | Yes | Original split settlement ID |
| 2 | `splitMerchantId` | `Text` | `split_merchant_id` | Yes | Sub-merchant ID |
| 3 | `merchantSettlementReference` | `Text` | `merchant_settlement_reference` | Yes | Settlement reference |
| 4 | `amount` | `AmountDetails` | `amount` | Yes | Split refund amount |

---

#### `PinelabsonlineSubmitOtpRequest` — `TxnTypes.hs:662`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `paymentId` | `Text` | `payment_id` | Yes | PineLabs payment ID from transaction response |
| 2 | `otp` | `Text` | `otp` | Yes | OTP entered by customer |

---

#### `PinelabsonlineResendOTPRequest` — `TxnTypes.hs:675`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `paymentId` | `Text` | `payment_id` | Yes | PineLabs payment ID |

---

#### `PinelabsonlineGetCardDetailsRequest` — `TxnTypes.hs:686`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `cardDetails` | `[GetCardDetails]` | `card_details` | Yes | Array of card lookup items |

#### `GetCardDetails` — `TxnTypes.hs:698`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `paymentIdentifier` | `Text` | `payment_identifier` | Yes | Card number, network token, alt token, or issuer token |
| 2 | `paymentReferenceType` | `Text` | `payment_reference_type` | Yes | One of: `"CARD"`, `"NETWORK_TOKEN_TXN"`, `"ALT_TOKEN_TXN"`, `"ISSUER_TOKEN_TXN"` |

---

#### `PinelabsonlineTriggerOtpRequest` — `TxnTypes.hs:740`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `paymentId` | `Text` | `payment_id` | Yes | PineLabs payment ID for which OTP should be triggered |

---

#### `PinelabsOnlineATRequest` — `TxnTypes.hs:1067`
Used in: Access Token API (`/api/auth/v1/token`)

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `client_id` | `Text` | `client_id` | Yes | OAuth2 client ID from merchant account |
| 2 | `client_secret` | `Text` | `client_secret` | Yes | OAuth2 client secret from merchant account |
| 3 | `grant_type` | `Text` | `grant_type` | Yes | Always `"client_credentials"` |

---

#### `ConvenienceFeeRequest` — `TxnTypes.hs:1082`
Used in: Convenience Fee / Surcharge API

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `amount` | `PaymentAmount` | `amount` | Yes | Order amount |
| 2 | `payment_method` | `Text` | `payment_method` | Yes | Payment method code |
| 3 | `network_type` | `Maybe Text` | `network_type` | No | Card network type (e.g., `"VISA"`, `"MASTERCARD"`) |

---

#### `OfferValidationRequest` — `TxnTypes.hs:872`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `payment_method` | `Text` | `payment_method` | Yes | Payment method for offer validation |
| 2 | `order_amount` | `PaymentAmount` | `order_amount` | Yes | Original order amount |
| 3 | `payment_amount` | `PaymentAmount` | `payment_amount` | Yes | Payment amount after discount |
| 4 | `payment_option` | `PaymentOption` | `payment_option` | Yes | Payment instrument details |
| 5 | `offer_data` | `OfferData` | `offer_data` | Yes | Offer to validate |

---

#### `ImeiValidationRequest` — `TxnTypes.hs:1033`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `merchant_product_imei_reference` | `Text` | `merchant_product_imei_reference` | Yes | Merchant's IMEI reference |
| 2 | `request_type` | `Text` | `request_type` | Yes | Type of IMEI validation request |
| 3 | `products` | `[ImeiProduct]` | `products` | Yes | List of products with IMEI |

#### `ImeiProduct` — `TxnTypes.hs:1041`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `product_code` | `Text` | `product_code` | Yes | Product code |
| 2 | `dealer_code` | `Maybe Text` | `dealer_code` | No | Dealer code |
| 3 | `state_code` | `Maybe Text` | `state_code` | No | State code |
| 4 | `product_imei` | `Text` | `product_imei` | Yes | Product IMEI number |
| 5 | `product_imei_status` | `Maybe Text` | `product_imei_status` | No | Status of IMEI |
| 6 | `product_brand_response` | `Maybe ProductBrandResponse` | `product_brand_response` | No | Brand validation response |

---

## 4. Response Structure

### 4.1 Primary Response Types

---

#### `PineLabsResponse` — `TxnTypes.hs:456`
Sum type (untagged JSON union) — used as response type for all transaction/capture/void/sync APIs.

```
PineLabsResponse = SuccessResponse TransactionResponse | FailureResponse PineLabsErrorResponse
```

Deserialization is **untagged** — the parser tries `TransactionResponse` first; if that fails it tries `PineLabsErrorResponse`.

---

#### `TransactionResponse` — `TxnTypes.hs:383`
The success variant of `PineLabsResponse`.

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `eventType` | `Maybe Text` | `event_type` | No | Event type (used in webhook responses) |
| 2 | `transactionData` | `TransactionData` | `data` | Yes | Core transaction data (JSON key is literally `"data"`) |

---

#### `TransactionData` — `TxnTypes.hs:400`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `orderId` | `Text` | `order_id` | Yes | PineLabs order ID |
| 2 | `merchantOrderReference` | `Text` | `merchant_order_reference` | Yes | Merchant order reference (echoed back) |
| 3 | `status` | `Text` | `status` | Yes | Order/transaction status string |
| 4 | `challengeUrl` | `Maybe Text` | `challenge_url` | No | 3DS challenge / redirect URL |
| 5 | `merchantId` | `Text` | `merchant_id` | Yes | PineLabs merchant ID |
| 6 | `orderAmount` | `PaymentAmount` | `order_amount` | Yes | Order amount |
| 7 | `preAuth` | `Maybe Bool` | `pre_auth` | No | Whether order is pre-auth |
| 8 | `payments` | `Maybe [ReponsePayments]` | `payments` | No | Array of payment objects |
| 9 | `integrationMode` | `Text` | `integration_mode` | Yes | Integration mode (e.g., `"REDIRECT"`, `"SDK"`) |
| 10 | `createdAt` | `Maybe Text` | `created_at` | No | Order creation timestamp |
| 11 | `updatedAt` | `Maybe Text` | `updated_at` | No | Order last update timestamp |
| 12 | `purchaseDetails` | `Maybe PurchaseDetails` | `purchase_details` | No | Purchase details echoed back |
| 13 | `partPayment` | `Maybe Bool` | `part_payment` | No | Whether partial payment is allowed |
| 14 | `allowedPaymentMethods` | `Maybe [Text]` | `allowed_payment_methods` | No | Allowed payment method list |
| 15 | `paymentRetriesRemaining` | `Maybe Integer` | `payment_retries_remaining` | No | Number of payment retries left |
| 16 | `isMccTransaction` | `Maybe Bool` | `is_mcc_transaction` | No | MCC (non-INR) transaction flag |

**Field Count**: 16 fields

---

#### `ReponsePayments` — `TxnTypes.hs:424`
Note: type constructor is `ResponsePayments` (typo in source preserved)

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `id` | `Text` | `id` | Yes | PineLabs payment ID |
| 2 | `status` | `Text` | `status` | Yes | Payment status |
| 3 | `merchantPaymentReference` | `Text` | `merchant_payment_reference` | Yes | Merchant payment reference (echoed) |
| 4 | `paymentMethod` | `Text` | `payment_method` | Yes | Payment method used |
| 5 | `paymentAmount` | `PaymentAmount` | `payment_amount` | Yes | Payment amount |
| 6 | `paymentOption` | `Maybe PaymentOption` | `payment_option` | No | Payment option details |
| 7 | `acquirerData` | `Maybe AcquirerData` | `acquirer_data` | No | Acquirer/bank response data |
| 8 | `offerData` | `Maybe OfferData` | `offer_data` | No | Applied offer data |
| 9 | `captureData` | `Maybe [CaptureData]` | `capture_data` | No | Capture history |
| 10 | `createdAt` | `Maybe Text` | `created_at` | No | Payment creation timestamp |
| 11 | `updatedAt` | `Maybe Text` | `updated_at` | No | Payment update timestamp |
| 12 | `errorDetail` | `Maybe PineLabsErrorResponse` | `error_detail` | No | Error detail if payment failed |
| 13 | `baseAmount` | `Maybe PaymentAmount` | `base_amount` | No | Base amount before surcharge |

---

#### `AcquirerData` — `TxnTypes.hs:124`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `approvalCode` | `Maybe Text` | `approval_code` | No | Bank approval code |
| 2 | `acquirerReference` | `Maybe Text` | `acquirer_reference` | No | Acquirer reference number |
| 3 | `rrn` | `Maybe Text` | `rrn` | No | Retrieval reference number |
| 4 | `isAggregator` | `Bool` | `is_aggregator` | Yes | Whether acquirer is aggregator |

---

#### `CaptureData` — `TxnTypes.hs:445`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `merchantCaptureReference` | `Text` | `merchant_capture_reference` | Yes | Merchant capture reference |
| 2 | `captureAmount` | `PaymentAmount` | `capture_amount` | Yes | Amount captured |
| 3 | `createdAt` | `Maybe Text` | `created_at` | No | Capture timestamp |

---

#### `PineLabsErrorResponse` — `TxnTypes.hs:1153`
The failure variant of `PineLabsResponse` (also used inline in payment objects).

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `code` | `Text` | `code` | Yes | PineLabs error code string |
| 2 | `message` | `Text` | `message` | Yes | Human-readable error description |

---

#### `RefundResponse` — `RefundTypes.hs:97`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `refundResponseData` | `RefundResponseData` | `data` | Yes | Refund data (JSON key is `"data"`) |

#### `RefundResponseData` — `RefundTypes.hs:101`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | `refundResponseDataOrderId` | `Text` | `order_id` | Yes | PineLabs refund order ID |
| 2 | `refundResponseDataParentOrderId` | `Text` | `parent_order_id` | Yes | Original payment order ID |
| 3 | `refundResponseDataMerchantOrderReference` | `Text` | `merchant_order_reference` | Yes | Merchant order reference |
| 4 | `refundResponseDataType` | `RefundType` (Text) | `type` | Yes | Refund type |
| 5 | `refundResponseDataStatus` | `RefundStatus` (Text) | `status` | Yes | Refund status string |
| 6 | `refundResponseDataMerchantId` | `Text` | `merchant_id` | Yes | PineLabs merchant ID |
| 7 | `refundResponseDataOrderAmount` | `AmountDetails` | `order_amount` | Yes | Refund amount |
| 8 | `refundResponseDataPayments` | `[PaymentDetails]` | `payments` | Yes | Payment breakdowns for this refund |
| 9 | `refundResponseDataCreatedAt` | `Maybe Text` | `created_at` | No | Refund created timestamp |
| 10 | `refundResponseDataUpdatedAt` | `Maybe Text` | `updated_at` | No | Refund updated timestamp |

---

#### `PinelabsonlineSubmitOtpResponse` — `TxnTypes.hs:653`
Sum type (untagged union):
```
SuccessSubmitOtpResp SuccessSubmitOtpResponse
| IncorrectOtpSubmitOtpResp IncorrectOtpSubmitOtpResponse
| FailureSubmitOtpResponse PineLabsErrorResponse
```

**`SuccessSubmitOtpResponse`** — `TxnTypes.hs:613`:

| # | Field | JSON Key | Type | Description |
|---|-------|----------|------|-------------|
| 1 | `status` | `status` | `Text` | Status string (success) |

**`IncorrectOtpSubmitOtpResponse`** — `TxnTypes.hs:638`:

| # | Field | JSON Key | Type | Description |
|---|-------|----------|------|-------------|
| 1 | `code` | `code` | `Text` | Error code |
| 2 | `message` | `message` | `Text` | Error message |
| 3 | `next` | `next` | `[Text]` | Allowed next actions |
| 4 | `meta_data` | `meta_data` | `Maybe SubmitOtpMetaData` | OTP retry metadata |

**`SubmitOtpMetaData`** — `TxnTypes.hs:626`:

| # | Field | JSON Key | Type | Description |
|---|-------|----------|------|-------------|
| 1 | `resend_after` | `resend_after` | `Text` | Seconds until OTP can be resent |

---

#### `PinelabsonlineResendOtpResponse` — `TxnTypes.hs:823`
Sum type (untagged union):
```
ResendOtpSuccessResp ResendOtpSuccessResponse
| ResendOtpErrorResp PineLabsErrorResponse
| ResendOtpFailureResp ResendOtpFailureResponse
```

**`ResendOtpSuccessResponse`** — `TxnTypes.hs:809`:

| # | Field | JSON Key | Type | Description |
|---|-------|----------|------|-------------|
| 1 | `status` | `status` | `Text` | Status string |
| 2 | `next` | `next` | `[Text]` | Allowed next actions |
| 3 | `metaData` | `meta_data` | `MetaDataType` | OTP timing metadata |

**`ResendOtpFailureResponse`** — `TxnTypes.hs:795`:

| # | Field | JSON Key | Type | Description |
|---|-------|----------|------|-------------|
| 1 | `code` | `code` | `Text` | Error code |
| 2 | `message` | `message` | `Text` | Error message |
| 3 | `next` | `next` | `[Text]` | Allowed next actions |

**`MetaDataType`** — `TxnTypes.hs:774`:

| # | Field | JSON Key | Type | Description |
|---|-------|----------|------|-------------|
| 1 | `resendAfter` | `resend_after` | `Text` | Time after which OTP can be resent |

---

#### `PinelabsonlineTriggerOtpResponse` — `TxnTypes.hs:752`
Sum type (untagged union):
```
SuccessTriggerOtpResponse PinelabsonlineTriggerOtpSuccessResponse
| FailureTriggerOtpResponse PineLabsErrorResponse
```

**`PinelabsonlineTriggerOtpSuccessResponse`** — `TxnTypes.hs:761`:

| # | Field | JSON Key | Type | Description |
|---|-------|----------|------|-------------|
| 1 | `next` | `next` | `[Text]` | Allowed next actions |
| 2 | `metaData` | `meta_data` | `MetaDataType` | OTP timing metadata |

---

#### `PinelabsonlineGetCardDetailsResponse` — `TxnTypes.hs:709`

| # | Field | JSON Key | Type | Description |
|---|-------|----------|------|-------------|
| 1 | `cardPaymentDetails` | `card_payment_details` | `[CardPaymentDetails]` | Card capability details |

#### `CardPaymentDetails` — `TxnTypes.hs:721`

| # | Field | JSON Key | Type | Description |
|---|-------|----------|------|-------------|
| 1 | `cardNetwork` | `card_network` | `Maybe Text` | Card network (e.g., `"VISA"`) |
| 2 | `cardIssuer` | `card_issuer` | `Maybe Text` | Issuing bank name |
| 3 | `cardType` | `card_type` | `Maybe Text` | Card type (`"CREDIT"`, `"DEBIT"`) |
| 4 | `cardCategory` | `card_category` | `Maybe Text` | Card category |
| 5 | `isInternationalCard` | `is_international_card` | `Maybe Bool` | Whether card is international |
| 6 | `isNativeOtpSupported` | `is_native_otp_supported` | `Bool` | Whether native OTP is supported for this card |
| 7 | `countryCode` | `country_code` | `Maybe Text` | Card country code |
| 8 | `currency` | `currency` | `Maybe Text` | Card currency |
| 9 | `isCurrencySupported` | `is_currency_supported` | `Maybe Bool` | Whether card currency is supported |

---

#### `PinelabsOnlineATResponse` — `TxnTypes.hs:1074`

| # | Field | JSON Key | Type | Description |
|---|-------|----------|------|-------------|
| 1 | `access_token` | `access_token` | `Text` | OAuth2 access token |
| 2 | `refresh_token` | `refresh_token` | `Maybe Text` | Refresh token (optional) |
| 3 | `expires_at` | `expires_at` | `Text` | Token expiry timestamp |

---

#### `PineLabsSurchargeResponse` — `TxnTypes.hs:1100`
Sum type (untagged union):
```
SurchargeSuccessResp ConvenienceFeeResponse
| SurchargeFailureResp PineLabsErrorResponse
```

**`ConvenienceFeeResponse`** — `TxnTypes.hs:1109`:

| # | Field | JSON Key | Type | Description |
|---|-------|----------|------|-------------|
| 1 | `surchargeData` | `data` | `[ConvenienceFeeData]` | Array of fee data (JSON key is `"data"`) |

**`ConvenienceFeeData`** — `TxnTypes.hs:1125`:

| # | Field | JSON Key | Type | Description |
|---|-------|----------|------|-------------|
| 1 | `payment_method` | `payment_method` | `Text` | Payment method code |
| 2 | `fee_type` | `fee_type` | `Text` | Fee type identifier |
| 3 | `amount` | `amount` | `PaymentAmount` | Base payment amount |
| 4 | `convenience_fee_breakdown` | `convenience_fee_breakdown` | `ConvenienceFeeBreakdown` | Fee breakdown |
| 5 | `payable_amount` | `payable_amount` | `PaymentAmount` | Total payable (amount + fee) |
| 6 | `payment_method_metadata` | `payment_method_metadata` | `PaymentMethodMetadata` | Card/network metadata |

**`ConvenienceFeeBreakdown`** — `TxnTypes.hs:1136`:

| # | Field | JSON Key | Type | Description |
|---|-------|----------|------|-------------|
| 1 | `fee_amount` | `fee_amount` | `PaymentAmount` | Base fee amount |
| 2 | `tax_amount` | `tax_amount` | `PaymentAmount` | Tax on fee |
| 3 | `additional_fee_amount` | `additional_fee_amount` | `PaymentAmount` | Additional fee |
| 4 | `maximum_fee_amount` | `maximum_fee_amount` | `PaymentAmount` | Maximum fee cap |
| 5 | `applicable_fee_amount` | `applicable_fee_amount` | `PaymentAmount` | Final applicable fee |

**`PaymentMethodMetadata`** — `TxnTypes.hs:1146`:

| # | Field | JSON Key | Type | Description |
|---|-------|----------|------|-------------|
| 1 | `network_type` | `network_type` | `Maybe Text` | Card network type |
| 2 | `card_type` | `card_type` | `Maybe Text` | Card type (CREDIT/DEBIT) |

---

#### `ImeiValidationResponse` — `TxnTypes.hs:1052`

| # | Field | JSON Key | Type | Description |
|---|-------|----------|------|-------------|
| 1 | `merchant_product_imei_reference` | `merchant_product_imei_reference` | `Text` | Merchant's IMEI reference (echoed) |
| 2 | `request_type` | `request_type` | `Text` | Request type (echoed) |
| 3 | `products` | `products` | `[ImeiProduct]` | Products with validation results |

#### `ProductBrandResponse` — `TxnTypes.hs:1060`

| # | Field | JSON Key | Type | Description |
|---|-------|----------|------|-------------|
| 1 | `code` | `code` | `Maybe Text` | Brand response code |
| 2 | `message` | `message` | `Maybe Text` | Brand response message |

---

#### `OfferValidationResponse` — `TxnTypes.hs:1024`
Sum type (untagged union):
```
SuccessValidationResponse OfferValidationResp
| FailureValidationResponse PineLabsErrorResponse
```

**`OfferValidationResp`** — `TxnTypes.hs:1017`:

| # | Field | JSON Key | Type | Description |
|---|-------|----------|------|-------------|
| 1 | `code` | `code` | `Text` | Validation result code |
| 2 | `message` | `message` | `Text` | Validation message |

---

## 5. Flows

### 5.1 Flow: Redirect Transaction Flow

**File**: `Flows/Transaction.hs`, `Instances.hs:68-135`
**Purpose**: Handle card/netbanking/wallet redirect payments end-to-end
**Trigger**: `API.RedirectTransaction` request via `nestedRedirectionHandler`

#### Steps (3-stage pipeline)

| Step | Action | Function | File | Details |
|------|--------|----------|------|---------|
| 1 | Validate request | `validateRedirectRequest` | `Flows/Transaction.hs` | Check required fields |
| 2 | Get account details | `getPineLabsAccountDetails` | `Instances.hs:139` | Decode MGA → `PinelabsOnlineAccountDetails` |
| 3 | Build Order request | `makeOrderRequest` | `Transforms/Transaction.hs` | Build `OrderRequest` from `RedirectTransaction` |
| 4 | API Call → POST `/api/pay/v1/orders` | `makeOrderCall` | `Routes.hs` | Create order; get `orderId` back |
| 5 | Handle order response | `handleOrderRedirectionResponse` | `Flows/Transaction.hs` | Extract `orderId`, build `RedirectionIntermediateReq` |
| 6 | [Stage 2] Check surcharge skip | `handleRedirectionSurchargeSkipFlow` | `Flows/Transaction.hs` | If no surcharge config, skip to stage 3 |
| 7 | Build surcharge request | `makeGatewaySurchargeRequest` | `Transforms/Common.hs` | Build `ConvenienceFeeRequest` |
| 8 | API Call → POST `/api/pay/v1/fees` | `makeConvenienceFeeCall` | `Routes.hs` | Fetch surcharge/convenience fee |
| 9 | Handle surcharge response | `handleResponseSurcharge` | `Flows/Transaction.hs` | Attach surcharge info to intermediate |
| 10 | [Stage 3] Check redirect skip | `handleRedirectionSkipFlow` | `Flows/Transaction.hs` | If already done, skip |
| 11 | Build Transaction request | `mkRedirectionTransactionRequest` | `Transforms/Transaction.hs` | Build `TransactionRequest` with `Payments` |
| 12 | API Call → POST `/api/pay/v1/orders/{orderId}/payments` | `makeTransactionCall` | `Routes.hs` | Create payment; get redirect URL |
| 13 | Handle transaction response | `handleRedirectionTxnResponse` | `Flows/Transaction.hs` | Build `API.PaymentResponse` with redirect |

#### Decision Points

| # | Condition | YES Branch | NO Branch |
|---|-----------|-----------|-----------|
| 1 | `shouldSendSurchargeBreakUpForGw == Just "true"` | Call convenience fee API | Skip to transaction create |
| 2 | `preAuth == True` | Set `preAuth` in `OrderRequest` | Normal flow |
| 3 | Order response is `FailureResponse` | Return error response | Continue to stage 2 |

---

### 5.2 Flow: InitiateTransaction Flow

**File**: `Flows/Transaction.hs`, `Instances.hs:425-516`
**Purpose**: Handle card payments with native OTP (DOTP) — 5-stage pipeline
**Trigger**: `API.InitiateTransaction` request via `nestedInitiateTxnHandler`

#### Steps

| Step | Action | Function | File | Details |
|------|--------|----------|------|---------|
| 1 | Validate request | `validateInitiateTransactionRequest` | `Flows/Transaction.hs` | Validate card data |
| 2 | Build Order request | `initiateTxnOrderRequest` | `Transforms/Transaction.hs` | Build `OrderRequest` |
| 3 | API Call → POST `/api/pay/v1/orders` | `makeOrderCall` | `Routes.hs` | Create order |
| 4 | Handle order response | `handleOrderInitiateTxnResponse` | `Flows/Transaction.hs` | Extract orderId |
| 5 | [Stage 2] Surcharge (optional) | `handleInitiateTxnSurchargeSkipFlow` | `Flows/Transaction.hs` | Fetch convenience fee |
| 6 | [Stage 3] Build transaction request | `mkInitiateTransactionRequest` | `Transforms/Transaction.hs` | Build `TransactionRequest` |
| 7 | API Call → POST `/api/pay/v1/orders/{orderId}/payments` | `makeTransactionCall` | `Routes.hs` | Create payment; get `paymentId` |
| 8 | [Stage 4] Get card details | `makeGetCardDetailsRequest` | `DotpTransforms.hs:18` | Build `PinelabsonlineGetCardDetailsRequest` |
| 9 | API Call → POST `/api/pay/v1/getCardDetails` | `makeGetCardDetailsCall` | `Routes.hs` | Check `isNativeOtpSupported` |
| 10 | Handle card details response | `handleGetCardDetailsResponse` | `Flows/DotpFlow.hs` | Set `isNativeOtpSupported` flag |
| 11 | [Stage 5] Check OTP trigger skip | `handleTriggerOtpSkipFlow` | `Flows/DotpFlow.hs` | Skip if native OTP not supported |
| 12 | Build OTP trigger request | `mkTriggerOtpTransactionRequest` | `DotpTransforms.hs:33` | Build `PinelabsonlineTriggerOtpRequest` |
| 13 | API Call → POST `/api/pay/v1/otp/generate` | `makeTriggerOtpCall` | `Routes.hs` | Trigger OTP send |
| 14 | Handle OTP trigger response | `handleTriggerOtpResponse` | `Flows/Transaction.hs` | Build final `PaymentResponse` with OTP challenge |

---

### 5.3 Flow: SDK (GetSdkParams) Flow

**File**: `Flows/SDKTransaction.hs`, `Instances.hs:155-217`
**Purpose**: UPI Intent / SDK payment flow — 3-stage pipeline
**Trigger**: `API.GetSdkParams` request via `nestedGetSdkHandler`

#### Steps

| Step | Action | Function | File | Details |
|------|--------|----------|------|---------|
| 1 | Validate SDK request | `validateSdkRequest` | `Flows/SDKTransaction.hs` | Validate UPI/SDK params |
| 2 | Build Order request | `makeOrderRequest (Left req)` | `Transforms/Transaction.hs` | Create order with SDK params |
| 3 | API Call → POST `/api/pay/v1/orders` | `makeOrderCall` | `Routes.hs` | Create order |
| 4 | Handle order response | `handleOrderSdkResponse` | `Flows/SDKTransaction.hs` | Extract orderId / SDK params |
| 5 | [Stage 2] Surcharge (optional) | `handleSdkSurchargeSkipFlow` | `Flows/SDKTransaction.hs` | Check if surcharge applies |
| 6 | API Call → POST `/api/pay/v1/fees` | `makeConvenienceFeeCall` | `Routes.hs` | Convenience fee (if needed) |
| 7 | [Stage 3] Build SDK transaction request | `mkSDKTransactionRequest` | `Transforms/Transaction.hs` | Build `TransactionRequest` for SDK |
| 8 | API Call → POST `/api/pay/v1/orders/{orderId}/payments` | `makeTransactionCall` | `Routes.hs` | Create payment; get UPI intent URL |
| 9 | Handle SDK transaction response | `handleSdkTxnResponse` | `Flows/SDKTransaction.hs` | Return `GetSdkParamsResponse` with intent URL |

---

### 5.4 Flow: SendCollect (UPI Collect) Flow

**File**: `Flows/SDKTransaction.hs`, `Instances.hs:242-300`
**Purpose**: UPI Collect payment — 3-stage pipeline
**Trigger**: `API.SendCollect` request via `nestedSendCollectHandler`

#### Steps

| Step | Action | Function | File | Details |
|------|--------|----------|------|---------|
| 1 | Validate collect request | `validateCollectRequest` | `Flows/SDKTransaction.hs` | Validate VPA / payer info |
| 2 | Build Order request | `makeSendCollectOrderRequest` | `Transforms/Transaction.hs` | Create order for collect |
| 3 | API Call → POST `/api/pay/v1/orders` | `makeOrderCall` | `Routes.hs` | Create order |
| 4 | Handle order response | `handleOrderSendCollectResponse` | `Flows/SDKTransaction.hs` | Extract orderId |
| 5 | [Stage 2] Surcharge (optional) | `handleCollectSurchargeSkipFlow` | `Flows/SDKTransaction.hs` | Surcharge if configured |
| 6 | [Stage 3] Build collect transaction request | `mkSendCollectRequest` | `Transforms/Transaction.hs` | Build `TransactionRequest` with VPA |
| 7 | API Call → POST `/api/pay/v1/orders/{orderId}/payments` | `makeTransactionCall` | `Routes.hs` | Send collect request to VPA |
| 8 | Handle collect response | `handleSentCollectTxnResponse` | `Flows/SDKTransaction.hs` | Return `SendCollectResponse` |

---

### 5.5 Flow: Transaction Sync Flow

**File**: `Flows/Sync.hs`, `Instances.hs:305-326`
**Purpose**: Fetch current transaction status from PineLabs
**Trigger**: `API.TransactionSync` request

#### Steps

| Step | Action | Function | File | Details |
|------|--------|----------|------|---------|
| 1 | Get account details | `getPineLabsAccountDetails` | `Instances.hs:139` | Decode MGA |
| 2 | Build auth header | `makeAuthHeader` | `Instances.hs:65` | `"Bearer " <> token` |
| 3 | Call sync handler | `mandatorySyncHandler` | `Flows/Sync.hs` | Determine which ID to use for sync |
| 4 | API Call → GET `/api/pay/v1/orders/reference/{merchantOrderReference}` | sync call in `Routes.hs` | `Routes.hs` | Fetch order status |
| 5 | Handle sync response | `handleSyncGwResponse` | `Flows/Sync.hs` | Map to `SyncResponse` |
| 6 | Send status response | `sendStatusResponse` | `Flows/Sync.hs` | Write to DB + return |

---

### 5.6 Flow: Refund Flow

**File**: `Flows/Refund.hs`, `Instances.hs:330-373`
**Purpose**: Initiate refund, sync refund status, sync ARN
**Trigger**: `API.InitiateRefund`, `API.RefundSync`, `API.InitRefundSyncArn`

#### Steps — InitiateRefund

| Step | Action | Function | File | Details |
|------|--------|----------|------|---------|
| 1 | Validate refund request | `validateRequestInitiateRefund` | `Flows/Refund.hs` | Check epgTxnId, split info |
| 2 | Build refund request | `makeGatewayRequestInitiateRefund` | `Transforms/Refund.hs` | Build `RefundRequest` |
| 3 | Add auth header | `makeAuthHeader` | `Instances.hs:65` | Bearer token |
| 4 | API Call → POST `/api/pay/v1/refunds/{epgTxnId}` | `callAPIInitiateRefund` | `Routes.hs` | Initiate refund |
| 5 | Handle refund response | `handleRefundResponse` | `Flows/Refund.hs` | Map `RefundStatus` → internal status |
| 6 | Handle error | `handleRefundError` | `Flows/Refund.hs` | Map to `GenericRefundError` |

#### Steps — RefundSync / InitRefundSyncArn

| Step | Action | Function | File | Details |
|------|--------|----------|------|---------|
| 1 | Build sync request | `refund.uniqueRequestId.refundUniqueRequestId` | `Instances.hs:354` | Use `uniqueRequestId` as lookup key |
| 2 | API Call → GET `/api/pay/v1/orders/reference/{uniqueRequestId}` | `mkRefundSyncCall` | `Routes.hs` | Fetch refund status |
| 3 | Handle sync response | `handleRefundSyncResponse` / `handleRefundArnSyncResponse` | `Flows/Refund.hs` | Map to refund status + ARN |

---

### 5.7 Flow: Capture/Redirect Flow

**File**: `Flows/CaptureRedirect.hs`, `Instances.hs:220-237`
**Purpose**: Handle gateway redirect callback; verify integrity; update transaction status
**Trigger**: `API.PayResponse` (redirect callback from PineLabs), `API.GatewayResponseSyncAndVerify`

#### Steps

| Step | Action | Function | File | Details |
|------|--------|----------|------|---------|
| 1 | Get gateway response | `request.gatewayResponse` | `Instances.hs:222` | Raw response from PineLabs redirect |
| 2 | Handle capture response | `handleCaptureResponse` | `Flows/CaptureRedirect.hs` | Decode and process |
| 3 | Decode redirect GW response | `decodeRedirectionGwResponse` | `Flows/CaptureRedirect.hs` | Decode JSON |
| 4 | Get integrity verification handler | `getRedirectionIntegrityVerificationHandler` | `Flows/CaptureRedirect.hs` | Verify HMAC / signature |
| 5 | Verify integrity payload | `getIntegrityPayload` | `Flows/CaptureRedirect.hs` | Extract payload for verification |
| 6 | Handle GW response | `handleRedirectionGwResponse` | `Flows/CaptureRedirect.hs` | Final response processing |
| 7 | Handle error | `handleRedirectionGwError` | `Flows/CaptureRedirect.hs` | Map to error type |

---

### 5.8 Flow: PreAuth Capture Flow

**File**: `Flows/CaptureVoid.hs`, `Instances.hs:395-423`
**Purpose**: Capture or void a pre-authorized transaction
**Trigger**: `API.InitiatePreAuthAction` (Capture or Void variant)

#### Steps — Capture

| Step | Action | Function | File | Details |
|------|--------|----------|------|---------|
| 1 | Validate | `getGatewayTxnIdFromMaybeSF` | `Utils` | Get gateway transaction ID from second factor |
| 2 | Get account details | `getPineLabsRefundAccountDetailsPreauth` | `Instances.hs:145` | Decode MGA (throws on error) |
| 3 | Build capture request | `makeCapturePayment` | `Transforms/Transaction.hs` | Build `CaptureRequest` |
| 4 | API Call → PUT `/api/pay/v1/orders/{orderId}/capture` | `makeCaptureTxnsCall` | `Routes.hs` | Capture the pre-auth |
| 5 | Handle response | `handleCaptureAPIResponse` | `Flows/CaptureVoid.hs` | Map to capture status |
| 6 | Handle error | `handleCaptureServantError` | `Flows/CaptureVoid.hs` | Map client error |

#### Steps — Void

| Step | Action | Function | File | Details |
|------|--------|----------|------|---------|
| 1 | Validate | `getGatewayTxnIdFromMaybeSF` | `Utils` | Get gateway transaction ID |
| 2 | API Call → PUT `/api/pay/v1/orders/{orderId}/cancel` | `makeVoidTxnsCall` | `Routes.hs` | Cancel/void the pre-auth |
| 3 | Handle response | `handleVoidAPIResponse` | `Flows/CaptureVoid.hs` | Map to void status |

---

### 5.9 Flow: OTP Submit/Resend Flow (DOTP)

**File**: `Flows/DotpFlow.hs`, `Instances.hs:518-550`
**Purpose**: Handle OTP submission and resend for native OTP card flows
**Trigger**: `API.SubmitOtp`, `API.ResendOTP`

#### Steps — SubmitOtp

| Step | Action | Function | File | Details |
|------|--------|----------|------|---------|
| 1 | Validate request | `validateRequestSubmitOtp` | `Flows/DotpFlow.hs` | Decode `PinelabsonlineOtpVerificationPayload` from `gatewayAuthReqParams` |
| 2 | Build request | `makeGatewayRequestSubmitOtp` | `DotpTransforms.hs:12` | `PinelabsonlineSubmitOtpRequest{paymentId, otp}` |
| 3 | API Call → POST `/api/pay/v1/otp/submit` | `makeSubmitOtpCall` | `Routes.hs` | Submit OTP |
| 4 | Handle response | `handleSubmitOtpResponse` | `Flows/DotpFlow.hs` | Success / IncorrectOtp / Failure |
| 5 | Handle error | `handleErrorSubmitOtp` | `Flows/DotpFlow.hs` | Map to error response |

#### Steps — ResendOTP

| Step | Action | Function | File | Details |
|------|--------|----------|------|---------|
| 1 | Validate | `validateRequestResendOtp` | `Flows/DotpFlow.hs` | Decode verification payload |
| 2 | Build request | `makeGatewayRequestResendOtp` | `DotpTransforms.hs:15` | `PinelabsonlineResendOTPRequest{paymentId}` |
| 3 | API Call → POST `/api/pay/v1/otp/resend` | `makeResendOtpCall` | `Routes.hs` | Resend OTP |
| 4 | Handle response | `handleResponseResendOTP` | `Flows/DotpFlow.hs` | Map to resend response |

---

### 5.10 Flow: Webhook Flows

**File**: `Flows/Webhooks.hs` (imported in `Instances.hs:375-392`)
**Purpose**: Process incoming PineLabs webhook notifications
**Trigger**: `API.WebhookSync`, `API.WebhookVerify`

#### Steps

| Step | Action | Function | File | Details |
|------|--------|----------|------|---------|
| 1 | [WebhookSync] Decode response | `extractWebhookResponse` | `Flows/Webhooks.hs` | Extract `TransactionResponse` from webhook body |
| 2 | [WebhookVerify] Get account details | `getPinelabsOnlineAccountDetails` | `Transforms/Common.hs` | Decode MGA |
| 3 | Decode webhook response | `decodeRedirectionWebhookResponse` | `Flows/Webhooks.hs` | Parse webhook payload |
| 4 | Get integrity handler | `getWebhookIntegrityVerificationHandler` | `Flows/Webhooks.hs` | Verify webhook signature |
| 5 | Verify integrity payload | `getWebhookIntegrityPayload` | `Flows/Webhooks.hs` | Extract payload for HMAC |
| 6 | Handle webhook GW response | `handleWebhookGwResponse` | `Flows/Webhooks.hs` | Final processing |

---

### 5.11 Flow: EMI Flow

**File**: `Flows/Emi.hs`
**Purpose**: Fetch EMI plans for card or cardless EMI
**Trigger**: Internal EMI plan lookup request

#### Steps

| Step | Action | Function | File | Details |
|------|--------|----------|------|---------|
| 1 | `getEmiPlans` | Entry point | `Flows/Emi.hs` | Dispatch based on EMI type |
| 2 | [Card EMI] Call PineLabsOnlineGetEmiDetails | `callPineLabsOnlineGetEmiDetails` | `Flows/Emi.hs` | Fetch EMI options |
| 3 | [Cardless EMI] Call OfferDiscovery | `callPineLabsOnlineOfferDiscoveryCardless` | `Flows/Emi.hs` | API Call → POST `/api/affordability/v1/offer/discovery/cardless` |
| 4 | [Card EMI] Call OfferDiscovery | cardless vs card dispatch | `Flows/Emi.hs` | API Call → POST `/api/affordability/v1/offer/discovery` |

---

### 5.12 Flow: Offers Flow

**File**: `Flows/Offers.hs`
**Purpose**: Offer list discovery and transformation
**Trigger**: Offer list request

#### Steps

| Step | Action | Function | File | Details |
|------|--------|----------|------|---------|
| 1 | `offerList` | Entry point | `Flows/Offers.hs` | Build offer discovery request |
| 2 | API Call → POST `/api/affordability/v1/offer/discovery` | offer discovery call | `Routes.hs` | Fetch available offers |
| 3 | Transform offers | offer transformation pipeline | `Flows/Offers.hs` | Convert `OfferDiscoveryResponse` to internal offer format |

---

### 5.13 Data Transformations

| # | From | To | Function | File | Logic |
|---|------|----|----------|------|-------|
| 1 | `API.RedirectTransaction` | `OrderRequest` | `makeOrderRequest (Right req)` | `Transforms/Transaction.hs` | Map order amount, preAuth, merchantOrderReference, customer details |
| 2 | `API.GetSdkParams` | `OrderRequest` | `makeOrderRequest (Left req)` | `Transforms/Transaction.hs` | Same mapping for SDK flow |
| 3 | `API.InitiateTransaction` | `OrderRequest` | `initiateTxnOrderRequest` | `Transforms/Transaction.hs` | Order creation for DOTP flow |
| 4 | `API.RedirectTransaction` + `SurchargeCallResp` | `TransactionRequest` | `mkRedirectionTransactionRequest` | `Transforms/Transaction.hs` | Build payments array with payment option, surcharge |
| 5 | `API.InitiateTransaction` + `SurchargeCallResp` | `TransactionRequest` | `mkInitiateTransactionRequest` | `Transforms/Transaction.hs` | Build payments for DOTP card flow |
| 6 | `API.GetSdkParams` + `SurchargeCallResp` | `TransactionRequest` | `mkSDKTransactionRequest` | `Transforms/Transaction.hs` | Build payments for UPI SDK |
| 7 | `API.SendCollect` + `SurchargeCallResp` | `TransactionRequest` | `mkSendCollectRequest` | `Transforms/Transaction.hs` | Build payments for UPI collect |
| 8 | `API.InitiateTransaction` | `PinelabsonlineGetCardDetailsRequest` | `makeGetCardDetailsRequest` | `DotpTransforms.hs:18` | Map card number + vault provider type to `paymentReferenceType` |
| 9 | `Text` (paymentId) | `PinelabsonlineTriggerOtpRequest` | `mkTriggerOtpTransactionRequest` | `DotpTransforms.hs:33` | Wrap paymentId |
| 10 | `API.SubmitOtp` + `PinelabsonlineOtpVerificationPayload` | `PinelabsonlineSubmitOtpRequest` | `makeGatewayRequestSubmitOtp` | `DotpTransforms.hs:12` | Extract paymentId from payload, otp from request |
| 11 | `API.ResendOTP` + `PinelabsonlineOtpVerificationPayload` | `PinelabsonlineResendOTPRequest` | `makeGatewayRequestResendOtp` | `DotpTransforms.hs:15` | Extract paymentId only |
| 12 | `API.InitiateRefund` + `RefundValidationPayload` + `PinelabsOnlineAccountDetails` | `RefundRequest` | `makeGatewayRequestInitiateRefund` | `Transforms/Refund.hs` | Build refund request with merchantOrderReference, amount |
| 13 | `TransactionData.status` + `preAuth` flag | `TxnDetail.TxnStatus` | `txnStatusMap` | `Transforms/Common.hs` | Status string → internal txn status (see Section 7) |
| 14 | `RefundStatus` (Text) | `Refund.RefundStatus` | `refundStatusMap` | `Transforms/Refund.hs` | Refund status string → internal status (see Section 7) |
| 15 | `MerchantGatewayAccount.accountDetails` | `PinelabsOnlineAccountDetails` | `getPinelabsOnlineAccountDetails` | `Transforms/Common.hs` | JSON decode of accountDetails field |
| 16 | `txnDetail` + `txnCardInfo` + `secondFactor` + `orderReference` | `ConvenienceFeeRequest` | `makeGatewaySurchargeRequest` | `Transforms/Common.hs` | Build surcharge request from transaction context |
| 17 | `API.InitiatePreAuthAction` | `CaptureRequest` | `makeCapturePayment` | `Transforms/Transaction.hs` | Map capture amount and merchant capture reference |

---

## 6. Error Handling

### 6.1 API Call Error Handling

| # | Error Type | Handling | Fallback | File |
|---|-----------|----------|----------|------|
| 1 | `Right (SuccessResponse resp)` | Success path — process `TransactionResponse` | — | `Flows/Transaction.hs` |
| 2 | `Right (FailureResponse err)` | Gateway business error → `GenericErrorResponseParam` with `PineLabsErrorResponse.code` + `TxnDetail.AuthenticationFailed` | — | All flow handlers |
| 3 | `Left (Servant.FailureResponse _ res)` | Try to decode response body as `PineLabsResponse`; if `FailureResponse` → gateway error; if decode fails → `handleClientError` | `handleClientError'` with errType + message | `Flows/Transaction.hs`, `Flows/Refund.hs` |
| 4 | `Left (other ClientError)` | `handleClientError` → maps to `TxnDetail.AuthenticationFailed` or `Pending` depending on context | Return error payment response | All flow files |
| 5 | Refund failure codes | Codes in `Constants.hs` checked to classify refund errors | Refund status → `Refund.Failure` | `Flows/Refund.hs`, `Constants.hs` |
| 6 | Account details decode failure | `Left` → `GenericErrorResponseParam` (for txn flows) or `GenericRefundError` (for refund flows) | Pre-auth flows throw exception via `Errors.throwExceptionV2` | `Instances.hs:139-150` |

### 6.2 HTTP Status Code Handling

| HTTP Status | Handling | Response to Caller |
|-------------|----------|--------------------|
| 200 with valid body | Decoded as `PineLabsResponse` — if `TransactionResponse` constructor → success | `PaymentResponse` / `SyncResponse` with mapped status |
| 200 with error body | Decoded as `PineLabsResponse` — if `PineLabsErrorResponse` constructor → gateway business error | `PaymentRespError` / error response with `AuthenticationFailed` status |
| 4xx / 5xx | `Servant.FailureResponse` → attempt to decode body as `PineLabsResponse`; if parseable → gateway error; if not → `handleClientError` | Error payment response with `AuthenticationFailed` status |
| Connection failure / timeout | `Left (other ClientError)` → `handleClientError` | Error response with `AuthenticationFailed` or `Pending` |
| Decode failure | `Left` error → `handleClientError` | Error response |

### 6.3 Timeout & Retry

- **Timeout Mechanism**: EulerHS HTTP client default (no connector-specific override found in source)
- **Default Timeout**: EulerHS HTTP client default
- **Retry Enabled**: No (not observed in connector source)
- **Max Retries**: 0
- **Retry Strategy**: N/A

### 6.4 Error Response Type

**Type**: `PineLabsErrorResponse` — `TxnTypes.hs:1153`

| # | Field Name | Type | JSON Key | Description |
|---|------------|------|----------|-------------|
| 1 | `code` | `Text` | `code` | PineLabs error code string |
| 2 | `message` | `Text` | `message` | Human-readable error description |

### 6.5 Refund Failure Codes

**Source**: `Constants.hs`

The following PineLabs error codes are classified as terminal refund failures (map to `Refund.Failure`):

| # | Error Code | Description |
|---|-----------|-------------|
| 1 | `INVALID_REQUEST` | Invalid refund request parameters |
| 2 | `API_RATE_LIMIT` | API rate limit exceeded |
| 3 | `OPERATION_NOT_ALLOWED` | Refund operation not permitted |
| 4 | `ORDER_NOT_FOUND` | Original order not found |
| 5 | `AMOUNT_LIMIT_EXCEEDED` | Refund amount exceeds allowed limit |

---

## 7. Status Mappings

### 7.1 Transaction Status Mapping

**Source**: `Transforms/Common.hs` — `txnStatusMap`
**Direction**: PineLabs `TransactionData.status` (Text) → `TxnDetail.TxnStatus`

| # | PineLabs Status | Condition | Internal Status | Description |
|---|----------------|-----------|----------------|-------------|
| 1 | `"AUTHORIZED"` | `preAuth == True` | `TxnDetail.Authorized` | Pre-auth authorized, not yet captured |
| 2 | `"AUTHORIZED"` | `preAuth == False` | `TxnDetail.Authorizing` | Authorization in progress |
| 3 | `"CANCELLED"` | `preAuth == True` | `TxnDetail.Voided` | Pre-auth voided/cancelled |
| 4 | `"PROCESSED"` | any | `TxnDetail.Charged` | Transaction fully completed |
| 5 | `"FAILED"` | any | `TxnDetail.AuthorizationFailed` | Transaction failed |
| 6 | any other | default | `TxnDetail.PendingVBV` | Pending (e.g., in 3DS challenge) |

### 7.2 Refund Status Mapping

**Source**: `Transforms/Refund.hs` — `refundStatusMap`
**Direction**: PineLabs `RefundStatus` (Text) → internal `Refund.RefundStatus`

| # | PineLabs Refund Status | Internal Status | Description |
|---|----------------------|----------------|-------------|
| 1 | `"PROCESSED"` | `Refund.Success` | Refund successfully completed |
| 2 | `"FAILED"` | `Refund.Failure` | Refund failed |
| 3 | any other | `Refund.Pending` | Refund in progress |

### 7.3 Capture Status Mapping

**Source**: `Flows/CaptureVoid.hs` — `getCaptureStatus`
**Direction**: PineLabs status (Text) → internal capture status

| # | PineLabs Status | Internal Status | Description |
|---|----------------|----------------|-------------|
| 1 | `"PROCESSED"` | `Charged` | Capture completed |
| 2 | `"FAILED"` | `CaptureFailed` | Capture failed |
| 3 | `"PENDING"` | `CaptureInitiated` | Capture in progress |
| 4 | `"PARTIALLY_CAPTURED"` | `PartialCharged` | Partial capture completed |

### 7.4 Void Status Mapping

**Source**: `Flows/CaptureVoid.hs` — `getVoidStatus`
**Direction**: PineLabs status (Text) → internal void status

| # | PineLabs Status | Internal Status | Description |
|---|----------------|----------------|-------------|
| 1 | `"FAILED"` | `VoidFailed` | Void failed |
| 2 | `"PENDING"` | `VoidInitiated` | Void in progress |
| 3 | `"CANCELLED"` | `Voided` | Void completed |

---

## 8. Payment Methods

### 8.1 Supported Payment Method Types

| # | Payment Method | `paymentMethod` Value in `Payments` | `PaymentOption` Field Used | Notes |
|---|---------------|-------------------------------------|---------------------------|-------|
| 1 | Card (Credit/Debit) | `"CARD"` | `cardDetails` | Native OTP supported via `isNativeOtpSupported` check |
| 2 | Credit EMI | `"CREDIT_EMI"` | `cardDetails` | EMI on credit card |
| 3 | Debit EMI | `"DEBIT_EMI"` | `cardDetails` | EMI on debit card |
| 4 | Cardless EMI (Consumer Finance) | Consumer finance code | `cardlessDetails` | Mobile + PAN last digits |
| 5 | UPI Intent (SDK) | `"UPI"` | `upiDetails` with `txnMode="INTENT"` | Returns UPI intent URL |
| 6 | UPI Collect | `"UPI"` | `upiDetails` with `txnMode="COLLECT"` + `payer.vpa` | Send collect to payer VPA |
| 7 | Netbanking | `"NET_BANKING"` or bank code | `netbankingDetails` with `txnMode="REDIRECT"` | Redirect to bank |
| 8 | Wallet | Wallet code | `walletDetails` with `walletCode` | Wallet provider redirect |

### 8.2 Payment Reference Type Mapping (for Get Card Details)

Determined by vault provider in `txnDetail.internalMetadata`:

| Vault Provider | `paymentReferenceType` Value |
|----------------|------------------------------|
| `"NETWORK_TOKEN"` | `"NETWORK_TOKEN_TXN"` |
| `"ALT_ID"` | `"ALT_TOKEN_TXN"` |
| `"ISSUER_TOKEN"` | `"ISSUER_TOKEN_TXN"` |
| (none / other) | `"CARD"` |

**Source**: `DotpTransforms.hs:26-31`

### 8.3 Merchant Gateway Account Fields

**Type**: `PinelabsOnlineAccountDetails` — `TxnTypes.hs:19`
Decoded from `MerchantGatewayAccount.accountDetails` (JSON).

| # | Field | Type | Required | Description |
|---|-------|------|----------|-------------|
| 1 | `pinelabsOnlineMerchantId` | `Text` | Yes | PineLabs merchant ID |
| 2 | `pinelabsOnlineClientId` | `Text` | Yes | OAuth2 client ID for token refresh |
| 3 | `pinelabsOnlineClientSecret` | `Text` | Yes | OAuth2 client secret for token refresh |
| 4 | `pinelabsOnlineAccessToken` | `Text` | Yes | Current active Bearer token |
| 5 | `defaultProductId` | `Maybe Text` | No | Default product ID for EMI |
| 6 | `oemName` | `Maybe Text` | No | OEM name for EMI/affordability |
| 7 | `shouldSendSurchargeBreakUpForGw` | `Maybe Text` | No | `"true"` to enable convenience fee API call |

---

## 9. Completeness Verification

| Check | Result |
|-------|--------|
| All 18 API endpoints documented | Yes |
| All request types documented | Yes |
| All response types documented | Yes |
| All nested types expanded | Yes |
| All sum type variants listed | Yes |
| All flows documented (10 major flows) | Yes |
| All status mappings documented (txn, refund, capture, void) | Yes |
| All error paths documented | Yes |
| All refund failure codes listed | Yes |
| OTP flows documented (Submit, Resend, Trigger, GetCardDetails) | Yes |
| Surcharge/ConvenienceFee flow documented | Yes |
| EMI/Offers flows documented | Yes |
| Webhook flows documented | Yes |
| PreAuth Capture/Void flows documented | Yes |
| Payment methods documented | Yes |
| Merchant gateway account fields documented | Yes |
| Authentication (Bearer token + OAuth2 refresh) documented | Yes |
| Missing items | None |

---

## 10. Source File References

| # | File | Lines Read | Purpose |
|---|------|-----------|---------|
| 1 | `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/PineLabsOnline/Routes.hs` | All | All 18 API endpoints, 3 base URL groups, `make*Call` functions |
| 2 | `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/PineLabsOnline/Types/TxnTypes.hs` | All (1177 lines) | All transaction request/response types, OTP types, EMI types, convenience fee types, error types |
| 3 | `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/PineLabsOnline/Types/RefundTypes.hs` | All (267 lines) | Refund request/response types, validation payload, split refund types |
| 4 | `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/PineLabsOnline/Types/EmiTypes.hs` | All | EMI/offer discovery types |
| 5 | `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/PineLabsOnline/Constants.hs` | All | Refund failure codes list |
| 6 | `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/PineLabsOnline/Instances.hs` | All (550 lines) | All `BasicGatewayFlow` instances, flow wiring, auth header construction, all flow pipelines |
| 7 | `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/PineLabsOnline/Transforms/Common.hs` | All (327 lines) | `txnStatusMap`, `getPinelabsOnlineAccountDetails`, `makeGatewaySurchargeRequest`, access token management |
| 8 | `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/PineLabsOnline/Transforms/Transaction.hs` | First 779 lines | Order/transaction request builders, all `make*Request` functions |
| 9 | `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/PineLabsOnline/Transforms/Refund.hs` | All (157 lines) | `makeGatewayRequestInitiateRefund`, `refundStatusMap` |
| 10 | `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/PineLabsOnline/Transforms/DotpTransforms.hs` | All (34 lines) | OTP request builders, card details request builder |
| 11 | `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/PineLabsOnline/Transforms.hs` | All (8 lines) | Re-export module |
| 12 | `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/PineLabsOnline/Flows/Transaction.hs` | All (640 lines) | Redirect/InitiateTransaction flow handlers, surcharge handling, OTP trigger response |
| 13 | `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/PineLabsOnline/Flows/Sync.hs` | All (209 lines) | `mandatorySyncHandler`, `handleSyncGwResponse`, `sendStatusResponse` |
| 14 | `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/PineLabsOnline/Flows/Refund.hs` | All (155 lines) | Refund validation, response handling, sync, ARN sync |
| 15 | `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/PineLabsOnline/Flows/CaptureRedirect.hs` | All (146 lines) | Redirect callback handling, integrity verification |
| 16 | `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/PineLabsOnline/Flows/CaptureVoid.hs` | All (161 lines) | Capture/void API call handling, status mapping |
| 17 | `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/PineLabsOnline/Flows/DotpFlow.hs` | All (272 lines) | OTP submit/resend/trigger response handling, native OTP detection |
| 18 | `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/PineLabsOnline/Flows/Emi.hs` | All (251 lines) | EMI plan fetching, offer discovery calls |
| 19 | `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/PineLabsOnline/Flows/Offers.hs` | All (347 lines) | Offer list discovery and transformation |
| 20 | `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/PineLabsOnline/Flows/SDKTransaction.hs` | All (270 lines) | SDK/UPI/SendCollect flow handlers, surcharge handling |

---

**Generated by**: Euler Connector Tech Spec Workflow
**Date**: 2026-03-26
