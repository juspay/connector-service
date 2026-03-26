# CRED — Technical Specification

> **Connector**: CRED
> **Direction**: gateway-outbound (gateway calls CRED's external APIs — gateway acts as HTTP client)
> **Endpoint**: Multiple (see Section 3)
> **Purpose**: CRED wallet/UPI/Card payments — eligibility check, order creation, refund, status sync, webhook verification, DIP (Device Instrument Provider) flows
> **Generated**: 2026-03-26

---

## 1. Connector Overview

### 1.1 Basic Information

- **Connector ID**: CRED
- **Direction**: euler-api-gateway → CRED external APIs (dreamplug.in)
- **HTTP Methods**: POST, GET
- **Protocol**: HTTP REST (synchronous)
- **Content Type**: application/json
- **Architecture**: Haskell (Servant + Warp)
- **Gateway Dir**: `gateway/src/Euler/API/Gateway/Gateway/CRED/`

### 1.2 Base URL Configuration

CRED exposes two base URL functions depending on flow type.

#### credBaseUrl (legacy checkout/refund/status flows)

| Environment | Host | Port | Scheme | Base Path |
|-------------|------|------|--------|-----------|
| Sandbox | `merchant-app-stg.dreamplug.in` | 443 | HTTPS | `heimdall/public/v2/partner` |
| Production | `merchant-app-prod.dreamplug.in` | 443 | HTTPS | `heimdall/public/v2/partner` |

**Selection**: `credBaseUrl isSandbox` — boolean flag determines sandbox vs prod.

#### credBaseUrlNew (DIP / eligibility / V1 order flows)

| Flags | Host | Base Path |
|-------|------|-----------|
| `isSandbox=True`, `isCredDevice=True` OR `useNonNativeUrl=True` | `merchant-app-stg.dreamplug.in` | `"payment-app"` or `""` |
| `isSandbox=True`, native (not nonNative) | `api-stage.dreamplug.in` | `"payment-app"` or `""` |
| `isSandbox=False`, `useNonNativeUrl=True` | `api.dreamplug.in` | `"payment-app"` or `""` |
| `isSandbox=False`, `isCredDevice=True` (native) | `merchant-app-prod.dreamplug.in` | `"payment-app"` or `""` |

**Base path**: `"payment-app"` if `shouldAddPaymentOptions=True`, else `""`.

**URL Resolution Logic**: `isSandbox` flag is derived from merchant gateway account configuration. `isCredDevice` / `useNonNativeUrl` / `shouldAddPaymentOptions` are flow-specific flags resolved in `Flows.hs` based on payment flow type (Container vs NonNative).

**Timeout Configuration**:
- **Custom Timeout Header**: Not specified in source; uses default HTTP client timeout
- **Per-Merchant Override**: Not observed in source

**File reference**: `gateway/src/Euler/API/Gateway/Gateway/CRED/Routes.hs:1–363`

---

## 2. Authentication

### 2.1 Authentication Methods

CRED uses **two distinct auth mechanisms** depending on the API endpoint:

| Mechanism | Applies To | Method |
|-----------|-----------|--------|
| API Key Headers | Checkout, Refund, Status APIs | `X-Merchant-Client-Id` + `X-Merchant-Client-Secret` headers (plaintext) |
| HTTP Basic Auth | Rewards, DIP, Eligibility APIs | `Authorization: Basic <base64(clientId:clientSecret)>` |

### 2.2 Authentication Flow

**For checkout/refund/status APIs (API Key Headers):**
1. Decode `MerchantGatewayAccount.accountDetails` as `CredAccountDetails`
2. Extract `credClientId` and `credClientSecret`
3. Attach as `X-Merchant-Client-Id` and `X-Merchant-Client-Secret` HTTP headers

**For rewards/DIP/eligibility APIs (Basic Auth):**
1. Decode `MerchantGatewayAccount.accountDetails` as `CredAccountDetails` (or for in-app offer flows, read env vars `JUSPAY_CRED_CLIENT_SECRET` and `JUSPAY_CRED_CLIENT_ID`)
2. Construct `BasicAuthData` from clientId + clientSecret (UTF-8 encoded)
3. Call `createBasicAuthHeader clientId clientSecret` — produces standard `Authorization: Basic <base64>` header

### 2.3 Required Headers

| # | Header Name | Value / Source | Required | Description |
|---|-------------|----------------|----------|-------------|
| 1 | `X-Merchant-Client-Id` | `CredAccountDetails.credClientId` | Yes (checkout/refund/status APIs) | Merchant client identifier |
| 2 | `X-Merchant-Client-Secret` | `CredAccountDetails.credClientSecret` | Yes (checkout/refund/status APIs) | Merchant client secret |
| 3 | `Authorization` | `Basic <base64(clientId:clientSecret)>` | Yes (rewards/DIP/eligibility APIs) | HTTP Basic Auth header |
| 4 | `X-Request-Id` | UUID generated per request | Yes | Unique request identifier |
| 5 | `X-Business-Partner-Id` | `CredAccountDetails.businessPartnerId` | No (optional) | Business partner identifier |
| 6 | `X-Merchant-ID` | `CredAccountDetails.credMerchantId` | No (optional) | Merchant identifier |
| 7 | `Content-Type` | `application/json` | Yes | Request body encoding |

**Credential source types:**
- `CredAccountDetails` from `MerchantGatewayAccount.accountDetails` (primary)
- `DeviceTokenCredentials` from `MerchantGatewayAccount.accountDetails` (DIP flow)
- Env vars `JUSPAY_CRED_CLIENT_ID` / `JUSPAY_CRED_CLIENT_SECRET` (in-app offer webhook flows)

**File references**: `Routes.hs`, `Types.hs:720–748`, `Transforms.hs`

---

## 3. Request Structure

### 3.1 API Endpoints (CREDAPIs servant type)

| # | Method | Path | Request Type | Response Type | Flow |
|---|--------|------|--------------|---------------|------|
| 1 | POST | `/checkout` | `CheckoutRequest` | `CommonResponse CheckoutResponseData` | Eligibility check / order creation |
| 2 | POST | `/refund` | `RefundRequest` | `CommonResponse RefundResponseData` | Standard refund |
| 3 | GET | `/status/{tracking_id}` | — (path param) | `CommonResponse OrderStatusResponseData` | Order status |
| 4 | POST | `/v1/rewards/actions/upi_plugin_payment_completed/nudge` | `RewardsRequest` | `RewardsResponseData` | Rewards eligibility nudge |
| 5 | POST | `/v1/rewards/actions/upi_plugin_payment_completed/allot` | `AllotRequest` | `AllotResponse` | Offer allotment |
| 6 | POST | `/v1/rewards/actions/nudges/batch-get` | `GenericRewardsRequest` | `GenericRewardsResponseData` | Batch rewards eligibility |
| 7 | POST | `/v1/orders` | `DeviceTokenOrdCreateReq` | `DeviceTokenOrdCreateResp` | DIP order creation |
| 8 | POST | `/payment-app/v1/oauth2/token` | `AuthTokenReqEnum` | `AuthTokenRespEnum` | Auth token / access token |
| 9 | POST | `/v1/payment-options` | `EligibilityReq` | `PaymentOptionsResponseEnum` | Eligibility DIP |
| 10 | GET | `/v1/orders/{order_id}` | — (path param) | `SyncRespV1Order` | V1 order status sync |
| 11 | POST | `/v1/orders/{order_id}/refunds` | `V1RefundRequest` | `RefundResponseV1` / `RefundSync` | V1 refund |

**File reference**: `Routes.hs:1–363`

### 3.2 CheckoutRequest — `Types.hs:236`

Used for: eligibility check and order creation (endpoint 1).

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | trackingId | Text | `tracking_id` | Yes | Order/transaction tracking ID |
| 2 | agent | Agent | `agent` | Yes | Device/platform info (platform, os, device) |
| 3 | user | User | `user` | Yes | User identity (phone/hashed phone) |
| 4 | credAppPresent | Bool | `cred_app_present` | Yes | Whether CRED app is installed on device |
| 5 | persistEligibility | Bool | `persist_eligibility` | Yes | Whether to persist eligibility result |
| 6 | merchant | Maybe Merchant | `merchant` | No | Merchant order and amount details |
| 7 | redirectUrl | Maybe Text | `redirect_url` | No | Redirect URL after payment |
| 8 | metadata | Maybe Value | `metadata` | No | Arbitrary JSON metadata |
| 9 | paymentMethodType | Maybe [Text] | `payment_method_type` | No | List of allowed payment method types |

**Field Count**: 9 fields

### 3.3 RefundRequest — `Types.hs:496`

Used for: standard refund (endpoint 2).

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | trackingId | Text | `tracking_id` | Yes | Original order tracking ID |
| 2 | refundTrackingId | Text | `refund_tracking_id` | Yes | Unique refund tracking ID |
| 3 | amount | Amount | `amount` | Yes | Refund amount with currency |
| 4 | reason | Maybe Text | `reason` | No | Refund reason text |
| 5 | refundFees | Bool | `refund_fees` | Yes | Whether to refund fees |
| 6 | metadata | RefundMetadata | `metadata` | Yes | Refund metadata (refund type) |

**Field Count**: 6 fields

### 3.4 V1RefundRequest — `Types.hs:1521`

Used for: V1 refund (endpoint 11).

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | refund_reference_id | Text | `refund_reference_id` | Yes | Unique refund reference ID |
| 2 | amount | Integer | `amount` | Yes | Refund amount in smallest currency unit |
| 3 | reason | Text | `reason` | Yes | Refund reason |
| 4 | currency | Text | `currency` | Yes | Currency code (e.g., "INR") |
| 5 | udfs | Maybe V1RefundUdfs | `udfs` | No | User-defined fields |
| 6 | refund_fees | Text | `refund_fees` | Yes | Whether to refund fees ("R" or "C") |

**Field Count**: 6 fields

### 3.5 DeviceTokenOrdCreateReq — `Types.hs:842`

Used for: DIP order creation (endpoint 7).

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | order_reference_id | Text | `order_reference_id` | Yes | Juspay order reference ID |
| 2 | merchant_details | Maybe MerchantData | `merchant_details` | No | Merchant name, logo, MID |
| 3 | amount | Double | `amount` | Yes | Order amount |
| 4 | currency | Text | `currency` | Yes | Currency code |
| 5 | payment_filter | Maybe PaymentFilterType | `payment_filter` | No | Card/non-native filter |
| 6 | device_context | DeviceContext | `device_context` | Yes | Device platform/OS/device info |
| 7 | return_url | Text | `return_url` | Yes | Return URL after payment |
| 8 | juspay_metadata | Maybe Juspay | `juspay.metadata` | No | Juspay order/auth metadata |
| 9 | user_identifier | TypeAndValue | `user_identifier` | Yes | User identifier (type + value) |
| 10 | flow_type | FlowType | `flow_type` | Yes | ACQUIRED / NON_ACQUIRED / AS_ISSUER |

**Field Count**: 10 fields

### 3.6 EligibilityReq — `Types.hs:1123`

Used for: eligibility DIP (endpoint 9).

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | device_context | DeviceContext | `device_context` | Yes | Device platform/OS/device info |
| 2 | user_identifier | TypeAndValue | `user_identifier` | Yes | User identifier |
| 3 | amount | Integer | `amount` | Yes | Order amount |
| 4 | currency | Text | `currency` | Yes | Currency code |
| 5 | payment_options_preference | Maybe PaymentOptPref | `payment_options_preference` | No | Payment options preference |
| 6 | redirect_url | Maybe Text | `redirect_url` | No | Redirect URL |
| 7 | return_url | Maybe Text | `return_url` | No | Return URL |

**Field Count**: 7 fields

### 3.7 RewardsRequest — `Types.hs:319`

Used for: rewards eligibility nudge (endpoint 4).

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | user | RewardsUser | `user` | Yes | User token (type + value) |
| 2 | metadata | Maybe Value | `metadata` | No | Arbitrary JSON metadata |

**Field Count**: 2 fields

### 3.8 AllotRequest — `Types.hs:412`

Used for: offer allotment (endpoint 5).

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | idempotencyId | Text | `idempotency_id` | Yes | Idempotency key |
| 2 | user | RewardsUser | `user` | Yes | User token |
| 3 | metadata | Value | `metadata` | Yes | Offer metadata (required, not optional) |

**Field Count**: 3 fields

### 3.9 GenericRewardsRequest — `Types.hs:362`

Used for: batch rewards eligibility (endpoint 6).

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | user | RewardsUser | `user` | Yes | User token |
| 2 | actions | [ActionIndentifier] | `actions` | Yes | List of action identifiers |

**Field Count**: 2 fields

### 3.10 AuthTokenReq — `Types.hs:978`

Used for: auth token (endpoint 8, authorization code flow).

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | grant_type | Text | `grant_type` | Yes | OAuth2 grant type (e.g., "authorization_code") |
| 2 | code | Text | `code` | Yes | Authorization code |
| 3 | redirect_uri | Text | `redirect_uri` | Yes | Redirect URI |
| 4 | code_verifier | Text | `code_verifier` | Yes | PKCE code verifier |

**Field Count**: 4 fields

### 3.11 RefreshTokenReq — `Types.hs:987`

Used for: auth token (endpoint 8, refresh token flow).

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | grant_type | Text | `grant_type` | Yes | OAuth2 grant type ("refresh_token") |
| 2 | redirect_uri | Text | `redirect_uri` | Yes | Redirect URI |
| 3 | refresh_token | Text | `refresh_token` | Yes | OAuth2 refresh token |

**Field Count**: 3 fields

### 3.12 Nested Request Types

#### Agent — `Types.hs:110`
Used in: `CheckoutRequest.agent`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | platform | Platform | `platform` | Yes | APP / WEB / UNKNOWN_PLATFORM |
| 2 | os | OS | `os` | Yes | ANDROID / IOS / WINDOWS / LINUX / MACOS / UNKNOWN_OS |
| 3 | device | Device | `device` | Yes | MOBILE / IPAD / DESKTOP / TABLET / UNKNOWN_DEVICE |

#### User — `Types.hs:135`
Used in: `CheckoutRequest.user`, `OrderStatusResponseData.user`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | countryCode | Maybe CountryCode | `country_code` | No | "+91" for INDIA |
| 2 | phoneNumber | Maybe Text | `phone_number` | No | User phone number |
| 3 | userId | Maybe Text | `user_id` | No | User identifier |
| 4 | hashedPhoneNumber | Maybe Text | `hashed_phone_number` | No | Hashed phone for privacy |

#### Merchant — `Types.hs:189`
Used in: `CheckoutRequest.merchant`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | offerDetails | OfferDetails | `offer_details` | Yes | Whether offers applied |
| 2 | orderId | Text | `order_id` | Yes | Merchant order ID |
| 3 | amount | Amount | `amount` | Yes | Order amount |

#### Amount — `Types.hs:164`
Used in: `CheckoutRequest`, `RefundRequest`, `PaymentMode`, `OrderStatusResponseData`, etc.

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | currency | Currency | `currency` | Yes | INR or OFFER |
| 2 | value | Double | `value` | Yes | Numeric amount |

#### RefundMetadata — `Types.hs:513`
Used in: `RefundRequest.metadata`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | refundType | Maybe Text | `refund_type` | No | "R" (surcharge refund) or "C" (cashback refund) |

#### DeviceContext — `Types.hs:1135`
Used in: `DeviceTokenOrdCreateReq.device_context`, `EligibilityReq.device_context`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | platform | Platform | `platform` | Yes | Device platform |
| 2 | os | OS | `os` | Yes | Operating system |
| 3 | device | Device | `device` | Yes | Device type |
| 4 | is_user_logged_in | Bool | `is_user_logged_in` | Yes | Whether user is logged into CRED |
| 5 | is_cred_app_present | Bool | `is_cred_app_present` | Yes | Whether CRED app is installed |
| 6 | device_id | Maybe Text | `device_id` | No | Device identifier |
| 7 | manufacturer | Manufacturer | `manufacturer` | Yes | Device manufacturer |
| 8 | model | Maybe Text | `model` | No | Device model name |

#### TypeAndValue — `Types.hs:1205`
Used in: `DeviceTokenOrdCreateReq.user_identifier`, `EligibilityReq.user_identifier`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | value_type | Text | `type` | Yes | Identifier type (e.g., "phone", "hashed_phone") |
| 2 | value | Text | `value` | Yes | Identifier value |

#### RewardsUser — `Types.hs:293`
Used in: `RewardsRequest.user`, `AllotRequest.user`, `GenericRewardsRequest.user`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | token | Token | `token` | Yes | User token (type + value) |

#### Token — `Types.hs:274`
Used in: `RewardsUser.token`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | userType | Text | `type` | Yes | Token type |
| 2 | userValue | Text | `value` | Yes | Token value |

#### ActionIndentifier — `Types.hs:375`
Used in: `GenericRewardsRequest.actions`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | action_identifier | Text | `action_identifier` | Yes | Action identifier string |
| 2 | metadata | Maybe Value | `metadata` | No | Action-specific metadata |

#### MerchantData — `Types.hs:869`
Used in: `DeviceTokenOrdCreateReq.merchant_details`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | name | Maybe Text | `name` | No | Merchant display name |
| 2 | logo_url | Maybe Text | `logo_url` | No | Merchant logo URL |
| 3 | mid | Text | `mid` | Yes | Merchant ID |

#### Juspay — `Types.hs:862`
Used in: `DeviceTokenOrdCreateReq.juspay_metadata` (JSON key: `juspay.metadata`)

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | order_id | Text | `order_id` | Yes | Juspay order ID |
| 2 | auth_code | Text | `auth_code` | Yes | Authorization code |

#### V1RefundUdfs — `Types.hs:1532`
Used in: `V1RefundRequest.udfs`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | refund_fees | Maybe Text | `refund_fees` | No | Refund fees flag |

#### PaymentOptPref — `Types.hs:1216`
Used in: `EligibilityReq.payment_options_preference`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | payment_opt_Pref_type | Text | `type` | Yes | Preference type |
| 2 | brands | [Text] | `brands` | Yes | List of brand preferences |

#### CreateContainerReq — `Types.hs:1381`
Used for: pre-transaction container creation (auth token exchange)

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | grant_type | Text | `grant_type` | Yes | OAuth2 grant type |
| 2 | code | Text | `code` | Yes | Authorization code |
| 3 | code_verifier | Text | `code_verifier` | Yes | PKCE code verifier |
| 4 | redirect_uri | Text | `redirect_uri` | Yes | Redirect URI |

---

## 4. Response Structure

### 4.1 CommonResponse — `Types.hs:704`

Wraps checkout, refund, and status API responses.

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | status | ResponseStatus | `status` | Yes | OK / BAD_REQUEST / INTERNAL_SERVER_ERROR |
| 2 | response | Maybe a | `response` | No | Payload (CheckoutResponseData, RefundResponseData, or OrderStatusResponseData) |
| 3 | errorCode | Maybe Text | `error_code` | No | Machine-readable error code |
| 4 | errorMessage | Maybe Text | `error_message` | No | Human-readable error message |
| 5 | errorDescription | Maybe Text | `error_description` | No | Detailed error description |

**Field Count**: 5 fields

### 4.2 CheckoutResponseData — `Types.hs:256`

Payload inside `CommonResponse` for checkout/eligibility.

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | trackingId | Text | `tracking_id` | Yes | Echoed tracking ID |
| 2 | referenceId | Maybe Text | `reference_id` | No | CRED internal reference ID |
| 3 | state | CheckoutState | `state` | Yes | ELIGIBLE/INELIGIBLE/ORDER_CREATED/FLOW_TRIGGERED |
| 4 | checkoutMode | Maybe CheckoutMode | `checkout_mode` | No | intent / collect / web |
| 5 | intentUrl | Maybe Text | `intent_url` | No | Deep link URL for CRED app intent |
| 6 | webUrl | Maybe Text | `web_url` | No | Web checkout URL |
| 7 | layout | Maybe Layout | `layout` | No | UI layout data |

**Field Count**: 7 fields

### 4.3 OrderStatusResponseData — `Types.hs:649`

Payload inside `CommonResponse` for status/sync.

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | trackingId | Text | `tracking_id` | Yes | Order tracking ID |
| 2 | referenceId | Text | `reference_id` | Yes | CRED reference ID |
| 3 | state | OrderState | `state` | Yes | Order state |
| 4 | amount | Amount | `amount` | Yes | Order amount |
| 5 | paymentModes | Maybe [PaymentMode] | `payment_modes` | No | Payment modes used |
| 6 | refunds | Maybe [Refund] | `refunds` | No | Refund records |
| 7 | user | Maybe User | `user` | No | User details |
| 8 | providerRefId | Maybe Text | `provider_ref_id` | No | Provider reference ID |
| 9 | error_message | Maybe Text | `error_message` | No | Error message |
| 10 | surcharge | Maybe Amount | `surcharge` | No | Surcharge amount |

**Field Count**: 10 fields

### 4.4 RefundResponseData — `Types.hs:595`

Payload inside `CommonResponse` for standard refund.

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | refundTrackingId | Text | `refund_tracking_id` | Yes | Refund tracking ID |
| 2 | refundReferenceId | Text | `refund_reference_id` | Yes | CRED refund reference ID |
| 3 | state | OrderState | `state` | Yes | Refund state |
| 4 | amount | Amount | `amount` | Yes | Refund amount |
| 5 | refundModes | Maybe [PaymentMode] | `refund_modes` | No | Refund payment modes |

**Field Count**: 5 fields

### 4.5 SyncRespV1Order — `Types.hs:1416`

Response for V1 order status (endpoint 10).

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | order_id | Text | `order_id` | Yes | CRED order ID |
| 2 | reference_id | Text | `reference_id` | Yes | Juspay reference ID |
| 3 | amount | Integer | `amount` | Yes | Order amount |
| 4 | amount_paid | Integer | `amount_paid` | Yes | Amount actually paid |
| 5 | offer_amount | Integer | `offer_amount` | Yes | Offer/cashback amount |
| 6 | status | OrderState | `status` | Yes | Order status |
| 7 | payment_methods | Maybe [Text] | `payment_methods` | No | Payment method names used |
| 8 | offers | [OffersSync] | `offers` | Yes | List of offers applied |
| 9 | refunds | Maybe [RefundSync] | `refunds` | No | Refund records |
| 10 | card | Maybe CardInfoSync | `card` | No | Card details |
| 11 | created_at | Maybe Text | `created_at` | No | Order creation timestamp |
| 12 | updated_at | Maybe Text | `updated_at` | No | Last update timestamp |

**Field Count**: 12 fields

### 4.6 DeviceTokenOrdCreateResp — `Types.hs:922`

Response for DIP order creation (endpoint 7). Untagged union.

| Variant | Type | Description |
|---------|------|-------------|
| Success | `DeviceTokenOrdSResp` | Order created successfully |
| Failure | `ErrorRespDIP` | Error response |

#### DeviceTokenOrdSResp — `Types.hs:934`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | order_id | Text | `order_id` | Yes | CRED order ID |
| 2 | order_reference_id | Maybe Text | `order_reference_id` | No | Juspay reference ID |
| 3 | amount | Maybe Int | `amount` | No | Order amount |
| 4 | status | Text | `status` | Yes | Order status text |
| 5 | next_action | NextAction | `next_action` | Yes | Next action with redirect params |

### 4.7 AuthTokenResp — `Types.hs:1016`

Success response for auth/refresh token (endpoint 8).

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | access_token | Text | `access_token` | Yes | OAuth2 access token |
| 2 | token_type | Text | `token_type` | Yes | Token type (e.g., "Bearer") |
| 3 | expires_in | Integer | `expires_in` | Yes | Token expiry in seconds |
| 4 | refresh_token | Maybe Text | `refresh_token` | No | OAuth2 refresh token |
| 5 | scope | Text | `scope` | Yes | OAuth2 scope |

**Field Count**: 5 fields

### 4.8 RewardsResponseData — `Types.hs:332`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | state | CheckoutState | `state` | Yes | ELIGIBLE / INELIGIBLE / etc. |
| 2 | layout | Maybe RewardsLayout | `layout` | No | Reward nudge layout |
| 3 | errorCode | Maybe Text | `error_code` | No | Error code |
| 4 | information | Maybe Text | `information` | No | Informational message |
| 5 | message | Maybe Text | `message` | No | Human-readable message |

**Field Count**: 5 fields

### 4.9 AllotResponse — `Types.hs:426`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | status | Text | `status` | Yes | Allotment status |
| 2 | errorCode | Maybe Text | `error_code` | No | Error code |
| 3 | message | Maybe Text | `message` | No | Human-readable message |

**Field Count**: 3 fields

### 4.10 PaymentOptionsResponse — `Types.hs:1239`

Success response for eligibility DIP (endpoint 9).

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | payment_options | PaymentOptions | `payment_options` | Yes | Card options, offers, container options |

#### PaymentOptions — `Types.hs:1252`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | card | CardOptions | `card` | Yes | Card eligibility state and instruments |
| 2 | offers | Maybe [Offer] | `offers` | No | Available offers |
| 3 | container | Maybe ContainerOptions | `container` | No | Container (CRED wallet) options |

### 4.11 Nested Response Types

#### PaymentMode — `Types.hs:538`
Used in: `OrderStatusResponseData.paymentModes`, `RefundResponseData.refundModes`, `Refund.refundModes`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | amount | Amount | `amount` | Yes | Payment mode amount |
| 2 | fundingSource | Maybe FundingSource | `funding_source` | No | Merchant vs others split |
| 3 | bank_reference_id | Maybe Text | `bank_reference_id` | No | Bank reference ID |
| 4 | arn | Maybe Text | `arn` | No | Acquirer reference number |
| 5 | gateway_reference_id | Maybe Text | `gateway_reference_id` | No | Gateway reference ID |
| 6 | card | Maybe CardData | `card` | No | Card details |
| 7 | upi | Maybe UpiData | `upi` | No | UPI details |
| 8 | reward | Maybe Reward | `reward` | No | Reward/points details |
| 9 | _type | Maybe Text | `type` | No | Payment mode type |

#### Refund — `Types.hs:632`
Used in: `OrderStatusResponseData.refunds`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | refundTrackingId | Text | `refund_tracking_id` | Yes | Refund tracking ID |
| 2 | refundReferenceId | Text | `refund_reference_id` | Yes | CRED refund reference ID |
| 3 | state | OrderState | `state` | Yes | Refund state |
| 4 | amount | Amount | `amount` | Yes | Refund amount |
| 5 | refundModes | Maybe [PaymentMode] | `refund_modes` | No | Refund modes used |
| 6 | arn | Maybe Text | `arn` | No | Acquirer reference number |

#### RefundSync — `Types.hs:1452`
Used in: `SyncRespV1Order.refunds`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | refund_id | Maybe Text | `refund_id` | No | CRED refund ID |
| 2 | refund_reference_id | Text | `refund_reference_id` | Yes | Juspay refund reference ID |
| 3 | amount | Integer | `amount` | Yes | Refund amount |
| 4 | status | Text | `status` | Yes | Status string ("CREATED"/"PROCESSING"/"COMPLETED"/"FAILED") |
| 5 | arn | Maybe Text | `arn` | No | Acquirer reference number |
| 6 | created_at | Maybe Text | `created_at` | No | Creation timestamp |
| 7 | updated_at | Maybe Text | `updated_at` | No | Last update timestamp |

#### CardData — `Types.hs:670`
Used in: `PaymentMode.card`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | brand | Maybe Text | `brand` | No | Card brand (e.g., "VISA") |
| 2 | issuer | Maybe Text | `issuer` | No | Card issuing bank |
| 3 | sub_method | Maybe Text | `sub_method` | No | Sub-method (e.g., "CREDIT") |

#### UpiData — `Types.hs:684`
Used in: `PaymentMode.upi`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | payer_vpa | Maybe Text | `payer_vpa` | No | Payer UPI VPA |

#### Reward — `Types.hs:581`
Used in: `PaymentMode.reward`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | instrumenType | Maybe Text | `instrumen_type` | No | Instrument type |
| 2 | issuer | Maybe Text | `issuer` | No | Reward issuer |
| 3 | redeemPoints | Maybe Double | `redeem_points` | No | Points redeemed |
| 4 | status | Maybe Text | `status` | No | Reward status |
| 5 | amount | Double | `amount` | Yes | Reward amount |

#### FundingSource — `Types.hs:525`
Used in: `PaymentMode.fundingSource`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | merchant | Double | `merchant` | Yes | Merchant-funded amount |
| 2 | others | Double | `others` | Yes | Other-funded amount |

#### Layout — `Types.hs:220`
Used in: `CheckoutResponseData.layout`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | title | Text | `title` | Yes | Layout title |
| 2 | subText | Text | `sub_text` | Yes | Subtitle |
| 3 | ctaText | Text | `cta_text` | Yes | Call-to-action text |
| 4 | bannerText | Text | `banner_text` | Yes | Banner text |
| 5 | icon | Text | `icon` | Yes | Icon URL/identifier |

#### RewardsLayout — `Types.hs:348`
Used in: `RewardsResponseData.layout`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | preActionNudge | Text | `pre_action_nudge` | Yes | Pre-action nudge text |
| 2 | postActionNudge | Text | `post_action_nudge` | Yes | Post-action nudge text |
| 3 | couponCode | Maybe Text | `coupon_code` | No | Coupon code |

#### CardInfoSync — `Types.hs:1438`
Used in: `SyncRespV1Order.card`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | issuer | Maybe Text | `issuer` | No | Card issuer |
| 2 | brand | Maybe Text | `brand` | No | Card brand |
| 3 | masked_card_number | Maybe Text | `masked_card_number` | No | Masked PAN |
| 4 | card_type | Maybe Text | `type` | No | Card type |

#### OffersSync — `Types.hs:1464`
Used in: `SyncRespV1Order.offers`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | offer_id | Text | `id` | Yes | Offer ID |
| 2 | offer_amount | Maybe Int | `offer_amount` | No | Offer amount |
| 3 | amount | Maybe Int | `amount` | No | Applied amount |

#### NextAction — `Types.hs:1332`
Used in: `DeviceTokenOrdSResp.next_action`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | next_action_type | Maybe Text | `type` | No | Next action type |
| 2 | redirect_params | RedirectParams | `redirect_params` | Yes | Redirect parameters |

#### RedirectParams — `Types.hs:1344`
Used in: `NextAction.redirect_params`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | base_url | Text | `base_url` | Yes | Redirect base URL |

#### ErrorRespDIP — `Types.hs:995`
Used in: `DeviceTokenOrdCreateResp`, `AuthTokenRespEnum`, `PaymentOptionsResponseEnum`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | error_type | Text | `error_type` | Yes | Error category |
| 2 | header | Text | `header` | Yes | Error header |
| 3 | error_code | Text | `error_code` | Yes | Machine-readable error code |
| 4 | message | Text | `message` | Yes | Human-readable message |

#### Nudge — `Types.hs:1350`
Used in: `ContainerOptions.layout`, `CardOptions.nudge`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | title | Text | `title` | Yes | Nudge title |
| 2 | text | Maybe Text | `text` | No | Nudge body text |
| 3 | sub_text | Maybe Text | `sub_text` | No | Sub-text |
| 4 | icon | Maybe Text | `icon` | No | Icon URL |
| 5 | flow_type | Maybe FlowType | `flow_type` | No | Flow type |

#### Instrument — `Types.hs:1293`
Used in: `CardOptions.instruments`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | instrument_id | Text | `instrument_id` | Yes | Instrument identifier |
| 2 | instrument_type | Text | `type` | Yes | Instrument type |
| 3 | priority | Maybe Int | `priority` | No | Display priority |
| 4 | card_issuer | Maybe Text | `card_issuer` | No | Card issuer |
| 5 | brand | Maybe Text | `brand` | No | Card brand |
| 6 | brand_logo | Maybe Text | `brand_logo` | No | Brand logo URL |
| 7 | masked_card_number | Maybe Text | `masked_card_number` | No | Masked PAN |
| 8 | par | Maybe Text | `par` | No | Payment account reference |
| 9 | issuer_logo_url | Maybe Text | `issuer_logo_url` | No | Issuer logo URL |
| 10 | bin_hash | Maybe Text | `bin_hash` | No | BIN hash |
| 11 | token_iin | Maybe Text | `token_iin` | No | Token IIN |
| 12 | flow_type | Maybe FlowType | `flow_type` | No | Flow type |

#### Offer — `Types.hs:1360`
Used in: `PaymentOptions.offers`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | text | Maybe Text | `text` | No | Offer description |
| 2 | sub_text | Maybe Text | `sub_text` | No | Offer sub-description |
| 3 | benefit_value | Maybe Double | `benefit_value` | No | Benefit value |

#### ContainerOptions — `Types.hs:1260`
Used in: `PaymentOptions.container`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | eligible | Bool | `eligible` | Yes | Whether container (CRED wallet) is eligible |
| 2 | flow_type | FlowType | `flow_type` | Yes | ACQUIRED / NON_ACQUIRED / AS_ISSUER |
| 3 | layout | Nudge | `layout` | Yes | UI nudge layout |

#### CardOptions — `Types.hs:1268`
Used in: `PaymentOptions.card`

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | state | LinkState | `state` | Yes | LINKED_INSTRUMENT / ELIGIBLE_TO_LINK / USER_INELIGIBLE |
| 2 | instruments | Maybe [Instrument] | `instruments` | No | Available card instruments |
| 3 | nudge | Maybe Nudge | `nudge` | No | UI nudge |

#### CredAccountDetails — `Types.hs:720`
Decoded from `MerchantGatewayAccount.accountDetails`.

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | credClientId | Text | `cred_client_id` | Yes | CRED merchant client ID |
| 2 | credClientSecret | Text | `cred_client_secret` | Yes | CRED merchant client secret |
| 3 | businessPartnerId | Maybe Text | `business_partner_id` | No | Business partner ID |
| 4 | sendExtraMetadata | Maybe Text | `send_extra_metadata` | No | Whether to send extra metadata |
| 5 | isWebEnabled | Maybe Text | `is_web_enabled` | No | Whether web checkout is enabled |
| 6 | credMerchantId | Maybe Text | `cred_merchant_id` | No | CRED merchant ID |

#### CredContainer — `Types.hs:1026`
Stored in session/container data for DIP flows.

| # | Field Name | Haskell Type | JSON Key | Required | Description |
|---|------------|-------------|----------|----------|-------------|
| 1 | expiryEpochTime | Integer | `expiry_epoch_time` | Yes | Token expiry epoch |
| 2 | accessToken | Text | `access_token` | Yes | CRED access token |
| 3 | deviceId | Maybe Text | `device_id` | No | Device identifier |
| 4 | refreshToken | Maybe Text | `refresh_token` | No | OAuth2 refresh token |

---

## 5. Flows

### 5.1 Flow: checkEligibility

**File**: `Flows.hs`
**Purpose**: CRED wallet/UPI/Card eligibility check
**Trigger**: Eligibility check request for CRED payment method

#### Steps

| Step | Action | Function | File | Details |
|------|--------|----------|------|---------|
| 1 | Validate request | `validateRequestEligibility` | `Flows.hs` | Extract and validate payment method type, metadata |
| 2 | Get account details | `getAccDetails` | `Transforms.hs` | Decode `CredAccountDetails` from `MerchantGatewayAccount` |
| 3 | Build request | `makeEligibilityRequest` | `Transforms.hs` | Construct `CheckoutRequest` from `EligibilityMetadata` + trackingId |
| 4 | Add auth headers | `makeHeaders` / `mkHeadersFromAccDetails` | `Transforms.hs` | Build `Headers` with clientId, clientSecret, requestId |
| 5 | API Call → `POST /checkout` | `doCheckoutCall` | `Routes.hs` | Call CRED checkout API |
| 6 | Handle response | `handleEligibilityResponse` | `Flows.hs` | Map `CheckoutState` → internal eligibility response |

#### Decision Points

| # | Condition | YES Branch | NO Branch |
|---|-----------|-----------|-----------|
| 1 | `paymentMethodType == UPI` or `CARD` | Call rewards nudge API (`POST /v1/rewards/...`) | Call standard checkout API (`POST /checkout`) |
| 2 | `isWebEnabled` and web flow | Use `credBaseUrlNew` with web host | Use `credBaseUrl` with native host |
| 3 | `CheckoutState == ELIGIBLE` | Return eligible status | Return ineligible status |

#### Flow Diagram

```
checkEligibility
  ├── Validate request (extract paymentMethodType, phone/hashed phone from metadata)
  ├── Decode CredAccountDetails from MerchantGatewayAccount
  ├── Build CheckoutRequest (trackingId, agent, user, credAppPresent, etc.)
  ├── Add auth headers (X-Merchant-Client-Id, X-Merchant-Client-Secret, X-Request-Id)
  ├── [paymentMethodType == UPI/CARD?]
  │     YES → POST /v1/rewards/actions/upi_plugin_payment_completed/nudge
  │     NO  → POST /checkout (credBaseUrl)
  └── Handle response: map CheckoutState → EligibilityStatus
```

---

### 5.2 Flow: checkBatchEligibility

**File**: `Flows.hs`
**Purpose**: Batch eligibility check across multiple payment instruments
**Trigger**: Batch eligibility request

#### Steps

| Step | Action | Function | File | Details |
|------|--------|----------|------|---------|
| 1 | Validate request | `validateRequestBatchEligibility` | `Flows.hs` | Extract instruments list |
| 2 | Group by type | internal grouping | `Flows.hs` | Separate UPI/Card instruments from wallet instruments |
| 3 | Call batch API | `doGenericRewardsCall` | `Routes.hs` | `POST /v1/rewards/actions/nudges/batch-get` for UPI/Card |
| 4 | Call checkout API | `doCheckoutCall` | `Routes.hs` | `POST /checkout` for wallet |
| 5 | Merge responses | internal merge | `Flows.hs` | Combine results from both API calls |

---

### 5.3 Flow: createOrder

**File**: `Flows.hs`
**Purpose**: CRED order creation (SDK params flow)
**Trigger**: Payment initiation with CRED

#### Steps

| Step | Action | Function | File | Details |
|------|--------|----------|------|---------|
| 1 | Validate | `validateRequestCreateOrder` | `Flows.hs` | Extract and validate SDK params |
| 2 | Get account details | `getAccDetails` | `Transforms.hs` | Decode credentials |
| 3 | Build request | `makeOrderCreateRequest` | `Transforms.hs` | Construct `CheckoutRequest` for order creation |
| 4 | Add auth | `makeHeaders` | `Transforms.hs` | Attach auth headers |
| 5 | API Call | `doCheckoutCall` | `Routes.hs` | `POST /checkout` |
| 6 | Handle response | `captureResponse` | `Flows.hs` | Map `OrderState` → `TxnStatus` |

---

### 5.4 Flow: initiateRefund (Standard)

**File**: `Flows.hs` + `Instances.hs` (BasicGatewayFlow CRED InitiateRefund)
**Purpose**: Standard CRED refund via checkout API
**Trigger**: Refund request for native CRED flow

#### Steps

| Step | Action | Function | File | Details |
|------|--------|----------|------|---------|
| 1 | Validate | `validateRequestRefund` | `Flows.hs` | Check txnDetail, refund amount |
| 2 | Get account | `getAccDetails` | `Transforms.hs` | Decode `CredAccountDetails` |
| 3 | Build request | `makeRefundRequest` | `Transforms.hs` | Build `RefundRequest`; handle surcharge (refType "R"/"C") |
| 4 | Add auth | `makeHeaders` | `Transforms.hs` | Attach auth headers |
| 5 | API Call → `POST /refund` | `doRefundCall` | `Routes.hs` | Call CRED refund API |
| 6 | Handle response | `handleRefundResponse` | `Flows.hs` | Map `OrderState` → `RefundStatus` |

---

### 5.5 Flow: initiateRefund (V1)

**File**: `Flows/InitiateRefundV1.hs` + `Instances.hs` (BasicGatewayFlow MFUtils.CRED InitiateRefund)
**Purpose**: V1 refund via `/v1/orders/{order_id}/refunds` endpoint
**Trigger**: Refund request for NonNative CRED flow

#### Steps

| Step | Action | Function | File | Details |
|------|--------|----------|------|---------|
| 1 | Validate | `validateRequestRefundV1` | `Flows/InitiateRefundV1.hs` | Validate order ID and refund details |
| 2 | Get account | `getAccountDetailsRefundV1` | `Flows/InitiateRefundV1.hs` | Decode credentials |
| 3 | Build request | `makeGatewayRequestRefundV1` | `Flows/InitiateRefundV1.hs` | Construct `V1RefundRequest` |
| 4 | Add auth | `addAuthenticationRefundV1` | `Flows/InitiateRefundV1.hs` | Basic Auth header |
| 5 | API Call | `callAPIRefundV1` → `doV1OrderRefundCall` | `Flows/InitiateRefundV1.hs` / `Routes.hs` | `POST /v1/orders/{order_id}/refunds` |
| 6 | Handle response | `handleResponseRefundV1` | `Flows/InitiateRefundV1.hs` | Map V1 refund status text → `RefundStatus` |

---

### 5.6 Flow: syncTransaction / validateSyncReq / callSyncApi / handleSyncResponse

**File**: `Flows.hs` + `Instance.hs` (VerifyIntegrityGatewayFlow CRED GatewayResponseSyncAndVerify)
**Purpose**: Transaction sync and integrity verification
**Trigger**: Periodic sync or explicit sync request

#### Steps

| Step | Action | Function | File | Details |
|------|--------|----------|------|---------|
| 1 | Validate | `validateSyncReq` | `Flows.hs` | Check payment flow type (NonNative vs native) |
| 2 | Build gateway request | `makeGwSyncRequest` | `Flows.hs` | Build `SyncVreq` (V1OrderVReq or CheckoutStatusVReq) |
| 3 | Add auth | auth header | `Flows.hs` | API key or Basic Auth per flow |
| 4 | API Call | `callSyncApi` | `Flows.hs` | NonNative: `GET /v1/orders/{order_id}`; Native: `GET /status/{tracking_id}` |
| 5 | Handle response | `handleSyncResponse` / `handleGwSyncResponse` | `Flows.hs` | Map `OrderState` → `TxnStatus` (sync mapping) |

#### Decision Points

| # | Condition | YES Branch | NO Branch |
|---|-----------|-----------|-----------|
| 1 | `isCredNonNativePF` | Use V1 order API (`GET /v1/orders/{order_id}`) | Use checkout status API (`GET /status/{tracking_id}`) |
| 2 | `shouldBlockSync` (Container flow + no merchantGatewayAccountId) | Skip sync, return current status | Proceed with sync |

---

### 5.7 Flow: syncRefund (Standard and V1)

**Files**: `Flows.hs`, `Flows/RefundSyncV1.hs`
**Purpose**: Refund status synchronization
**Trigger**: Refund sync request

#### Standard Refund Sync Steps

| Step | Action | Function | File | Details |
|------|--------|----------|------|---------|
| 1 | Validate | `validateSyncRefund` | `Flows.hs` | Check refund details |
| 2 | API Call | `doStatusCall` | `Routes.hs` | `GET /status/{tracking_id}` |
| 3 | Handle | `syncRefundResponse` | `Flows.hs` | Find refund in response refunds list, map state → RefundStatus |

#### V1 Refund Sync Steps (`Flows/RefundSyncV1.hs`)

| Step | Action | Function | File | Details |
|------|--------|----------|------|---------|
| 1 | Validate | `validateRequestRefundSyncV1` | `Flows/RefundSyncV1.hs` | Extract order ID |
| 2 | Get account | `getAccountDetailsRefundSyncV1` | `Flows/RefundSyncV1.hs` | Decode credentials |
| 3 | Build request | `makeGatewayRequestRefundSyncV1` | `Flows/RefundSyncV1.hs` | Build request |
| 4 | Add auth | `addAuthenticationRefundSyncV1` | `Flows/RefundSyncV1.hs` | Basic Auth |
| 5 | API Call | `callAPIRefundSyncV1` → `doV1OrderStatusCall` | `Flows/RefundSyncV1.hs` | `GET /v1/orders/{order_id}` |
| 6 | Handle | `handleResponseRefundSyncV1` | `Flows/RefundSyncV1.hs` | Map V1 refund status → RefundStatus |

---

### 5.8 Flow: redirectTransaction

**File**: `Flows.hs` + `Instances.hs` (BasicGatewayFlow MFUtils.CRED RedirectTransaction)
**Purpose**: Redirect user to CRED web URL or DIP payment URL
**Trigger**: Redirect-based payment initiation

#### Steps

| Step | Action | Function | File | Details |
|------|--------|----------|------|---------|
| 1 | Validate | `validateRequestRedirect` | `Flows.hs` | Check flow type |
| 2 | Build gateway request | `makeGatewayRequestDevice` | `Flows.hs` | Build `DeviceTokenOrdCreateReq` |
| 3 | Add auth | `addAuthDevice` | `Flows.hs` | Basic Auth (DIP flow) |
| 4 | API Call | `callAPIDevice` | `Flows.hs` → `doCreateOrderCall` | `POST /v1/orders` |
| 5 | Handle | redirect to `webUrl` or `intentUrl` | `Flows.hs` | Return redirect response |

---

### 5.9 Flow: DIP Eligibility (Device Instrument Provider)

**File**: `Flows.hs` + `Instances.hs` (multiple BasicGatewayFlow MFUtils.CRED variants)
**Purpose**: CRED card/wallet eligibility via CRED DIP API
**Trigger**: Pre-transaction eligibility check for DIP flow

#### Sub-flows:

1. **CommonEligibilityRequest → IntermediateEligibility** (auth token check):
   - Call `POST /payment-app/v1/oauth2/token` (auth or refresh token)
   - Store `AuthTokenResponse` in `IntermediateEligibility`

2. **IntermediateEligibility → CommonEligibilityResponse** (eligibility DIP):
   - Call `POST /v1/payment-options` with `EligibilityReq`
   - Map `PaymentOptionsResponse` → internal eligibility response

---

### 5.10 Flow: offerAllotWebhook

**File**: `Flows.hs`
**Purpose**: Post-transaction offer allotment via CRED rewards API
**Trigger**: Post-payment webhook or callback

#### Steps

| Step | Action | Function | File | Details |
|------|--------|----------|------|---------|
| 1 | Validate | `validateOfferAllot` | `Flows.hs` | Extract user token from webhook payload |
| 2 | Build request | `makeAllotRequest` | `Flows.hs` | Construct `AllotRequest` |
| 3 | Add auth | `makeCredAuthHeaders` | `Transforms.hs` | Basic Auth using env vars |
| 4 | API Call | `doAllotCall` | `Routes.hs` | `POST /v1/rewards/actions/upi_plugin_payment_completed/allot` |
| 5 | Handle response | `handleAllotResponse` | `Flows.hs` | Log result |

---

### 5.11 Flow: webhookVerify

**File**: `Flows.hs` + `Instance.hs` (VerifyIntegrityGatewayFlow CRED WebhookVerify)
**Purpose**: Verify webhook authenticity from CRED
**Trigger**: Incoming webhook from CRED

---

### 5.12 Flow: PreTxnContainer / Container Creation

**File**: `Instances.hs` (BasicGatewayFlow MFUtils.CRED PreTxnContainerRequest)
**Purpose**: Create CRED container (obtain access token via OAuth2 code exchange)
**Trigger**: Pre-transaction container setup

#### Steps

| Step | Action | Function | File | Details |
|------|--------|----------|------|---------|
| 1 | Validate | `validateRequestContainer` | `Flows.hs` | Extract auth code, code verifier, redirect URI |
| 2 | Build request | `makeContainerReq` | `Transforms.hs` | Construct `CreateContainerReq` (grant_type, code, code_verifier, redirect_uri) |
| 3 | Add auth | Basic Auth | `Flows.hs` | Using `DeviceTokenCredentials` |
| 4 | API Call | `doAuthTokenCall` | `Routes.hs` | `POST /payment-app/v1/oauth2/token` |
| 5 | Handle | Store `CredContainer` | `Flows.hs` | Extract access_token, refresh_token, expiry |

---

### 5.13 Data Transformations

| # | From | To | Function | File | Logic |
|---|------|----|----------|------|-------|
| 1 | `EligibilityMetadata` + trackingId | `CheckoutRequest` | `makeEligibilityRequest` | `Transforms.hs` | Build checkout request with phone/hashed phone from metadata |
| 2 | Internal order data | `CheckoutRequest` | `makeOrderCreateRequest` | `Transforms.hs` | Build order creation request |
| 3 | `GatewayRefundData` | `RefundRequest` | `makeRefundRequest` | `Transforms.hs` | Map refund fields; set `refundFees`; handle surcharge via refType "R"/"C" |
| 4 | `GatewayRefundData` | `V1RefundRequest` | `makeRefundRequestV1` | `Transforms.hs` | Map to V1 refund format |
| 5 | `CredAccountDetails` | `Headers` | `mkHeadersFromAccDetails` | `Transforms.hs` | Extract clientId, clientSecret, businessPartnerId, credMerchantId |
| 6 | `EligibilityMetadata.encryptedPhoneNumber` | plaintext phone | `extractEligibilityMetadata` | `Transforms.hs` | Decrypt AES-GCM encrypted phone; PBKDF2 key derivation |
| 7 | `OrderState` | `TxnStatus` | `captureResponse` / `mapOrderState` | `Transforms.hs` | Payment capture mapping |
| 8 | `OrderState` | `TxnStatus` (sync) | `getTxnStatusSync` | `Transforms.hs` | Sync-specific mapping (different from capture) |
| 9 | `OrderState` | `RefundStatus` | `mapRefundStatus` | `Transforms.hs` | Refund state mapping |
| 10 | V1 refund status text | `RefundStatus` | `mapCredV1RefundStatus` | `Transforms.hs` | "CREATED"/"PROCESSING"/"COMPLETED"/"FAILED" → RefundStatus |
| 11 | `CheckoutState` | `EligibilityStatus` | inline in eligibility handler | `Transforms.hs` | ELIGIBLE→ELIGIBLE, INELIGIBLE→INELIGIBLE |
| 12 | Metadata JSON | `EligibilityMetadata` | `decodeEligibilityMetadata` | `Transforms.hs` | JSON decode from txn metadata |

---

## 6. Error Handling

### 6.1 Error Types

| # | Error Type | Constructors | Used In | File |
|---|-----------|--------------|---------|------|
| 1 | `WErrorResponse` | `WErrorC ClientError`, `WError WebhookVerifyResponse` | Webhook verify | `Types.hs:778` |
| 2 | `RErrorResponse` | `RErrorC ClientError`, `RErrorBadRequest CommonResponse`, `RErrorInternalServerError CommonResponse`, `RErrorInvalidData CommonResponse` | Refund / status sync | `Types.hs:782` |
| 3 | `SErrorResponse` | `SErrorC APIError`, `SErrorInternalServerError CommonResponse`, `SErrorInvalidData CommonResponse`, `SErrorBadRequest (CommonResponse CommonError)` | Sync flows | `Types.hs:790` |
| 4 | `CommonError` | `MANDATORY_DETAILS_MISSING Text`, `CREDENTIALS_DECODE_ERROR Text`, `METADATA_DECODE_ERROR Text`, `CONTAINER_DATA_DECODE_ERROR Text`, `NOT_SUPPORTED_FLOW Text` | Internal validation | `Types.hs:825` |
| 5 | `ErrorRespDIP` | `error_type`, `header`, `error_code`, `message` | DIP / token flows | `Types.hs:995` |

### 6.2 API Call Error Handling

| # | Error Type | Handling | Fallback | File |
|---|-----------|----------|----------|------|
| 1 | `Servant.ClientError` | Wrapped as `RErrorC` / `WErrorC` / `SErrorC` | Returns error response to caller | `Flows.hs` |
| 2 | `CommonResponse` status = `BAD_REQUEST` | Wrapped as `RErrorBadRequest` | Returns bad request error | `Flows.hs` |
| 3 | `CommonResponse` status = `INTERNAL_SERVER_ERROR` | Wrapped as `RErrorInternalServerError` | Returns server error | `Flows.hs` |
| 4 | `CommonResponse` with unexpected data | Wrapped as `RErrorInvalidData` | Returns invalid data error | `Flows.hs` |
| 5 | `CommonError.CREDENTIALS_DECODE_ERROR` | Fail fast | Returns credentials error | `Transforms.hs` |
| 6 | `CommonError.METADATA_DECODE_ERROR` | Fail fast | Returns metadata decode error | `Transforms.hs` |
| 7 | `CommonError.NOT_SUPPORTED_FLOW` | Fail fast | Returns not supported error | `Flows.hs` |
| 8 | `ErrorRespDIP` | Parsed from untagged union response | Returns DIP error | `Flows.hs` |
| 9 | `AuthTokenResponse.APIErr` | API error from auth token call | Fail eligibility | `Flows.hs` |
| 10 | `AuthTokenResponse.CommonErr` | CommonError in auth flow | Fail eligibility | `Flows.hs` |
| 11 | `AuthTokenResponse.SkipTheFlow` | Skip auth token call (existing token) | Proceed with eligibility | `Flows.hs` |

### 6.3 HTTP Status Code Handling

| HTTP Status | Handling | Response to Caller |
|-------------|----------|--------------------|
| 200 + `status=OK` | Success path | Parse `response` field as typed payload |
| 200 + `status=BAD_REQUEST` | Mapped to `RErrorBadRequest` | Error response returned |
| 200 + `status=INTERNAL_SERVER_ERROR` | Mapped to `RErrorInternalServerError` | Error response returned |
| 4xx (HTTP level) | Servant `ClientError` → `RErrorC` / `SErrorC` | Error propagated to caller |
| 5xx (HTTP level) | Servant `ClientError` → `RErrorC` / `SErrorC` | Error propagated to caller |
| Connection Failure | Servant `ClientError` | Error propagated to caller |

**Note**: CRED uses application-level status codes inside the HTTP 200 body (`CommonResponse.status`). HTTP-level errors are handled via `Servant.ClientError`.

### 6.4 Timeout & Retry

- **Timeout Mechanism**: Default HTTP client timeout (no custom per-request timeout header observed in source)
- **Retry Enabled**: Not observed in source code
- **shouldBlockSync**: `isCredContainerPF && not (isJust txnDetail.merchantGatewayAccountId)` — blocks sync for container flows without merchant gateway account ID

### 6.5 Error Code Mappings

| # | Source Error | Description |
|---|------------|-------------|
| 1 | `MANDATORY_DETAILS_MISSING` | Required fields missing from request/metadata |
| 2 | `CREDENTIALS_DECODE_ERROR` | Failed to decode `CredAccountDetails` from account details |
| 3 | `METADATA_DECODE_ERROR` | Failed to decode eligibility metadata from txn metadata |
| 4 | `CONTAINER_DATA_DECODE_ERROR` | Failed to decode container data (DIP flows) |
| 5 | `NOT_SUPPORTED_FLOW` | Flow type not supported for this payment method |

---

## 7. Status Mappings

### 7.1 OrderState — `Types.hs:612`

**Project**: euler-api-gateway

| # | Constructor | JSON Wire Value | Description |
|---|-------------|----------------|-------------|
| 1 | PROCESSING | `"PROCESSING"` | Payment in progress |
| 2 | COMPLETED | `"COMPLETED"` | Payment completed successfully |
| 3 | FAILED | `"FAILED"` | Payment failed |
| 4 | MANUAL_REVIEW | `"MANUAL_REVIEW"` | Under manual review |
| 5 | CREATED | `"CREATED"` | Order created but not yet processed |
| 6 | EXPIRED | `"EXPIRED"` | Order expired |
| 7 | ORDER_CREATED_INTERNAL | `"ORDER_CREATED"` | Internal state for wire value "ORDER_CREATED" |

**Note**: The wire value `"ORDER_CREATED"` maps to the Haskell constructor `ORDER_CREATED_INTERNAL` to avoid name conflict.

### 7.2 CheckoutState — `Types.hs:150`

**Project**: euler-api-gateway

| # | Constructor | JSON Wire Value | Description |
|---|-------------|----------------|-------------|
| 1 | ELIGIBLE | `"ELIGIBLE"` | User is eligible for CRED payment |
| 2 | INELIGIBLE | `"INELIGIBLE"` | User is not eligible |
| 3 | ORDER_CREATED | `"ORDER_CREATED"` | Order has been created |
| 4 | FLOW_TRIGGERED | `"FLOW_TRIGGERED"` | Flow has been triggered |

### 7.3 ResponseStatus — `Types.hs:697`

**Project**: euler-api-gateway

| # | Constructor | JSON Wire Value | Description |
|---|-------------|----------------|-------------|
| 1 | OK | `"OK"` | Success |
| 2 | BAD_REQUEST | `"BAD_REQUEST"` | Client error |
| 3 | INTERNAL_SERVER_ERROR | `"INTERNAL_SERVER_ERROR"` | Server error |

### 7.4 OrderState → TxnStatus (Capture/Payment) Mapping

**Mapping File**: `Transforms.hs` (`captureResponse` / `mapOrderState`)
**Direction**: `OrderState` → internal `TxnStatus`

| # | Source (OrderState) | Target (TxnStatus) | Condition |
|---|--------------------|--------------------|-----------|
| 1 | PROCESSING | Authorizing | Default |
| 2 | COMPLETED | Charged | Default |
| 3 | FAILED | AuthorizationFailed | Default |
| 4 | MANUAL_REVIEW | PendingVBV | Default |
| 5 | CREATED | PendingVBV | Default |
| 6 | EXPIRED | AuthorizationFailed | Default |
| 7 | ORDER_CREATED_INTERNAL | PendingVBV | Default |

### 7.5 OrderState → TxnStatus (Sync) Mapping

**Mapping File**: `Transforms.hs` (`getTxnStatusSync`)
**Direction**: `OrderState` → internal `TxnStatus` (used during status sync)

| # | Source (OrderState) | Target (TxnStatus) | Condition |
|---|--------------------|--------------------|-----------|
| 1 | PROCESSING | PendingVBV | Default |
| 2 | COMPLETED | Charged | Default |
| 3 | FAILED | AuthenticationFailed | Default |
| 4 | MANUAL_REVIEW | PendingVBV | Default |
| 5 | CREATED | PendingVBV | Default |
| 6 | EXPIRED | AuthenticationFailed | Default |
| 7 | ORDER_CREATED_INTERNAL | PendingVBV | Default |

**Note**: Sync mapping differs from capture mapping: FAILED → AuthenticationFailed (not AuthorizationFailed), PROCESSING → PendingVBV (not Authorizing).

### 7.6 OrderState → RefundStatus Mapping

**Mapping File**: `Transforms.hs` (`mapRefundStatus`)
**Direction**: `OrderState` → internal `RefundStatus`

| # | Source (OrderState) | Target (RefundStatus) | Condition |
|---|--------------------|-----------------------|-----------|
| 1 | PROCESSING | Pending | Default |
| 2 | COMPLETED | Success | Default |
| 3 | FAILED | Failure | Default |
| 4 | MANUAL_REVIEW | Pending | Default |
| 5 | CREATED | Pending | Default |
| 6 | EXPIRED | Failure | Default |
| 7 | ORDER_CREATED_INTERNAL | Pending | Default |

### 7.7 V1 Refund Status Text → RefundStatus Mapping

**Mapping File**: `Transforms.hs` (`mapCredV1RefundStatus`)
**Direction**: `RefundSync.status` (Text) → internal `RefundStatus`

| # | Source (Text) | Target (RefundStatus) |
|---|---------------|-----------------------|
| 1 | "CREATED" | Pending |
| 2 | "PROCESSING" | Pending |
| 3 | "COMPLETED" | Success |
| 4 | "FAILED" | Failure |

### 7.8 CheckoutState → EligibilityStatus Mapping

**Direction**: `CheckoutState` → internal `EligibilityStatus`

| # | Source (CheckoutState) | Target (EligibilityStatus) |
|---|------------------------|---------------------------|
| 1 | ELIGIBLE | ELIGIBLE |
| 2 | INELIGIBLE | INELIGIBLE |
| 3 | ORDER_CREATED | (order created — treated as eligible for flow) |
| 4 | FLOW_TRIGGERED | (flow triggered — treated as eligible) |

---

## 8. Payment Methods

### 8.1 Supported Payment Method Types

| # | Payment Method | Sub-flow | Flow Identifier | Notes |
|---|----------------|----------|-----------------|-------|
| 1 | CRED Wallet (Collect) | CRED_COLLECT | `isCredContainerPF` | Container/native flow; uses checkout API; synced via `/status/{tracking_id}` |
| 2 | CRED Wallet (Intent) | CRED_INTENT | `isCredContainerPF` | Native intent flow; deep link via `intentUrl` |
| 3 | CRED Card | CRED_CARD | DIP flow | Card via CRED DIP; eligibility via `/v1/payment-options` |
| 4 | CRED UPI | CRED_UPI | DIP flow | UPI via CRED DIP; eligibility via rewards nudge API |
| 5 | CRED NonNative | NonNative | `isCredNonNativePF` | NonNative flow; uses V1 orders API; synced via `/v1/orders/{order_id}` |
| 6 | CRED Web | Web checkout | `isWebEnabled` | Web checkout via `webUrl`; uses `credBaseUrlNew` with web host |

### 8.2 Payment Method Detection

| # | Condition | Flow Type |
|---|-----------|-----------|
| 1 | `isCredNonNativePF` | NonNative flow — V1 orders API |
| 2 | `isCredContainerPF` | Container flow — standard checkout API |
| 3 | `paymentMethodType == "UPI"` or `"CARD"` | Rewards/DIP flow |
| 4 | `isWebEnabled` | Web checkout flow |

### 8.3 Payment Method Fields in Request/Response

**Request fields** (in `CheckoutRequest`):

| # | Field | JSON Key | Type | Description |
|---|-------|----------|------|-------------|
| 1 | paymentMethodType | `payment_method_type` | Maybe [Text] | List of allowed payment method types |

**Response fields** (in `CheckoutResponseData`):

| # | Field | JSON Key | Type | Description |
|---|-------|----------|------|-------------|
| 1 | checkoutMode | `checkout_mode` | Maybe CheckoutMode | intent / collect / web — determines payment mode |
| 2 | intentUrl | `intent_url` | Maybe Text | Deep link for intent-based payments |
| 3 | webUrl | `web_url` | Maybe Text | URL for web checkout |

### 8.4 Payment Method Enums

#### CheckoutMode — `Types.hs:203`

| # | Constructor | JSON Value | Description |
|---|-------------|-----------|-------------|
| 1 | INTENT | `"intent"` | CRED app deep link intent |
| 2 | COLLECT | `"collect"` | Collect request via CRED |
| 3 | WEB_CHECKOUT | `"web"` | Web-based checkout |

#### LinkState — `Types.hs:1276`

| # | Constructor | JSON Value | Description |
|---|-------------|-----------|-------------|
| 1 | LINKED_INSTRUMENT | `"LINKED_INSTRUMENT"` | Card is linked to CRED account |
| 2 | ELIGIBLE_TO_LINK | `"ELIGIBLE_TO_LINK"` | Card can be linked |
| 3 | USER_INELIGIBLE | `"INELIGIBLE"` | User is not eligible |

#### FlowType — `Types.hs:1315`

| # | Constructor | JSON Value | Description |
|---|-------------|-----------|-------------|
| 1 | ACQUIRED | `"ACQUIRED"` | Acquired flow |
| 2 | NON_ACQUIRED | `"NON_ACQUIRED"` | Non-acquired flow |
| 3 | AS_ISSUER | `"AS_ISSUER"` | As issuer flow |

---

## 9. Request / Response Enums

### 9.1 Platform — `Types.hs:47`

| # | Constructor | JSON Value | Description |
|---|-------------|-----------|-------------|
| 1 | APP | `"app"` | Native mobile app |
| 2 | WEB | `"web"` | Web browser |
| 3 | UNKNOWN_PLATFORM | `"unknown"` | Unknown platform |

### 9.2 OS — `Types.hs:63`

| # | Constructor | JSON Value | Description |
|---|-------------|-----------|-------------|
| 1 | ANDROID | `"android"` | Android OS |
| 2 | IOS | `"iOS"` | Apple iOS |
| 3 | WINDOWS | `"windows"` | Windows |
| 4 | LINUX | `"linux"` | Linux |
| 5 | MACOS | `"macOS"` | macOS |
| 6 | UNKNOWN_OS | `"unknown"` | Unknown OS |

### 9.3 Device — `Types.hs:88`

| # | Constructor | JSON Value | Description |
|---|-------------|-----------|-------------|
| 1 | MOBILE | `"mobile"` | Mobile phone |
| 2 | IPAD | `"iPAD"` | iPad |
| 3 | DESKTOP | `"desktop"` | Desktop computer |
| 4 | TABLET | `"tablet"` | Tablet |
| 5 | UNKNOWN_DEVICE | `"unknown"` | Unknown device |

### 9.4 Currency — `Types.hs:158`

| # | Constructor | JSON Value | Description |
|---|-------------|-----------|-------------|
| 1 | INR | `"INR"` | Indian Rupee |
| 2 | OFFER | `"OFFER"` | Offer/cashback currency |

### 9.5 CountryCode — `Types.hs:124`

| # | Constructor | JSON Value | Description |
|---|-------------|-----------|-------------|
| 1 | INDIA | `"+91"` | India country code |

### 9.6 Manufacturer — `Types.hs:1148`

| # | Constructor | JSON Input (case-insensitive) | JSON Output |
|---|-------------|-------------------------------|-------------|
| 1 | SAMSUNG | `"samsung"` | `"samsung"` |
| 2 | GOOGLE | `"google"` | `"Google"` |
| 3 | XIAOMI | `"xiaomi"` | `"Xiaomi"` |
| 4 | ONEPLUS | `"oneplus"` | `"OnePlus"` |
| 5 | OPPO | `"oppo"` | `"OPPO"` |
| 6 | VIVO | `"vivo"` | `"vivo"` |
| 7 | HUAWEI | `"huawei"` | `"HUAWEI"` |
| 8 | MOTOROLA | `"motorola"` | `"motorola"` |
| 9 | REALME | `"realme"` | `"realme"` |
| 10 | SONY | `"sony"` | `"Sony"` |
| 11 | ASUS | `"asus"` | `"asus"` |
| 12 | LGE | `"lge"` | `"LGE"` |
| 13 | HMD_GLOBAL | `"hmd global"` | `"HMD Global"` |
| 14 | INFINIX_MOBILITY_LIMITED | `"infinix mobility limited"` | `"INFINIX MOBILITY LIMITED"` |
| 15 | TECNO_MOBILE_LIMITED | `"tecno mobile limited"` | `"TECNO MOBILE LIMITED"` |
| 16 | UNKNOWN_MANUFACTURE | any other | `"unknown"` |

---

## 10. Encryption / Security

### 10.1 AES-GCM Encryption (Utils.hs)

Used for: decrypting `encryptedPhoneNumber` from eligibility metadata.

**File**: `Utils.hs:1–137`

| Parameter | Value |
|-----------|-------|
| Algorithm | AES-GCM |
| Key Size | 32 bytes |
| IV Size | 12 bytes |
| Salt Size | 16 bytes |
| Auth Tag Size | 16 bytes |
| KDF | PBKDF2-HMAC-SHA256 |
| Iterations | 65536 |

**Process**:
1. Extract 16-byte salt from beginning of ciphertext
2. Derive 32-byte key using PBKDF2-HMAC-SHA256 with password (client secret), salt, 65536 iterations
3. Extract 12-byte IV
4. Extract 16-byte auth tag
5. Decrypt remaining ciphertext using AES-256-GCM
6. Return decrypted plaintext (phone number)

---

## 11. Registered Gateway Flow Instances

**File**: `Instances.hs:1–199`

| # | Instance | Flow Type | Description |
|---|----------|-----------|-------------|
| 1 | `BasicGatewayFlow CRED InitiateRefund RefundResponse` | Standard refund | Native CRED refund via checkout API |
| 2 | `BasicGatewayFlow CRED RefundSync RefundSyncResponse` | Standard refund sync | Native refund status sync |
| 3 | `BasicGatewayFlow MFUtils.CRED InitiateRefund RefundResponse` | V1 refund | NonNative CRED refund via V1 orders API |
| 4 | `BasicGatewayFlow MFUtils.CRED RefundSync RefundSyncResponse` | V1 refund sync | NonNative refund status sync |
| 5 | `BasicGatewayFlow MFUtils.CRED DeviceInstrumentProviderCreateOrder` | DIP order | Create order via DIP (device token) |
| 6 | `BasicGatewayFlow MFUtils.CRED CommonEligibilityRequest IntermediateEligibility` | Auth token check | OAuth2 auth/refresh token for DIP eligibility |
| 7 | `BasicGatewayFlow MFUtils.CRED IntermediateEligibility CommonEligibilityResponse` | Eligibility DIP | Eligibility check via `/v1/payment-options` |
| 8 | `BasicGatewayFlow MFUtils.CRED PreTxnContainerRequest` | Container creation | Pre-transaction container (access token exchange) |
| 9 | `BasicGatewayFlow MFUtils.CRED RedirectTransaction PaymentResponse` | Redirect / DIP transaction | DIP order creation + redirect |
| 10 | `VerifyIntegrityGatewayFlow CRED WebhookVerify` | Webhook verify | Incoming webhook signature verification |
| 11 | `VerifyIntegrityGatewayFlow CRED GatewayResponseSyncAndVerify` | Sync and verify | Transaction sync + integrity verification |

---

## 12. Completeness Verification

| Check | Result |
|-------|--------|
| Request types documented | 10 (CheckoutRequest, RefundRequest, V1RefundRequest, DeviceTokenOrdCreateReq, EligibilityReq, RewardsRequest, AllotRequest, GenericRewardsRequest, AuthTokenReq, RefreshTokenReq) |
| Nested request types documented | 14 (Agent, User, Merchant, Amount, RefundMetadata, DeviceContext, TypeAndValue, RewardsUser, Token, ActionIndentifier, MerchantData, Juspay, V1RefundUdfs, PaymentOptPref, CreateContainerReq) |
| Response types documented | 9 (CommonResponse, CheckoutResponseData, OrderStatusResponseData, RefundResponseData, SyncRespV1Order, DeviceTokenOrdSResp, AuthTokenResp, RewardsResponseData, AllotResponse, PaymentOptionsResponse) |
| Nested response types documented | 17 (PaymentMode, Refund, RefundSync, CardData, UpiData, Reward, FundingSource, Layout, RewardsLayout, CardInfoSync, OffersSync, NextAction, RedirectParams, ErrorRespDIP, Nudge, Instrument, Offer, ContainerOptions, CardOptions, CredAccountDetails, CredContainer) |
| All nested types expanded | Yes |
| All enum values listed | Yes (Platform, OS, Device, CheckoutState, OrderState, ResponseStatus, Currency, CountryCode, CheckoutMode, LinkState, FlowType, Manufacturer with all 16 values) |
| All flows documented | Yes (12 flows: checkEligibility, checkBatchEligibility, createOrder, initiateRefund, initiateRefundV1, syncTransaction, syncRefund, syncRefundV1, redirectTransaction, DIP eligibility, offerAllotWebhook, webhookVerify, PreTxnContainer) |
| All error paths documented | Yes |
| All status mappings documented | Yes (4 mapping tables: capture, sync, refund, V1 refund text, CheckoutState→EligibilityStatus) |
| Payment methods documented | Yes |
| Encryption documented | Yes (AES-GCM + PBKDF2) |
| Missing items | None identified |

---

## 13. Source File References

| # | File | Lines | Purpose |
|---|------|-------|---------|
| 1 | `gateway/src/Euler/API/Gateway/Gateway/CRED/Routes.hs` | 363 | API type definitions (CREDAPIs servant type), base URL functions (`credBaseUrl`, `credBaseUrlNew`), all `do*Call` HTTP client functions |
| 2 | `gateway/src/Euler/API/Gateway/Gateway/CRED/Types.hs` | 1549 | All request/response types, enums, credential types, error types, encryption config |
| 3 | `gateway/src/Euler/API/Gateway/Gateway/CRED/Flows.hs` | 839+ | All main flow implementations (eligibility, order creation, refund, sync, redirect, DIP, webhook) |
| 4 | `gateway/src/Euler/API/Gateway/Gateway/CRED/Transforms.hs` | 1593 | All transformation and mapping functions (makeEligibilityRequest, makeRefundRequest, status mappings, credential extraction, AES decrypt) |
| 5 | `gateway/src/Euler/API/Gateway/Gateway/CRED/Instance.hs` | 82 | Sync flow instances (VerifyIntegrityGatewayFlow) |
| 6 | `gateway/src/Euler/API/Gateway/Gateway/CRED/Instances.hs` | 199 | All BasicGatewayFlow and VerifyIntegrityGatewayFlow instances |
| 7 | `gateway/src/Euler/API/Gateway/Gateway/CRED/Utils.hs` | 137 | AES-GCM encryption/decryption utility functions, PBKDF2 key derivation |
| 8 | `gateway/src/Euler/API/Gateway/Gateway/CRED/Flows/InitiateRefundV1.hs` | 81 | V1 refund flow (validateRequestRefundV1 → handleResponseRefundV1) |
| 9 | `gateway/src/Euler/API/Gateway/Gateway/CRED/Flows/RefundSyncV1.hs` | 106 | V1 refund sync flow (validateRequestRefundSyncV1 → handleResponseRefundSyncV1) |

---

**Generated by**: Euler Connector Tech Spec Workflow
**Date**: 2026-03-26
