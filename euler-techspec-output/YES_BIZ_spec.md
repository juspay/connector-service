# YES_BIZ Payment Gateway — Technical Specification

## Overview

YES_BIZ is a UPI payment gateway connector integrated via the **Newton** shared gateway framework, implemented in `euler-api-gateway`. It is **not** a standalone connector — it shares all flow logic with AXIS_BIZ and RBL_BIZ under the `Newton/` module, with YES_BIZ-specific branching where required.

**Key characteristics:**
- UPI-only gateway (Pay, Collect, Intent/InApp, UPI Autopay mandates)
- Signature scheme: **RSA-SHA256-PSS, Base16-encoded** (distinct from AXIS_BIZ which uses HMAC or JWE)
- JWE encryption: **not supported** (`isAxizBizJweFlow` returns `False` for YES_BIZ)
- Transaction ID prefix: **`YJP`** (e.g. `YJP09...`)
- UPI request ID padding prefix: **`YJP`** (35-char padded ID sent to gateway)

**Relevant source files:**
| File | Purpose |
|------|---------|
| `gateway/src/Euler/API/Gateway/Gateway/Newton/Flows/YesBiz/Instances.hs` | Flow type class instances (entry point for all YES_BIZ flows) |
| `gateway/src/Euler/API/Gateway/Gateway/Newton/Flows/YesBiz/Flow.hs` | Empty stub |
| `gateway/src/Euler/API/Gateway/Gateway/Newton/Flows/YesBiz/Types.hs` | Empty stub |
| `gateway/src/Euler/API/Gateway/Gateway/Newton/Flows/Sync.hs` | Transaction sync (V1, V2, 360) + mandate status sync |
| `gateway/src/Euler/API/Gateway/Gateway/Newton/Flows/RegisterIntent.hs` | UPI Intent/InApp initiation |
| `gateway/src/Euler/API/Gateway/Gateway/Newton/Flows/SendCollect.hs` | UPI Collect + Mandate Register |
| `gateway/src/Euler/API/Gateway/Gateway/Newton/Flows/Refund.hs` | Refund initiation + refund sync |
| `gateway/src/Euler/API/Gateway/Gateway/Newton/Flows/Webhook.hs` | Webhook verification + processing |
| `gateway/src/Euler/API/Gateway/Gateway/Newton/Routes.hs` | HTTP endpoints, base URLs |
| `gateway/src/Euler/API/Gateway/Gateway/Newton/Transforms.hs` | Request builders, signature generation, account detail transforms |
| `gateway/src/Euler/API/Gateway/Gateway/Newton/Types.hs` | All data types (request/response/webhook) |
| `common/src/Euler/API/Gateway/Config/EnvVars.hs` | Environment variable definitions (`YES_BIZ_UAT_PUBLIC_KEY`, `YES_BIZ_PROD_PUBLIC_KEY`) |

---

## Base URLs

| Environment | Host | Base Path |
|-------------|------|-----------|
| Sandbox (UAT) | `api.beta.yesbank.upi.juspay.in` | `api/n2/merchants` |
| Production | `api.yesbank.upi.juspay.in` | `api/n2/merchants` |
| SBMD simulation | _(same host as env)_ | `api/t4/merchants` |

All endpoints use HTTPS on port 443.

---

## Authentication

### Request Authentication Headers

Every outbound API call sends the following HTTP headers:

| Header | Required | Description |
|--------|----------|-------------|
| `x-merchant-id` | Yes | Merchant ID (`yesBizMerchantId`) |
| `x-merchant-channel-id` | Yes | Channel ID (`yesBizChannelId`) |
| `x-timestamp` | Yes | Unix epoch milliseconds |
| `x-merchant-signature` | Conditional | RSA-SHA256-PSS signature, Base16-encoded |
| `x-api-version` | No | Integer API version |
| `x-sub-merchant-id` | No | Sub-merchant ID (if applicable) |
| `x-sub-merchant-channel-id` | No | Sub-merchant channel ID (if applicable) |
| `x-sandbox-id` | No | Set to `"SIMULATOR"` to enable test simulation |
| `x-psp-encryption` | No | PSP encryption header (if applicable) |
| `content-type` | Yes | Always `application/json` |
| `user-agent` | Yes | Always `api-gateway/1.0.0` |

### Request Signature

**Algorithm:** RSA private key signing → Base16 (hex) encoded output  
**Key used:** `eulerPrivateKey` (from `AxisBizDetails`, sourced from `yesBizEulerPrivateKey` in MGA account details)

**Signature payload (concatenation):**
```
merchantId + channelId + subMerchantId + subMerchantChannelId + timestamp + requestBody
```

- Fields are concatenated as plain strings (empty string if absent)
- The result is signed using RSA-SHA256-PSS
- The signature is Base16 (hex) encoded and sent in `x-merchant-signature`

### Response Signature Verification

- The gateway returns its signature in the `X-Response-Signature` HTTP response header
- Verification uses the Newton/YES_BIZ public key (`newtonPublicKey`, sourced from `yesBizPublicKey` in MGA or from env var)
- Algorithm: RSA-SHA256-PSS, Base16-encoded
- A tampered/unverifiable response sets txn status to `AuthorizationFailed`

### Public Key Resolution (Priority Order)
1. Environment variable (`YES_BIZ_UAT_PUBLIC_KEY` for sandbox, `YES_BIZ_PROD_PUBLIC_KEY` for production)
2. If env var is empty/missing: falls back to `yesBizPublicKey` in the MGA account details

**Env vars:**
- `YES_BIZ_UAT_PUBLIC_KEY` — sandbox public key
- `YES_BIZ_PROD_PUBLIC_KEY` — production public key

---

## Credentials / Account Fields

### Primary Account Type: `YesBizDetails`

Stored as JSON in `MerchantGatewayAccount.accountDetails`. Decoded via `getYesBizAccountDetails`.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `yesBizChannelId` | Text | Yes | Merchant channel ID sent in `x-merchant-channel-id` |
| `yesBizMerchantId` | Text | Yes | Merchant ID sent in `x-merchant-id` |
| `yesBizSubMerchantId` | Maybe Text | No | Sub-merchant ID |
| `yesBizSubMerchantChannelId` | Maybe Text | No | Sub-merchant channel ID |
| `payeeVpa` | MerchantVpa | Yes | Merchant's UPI VPA (payee) |
| `refundVpa` | Maybe MerchantVpa | No | VPA to use for refunds |
| `mcc` | Maybe Text | No | Merchant category code |
| `waitingPageExpiryInSeconds` | Maybe Int | No | Expiry for collect/mandate requests (converted to minutes) |
| `intentRegistrationEnabled` | IsIntentEnabled | Yes | Whether UPI Intent flow is enabled |
| `intentExpiryInSeconds` | Maybe Int | No | Intent expiry |
| `enableBankInstantRefund` | Maybe Bool | No | Enable bank-side instant refund |
| `useTxnUuidAsTr` | Maybe Bool | No | Use transaction UUID as TR (transaction reference) |
| `yesBizPublicKey` | Maybe Text | No | YES Bank's RSA public key for response verification (fallback if env var absent) |
| `yesBizEulerPrivateKey` | Maybe Text | No | Euler's RSA private key for signing outbound requests |
| `yesBizEulerPublicKey` | Maybe Text | No | Euler's RSA public key |
| `mn` | Maybe Text | No | Mandate name |

### Sub-Merchant Account Type: `YesBizSubMerchantAccountDetails`

Used when a `MasterAccountDetail` is present (aggregator/marketplace flows).

| Field | Type | Description |
|-------|------|-------------|
| `yesBizSubMerchantChannelId` | Text | Sub-merchant channel ID |
| `yesBizSubMerchantId` | Text | Sub-merchant ID |
| `payeeVpa` | MerchantVpa | Sub-merchant payee VPA |
| `mcc` | Maybe Text | MCC |
| `waitingPageExpiryInSeconds` | Maybe Int | Collect expiry |
| `intentRegistrationEnabled` | IsIntentEnabled | Intent enabled |
| `intentExpiryInSeconds` | Maybe Int | Intent expiry |
| `enableBankInstantRefund` | Maybe Bool | Instant refund flag |
| `useTxnUuidAsTr` | Maybe Bool | Use UUID as TR |
| `mn` | Maybe Text | Mandate name |
| `subMerchantRefundVpa` | Maybe MerchantVpa | Sub-merchant refund VPA |
| `shouldUseSubMerchantRefundVpa` | Maybe Bool | If true, use sub-merchant refund VPA instead of master |

### Master Merchant Account Type: `YesBizMasterMerchantAccountDetails`

Stored in `MasterAccountDetail.credentials`.

| Field | Type | Description |
|-------|------|-------------|
| `yesBizMasterMerchantChannelId` | Text | Master channel ID |
| `yesBizMasterMerchantId` | Text | Master merchant ID |
| `payeeVpa` | MerchantVpa | Master payee VPA |
| `refundVpa` | Maybe MerchantVpa | Master refund VPA |
| `mcc` | Maybe Text | MCC |
| `algorithm` | Maybe Text | Key algorithm |
| `keyId` | Maybe Text | Key identifier |
| `yesBizPublicKey` | Maybe Text | YES Bank public key |
| `yesBizEulerPrivateKey` | Maybe Text | Euler private key for signing |

### Auth Account Type: `YesBizAuthAccountDetails`

Used in authentication flows.

| Field | Type | Description |
|-------|------|-------------|
| `yesBizChannelId` | Text | Channel ID |
| `yesBizMerchantId` | Text | Merchant ID |
| `mcc` | Maybe Text | MCC |
| `yesBizPublicKey` | Maybe Text | YES Bank public key |
| `yesBizEulerPrivateKey` | Maybe Text | Euler private key |
| `yesBizPrefix` | Maybe Text | Prefix for ID generation |
| `yesBizEncKid` | Maybe Text | Encryption key ID |
| `yesBizSignKid` | Maybe Text | Signing key ID |

### Runtime Mapping

At runtime, `YesBizDetails` is transformed into `AxisBizDetails` for use in shared Newton flow logic:

| `AxisBizDetails` field | Mapped from `YesBizDetails` |
|------------------------|------------------------------|
| `axisBizChannelId` | `yesBizChannelId` |
| `axisBizMerchantId` | `yesBizMerchantId` |
| `axisBizSubMerchantId` | `yesBizSubMerchantId` |
| `axisBizSubMerchantChannelId` | `yesBizSubMerchantChannelId` |
| `eulerPrivateKey` | `yesBizEulerPrivateKey` |
| `newtonPublicKey` | env var (if set) OR `yesBizPublicKey` |
| `newtonGateway` | `Just YES_BIZ` |
| `axisBizSignatureKey` | `Nothing` (not used for YES_BIZ) |
| `axisBizSignKid` | `Nothing` |
| `axisBizEncKid` | `Nothing` |

---

## API Endpoints

All endpoints are `POST`, use `application/json`, and are relative to the base path `api/n2/merchants`.

| Endpoint | Path | Flow |
|----------|------|------|
| VPA Validity Check | `/vpas/validity360` | VPA validation |
| Register Intent | `/transactions/registerIntent` | UPI Intent / InApp initiation |
| Send Collect | `/transactions/webCollect` | UPI Collect (pay request to customer) |
| Transaction Status V1 | `/transactions/status` | Sync V1 |
| Transaction Status V2 | `/transactions/statusV2` | Sync V2 |
| Transaction Status 360 | `/transactions/status360` | Sync 360 (extended status) |
| Initiate Refund | `/transactions/refund360` | Refund initiation |
| Refund Status | `/transactions/refund/status` | Refund sync |
| Update Split Settlement | `/transactions/settlement/split` | Split settlement update |
| Register Mandate | `/mandates/webMandate` | UPI Autopay mandate register |
| Execute Mandate | `/mandates/webExecute` | UPI Autopay mandate execute |
| Update/Revoke Mandate | `/mandates/webUpdate` | Mandate update or revocation |
| Mandate Status | `/mandates/status` | Mandate status sync |
| Mandate Notification | `/mandates/webNotify` | Mandate debit notification |
| Mandate Notification Status | `/mandates/webNotify/status` | Notification status check |

---

## Flows

### 1. GetSdkParams (RegisterIntent — UPI Intent / InApp)

**Entry:** `Instances.hs` → `GetSdkParams` type class instance  
**Endpoint:** `POST /transactions/registerIntent`

**Purpose:** Initiates a UPI Intent or InApp payment by registering the intent with the gateway. Returns SDK params that the mobile app uses to deep-link into a UPI app.

**Request type:** `TransactionStatusRequest` (reused) / `RegisterIntentRequest`

**Key request fields:**
```
merchantRequestId    -- TR (transaction reference), padded with YJP prefix
upiRequestId         -- TID, padded with YJP prefix
amount               -- Fixed-precision decimal string
payeeVpa             -- Merchant payee VPA
merchantName         -- From MGA
mcc                  -- Optional MCC
remarks              -- Optional
udfParameters        -- UDF params (order/customer metadata, optional)
intentExpiryInSeconds -- Optional; from account config or metadata
```

**ID padding:** Both `merchantRequestId` (TR) and `upiRequestId` (TID) are padded to 35 chars using prefix `YJP` followed by a 2-digit pad length and random alphabetic padding.

**Response type:** `RegisterIntentResponse`  
**SDK Params returned:** `AxisBizSdkParams`
```
tr               -- transaction reference
tid              -- transaction ID
merchant_vpa     -- payee VPA
merchant_name    -- merchant name
amount           -- payment amount
customer_first_name
customer_last_name
tr_prefix        -- optional
mcc              -- optional
```

**Metadata overrides (from `YesBizMetaData` in `order_metadata_v2`):**
- `YES_BIZ:intent_expiry_minutes` — override intent expiry

---

### 2. SendCollect (UPI Collect)

**Entry:** `Instances.hs` → `SendCollect` type class instance  
**Endpoint:** `POST /transactions/webCollect`

**Purpose:** Sends a UPI collect request to the customer's VPA. The customer approves the request in their UPI app. Also handles Mandate Registration (when txn type is `EmandateRegister` or `TpvEmandateRegister`), routing to `/mandates/webMandate`.

**Request type:** `SendCollectRequest`

**Key request fields:**
```
merchantRequestId          -- TR, padded
upiRequestId               -- TID (may be None for collect)
amount                     -- amount string
customerVpa                -- payer VPA (from txn card info)
payeeVpa                   -- merchant VPA
collectRequestExpiryMinutes -- expiry in minutes
remarks                    -- validated against ^[a-zA-Z0-9 -]*$
udfParameters              -- optional
splitSettlementDetails     -- optional split settlement
refUrl / refCategory       -- optional invoice URL/category
```

**Mandate Registration** (when `txnObjectType` is `EmandateRegister` or `TpvEmandateRegister`):  
Routes to `POST /mandates/webMandate` with `WebMandate` request:
```
mandateRequestExpiryMinutes
amount                      -- max mandate amount
mandateName                 -- from metadata or account config (mn field)
amountRule                  -- EXACT (FIXED) or MAX (VARIABLE)
upiRequestId                -- mandate reg ref ID, YJP-padded
validityStart               -- ISO 8601 date
validityEnd                 -- ISO 8601 date
recurrencePattern           -- DAILY/WEEKLY/MONTHLY etc.
recurrenceRule              -- optional
recurrenceValue             -- optional (None for DAILY)
customerVpa                 -- payer VPA
merchantRequestId           -- TR
payerRevocable              -- "true"/"false"
blockFund                   -- "true"/"false" (forced "true" for purpose 76/77)
refUrl / refCategory        -- optional
udfParameters               -- optional (includes TPV account hashes if TPV)
initiationMode              -- from YES_BIZ metadata
purpose                     -- "01" for OneTime, "77" for SBMD, else from metadata
payerAccountHashes          -- TPV account hash array (SHA-256 of account+IFSC)
tpvType                     -- "PARTIAL" or None
```

**YES_BIZ metadata keys** (in `order_metadata_v2.metadata` JSON):
| Key | Purpose |
|-----|---------|
| `YES_BIZ:ref_url` | Invoice URL |
| `YES_BIZ:ref_category` | Invoice category code |
| `YES_BIZ:initiation_mode` | Mandate initiation mode |
| `YES_BIZ:purpose` | Mandate purpose code |
| `YES_BIZ:txn_type` | Transaction type |
| `YES_BIZ:intent_expiry_minutes` | Intent expiry override |
| `YES_BIZ:collect_expiry_minutes` | Collect expiry override |
| `YES_BIZ:remarks` | Remarks override |
| `YES_BIZ:splitType` | Split settlement type |
| `YES_BIZ:shouldSimulateTxn` | Boolean: simulate transaction |

---

### 3. TransactionSync (Status Polling)

**Entry:** `Instances.hs` → `TransactionSync` type class instance  
**Three variants:** V1, V2, and 360

#### Sync V1
**Endpoint:** `POST /transactions/status`  
**Request type:** `TransactionStatusRequest`
```
merchantRequestId   -- TR
udfParameters       -- optional
```
**Response type:** `TransactionStatusResponse`

#### Sync V2
**Endpoint:** `POST /transactions/statusV2`  
**Request type:** `TransactionStatusV2Request`
```
merchantRequestId   -- TR
upiRequestId        -- TID (optional)
udfParameters       -- optional
```
**Response type:** `TransactionStatusV2or360Response`

#### Sync 360
**Endpoint:** `POST /transactions/status360`  
**Request type:** `TransactionStatus360Request`
```
merchantRequestId   -- TR
upiRequestId        -- TID (optional)
udfParameters       -- optional
```
**Response type:** `TransactionStatusV2or360Response`

**Newton360 flow:** Enabled when `isNewton360Transaction = "true"` in UPI auth params of the `SecondFactor`.

**Mandate Status Sync:**  
**Endpoint:** `POST /mandates/status`  
**Request type:** `MandateStatus`
```
orgMandateId        -- mandate gateway ID, YJP-padded
udfParameters       -- optional
merchantRequestId   -- optional
role                -- "PAYEE"
```
**Response type:** `MandateStatusResponse`

---

### 4. InitiateRefund

**Entry:** `Instances.hs` → `InitiateRefund` type class instance  
**Endpoint:** `POST /transactions/refund360`

**Request type:** `RefundRequest`

**Key request fields:**
```
merchantRequestId        -- refund reference ID (TR)
originalMerchantRequestId -- original txn TR
amount                   -- refund amount string
refundType               -- "ONLINE", "OFFLINE"/"STANDARD", or "UDIR"
bankRefNumber            -- optional bank reference
udfParameters            -- optional
```

**Refund types:**
| Internal Type | Sent to Gateway |
|---------------|-----------------|
| `ONLINE` | `"ONLINE"` (instant refund) |
| `OFFLINE` | `"STANDARD"` (standard/T+N refund) |
| `UDIR` | `"UDIR"` (dispute refund — includes additional UDIR fields) |

**UDIR-specific additional fields:**
```
reqAdjCode    -- adjustment code
reqAdjFlag    -- adjustment flag
crn           -- complaint reference number
adjFlag       -- optional
adjCode       -- optional
```

**Instant refund:** Enabled when `enableBankInstantRefund = true` in account details. Changes refund type from OFFLINE to ONLINE for supported banks.

---

### 5. RefundSync

**Entry:** `Instances.hs` → `RefundSync` type class instance  
**Endpoint:** `POST /transactions/refund/status`

**Request type:** `RefundStatusRequest`
```
merchantRequestId    -- refund TR
udfParameters        -- optional
```

**Response type:** `RefundStatusResponse` with nested `RefundStatusPayload`

**Key response fields from payload:**
```
gatewayResponseCode     -- used to determine refund status
gatewayResponseStatus   -- "SUCCESS", "FAILURE", etc.
refundReferenceId       -- bank reference for the refund
amount                  -- refunded amount
merchantRequestId
originalMerchantRequestId
```

---

### 6. WebhookVerify

**Entry:** `Instances.hs` → `WebhookVerify` type class instance

**Purpose:** Verifies the authenticity of an incoming webhook from YES Bank by validating the `X-Response-Signature` header using the YES Bank RSA public key (RSA-SHA256-PSS, Base16). If signature verification fails, the webhook is rejected.

**Optional mandatory sync:** For certain webhook event types (configurable), the system may perform a synchronous gateway status call to confirm the transaction state before processing the webhook.

**Signature verification payload:** The raw webhook request body is verified against the `X-Response-Signature` header value using `newtonPublicKey`.

---

### 7. WebhookSync (Webhook Processing)

**Entry:** `Instances.hs` → `WebhookSync` type class instance

**Purpose:** Parses the verified webhook payload and routes it to the appropriate internal handler.

**Consumed webhook event types** (only these are processed; all others are passed through without action):
- `MERCHANT_CREDITED_VIA_COLLECT`
- `MERCHANT_CREDITED_VIA_PAY`
- `MERCHANT_OUTGOING_CREATE_MANDATE`
- `MERCHANT_OUTGOING_UPDATE_MANDATE`
- `MERCHANT_OUTGOING_EXECUTE_MANDATE`
- `MERCHANT_NOTIFICATION_MANDATE`
- `MERCHANT_INCOMING_CREATE_MANDATE`
- `MERCHANT_INCOMING_PAUSE_MANDATE`
- `UPI_LITE_TOPUP`
- `UPI_LITE_DEREGISTRATION`
- `UPI_LITE_STATUS_UPDATE`

**All webhook event types handled (full set):**

| Webhook Type | Parsed As |
|--------------|-----------|
| Transaction credit webhooks | `TransactionSuccessWebhook` → `TransactionStatusPayload` |
| Error/failure webhooks | `ErrorResponseWebhook` → `TxnStatusErrorResponse` |
| Execute Mandate webhook | `ExecuteMandateWebhook` → `WebExecutePayload` |
| Mandate Register/Create webhooks | `MandateWebhook` → `MandateWebhookPayload` |
| Mandate Update/Revoke webhooks | `UpdateMandateWebhook` → `WebUpdatePayload` |
| Mandate Status Auto-Update | `MandateStatusUpdate` → `MandateStatusUpdateWebhook` |
| Mandate Notification Status | `NotificationStatusWebhook` → `WebNotifyStatusPayload` |
| Refund status updates | `RefundStatusUpdate` → `RefundStatusPayload` |
| Merchant debited via refund | `MerchantDebitedRefundUpdate` → `MerchantDebitedRefundPayload` |
| P2P transaction webhooks | `P2PTransactionWebhook` → `P2PWebhookPayload` |
| P2P mandate webhooks | `P2PMandateWebhook` → `P2PWebhookPayload` |
| Customer complaint webhooks | `CustomerComplaintWebhook` → `P2PWebhookPayload` |
| UPI Lite top-up | `UPILiteTopUpWebhook` → `UPILiteWebhookPayload` |
| UPI Lite status update | `UPILiteStatusUpdateWebhook` → `UPILiteStatusUpdatePayload` |
| Customer re-registered | `CustomerReregisteredWebhook` → `CustomerReregisteredPayload` |
| Customer deregistered (MNRL) | `CustomerDeregisteredMnrl` → `CustomerDeregisteredMnrlPayload` |
| UPI number mapper | `UpinumberMapperWebhook` → `UpiNumberMapperWebhook` |
| Customer complaint raised | `CustomercomplaintRaisedWebhook` → `CustomerComplaintRaisedWebhook` |
| Account linked by customer | `AccountLinkedByCustomer` → `AccountLinkedByCustomerWebhook` |
| Mandate status auto-update | `MandateStatusAutoupdate` → `P2PWebhookPayload` |

**P2P webhook event type mapping:**
| Webhook `type` field | Internal event |
|----------------------|----------------|
| `CUSTOMER_CREDITED_VIA_PAY` | `MERCHANT_CUSTOMER_RECEIVED_MONEY` |
| `COLLECT_REQUEST_RECEIVED` | `MERCHANT_CUSTOMER_COLLECT_REQUEST_RECEIVED` |
| `COLLECT_REQUEST_SENT` | `MERCHANT_CUSTOMER_COLLECT_REQUEST_SENT` |
| `MANDATE_STATUS_UPDATE` | `MERCHANT_CUSTOMER_MANDATE_STATUS_UPDATE` |
| `UPI_LITE_TOPUP` | `MERCHANT_CUSTOMER_UPI_LITE_TOPUP` |
| `UPI_LITE_DEREGISTRATION` | `MERCHANT_CUSTOMER_UPI_LITE_DEREGISTRATION` |
| `UPI_LITE_STATUS_UPDATE` | `MERCHANT_CUSTOMER_UPI_LITE_STATUS_UPDATE` |
| `CUSTOMER_DEREGISTERD_MNRL` | `MERCHANT_CUSTOMER_DEREGISTERED_MNRL` |
| `CUSTOMER_REREGISTERD` | `MERCHANT_CUSTOMER_REREGISTERED` |
| (any other) | `MERCHANT_<type>` |

---

### 8. Mandate Execute

**Endpoint:** `POST /mandates/webExecute`  
**Request type:** `WebExecute`

```
merchantRequestId             -- TR (txn ID)
umn                           -- UPI Mandate Number (from mandate gateway params)
collectRequestExpiryMinutes   -- expiry in minutes
amount                        -- debit amount
upiRequestId                  -- generated unique ID
remarks                       -- "RecurringTxn"
seqNo                         -- optional sequence number
refUrl / refCategory          -- optional
udfParameters                 -- optional
notificationMerchantRequestId -- optional (links to prior notification)
splitSettlementDetails        -- optional
mutualFundDetails             -- optional (for mutual fund transactions)
```

---

### 9. Mandate Update / Revoke

**Endpoint:** `POST /mandates/webUpdate`  
**Request type:** `WebUpdate`

```
merchantRequestId             -- TR
orgMandateId                  -- gateway mandate ID, YJP-padded
requestType                   -- REVOKE or UPDATE
mandateRequestExpiryMinutes   -- optional
amount                        -- optional (for updates)
upiRequestId                  -- generated unique ID
remarks                       -- reason/description
validityEnd                   -- optional (for extensions)
udfParameters                 -- optional
```

**Revoke success codes:** `"00"`, `"QC"`, or `"JPMR"` (treated as success)

---

### 10. Mandate Notification (WebNotify)

**Endpoint:** `POST /mandates/webNotify`  
**Request type:** `WebNotify`

```
umn                          -- UPI Mandate Number
amount                       -- debit amount
mandateExecutionTimestamp    -- ZonedTime
remarks                      -- default: "RecurringTransaction"
merchantRequestId            -- notification reference ID
udfParameters                -- optional (simulation params if simulateNotification=true)
makeAsync                    -- "true"/"false" (opposite of shouldDoNotificationCallSynchronously)
seqNo                        -- optional
```

---

### 11. Mandate Notification Status

**Endpoint:** `POST /mandates/webNotify/status`  
**Request type:** `WebNotifyStatus`

```
merchantRequestId   -- notification reference ID
udfParameters       -- optional
```

---

### 12. Split Settlement Update

**Endpoint:** `POST /transactions/settlement/split`  
**Request type:** `UpdateSplitSettlementRequest`

```
merchantRequestId       -- TR of original transaction
splitSettlementDetails  -- split details object
udfParameters           -- optional
```

---

## Request / Response Types

### Common Envelope

All gateway responses follow this outer structure:

```json
{
  "status": "SUCCESS|FAILURE|PENDING",
  "responseCode": "<code>",
  "responseMessage": "<message>",
  "payload": { ... },
  "udfParameters": "<optional>"
}
```

- `status` = `SUCCESS` + `responseCode` = `"SUCCESS"` + `responseMessage` = `"SUCCESS"` + `payload` present → actual success
- Otherwise evaluated as pending or failure

### TransactionStatusPayload (V1 Sync / Webhook)

```
merchantId, merchantChannelId, merchantRequestId
payerVpa, payeeVpa
amount
gatewayTransactionId       -- NPCI transaction ID
gatewayReferenceId         -- bank reference ID
gatewayResponseCode        -- see status mapping
gatewayResponseMessage
gatewayResponseStatus
transactionTimestamp       -- ZonedTime
udfParameters              -- optional
collectType                -- optional
customResponse             -- optional
bankCode, maskedAccountNumber -- optional
payerName, payeeName, payeeMcc -- optional
umn                        -- optional (mandate UMN)
refUrl, refCategory        -- optional
tpvValidationStatus        -- optional
seqNumber                  -- optional
isMarkedSpam, isVerifiedPayee -- optional bool
mutualFundDetails          -- optional
```

### TransactionStatusV2or360Payload (V2/360 Sync / Webhook)

Extends V1 payload with:
```
merchantChannelId          -- added
payerMobileNumber          -- optional
payeeMobileNumber          -- optional
payerMerchantCustomerId    -- optional
payeeMerchantCustomerId    -- optional
bankAccountUniqueId        -- optional
payerIfsc                  -- optional
payerMaskedAccNumber       -- optional
payerActype                -- optional
payerAccType               -- optional
```

### RefundStatusPayload

```
merchantId, merchantChannelId, merchantRequestId
originalMerchantRequestId
amount
gatewayResponseCode
gatewayResponseMessage
gatewayResponseStatus      -- used for refund status determination
refundReferenceId          -- bank reference for refund
transactionTimestamp       -- optional ZonedTime
udfParameters              -- optional
```

### UDF Parameters

`udfParameters` is a JSON-encoded string containing UDF fields (udf1–udf10), plus:
- `status` — customer VPA (for TPV payments)
- `code` — "TPV" if TPV payment
- `tpv` — TPV type ("PARTIAL" etc.)

---

## Error Codes & Status Mapping

### Gateway Response Code → Internal TxnStatus

| Gateway `responseCode` / condition | Internal TxnStatus |
|------------------------------------|--------------------|
| Outer status=SUCCESS, code=SUCCESS, message=SUCCESS, payload present, gatewayResponseCode=`"00"`, not tampered | `Charged` |
| Outer status=SUCCESS, code=SUCCESS, message=SUCCESS, payload present, gatewayResponseCode=`"00"`, for SBMD/OneTime mandate (excl. codes VH/VO/K1/59/01/RB/REQUEST_PENDING/REQUEST_NOT_FOUND), not tampered | `Charged` |
| `"REQUEST_PENDING"` | `Authorizing` (default) OR `AuthenticationFailed` if `shouldUpdateTxnToAuthenticationFailed "YES_BIZ"` flag is enabled |
| `"REQUEST_NOT_FOUND"` | `AuthenticationFailed` if `shouldUpdateTxnToAuthenticationFailed "NEWTON"` flag enabled; else `Authorizing` |
| `"RB"` (deemed/tampered outer response) | `AuthorizationFailed` (PendingResponse internally — retried) |
| Response tampered (signature mismatch) | `AuthorizationFailed` |
| Outer responseCode = `"DUPLICATE_REQUEST"` / `"GATEWAY_TIMEOUT"` / `"INTERNAL_SERVER_ERROR"` | `Authorizing` (PendingResponse — retried) |
| HTTP 429 (rate limited) | `PendingVBV` |
| HTTP error (non-429) | `AuthorizationFailed` |
| ECONNABORTED (timeout) | `Authorizing` |
| DECODE_ERROR | `Authorizing` |
| Otherwise | `AuthorizationFailed` |

### SBMD / One-Time Mandate Exclusion Codes

For SBMD or OneTime mandate transactions, these gateway response codes are **not** treated as success even if outer envelope says SUCCESS:
- `"VH"`, `"VO"`, `"K1"`, `"59"` — NPCI failure codes
- `"01"` — pending
- `"RB"` — deemed transaction
- `"REQUEST_PENDING"` — still pending
- `"REQUEST_NOT_FOUND"` — not found

### Mandate Status Response Codes

| `gatewayResponseCode` | Mandate Status |
|-----------------------|----------------|
| `"00"` | SUCCESS / Active |
| `"01"` | PENDING |
| `"JPMR"` | REVOKED (also: EXECUTE_REVOKE_PENDING / EXECUTE_REVOKE_INITIATED) |
| `"JPMP"` | PAUSE |
| `"JPMC"` | COMPLETED |
| `"JPMD"` | DECLINED by payer |
| `"JPMX"` | EXPIRED (no action by payer) |
| NPCI error code | FAILURE |
| `"QC"` | Revoke success (treated same as `"00"` for revoke) |

### Internal Error Response Codes (Juspay-generated)

| Code | Description |
|------|-------------|
| `JP_802` | PG request timed out. Awaiting response. |
| `JP_803` | Awaiting PG response (unknown error). |
| `JP_804` | TR information not available. Transaction Failed. |

### Non-Failure Response Codes (treated as Pending, not Failure)

- `"REQUEST_PENDING"`
- `"GATEWAY_TIMEOUT"`
- `"INTERNAL_SERVER_ERROR"`

### Non-Failure Response Messages (webhook execute mandate)

- `"EXECUTION_ALREADY_IN_PROGRESS"`
- `"INTERNAL_SERVER_ERROR"`

### TPV Validation Errors

| Error Code | Error Description |
|------------|-------------------|
| `INVALID_REQUEST` | `BANK_IFSC_CODE_MISSING` — bank IFSC missing for TPV hash calculation |
| `INVALID_REQUEST` | `BANK_ACCOUNT_DETAILS_MISSED` — no bank account details provided for TPV payment |

---

## ID Generation & Padding

### Transaction ID Prefix
```
generateUniqueId YESBIZ → prefix "YJP"
```

### UPI Request ID Padding (35-char scheme)

Both `merchantRequestId` (TR) and `upiRequestId` (TID) sent to YES Bank are padded to 35 characters:

```
[PREFIX(3)] + [PAD_LEN(2)] + [PADDING(N)] + [EULER_ID(up to 30)]
```

- Prefix: `"YJP"` (for YES_BIZ) or `"AXB"` (for AXIS_BIZ)
- PAD_LEN: 2-digit zero-padded integer (e.g., `"09"`)
- PADDING: N chars from `"gsqszvoufocsvmdhknkigsqszvoufocsvmdhknki"`
- EULER_ID: The internal Euler identifier (max 30 chars)
- Total: always 35 chars

**Reverse:** `removePaddingFromId` strips the prefix + padding to recover the original Euler ID.

---

## TPV (Third-Party Verification)

Both YES_BIZ and AXIS_BIZ support TPV mandate flows. TPV account hash is computed as:

```
SHA-256(account_number_part + first_4_chars_of_IFSC) → hex string
```

- For `PARTIAL` TPV: uses last 4 digits of account number
- For full TPV: strips leading zeros from account number

The hash array is sent in `payerAccountHashes` in mandate register requests and `udfParameters` for collect requests.

---

## Known Issues / TODOs

1. **`role` field in mandate status requests** is hardcoded to `"PAYEE"` with a TODO comment: `"TODO : this can be a ENUM"` (in `Transforms.hs:1126`).

2. **`YesBiz/Flow.hs` and `YesBiz/Types.hs` are empty stubs** — all actual logic lives in the shared Newton `Flows/` and `Newton/Types.hs` files. This is intentional architecture (code reuse), not missing code.

3. **Typo in log tag**: `makeWebMandateRequest` has a log tag `"Euler.API.Gateway.Gateway.AXIS_BIZ.Transforms::makeWebMandateRequest::timestamp"` (says AXIS_BIZ, should be YES_BIZ). Cosmetic only.

4. **`validateRemarks` bug in `getRemarksForYesBizSendCollect`**: On regex mismatch, returns the string literal `"defaultRemark"` (in quotes) instead of the `defaultRemark` variable (line 1645). The AXIS_BIZ variant `getRemarksForSendCollect` correctly returns the variable.

5. **`getUniqueId` in Transforms.hs** always generates an AXISBIZ-prefixed ID (`C.generateUniqueId Types.AXISBIZ`) — the YES_BIZ variant `getUniqueIdByGateway` is available but the default call site uses AXISBIZ. This may be intentional for flows that are fully shared.

6. **JWE/encryption not supported**: `isAxizBizJweFlow` returns `False` for YES_BIZ. The `iat` (timestamp) field in JWE requests is set to `Nothing` for YES_BIZ across all request builders.

7. **`axisBizSignatureKey` is always `Nothing`** for YES_BIZ: HMAC-based signature (used by AXIS_BIZ) is not applicable. YES_BIZ uses RSA-SHA256-PSS exclusively.
