# KOTAK_BIZ Connector — Technical Specification

**Connector:** KOTAK_BIZ  
**Gateway:** Kotak UPI Switch (UPI 2.0 / UPI V3)  
**Direction:** B — euler-api-gateway calls Kotak's API directly  
**Payment Methods:** UPI Collect, UPI Intent (SDK), UPI Mandate (e-NACH / SBMD), UPI Lite, VPA Verification, Refund, Split Settlement  
**Source:** `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/KOTAK_BIZ/`

---

## 1. Base URLs

| Environment | Variant | Base URL |
|---|---|---|
| UAT / Sandbox | Default | `https://merchantacquiring-uat.upiswitch.kotak.com/api/n2/merchants` |
| UAT / Sandbox | UPI V3 | `https://merchantacquiring-uat.upiswitch.kotakuat.bank.in/api/n2/merchants` |
| Production | Default | `https://merchantacquiring.upiswitch.kotak.com/api/n2/merchants` |
| Production | UPI V3 | `https://merchantacquiring.upiswitch.kotak.bank.in/api/n2/merchants` |

**V3 Feature Flag:** Redis feature `kotakBizUpiV3EnabledMerchants` (per-merchant toggle).  
**Environment selection:** Driven by `IsSandbox` boolean in the merchant gateway account (`MGA`). No environment-variable URL override.  
**Timeout:** None configured (`getRequestTimeout = Nothing`).

---

## 2. Authentication

### 2.1 Auth Types

KOTAK_BIZ supports two auth modes, selected per merchant via the `authType` field in `KotakBizDetails`:

| Auth Type | Description |
|---|---|
| `JWS` | Sign request body with Euler's RSA private key (RS256). Produces `SignedRequestBody`. |
| `JWE` | Sign with JWS first, then encrypt the `SignedRequestBody` with Kotak's RSA public key (RSA_OAEP_256 + A256GCM). Produces `EncryptedRequestBody`. |

### 2.2 JWS Signing (Outgoing Request)

1. Serialize the request payload as JSON.
2. Sign using Euler's RSA private key (`kotakBizEulerPrivateKey`) with algorithm RS256.
3. Key ID: `kotakBizSignKid`.
4. Output: `SignedRequestBody { signature: Text, payload: Text, protected: Text }`.

### 2.3 JWE Encryption (Outgoing Request — JWE mode only)

After JWS signing:
1. Encrypt the `SignedRequestBody` using Kotak's RSA public key (`kotakBizPublicKey`).
2. Algorithm: `RSA_OAEP_256`, Encryption: `A256GCM`.
3. Key ID: `kotakBizEncKid`.
4. Output: `EncryptedRequestBody { protected, encryptedKey, iv, cipherText, tag }`.
5. Wire format (JWE compact): `protected.encryptedKey.iv.cipherText.tag`.

### 2.4 Response Signature Verification (JWS mode)

- Kotak returns `x-response-signature` header (hex-encoded RSA-PSS-SHA256 signature).
- Verified against the sorted JSON of the response body using `kotakBizPublicKey`.
- If missing or tampered: response is treated as `FailureResponse`.

### 2.5 JWE Response Decryption (JWE mode)

1. Parse response body as `EncryptedRequestBody`.
2. Decrypt using Euler's private key (`kotakBizEulerPrivateKey`) with RSA OAEP.
3. Parse decrypted payload as `SignedRequestBody` (JWS JSON).
4. Convert JWS JSON to compact form: `protected.payload.signature`.
5. Verify JWS using Kotak's public key (`kotakBizPublicKey`).
6. Decode inner payload as the expected response type.

### 2.6 Webhook Signature Verification

- Header: `x-merchant-payload-signature` (Base16/hex RSA-PSS-SHA256).
- Verified against the **sorted JSON** string of the webhook body.
- For JWE merchants: signature check is skipped (`SkipSignature`).

---

## 3. Request Headers

### Standard Headers (all flows)

| Header | Value |
|---|---|
| `content-type` | `application/json` |
| `x-merchant-id` | `kotakBizMerchantId` |
| `x-merchant-channel-id` | `kotakBizChannelId` |
| `x-sub-merchant-id` | `kotakBizSubMerchantId` (optional) |
| `x-sub-merchant-channel-id` | `kotakBizSubMerchantChannelId` (optional) |
| `x-timestamp` | Current epoch milliseconds |
| `user-agent` | `api-gateway/1.0.0` |
| `referer` | `https://api.juspay.in` |
| `accept` | `application/json` |

### Intent-specific Headers (RegisterIntent flow)

Same as above, **plus**:

| Header | Value |
|---|---|
| `x-api-version` | `3` |

---

## 4. Credentials (`KotakBizDetails`)

| Field | Description |
|---|---|
| `kotakBizMerchantId` | Master merchant ID |
| `kotakBizChannelId` | Master merchant channel ID |
| `kotakBizSubMerchantId` | Sub-merchant ID (optional) |
| `kotakBizSubMerchantChannelId` | Sub-merchant channel ID (optional) |
| `kotakBizPublicKey` | Kotak's RSA public key (response verification + JWE encryption) |
| `kotakBizEulerPublicKey` | Euler's RSA public key |
| `kotakBizEulerPrivateKey` | Euler's RSA private key (JWS signing + JWE decryption) |
| `kotakBizSignKid` | Key ID for JWS signing |
| `kotakBizEncKid` | Key ID for JWE encryption |
| `authType` | `JWS` or `JWE` |
| `payeeVpa` | Merchant payee VPA |
| `refundVpa` | Merchant refund VPA |
| `mcc` | Merchant category code |
| `waitingPageExpiryInSeconds` | Collect timeout |
| `intentRegistrationEnabled` | Boolean for intent flow |
| `intentExpiryInMinutes` | Intent TTL |
| `madConfigurations` | `MADConfigurations` (e.g., `usePayeeNameFromResponse`) |

**Sub-merchant / Master-merchant:** When `MasterAccountDetail` is present, credentials are merged from both master and sub-merchant account details.

---

## 5. Endpoints

| Flow | Method | Endpoint |
|---|---|---|
| UPI Collect | POST | `/transactions/webCollect360` |
| Mandate Register (Collect) | POST | `/mandates/webMandate` |
| Transaction Status Sync | POST | `/transactions/status360` |
| Mandate Status Sync | POST | `/mandates/status` |
| Refund | POST | `/transactions/refund360` |
| Refund Sync | POST | `/transactions/refund360` |
| Register Intent (SDK) | POST | `/transactions/registerIntent` |
| Mandate Execute | POST | `/mandates/webExecute` |
| Mandate Revoke / Update | POST | `/mandates/webUpdate` |
| Mandate Notify (Pre-debit) | POST | `/mandates/webNotify` |
| Mandate Notify Status | POST | `/mandates/webNotify/status` |
| VPA Verification | POST | `/vpas/validity360` |
| Split Settlement Update | POST | `/split/update` |

---

## 6. Flows

### 6.1 UPI Collect (`sendCollect`)

**Entry point:** `sendCollectOrMandateCollect` — routes to `sendCollect` or `webMandateRegister` based on `isMandateReg` flag.

**Steps:**
1. Fetch `KotakBizDetails` from MGA (+ master account if present).
2. Generate TPV hash if TPV transaction (`checkGatewayAndGenerateHashTPVAccountDetails`).
3. Build `SendCollectRequest`.
4. Sign (JWS) or sign+encrypt (JWE) request body.
5. POST `<baseUrl>/transactions/webCollect360` with standard headers.
6. Verify response signature (`x-response-signature`).
7. Decode `SendCollectResponse`.
8. Map `gatewayResponseCode` to `TxnStatus`:
   - `"00"` → `Charged`
   - `"RB"` → `AuthorizationFailed`
   - `"REQUEST_PENDING"` → `Authorizing`
   - `"REQUEST_NOT_FOUND"` → `AuthorizationFailed`
   - Other → `AuthenticationFailed`

**Request: `SendCollectRequest`**

| Field | Type | Notes |
|---|---|---|
| `merchantRequestId` | Text | Unique request ID |
| `payerVpa` | Text | Payer's UPI VPA |
| `amount` | Text | Fixed precision (INR) |
| `iat` | Text | Epoch millis |
| `remarks` | Maybe Text | |
| `expireAfter` | Maybe Text | Collect expiry (seconds) |
| `payerAccountHashes` | Maybe [Text] | TPV bank account hashes |
| `udfParameters` | Maybe UdfParams | UDF1–10 from order |
| `subMerchantDetails` | Maybe SubMerchantDetails | Sub-merchant info |
| `mutualFundDetails` | Maybe [MutualFundDetails] | MF-specific fields |
| `splitSettlementDetails` | Maybe SplitDetails | Split settlement |
| `purpose` | Maybe Text | UPI purpose code |
| `refCategory` | Maybe Text | Ref category |
| `refUrl` | Maybe Text | Ref URL |
| `flow` | Maybe Text | Flow type |

**Response: `SendCollectResponse`**

| Field | Type | Notes |
|---|---|---|
| `status` | Status | SUCCESS / FAILURE / PENDING |
| `responseCode` | Text | Top-level gateway response code |
| `responseMessage` | Text | |
| `payload` | Maybe SendCollectResponsePayload | Present on success |

**`SendCollectResponsePayload`** includes: `merchantRequestId`, `gatewayTransactionId`, `gatewayResponseCode`, `gatewayResponseMessage`, `gatewayResponseStatus`, `amount`, `umn`, `orgMandateId`, `payerVpa`, `payeeVpa`.

---

### 6.2 Mandate Register via Collect (`webMandateRegister`)

**Steps:**
1. Build `WebMandate` request.
2. Sign / encrypt.
3. POST `/mandates/webMandate`.
4. Verify signature and decode `WebMandateResponse`.
5. On success: extract `umn`, `orgMandateId`, `merchantRequestId` as gateway params (`KotakBizMandateParams`).

**Request: `WebMandate`** (21 fields)

Key fields: `merchantRequestId`, `iat`, `payerVpa`, `amount`, `amountRule`, `amountRuleValue`, `endDate`, `startDate`, `frequency`, `remarks`, `mandateRequestExpiryMinutes`, `udfParameters`, `subMerchantDetails`, `mutualFundDetails`, `splitSettlementDetails`, `payerAccountHashes`, `makeAsync`, `revokableByCustomer`, `blockFund`, `shareToPayee`, `purpose`.

**Response: `WebMandateResponse`** → `WebMandatePayload` includes: `umn`, `orgMandateId`, `merchantRequestId`, `gatewayTransactionId`, `gatewayResponseCode`, `gatewayResponseMessage`, `gatewayResponseStatus`.

---

### 6.3 UPI Intent / SDK (`getSdkParams` / `registerIntent`)

**Entry point:** `getSdkParams` in `Flows/RegisterIntent.hs`.

**Steps:**
1. Validate TR from second factor (for TPV transactions).
2. Generate TPV hash.
3. Build `RegisterIntentRequest`.
4. Sign the request body (JWS or JWE).
5. POST `/transactions/registerIntent` with **intent headers** (`x-api-version: 3`).
6. Verify response.
7. On success: call `handleRegisterIntentSuccessResponse`:
   - If mandate register txn: build `KotakBizSdkParamsForMandateRegister`.
   - Otherwise: build `KotakBizSdkParams` (9 fields).
8. Return `SdkParamsSuccessResp`.

**Mutual fund rejection:** If `mutualFundDetails` required but missing → `JuspayDeclined` with code `MUTUAL_FUND_DETAILS_MISSING`.

**Request: `RegisterIntentRequest`**

| Field | Type |
|---|---|
| `merchantCustomerId` | Text |
| `merchantRequestId` | Text |
| `iat` | Text |
| `amount` | Maybe Text |
| `udfParameters` | Maybe UdfParams |
| `payerAccountHashes` | Maybe [Text] |
| `intentRequestExpiryMinutes` | Maybe Text |
| `mutualFundDetails` | Maybe [MutualFundDetails] |
| `refCategory` | Maybe Text |
| `refUrl` | Maybe Text |
| `remarks` | Maybe Text |
| `splitSettlementDetails` | Maybe SplitDetails |
| `flow` | Text |

**Response: `RegisterIntentResponse`** → `RegisterIntentPayload` includes: `orderId`, `gatewayTransactionId`, `payeeName`, `umn` (for mandate), and UPI deep-link params.

**SDK Params (`KotakBizSdkParams`):** `pa` (payee VPA), `pn` (payee name), `mc` (MCC), `tid`, `tr`, `am`, `cu`, `tn`, `mode`.

---

### 6.4 Transaction Sync (`transactionSync360`)

**Steps:**
1. Build `TransactionStatus360Request`.
2. POST `/transactions/status360`.
3. Verify response.
4. Decode `TransactionStatus360Response`.
5. Map `gatewayResponseCode` to `TxnStatus`:
   - `"00"` → `Charged`
   - `"RB"` → `AuthorizationFailed`
   - `"REQUEST_PENDING"` → `Authorizing`
   - `"REQUEST_NOT_FOUND"` → `AuthorizationFailed`
   - Other → `AuthenticationFailed`

**Non-failure response codes** (treated as pending/retry): `["REQUEST_PENDING", "GATEWAY_TIMEOUT", "INTERNAL_SERVER_ERROR"]`  
**Non-failure response messages:** `["EXECUTION_ALREADY_IN_PROGRESS", "INTERNAL_SERVER_ERROR"]`

**`isPendingResponse'` logic:**
- `"DUPLICATE_REQUEST"` | `"GATEWAY_TIMEOUT"` | `"INTERNAL_SERVER_ERROR"` → `PendingResponse`
- else → `FailureResponse`

**Request: `TransactionStatus360Request`**

| Field | Type |
|---|---|
| `merchantRequestId` | Text |
| `iat` | Text |
| `udfParameters` | Maybe UdfParams |
| `role` | Text (default: "PAYEE") |
| `refCategory` | Maybe Text |
| `refUrl` | Maybe Text |
| `subMerchantDetails` | Maybe SubMerchantDetails |

**Response: `TransactionStatus360Response`** → `TransactionStatus360Payload` includes: `merchantRequestId`, `gatewayTransactionId`, `gatewayResponseCode`, `gatewayResponseMessage`, `gatewayResponseStatus`, `amount`, `umn`, `payerVpa`, `payeeVpa`.

---

### 6.5 Mandate Sync (`mandateSync`)

**Steps:**
1. Build `MandateStatus` request.
2. POST `/mandates/status`.
3. Decode `MandateStatusResponse`.
4. Map:
   - `"01"` → `PendingResponse`
   - `"00"` → `SuccessResponse`
   - Other → depends on `isPendingResponse'`

**Request: `MandateStatus`**

| Field | Type |
|---|---|
| `originalMerchantRequestId` | Text |
| `iat` | Text |
| `udfParameters` | Maybe UdfParams |
| `role` | Text (default: "PAYEE") |

**Response: `MandateStatusResponse`** → `MandateStatusPayload` includes: `umn`, `orgMandateId`, `merchantRequestId`, `gatewayResponseCode`, `gatewayResponseMessage`, `gatewayResponseStatus`, `amount`, `currentBlockedAmount`.

---

### 6.6 Refund (`initiateRefund`)

**Steps:**
1. Determine refund type: `ONLINE` (standard) or `UDIR` (instant/bank).
2. Build `RefundRequest` or `InstantRefundRequest`.
3. POST `/transactions/refund360`.
4. Verify response and decode `RefundResponse`.

**Request: `RefundRequest`**

| Field | Type |
|---|---|
| `merchantRequestId` | Text |
| `refundMerchantRequestId` | Text |
| `amount` | Text |
| `iat` | Text |
| `udfParameters` | Maybe UdfParams |
| `refundType` | Text (`"ONLINE"`) |
| `splitSettlementDetails` | Maybe SplitDetails |
| `remarks` | Maybe Text |
| `subMerchantDetails` | Maybe SubMerchantDetails |
| `mutualFundDetails` | Maybe [MutualFundDetails] |
| `refCategory` | Maybe Text |

**Request: `InstantRefundRequest`** (UDIR)

| Field | Type |
|---|---|
| `merchantRequestId` | Text |
| `refundMerchantRequestId` | Text |
| `amount` | Text |
| `iat` | Text |
| `udfParameters` | Maybe UdfParams |
| `refundType` | Text (`"UDIR"`) |
| `beneficiaryIFSC` | Text |
| `beneficiaryAccountNumber` | Text |
| `beneficiaryName` | Text |

**Response: `RefundResponse`** → `RefundResponsePayload` includes: `merchantRequestId`, `refundMerchantRequestId`, `gatewayResponseCode`, `gatewayResponseMessage`, `gatewayResponseStatus`.

---

### 6.7 Refund Sync (`initiateRefundSync`)

Same endpoint as Refund: POST `/transactions/refund360`.  
Uses the same `RefundRequest` structure with the refund merchant request ID for lookup.  
Response decoded as `RefundResponse`.

---

### 6.8 Mandate Execute (`executeMandate`)

**Steps:**
1. Build `WebExecute` request.
2. Sign / encrypt.
3. POST `/mandates/webExecute`.
4. Verify response and decode `WebExecuteResponse`.
5. Map `gatewayResponseCode`:
   - `"00"` → `SuccessResponse` → `Charged`
   - `"01"` → `PendingResponse` → `Authorizing`
   - Other → `FailureResponse` → `AuthorizationFailed`

**Error mapping:**
- `ECONNABORTED` → `Authorizing`
- `DECODE_ERROR` → `Authorizing`
- Other → `AuthorizationFailed`

**GSM lookup codes:**
- `JP_802` — "PG request timed out."
- `JP_803` — "Awaiting pg response."

**Request: `WebExecute`** (13 fields)

Key fields: `merchantRequestId`, `iat`, `amount`, `umn`, `originalMerchantRequestId`, `remarks`, `makeAsync`, `udfParameters`, `subMerchantDetails`, `mutualFundDetails`, `splitSettlementDetails`, `payerAccountHashes`, `mandateExecutionTimestamp`.

**Response: `WebExecuteResponse`** → `WebExecutePayload` includes: `umn`, `orgMandateId`, `merchantRequestId`, `gatewayTransactionId`, `gatewayResponseCode`, `gatewayResponseMessage`, `gatewayResponseStatus`, `amount`.

---

### 6.9 Mandate Revoke / Auto-Revoke (`revokeMandate` / `autoRevokeMandateToken`)

**Steps:**
1. Get `originalMerchantRequestId` from gateway params or second factor.
2. Build `WebUpdate` with `requestType = REVOKE`.
3. POST `/mandates/webUpdate`.
4. Verify response and decode `WebUpdateResponse`.

**Request: `WebUpdate`** (10 fields)

Key fields: `merchantRequestId`, `iat`, `originalMerchantRequestId`, `requestType` (`REVOKE` or `UPDATE`), `mandateRequestExpiryMinutes`, `amount`, `remarks`, `validityEnd`, `makeAsync`, `udfParameters`.

---

### 6.10 Mandate Update (`updateMandateRequest`)

Two sub-flows depending on payment method:

**UPI Collect (`UPI_COLLECT` / `COLLECT`):**
- Build `WebUpdate` with `requestType = UPDATE`.
- POST `/mandates/webUpdate`.

**UPI Intent:**
- Build `RegisterIntentRequest` with `flow = "MANDATE"`.
- POST `/transactions/registerIntent`.
- Returns SDK params + intent URL (`upi://mandate?...`).

**Sync Update Mandate (`syncUpdateMandate`):**
- POST `/mandates/status` to check mandate status post-update.
- Maps `("00", "SUCCESS")` → Success, `("01", "PENDING")` → Pending.

---

### 6.11 Mandate Notification / Pre-debit (`sendNotification` / `initSendNotification`)

**Steps:**
1. Build `WebNotify` request.
2. POST `/mandates/webNotify`.
3. Verify response; decode `WebNotifyResponse`.
4. `gatewayResponseCode` `"00"` or `"01"` → `PENDING` status; else `FAILURE`.

**Request: `WebNotify`** (8 fields)

| Field | Type |
|---|---|
| `merchantRequestId` | Text |
| `originalMerchantRequestId` | Maybe Text |
| `umn` | Maybe Text |
| `amount` | Text |
| `iat` | Text |
| `mandateExecutionTimestamp` | Maybe ZonedTime |
| `remarks` | Maybe Text |
| `udfParameters` | Maybe UdfParams |

---

### 6.12 Mandate Notification Sync (`syncNotification` / `initSyncNotification`)

**Steps:**
1. Build `WebNotifyStatus` request.
2. POST `/mandates/webNotify/status`.
3. Decode `WebNotifyStatusResponse`.
4. `gatewayResponseCode` `"00"` + not tampered → `SUCCESS`; `"01"` → `PENDING`; else `FAILURE`.

**Request: `WebNotifyStatus`** (4 fields)

| Field | Type |
|---|---|
| `merchantRequestId` | Text |
| `originalMerchantRequestId` | Maybe Text |
| `iat` | Text |
| `udfParameters` | Maybe UdfParams |

---

### 6.13 VPA Verification (`verifyVPA`)

**Note:** Always uses JWE flow (response is always decrypted regardless of `authType`).

**Steps:**
1. Build `VerifyVpa360Request` with `vpa`.
2. POST `/vpas/validity360`.
3. Decrypt JWE response.
4. Decode `VerifyVpa360Response`.
5. `gatewayResponseCode == "00"` → `VALID`; else `INVALID`.

**Request: `VerifyVpa360Request`**

| Field | Type |
|---|---|
| `vpa` | Text |
| `iat` | Text |
| `udfParameters` | Maybe UdfParams |
| `role` | Text (default "PAYEE") |

**Response: `VerifyVpa360Response`** → `IsValidVpaPayload`: `vpa`, `name`, `gatewayResponseCode`, `gatewayResponseMessage`.

---

### 6.14 Mandate Setup (`getSetupMandate`)

**Steps (post-registration):**
1. If txn status is `AuthenticationFailed` / `AuthorizationFailed`: check second factor UPI auth params.
   - If `mandateRegStatus == "MDTREG_SUCCESS"` → `RevokeInternallyAndSetupMandateAsFailure`.
   - Else → `SetupMandateFailureResp`.
2. Try to decode `gatewayResponse` as `WebExecutePayload`.
   - On success: extract `umn`, `orgMandateId`, `originalMerchantRequestId` → `KotakBizMandateParams`.
3. Fallback: try decode as `MandateStatusPayload`.
   - `"00"` or `"01"` → success.
4. Fallback: POST `/mandates/status` to fetch registration details.

---

### 6.15 Mandate Status Check (`checkMandateStatus`)

**Steps:**
1. Get `originalMerchantRequestId` from gateway params.
2. POST `/mandates/status`.
3. Map `gatewayResponseStatus`:
   - `"SUCCESS"` → `Active`
   - `"FAILURE"` / `"DECLINED"` → `Failure`
   - `"REVOKED"` → `Revoked`
   - `"PAUSED"` / `"PAUSE"` → `Paused`
   - `"COMPLETED"` / `"EXPIRED"` → `Expired`

---

### 6.16 Post-Transaction Split Settlement (`postTxnsSplitSettlement`)

**Steps:**
1. Build `UpdateSplitSettlementRequest`.
2. Sign / encrypt.
3. POST `/split/update`.
4. Response: `UpdateSplitSettlementResponse` with `status` = `"CREATED"` on success.

**Request: `UpdateSplitSettlementRequest`**

| Field | Type |
|---|---|
| `merchantRequestId` | Text |
| `splitSettlementDetails` | Maybe SplitDetails |
| `udfParameters` | Maybe UdfParams |

---

### 6.17 Webhook Processing (`validateAndExtractWebhook`)

Webhooks are identified by the `type` field in the payload.

#### Webhook Type → Handler Mapping

| Webhook `type` | Internal Type | Event |
|---|---|---|
| `MERCHANT_CREDITED_VIA_COLLECT` | `TransactionSuccessWebhook` | Transaction credit |
| `MERCHANT_CREDITED_VIA_PAY` | `TransactionSuccessWebhook` | Transaction credit |
| `MERCHANT_INCOMING_CREATE_MANDATE` | `MandateWebhook` | Mandate created |
| `MERCHANT_OUTGOING_CREATE_MANDATE` | `MandateWebhook` | Mandate created |
| `MERCHANT_OUTGOING_UPDATE_MANDATE` | `UpdateMandateWebhook` | Mandate updated |
| `MERCHANT_OUTGOING_EXECUTE_MANDATE` | `ExecuteMandateWebhook` | Mandate executed |
| `MERCHANT_NOTIFICATION_MANDATE` | `NotificationStatusWebhook` | Notification status |
| `MERCHANT_INCOMING_PAUSE_MANDATE` | `MandateStatusUpdate` | Pause/unpause |
| `MERCHANT_INCOMING_UPDATE_MANDATE` | `MandateStatusUpdate` | Mandate status update |
| `MANDATE_STATUS_UPDATE` | `MandateStatusAutoUpdate` | Auto status update |
| `CUSTOMER_CREDITED_VIA_PAY` | `P2PTransactionWebhook` | P2P transaction |
| `COLLECT_REQUEST_RECEIVED` | `P2PTransactionWebhook` | P2P collect |
| `CUSTOMER_CREDITED_VIA_COLLECT` | `P2PTransactionWebhook` | P2P transaction |
| `CUSTOMER_DEBITED_FOR_MERCHANT_VIA_COLLECT` | `P2PTransactionWebhook` | P2P debit |
| `CUSTOMER_DEBITED_FOR_MERCHANT_VIA_PAY` | `P2PTransactionWebhook` | P2P debit |
| `CUSTOMER_DEBITED_VIA_COLLECT` | `P2PTransactionWebhook` | P2P debit |
| `CUSTOMER_DEBITED_VIA_PAY` | `P2PTransactionWebhook` | P2P debit |
| `COLLECT_REQUEST_SENT` | `P2PTransactionWebhook` | P2P collect sent |
| `CUSTOMER_INCOMING_MANDATE_*` | `P2PMandateWebhook` | P2P mandate |
| `CUSTOMER_OUTGOING_MANDATE_*` | `P2PMandateWebhook` | P2P mandate |
| `CUSTOMER_COMPLAINT_RESOLVED` | `CustomerComplaintWebhook` | Complaint |
| `CUSTOMER_LINK_ACCOUNT` | `AccountLinkedByCustomer` | Account link |
| `UPI_NUMBER_MAPPER` | `UpiNumberMapperWebhook` | UPI porting |
| `CUSTOMER_ONLINE_REFUND` | `RefundStatusUpdate` | Refund status |
| `CUSTOMER_OFFLINE_REFUND` | `RefundStatusUpdate` | Refund status |
| `CUSTOMER_COMPLAINT_RAISED` | `CustomerComplaintRaisedWebhook` | Complaint raised |
| `UPI_LITE_TOPUP` | `UPILiteTopUpWebhook` | UPI Lite top-up |
| `UPI_LITE_DEREGISTRATION` | `UPILiteTopUpWebhook` | UPI Lite dereg |
| Any other | `ErrorResponseWebhook` | Error |

#### Event Type → `WebhookEvent` Mapping

| Webhook Type | `eventType` |
|---|---|
| Transaction / Mandate execute | `TRANSACTION` |
| Notification | `NOTIFICATION` |
| Mandate Update / Status | `MANDATE_UPDATE` / `MANDATE_STATUS` |
| P2P, Complaint, UPI Lite, Mapper, Account | `MERCHANT_CUSTOMER` |
| Refund | `REFUND` |

#### Mandate Status Flow (`getFlowStatus`)

| `mandateType` | `gatewayResponseStatus` | `FlowStatus` |
|---|---|---|
| `PAUSE` / `PAUSED` | any | `MandateEventStatus Paused` |
| `UNPAUSE` / `UNPAUSED` | any | `MandateEventStatus Active` |
| `REVOKE` / `REVOKED` | `SUCCESS` | `MandateEventStatus Revoked` |
| `COMPLETED` | any | `MandateEventStatus Expired` |
| Other | any | `Nothing` |

#### `MandateStatusAutoUpdate` handling

- If `role == "PAYEE"`: processed as mandate status update (requires `orgMandateId` + `gatewayResponseStatus`).
- If `role != "PAYEE"`: processed as P2P mandate webhook.

---

## 7. Response Status Codes

### General Response Handle Logic (`handleResponseForKotakBiz` / `getResponseHandle`)

A response is considered a success only if ALL of the following are true:
- `status == SUCCESS`
- `responseCode == "SUCCESS"`
- `responseMessage == "SUCCESS"`
- `payload` is present

If not a success:
- `respCode == "DUPLICATE_REQUEST"` | `"GATEWAY_TIMEOUT"` | `"INTERNAL_SERVER_ERROR"` → `PendingResponse`
- `gatewayRespCode == "RB"` | `"JPME"` → `PendingResponse`
- Else → `FailureResponse`

### Gateway Response Code Mapping

| `gatewayResponseCode` | Meaning | Juspay TxnStatus |
|---|---|---|
| `"00"` | Success | `Charged` |
| `"01"` | Pending / Initiated | `Authorizing` |
| `"RB"` | Rejected by bank | `AuthorizationFailed` |
| `"REQUEST_PENDING"` | In-flight | `Authorizing` |
| `"REQUEST_NOT_FOUND"` | Not found | `AuthorizationFailed` |
| Other | Failure | `AuthenticationFailed` |

### Mandate Status Mapping (`mapMandateStatus`)

| `gatewayResponseStatus` | `Mandate.MandateStatus` |
|---|---|
| `SUCCESS` | `Active` |
| `FAILURE` / `DECLINED` | `Failure` |
| `REVOKED` | `Revoked` |
| `PAUSED` / `PAUSE` | `Paused` |
| `COMPLETED` / `EXPIRED` | `Expired` |
| Other / None | Existing status unchanged |

### Sync Update Mandate Codes

| Code | Status | Action |
|---|---|---|
| `("00", "SUCCESS")` | Success | Return updated fields |
| `("01", "PENDING")` | Pending | Retry |
| Other | Failure | Mark as failure |

### Retryable codes (mandate update sync)

`["REQUEST_PENDING", "REQUEST_NOT_FOUND", "GATEWAY_TIMEOUT", "INTERNAL_SERVER_ERROR"]`

---

## 8. Error Handling

### Client / Network Errors

| Error Type | Outgoing Response |
|---|---|
| HTTP client error | `handleClientError` → `AuthenticationFailed` |
| Decode error | `UNEXPECTED_GATEWAY_RESPONSE` |
| JWS RSA verification failed | `JWS_RSA_VERIFICATION_FAILED` exception |
| Missing TR | `MISSING_MANDATORY_PARAM` → `JuspayDeclined` |
| Missing mutual fund details | `MUTUAL_FUND_DETAILS_MISSING` → `JuspayDeclined` |
| Tampered signature | `FailureResponse` / `SIGNATURE_VALIDATION_FAILED` |

### TPV Validation Errors

- `BANK_IFSC_CODE_MISSING` — when IFSC is absent for a TPV transaction.
- `INVALID_REQUEST` — malformed TPV account details.

### Execute Mandate API Error GSM Codes

| `errType` | TxnStatus | GSM Code | Message |
|---|---|---|---|
| `ECONNABORTED` | `Authorizing` | `JP_802` | PG request timed out |
| `DECODE_ERROR` | `Authorizing` | `JP_803` | Awaiting pg response |
| Other | `AuthorizationFailed` | `JP_803` | Awaiting pg response |

---

## 9. Supplementary Types

### `SubMerchantDetails` (18 fields)

Used in collect/mandate flows for marketplace routing.

Key fields: `subMerchantId`, `subMerchantName`, `subMerchantMcc`, `subMerchantVpa`, `subMerchantIfsc`, `subMerchantAccountNumber`, `subMerchantBusinessName`, `subMerchantBusinessType`, `subMerchantOwnership`, `subMerchantIdentifier`, `subMerchantCategory`, `subMerchantCountry`, `subMerchantCity`, `subMerchantPincode`, `subMerchantState`, `subMerchantPhone`, `subMerchantEmail`, `subMerchantUrl`.

### `MutualFundDetails` (16 fields)

Used for mutual fund SIP transactions.

Key fields: `memberId`, `userId`, `mfPartner`, `folioNumber`, `orderNumber`, `amount`, `schemeCode`, `amcCode`, `panNumber`, `investmentType`, `amcName`, `amcNumber`, `ihNumber`, `schemeType`, `schemeName`, `sipTrxnNo`.

### `SplitDetails`

| Field | Type |
|---|---|
| `splitType` | Text (`"AMOUNT"` or `"LATER"`) |
| `merchantSplit` | Maybe Text |
| `partnersSplit` | Maybe [PartnersSplit] |

### `PartnersSplit`

| Field | Type |
|---|---|
| `partnerId` | Text |
| `value` | Text |

### `KotakBizMandateParams`

| Field | Type |
|---|---|
| `umn` | Maybe Text |
| `orgMandateId` | Maybe Text |
| `originalMerchantRequestId` | Text |

Stored as gateway params in the mandate record after successful registration.

### `KotakBizMetadata`

Order metadata stored as JSON with `KOTAK_BIZ`-prefixed keys. Used for purpose codes, split type, etc.

### Purpose Codes (`checkPurposeCode`)

| Code | Meaning |
|---|---|
| `"44"` | `UPI_LITE` |
| `"92"` | `DIGITAL_RUPEE` |
| `"00"` | `DEFAULT` |

### UDF Parameters (`Udf`)

10 optional text fields (`udf1`–`udf10`) mapped from the order's UDF fields.

---

## 10. Webhook Payload Types

### `P2PWebhookPayload` (76 fields)

Used for: P2P transactions, P2P mandates, complaints, mandate status auto-update (non-PAYEE role).

Key fields: `type` (responseType), `merchantRequestId`, `gatewayTransactionId`, `gatewayResponseCode`, `gatewayResponseMessage`, `gatewayResponseStatus`, `gatewayReferenceId`, `amount`, `merchantId`, `merchantChannelId`, `payerVpa`, `payeeVpa`, `umn`, `orgMandateId`, `role`, `mandateType`, `gatewayMandateId`, `transactionTimestamp`.

### `TransactionStatusPayload`

Key fields: `merchantRequestId`, `gatewayTransactionId`, `gatewayResponseCode`, `gatewayResponseMessage`, `amount`, `payerVpa`, `payeeVpa`, `gatewayReferenceId`.

### `WebExecutePayload`

Key fields: `merchantRequestId`, `umn`, `orgMandateId`, `gatewayTransactionId`, `gatewayResponseCode`, `gatewayResponseMessage`, `amount`.

### `MandateWebhookPayload`

Key fields: `gatewayMandateId`, `gatewayResponseCode`, `gatewayResponseMessage`.

### `WebUpdatePayload`

Key fields: `umn`, `merchantRequestId`, `mandateType`, `gatewayResponseCode`, `gatewayResponseMessage`, `gatewayResponseStatus`, `gatewayReferenceId`.

### `MandateStatusUpdateWebhook`

Key fields: `umn`, `role`, `orgMandateId`, `mandateType`, `gatewayResponseCode`, `gatewayResponseMessage`, `gatewayResponseStatus`, `amount`, `validityEnd`.

### `RefundStatusPayload`

Key fields: `merchantRequestId`, `refundMerchantRequestId`, `gatewayResponseCode`, `gatewayResponseMessage`.

### `WebNotifyStatusPayload`

Key fields: `merchantRequestId`, `gatewayResponseCode`, `gatewayResponseMessage`, `gatewayReferenceId`.

### `UPILiteWebhookPayload`

Key fields: `merchantRequestId`, `merchantId`, `merchantChannelId`, `payerVpa`, `payeeVpa`, `amount`, `gatewayTransactionId`, `gatewayReferenceId`, `gatewayResponseCode`, `gatewayResponseMessage`, `_type`.

### `UpiNumberMapperWebhookPayload`

Key fields: `merchantCustomerId`, `customerMobileNumber`, `merchantChannelId`, `merchantId`, `status`, `action`.

### `AccountLinkedByCustomerWebhook`

Key fields: `merchantCustomerId`, `customerMobileNumber`, `merchantId`, `accounts` (list of `Account`).

**`Account`** fields: `encryptedAcccountNumber` (RSA-OAEP-SHA256 encrypted, Base64), `maskedAccountNumber`, `ifsc`, `referenceId`, `bankName`, `bankCode`, `name`, `responseType`.

Account number is decrypted using `kotakBizEulerPrivateKey` (RSA-OAEP-SHA256).

### `CustomerComplaintRaisedWebhookPayload`

Key fields: `payerVpa`, `payeeVpa`, `merchantChannelId`, `merchantId`, `payerMobileNumber`, `transactionAmount`, `originalGatewayTransactionId`, `originalTransactionTimestamp`, `crn`, `gatewayComplaintId`, `gatewayResponseCode`, `gatewayResponseMessage`, `gatewayResponseStatus`, `reqAdjAmount`, `reqAdjCode`, `reqAdjFlag`, `remarks`.

---

## 11. Key Design Notes

1. **Dual-mode auth:** JWS (sign only) and JWE (sign + encrypt) are both supported and selected per merchant. All response handling adapts accordingly — JWE always decrypts, JWS always verifies the `x-response-signature` header.

2. **Sorted JSON for signature verification:** Webhook and response signature verification uses JSON keys sorted alphabetically before stringification (`sortJsonAndStringify`).

3. **Sub-merchant / Master-merchant hierarchy:** `KotakBizMasterMerchantAccountDetails` and `KotakBizSubMerchantAccountDetails` are merged to produce the final `KotakBizDetails`. Sub-merchant IDs appear in headers when present.

4. **Intent URL scheme:** `upi://mandate?<sorted-params>` — spaces are URL-encoded as `%20`.

5. **Mandate gateway params:** After mandate registration, `KotakBizMandateParams { umn, orgMandateId, originalMerchantRequestId }` is stored as the mandate's `gatewayParam` field (JSON-serialized). All subsequent mandate operations (execute, revoke, notify, sync) key off `originalMerchantRequestId`.

6. **UPI V3:** Enabled per merchant via Redis feature flag. Uses alternate base URLs (`.kotakuat.bank.in` / `.kotak.bank.in`).

7. **Payee name resolution:** If `MADConfigurations.usePayeeNameFromResponse = true`, the payee name from Kotak's response is used; otherwise `kotakBizMerchantId` is used as the payee name.

8. **Amount formatting:** Uses `MFUtils.toTextFixedPrecision MFUtils.KOTAKBIZ` for currency-aware fixed-precision formatting.

9. **Pending on signature missing:** If `x-response-signature` header is absent, `isSignatureTampered = True` (treated as tampered → `FailureResponse`). Callers should be aware that missing headers are not silently ignored.

10. **NEWTON_BIZ shadow comparison:** For Intent and Webhook flows, a forked comparison against NEWTON_BIZ is performed (`Common.forkSuccessComparison` / `Common.forkWebhookSuccessComparison`). This is a read-only observability check and does not affect the primary flow.

---

*Generated from source: `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/KOTAK_BIZ/` — Routes.hs, Types.hs, Transforms.hs, Flows/*.hs*
