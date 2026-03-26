# SODEXO Payment Gateway Connector — Technical Specification

> **Generated from source code analysis of:**
> - `euler-api-gateway/gateway/src/Euler/API/Gateway/Gateway/SODEXO/`
> - `euler-api-txns/euler-x/src-generated/Product/Gateway/Remote/Sodexo.hs`

---

## Table of Contents

1. [Overview](#1-overview)
2. [Base URLs](#2-base-urls)
3. [Authentication](#3-authentication)
4. [Credentials / Account Fields](#4-credentials--account-fields)
5. [Flows](#5-flows)
   - 5.1 [Initiate Transaction (Redirect)](#51-initiate-transaction-redirect)
   - 5.2 [Sync & Verify Gateway Response (Integrity Check)](#52-sync--verify-gateway-response-integrity-check)
   - 5.3 [Transaction Sync (Stateless Polling)](#53-transaction-sync-stateless-polling)
   - 5.4 [Capture Response (PGR Decode)](#54-capture-response-pgr-decode)
   - 5.5 [Get Status](#55-get-status)
   - 5.6 [Initiate Refund](#56-initiate-refund)
   - 5.7 [Refund Sync](#57-refund-sync)
   - 5.8 [Get Card Info (Source Detail)](#58-get-card-info-source-detail)
   - 5.9 [Get Source Detail (Async)](#59-get-source-detail-async)
   - 5.10 [Remove Saved Card (Delete Source)](#510-remove-saved-card-delete-source)
6. [Request & Response Types](#6-request--response-types)
7. [Error Codes & Status Mapping](#7-error-codes--status-mapping)
8. [Known Issues / TODOs](#8-known-issues--todos)

---

## 1. Overview

SODEXO is a meal/food-purpose wallet gateway integrated via the **Zeta Pay** platform. The connector supports:

- **Payment initiation** via two flows:
  - Standard (using a stored `sourceId` / card token)
  - Seamless (passing raw card details as `sourceInfo`)
- **Transaction status sync** with integrity verification (amount + txnId check)
- **Refund initiation** and **refund status sync**
- **Saved card management**: fetch source info, remove saved card
- **Purpose is hardcoded to `"FOOD"`** — the only purpose permitted by Sodexo/Zeta

The gateway type tag is `SODEXO`. The gateway identifier used for transaction ID generation is `"SODEXO"` (prefix applied via `generateUniqueId`). Transaction IDs are sanitized to allow only `[a-zA-Z0-9_-]` characters.

**API Version:** v1.0 is used for most operations; v2.0 path exists but is not invoked in current code (the `isV1` flag is always `True` at call sites for transaction/sync calls, and `False` for refund calls — both resolve to the same host).

---

## 2. Base URLs

### Transaction Endpoints

| Environment | Host                      | Path                          |
|-------------|---------------------------|-------------------------------|
| Sandbox     | `pay-gw.preprod.zeta.in`  | `/v1.0/sodexo/transactions`   |
| Production  | `pay.gw.zetapay.in`       | `/v1.0/sodexo/transactions`   |

> When `isV1 = True` (default for all call sites), the path is `/v1.0/sodexo/transactions`.  
> When `isV1 = False`, the path would be `/v2.0/sodexo/transactions` (unused in practice for current flows).

### Source / Card Endpoints

| Environment | Host                      | Path                    |
|-------------|---------------------------|-------------------------|
| Sandbox     | `pay-gw.preprod.zeta.in`  | `/v1.0/sodexo/sources`  |
| Production  | `pay.gw.zetapay.in`       | `/v1.0/sodexo/sources`  |

All connections use **HTTPS on port 443**.

### Full Endpoint Map

| Operation                          | Method | Full Path (relative to base)                              | API Tag                  |
|------------------------------------|--------|-----------------------------------------------------------|--------------------------|
| Create Transaction                 | POST   | `POST /v1.0/sodexo/transactions`                          | `GW_INIT_TXN`            |
| Create Transaction with SourceInfo | POST   | `POST /v1.0/sodexo/transactions/createWithSourceInfo`     | `GW_INIT_TXN`            |
| Transaction Status (Sync)          | GET    | `GET /v1.0/sodexo/transactions/request_id/{requestId}`    | `GW_TXN_SYNC`            |
| Initiate Refund                    | POST   | `POST /v2.0/sodexo/transactions/refund`                   | `GW_INIT_REFUND`         |
| Refund Status (Sync)               | GET    | `GET /v2.0/sodexo/transactions/{purchaseTransactionId}/refunds` | `GW_REFUND_SYNC`    |
| Get Source Info                    | GET    | `GET /v1.0/sodexo/sources/{sourceId}`                     | `GW_LIST_SODEXO_CARDS`   |
| Remove Saved Card                  | POST   | `POST /v1.0/sodexo/sources/unsave`                        | `GW_DELETE_SODEXO_CARD`  |

> **Note on refund base URL:** Refund calls (`doRefundCall`, `doRefundSyncCall`) are made with `isV1 = False`, which resolves to `/v2.0/sodexo/transactions`. All other calls use `isV1 = True` → `/v1.0/sodexo/transactions`.

---

## 3. Authentication

**Mechanism: API Key in HTTP Header**

All requests to Sodexo/Zeta carry the API key as a custom HTTP header:

```
apiKey: <sodexo_api_key>
Content-Type: application/json
```

There is **no HMAC, RSA, or OAuth** involved. The API key is loaded at application startup from a secrets store and cached as an in-memory option.

### API Key Resolution Logic

```
if testMode (sandbox):
    load SodexoUatKey  → UatApiKey Text
else:
    load SodexoProdKey → ProdApiKey Text
```

### Acquirer ID Resolution Logic

```
if testMode:
    load SodexoUatAcquireId  → UatAcquirerId Text
else:
    load SodexoProdAcquireId → ProdAcquirerId Text
```

The Acquirer ID is used as the `merchantInfo.aid` field in all transaction requests (see Section 6).

### Option Keys (Internal Config)

| Option Key           | Type             | Environment  | Purpose                    |
|----------------------|------------------|--------------|----------------------------|
| `SodexoUatKey`       | `UatApiKey Text` | Sandbox/UAT  | API key for test mode       |
| `SodexoProdKey`      | `ProdApiKey Text`| Production   | API key for production      |
| `SodexoUatAcquireId` | `UatAcquirerId Text` | Sandbox/UAT | Acquirer ID for test mode |
| `SodexoProdAcquireId`| `ProdAcquirerId Text`| Production  | Acquirer ID for production |

---

## 4. Credentials / Account Fields

Decoded from `MerchantGatewayAccount.accountDetails` (JSON) into `SodexoDetails`:

| Field                          | Type   | Required | Description                                                                                 |
|--------------------------------|--------|----------|---------------------------------------------------------------------------------------------|
| `sodexoMerchantId`             | Text   | Yes      | Merchant ID (`mid`) assigned by Sodexo/Zeta                                                 |
| `sodexoTerminalId`             | Text   | Yes      | Terminal ID (`tid`) assigned by Sodexo/Zeta                                                 |
| `allowFetchBalance`            | Text   | Yes      | Whether balance fetch is permitted (e.g., `"true"` / `"false"`)                             |
| `storeAndUseSourceIdImplicitly`| Text   | Yes      | Controls implicit save-and-reuse of `sourceId` for wallet debit redirect flows (`"true"`/`"false"`) |

**Validation logic (txns side):**  
A transaction using a saved source (`sourceId`) is considered valid if:
- `sourceId` is a non-empty/non-false string (`isTrueString`)
- AND one of:
  - `addToLocker = true` on the transaction
  - `sourceObject == redirectWalletDebit` AND `storeAndUseSourceIdImplicitly == "true"`
  - (Note: `expressCheckout = true` always returns `false` — express checkout is NOT supported)

---

## 5. Flows

### 5.1 Initiate Transaction (Redirect)

**Trigger:** `API.RedirectTransaction` → `Flow.initiateTransaction`

**Purpose:** Start a Sodexo payment. Returns a redirect URL to the Zeta payment page.

**Decision Tree:**

```
RedirectTransaction received
    │
    ├── txnCardInfo.cardIsin is Just (card ISIN present)
    │       │
    │       ├── cardData.cardToken is truthy (sourceId available)
    │       │       → Build SodexoCreateTransactionRequest (with sourceId)
    │       │       → POST /v1.0/sodexo/transactions
    │       │
    │       └── cardData.cardToken is empty/falsy
    │               → Build CreateTxnWithSourceInfoRequest (raw card data)
    │               → POST /v1.0/sodexo/transactions/createWithSourceInfo
    │               (Seamless / new-card flow)
    │
    └── txnCardInfo.cardIsin is Nothing (no card ISIN)
            → Build SodexoCreateTransactionRequest (sourceId = Nothing)
            → POST /v1.0/sodexo/transactions
```

**Response Handling (`handleResponseAndCallRedirectUrl`):**

| Response                         | Action                                                                                     |
|----------------------------------|-------------------------------------------------------------------------------------------|
| `Left ClientError`               | Parse optional `SodexoErrorResponse` from error body; return `PaymentErrorResponse` with `AuthenticationFailed` |
| `Right ValidSodexoCreateTxnResponse` | Extract `redirectUserTo` URL and URL query params; return `GatewayRedirect` with `epgTxnId = transactionId`, HTTP GET method |
| `Right SodexoErrResponse`        | If `errorCode == "ER011"` (duplicate): log and return error without changing status. Otherwise: return `PaymentErrorResponse` with `AuthenticationFailed` |

**Success/Redirect Path output fields:**

| Field            | Source                                              |
|------------------|-----------------------------------------------------|
| `epgTxnId`       | `txnCreateResponse.transactionId`                   |
| `url`            | `txnCreateResponse.redirectUserTo`                  |
| `method`         | `GET`                                               |
| `formData`       | JSON-encoded query params extracted from redirect URL |

---

### 5.2 Sync & Verify Gateway Response (Integrity Check)

**Trigger:** `API.GatewayResponseSyncAndVerify` → `Flow.syncAndVerifyGatewayResponse` or `getRedirectionIntegrityVerification` (class-based)

**Purpose:** After the user returns from the Sodexo redirect page, verify the transaction by calling the status API and checking integrity (amount + txnId).

**Steps:**
1. Determine `testMode` from `merchantGatewayAccount`
2. Get `txnId` via `Transforms.getTxnDetailId` (cleaned/filtered txnId)
3. Fetch Sodexo API key
4. Call `GET /v1.0/sodexo/transactions/request_id/{txnId}` (`doTransactionSyncCall`)
5. Handle `TxnStatusResp`:

| Response Type                     | Action                                                                                  |
|-----------------------------------|----------------------------------------------------------------------------------------|
| `Left ClientError`                | Return `GatewayResponseSyncAndVerifyResponse` with `isVerifiedByV2 = False`, no `verifyMessageResult` |
| `Right SodexoErrRespons`          | Return response with `isVerifiedByV2 = False`, `verifiedGatewayResponse = errorResp`   |
| `Right ValidSodexoTxnStatusResponse` | Run integrity checks (see below), return with `isVerifiedByV2 = True`              |

**Integrity Checks:**

| Check          | Validation                                                                       | Failure Code            |
|----------------|----------------------------------------------------------------------------------|-------------------------|
| TxnId check    | `statusResp.requestId == getTxnDetailId(txnDetail)`                              | `TXN_ID_CHECK_FAILED`   |
| Amount check   | `statusResp.amount.value == computed txn amount` (using MoneyFramework or legacy) | `AMOUNT_CHECK_FAILED`   |

On failure: `actionOnFailure = MARK_FAILURE`, `txnStatusOnFailure = AuthorizationFailed`

**Integrity Payload (for framework):**
- `mandatoryTrackerChecks.epgTxnId = ""` (empty — no epgTxnId check)
- `mandatoryTrackerChecks.requestId = statusResp.requestId`
- `mandatoryTrackerChecks.amount = statusResp.amount.value` (TextAmount with 2 decimal places, or AmountInText if MoneyFramework)
- `skipConfiguration.skipGwTxnIdCheck = False`
- `skipConfiguration.skipAmountCheck = True` ← amount check skipped by framework (done inline)
- `skipConfiguration.skipRequestIdCheck = (statusResp.requestId == getTxnDetailId(txnDetail))`

---

### 5.3 Transaction Sync (Stateless Polling)

**Trigger:** `API.TransactionSync` → `Flow.syncTransaction` or class-based `callSyncApi` + `handleSyncIntegrityResponse`

**Purpose:** Poll Sodexo for current transaction status during async/pending flows.

**Steps:**
1. Get `testMode`, `txnDetailId`, `apiKey`
2. Call `GET /v1.0/sodexo/transactions/request_id/{txnDetailId}`
3. Evaluate response:

| Response                               | Action                                                                              |
|----------------------------------------|-------------------------------------------------------------------------------------|
| `Left ClientError`                     | Build `failureGwTxnData`; return `makeTxnSyncErrorResponse` with existing txn status |
| `Right SodexoErrRespons`               | Log error; return `SyncResponse` with `IntegrityFail` pgr, `PendingVBV` status     |
| `Right ValidSodexoTxnStatusResponse`   | Run integrity checks (same as 5.2); if pass → `IntegritySuccess` + update gwTxnData; if fail → `IntegrityFail` |

**All sync responses:**
- `status = PendingVBV` (always — status updated downstream based on pgr)
- `response = "STATELESS"`
- `isStateful = True`

**Gateway TxnData update logic:**
- If `gatewayStatus` has not changed → keep existing `gwTxnData`
- If changed → update with new `transactionState`, `failureReason`, raw response

---

### 5.4 Capture Response (PGR Decode)

**Trigger:** `API.PayResponse` → `Flow.captureResponse` / `Flow.handleGatewayResponse`

**Purpose:** Parse the stored gateway response (PGR) and produce a `TransactionResponse` with the final transaction status.

**Steps:**
1. Decode `req.gatewayResponse` as `TxnStatusResp`
2. Map decoded response to `TxnStatus`:

| Decoded                               | Mapped Status    |
|---------------------------------------|------------------|
| `ValidSodexoTxnStatusResponse`        | `getTxnStatus(transactionState, failureReason, Nothing, Just currentTime)` |
| `SodexoErrRespons`                    | `AuthorizationFailed`                                                       |
| Left decode error                     | `AuthorizationFailed`                                                       |

**PGR Info fields set:**
- `responseCode` = `transactionState` (or error code)
- `responseMessage` = `failureReason` (or error message)
- `responseXml` = full raw response text

---

### 5.5 Get Status

**Trigger:** `API.GetStatus` → `Flow.getStatus`

**Purpose:** Determine payment outcome from stored PGR for downstream decision-making.

**Steps:**
1. Decode `req.pgr` as `TxnStatusSyncResponse`
2. Evaluate each case of `TxnStatusSyncResponse`:

| Pgr Type            | `isPaymentSuccessful`                     | `isPendingTransaction`                            | `didAuthenticationFail`               |
|---------------------|-------------------------------------------|---------------------------------------------------|---------------------------------------|
| `IntegritySuccess`  | `isCharged(transactionState)`             | `isPending(transactionState, failureReason, ...)`  | `isAuthenticationFailed(transactionState)` |
| `IntegrityFail`     | `False`                                   | `False`                                           | `False`                               |
| `InvalidSyncResp`   | `False`                                   | `False`                                           | `False`                               |

**Always `False`:** `isAuthorized`, `isTxnNotFound`, `isPGRUpdated`, `shouldUpdateAsPreauth`, `isVbvSuccessful`

---

### 5.6 Initiate Refund

**Trigger:** `API.InitiateRefund` → `Flow.refund` (or class-based `callAPI` + `handleResponse`)

**Purpose:** Submit a refund for a completed Sodexo transaction.

**Steps:**
1. Extract `refundUniqueRequestId` from `request.refund.uniqueRequestId`
2. Get `testMode`, `apiKey`
3. Build `SodexoRefundRequest` via `Transforms.getSodexoRefundRequest`:
   - `requestId` = `refundUniqueRequestId`
   - `transactionId` = looked up from `paymentGatewayResponse.responseXml` using key `"transactionId"`
   - `amount` = refund amount in INR (currency hardcoded)
   - `purposes = [Purpose { purpose = "FOOD", amount = refundAmount }]`
4. Call `POST /v2.0/sodexo/transactions/refund`
5. Handle `SodexoRefundResp`:

| Response                          | Action                                                                                              |
|-----------------------------------|-----------------------------------------------------------------------------------------------------|
| `Left ClientError`                | Set refund `status = Pending`, `sentToGateway = True`, store error code/message                     |
| `Right SodexoErrRespon`           | Set refund `status = Failure`, `processed = True`, `sentToGateway = True`, store `errorCode`/`errorMessage` |
| `Right ValidSodexoRefundResponse` | Set `processed = True`, `sentToGateway = True`, `epgTransactionId = refundTransactionId`, `refundArn = refundTransactionId`, `referenceId = purchaseTransactionId` |

---

### 5.7 Refund Sync

**Trigger:** `API.RefundSync` → `Flow.refundSync` (or class-based `callAPIRefundSync` + `handleResponseRefundSync`)

**Purpose:** Check current state of a submitted refund.

**Early Exit:** If `refund.status == Success` → return immediately without API call.

**Steps:**
1. Resolve `epgTxnId` from `refund.referenceId` (converted) OR `secondFactor` (getMbEpgTxnId)
2. Get `testMode`, `apiKey`
3. Call `GET /v2.0/sodexo/transactions/{epgTxnId}/refunds`
4. Handle `RefundStatusResp`:

| Response                          | Action                                                                                           |
|-----------------------------------|--------------------------------------------------------------------------------------------------|
| `Left ClientError`                | Preserve existing refund, store error code/message                                               |
| `Right SodexoErr`                 | Set `processed = True`, `sentToGateway = True`, store `errorCode`/`errorMessage`                 |
| `Right ValidRefundStatusResponse` | Parse `refundStatusDetails` (a JSON Object) — see below                                          |

**Refund Status Detail Parsing:**

| `refundStatusDetails` shape                | Action                                                                                |
|--------------------------------------------|---------------------------------------------------------------------------------------|
| Empty JSON object `{}`                     | Mark `status = Failure`, `errorMessage = "No refund record exists on payment gateway"`, `responseCode = "REFUND_NOT_FOUND"` |
| Non-empty object, `refundId` is known      | Lookup by `refundTransactionId` key in the object; parse as `RefundStatusDetails`     |
| Non-empty object, `refundId` is `Nothing`  | Scan all values for matching `requestId == refundUniqueRequestId`                     |
| Key found, parse success                   | Update `epgTransactionId`, `refundArn = refundTransactionId`, map `refundState` to internal status |
| Key not found                              | Apply `shouldMarkFailureOnNotFound` logic (see below)                                 |

**Refund State Mapping:**

| Sodexo `refundState`  | Internal `RefundStatus` |
|-----------------------|-------------------------|
| `REFUND_COMPLETED`    | `Success`               |
| `REFUND_FAILED`       | `Failure`               |
| `REFUND_DROPPED`      | `ManualReview`          |
| `REFUND_INITIATED`    | `Pending`               |
| (anything else)       | `Pending`               |

**Not-Found Failure Logic (`shouldMarkFailureOnNotFound`):**  
Mark refund as `Failure` (code `"404"`, message `"Refund dropped."`) if ALL:
- Current time > `refund.dateCreated + threshold` (default: 2 days; overridable via Redis key `REFUND_FAILURE_ON_NOT_FOUND_THRESHOLD_MINUTE`)
- Refund amount > 50% of txn amount
- Refund status is `Pending` or `ManualReview`

Otherwise: mark as `ManualReview` with message `"No Refund Id fetched from epgTransactionId"`.

---

### 5.8 Get Card Info (Source Detail)

**Trigger:** `API.GetCardInfo` → `Flow.sodexoCardDetails`

**Purpose:** Retrieve saved card/source info for a given Sodexo `sourceId`.

**Steps:**
1. Parse `request.contents` as JSON object
2. Look up `"sourceId"` key from contents
3. If found: call `GET /v1.0/sodexo/sources/{sourceId}` (`doGetSourceInfoCall`)
4. If not found: return `AuthenticationFailed` error response

**Response Handling (`handleSourceInfoResp`):**

| Response                             | Action                                                   |
|--------------------------------------|----------------------------------------------------------|
| `Right ValidGetSourceInfoResponse`   | Return `makeCardInfo(toJSON sourceInfo)`                 |
| `Right SodexoErrResp`                | Log error; return `makeCardInfo(toJSON errorResp)`       |
| `Left ClientError`                   | Log error; return `AuthenticationFailed` card info       |

---

### 5.9 Get Source Detail (Async)

**Trigger:** `API.SodexoCardInfo` → `Flow.getSourceDetailAsync`

**Purpose:** Async variant for retrieving source info by `cardTokenOfVaultProvider`.

**Steps:**
1. Extract `testMode` and `cardTokenOfVaultProvider` from request
2. If `sourceId` is `Just value`: call `GET /v1.0/sodexo/sources/{value}` (`doGetSourceInfoCallForSodexo`)
3. If `Nothing`: return `AuthenticationFailed` response

Response handling is identical to §5.8.

---

### 5.10 Remove Saved Card (Delete Source)

**Trigger:** `API.SodexoDeleteCardRequest` → `Flow.removeSavedCard`

**Purpose:** Unsave/delete a stored Sodexo card source.

**Steps:**
1. Extract `testMode` and `cardTokenOfVaultProvider`
2. Build `SodexoDeleteRequest { sourceId = cardTokenOfVaultProvider }`
3. Call `POST /v1.0/sodexo/sources/unsave`
4. Handle `RemoveSodexoCardResp`:

| Response                           | Action                                                                                     |
|------------------------------------|-------------------------------------------------------------------------------------------|
| `Right ValidRemoveSodexoCardResp`  | Return `makeDeleteCardInfo(toJSON deleteCardInfo)` — success                               |
| `Right SodexoErrorResp`            | Log error; return `makeDeleteCardInfo(toJSON errorResp)`                                   |
| `Left FailureResponse` with body decodeable as `SodexoRemoveCardErrorResponse`: `errorCode == "ER051"` AND `errorType == "CARD_NOT_FOUND"` | Treat as success (card already not at PG end); return `RemoveSodexoValidCardResp { status = "SUCCESS", sourceId = sourceId }` |
| `Left FailureResponse` (other)     | Log error; return decoded error response                                                   |
| `Left ClientError` (other)         | Log error; return `AuthenticationFailed` response                                          |

---

## 6. Request & Response Types

### 6.1 `SodexoCreateTransactionRequest`
**Used for:** Create Transaction (standard flow — with or without stored `sourceId`)

| Field          | Type             | Required | Description                                                        |
|----------------|------------------|----------|--------------------------------------------------------------------|
| `requestId`    | `TxnId` (Text)   | Yes      | Cleaned transaction ID (only `[a-zA-Z0-9_-]` allowed)            |
| `sourceId`     | `Maybe Text`     | No       | Stored card token from vault; `null` if new card                   |
| `sourceType`   | `Text`           | Yes      | Always `"CARD"`                                                    |
| `amount`       | `Amount`         | Yes      | Transaction amount object                                          |
| `merchantInfo` | `MerchantInfo`   | Yes      | Merchant identifiers (aid, mid, tid)                               |
| `purposes`     | `[Purpose]`      | Yes      | Always `[{ purpose: "FOOD", amount: <txn amount> }]`              |
| `failureUrl`   | `Text`           | Yes      | Callback URL on failure (same as successUrl — handled internally)  |
| `successUrl`   | `Text`           | Yes      | Callback URL on success (same as failureUrl — handled internally)  |

---

### 6.2 `CreateTxnWithSourceInfoRequest`
**Used for:** Seamless create transaction (new card, no stored token)

| Field          | Type             | Required | Description                                                        |
|----------------|------------------|----------|--------------------------------------------------------------------|
| `requestId`    | `TxnId` (Text)   | Yes      | Cleaned transaction ID                                             |
| `sourceInfo`   | `SourceInfo`     | Yes      | Raw card details                                                   |
| `amount`       | `Amount`         | Yes      | Transaction amount                                                 |
| `merchantInfo` | `MerchantInfo`   | Yes      | Merchant identifiers                                               |
| `purposes`     | `[Purpose]`      | Yes      | Always `[{ purpose: "FOOD", amount: <txn amount> }]`              |
| `permissions`  | `[Text]`         | Yes      | If `addToLocker=true`: `["SAVE_FOR_FUTURE", "GET_BALANCE"]`; else `[]` |
| `failureUrl`   | `Text`           | Yes      | Callback URL on failure                                            |
| `successUrl`   | `Text`           | Yes      | Callback URL on success                                            |

---

### 6.3 `SourceInfo`
**Nested in:** `CreateTxnWithSourceInfoRequest`

| Field         | Type          | Required | Description                                    |
|---------------|---------------|----------|------------------------------------------------|
| `sourceType`  | `Text`        | Yes      | Always `"CARD"`                                |
| `cardNumber`  | `Maybe Text`  | Yes      | Full card number (PAN)                         |
| `ownerName`   | `Maybe Text`  | No       | Cardholder name                                |
| `expiryMonth` | `Maybe Text`  | Yes      | Expiry month (2-digit)                         |
| `expiryYear`  | `Maybe Text`  | Yes      | Expiry year — last 2 digits only (e.g., `"26"` from `"2026"`) |
| `cvv`         | `Maybe Text`  | Yes      | Card CVV                                       |

---

### 6.4 `MerchantInfo`
**Nested in:** `SodexoCreateTransactionRequest`, `CreateTxnWithSourceInfoRequest`

| Field | Type   | Required | Description                                              |
|-------|--------|----------|----------------------------------------------------------|
| `aid` | `Text` | Yes      | Acquirer ID (from config: `SodexoUatAcquireId` / `SodexoProdAcquireId`) |
| `mid` | `Text` | Yes      | Merchant ID from `SodexoDetails.sodexoMerchantId`        |
| `tid` | `Text` | Yes      | Terminal ID from `SodexoDetails.sodexoTerminalId`        |

---

### 6.5 `Amount`
**Used throughout**

| Field      | Type           | Required | Description                                           |
|------------|----------------|----------|-------------------------------------------------------|
| `currency` | `Text`         | Yes      | Currency code (e.g., `"INR"`) — hardcoded for refunds |
| `value`    | `GT.Amount` (Text) | Yes  | Amount as fixed-precision text string (2 decimal places) |

---

### 6.6 `Purpose`
**Used throughout**

| Field     | Type     | Required | Description                                       |
|-----------|----------|----------|---------------------------------------------------|
| `purpose` | `Text`   | Yes      | Always `"FOOD"` (hardcoded)                       |
| `amount`  | `Amount` | Yes      | Amount for this purpose (same as transaction amount) |

---

### 6.7 `CreateTransactionResp` (Success)
**Decoded from:** `CreateTxnResp.ValidSodexoCreateTxnResponse`

| Field              | Type            | Required | Description                                |
|--------------------|-----------------|----------|--------------------------------------------|
| `transactionId`    | `Text`          | Yes      | Sodexo transaction ID (becomes `epgTxnId`) |
| `requestId`        | `Maybe Text`    | No       | Echo of our `requestId`                    |
| `amount`           | `Amount`        | Yes      | Authorized amount                          |
| `transactionState` | `Text`          | Yes      | Current state of transaction               |
| `sourceId`         | `Maybe Text`    | No       | Source card ID (if card was saved)         |
| `redirectUserTo`   | `Text`          | Yes      | Redirect URL for user authentication       |
| `purposes`         | `Maybe [Purpose]` | No     | Purposes breakdown                         |

---

### 6.8 `TxnSyncResp` (Transaction Status)
**Decoded from:** `TxnStatusResp.ValidSodexoTxnStatusResponse`

| Field                     | Type                  | Required | Description                                       |
|---------------------------|-----------------------|----------|---------------------------------------------------|
| `transactionId`           | `Text`                | Yes      | Sodexo's transaction ID                           |
| `requestId`               | `Text`                | Yes      | Our original request/txn ID                       |
| `amount`                  | `Amount`              | Yes      | Transaction amount                                |
| `purposes`                | `[Purpose]`           | Yes      | Purposes breakdown                                |
| `sourceId`                | `Maybe Text`          | No       | Source card ID                                    |
| `transactionState`        | `Text`                | Yes      | Current transaction state (see status mapping)    |
| `failureReason`           | `Maybe Text`          | No       | Failure reason text (e.g., `"Wrong Pin"`)         |
| `requestTime`             | `Maybe Int`           | No       | Unix timestamp of request                         |
| `transactionReceipt`      | `TransactionReceipt`  | Yes      | Detailed receipt with debit/credit info           |
| `retrievalReferenceNumber`| `Maybe Text`          | No       | RRN for settlement reference                      |

---

### 6.9 `TransactionReceipt`
**Nested in:** `TxnSyncResp`

| Field               | Type                    | Required | Description                            |
|---------------------|-------------------------|----------|----------------------------------------|
| `authorisedAmount`  | `Maybe AuthorisedAmount`| No       | Actual authorized amount               |
| `debits`            | `Maybe [Info]`          | No       | Debit entries                          |
| `credits`           | `Maybe [Info]`          | No       | Credit entries                         |
| `receiptID`         | `Maybe Int`             | No       | Receipt identifier                     |
| `payeeInfo`         | `PayeeInfo`             | Yes      | Merchant/payee details                 |
| `payerInfo`         | `Maybe PayerInfo`       | No       | Customer/payer details                 |
| `authorisationTime` | `Maybe Int`             | No       | Authorisation timestamp                |
| `merchantRequestId` | `Maybe Text`            | No       | Merchant request reference             |
| `attributes`        | `Maybe Text`            | No       | Additional attributes                  |

---

### 6.10 `PayeeInfo`
| Field      | Type          | Required | Description             |
|------------|---------------|----------|-------------------------|
| `name`     | `Maybe Text`  | No       | Merchant name           |
| `location` | `Maybe Text`  | No       | Merchant location       |
| `cardType` | `Text`        | Yes      | Card type identifier    |

---

### 6.11 `PayerInfo`
| Field      | Type   | Required | Description               |
|------------|--------|----------|---------------------------|
| `imageURL` | `Text` | Yes      | Customer card image URL   |
| `name`     | `Text` | Yes      | Customer name             |
| `cardType` | `Text` | Yes      | Card type identifier      |

---

### 6.12 `Info` (Debit/Credit entry)
| Field         | Type                | Required | Description                       |
|---------------|---------------------|----------|-----------------------------------|
| `ifi`         | `Int`               | Yes      | IFI (Issuer Financial Institution) code |
| `postingID`   | `Text`              | Yes      | Posting identifier                |
| `value`       | `AuthorisedAmount`  | Yes      | Amount for this entry             |
| `productType` | `Maybe Text`        | No       | Product type                      |

---

### 6.13 `AuthorisedAmount`
| Field      | Type   | Required | Description      |
|------------|--------|----------|------------------|
| `amount`   | `Text` | Yes      | Amount value     |
| `currency` | `Text` | Yes      | Currency code    |

---

### 6.14 `SodexoErrorResponse` (Transaction/Status errors)
| Field           | Type          | Required | Description                       |
|-----------------|---------------|----------|-----------------------------------|
| `traceId`       | `Maybe Text`  | No       | Trace ID for debugging            |
| `errorCode`     | `Maybe Text`  | No       | Error code (e.g., `"ER011"`)      |
| `errorType`     | `Maybe Text`  | No       | Error type (e.g., `"DUPLICATE_REQUEST"`) |
| `errorMessage`  | `Maybe Text`  | No       | Human-readable error message      |
| `additionalInfo`| `Maybe Text`  | No       | Extra error details               |

---

### 6.15 `SodexoRefundRequest`
**Used for:** Initiate Refund

| Field           | Type        | Required | Description                                   |
|-----------------|-------------|----------|-----------------------------------------------|
| `requestId`     | `TxnId`     | Yes      | Refund unique request ID                      |
| `amount`        | `Amount`    | Yes      | Refund amount (currency hardcoded to `"INR"`) |
| `transactionId` | `Text`      | Yes      | Original Sodexo transaction ID (from PGR XML) |
| `purposes`      | `[Purpose]` | Yes      | `[{ purpose: "FOOD", amount: <refundAmount> }]` |

---

### 6.16 `RefundResp` (Refund Success)
**Decoded from:** `SodexoRefundResp.ValidSodexoRefundResponse`

| Field                  | Type   | Required | Description                            |
|------------------------|--------|----------|----------------------------------------|
| `requestId`            | `Text` | Yes      | Echo of our refund request ID          |
| `purchaseTransactionId`| `Text` | Yes      | Original purchase transaction ID       |
| `refundTransactionId`  | `Text` | Yes      | Sodexo refund transaction ID           |

---

### 6.17 `SodexoRefundErrorResponse`
| Field           | Type                         | Required | Description                         |
|-----------------|------------------------------|----------|-------------------------------------|
| `traceId`       | `Maybe Text`                 | No       | Trace ID                            |
| `errorCode`     | `Maybe Text`                 | No       | Error code                          |
| `errorType`     | `Maybe Text`                 | No       | Error type                          |
| `errorMessage`  | `Maybe SodexoErrorMessage`   | No       | Nested error message object         |
| `additionalInfo`| `Maybe Text`                 | No       | Additional details                  |
| `message`       | `Maybe Text`                 | No       | Top-level message text              |

`SodexoErrorMessage`:

| Field     | Type          | Required | Description        |
|-----------|---------------|----------|--------------------|
| `message` | `Maybe Text`  | No       | Error message text |

---

### 6.18 `RefundStatusResponse`
**Decoded from:** `RefundStatusResp.ValidRefundStatusResponse`

| Field                 | Type    | Required | Description                                                              |
|-----------------------|---------|----------|--------------------------------------------------------------------------|
| `refundStatusDetails` | `Value` | Yes      | JSON object keyed by `refundTransactionId`, each value is `RefundStatusDetails`. Empty `{}` means no refund found. |

---

### 6.19 `RefundStatusDetails`
**Nested in:** `refundStatusDetails` object values

| Field                | Type            | Required | Description                               |
|----------------------|-----------------|----------|-------------------------------------------|
| `refundTransactionId`| `Text`          | Yes      | Sodexo refund transaction ID              |
| `requestId`          | `Text`          | Yes      | Original refund request ID                |
| `refundState`        | `Text`          | Yes      | Current refund state (see status mapping) |
| `amount`             | `Amount`        | Yes      | Refunded amount                           |
| `requestTime`        | `Maybe Int`     | No       | Unix timestamp                            |
| `purposes`           | `Maybe [Purpose]`| No      | Purposes breakdown                        |

---

### 6.20 `GetSourceInfo`
**Decoded from:** `GetSourceInfoResp.ValidGetSourceInfoResponse`

| Field               | Type                       | Required | Description                               |
|---------------------|----------------------------|----------|-------------------------------------------|
| `sourceId`          | `Maybe Text`               | No       | Card source ID                            |
| `sourceType`        | `Text`                     | Yes      | Source type (e.g., `"CARD"`)             |
| `cardSourceDetails` | `Maybe SourceDetails`      | No       | Masked card details                       |
| `accountBalances`   | `Maybe [AccountBalances]`  | No       | Balance information per product type      |

`SourceDetails`:

| Field        | Type          | Required | Description           |
|--------------|---------------|----------|-----------------------|
| `maskedPan`  | `Maybe Text`  | No       | Masked card number    |
| `ownerName`  | `Maybe Text`  | No       | Cardholder name       |
| `cardIssuer` | `Text`        | Yes      | Card issuer name      |

`AccountBalances`:

| Field         | Type           | Required | Description                        |
|---------------|----------------|----------|------------------------------------|
| `account`     | `Maybe Text`   | No       | Account identifier                 |
| `productType` | `Text`         | Yes      | Product type (e.g., `"FOOD"`)     |
| `currency`    | `Text`         | Yes      | Currency code                      |
| `balance`     | `GT.Amount`    | Yes      | Available balance                  |
| `ifi`         | `Maybe Text`   | No       | IFI code                           |

---

### 6.21 `SodexoDeleteRequest`
**Used for:** Remove Saved Card

| Field      | Type   | Required | Description                    |
|------------|--------|----------|--------------------------------|
| `sourceId` | `Text` | Yes      | Card source ID to remove       |

---

### 6.22 `RemoveSodexoValidCardResp`
**Decoded from:** `RemoveSodexoCardResp.ValidRemoveSodexoCardResp`

| Field      | Type   | Required | Description                        |
|------------|--------|----------|------------------------------------|
| `sourceId` | `Text` | Yes      | The deleted source ID              |
| `status`   | `Text` | Yes      | Should be `"SUCCESS"` on success   |

---

### 6.23 `SodexoRemoveCardErrorResponse`
| Field           | Type          | Required | Description                     |
|-----------------|---------------|----------|---------------------------------|
| `traceId`       | `Maybe Text`  | No       | Trace ID                        |
| `errorCode`     | `Maybe Text`  | No       | Error code (e.g., `"ER051"`)   |
| `errorType`     | `Maybe Text`  | No       | Error type (e.g., `"CARD_NOT_FOUND"`) |
| `errorMessage`  | `Maybe Text`  | No       | Error message                   |
| `additionalInfo`| `Maybe Text`  | No       | Additional details              |
| `requestId`     | `Maybe Text`  | No       | Request trace ID                |

---

### 6.24 `SodexoDetails` (Account Credentials)

| Field                           | Type   | Required | Description                                              |
|---------------------------------|--------|----------|----------------------------------------------------------|
| `sodexoMerchantId`              | `Text` | Yes      | Merchant ID for Sodexo/Zeta                              |
| `sodexoTerminalId`              | `Text` | Yes      | Terminal ID for Sodexo/Zeta                              |
| `allowFetchBalance`             | `Text` | Yes      | Balance fetch permission flag (`"true"`/`"false"`)       |
| `storeAndUseSourceIdImplicitly` | `Text` | Yes      | Implicit source ID save-and-reuse for wallet debit flows |

---

## 7. Error Codes & Status Mapping

### 7.1 Transaction State → Internal Status

| Sodexo `transactionState`    | Internal `TxnStatus`       | Notes                                                                                        |
|------------------------------|----------------------------|----------------------------------------------------------------------------------------------|
| `AUTHORIZED`                 | `Charged`                  |                                                                                              |
| `CLEARANCE_INITIATED`        | `Charged`                  |                                                                                              |
| `CLEARED`                    | `Charged`                  |                                                                                              |
| `CANCELLED_BY_USER_AGENT`    | `AuthenticationFailed`     |                                                                                              |
| `CANCELLED`                  | `AuthenticationFailed`     |                                                                                              |
| `WAITING_FOR_SOURCE`         | `PendingVBV`               | Always pending                                                                               |
| `WAITING_FOR_CONSENT`        | `PendingVBV`               | Only if `failureReason == Nothing` OR `failureReason == Just "Wrong Pin"` AND time < threshold |
| `UNAUTHORIZED`               | `AuthorizationFailed`      |                                                                                              |
| `WAITING_FOR_AUTHORIZATION`  | `Authorizing`              |                                                                                              |
| (anything else)              | `AuthenticationFailed`     | Default catch-all                                                                            |

**Pending Status Time Threshold:**
- Environment variable: `SODEXO_TXN_PENDING_STATUS_UPDATE_THRESHOLD_IN_SEC`
- Default: `864000` seconds (10 days)
- A `WAITING_FOR_CONSENT` transaction beyond this threshold will NOT be `PendingVBV` (falls through to `AuthenticationFailed`)

### 7.2 Refund State → Internal Status

| Sodexo `refundState`   | Internal `RefundStatus` |
|------------------------|-------------------------|
| `REFUND_COMPLETED`     | `Success`               |
| `REFUND_FAILED`        | `Failure`               |
| `REFUND_DROPPED`       | `ManualReview`          |
| `REFUND_INITIATED`     | `Pending`               |
| (anything else)        | `Pending`               |

### 7.3 Known Error Codes

| Error Code | Error Type              | Context                  | Handling                                                                                             |
|------------|-------------------------|--------------------------|------------------------------------------------------------------------------------------------------|
| `ER011`    | (Duplicate Request)     | Create Transaction       | Do NOT update transaction status; log and return error response without `AuthenticationFailed` override |
| `ER013`    | `PRECONDITION_MISMATCH` | Create Transaction       | Returned when purpose ≠ `"FOOD"`; purpose is now hardcoded to avoid this                            |
| `ER051`    | `CARD_NOT_FOUND`        | Remove Saved Card        | Treated as **success** — card is already absent at PG end                                           |

### 7.4 Client Error Handling

When a `ClientError` is received:
- It is passed to `C.handleClientError` which produces an `APIError` with:
  - `errType`: string error type
  - `errorMessage`: human-readable message
  - `errCode`: numeric error code
  - `errorResponse`: raw response body

For **transaction initiation errors:** status set to `AuthenticationFailed`  
For **sync errors:** status preserved as `PendingVBV` in sync response  
For **refund client errors:** status set to `Pending`, `sentToGateway = True`

### 7.5 Integrity Check Failure Codes

| Check              | Error Code             | Action on Failure             |
|--------------------|------------------------|-------------------------------|
| TxnId mismatch     | `TXN_ID_CHECK_FAILED`  | `MARK_FAILURE`, `AuthorizationFailed` |
| Amount mismatch    | `AMOUNT_CHECK_FAILED`  | `MARK_FAILURE`, `AuthorizationFailed` |

---

## 8. Known Issues / TODOs

The following TODOs and code comments were found in the source:

1. **`Transforms.hs:182`** — Refund amount currency is hardcoded to `"INR"`:
   ```haskell
   currency = "INR", --HAVE TO TAKE FROM ORDER---
   ```
   The currency should be taken from the order/transaction but is not currently implemented.

2. **`Transforms.hs:119-124`** — Purpose is hardcoded to `"FOOD"`:
   ```haskell
   {-
    hard coded to food as Sodexo Gives this err for any other purpose
   "errorCode": "ER013",
   "errorType": "PRECONDITION_MISMATCH",
   "errorMessage": "FOOD is the only purpose possible",
   -}
   getPurposeId = "FOOD" --fromMaybe "FOOD" $ Storage.unProductId <$> order.productId
   ```
   The `productId` from the order was intended to be used but Sodexo only supports `"FOOD"`.

3. **`Transforms.hs:169`** — `transactionId` for refund is fetched from PGR XML using a lookup:
   ```haskell
   transactionId = getTransactionId (request.paymentGatewayResponse), -- HAVE TO CHANGE USING LOOKUP --
   ```
   There is a note indicating this lookup approach may need revisiting.

4. **`Flow.hs:317`** — Unresolved question about refund failed handling in sync:
   ```haskell
   -- Do we need to add REFUND_FAILED here
   ```

5. **`Flow.hs:44`** — `isMeshEnabled` flag usage noted with a CHECK comment:
   ```haskell
   isMeshEnabled = request.isMeshEnabled --CHECK IT--
   ```
   Appears in both `createTransactionRequest` and `createTxnWithRequestSourceInfo`.

6. **`Flow.hs:776`** — Uncertainty about `REFUND_INITIATED` mapping:
   ```haskell
   "REFUND_INITIATED" -> Refund.Pending -- Is this corrected or need to change to success?
   ```
   The correct terminal mapping is not confirmed.

7. **`Routes.hs:163-170`** — `doGetSourceInfoCall` and `doGetSourceInfoCallForSodexo` are **duplicate functions** with identical implementations. Only the names differ; they are both called with `GW_LIST_SODEXO_CARDS` tag using the same endpoint.

8. **`Flow.hs:382`** — In class-based sync handler, `status = PendingVBV` is hardcoded in `makeSyncResponse`. Actual status resolution happens downstream from the `pgr` field.

9. **Expy year trimming**: In `getSourceInfo`, the expiry year is trimmed to last 2 digits:
   ```haskell
   expiryYear = Just $ DT.drop 2 (Domain.getExpiryYear $ request.cardData.expYear)
   ```
   This assumes a 4-digit year input; if the format changes this would break.

10. **API Version**: `isV1 = False` is passed for refund calls but the base path resolves to `/v2.0/sodexo/transactions`. This is intentional but undocumented. All other calls use `isV1 = True` → `/v1.0/sodexo/transactions`.

---

*End of SODEXO connector technical specification.*
