# Flow Plan: PAYU

## Summary

- **Connector**: PAYU
- **Techspec**: /home/kanikachaudhary/Kanika/euler-techspec-output/PAYU_spec.md
- **Total Flows Analyzed**: 19
- **Flows to Implement**: 6
- **Existing (skip)**: [Authorize, PSync]
- **Not Supported**: [CreateOrder, CreateAccessToken, CreateConnectorCustomer, CreateSessionToken, PaymentMethodToken, PreAuthenticate, Authenticate, PostAuthenticate, SdkSessionToken, IncrementalAuthorization, Accept, SubmitEvidence, DefendDispute, VoidPC, VerifyWebhookSource]

## 1. Gateway Presence & Scaffolding

- **Status**: EXISTS in connector-service
- **Connector module**: `payu.rs`
- **Connector enum variant**: `ConnectorEnum::Payu`
- **Scaffolding action taken**: None required - connector already exists

## 2. Tech Spec Summary

- **Gateway**: PayU
- **Base URL**: `https://test.payu.in` (sandbox), `https://info.payu.in` / `https://secure.payu.in` (production)
- **Auth mechanism**: HMAC-SHA512 signature embedded in request body `hash` field (not HTTP header). Credentials: `payuMerchantKey` + `payuSalt`.
- **Operations found**: Payment initiation (Card/UPI/NB/Wallet/BNPL/EMI), Verify Payment (PSync), Capture, Void, Refund, Refund ARN Sync, Capture/Void Sync, Setup Mandate, Exercise Mandate (RepeatPayment), Mandate Revoke, Mandate Status Check, Pre-Debit Notification, 3DS Authentication, OTP flows, Settlement, Eligibility, Surcharge, Split Settlement, Delink Wallet, VPA Validation, Push Pay
- **Payment methods found**: Card (Visa, Mastercard, Amex, Diners, Maestro, RuPay), UPI (Collect, Intent, Push Pay), Net Banking, Wallet (Google Pay via UPI, LazyPay via BNPL), BNPL, EMI (DC EMI, LinkAndPay)
- **Pre-auth requirements**: None required - PayU does not need order creation, session tokens, access tokens, customer creation, or tokenization before payment authorization. `ValidationTrait` methods all default to `false`.

## 3. Flow Mapping

| # | Tech Spec Operation | Tech Spec Endpoint | Connector-Service Flow | Status | Notes |
|---|---------------------|--------------------|------------------------|--------|-------|
| 1 | Payment Initiation (initiateTxn) | POST `/_payment` | Authorize | ✅ | Implemented - UPI Collect/Intent flows |
| 2 | Verify Payment (verifyPayment) | POST `/merchant/postservice.php?form=2` (command=verify_payment) | PSync | ✅ | Implemented |
| 3 | Capture (captureTxn) | POST `/merchant/postservice.php?form=2` (command=capture_transaction) | Capture | ❌ | Stub - needs implementation |
| 4 | Void (voidTxn) | POST `/merchant/postservice.php?form=2` (command=cancel_refund_transaction) | Void | ❌ | Stub - needs implementation |
| 5 | Refund (initPayuRefundRequestApi) | POST `/merchant/postservice.php?form=2` (command=cancel_refund_transaction) | Refund | ❌ | Stub - needs implementation |
| 6 | Refund ARN Sync (Refund status) | POST `/merchant/postservice.php?form=2` (command=getAllRefundsFromTxnIds) | RSync | ❌ | Stub - needs implementation |
| 7 | Capture/Void Sync (payUCaptureVoidTxnSync) | POST `/merchant/postservice.php?form=2` (command=check_action_status) | PSync | ✅ | Can reuse PSync with different command |
| 8 | Setup Mandate (setupMandate) | POST `/_payment` with SI fields | SetupMandate | ❌ | Stub - techspec has detailed SI flow |
| 9 | Exercise Mandate (executeMandate) | POST `/merchant/postservice.php?form=2` (command=si_transaction) | RepeatPayment | ❌ | Stub - techspec has detailed mandate exercise flow |
| 10 | Mandate Revoke (revokeMandateToken) | POST `/merchant/postservice.php?form=2` (command=upi_mandate_revoke) | MandateRevoke | ❌ | Stub - techspec has UPI mandate revoke |
| 11 | Mandate Status Check (checkMandateStatus) | POST `/merchant/postservice.php?form=2` (command=upi_mandate_status/check_mandate_status) | PSync | ✅ | Could be handled via PSync or dedicated flow |
| 12 | Pre-Debit Notification (callInitNotification) | POST `/merchant/postservice.php?form=2` (command=pre_debit_SI) | 🆕 No equivalent | N/A | No framework flow for pre-debit notification |
| 13 | 3DS Auth Params (getThreeDSAuthenticationParams) | GET `/decoupled/AuthData?referenceId={id}` | PreAuthenticate | ❌ | Stub - techspec has 3DS2 authentication |
| 14 | 3DS Auth Webhook (extractPayUAuthenticationWebhook) | Webhook payload | Authenticate | ❌ | Stub - webhook-based 3DS authentication |
| 15 | OTP Submit/Resend (submitOtp/resendOtp) | POST ResponseHandler.php | 🆕 No equivalent | N/A | No framework flow for OTP submission |
| 16 | Settlement (getSettlements) | POST `/merchant/postservice.php?form=2` (command=get_settlement_details) | 🆕 No equivalent | N/A | No framework flow for settlement fetch |
| 17 | Eligibility (checkEligibility) | POST `/merchant/postservice.php?form=2` (command=get_checkout_details) | 🆕 No equivalent | N/A | No framework flow for eligibility check |
| 18 | Split Settlement (initiateSplitSettlement) | POST `/merchant/postservice.php?form=2` (command=payment_split) | 🆕 No equivalent | N/A | No framework flow for split settlement |
| 19 | Webhook (PayUResponseReq) | Incoming POST from PayU | IncomingWebhook | ❌ | Stub - PayU sends payment/refund/mandate webhooks |

Legend: ✅ = Implemented, ❌ = Stub (exists but not implemented), 🆕 = Not in framework (needs new flow type)

## 4. Payment Method / PMT Mapping

| # | Tech Spec PM | Tech Spec PMT | CS PaymentMethod | CS PaymentMethodType | CS PaymentMethodData Variant | Status | Mandates | Refunds | Capture Methods |
|---|--------------|---------------|------------------|----------------------|------------------------------|--------|----------|---------|-----------------|
| 1 | UPI | UPI Collect | Upi | UpiCollect | UpiData::UpiCollect(UpiCollectData) | ✅ | Yes (SI) | Yes | Auto only |
| 2 | UPI | UPI Intent | Upi | UpiIntent | UpiData::UpiIntent(UpiIntentData) | ✅ | No | Yes | Auto only |
| 3 | UPI | UPI QR | Upi | UpiQr | UpiData::UpiQr(UpiQrData) | ✅ | No | Yes | Auto only |
| 4 | Card | Visa Credit | Card | Card | Card(Card) | ❌ | Yes | Yes | Auto + Manual |
| 5 | Card | Visa Debit | Card | Card | Card(Card) | ❌ | Yes | Yes | Auto + Manual |
| 6 | Card | Mastercard Credit | Card | Card | Card(Card) | ❌ | Yes | Yes | Auto + Manual |
| 7 | Card | Mastercard Debit | Card | Card | Card(Card) | ❌ | Yes | Yes | Auto + Manual |
| 8 | Card | Amex | Card | Card | Card(Card) | ❌ | Yes | Yes | Auto + Manual |
| 9 | Card | Diners | Card | Card | Card(Card) | ❌ | Yes | Yes | Auto + Manual |
| 10 | Card | Maestro | Card | Card | Card(Card) | ❌ | Yes | Yes | Auto + Manual |
| 11 | Card | RuPay Credit | Card | Card | Card(Card) | ❌ | Yes | Yes | Auto + Manual |
| 12 | Card | RuPay Debit | Card | Card | Card(Card) | ❌ | Yes | Yes | Auto + Manual |
| 13 | Wallet | Google Pay (via UPI) | Wallet | GooglePay | WalletData::GooglePay(GooglePayWalletData) | ❌ | No | Yes | Auto only |
| 14 | BNPL | LazyPay | PayLater | 🆕 LazyPay | 🆕 No direct variant | 🆕 | No | Yes | Auto only |
| 15 | Net Banking | Various banks | BankRedirect | 🆕 Various | BankRedirectData (various) | ❌ | Yes (eNACH) | Yes | Auto only |
| 16 | EMI | DC EMI / LinkAndPay | 🆕 | 🆕 | 🆕 | 🆕 | No | Yes | Auto only |

Legend: ✅ = Mapped & Implemented, ❌ = Mappable but not implemented, 🆕 = No equivalent in framework

## 5. API Call Sequence (Ordered)

### 5.1 Payment Flow (Auto-Capture - UPI)
1. [Core] Authorize (auto-capture) -> POST `/_payment` (pg=UPI, bankcode=UPI/INTENT)
2. [Sync] PSync -> POST `/merchant/postservice.php?form=2` (command=verify_payment)
3. [Async] IncomingWebhook <- POST /webhook (PayU calls us with PayUResponseReq)

### 5.2 Payment Flow (Manual Capture - Cards)
1. [Core] Authorize (manual, isPreAuthEnabled=true) -> POST `/_payment` (pg=CC/DC/AMEX/etc)
2. [Sync] PSync -> POST `/merchant/postservice.php?form=2` (command=verify_payment)
3. [Capture] Capture -> POST `/merchant/postservice.php?form=2` (command=capture_transaction)
4. [Sync] PSync -> POST `/merchant/postservice.php?form=2` (command=check_action_status)

### 5.3 Refund Flow
1. [Core] Refund -> POST `/merchant/postservice.php?form=2` (command=cancel_refund_transaction)
2. [Sync] RSync -> POST `/merchant/postservice.php?form=2` (command=getAllRefundsFromTxnIds)

### 5.4 Void Flow
1. [Core] Void -> POST `/merchant/postservice.php?form=2` (command=cancel_refund_transaction, var1=payuId only)

### 5.5 Mandate/Recurring Flow
1. [Setup] SetupMandate -> POST `/_payment` with si=1, si_details=JSON
2. [Repeat] RepeatPayment -> POST `/merchant/postservice.php?form=2` (command=si_transaction)
3. [Revoke] MandateRevoke -> POST `/merchant/postservice.php?form=2` (command=upi_mandate_revoke)

### 5.6 Webhook Flow
1. IncomingWebhook -- parse PayUResponseReq / PayuRefundWebhookResp / PayuUpiMandateStatusWebhook payload, map to internal event types

## 6. Gap Analysis

### 6.1 Tech Spec Features Missing from Connector-Service

| Feature | Category | What's Needed |
|---------|----------|---------------|
| OTP Submit/Resend | Flow | New flow type for OTP-based 2FA during payment |
| Pre-Debit Notification | Flow | New flow type for mandate pre-debit notifications |
| Settlement Fetch | Flow | New flow type for settlement data retrieval |
| Eligibility Check (BNPL/EMI) | Flow | New flow type for payment method eligibility |
| DC EMI / LinkAndPay EMI | PMT/PMD | New payment method types and data structures |
| Split Settlement | Flow | New flow type for split settlement operations |
| Delink Wallet | Flow | New flow type for wallet delinking |
| VPA Validation | Flow | New flow type for UPI VPA validation |
| Surcharge Check | Flow | New flow type for surcharge/fee calculation |
| Direct Debit (LinkAndPay) | Flow | New flow type or Authorize sub-flow |
| LazyPay (BNPL) | PMT | New PaymentMethodType::LazyPay variant |
| Mandate Token Update | Flow | New flow or enhancement to MandateRevoke |

### 6.2 Connector-Service Capabilities Not in Tech Spec

| Capability | Category | Notes |
|------------|----------|-------|
| VoidPC (Post-Capture Void) | Flow | PayU uses cancel_refund_transaction for both void and refund; VoidPC may be achievable via same API |
| IncrementalAuthorization | Flow | Not mentioned in PayU techspec |
| Dispute flows (Accept/Submit/Defend) | Flow | Not documented in PayU techspec |
| Payout flows | Flow | Not documented in PayU techspec |
| PaymentMethodToken | Flow | PayU tokenization exists but uses different flow (get_payment_instrument) |
| CreateOrder | Flow | PayU doesn't require order creation before payment |
| CreateAccessToken | Flow | PayU uses HMAC, not OAuth tokens |
| CreateConnectorCustomer | Flow | PayU doesn't require customer creation |

## 7. Implementation Priority (Recommended Order)

### Phase 1: Core Flows (implement these first)
1. Capture -> Void -> Refund -> RSync

### Phase 2: Prerequisites (if needed by gateway)
None needed - PayU has no prerequisite flows.

### Phase 3: Payment Methods (one at a time)
3. Card (Visa, Mastercard, Amex, Diners, Maestro, RuPay) first -> then Wallet (GooglePay)

### Phase 4: Advanced Flows
4. SetupMandate -> RepeatPayment -> MandateRevoke

### Phase 5: Webhooks
5. IncomingWebhook

## 8. Next Steps After Scaffolding (if gateway was absent)

N/A - Gateway already exists. Use the following workflows to implement additional flows:

### To implement flows:
```bash
# Add specific flows one at a time
add Capture flow to payu using grace/rulesbook/codegen/.gracerules_add_flow

# Add multiple flows
add Capture and Void and Refund and RSync flows to payu using grace/rulesbook/codegen/.gracerules_add_flow
```

### To add payment methods:
```bash
# Add card payment method types
add Card:Visa,Mastercard,Amex to payu using grace/rulesbook/codegen/.gracerules_add_payment_method
```

## Implementation Order (for Connector Agent consumption)

### 1. Capture
- **Status**: PLAN
- **Techspec Section**: "Flow 3: `captureTxn`" (lines 995-1012)
- **API Endpoint**: POST `/merchant/postservice.php?form=2`
- **HTTP Method**: POST
- **gRPC Service**: `types.PaymentService/Capture`
- **Pattern Guide**: `grace/rulesbook/codegen/guides/patterns/pattern_capture.md`
- **Key Request Fields**: key, command ("capture_transaction"), var1 (mihpayid/PayU payment ID), var2 (amount), hash (SHA512: key|command|var1|salt)
- **Key Response Fields**: status, message, error_code, error_description
- **Testing Notes**: Testing Agent runs its own MANUAL-capture Authorize first (isPreAuthEnabled=true), then Captures that payment. Note: PayU uses form-urlencoded POST with command field, not REST-style URLs.

### 2. Void
- **Status**: PLAN
- **Techspec Section**: "Flow 4: `voidTxn`" (lines 1013-1029)
- **API Endpoint**: POST `/merchant/postservice.php?form=2`
- **HTTP Method**: POST
- **gRPC Service**: `types.PaymentService/Void`
- **Pattern Guide**: `grace/rulesbook/codegen/guides/patterns/pattern_void.md`
- **Key Request Fields**: key, command ("cancel_refund_transaction"), var1 (mihpayid/PayU payment ID), hash (SHA512: key|command|var1|salt)
- **Key Response Fields**: status, message, error_code, error_description
- **Testing Notes**: Testing Agent runs its own MANUAL-capture Authorize, then Voids WITHOUT Capturing. Note: Same command as Refund ("cancel_refund_transaction") but WITHOUT var2 (amount) and var3 (txnId) fields.

### 3. Refund
- **Status**: PLAN
- **Techspec Section**: "Flow 15: `initPayuRefundRequestApi`" (lines 1150-1169) and "Section 3.5 PayuRefundRequest" (lines 235-245)
- **API Endpoint**: POST `/merchant/postservice.php?form=2`
- **HTTP Method**: POST
- **gRPC Service**: `types.PaymentService/Refund`
- **Pattern Guide**: `grace/rulesbook/codegen/guides/patterns/pattern_refund.md`
- **Key Request Fields**: key, command ("cancel_refund_transaction"), var1 (mihpayid/PayU payment ID), var2 (refund amount), var3 (transaction ID), hash (SHA512: key|command|var1|salt)
- **Key Response Fields**: PayuRefundResp ADT (SuccessRefundFetch/SplitRefundFetch/FailureRefundResponse), status (Int or String), message, error_code
- **Testing Notes**: Use connector_transaction_id (mihpayid) from the original AUTOMATIC-capture Authorize (which is CHARGED). Note: Refund status can be integer or string type.

### 4. RSync
- **Status**: PLAN
- **Techspec Section**: "Flow 30: Refund ARN Sync" (lines 1315-1322) and "Section 3.16 PayuRefundArnSyncRequest" (lines 338-346)
- **API Endpoint**: POST `/merchant/postservice.php?form=2`
- **HTTP Method**: POST
- **gRPC Service**: `types.RefundService/Get`
- **Pattern Guide**: `grace/rulesbook/codegen/guides/patterns/pattern_rsync.md`
- **Key Request Fields**: key, command ("getAllRefundsFromTxnIds"), var1 (transaction ID list), hash (SHA512: key|command|var1|salt)
- **Key Response Fields**: Refund status per transaction (SUCCESS/FAILURE/PENDING), ARN (bank reference number)
- **Testing Notes**: Use connector_refund_id from Refund response + connector_transaction_id from Authorize. PayU refund status can be StatusIntType or StatusStringType.

### 5. SetupMandate
- **Status**: PLAN
- **Techspec Section**: "Flow 9: `setupMandate`" (lines 1081-1091) and "Section 8.5 Mandate Frequency" (lines 1912-1926)
- **API Endpoint**: POST `/_payment`
- **HTTP Method**: POST
- **gRPC Service**: `types.PaymentService/SetupRecurring`
- **Pattern Guide**: `grace/rulesbook/codegen/guides/patterns/pattern_setup_mandate.md`
- **Key Request Fields**: Same as Authorize plus: si ("1"), si_details (JSON with mandateAmount, billingCycle, billingInterval, startDate, endDate, amountRule), pg, bankcode
- **Key Response Fields**: Same as Authorize response (status, mihpayid, unmappedstatus), plus mandate_id, umrn
- **Testing Notes**: Uses connector_transaction_id from Authorize. Must include si="1" and si_details JSON. Mandate frequency maps: DAILY->DAILY/1, WEEKLY->WEEKLY/1, MONTHLY->MONTHLY/1, QUARTERLY->MONTHLY/3, etc.

### 6. RepeatPayment
- **Status**: PLAN
- **Techspec Section**: "Flow 10: `executeMandate`" (lines 1092-1102) and "Section 3.9 PayuExerciseMandateRequest" (lines 274-282)
- **API Endpoint**: POST `/merchant/postservice.php?form=2`
- **HTTP Method**: POST
- **gRPC Service**: `types.RecurringPaymentService/Charge`
- **Pattern Guide**: `grace/rulesbook/codegen/guides/patterns/pattern_repeat_payment_flow.md`
- **Key Request Fields**: key, command ("si_transaction"), var1 (JSON-encoded mandate token type), hash (SHA512: key|"si_transaction"|encodeJSON(payUMandateTokenType)|salt)
- **Key Response Fields**: PayUExerciseMandateResponse (status, message, mandateDetails, mihpayid, txnid, amount, unmappedstatus, error_code, error_Message)
- **Testing Notes**: Needs mandate_id from SetupMandate. The var1 field is JSON-encoded mandate token details.

## Testing Strategy

- **Authorize**: EXISTING - already implemented for UPI (Collect/Intent). Use AUTOMATIC capture.
- **PSync**: EXISTING - already implemented using verify_payment command.
- **Capture**: Testing Agent runs its OWN fresh Authorize with MANUAL capture (isPreAuthEnabled=true must be configured), then Captures. Requires card payment method support (UPI is auto-capture only).
- **Void**: Testing Agent runs its OWN fresh Authorize with MANUAL capture, then Voids WITHOUT Capturing.
- **Refund**: Use connector_transaction_id (mihpayid) from the original AUTOMATIC-capture Authorize (which is CHARGED).
- **RSync**: Use connector_refund_id from Refund response + connector_transaction_id from Authorize.
- **SetupMandate**: Use Authorize flow with SI fields.
- **RepeatPayment**: Needs mandate_id from SetupMandate response.

## Data Flow Map

```
Authorize (AUTOMATIC) -> connector_transaction_id (mihpayid) -> PSync, Refund, SetupMandate
Authorize (MANUAL, by Capture testing) -> connector_transaction_id (mihpayid) -> Capture
Authorize (MANUAL, by Void testing) -> connector_transaction_id (mihpayid) -> Void
Refund -> connector_refund_id -> RSync
SetupMandate -> mandate_id -> RepeatPayment
```
