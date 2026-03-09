# Nuvei UCS Test Cases

## Overview

This document contains all test cases, curl requests, and responses for the Nuvei UCS (Unified Connector Service) integration, including CIT/MIT flows and PG-agnostic mandate testing.

## Prerequisites

### Test Environment Setup

```
Hyperswitch:  http://localhost:8080
UCS (gRPC):   localhost:8000
```

### Test Credentials (Nuvei Sandbox)

| Field | Value |
|-------|-------|
| Merchant ID | `3132254` |
| Merchant Site ID | `247446` |
| Merchant Secret | (configured in connector_account_details) |
| Auth Type | `SignatureKey` (`api_key` = merchant_id, `key1` = merchant_site_id, `api_secret` = merchant_secret) |

### Test Cards

| Card Number | Brand | Use Case |
|-------------|-------|----------|
| `4761344136141390` | Visa | Success (no 3DS) |

### Enable PG-Agnostic Mandates

```sql
UPDATE business_profile
SET is_connector_agnostic_mit_enabled = true
WHERE profile_id = '<your_profile_id>';
```

Or via API:
```bash
curl -X POST 'http://localhost:8080/account/<merchant_id>/business_profile/<profile_id>' \
  -H 'Content-Type: application/json' \
  -H 'api-key: test_admin' \
  -d '{"is_connector_agnostic_mit_enabled": true}'
```

---

## Implemented Flows

| Flow | Endpoint | Status |
|------|----------|--------|
| Authorize (CIT) | `payment.do` | Implemented + Tested |
| PSync | `getPaymentStatus.do` | Implemented + Tested |
| Capture | `settleTransaction.do` | Implemented + Tested |
| Void | `voidTransaction.do` | Implemented + Tested |
| Refund | `refundTransaction.do` | Implemented + Tested |
| RSync | `getPaymentStatus.do` | Implemented + Tested |
| SessionToken | `getSessionToken.do` | Implemented + Tested |
| RepeatPayment (MIT) | `payment.do` | Implemented + Tested |
| VoidPC (Void Post Capture) | `voidTransaction.do` | Implemented |
| PreAuthenticate | `initPayment.do` | Implemented |
| SetupMandate | `payment.do` | Implemented |

---

## Test Cases

### 1. CIT (Customer Initiated Transaction) with `setup_future_usage`

Creates a payment via Nuvei with `setup_future_usage: off_session` to obtain a Network Transaction ID (NTID) for future MIT payments.

**Request:**
```bash
curl -X POST http://localhost:8080/payments \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -H "api-key: <YOUR_API_KEY>" \
  -d '{
    "amount": 6540,
    "currency": "USD",
    "confirm": true,
    "capture_method": "automatic",
    "customer_id": "cit_mit_test_customer",
    "email": "test@example.com",
    "payment_method": "card",
    "payment_method_type": "credit",
    "payment_method_data": {
      "card": {
        "card_number": "4761344136141390",
        "card_exp_month": "12",
        "card_exp_year": "2027",
        "card_cvc": "123",
        "card_holder_name": "John Doe"
      }
    },
    "setup_future_usage": "off_session",
    "description": "CIT payment for PG-agnostic test",
    "return_url": "https://google.com/",
    "routing": {"type": "single", "data": "nuvei"},
    "browser_info": {
      "user_agent": "Mozilla/5.0",
      "accept_header": "text/html",
      "language": "en-US",
      "color_depth": 24,
      "screen_height": 1080,
      "screen_width": 1920,
      "time_zone": -330,
      "java_enabled": false,
      "java_script_enabled": true,
      "ip_address": "1.1.1.1"
    },
    "billing": {
      "address": {
        "line1": "123 Main St",
        "city": "San Francisco",
        "state": "CA",
        "zip": "94107",
        "country": "US",
        "first_name": "John",
        "last_name": "Doe"
      },
      "phone": {"number": "1234567890", "country_code": "+1"}
    }
  }'
```

**Response (key fields):**
```json
{
  "payment_id": "pay_sc7coWWMpOCjleM0Lyyf",
  "status": "succeeded",
  "connector": "nuvei",
  "amount": 6540,
  "amount_received": 6540,
  "connector_transaction_id": "8110000000025171951",
  "network_transaction_id": "483297487231504",
  "setup_future_usage": "off_session",
  "authentication_type": "no_three_ds",
  "capture_method": "automatic"
}
```

**Key:** The `network_transaction_id` (`483297487231504`) is used for subsequent MIT payments.

---

### 2. MIT (Merchant Initiated Transaction) via Same Connector (Nuvei)

Uses the NTID from the CIT to perform a recurring payment through the same connector.

**Request:**
```bash
curl -X POST http://localhost:8080/payments \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -H "api-key: <YOUR_API_KEY>" \
  -d '{
    "amount": 3000,
    "currency": "USD",
    "confirm": true,
    "capture_method": "automatic",
    "customer_id": "cit_mit_test_customer",
    "email": "test@example.com",
    "off_session": true,
    "payment_method": "card",
    "payment_method_type": "credit",
    "recurring_details": {
      "type": "network_transaction_id_and_card_details",
      "data": {
        "card_number": "4761344136141390",
        "card_exp_month": "12",
        "card_exp_year": "2027",
        "card_holder_name": "John Doe",
        "card_network": "Visa",
        "network_transaction_id": "483297487231504"
      }
    },
    "description": "MIT payment via Nuvei using NTID",
    "return_url": "https://google.com/",
    "browser_info": {
      "user_agent": "Mozilla/5.0",
      "accept_header": "text/html",
      "language": "en-US",
      "color_depth": 24,
      "screen_height": 1080,
      "screen_width": 1920,
      "time_zone": -330,
      "java_enabled": false,
      "java_script_enabled": true,
      "ip_address": "1.1.1.1"
    },
    "billing": {
      "address": {
        "line1": "123 Main St",
        "city": "San Francisco",
        "state": "CA",
        "zip": "94107",
        "country": "US",
        "first_name": "John",
        "last_name": "Doe"
      }
    }
  }'
```

**Response (key fields):**
```json
{
  "payment_id": "pay_neK0bgBO8nFp3cit1cQN",
  "status": "succeeded",
  "connector": "nuvei",
  "amount": 3000,
  "amount_received": 3000,
  "connector_transaction_id": "8110000000025172022",
  "network_transaction_id": "483297487231504",
  "is_stored_credential": true,
  "off_session": true
}
```

---

### 3. PG-Agnostic MIT (Cross-Connector: Nuvei NTID -> Cybersource)

Uses the NTID from a Nuvei CIT to perform MIT through a different connector (Cybersource). Requires `is_connector_agnostic_mit_enabled = true` on the business profile.

**Routing Setup:** Set Cybersource as first priority in routing for MIT test.

**Request:**
```bash
curl -X POST http://localhost:8080/payments \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -H "api-key: <YOUR_API_KEY>" \
  -d '{
    "amount": 4500,
    "currency": "USD",
    "confirm": true,
    "capture_method": "automatic",
    "customer_id": "cit_mit_test_customer",
    "email": "test@example.com",
    "off_session": true,
    "payment_method": "card",
    "payment_method_type": "credit",
    "recurring_details": {
      "type": "network_transaction_id_and_card_details",
      "data": {
        "card_number": "4761344136141390",
        "card_exp_month": "12",
        "card_exp_year": "2027",
        "card_holder_name": "John Doe",
        "card_network": "Visa",
        "network_transaction_id": "483297487231504"
      }
    },
    "description": "PG-agnostic MIT: NTID from Nuvei CIT, processed via Cybersource",
    "return_url": "https://google.com/",
    "browser_info": {
      "user_agent": "Mozilla/5.0",
      "accept_header": "text/html",
      "language": "en-US",
      "color_depth": 24,
      "screen_height": 1080,
      "screen_width": 1920,
      "time_zone": -330,
      "java_enabled": false,
      "java_script_enabled": true,
      "ip_address": "1.1.1.1"
    },
    "billing": {
      "address": {
        "line1": "123 Main St",
        "city": "San Francisco",
        "state": "CA",
        "zip": "94107",
        "country": "US",
        "first_name": "John",
        "last_name": "Doe"
      }
    }
  }'
```

**Response (key fields):**
```json
{
  "payment_id": "pay_HhFMclkigbQghtLHsRR5",
  "status": "failed",
  "connector": "cybersource",
  "error_message": "Authentication Failed",
  "error_details": {
    "connector_details": {
      "code": "No error code",
      "message": "Authentication Failed",
      "reason": "Authentication Failed"
    }
  }
}
```

**Note:** The payment was correctly routed to Cybersource (PG-agnostic routing works). The failure is due to invalid/expired Cybersource sandbox credentials. With valid credentials, this would succeed.

---

### 4. Authorize with Manual Capture

Creates an authorized payment that requires manual capture.

**Request:**
```bash
curl -X POST http://localhost:8080/payments \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -H "api-key: <YOUR_API_KEY>" \
  -d '{
    "amount": 5000,
    "currency": "USD",
    "confirm": true,
    "capture_method": "manual",
    "customer_id": "capture_test_customer",
    "email": "test@example.com",
    "payment_method": "card",
    "payment_method_type": "credit",
    "payment_method_data": {
      "card": {
        "card_number": "4761344136141390",
        "card_exp_month": "12",
        "card_exp_year": "2027",
        "card_cvc": "123",
        "card_holder_name": "Test User"
      }
    },
    "description": "Manual capture test",
    "return_url": "https://google.com/",
    "routing": {"type": "single", "data": "nuvei"},
    "browser_info": {
      "user_agent": "Mozilla/5.0",
      "accept_header": "text/html",
      "language": "en-US",
      "color_depth": 24,
      "screen_height": 1080,
      "screen_width": 1920,
      "time_zone": -330,
      "java_enabled": false,
      "java_script_enabled": true,
      "ip_address": "1.1.1.1"
    },
    "billing": {
      "address": {
        "line1": "123 Main St",
        "city": "San Francisco",
        "state": "CA",
        "zip": "94107",
        "country": "US",
        "first_name": "Test",
        "last_name": "User"
      },
      "phone": {"number": "1234567890", "country_code": "+1"}
    }
  }'
```

**Response (key fields):**
```json
{
  "payment_id": "pay_Vo6yxgZkKQbbpPrCmw9j",
  "status": "requires_capture",
  "connector": "nuvei",
  "amount": 5000,
  "connector_transaction_id": "8110000000025172058",
  "capture_method": "manual"
}
```

---

### 5. PSync (Payment Sync)

Retrieves the current status of a payment.

**Request:**
```bash
curl http://localhost:8080/payments/<payment_id> \
  -H "api-key: <YOUR_API_KEY>"
```

**Response (key fields):**
```json
{
  "payment_id": "pay_Vo6yxgZkKQbbpPrCmw9j",
  "status": "requires_capture",
  "connector_transaction_id": "8110000000025172058"
}
```

---

### 6. Capture

Captures a previously authorized payment.

**Request:**
```bash
curl -X POST http://localhost:8080/payments/<payment_id>/capture \
  -H "Content-Type: application/json" \
  -H "api-key: <YOUR_API_KEY>" \
  -d '{"amount_to_capture": 5000}'
```

**Response (key fields):**
```json
{
  "payment_id": "pay_Vo6yxgZkKQbbpPrCmw9j",
  "status": "succeeded",
  "amount_received": 5000
}
```

---

### 7. Void (Cancel)

Cancels an authorized-but-not-captured payment.

**Request:**
```bash
curl -X POST http://localhost:8080/payments/<payment_id>/cancel \
  -H "Content-Type: application/json" \
  -H "api-key: <YOUR_API_KEY>" \
  -d '{"cancellation_reason": "Customer requested"}'
```

**Response (key fields):**
```json
{
  "payment_id": "pay_qxjZRG5QLZlxHeE32OZ7",
  "status": "cancelled"
}
```

---

### 8. Refund

Refunds a captured/succeeded payment (partial or full).

**Request:**
```bash
curl -X POST http://localhost:8080/refunds \
  -H "Content-Type: application/json" \
  -H "api-key: <YOUR_API_KEY>" \
  -d '{
    "payment_id": "<payment_id>",
    "amount": 2000,
    "reason": "Customer refund"
  }'
```

**Response (key fields):**
```json
{
  "refund_id": "ref_aaelHqWCeDHkiUhE23KL",
  "status": "succeeded",
  "amount": 2000
}
```

---

### 9. RSync (Refund Sync)

Retrieves the current status of a refund.

**Request:**
```bash
curl http://localhost:8080/refunds/<refund_id> \
  -H "api-key: <YOUR_API_KEY>"
```

**Response (key fields):**
```json
{
  "refund_id": "ref_aaelHqWCeDHkiUhE23KL",
  "status": "succeeded",
  "amount": 2000
}
```

---

## PG-Agnostic Mandate Flow (End-to-End)

### Flow Diagram

```
1. CIT via Nuvei      -->  Nuvei returns network_transaction_id (NTID)
2. MIT via Cybersource -->  Uses NTID from step 1 (cross-connector)
```

### Step-by-Step

#### Step 1: Enable PG-Agnostic Mandates on Business Profile

```sql
UPDATE business_profile
SET is_connector_agnostic_mit_enabled = true
WHERE profile_id = '<profile_id>';
```

#### Step 2: Create Both Connectors (Nuvei + Cybersource)

Ensure both connectors are created under the same merchant and profile.

#### Step 3: Set Routing

For CIT: Route to Nuvei (priority first)
```bash
curl -X POST http://localhost:8080/routing \
  -H "Content-Type: application/json" \
  -H "api-key: <YOUR_API_KEY>" \
  -d '{
    "name": "nuvei-first",
    "algorithm": {
      "type": "priority",
      "data": [
        {"connector": "nuvei", "merchant_connector_id": "<nuvei_mca_id>"},
        {"connector": "cybersource", "merchant_connector_id": "<cybersource_mca_id>"}
      ]
    },
    "profile_id": "<profile_id>"
  }'
# Activate: POST /routing/<routing_id>/activate with body {}
```

#### Step 4: CIT Payment via Nuvei

Use the CIT curl from Test Case 1 above. Extract `network_transaction_id` from response.

#### Step 5: Switch Routing to Cybersource-first for MIT

```bash
curl -X POST http://localhost:8080/routing \
  -H "Content-Type: application/json" \
  -H "api-key: <YOUR_API_KEY>" \
  -d '{
    "name": "cybersource-first",
    "algorithm": {
      "type": "priority",
      "data": [
        {"connector": "cybersource", "merchant_connector_id": "<cybersource_mca_id>"},
        {"connector": "nuvei", "merchant_connector_id": "<nuvei_mca_id>"}
      ]
    },
    "profile_id": "<profile_id>"
  }'
# Activate: POST /routing/<routing_id>/activate with body {}
```

#### Step 6: MIT Payment via Cybersource using Nuvei's NTID

Use the PG-Agnostic MIT curl from Test Case 3, providing the NTID from the CIT response.

---

## Test Results Summary

| Test Case | Connector | Status | Payment ID |
|-----------|-----------|--------|------------|
| CIT (auto capture) | nuvei | succeeded | `pay_sc7coWWMpOCjleM0Lyyf` |
| MIT (same connector) | nuvei | succeeded | `pay_neK0bgBO8nFp3cit1cQN` |
| PG-Agnostic MIT | cybersource | failed (bad creds) | `pay_HhFMclkigbQghtLHsRR5` |
| Authorize (manual) | nuvei | requires_capture | `pay_Vo6yxgZkKQbbpPrCmw9j` |
| PSync | nuvei | requires_capture | `pay_Vo6yxgZkKQbbpPrCmw9j` |
| Capture | nuvei | succeeded | `pay_Vo6yxgZkKQbbpPrCmw9j` |
| Void | nuvei | cancelled | `pay_qxjZRG5QLZlxHeE32OZ7` |
| Refund | nuvei | succeeded | `ref_aaelHqWCeDHkiUhE23KL` |
| RSync | nuvei | succeeded | `ref_aaelHqWCeDHkiUhE23KL` |

---

## Known Limitations

### 1. Session Token via UCS
Nuvei requires a session token before each payment (`getSessionToken.do`). In hyperswitch, `session_token.rs` uses `execute_payment_gateway` (old connector path), not the UCS-compatible `execute_payment_gateway_with_context`. This means the session token always goes through the old nuvei connector code, even when nuvei is in `ucs_only_connectors`.

**Impact:** Session token works (old connector code handles it), but it's not going through UCS.

### 2. PostAuthenticate Response Type Mismatch
UCS's `PostAuthenticate` (equivalent to hyperswitch's `CompleteAuthorize`) expects a `PostAuthenticateResponse` variant with `authentication_data`, but Nuvei returns a full payment `TransactionResponse`. The grpc-server's `generate_payment_post_authenticate_response` rejects non-`PostAuthenticateResponse` variants.

### 3. Cybersource Credentials
The Cybersource sandbox credentials used in PG-agnostic testing returned "Authentication Failed". This is a credential issue, not a routing issue - the payment was correctly routed to Cybersource with the NTID.

---

## NTID (Network Transaction ID) Details

The `network_transaction_id` is returned by the card network (Visa/Mastercard) during a CIT when `setup_future_usage: off_session` is set. It serves as a proof of cardholder authentication for subsequent MIT payments.

| Field | Value |
|-------|-------|
| NTID from CIT | `483297487231504` |
| Source connector | Nuvei |
| Nuvei field | `externalTransactionId` in payment response |
| Stored in | `payment_attempt.network_transaction_id` |

The NTID is connector-agnostic - it can be used with any connector that supports network-level stored credentials (e.g., Cybersource, Nuvei, Adyen).
