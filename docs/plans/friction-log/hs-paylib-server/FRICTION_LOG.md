# hs-paylib Integration Friction Log

**Date:** 2026-04-07  
**Project:** Node.js Payment Server with hs-paylib  
**Connectors:** Stripe (USD), Adyen (EUR)  
**Version Tested:** hs-paylib v0.0.4

---

## Executive Summary

This friction log documents the integration experience of building a Node.js payment server using the `hs-paylib` NPM library. The integration successfully routes USD payments through Stripe and EUR payments through Adyen. While the core functionality works, several friction points were encountered related to documentation gaps, naming inconsistencies, and missing field requirements.

### Key Findings by Pattern

| Pattern | Friction Points | Criticality | Status |
|---------|----------------|-------------|--------|
| **Documentation** | Missing field requirements, unclear enum values | High | Partially Resolved |
| **Naming Consistency** | Snake_case vs camelCase field naming | Medium | Workaround Applied |
| **Error Messages** | Generic "MISSING_REQUIRED_FIELD" without context | High | Workaround Applied |
| **Type Discovery** | No autocomplete for Currency/Connector enums | Medium | Resolved via Source |
| **Testing** | No test mode indicator in config | Low | Documented |

---

## Summary of Recommendations

| # | Recommendation | Criticality | Impact |
|---|---------------|-------------|--------|
| 1 | Document all required fields per connector in README | **Critical** | Prevents trial-and-error integration |
| 2 | Standardize field naming (camelCase for JS SDK) | **High** | Reduces confusion and bugs |
| 3 | Add specific error messages with field paths | **High** | Faster debugging |
| 4 | Export TypeScript enum types for Currency/Connector | **Medium** | Better IDE support |
| 5 | Add `testMode: true` to config examples | **Low** | Clearer testing setup |
| 6 | Provide JSON Schema for all request types | **Medium** | Validation and documentation |
| 7 | Document browser_info requirements for 3DS | **High** | Essential for EU payments |

---

## Detailed Step-by-Step Log

### Step 1: Initial Setup

**Action:** Install hs-paylib and dependencies

```bash
npm install hs-paylib express dotenv
```

**Friction:** None - installation was straightforward

**Time Spent:** 1 minute

---

### Step 2: Client Initialization

**Action:** Create PaymentClient with Stripe configuration

```javascript
const stripeConfig = {
  connectorConfig: {
    stripe: {
      apiKey: { value: process.env.STRIPE_API_KEY }
    }
  }
};
const client = new PaymentClient(stripeConfig, requestConfig);
```

**Friction:**  
- **Issue:** Unclear if `apiKey` should be nested in `stripe` or at root level
- **Resolution:** Examined SDK source code to understand nested structure
- **Assumption Made:** Configuration follows `connectorConfig.{connectorName}` pattern

**Time Spent:** 5 minutes

**How Overcome:** Read SDK source in `node_modules/hs-paylib/dist/src/payments/connector_client.js`

---

### Step 3: Currency Enum Discovery

**Action:** Attempt to set currency in payment request

```javascript
currency: types.Currency.USD  // First attempt
```

**Friction:**
- **Issue:** TypeScript types show `Currency.USD` but runtime value is undefined
- **Root Cause:** SDK exports protobuf enums as numbers, not string constants
- **Error:** `Currency` is undefined when destructured from import

**Resolution:**
```javascript
const { types } = require('hs-paylib');
// Access via types.Currency.USD which equals 146
```

**Time Spent:** 15 minutes

**How Overcome:** Searched proto.js source to find: `USD = 146` at line 2608

**Assumption Made:** Currency values are protobuf enum ordinals, not ISO strings

---

### Step 4: First Authorization Attempt

**Action:** Call `client.authorize()` with basic card data

**Friction:**
- **Issue:** Error "Missing required field: browser_info" for EUR payments
- **Error Code:** `MISSING_REQUIRED_FIELD`
- **Root Cause:** Adyen requires browser_info for 3D Secure compliance

**Resolution:**
```javascript
if (currency === 'EUR') {
  request.browserInfo = {
    user_agent: '...',
    accept_header: '...',
    // ... more fields
  };
}
```

**Time Spent:** 25 minutes

**How Overcome:** Trial and error - SDK kept rejecting with progressively more specific field names:
1. First: "browser_info" - added object
2. Then: "browser_info.time_zone" - tried camelCase, failed
3. Then: "browser_info.timeZoneOffsetMinutes" - failed
4. Finally: "browser_info.time_zone" - **snake_case required**

**Critical Learning:** Field naming convention is **snake_case** for nested objects, not camelCase

---

### Step 5: Field Naming Convention Confusion

**Action:** Add browser info with intuitive JavaScript naming

```javascript
browserInfo: {
  userAgent: '...',           // ❌ Wrong
  timeZone: -480,             // ❌ Wrong
  acceptHeader: '...'         // ❌ Wrong
}
```

**Friction:**
- **Issue:** SDK expects snake_case but JavaScript convention is camelCase
- **Error Messages:** Generic "Missing required field" without showing expected name
- **Examples:**
  - Expected: `user_agent`, Got: `userAgent`
  - Expected: `time_zone`, Got: `timeZoneOffsetMinutes`
  - Expected: `accept_header`, Got: `acceptHeader`

**Resolution:**
```javascript
browserInfo: {
  user_agent: 'Mozilla/5.0...',  // ✓ Correct
  accept_header: 'text/html...', // ✓ Correct
  time_zone: -480,                // ✓ Correct
  color_depth: 24,
  screen_height: 1080,
  screen_width: 1920,
  java_enabled: false,
  java_script_enabled: true
}
```

**Time Spent:** 20 minutes

**How Overcome:** Systematic trial-and-error with SDK error feedback

**Assumption Made:** FFI layer (Rust) expects snake_case matching Rust conventions

---

### Step 6: Refund Implementation

**Action:** Implement refund endpoint

```javascript
const refundRequest = {
  merchantTransactionId: '...',
  amount: { minorAmount: 1000, currency: types.Currency.USD },
  referenceTransactionId: txnId,
  reason: 'Customer requested refund'
};
```

**Friction:**
- **Issue:** Error "Missing required field: refund_amount"
- **Root Cause:** Field name is `refundAmount` not `amount`
- **Secondary Issue:** Field name is `connectorTransactionId` not `referenceTransactionId`

**Resolution:**
```javascript
const refundRequest = {
  merchantTransactionId: '...',
  refundAmount: { minorAmount: 1000, currency: types.Currency.USD },
  connectorTransactionId: txnId,
  reason: 'Customer requested refund'
};
```

**Time Spent:** 10 minutes

**How Overcome:** Searched proto.js for `PaymentServiceRefundRequest` definition

---

### Step 7: Understanding Status Codes

**Action:** Interpret payment response status

**Friction:**
- **Issue:** Status returned as number (e.g., `status: 8`)
- **Documentation Gap:** No status code legend in README

**Resolution:** Searched proto.js and found enum definition:
```javascript
const statusMap = {
  0: 'PENDING',
  1: 'PROCESSING',
  2: 'SUCCESS',
  3: 'FAILED',
  4: 'CANCELLED',
  5: 'AUTHORIZED',
  6: 'CAPTURED',
  7: 'REFUNDED',
  8: 'CHARGED'
};
```

**Time Spent:** 5 minutes

**How Overcome:** Source code search for status-related enums

---

### Step 8: EUR Payment Testing

**Action:** Test Adyen integration with EUR currency

**Friction:**
- **Issue:** Multiple missing required fields discovered incrementally
- **Progression:**
  1. Missing `browser_info`
  2. Missing `browser_info.time_zone`
  3. Missing `browser_info.accept_header`
  4. Missing `browser_info.user_agent`

**Time Spent:** 30 minutes

**How Overcome:** Iterative testing with server restart between attempts

**Recommendation:** Document complete browser_info requirements upfront

---

## Assumptions Made and How Overcome

### Assumption 1: Configuration Structure
**Assumed:** API keys go at root of connectorConfig  
**Reality:** Must be nested: `connectorConfig.stripe.apiKey`  
**Overcome:** Source code inspection

### Assumption 2: Field Naming Convention
**Assumed:** JavaScript camelCase convention  
**Reality:** Snake_case required for FFI compatibility  
**Overcome:** Error-driven discovery

### Assumption 3: Enum Access
**Assumed:** `types.Currency.USD` would be a string  
**Reality:** It's a number (146) - protobuf ordinal  
**Overcome:** Runtime inspection and source reading

### Assumption 4: Universal Browser Info
**Assumed:** browser_info optional for all payments  
**Reality:** Required for EUR/Adyen (3D Secure)  
**Overcome:** Error message indicated requirement

### Assumption 5: Refund Field Names
**Assumed:** Consistent with authorize (use `amount`)  
**Reality:** Use `refundAmount`  
**Overcome:** Source code inspection

---

## Connector-Specific Findings

### Stripe (USD)
- ✅ Simple configuration (just apiKey)
- ✅ Works without browser_info
- ✅ Clear transaction IDs (pi_* format)
- ⚠️ Refund response status mapping unclear

### Adyen (EUR)
- ⚠️ Requires extensive browser_info
- ⚠️ Field naming very strict
- ⚠️ 3D Secure compliance mandatory
- ✅ Returns structured error messages

---

## Files Delivered

1. **server.js** - Main Express server with USD/EUR routing
2. **test.js** - Automated test suite
3. **test-payment.sh** - Quick payment test script
4. **.env** - Configuration template with credentials
5. **package.json** - Project dependencies
6. **README.md** - Server documentation
7. **FRICTION_LOG.md** - This document

---

## Time Breakdown

| Activity | Time |
|----------|------|
| Initial setup & installation | 5 min |
| SDK exploration & source reading | 20 min |
| Stripe integration (USD) | 15 min |
| Adyen integration (EUR) | 45 min |
| Refund implementation | 15 min |
| Testing & debugging | 20 min |
| Documentation | 15 min |
| **Total** | **135 min (2h 15m)** |

---

## Conclusion

The `hs-paylib` SDK provides powerful payment orchestration capabilities but has significant documentation gaps that increase integration time. The most critical improvements needed are:

1. **Complete field documentation** with naming conventions
2. **Connector-specific requirements** (browser_info, auth methods)
3. **Standardized naming** (camelCase for JavaScript SDK)
4. **Better error messages** with field paths and expected formats

Despite these friction points, the SDK successfully enables multi-connector payments with a unified API, which is valuable for payment orchestration use cases.
