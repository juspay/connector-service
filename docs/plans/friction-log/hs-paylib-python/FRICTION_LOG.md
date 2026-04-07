# hs-paylib Python Integration Friction Log

**Date:** 2026-04-07  
**Project:** Python Payment Server with hs-paylib  
**Connectors:** Stripe (USD), Adyen (EUR)  
**Version Tested:** hs-paylib v0.0.4

---

## Executive Summary

This friction log documents the integration experience of building a Python FastAPI payment server using the `hs-paylib` PyPI library. The integration successfully routes USD payments through Stripe and EUR payments through Adyen.

### Key Findings by Pattern

| Pattern | Friction Points | Criticality | Status |
|---------|----------------|-------------|--------|
| **Documentation** | Sparse SDK documentation, missing field requirements | High | Partially Resolved |
| **Type Discovery** | Unclear how to access Currency/Connector enums | Medium | Resolved via Source |
| **Field Naming** | Snake_case required for FFI compatibility | Medium | Documented |
| **Type System** | Pydantic vs SDK types confusion | Low | Workaround Applied |
| **Import Structure** | Unclear module structure for imports | Medium | Resolved |

---

## Summary of Recommendations

| # | Recommendation | Criticality | Impact |
|---|---|---|---|
| 1 | Add comprehensive Python SDK documentation with examples | **Critical** | Reduces integration time significantly |
| 2 | Document enum access patterns (types.Currency, types.Connector) | **High** | Prevents trial-and-error |
| 3 | Clarify field naming conventions in README | **Medium** | Avoids runtime errors |
| 4 | Provide FastAPI/Flask integration examples | **Medium** | Common use case |
| 5 | Document browser_info requirements for EUR/Adyen | **High** | Essential for EU payments |
| 6 | Add type hints/stubs for better IDE support | **Medium** | Developer experience |

---

## Detailed Step-by-Step Log

### Step 1: Environment Setup

**Action:** Create virtual environment and install dependencies

```bash
python3 -m venv venv
source venv/bin/activate
pip install fastapi uvicorn hs-paylib
```

**Friction:** None - installation was straightforward

**Time Spent:** 2 minutes

---

### Step 2: Import Discovery

**Action:** Attempt to import PaymentClient and types

**Friction:**
- **Issue:** Unclear import path for the SDK
- **Attempt 1:** `from hs_paylib import PaymentClient` - Failed
- **Attempt 2:** `from hs_paylib.payments import PaymentClient` - Failed
- **Attempt 3:** `from payments import PaymentClient` - Success

**Resolution:**
```python
from payments import PaymentClient, types
```

**Time Spent:** 5 minutes

**How Overcome:** Explored installed package structure via `pip show hs-paylib` and directory inspection

**Assumption Made:** Package uses `payments` as the top-level module name

---

### Step 3: Configuration Structure

**Action:** Create PaymentClient configuration for Stripe

**Friction:**
- **Issue:** Unclear if configuration should use Python dict or SDK types
- **Attempt 1:** Plain dict - Failed (SDK expects specific types)
- **Attempt 2:** Using `types.ConnectorConfig` - Success

**Resolution:**
```python
stripe_config = types.ConnectorConfig({
    "connectorConfig": {
        "stripe": {
            "apiKey": {"value": os.getenv("STRIPE_API_KEY")}
        }
    }
})
```

**Time Spent:** 10 minutes

**How Overcome:** Examined SDK source code in `site-packages/payments/`

---

### Step 4: Currency Enum Access

**Action:** Set currency in payment request

**Friction:**
- **Issue:** No documentation on how to access currency values
- **Attempt 1:** `types.Currency.USD` - Success (value is an int, 146)
- **Attempt 2:** Using string "USD" - Failed (SDK expects enum)

**Resolution:**
```python
from payments import types
currency = types.Currency.USD  # Returns int: 146
```

**Time Spent:** 8 minutes

**How Overcome:** Runtime inspection via `dir(types.Currency)` and `print(types.Currency.USD)`

**Assumption Made:** Currency values are protobuf enum ordinals

---

### Step 5: Connector Enum Access

**Action:** Get connector enum for routing logic

**Friction:**
- **Issue:** Similar to Currency, needed to discover Connector enum
- **Discovery:** `types.Connector` enum exists with STRIPE, ADYEN values

**Resolution:**
```python
connector = types.Connector.STRIPE  # Returns enum value
connector_name = connector.name     # "STRIPE"
```

**Time Spent:** 3 minutes

**How Overcome:** Pattern recognition from Currency enum discovery

---

### Step 6: Request Structure - Authorize

**Action:** Build authorize request payload

**Friction:**
- **Issue:** Unclear field structure for payment request
- **Discovery:** Request must match protobuf structure exactly
- **Key Fields:**
  - `merchantTransactionId` (string)
  - `amount` with `minorAmount` (int) and `currency` (enum)
  - `paymentMethod.card` with nested card fields
  - `captureMethod` (enum)
  - `authType` (enum)

**Resolution:**
```python
authorize_request = {
    "merchantTransactionId": txn_id,
    "amount": {
        "minorAmount": int(amount * 100),  # Convert to cents
        "currency": types.Currency.USD,
    },
    "captureMethod": types.CaptureMethod.AUTOMATIC,
    "paymentMethod": {
        "card": {
            "cardNumber": {"value": card_number},
            "cardExpMonth": {"value": exp_month},
            # ... etc
        }
    },
    "authType": types.AuthenticationType.NO_THREE_DS,
    # ...
}
```

**Time Spent:** 15 minutes

**How Overcome:** Source code inspection and trial-and-error

---

### Step 7: Browser Info for EUR/Adyen

**Action:** Handle EUR payments requiring browser_info

**Friction:**
- **Issue:** Adyen requires browser_info for 3D Secure
- **Error:** "Missing required field: browser_info"
- **Naming:** Must use snake_case fields (user_agent, not userAgent)

**Resolution:**
```python
if currency_upper == "EUR":
    authorize_request["browserInfo"] = {
        "user_agent": "Mozilla/5.0...",
        "accept_header": "text/html...",
        "language": "en-US",
        "color_depth": 24,
        "screen_height": 1080,
        "screen_width": 1920,
        "time_zone": -480,
        "java_enabled": False,
        "java_script_enabled": True,
    }
```

**Time Spent:** 20 minutes

**How Overcome:** Learned from Node.js implementation friction log

---

### Step 8: Refund Request Structure

**Action:** Build refund request

**Friction:**
- **Issue:** Field naming differs from authorization
- **Key Discovery:** Use `refundAmount` not `amount`
- **Key Discovery:** Use `connectorTransactionId` not `referenceTransactionId`

**Resolution:**
```python
refund_request = {
    "merchantTransactionId": f"{original_txn}_refund_{timestamp}",
    "refundAmount": {
        "minorAmount": int(amount * 100),
        "currency": types.Currency.USD,
    },
    "connectorTransactionId": original_connector_txn,
    "reason": "Customer requested refund",
}
```

**Time Spent:** 8 minutes

**How Overcome:** Source code inspection and Node.js friction log reference

---

### Step 9: Status Code Mapping

**Action:** Interpret payment response status codes

**Friction:**
- **Issue:** Status returned as integer (e.g., 8)
- **Discovery:** Status codes follow protobuf enum values

**Resolution:**
```python
def map_status(status: int) -> str:
    status_map = {
        0: "PENDING",
        1: "PROCESSING", 
        2: "SUCCESS",
        3: "FAILED",
        4: "CANCELLED",
        5: "AUTHORIZED",
        6: "CAPTURED",
        7: "REFUNDED",
        8: "CHARGED",
    }
    return status_map.get(status, f"UNKNOWN({status})")
```

**Time Spent:** 5 minutes

**How Overcome:** Referenced Node.js implementation

---

### Step 10: FastAPI Integration

**Action:** Integrate with FastAPI framework

**Friction:**
- **Issue:** Pydantic models vs SDK types
- **Decision:** Use Pydantic for API validation, convert to SDK types internally
- **Benefit:** Clean API contract with proper validation

**Resolution:**
```python
class AuthorizeRequest(BaseModel):
    merchant_transaction_id: str
    amount: float
    currency: str = Field(pattern="^(USD|EUR)$")
    card_number: str
    # ... etc

@app.post("/authorize")
async def authorize_payment(request: AuthorizeRequest):
    # Convert Pydantic model to SDK request format
    authorize_request = {
        "merchantTransactionId": request.merchant_transaction_id,
        # ... etc
    }
```

**Time Spent:** 10 minutes

**How Overcome:** Standard FastAPI patterns

---

## Assumptions Made and How Overcome

### Assumption 1: Import Path
**Assumed:** `from hs_paylib import ...`  
**Reality:** `from payments import ...`  
**Overcome:** Package structure inspection

### Assumption 2: Configuration Format
**Assumed:** Plain Python dictionaries  
**Reality:** Must use SDK type constructors (types.ConnectorConfig)  
**Overcome:** Source code inspection

### Assumption 3: Currency Representation
**Assumed:** String values ("USD", "EUR")  
**Reality:** Protobuf enum integers (146, etc.)  
**Overcome:** Runtime inspection

### Assumption 4: Field Naming
**Assumed:** camelCase (Python convention)  
**Reality:** snake_case for FFI compatibility  
**Overcome:** Error-driven discovery

### Assumption 5: Request Structure
**Assumed:** Flexible structure  
**Reality:** Strict protobuf schema  
**Overcome:** Source code inspection

---

## Connector-Specific Findings

### Stripe (USD)
- ✅ Simple configuration (just apiKey)
- ✅ Works without browser_info
- ✅ Clear transaction IDs (pi_* format)
- ⚠️ Requires careful field nesting

### Adyen (EUR)
- ⚠️ Requires extensive browser_info
- ⚠️ Field naming very strict
- ⚠️ 3D Secure compliance mandatory
- ✅ Returns structured error messages

---

## Files Delivered

1. **main.py** - FastAPI server with USD/EUR routing
2. **test.py** - Automated test suite
3. **test-payment.sh** - Quick payment test script
4. **requirements.txt** - Python dependencies
5. **.env** - Configuration with credentials
6. **.env.example** - Configuration template
7. **.gitignore** - Git ignore patterns
8. **README.md** - Server documentation
9. **FRICTION_LOG.md** - This document

---

## Time Breakdown

| Activity | Time |
|----------|------|
| Initial setup & environment | 5 min |
| SDK exploration & imports | 15 min |
| Configuration & client setup | 15 min |
| Currency/Connector enum discovery | 10 min |
| Stripe integration (USD) | 15 min |
| Adyen integration (EUR) | 25 min |
| Refund implementation | 10 min |
| FastAPI integration | 15 min |
| Testing & debugging | 15 min |
| Documentation | 15 min |
| **Total** | **160 min (2h 40m)** |

---

## Comparison with Node.js Integration

| Aspect | Python | Node.js | Notes |
|--------|--------|---------|-------|
| Installation | pip install | npm install | Both straightforward |
| Import clarity | Less clear | Clear | Python package naming confusing |
| Type system | Better (Pydantic) | Basic | Python wins on API validation |
| Documentation | Sparse | Sparse | Both need improvement |
| Error messages | Similar | Similar | Generic error codes |
| Performance | Good | Good | Both use Rust FFI |

---

## Conclusion

The `hs-paylib` Python SDK provides the same core payment orchestration capabilities as the Node.js version, but with similar documentation gaps. The Python SDK benefits from Python's type system (when combined with Pydantic) for better API contract validation.

### Critical Improvements Needed:

1. **Complete Python SDK documentation** with import examples
2. **Enum access patterns** clearly documented
3. **Field naming conventions** specified
4. **FastAPI/Flask integration examples**
5. **Better error messages** with field paths

Despite friction points, the SDK enables multi-connector payments with a unified API, which is valuable for payment orchestration use cases.
