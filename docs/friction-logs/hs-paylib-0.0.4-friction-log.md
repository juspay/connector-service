# Friction Log: hs-paylib Integration (Stripe + Adyen)

**Date:** 2026-04-08  
**Library:** [hs-paylib 0.0.4](https://pypi.org/project/hs-paylib/0.0.4/)  
**Goal:** Build a Python server routing USD → Stripe, EUR → Adyen with authorize + refund support.  
**Integrator profile:** AI agent (OpenCode / claude-sonnet-4-5)

---

## Executive Summary

The library works end-to-end and successfully routes payments to Stripe and Adyen. However, the integration experience had **five distinct friction clusters** that collectively wasted significant time and would block or confuse most integrators — human or AI:

| # | Friction Pattern | Criticality |
|---|-----------------|-------------|
| 1 | **README documents a dict-based API that does not exist** — actual API is proto-based | HIGH |
| 2 | **Proto enum integers** returned from SDK instead of human-readable strings | HIGH |
| 3 | **Adyen refund reason** silently breaks with `snake_case` values | HIGH |
| 4 | **Credential structure not documented** — guessable only via proto introspection or example files | MEDIUM |
| 5 | **Mixed enum namespaces** for status decoding (PaymentStatus vs RefundStatus) | MEDIUM |

---

## Recommendations

| Priority | Recommendation |
|----------|---------------|
| **CRITICAL** | Fix the README / PyPI `METADATA` to show the actual proto-based API. The current Quick Start shows a dict-based `{"connectorConfig": {"stripe": ...}}` API and a `types` module that do not exist in the installed package. Any integrator starting from the docs will immediately hit `TypeError` or `ImportError`. |
| **HIGH** | SDK clients should return human-readable status strings (or named enum objects), not raw protobuf integers. The integer `8` is meaningless without cross-referencing the proto descriptor. |
| **HIGH** | Document connector-specific field requirements (e.g. Adyen `reason` valid values) in one place — not buried in connector API docs. Include in the SDK's own docstrings or type annotations. |
| **MEDIUM** | Provide a `ConnectorConfig` factory / builder per connector: `StripeConfig.from_api_key(key)`, `AdyenConfig.from_creds(key, merchant)`. Current API requires deep knowledge of proto nesting. |
| **MEDIUM** | `PaymentStatus` and `RefundStatus` are two separate enums sharing integer space. Document which response type carries which enum, or unify into a single `OperationStatus`. |
| **LOW** | Publish pip-installable example scripts or a `quickstart.py` that demonstrates authorize + refund end-to-end for at least Stripe and Adyen. |

---

## Step-by-Step Integration Log

### Step 1 — Discover the library (friction: HIGH)

**Action:** Navigate to `https://pypi.org/project/hs-paylib/0.0.4/` and read the README to understand the API.  
**Outcome:** The PyPI README documents a **dict-based API and a `types` module that do not exist** in the installed package. Specifically:

```python
# README says this works — it does not:
from payments import PaymentClient, types

stripe_config: types.ConnectorConfig = {      # types module doesn't exist
    "connectorConfig": {                       # dict config doesn't work
        "stripe": {
            "apiKey": {"value": "sk_test_..."}
        }
    }
}
client = PaymentClient(stripe_config)
response = client.authorize(request_dict)
print(response.status)  # README implies string — actually returns int
```

The actual API is proto-based and requires:
```python
from payments import PaymentClient, SecretString
from payments.generated import sdk_config_pb2, payment_pb2

cfg = sdk_config_pb2.ConnectorConfig(
    options=sdk_config_pb2.SdkOptions(environment=sdk_config_pb2.Environment.SANDBOX)
)
cfg.connector_config.CopyFrom(payment_pb2.ConnectorSpecificConfig(
    stripe=payment_pb2.StripeConfig(api_key=SecretString(value="sk_test_..."))
))
client = PaymentClient(cfg)
```

**Time wasted:** ~5 minutes attempting to use the documented dict-based API before hitting `TypeError`, then switching to proto introspection.  
**Resolution:** Used `python3 -c "import payments; print(dir(payments))"` and `DESCRIPTOR.fields` introspection to discover the real proto structure. Also consulted GitHub examples at `https://github.com/juspay/hyperswitch-prism/tree/main/examples`.  
**Assumption:** Library is the Python SDK for the Hyperswitch UCS connector-service, using protobuf for serialization and httpx for HTTP transport.

---

### Step 2 — Install and explore the package (friction: LOW)

**Action:** `pip install hs-paylib==0.0.4`  
**Outcome:** Clean install. All transitive deps (httpx, protobuf) already satisfied.  
**Time wasted:** 0 minutes.  
**Notes:** Installation itself is smooth. The package name `hs-paylib` installs as `payments` module — a minor naming surprise (install `hs-paylib`, import `payments`).

---

### Step 3 — Understand credential structure (friction: MEDIUM)

**Action:** Read the module to understand how to configure a connector.  
**Outcome:** Module exports `PaymentClient`, `SecretString`, and proto-generated classes. No documentation or docstrings for configuration.  
**Time wasted:** ~10 minutes reverse-engineering the proto descriptor.  
**Resolution:** Used Python introspection (`DESCRIPTOR.fields`) to discover:
```
ConnectorConfig
  └── connector_config: ConnectorSpecificConfig
        ├── stripe: StripeConfig(api_key: SecretString)
        └── adyen: AdyenConfig(api_key: SecretString, merchant_account: SecretString)
  └── options: SdkOptions(environment: Environment.SANDBOX)
```
**Assumption:** `SecretString` wraps a plaintext string with a `value` field. This is a proto message, not a Python `str`. Direct assignment (`api_key="key"`) fails silently or with an unhelpful proto type error.

---

### Step 4 — Build authorize request (friction: LOW)

**Action:** Copy `_build_authorize_request()` from the GitHub example and adapt it.  
**Outcome:** Authorize succeeded for both Stripe and Adyen on first attempt.  
**Notes:** The Adyen example adds `browser_info` to the authorize request. This field is required by Adyen but optional for Stripe. The field was undocumented as a requirement — discovered only by comparing example files.  
**Assumption:** `browser_info` is silently dropped by Stripe, harmlessly included for Adyen.

---

### Step 5 — Interpret authorize response status (friction: HIGH)

**Action:** Check `resp.status` to determine if payment succeeded.  
**Outcome:** `resp.status` is an `int` (e.g. `8`), not a string or named enum.  
**Time wasted:** ~15 minutes. Initial comparison `resp.status == "CHARGED"` always failed. Test showed "FAIL" even though the real payment succeeded at Stripe.  
**Root cause:** `PaymentStatus` is a proto enum. The integer `8` maps to `CHARGED`, but this is non-obvious.  
**Resolution:** Used `payment_pb2.PaymentStatus.Name(resp.status)` for display. Used integer constants (`payment_pb2.CHARGED`) for comparison.  
```python
# Wrong: resp.status == "CHARGED"  → always False
# Right: resp.status == payment_pb2.CHARGED  → works
```
**Assumption:** All payment status comparisons must use integer enum constants from the generated proto module.

---

### Step 6 — Adyen refund reason rejected (friction: HIGH)

**Action:** Attempted refund with `reason: "customer_request"` (snake_case, from Stripe example).  
**Outcome:** Adyen returned `HTTP 422 Unprocessable Entity`:  
```
Invalid merchant refund reason, the only valid values are:
[OTHER, RETURN, DUPLICATE, FRAUD, CUSTOMER REQUEST]
```
**Time wasted:** ~10 minutes. The error came from inside `ConnectorError` via the SDK's error propagation. No SDK-level validation warned about the value before sending.  
**Root cause:** Adyen requires SCREAMING_CASE reason strings. The hs-paylib SDK passes the value through verbatim without normalization.  
**Resolution:** Changed `reason` to `"CUSTOMER REQUEST"` (exact Adyen format). This also works for Stripe (reason field is optional / passed as metadata).  
**Assumption:** The `reason` field is connector-specific. No normalization layer exists in the library.

---

### Step 7 — Refund status decoded via wrong enum (friction: MEDIUM)

**Action:** Display refund response status using `payment_pb2.PaymentStatus.Name(resp.status)`.  
**Outcome:** Refund status `4` displayed as `"AUTHENTICATION_PENDING"` (PaymentStatus value 4) instead of `"REFUND_SUCCESS"` (RefundStatus value 4).  
**Time wasted:** ~5 minutes confusion before noticing the response object is `RefundResponse` (not `PaymentServiceAuthorizeResponse`).  
**Root cause:** `PaymentStatus` and `RefundStatus` are independent enums. Integer `4` means different things in each. `RefundResponse.status` uses `RefundStatus`, not `PaymentStatus`.  
**Resolution:** Used `payment_pb2.RefundStatus.Name(resp.status)` for refund responses.  
**Assumption:** Authorize responses use `PaymentStatus`; refund responses use `RefundStatus`. These must be decoded separately.

---

### Step 8 — Server routing implementation (friction: NONE)

**Action:** Build an `http.server`-based Python server routing by `currency` field.  
**Outcome:** Clean implementation. USD → Stripe config, EUR → Adyen config. Both authorize and refund work via HTTP endpoints.  
**Notes:** Used `asyncio.get_event_loop().run_until_complete()` to bridge sync HTTP handler with async SDK clients.

---

### Step 9 — End-to-end validation (friction: NONE)

**Stripe USD authorize:** `CHARGED` (200 OK, `pi_*`)  
**Stripe USD refund:** `REFUND_SUCCESS` (200 OK, `re_*`)  
**Adyen EUR authorize:** `CHARGED` (200 OK, `*`)  
**Adyen EUR refund:** `REFUND_PENDING` (201 Created — Adyen refunds are async)  

All 4 test cases: **PASS**

---

## Assumptions Log

| # | Assumption | How overcome |
|---|-----------|-------------|
| A1 | `hs-paylib` installs as `payments` module | `python3 -c "import payments"` confirmed |
| A2 | Library uses HTTP/gRPC internally (not direct Stripe/Adyen API) | Confirmed via httpx logs showing direct connector URLs |
| A3 | `SecretString(value=...)` wraps credentials | Proto descriptor inspection |
| A4 | `browser_info` is optional for Stripe but required for Adyen | Confirmed by comparing example files |
| A5 | `resp.status` is an int (proto enum) | Python `type()` introspection |
| A6 | `reason` field is passed verbatim to connector | Adyen 422 error message confirmed |
| A7 | Adyen refunds are async (REFUND_PENDING is success) | HTTP 201 from Adyen docs implies async processing |
| A8 | `RefundResponse.status` uses `RefundStatus` enum, not `PaymentStatus` | Python `type(resp)` + descriptor inspection |

---

## Time Summary

| Activity | Time |
|---------|------|
| README API mismatch (dict vs proto) | 5 min |
| Credential structure reverse-engineering | 10 min |
| Status integer comparison debugging | 15 min |
| Adyen refund reason validation error | 10 min |
| Mixed enum namespace confusion | 5 min |
| **Total friction time** | **~45 min** |
| Actual productive coding time | ~30 min |

Without friction: integration would take ~30 minutes. With friction: ~75 minutes total.
