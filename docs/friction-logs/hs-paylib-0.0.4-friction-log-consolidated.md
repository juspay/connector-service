# hs-paylib — Consolidated Friction Log

**Library:** hs-paylib v0.0.4  
**Date:** 2026-04-08  
**Sources:** 4 independent integrations (3 AI agents, 1 human developer) across macOS and Linux  

| Integrator | Platform | Server Framework | Log Path |
|-----------|----------|-----------------|----------|
| AI Agent (OpenCode / claude-sonnet-4-5) | macOS | http.server | `/Users/gopikrishna.c/github/payment-router/FRICTION_LOG.md` |
| AI Agent (Claude) | macOS | FastAPI | `/Users/uzair.khan/hs-paylib-server/FRICTION_LOG.md` |
| AI Agent (Claude Code) | macOS | FastAPI | `/Users/amitsingh.tanwar/Documents/hs-paylib-server-app` |
| Human Developer | Linux x86_64 | FastAPI | `/home/grace/test-prism/FRICTION_LOG.md` |

---

## Executive Summary

All 4 integrations eventually succeeded. Every single one hit the same core friction points independently, which confirms these are real, reproducible issues — not one-off mistakes. The most damaging issues were the **README describing an API that does not exist** and **integer status codes with no helper to decode them**.

**Total friction time across all integrators: ~230 minutes** that would have been zero with correct documentation and minor SDK fixes.

---

## Consolidated Friction Points

Issues are grouped by pattern. Frequency = how many of the 4 integrators hit it.

---

### PATTERN 1 — README documents a fake API
**Frequency: 3/4 integrators | Criticality: CRITICAL**

The PyPI README Quick Start shows a dict-based API with camelCase keys and a `types` module:

```python
# What the README shows — does NOT work:
from payments import PaymentClient, types

stripe_config: types.ConnectorConfig = {
    "connectorConfig": {
        "stripe": {"apiKey": {"value": "sk_test_..."}}
    }
}
client = PaymentClient(stripe_config)
```

The actual installed package requires protobuf objects with snake_case field names:

```python
# What actually works:
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

Differences between README and reality:
- `types` module does not exist
- `PaymentClient` does not accept a dict
- Field names are camelCase in README (`apiKey`, `connectorConfig`) but snake_case in proto (`api_key`, `connector_config`)
- `response.status` implies string in README — actually returns an integer

**Integrator experiences:**
- OpenCode: ~5 min wasted hitting `TypeError` before switching to proto introspection
- Uzair: ~15 min wasted; noted README describes "a planned higher-level API that is not yet implemented"
- Linux integrator: ~15 min wasted; confirmed "`PaymentClient` constructor only accepts protobuf `ConnectorConfig`"
- Amit: ~20 min wasted trying `payment_pb2.Secret(value=api_key)` (class doesn't exist) before finding `ParseDict`

---

### PATTERN 2 — Integer status codes with no decoder
**Frequency: 4/4 integrators | Criticality: HIGH**

`response.status` returns a raw protobuf enum integer. There is no `.status_name` property, no string representation, and no helper.

```python
resp = await client.authorize(req)
print(resp.status)   # prints: 8
# 8 means CHARGED — but you have to know that
```

All 4 integrators assumed status would be a string and wrote comparisons like `resp.status == "CHARGED"` which silently fail (always `False`).

Correct approach requires knowing to use:
```python
payment_pb2.PaymentStatus.Name(resp.status)   # for authorize responses
payment_pb2.RefundStatus.Name(resp.status)    # for refund responses
```

Time wasted: ~10–20 min per integrator. The Uzair log also noted hitting a Pydantic `ValidationError` because a downstream model expected a string and got an int.

---

### PATTERN 3 — PaymentStatus vs RefundStatus enum collision
**Frequency: 3/4 integrators | Criticality: HIGH**

`PaymentStatus` and `RefundStatus` are two separate enums that share integer values with different meanings:

| Integer | PaymentStatus name | RefundStatus name |
|---------|-------------------|-------------------|
| 3 | `ROUTER_DECLINED` | `REFUND_PENDING` |
| 4 | `AUTHENTICATION_PENDING` | `REFUND_SUCCESS` |

`RefundResponse.status` uses `RefundStatus`. `PaymentServiceAuthorizeResponse.status` uses `PaymentStatus`. There is no indication on the response object which enum applies.

A developer who uses `PaymentStatus.Name()` on a refund response will see `AUTHENTICATION_PENDING` for a successful refund — which is actively misleading. The Uzair log described iterating through `AuthorizationStatus`, `PaymentStatus`, `OperationStatus`, and `RefundStatus` to figure out which one mapped `8` correctly.

The Linux integrator noted the SDK also exports `AuthorizationStatus` with values like `AUTHORIZATION_SUCCESS = 1` — which a developer would naturally reach for first when reading authorize response status. It is the wrong enum.

---

### PATTERN 4 — Adyen refund reason: no normalization, silent connector leak
**Frequency: 4/4 integrators | Criticality: HIGH**

The `reason` field on refund requests is passed verbatim to the connector. Adyen only accepts:
`OTHER`, `RETURN`, `DUPLICATE`, `FRAUD`, `CUSTOMER REQUEST`

The auto-generated example in `adyen.py` uses `"customer_request"` (snake_case) which **fails at runtime** with a 422 from Adyen. Every integrator used this value and hit the error.

```
ConnectorError: Invalid merchant refund reason, the only valid values are:
[OTHER, RETURN, DUPLICATE, FRAUD, CUSTOMER REQUEST]
```

Stripe accepts freeform strings so this only surfaces when testing Adyen. The Amit log documented adding a manual mapping layer as the workaround.

---

### PATTERN 5 — Credential structure undocumented
**Frequency: 3/4 integrators | Criticality: MEDIUM**

There is no documentation mapping the fields in `creds.json` to the protobuf config field names. Specifically:

- `key1` in creds.json → `merchant_account` in `AdyenConfig` (undocumented)
- `api_secret` in creds.json for Adyen → not used at all for payment operations (undocumented)
- `auth_type` field in creds.json → no corresponding proto field (library handles auth internally)
- `SecretString` must wrap credentials — passing a plain `str` gives a cryptic proto type error

All three integrators who hit this used `DESCRIPTOR.fields` introspection as the workaround. The Uzair log noted discovering through trial and error that `key1` is the merchant account.

---

### PATTERN 6 — Linux: no .so binary shipped in wheel
**Frequency: 1/4 integrators (Linux only) | Criticality: CRITICAL for Linux**

The PyPI wheel ships only `libconnector_service_ffi.dylib` (macOS ARM64). On Linux, the FFI loader looks for `libconnector_service_ffi.so` which does not exist. The package is completely non-functional on Linux out of the box.

```
OSError: libconnector_service_ffi.so: cannot open shared object file: No such file or directory
```

The Linux integrator resolved this by manually copying a locally-built `.so` from a Rust source build. A typical user without access to the Rust source would be completely blocked. Note: the debug build also fails due to missing UniFFI symbols — only the release build works.

---

### PATTERN 7 — protobuf not declared as a dependency
**Frequency: 1/4 integrators | Criticality: HIGH**

The package uses `google.protobuf` internally but only declares `httpx[http2]>=0.27.0` in its dependencies. On a clean environment without protobuf pre-installed:

```
ModuleNotFoundError: No module named 'google'
```

The other 3 integrators had protobuf already installed from other packages so didn't hit this — but on a clean venv it is an immediate failure.

---

### PATTERN 8 — protobuf.error object not JSON-serializable
**Frequency: 1/4 integrators | Criticality: MEDIUM**

`response.error` is a protobuf message object, not a Python string or dict. Passing it directly to a JSON serializer (FastAPI, `json.dumps`) raises a `TypeError`. No `.to_dict()` or `.to_json()` helper is provided on response objects.

The Linux integrator used `str(response.error)` as a workaround.

---

### PATTERN 9 — Python version incompatibility undocumented
**Frequency: 1/4 integrators | Criticality: MEDIUM**

Package is silently incompatible with Python 3.14. The Amit log documented 15 minutes lost because the system's default `python3` was 3.14, but hs-paylib was installed under Python 3.9. `ModuleNotFoundError: No module named 'payments'` with no version hint in the error.

---

### PATTERN 10 — Expired Stripe API key in creds.json with no label
**Frequency: 1/4 integrators | Criticality: LOW**

The `creds.json` contains two Stripe credential sets (`connector_1`, `connector_2`). `connector_1` has an expired key. There is no label, comment, or documentation indicating which is current.

```
ConnectorError: Expired API Key provided: sk_test_...3hm
```

---

### PATTERN 11 — browser_info required for Adyen, undocumented
**Frequency: 3/4 integrators (noted) | Criticality: MEDIUM**

Adyen authorize requests require a `browser_info` field. Stripe does not. This requirement is not documented anywhere — discoverable only by comparing the `stripe.py` and `adyen.py` example files side by side. No SDK-level validation raises a clear error if it is missing.

---

## Time Lost Per Integrator

| Integrator | Total friction time | Total integration time |
|-----------|--------------------|-----------------------|
| OpenCode (ours) | ~45 min | ~75 min |
| Uzair | ~75 min | ~120 min |
| Amit | ~72 min | ~240 min |
| Linux (Grace) | ~55 min | ~90 min |
| **Combined** | **~247 min** | **~525 min** |

Without any of these friction points, a clean integration should take ~30–45 minutes.

---

## Friction Frequency Matrix

| Issue | OpenCode | Uzair | Amit | Grace (Linux) | Count |
|-------|----------|-------|------|---------------|-------|
| README fake API | ✅ | ✅ | ✅ | ✅ | 4/4 |
| Integer status codes | ✅ | ✅ | ✅ | ✅ | 4/4 |
| PaymentStatus vs RefundStatus collision | ✅ | ✅ | — | ✅ | 3/4 |
| Adyen refund reason | ✅ | ✅ | ✅ | ✅ | 4/4 |
| Credential structure undocumented | ✅ | ✅ | ✅ | — | 3/4 |
| No Linux .so binary | — | — | — | ✅ | 1/4 |
| protobuf not in dependencies | — | — | — | ✅ | 1/4 |
| error object not serializable | — | — | — | ✅ | 1/4 |
| Python version undocumented | — | — | ✅ | — | 1/4 |
| Expired key in creds.json | — | — | — | ✅ | 1/4 |
| browser_info undocumented | ✅ | ✅ | — | ✅ | 3/4 |
