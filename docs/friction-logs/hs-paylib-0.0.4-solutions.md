# hs-paylib — Consolidated Solutions & Recommendations

**Based on:** 4 independent integrations (consolidated friction log)  
**Date:** 2026-04-08  

Each solution states exactly what to change, where, and what it fixes. Ordered by impact.

---

## S1 — Fix the README Quick Start to show the real API
**Fixes:** Pattern 1 (4/4 integrators, ~5–20 min wasted each)  
**Effort:** Low — documentation only  
**Where:** `pyproject.toml` / `README.md` (the `long_description` that appears on PyPI)

### What is wrong now

The current README shows:
```python
from payments import PaymentClient, types

stripe_config: types.ConnectorConfig = {
    "connectorConfig": {
        "stripe": {"apiKey": {"value": os.environ["STRIPE_API_KEY"]}}
    }
}
client = PaymentClient(stripe_config, request_config)
response = client.authorize(authorize_request)
print(f"Status: {response.status}")  # implies string
```

None of this works. `types` does not exist. `PaymentClient` does not accept a dict. Field names are camelCase in docs but snake_case in reality. `response.status` is an int.

### What to replace it with

```python
import asyncio
from payments import PaymentClient, SecretString
from payments.generated import sdk_config_pb2, payment_pb2
from google.protobuf.json_format import ParseDict

# 1. Build connector config
cfg = sdk_config_pb2.ConnectorConfig(
    options=sdk_config_pb2.SdkOptions(environment=sdk_config_pb2.Environment.SANDBOX)
)
cfg.connector_config.CopyFrom(payment_pb2.ConnectorSpecificConfig(
    stripe=payment_pb2.StripeConfig(
        api_key=SecretString(value="sk_test_YOUR_KEY_HERE")
    )
))

# 2. Build authorize request
req = ParseDict(
    {
        "merchant_transaction_id": "txn_001",
        "amount": {"minor_amount": 1000, "currency": "USD"},
        "payment_method": {
            "card": {
                "card_number": {"value": "4111111111111111"},
                "card_exp_month": {"value": "03"},
                "card_exp_year": {"value": "2030"},
                "card_cvc": {"value": "737"},
                "card_holder_name": {"value": "John Doe"}
            }
        },
        "capture_method": "AUTOMATIC",
        "address": {"billing_address": {}},
        "auth_type": "NO_THREE_DS",
        "return_url": "https://example.com/return"
    },
    payment_pb2.PaymentServiceAuthorizeRequest()
)

# 3. Execute and read status
async def run():
    client = PaymentClient(cfg)
    resp = await client.authorize(req)
    # resp.status is an int — convert to name:
    print(payment_pb2.PaymentStatus.Name(resp.status))  # e.g. "CHARGED"
    print(resp.connector_transaction_id)

asyncio.run(run())
```

Also add a note at the top of the README:

> **Note:** All field names use `snake_case`. Credentials must be wrapped in `SecretString(value=...)`. `response.status` returns a protobuf integer — use `PaymentStatus.Name(resp.status)` to get the string name.

---

## S2 — Add `status_name` property to all response types
**Fixes:** Pattern 2 (4/4 integrators) and Pattern 3 (3/4 integrators)  
**Effort:** Medium — SDK change  
**Where:** `payments/connector_client.py` or a response wrapper class

Every integrator wasted time because `resp.status` returns an integer and there is no helper. The additional problem is that `PaymentStatus` and `RefundStatus` are different enums with colliding integer values — so even a developer who knows to call `.Name()` will get the wrong answer if they use the wrong enum.

### What to add

In the Python layer, wrap the raw protobuf response to expose a `status_name` property that uses the correct enum for each response type:

```python
# In connector_client.py or a response_types.py wrapper:

from payments.generated import payment_pb2

class AuthorizeResponse:
    def __init__(self, proto_resp):
        self._resp = proto_resp

    @property
    def status(self) -> int:
        return self._resp.status

    @property
    def status_name(self) -> str:
        return payment_pb2.PaymentStatus.Name(self._resp.status)

    @property
    def connector_transaction_id(self) -> str:
        return self._resp.connector_transaction_id


class RefundResponse:
    def __init__(self, proto_resp):
        self._resp = proto_resp

    @property
    def status(self) -> int:
        return self._resp.status

    @property
    def status_name(self) -> str:
        return payment_pb2.RefundStatus.Name(self._resp.status)
```

Then integrators can write:
```python
resp = await client.authorize(req)
print(resp.status_name)   # "CHARGED" — no enum lookup needed

rresp = await client.refund(req)
print(rresp.status_name)  # "REFUND_SUCCESS" — uses RefundStatus, not PaymentStatus
```

Also document in the README which enum each response uses:

| Response type | Status enum |
|--------------|-------------|
| `PaymentServiceAuthorizeResponse` | `PaymentStatus` |
| `PaymentServiceCaptureResponse` | `PaymentStatus` |
| `PaymentServiceVoidResponse` | `PaymentStatus` |
| `RefundResponse` | `RefundStatus` |

---

## S3 — Normalize refund reason values in the SDK
**Fixes:** Pattern 4 (4/4 integrators)  
**Effort:** Low — one function, one place  
**Where:** The refund transformer for Adyen (`crates/` or the Python HTTP client layer)

### What is wrong now

The auto-generated `adyen.py` example uses `"customer_request"` as the refund reason. This value is rejected by Adyen at runtime with a 422. Every integrator hit this.

### Option A — Normalize in the SDK (recommended)

Add a normalization step before sending to Adyen. Map common snake_case inputs to the values Adyen accepts:

```python
_ADYEN_REASON_MAP = {
    "customer_request": "CUSTOMER REQUEST",
    "fraud":            "FRAUD",
    "duplicate":        "DUPLICATE",
    "return":           "RETURN",
    "other":            "OTHER",
}

def _normalize_adyen_reason(reason: str) -> str:
    return _ADYEN_REASON_MAP.get(reason.lower().replace(" ", "_"), reason)
```

### Option B — Fix the generated example (minimum fix)

Change `adyen.py` example from:
```python
"reason": "customer_request"
```
to:
```python
"reason": "CUSTOMER REQUEST"
```

### Option C — Add SDK-level validation

Raise a clear error before the HTTP call:
```python
ADYEN_VALID_REASONS = {"OTHER", "RETURN", "DUPLICATE", "FRAUD", "CUSTOMER REQUEST"}

if connector == "adyen" and reason not in ADYEN_VALID_REASONS:
    raise IntegrationError(
        f"Invalid Adyen refund reason '{reason}'. "
        f"Valid values: {sorted(ADYEN_VALID_REASONS)}"
    )
```

---

## S4 — Declare `protobuf` as a package dependency
**Fixes:** Pattern 7 (hits on clean environments)  
**Effort:** Trivial — one line  
**Where:** `pyproject.toml`

### What to change

```toml
# Current:
dependencies = ["httpx[http2]>=0.27.0"]

# Fixed:
dependencies = [
    "httpx[http2]>=0.27.0",
    "protobuf>=5.0.0",
]
```

Without this, anyone installing in a clean venv gets `ModuleNotFoundError: No module named 'google'` immediately after install. The package is broken on first use.

---

## S5 — Ship Linux x86_64 binary in the PyPI wheel
**Fixes:** Pattern 6 (blocks all Linux deployments)  
**Effort:** High — CI/build change  
**Where:** Build pipeline / GitHub Actions release workflow

The package currently ships only `libconnector_service_ffi.dylib` (macOS ARM64). Payment servers run on Linux in production. The wheel must include pre-built `.so` binaries for:

- `linux/x86_64` — `libconnector_service_ffi.so` (most common server target)
- `linux/aarch64` — for ARM-based cloud instances

Use `manylinux` wheels (`manylinux2014_x86_64`) so the binary is portable across Linux distributions:

```
hs_paylib-0.0.4-cp39-cp39-manylinux_2_17_x86_64.manylinux2014_x86_64.whl
hs_paylib-0.0.4-cp39-cp39-macosx_11_0_arm64.whl
```

Until then, the package description should clearly state: **"Currently only supports macOS. Linux support coming soon."**

---

## S6 — Document credential structure and field mapping
**Fixes:** Pattern 5 (3/4 integrators, ~8–15 min wasted each)  
**Effort:** Low — documentation only  
**Where:** README, or a `CREDENTIALS.md` section

Add a section to the README that shows exactly how to construct each connector config from raw API credentials:

```markdown
## Credential Setup

### Stripe
```python
from payments import SecretString
from payments.generated import sdk_config_pb2, payment_pb2

cfg = sdk_config_pb2.ConnectorConfig(
    options=sdk_config_pb2.SdkOptions(environment=sdk_config_pb2.Environment.SANDBOX)
)
cfg.connector_config.CopyFrom(payment_pb2.ConnectorSpecificConfig(
    stripe=payment_pb2.StripeConfig(
        api_key=SecretString(value="sk_test_...")   # your Stripe secret key
    )
))
```

### Adyen
```python
cfg.connector_config.CopyFrom(payment_pb2.ConnectorSpecificConfig(
    adyen=payment_pb2.AdyenConfig(
        api_key=SecretString(value="AQEq..."),          # X-API-Key header value
        merchant_account=SecretString(value="YourECOM") # Adyen merchant account name
        # Note: api_secret / review_key are not needed for basic payment operations
    )
))
```

Also document:
- `SecretString` is a protobuf message — use `SecretString(value="...")` not a plain string
- The `key1` field in connector-service `creds.json` maps to `merchant_account` for Adyen
- `api_secret` in `creds.json` is not used for Adyen payment/refund operations

---

## S7 — Document Adyen browser_info requirement
**Fixes:** Pattern 11 (3/4 integrators)  
**Effort:** Low — documentation + optional SDK validation  
**Where:** README connector-specific section, and optionally adyen transformer

Add to the README under an "Adyen-specific requirements" section:

```markdown
## Connector-specific requirements

### Adyen
Adyen authorize requests require a `browser_info` field:

```python
"browser_info": {
    "color_depth": 24,
    "screen_height": 900,
    "screen_width": 1440,
    "java_enabled": False,
    "java_script_enabled": True,
    "language": "en-US",
    "time_zone_offset_minutes": -480,
    "accept_header": "application/json",
    "user_agent": "Mozilla/5.0 ...",
    "accept_language": "en-US,en;q=0.9",
    "ip_address": "1.2.3.4"
}
```

This field is optional for Stripe and other connectors.
```

---

## S8 — Fix error object serialization
**Fixes:** Pattern 8  
**Effort:** Low — SDK change  
**Where:** `payments/connector_client.py` — `ConnectorError` class

The `response.error` field is a protobuf message, not serializable by `json.dumps` or FastAPI. Add a `__str__` or conversion helper:

```python
from google.protobuf.json_format import MessageToDict

class ConnectorError(Exception):
    def to_dict(self) -> dict:
        return MessageToDict(self.connector_error)

    def __str__(self) -> str:
        return str(MessageToDict(self.connector_error))
```

Also on response objects, expose `error` as a dict or string rather than a raw proto message.

---

## S9 — Document Python version support explicitly
**Fixes:** Pattern 9  
**Effort:** Trivial  
**Where:** README, `pyproject.toml`

In `pyproject.toml`:
```toml
requires-python = ">=3.9,<3.14"
```

In README:
```markdown
**Requirements:** Python 3.9 – 3.13. Python 3.14+ is not yet supported.
```

---

## Summary Table

| # | Solution | Fixes Patterns | Integrators Affected | Effort |
|---|---------|---------------|---------------------|--------|
| S1 | Fix README Quick Start | 1 | 4/4 | Low |
| S2 | Add `status_name` property | 2, 3 | 4/4 | Medium |
| S3 | Normalize Adyen refund reason | 4 | 4/4 | Low |
| S4 | Declare protobuf dependency | 7 | All clean envs | Trivial |
| S5 | Ship Linux .so binary | 6 | All Linux users | High |
| S6 | Document credential structure | 5 | 3/4 | Low |
| S7 | Document Adyen browser_info | 11 | 3/4 | Low |
| S8 | Fix error serialization | 8 | FastAPI users | Low |
| S9 | Document Python version | 9 | 1/4 | Trivial |

**S1 through S4 together would eliminate ~80% of the total friction time across all integrators.**
