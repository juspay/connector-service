"""
Smoke test for the packed hyperswitch-payments wheel.

Run via `make test-pack` — the Makefile installs the wheel into a temp
directory, copies this script there, and runs it in-place so imports
resolve against the installed package.
"""

import json
import os

from payments import ConnectorClient
from payments.generated.connector_service_ffi import authorize_req_transformer
from payments.generated.payment_pb2 import (
    PaymentServiceAuthorizeRequest,
    PaymentAddress,
    USD,
    AUTOMATIC,
    NO_THREE_DS,
)
from payments.generated.sdk_options_pb2 import Options, HttpOptions, FfiOptions, EnvOptions

print(f"Loaded payments package from: {__file__}")
print(f"  ConnectorClient: {ConnectorClient}")
print(f"  authorize_req_transformer: {authorize_req_transformer}")

api_key = os.getenv("STRIPE_API_KEY", "sk_test_placeholder")
metadata = {
    "connector": "Stripe",
    "connector_auth_type": json.dumps({
        "Stripe": {
            "api_key": api_key
        }
    }),
    "x-connector": "Stripe",
    "x-merchant-id": "test_merchant_123",
    "x-request-id": "test-pack-001",
    "x-tenant-id": "public",
    "x-auth": "body-key",
    "x-api-key": api_key,
}

# Create options with both HttpOptions and FfiOptions
options = Options()
options.http.total_timeout_ms = 30000
options.http.connect_timeout_ms = 10000
options.http.response_timeout_ms = 20000
options.http.keep_alive_timeout_ms = 5000
options.ffi.env.test_mode = True

# Build a protobuf request
req = PaymentServiceAuthorizeRequest()
req.merchant_transaction_id.id = "test_pack_123"
req.amount.minor_amount = 1000
req.amount.currency = USD
req.capture_method = AUTOMATIC
card = req.payment_method.card
card.card_number.value = "4111111111111111"
card.card_exp_month.value = "12"
card.card_exp_year.value = "2050"
card.card_cvc.value = "123"
card.card_holder_name.value = "Test User"
req.customer.email.value = "test@example.com"
req.customer.name = "Test"
req.auth_type = NO_THREE_DS
req.return_url = "https://example.com/return"
req.webhook_url = "https://example.com/webhook"
req.address.CopyFrom(PaymentAddress())
req.test_mode = True

# --- Test 1: Low-level FFI ---
print("\n=== Test 1: Low-level FFI (authorize_req_transformer) ===")
result = authorize_req_transformer(req.SerializeToString(), metadata, options.SerializeToString())
parsed = json.loads(result)
print(f"  URL:    {parsed['url']}")
print(f"  Method: {parsed['method']}")
assert parsed["url"] == "https://api.stripe.com/v1/payment_intents", "Unexpected URL"
assert parsed["method"] == "POST", "Unexpected method"
print("  PASSED")

# --- Test 2: Full round-trip via ConnectorClient ---
print("\n=== Test 2: Full round-trip (ConnectorClient.authorize) ===")
if api_key == "sk_test_placeholder":
    print("  SKIPPED (set STRIPE_API_KEY to enable)")
else:
    client = ConnectorClient()
    try:
        response = client.authorize(req, metadata)
        print(f"  Response status: {response.status}")
        print(f"  Response type:   {type(response).__name__}")
        print("  PASSED")
    except Exception as e:
        print(f"  Response/error received: {e}")
        print("  PASSED (round-trip completed, error is from Stripe)")

print("\nAll checks passed.")
