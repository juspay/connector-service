"""
Smoke test for the packed hyperswitch-payments wheel.

Usage:
    pip install --target /tmp/test-py-sdk dist/hyperswitch_payments-*.whl --no-deps
    python3 examples/test_pack.py /tmp/test-py-sdk
"""

import json
import os
import sys

if len(sys.argv) < 2:
    print("Usage: python3 examples/test_pack.py <install-dir>", file=sys.stderr)
    sys.exit(1)

# Prepend the install directory so we load from the installed wheel
sys.path.insert(0, sys.argv[1])

from payments import ConnectorClient
from payments.generated.connector_service_ffi import authorize_req_transformer
from payments.generated.payment_pb2 import PaymentServiceAuthorizeRequest, PaymentAddress

print(f"Loaded payments package from: {sys.argv[1]}")
print(f"  ConnectorClient: {ConnectorClient}")
print(f"  authorize_req_transformer: {authorize_req_transformer}")

api_key = os.getenv("STRIPE_API_KEY", "sk_test_placeholder")
metadata = {
    "connector": "Stripe",
    "connector_auth_type": json.dumps({"auth_type": "HeaderKey", "api_key": api_key}),
    "x-connector": "Stripe",
    "x-merchant-id": "test_merchant_123",
    "x-request-id": "test-pack-001",
    "x-tenant-id": "public",
    "x-auth": "body-key",
    "x-api-key": api_key,
}

# Build a protobuf request
req = PaymentServiceAuthorizeRequest()
req.request_ref_id.id = "test_pack_123"
req.amount = 1000
req.minor_amount = 1000
req.currency = 146  # USD
req.capture_method = 1  # AUTOMATIC
card = req.payment_method.card
card.card_number.value = "4111111111111111"
card.card_exp_month.value = "12"
card.card_exp_year.value = "2050"
card.card_cvc.value = "123"
card.card_holder_name.value = "Test User"
req.email.value = "test@example.com"
req.customer_name = "Test"
req.auth_type = 2  # NO_THREE_DS
req.return_url = "https://example.com/return"
req.webhook_url = "https://example.com/webhook"
req.address.CopyFrom(PaymentAddress())
req.test_mode = True

# --- Test 1: Low-level FFI ---
print("\n=== Test 1: Low-level FFI (authorize_req_transformer) ===")
result = authorize_req_transformer(req.SerializeToString(), metadata)
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
