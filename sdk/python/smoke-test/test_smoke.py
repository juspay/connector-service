"""
Smoke test for the packed hyperswitch-payments wheel.

Run via `make test-pack` — the Makefile installs the wheel into a temp
directory, copies this script there, and runs it in-place so imports
resolve against the installed package.
"""

import json
import os

from payments import (
    ConnectorClient,
    PaymentServiceAuthorizeRequest,
    PaymentServiceAuthorizeResponse,
    PaymentAddress,
    USD,
    AUTOMATIC,
    NO_THREE_DS,
    Connector,
    Environment,
    ClientConfig,
    PaymentStatus
)

print(f"Loaded payments package from: {__file__}")
print(f"  ConnectorClient: {ConnectorClient}")

# Real Stripe test key provided by user for verification
api_key = "sk_test_placeholder"

metadata = {
    "x-connector": "Stripe",
    "x-merchant-id": "test_merchant_123",
    "x-request-id": "test-pack-001",
    "x-tenant-id": "public",
    "x-auth": "body-key",
    "x-api-key": api_key,
}

# 1. Initialize Client with new "Blueprint" pattern
config = ClientConfig(
    connector=Connector.STRIPE,
    environment=Environment.SANDBOX
)
# Set Stripe API key surgically via the typed auth oneof
config.auth.stripe.api_key.value = api_key

client = ConnectorClient(config)

# 2. Build a domain protobuf request
print("\n--- Step 1: Building Authorize Request ---")
req = PaymentServiceAuthorizeRequest()
req.merchant_transaction_id.id = "test_py_stripe_" + str(os.getpid())
req.amount.minor_amount = 1000 # $10.00
req.amount.currency = USD
req.capture_method = AUTOMATIC
card = req.payment_method.card
card.card_number.value = "4242424242424242"
card.card_exp_month.value = "12"
card.card_exp_year.value = "2050"
card.card_cvc.value = "123"
card.card_holder_name.value = "Stripe Test User"
req.customer.email.value = "test@example.com"
req.customer.name = "Test"
req.auth_type = NO_THREE_DS
req.return_url = "https://example.com/return"
req.webhook_url = "https://example.com/webhook"
req.test_mode = True

# --- Test: Full round-trip via ConnectorClient ---
print("\n=== Test: Stripe Authorize Round-Trip ===")
try:
    response = client.authorize(req, metadata)
    
    # Display human-readable status and wire number
    status_name = PaymentStatus.Name(response.status)
    print(f"  Payment status: {status_name} ({response.status})")
    print(f"  Connector Transaction ID: {response.connector_transaction_id}")
    print("  PASSED")
except Exception as e:
    print(f"  Error during round-trip: {e}")
    # If it's a 401/403 from Stripe, the round-trip still technically "worked" (reached gateway)
    print("  FAILED (Check if API key is valid)")
    exit(1)

print("\nAll Python checks passed.")
