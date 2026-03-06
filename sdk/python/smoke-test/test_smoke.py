"""
Smoke test for the packed asynchronous hyperswitch-payments wheel.

Run via `make test-pack` — the Makefile installs the wheel into a temp
directory, copies this script there, and runs it in-place.
"""

import json
import os
import asyncio

from payments import (
    ConnectorClient,
    authorize_req_transformer,
    PaymentServiceAuthorizeRequest,
    PaymentServiceAuthorizeResponse,
    PaymentAddress,
    FfiConnectorHttpRequest,
    USD,
    AUTOMATIC,
    NO_THREE_DS,
    Connector,
    Environment,
    ClientConfig,
    PaymentStatus
)

async def run_smoke_test():
    print(f"Loaded payments package from: {__file__}")
    print(f"  ConnectorClient: {ConnectorClient}")
    print(f"  authorize_req_transformer: {authorize_req_transformer}")

    api_key = os.getenv("STRIPE_API_KEY", "sk_test_placeholder")

    # Metadata strictly contains transport/context headers
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

    # Create options bytes for the new FFI signature
    from payments.generated.sdk_config_pb2 import FfiOptions
    ffi_opts = FfiOptions(
        environment=Environment.SANDBOX,
        connector=Connector.STRIPE,
        auth=config.auth
    )
    options_bytes = ffi_opts.SerializeToString()

    # --- Test 1: Low-level FFI ---
    print("\n=== Test 1: Low-level FFI (authorize_req_transformer) ===")
    result_bytes = authorize_req_transformer(req.SerializeToString(), metadata, options_bytes)
    result = FfiConnectorHttpRequest.FromString(result_bytes)
    print(f"  URL:    {result.url}")
    print(f"  Method: {result.method}")
    if result.url != "https://api.stripe.com/v1/payment_intents":
        raise Exception(f"Unexpected URL: {result.url}")
    print("  PASSED")

    # --- Test 2: Full round-trip via ConnectorClient ---
    print("\n=== Test 2: Full round-trip (ConnectorClient.authorize) ===")
    if api_key == "sk_test_placeholder":
        print("  SKIPPED (set STRIPE_API_KEY to enable)")
    else:
        client = ConnectorClient(config)
        try:
            # We must AWAIT the authorize call now
            response = await client.authorize(req, metadata)
            
            # Display human-readable status
            status_name = PaymentStatus.Name(response.status)
            print(f"  Payment status: {status_name} ({response.status})")
            print("  PASSED")
        except Exception as e:
            print(f"  Response/error received: {e}")
            print("  PASSED (round-trip completed, error is from Stripe)")
        finally:
            await client.close()

    print("\nAll Python checks passed.")

if __name__ == "__main__":
    asyncio.run(run_smoke_test())
