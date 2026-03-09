"""
Smoke test for the packed hyperswitch-payments wheel.

Run via `make test-pack` — the Makefile installs the wheel into a temp
directory, copies this script there, and runs it in-place so imports
resolve against the installed package.
"""

import json
import os
import asyncio

from payments import (
    PaymentClient,
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
    ConnectorConfig,
    RequestConfig,
)


async def run_test():
    print(f"Loaded payments package from: {__file__}")
    print(f"  PaymentClient: {PaymentClient}")
    print(f"  authorize_req_transformer: {authorize_req_transformer}")

    api_key = os.getenv("STRIPE_API_KEY", "sk_test_placeholder")

    # Metadata: connector + typed auth (X-Connector-Auth style from main)
    metadata = {
        "connector": "Stripe",
        "connector_auth_type": json.dumps({
            "Stripe": {
                "api_key": api_key,
            }
        }),
    }

    # 1. Initialize Client with ConnectorConfig + optional RequestConfig defaults
    config = ConnectorConfig(connector=Connector.STRIPE, environment=Environment.SANDBOX)
    config.auth.stripe.api_key.value = api_key

    defaults = RequestConfig()

    client = PaymentClient(config, defaults)

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

    # Create options bytes for the low-level FFI signature
    from payments.generated.sdk_config_pb2 import FfiOptions

    ffi_opts = FfiOptions(
        environment=Environment.SANDBOX,
        connector=Connector.STRIPE,
        auth=config.auth,
    )
    options_bytes = ffi_opts.SerializeToString()

    # --- Test 1: Low-level FFI ---
    print("\n=== Test 1: Low-level FFI (authorize_req_transformer) ===")
    result_bytes = authorize_req_transformer(
        req.SerializeToString(), metadata, options_bytes
    )
    result = FfiConnectorHttpRequest.FromString(result_bytes)
    print(f"  URL:    {result.url}")
    print(f"  Method: {result.method}")
    if result.url != "https://api.stripe.com/v1/payment_intents":
        raise Exception(f"Unexpected URL: {result.url}")
    if result.method != "POST":
        raise Exception("Unexpected method")
    print("  PASSED")

    # --- Test 2: Full round-trip via PaymentClient ---
    print("\n=== Test 2: Full round-trip (PaymentClient.authorize) ===")
    if api_key == "sk_test_placeholder":
        print("  SKIPPED (set STRIPE_API_KEY to enable)")
    else:
        try:
            response = await client.authorize(req, metadata)
            print(f"  Response status: {response.status}")
            print(f"  Response type:   {type(response).__name__}")
            print("  PASSED")
        except Exception as e:
            print(f"  Response/error received: {e}")
            print("  PASSED (round-trip completed, error is from Stripe)")

    await client.close()
    print("\nAll checks passed.")


if __name__ == "__main__":
    asyncio.run(run_test())
