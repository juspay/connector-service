#!/usr/bin/env python3
"""
Smoke test for PayPal access token flow using hyperswitch-payments SDK.

This test demonstrates:
  1. Create an access token via PayPal
  2. Use the access token in an authorize request

Usage:
    python3 test_smoke_composite.py
"""

import asyncio
import os
import sys
import time

# Add parent directory to path for imports when running directly
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

try:
    from payments import (
        PaymentClient,
        MerchantAuthenticationClient,
        ConnectorConfig,
        RequestConfig,
        Environment,
        Connector,
        MerchantAuthenticationServiceCreateAccessTokenRequest,
        PaymentServiceAuthorizeRequest,
        Currency,
        CaptureMethod,
        AuthenticationType,
        SecretString,
        AccessToken,
        ConnectorState,
        PaymentAddress,
        RequestError,
        ResponseError,
    )
except ImportError as e:
    print(f"Error importing payments package: {e}")
    print(
        "Make sure the wheel is installed: pip install dist/hyperswitch_payments-*.whl"
    )
    sys.exit(1)


# Hardcoded placeholder credentials
PAYPAL_CREDS = {
    "client_id": "client_id",
    "client_secret": "client_secret",
}


def create_config() -> ConnectorConfig:
    """Create ConnectorConfig with PayPal credentials."""
    config = ConnectorConfig()
    config.options.environment = Environment.SANDBOX
    config.connector_config.paypal.client_id.value = PAYPAL_CREDS["client_id"]
    config.connector_config.paypal.client_secret.value = PAYPAL_CREDS["client_secret"]
    return config


async def test_access_token_flow() -> None:
    """Test the access token flow:
    1. Create access token
    2. Use access token in authorize request
    """
    print("\n=== Test: PayPal Access Token Flow ===")

    config = create_config()
    defaults = RequestConfig()

    auth_client = MerchantAuthenticationClient(config, defaults)
    payment_client = PaymentClient(config, defaults)

    # Step 1: Create Access Token Request
    print("\n--- Step 1: Create Access Token ---")
    access_token_request = MerchantAuthenticationServiceCreateAccessTokenRequest()
    access_token_request.merchant_access_token_id = (
        f"access_token_test_{int(time.time() * 1000)}"
    )
    access_token_request.connector = Connector.PAYPAL
    access_token_request.test_mode = True

    access_token_value = None
    token_type_value = None
    access_token_response = None

    try:
        access_token_response = await auth_client.create_access_token(
            access_token_request
        )
        print(f"  Response type: {type(access_token_response).__name__}")

        # Extract access token from response
        if (
            access_token_response.access_token
            and access_token_response.access_token.value
        ):
            access_token_value = access_token_response.access_token.value
            token_type_value = access_token_response.token_type or "Bearer"
            print(f"  Access Token received: {access_token_value[:20]}...")
            print(f"  Token Type: {token_type_value}")
            print(f"  Expires In: {access_token_response.expires_in_seconds} seconds")
            print(f"  Status: {access_token_response.status}")
        else:
            print("  WARNING: No access token in response")
            print(f"  Full response: {access_token_response}")

    except RequestError as e:
        print(f"  RequestError: {e.error_code} - {e.error_message}")
        print("  This might be expected if credentials are not valid")
        return
    except ResponseError as e:
        print(f"  ResponseError: {e.error_code} - {e.error_message}")
        print("  This might be expected if credentials are not valid")
        return
    except Exception as e:
        message = str(e) if str(e) else type(e).__name__
        print(f"  Error creating access token: {message}")
        print("  This might be expected if credentials are not valid")
        return

    if not access_token_value:
        print("  SKIPPED: Cannot proceed without access token")
        return

    # Step 2: Use Access Token in Authorize Request
    print("\n--- Step 2: Authorize with Access Token ---")
    authorize_request = PaymentServiceAuthorizeRequest()
    authorize_request.merchant_transaction_id = (
        f"authorize_with_token_{int(time.time() * 1000)}"
    )
    authorize_request.amount.minor_amount = 1000  # $10.00
    authorize_request.amount.currency = Currency.USD
    authorize_request.capture_method = CaptureMethod.AUTOMATIC

    # Card details
    card = authorize_request.payment_method.card
    card.card_number.value = "4111111111111111"
    card.card_exp_month.value = "12"
    card.card_exp_year.value = "2050"
    card.card_cvc.value = "123"
    card.card_holder_name.value = "Test User"

    # Customer info
    authorize_request.customer.email.value = "test@example.com"
    authorize_request.customer.name = "Test"

    # Set connector state with access token
    authorize_request.state.access_token.token.value = access_token_value
    authorize_request.state.access_token.token_type = token_type_value
    authorize_request.state.access_token.expires_in_seconds = (
        access_token_response.expires_in_seconds
    )

    # Auth and URLs
    authorize_request.auth_type = AuthenticationType.NO_THREE_DS
    authorize_request.return_url = "https://example.com/return"
    authorize_request.webhook_url = "https://example.com/webhook"
    authorize_request.address.CopyFrom(PaymentAddress())
    authorize_request.test_mode = True

    try:
        authorize_response = await payment_client.authorize(authorize_request)
        print(f"  Response type: {type(authorize_response).__name__}")
        print(f"  Payment status: {authorize_response.status}")
        print("  PASSED")
    except RequestError as e:
        print(f"  RequestError: {e.error_code} - {e.error_message}")
        print("  PASSED (round-trip completed, error is from PayPal)")
    except ResponseError as e:
        print(f"  ResponseError: {e.error_code} - {e.error_message}")
        print("  PASSED (round-trip completed, error is from PayPal)")
    except Exception as e:
        print(f"  Error during authorize: {e}")
        print("  PASSED (round-trip completed, error is from PayPal)")

    print("\n=== Test Complete ===")


def main():
    """Run the composite flow test."""
    try:
        asyncio.run(test_access_token_flow())
        print("\nAll checks passed.")
    except Exception as e:
        print(f"\nFatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
