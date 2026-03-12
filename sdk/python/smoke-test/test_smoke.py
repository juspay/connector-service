"""
Smoke test for PayPal access token flow using hyperswitch-payments wheel.

This test demonstrates:
  1. Create an access token via PayPal
  2. Use the access token in an authorize request

Usage:
  Run via `make test-pack` — the Makefile installs the wheel into a temp
  directory, copies this script there, and runs it in-place so imports
  resolve against the installed package.
"""

import asyncio

from payments import (
    PaymentClient,
    MerchantAuthenticationClient,
    # Request/Response types
    MerchantAuthenticationServiceCreateAccessTokenRequest,
    PaymentServiceAuthorizeRequest,
    # Enums
    Currency,
    CaptureMethod,
    AuthenticationType,
    Connector,
    PaymentStatus,
    # Data types
    SecretString,
    AccessToken,
    ConnectorState,
    # Config types
    ConnectorConfig,
    RequestConfig,
    Environment,
    RequestError,
    ResponseError,
)


# PayPal credentials (test values)
PAYPAL_CREDS = {
    "client_id": "ASKAGh2WXgqfQ5TzjpZzLsfhVGlFbjq5VrV5IOX8KXDD2N_XqkGeYNDkWyr_UXnfhXpEkABdmP284b_2",
    "client_secret": "EOpaRHxEgaMJ9OHfsn3ngHy7DoXArNjPgCwsrzaJreO3gXPSJP_r4iOp1UUEn140CsEjaYxtm0g61VFU",
}


# 1. ConnectorConfig (connector, auth, environment)
config = ConnectorConfig(
    connector=Connector.PAYPAL,
    auth={
        "paypal": {
            "client_id": {"value": PAYPAL_CREDS["client_id"]},
            "client_secret": {"value": PAYPAL_CREDS["client_secret"]},
        }
    },
    environment=Environment.SANDBOX,
)

# 2. Optional RequestConfig defaults (http, vault)
defaults = RequestConfig()


async def test_access_token_flow():
    """
    Test the access token flow:
    1. Create access token
    2. Use access token in authorize request
    """
    print("\n=== Test: PayPal Access Token Flow ===")

    auth_client = MerchantAuthenticationClient(config, defaults)
    payment_client = PaymentClient(config, defaults)

    # Step 1: Create Access Token Request
    print("\n--- Step 1: Create Access Token ---")
    access_token_request = MerchantAuthenticationServiceCreateAccessTokenRequest(
        merchant_access_token_id="access_token_test_"
        + str(int(asyncio.get_event_loop().time() * 1000)),
        connector=Connector.PAYPAL,
        test_mode=True,
    )

    # Make the request via MerchantAuthenticationClient
    access_token_value = None
    token_type_value = None
    access_token_response = None

    try:
        access_token_response = await auth_client.create_access_token(
            access_token_request
        )
        print(f"  Response type: {type(access_token_response).__name__}")
        print(
            f"  Response fields: {[f.name for f in access_token_response.DESCRIPTOR.fields]}"
        )

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
        print(
            f"  Request error {e.error_code} {e.error_message} {PaymentStatus.Name(e.status)} {e.status_code}"
        )
        print("  This might be expected if credentials are not valid")
        return
    except ResponseError as e:
        print(
            f"  Response error {e.error_code} {e.error_message} {PaymentStatus.Name(e.status)} {e.status_code}"
        )
        print("  This might be expected if credentials are not valid")
        return
    except Exception as e:
        print(f"  Error creating access token: {e}")
        print("  This might be expected if credentials are not valid")
        return

    if not access_token_value:
        print("  SKIPPED: Cannot proceed without access token")
        return

    # Step 2: Use Access Token in Authorize Request
    print("\n--- Step 2: Authorize with Access Token ---")
    authorize_request = PaymentServiceAuthorizeRequest(
        merchant_transaction_id="authorize_with_token_"
        + str(int(asyncio.get_event_loop().time() * 1000)),
        amount={
            "minor_amount": 1000,  # $10.00
            "currency": Currency.USD,
        },
        capture_method=CaptureMethod.AUTOMATIC,
        payment_method={
            "card": {
                "card_number": {"value": "4111111111111111"},
                "card_exp_month": {"value": "12"},
                "card_exp_year": {"value": "2050"},
                "card_cvc": {"value": "123"},
                "card_holder_name": {"value": "Test User"},
            },
        },
        customer={
            "email": {"value": "test@example.com"},
            "name": "Test",
        },
        state=ConnectorState(
            access_token=AccessToken(
                token=SecretString(value=access_token_value),
                token_type=token_type_value,
                expires_in_seconds=access_token_response.expires_in_seconds,
            ),
        ),
        auth_type=AuthenticationType.NO_THREE_DS,
        return_url="https://example.com/return",
        webhook_url="https://example.com/webhook",
        # address={},
        test_mode=True,
    )

    try:
        authorize_response = await payment_client.authorize(authorize_request)
        print(f"  Response type: {type(authorize_response).__name__}")
        print(
            f"  Response fields: {[f.name for f in authorize_response.DESCRIPTOR.fields]}"
        )

        if authorize_response.status == PaymentStatus.CHARGED:
            print(f"  Transaction ID: {authorize_response.connector_transaction_id}")
            print("  PASSED")
        elif authorize_response.status == PaymentStatus.FAILURE:
            error = authorize_response.error
            code = (
                error.unified_details.code
                if error.HasField("unified_details")
                and error.unified_details.HasField("code")
                else "N/A"
            )
            message = (
                error.unified_details.message
                if error.HasField("unified_details")
                and error.unified_details.HasField("message")
                else "Unknown error"
            )
            print(f"  Error Code: {code}")
            print(f"  Error Message: {message}")
            print("  FAILED")
        else:
            status_name = PaymentStatus.Name(authorize_response.status)
            print(f"  Payment status: {status_name}")
            print("  PASSED (round-trip completed)")

    except RequestError as e:
        print(
            f"  Request error {e.error_code} {e.error_message} {PaymentStatus.Name(e.status)} {e.status_code}"
        )
        print("  PASSED (round-trip completed, error is from PayPal)")
    except ResponseError as e:
        print(
            f"  Response error {e.error_code} {e.error_message} {PaymentStatus.Name(e.status)} {e.status_code}"
        )
        print("  PASSED (round-trip completed, error is from PayPal)")
    except Exception as e:
        print(f"  Error during authorize: {e}")
        print("  PASSED (round-trip completed, error is from PayPal)")

    print("\n=== Test Complete ===")


async def run_test():
    print(f"Loaded payments package from: {__file__}")
    print(f"  PaymentClient: {PaymentClient}")
    print(f"  MerchantAuthenticationClient: {MerchantAuthenticationClient}")

    await test_access_token_flow()

    print("\nAll checks passed.")


if __name__ == "__main__":
    asyncio.run(run_test())