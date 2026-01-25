#!/usr/bin/env python3
"""
Example usage of UniFFI-generated Python bindings for Connector FFI.

This example demonstrates how the auto-generated bindings from UniFFI
provide type-safe access to the Rust connector transformation library.

To run this example:
1. Build the library: cargo build --release -p connector-ffi-uniffi
2. Set LD_LIBRARY_PATH: export LD_LIBRARY_PATH=$PWD/target/release:$LD_LIBRARY_PATH
3. Run: python examples/example_uniffi.py

Note: The generated bindings are in bindings/python/connector_ffi_uniffi.py
"""

import sys
import os

# Add the bindings directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'bindings', 'python'))

# Import the auto-generated UniFFI bindings
# Note: These types are automatically generated from the Rust code!
try:
    from connector_ffi_uniffi import (
        # Functions
        list_supported_connectors,
        get_connector_info,
        transform_request,
        transform_response,
        create_card_payment_method,
        create_wallet_payment_method,

        # Types (auto-generated from Rust!)
        TransformRequestInput,
        TransformResponseInput,
        PaymentData,
        PaymentMethod,
        CardData,
        HttpRequest,
        PaymentResult,
        ConnectorInfo,

        # Enums (auto-generated from Rust!)
        HttpMethod,
        PaymentStatus,
        PaymentFlow,
        BodyFormat,
        AuthType,

        # Object (auto-generated from Rust!)
        ConnectorRegistry,

        # Errors (auto-generated from Rust!)
        ConnectorError,
    )
    print("Successfully imported UniFFI-generated bindings!")
except ImportError as e:
    print(f"Failed to import UniFFI bindings: {e}")
    print("\nMake sure you've:")
    print("1. Built the library: cargo build --release -p connector-ffi-uniffi")
    print("2. Set LD_LIBRARY_PATH: export LD_LIBRARY_PATH=$PWD/target/release:$LD_LIBRARY_PATH")
    sys.exit(1)


def main():
    print("\n" + "=" * 60)
    print("UniFFI-Generated Connector FFI Example")
    print("=" * 60)

    # 1. List supported connectors
    print("\n1. Listing supported connectors...")
    connectors = list_supported_connectors()
    print(f"   Supported connectors: {connectors}")

    # 2. Get connector info (using free function)
    print("\n2. Getting Stripe connector info...")
    stripe_info = get_connector_info("stripe")
    if stripe_info:
        print(f"   Name: {stripe_info.name}")
        print(f"   Display Name: {stripe_info.display_name}")
        print(f"   Base URL: {stripe_info.base_url}")
        print(f"   Auth Type: {stripe_info.auth_type}")
        print(f"   Auth Fields: {stripe_info.auth_fields}")
        print(f"   Supported Flows: {stripe_info.supported_flows}")
        print(f"   Body Format: {stripe_info.body_format}")
        print(f"   Supports Webhooks: {stripe_info.supports_webhooks}")
        print(f"   Supports 3DS: {stripe_info.supports_3ds}")

    # 3. Use ConnectorRegistry object
    print("\n3. Using ConnectorRegistry object...")
    registry = ConnectorRegistry()
    adyen_info = registry.get_connector_info("adyen")
    if adyen_info:
        print(f"   Adyen base URL: {adyen_info.base_url}")
        print(f"   Adyen supported currencies: {adyen_info.supported_currencies}")

    # 4. Create a payment method using helper function
    print("\n4. Creating card payment method...")
    card_pm = create_card_payment_method(
        number="4242424242424242",
        exp_month=12,
        exp_year=2025,
        cvc="123",
        holder_name="John Doe"
    )
    print(f"   Payment method type: {card_pm.method_type}")
    print(f"   Card number (masked): ****{card_pm.card.number[-4:]}")

    # 5. Create PaymentData using auto-generated class
    print("\n5. Creating PaymentData...")
    payment_data = PaymentData(
        amount=1000,  # $10.00 in cents
        currency="USD",
        payment_method=card_pm,
        reference_id="order_123",
        transaction_id=None,
        return_url=None,
        metadata=None
    )
    print(f"   Amount: {payment_data.amount} cents")
    print(f"   Currency: {payment_data.currency}")

    # 6. Transform request
    print("\n6. Transforming request for Stripe authorize...")
    try:
        request_input = TransformRequestInput(
            connector="stripe",
            flow="authorize",
            auth={"api_key": "sk_test_YOUR_KEY_HERE"},
            payment=payment_data
        )

        http_request = transform_request(request_input)
        print(f"   URL: {http_request.url}")
        print(f"   Method: {http_request.method}")
        print(f"   Headers: {list(http_request.headers.keys())}")
        print(f"   Body Format: {http_request.body_format}")
        print(f"   Body (truncated): {http_request.body[:100] if http_request.body else 'None'}...")
    except ConnectorError as e:
        print(f"   Error: {e}")

    # 7. Transform response
    print("\n7. Transforming Stripe response...")
    response_input = TransformResponseInput(
        connector="stripe",
        flow="authorize",
        status_code=200,
        headers={},
        body='{"id": "pi_test_123", "status": "requires_capture", "amount": 1000, "currency": "usd"}'
    )

    try:
        result = transform_response(response_input)
        print(f"   Success: {result.success}")
        print(f"   Status: {result.status}")
        print(f"   Transaction ID: {result.transaction_id}")
        print(f"   Amount: {result.amount}")
        print(f"   Currency: {result.currency}")
    except ConnectorError as e:
        print(f"   Error: {e}")

    # 8. Demonstrate type safety with enums
    print("\n8. Demonstrating type-safe enums...")
    print(f"   HttpMethod.POST = {HttpMethod.POST}")
    print(f"   PaymentStatus.AUTHORIZED = {PaymentStatus.AUTHORIZED}")
    print(f"   PaymentFlow.CAPTURE = {PaymentFlow.CAPTURE}")
    print(f"   BodyFormat.JSON = {BodyFormat.JSON}")
    print(f"   AuthType.HEADER_KEY = {AuthType.HEADER_KEY}")

    # 9. Show comparison with manual FFI
    print("\n" + "=" * 60)
    print("Comparison: UniFFI vs Manual FFI")
    print("=" * 60)
    print("""
    UniFFI-Generated (this example):
    - Types are auto-generated from Rust definitions
    - Type annotations included automatically
    - __eq__, __str__ implemented automatically
    - Enums are proper Python enums
    - Error types are proper exceptions
    - No JSON serialization at boundaries

    Manual FFI (backend/ffi):
    - Types duplicated manually in Python
    - JSON-based interface (runtime type errors possible)
    - More flexible but more error-prone
    - Requires manual synchronization
    """)

    print("\n" + "=" * 60)
    print("Example completed successfully!")
    print("=" * 60)


if __name__ == "__main__":
    main()
