#!/usr/bin/env python3
"""
Complete example of UniFFI-generated Python bindings with HTTP execution.

This demonstrates the full flow:
1. Transform payment request → HTTP request
2. Execute HTTP request using Python's urllib
3. Transform HTTP response → Payment result

Usage:
    python3 example_with_http.py
"""

import sys
import os
import json
import urllib.request
import urllib.error
import ssl

# Add the bindings directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'bindings', 'python'))

from connector_ffi_uniffi import (
    # Functions
    list_supported_connectors,
    get_connector_info,
    transform_request,
    transform_response,
    create_card_payment_method,

    # Types
    TransformRequestInput,
    TransformResponseInput,
    PaymentData,

    # Enums
    HttpMethod,
    BodyFormat,

    # Errors
    ConnectorError,
)


class HttpClient:
    """Simple HTTP client using urllib."""

    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        # Create SSL context that doesn't verify (for testing only)
        self.ssl_context = ssl.create_default_context()

    def execute(self, url: str, method: HttpMethod, headers: dict,
                body: str = None, body_format: BodyFormat = None) -> tuple:
        """
        Execute an HTTP request.

        Returns:
            tuple: (status_code, response_headers, response_body)
        """
        # Convert HttpMethod enum to string
        method_str = method.name  # GET, POST, etc.

        # Encode body if present
        data = body.encode('utf-8') if body else None

        # Create request
        req = urllib.request.Request(url, data=data, method=method_str)

        # Add headers
        for key, value in headers.items():
            req.add_header(key, value)

        try:
            with urllib.request.urlopen(req, timeout=self.timeout,
                                         context=self.ssl_context) as response:
                status_code = response.status
                response_headers = dict(response.headers)
                response_body = response.read().decode('utf-8')
                return status_code, response_headers, response_body

        except urllib.error.HTTPError as e:
            # Return error response
            status_code = e.code
            response_headers = dict(e.headers) if e.headers else {}
            response_body = e.read().decode('utf-8') if e.fp else '{}'
            return status_code, response_headers, response_body

        except urllib.error.URLError as e:
            # Network error
            return 0, {}, json.dumps({"error": str(e.reason)})


class ConnectorClient:
    """
    High-level connector client that uses UniFFI bindings + HTTP.

    This demonstrates the full integration:
    - Rust handles request/response transformation
    - Python handles HTTP execution
    """

    def __init__(self, connector: str, auth: dict):
        """
        Initialize connector client.

        Args:
            connector: Connector name (stripe, adyen, etc.)
            auth: Authentication credentials dict
        """
        self.connector = connector.lower()
        self.auth = auth
        self.http_client = HttpClient()

        # Validate connector exists
        info = get_connector_info(self.connector)
        if not info:
            raise ValueError(f"Unknown connector: {connector}")
        self.info = info

    def authorize(self, amount: int, currency: str,
                  card_number: str, exp_month: int, exp_year: int, cvc: str,
                  holder_name: str = None, reference_id: str = None,
                  dry_run: bool = False) -> dict:
        """
        Authorize a payment.

        Args:
            amount: Amount in cents
            currency: Currency code (USD, EUR, etc.)
            card_number: Card number
            exp_month: Expiry month (1-12)
            exp_year: Expiry year (4 digits)
            cvc: Card verification code
            holder_name: Cardholder name (optional)
            reference_id: Reference ID (optional)
            dry_run: If True, don't execute HTTP, just return transformed request

        Returns:
            dict with result or request details (if dry_run)
        """
        # 1. Create payment method using UniFFI helper
        payment_method = create_card_payment_method(
            number=card_number,
            exp_month=exp_month,
            exp_year=exp_year,
            cvc=cvc,
            holder_name=holder_name
        )

        # 2. Create payment data
        payment_data = PaymentData(
            amount=amount,
            currency=currency,
            payment_method=payment_method,
            reference_id=reference_id,
            transaction_id=None,
            return_url=None,
            metadata=None
        )

        # 3. Transform to HTTP request using Rust/UniFFI
        request_input = TransformRequestInput(
            connector=self.connector,
            flow="authorize",
            auth=self.auth,
            payment=payment_data
        )

        http_request = transform_request(request_input)

        print(f"\n{'='*60}")
        print(f"STEP 1: Request transformed by Rust")
        print(f"{'='*60}")
        print(f"URL: {http_request.url}")
        print(f"Method: {http_request.method}")
        print(f"Headers: {list(http_request.headers.keys())}")
        print(f"Body Format: {http_request.body_format}")
        if http_request.body:
            # Mask sensitive data in body
            body_display = http_request.body
            if len(body_display) > 200:
                body_display = body_display[:200] + "..."
            print(f"Body: {body_display}")

        if dry_run:
            return {
                "dry_run": True,
                "url": http_request.url,
                "method": str(http_request.method),
                "headers": dict(http_request.headers),
                "body": http_request.body,
                "body_format": str(http_request.body_format)
            }

        # 4. Execute HTTP request using Python
        print(f"\n{'='*60}")
        print(f"STEP 2: Executing HTTP request with Python")
        print(f"{'='*60}")

        status_code, response_headers, response_body = self.http_client.execute(
            url=http_request.url,
            method=http_request.method,
            headers=http_request.headers,
            body=http_request.body,
            body_format=http_request.body_format
        )

        print(f"Status Code: {status_code}")
        print(f"Response Headers: {list(response_headers.keys())}")
        if response_body:
            body_display = response_body
            if len(body_display) > 300:
                body_display = body_display[:300] + "..."
            print(f"Response Body: {body_display}")

        # 5. Transform response using Rust/UniFFI
        print(f"\n{'='*60}")
        print(f"STEP 3: Response transformed by Rust")
        print(f"{'='*60}")

        response_input = TransformResponseInput(
            connector=self.connector,
            flow="authorize",
            status_code=status_code,
            headers=response_headers,
            body=response_body
        )

        result = transform_response(response_input)

        print(f"Success: {result.success}")
        print(f"Status: {result.status}")
        print(f"Transaction ID: {result.transaction_id}")
        if result.error_code:
            print(f"Error Code: {result.error_code}")
        if result.error_message:
            print(f"Error Message: {result.error_message}")

        return {
            "success": result.success,
            "status": str(result.status),
            "transaction_id": result.transaction_id,
            "connector_transaction_id": result.connector_transaction_id,
            "amount": result.amount,
            "currency": result.currency,
            "error_code": result.error_code,
            "error_message": result.error_message
        }

    def capture(self, transaction_id: str, amount: int, currency: str,
                dry_run: bool = False) -> dict:
        """Capture a previously authorized payment."""
        payment_data = PaymentData(
            amount=amount,
            currency=currency,
            payment_method=None,
            reference_id=None,
            transaction_id=transaction_id,
            return_url=None,
            metadata=None
        )

        request_input = TransformRequestInput(
            connector=self.connector,
            flow="capture",
            auth=self.auth,
            payment=payment_data
        )

        http_request = transform_request(request_input)

        if dry_run:
            return {"dry_run": True, "url": http_request.url, "method": str(http_request.method)}

        status_code, response_headers, response_body = self.http_client.execute(
            url=http_request.url,
            method=http_request.method,
            headers=http_request.headers,
            body=http_request.body
        )

        result = transform_response(TransformResponseInput(
            connector=self.connector,
            flow="capture",
            status_code=status_code,
            headers=response_headers,
            body=response_body
        ))

        return {
            "success": result.success,
            "status": str(result.status),
            "transaction_id": result.transaction_id
        }

    def void(self, transaction_id: str, dry_run: bool = False) -> dict:
        """Void/cancel a payment."""
        payment_data = PaymentData(
            amount=0,
            currency="USD",
            payment_method=None,
            reference_id=None,
            transaction_id=transaction_id,
            return_url=None,
            metadata=None
        )

        request_input = TransformRequestInput(
            connector=self.connector,
            flow="void",
            auth=self.auth,
            payment=payment_data
        )

        http_request = transform_request(request_input)

        if dry_run:
            return {"dry_run": True, "url": http_request.url, "method": str(http_request.method)}

        status_code, response_headers, response_body = self.http_client.execute(
            url=http_request.url,
            method=http_request.method,
            headers=http_request.headers,
            body=http_request.body
        )

        result = transform_response(TransformResponseInput(
            connector=self.connector,
            flow="void",
            status_code=status_code,
            headers=response_headers,
            body=response_body
        ))

        return {
            "success": result.success,
            "status": str(result.status),
            "transaction_id": result.transaction_id
        }


def demo_dry_run():
    """Demo without making real API calls."""
    print("\n" + "=" * 60)
    print("DRY RUN DEMO - No real API calls")
    print("=" * 60)

    # Show all supported connectors
    print("\nSupported connectors:", list_supported_connectors())

    # Demo with Stripe (dry run)
    print("\n--- Stripe Authorize (Dry Run) ---")
    stripe_client = ConnectorClient("stripe", {"api_key": "sk_test_YOUR_KEY_HERE"})
    result = stripe_client.authorize(
        amount=2500,
        currency="USD",
        card_number="4242424242424242",
        exp_month=12,
        exp_year=2025,
        cvc="123",
        holder_name="Test User",
        reference_id="order_12345",
        dry_run=True
    )
    print(f"\nDry run result: {json.dumps(result, indent=2)}")

    # Demo with Adyen (dry run)
    print("\n--- Adyen Authorize (Dry Run) ---")
    adyen_client = ConnectorClient("adyen", {
        "api_key": "YOUR_ADYEN_API_KEY",
        "merchant_account": "YOUR_MERCHANT_ACCOUNT"
    })
    result = adyen_client.authorize(
        amount=1500,
        currency="EUR",
        card_number="4111111111111111",
        exp_month=3,
        exp_year=2026,
        cvc="737",
        holder_name="John Doe",
        dry_run=True
    )
    print(f"\nDry run result: {json.dumps(result, indent=2)}")


def demo_with_mock_response():
    """Demo with mock HTTP responses (simulates full flow)."""
    print("\n" + "=" * 60)
    print("MOCK RESPONSE DEMO - Simulates full flow")
    print("=" * 60)

    # Create client
    client = ConnectorClient("stripe", {"api_key": "sk_test_mock"})

    # 1. Transform request
    payment_method = create_card_payment_method(
        "4242424242424242", 12, 2025, "123", "Test User"
    )

    request_input = TransformRequestInput(
        connector="stripe",
        flow="authorize",
        auth={"api_key": "sk_test_mock"},
        payment=PaymentData(
            amount=5000,
            currency="USD",
            payment_method=payment_method,
            reference_id="mock_order_1",
            transaction_id=None,
            return_url=None,
            metadata=None
        )
    )

    http_request = transform_request(request_input)
    print(f"\nTransformed Request:")
    print(f"  URL: {http_request.url}")
    print(f"  Method: {http_request.method}")

    # 2. Simulate successful response
    mock_response = json.dumps({
        "id": "pi_mock_12345",
        "status": "requires_capture",
        "amount": 5000,
        "currency": "usd",
        "payment_method": "pm_card_visa"
    })

    print(f"\nMock Response Body: {mock_response}")

    # 3. Transform response
    result = transform_response(TransformResponseInput(
        connector="stripe",
        flow="authorize",
        status_code=200,
        headers={"content-type": "application/json"},
        body=mock_response
    ))

    print(f"\nTransformed Result:")
    print(f"  Success: {result.success}")
    print(f"  Status: {result.status}")
    print(f"  Transaction ID: {result.transaction_id}")
    print(f"  Amount: {result.amount}")
    print(f"  Currency: {result.currency}")

    # 4. Simulate error response
    print("\n--- Simulating Error Response ---")

    error_response = json.dumps({
        "error": {
            "code": "card_declined",
            "message": "Your card was declined.",
            "type": "card_error"
        }
    })

    error_result = transform_response(TransformResponseInput(
        connector="stripe",
        flow="authorize",
        status_code=402,
        headers={},
        body=error_response
    ))

    print(f"\nError Result:")
    print(f"  Success: {error_result.success}")
    print(f"  Status: {error_result.status}")
    print(f"  Error Code: {error_result.error_code}")
    print(f"  Error Message: {error_result.error_message}")


def demo_real_api_call():
    """Demo with real Stripe API call (requires valid API key)."""
    print("\n" + "=" * 60)
    print("REAL API DEMO - Uncomment and add your API key to test")
    print("=" * 60)

    # Uncomment below and add your Stripe test API key to make real calls
    """
    stripe_client = ConnectorClient("stripe", {
        "api_key": "sk_test_YOUR_REAL_KEY_HERE"
    })

    result = stripe_client.authorize(
        amount=1000,  # $10.00
        currency="USD",
        card_number="4242424242424242",  # Stripe test card
        exp_month=12,
        exp_year=2025,
        cvc="123",
        holder_name="Test User",
        reference_id="test_order_001",
        dry_run=False  # Set to False for real API call
    )

    print(f"\\nReal API Result: {json.dumps(result, indent=2)}")

    # If authorized, try capture
    if result.get("success") and result.get("transaction_id"):
        print("\\nAttempting capture...")
        capture_result = stripe_client.capture(
            transaction_id=result["transaction_id"],
            amount=1000,
            currency="USD"
        )
        print(f"Capture Result: {json.dumps(capture_result, indent=2)}")
    """
    print("\n(Real API demo code is commented out - edit the file to enable)")


def main():
    print("\n" + "=" * 60)
    print("UniFFI Connector Client - Full Flow Demo")
    print("=" * 60)
    print("""
This demo shows the complete integration:
  1. Rust/UniFFI: Transforms payment data → HTTP request
  2. Python: Executes the HTTP request
  3. Rust/UniFFI: Transforms HTTP response → Payment result
""")

    # Run demos
    demo_dry_run()
    demo_with_mock_response()
    demo_real_api_call()

    print("\n" + "=" * 60)
    print("Demo completed!")
    print("=" * 60)


if __name__ == "__main__":
    main()
