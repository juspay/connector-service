#!/usr/bin/env python3
"""
Full Payment Processing Example with Connector FFI

This example demonstrates the complete payment flow:
1. Transform payment request to connector-specific HTTP request
2. Execute the HTTP request using Python's requests library
3. Transform the response back to a standardized format

Note: This example uses mock responses since we don't have real API credentials.
In production, you would use real credentials and make actual HTTP requests.
"""

import json
from typing import Dict, Any, Optional
from dataclasses import dataclass

# Import our FFI bindings
from connector_ffi import ConnectorFFI


@dataclass
class PaymentResult:
    """Result of a payment operation."""
    success: bool
    status: str
    transaction_id: Optional[str] = None
    amount: Optional[int] = None
    currency: Optional[str] = None
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    raw_response: Optional[Dict] = None


class MockHttpClient:
    """
    Mock HTTP client that returns simulated responses.

    In production, replace this with actual HTTP calls using
    requests, httpx, aiohttp, or your preferred HTTP library.
    """

    def request(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        body: Optional[str] = None,
    ) -> tuple[int, str]:
        """
        Simulate an HTTP request.

        Returns:
            Tuple of (status_code, response_body)
        """
        # Simulate Stripe responses
        if "stripe.com" in url:
            if "/payment_intents" in url and method == "POST":
                return 200, json.dumps({
                    "id": "pi_mock_12345",
                    "object": "payment_intent",
                    "amount": 2000,
                    "currency": "usd",
                    "status": "succeeded",
                    "client_secret": "pi_mock_12345_secret_xyz",
                })
            elif "/payment_intents" in url and "/capture" in url:
                return 200, json.dumps({
                    "id": "pi_mock_12345",
                    "status": "succeeded",
                    "amount": 2000,
                    "currency": "usd",
                })
            elif "/refunds" in url:
                return 200, json.dumps({
                    "id": "re_mock_67890",
                    "object": "refund",
                    "amount": 500,
                    "currency": "usd",
                    "status": "succeeded",
                    "payment_intent": "pi_mock_12345",
                })

        # Simulate Adyen responses
        elif "adyen.com" in url:
            if "/payments" in url and method == "POST":
                return 200, json.dumps({
                    "pspReference": "883634778926265D",
                    "resultCode": "Authorised",
                    "amount": {
                        "currency": "EUR",
                        "value": 1500
                    },
                })

        # Simulate Forte responses
        elif "forte.net" in url:
            if "/transactions" in url and method == "POST":
                return 200, json.dumps({
                    "transaction_id": "trn_mock_abc123",
                    "authorization_amount": "20.00",
                    "response": {
                        "response_code": "A01",
                        "response_desc": "APPROVED"
                    }
                })

        # Default: unknown endpoint
        return 404, json.dumps({"error": {"message": "Not Found"}})


class PaymentProcessor:
    """
    Payment processor that uses the Connector FFI for transformations
    and makes HTTP requests using a native HTTP client.
    """

    def __init__(self, http_client=None):
        """
        Initialize the payment processor.

        Args:
            http_client: HTTP client to use. Defaults to MockHttpClient.
        """
        self.ffi = ConnectorFFI()
        self.http_client = http_client or MockHttpClient()

    def authorize(
        self,
        connector: str,
        auth: Dict[str, Any],
        amount: int,
        currency: str,
        payment_method: Dict[str, Any],
        reference_id: Optional[str] = None,
    ) -> PaymentResult:
        """
        Authorize a payment.

        Args:
            connector: Connector name (e.g., "stripe", "adyen")
            auth: Connector authentication credentials
            amount: Amount in minor units (cents)
            currency: 3-letter currency code
            payment_method: Payment method details
            reference_id: Optional reference ID

        Returns:
            PaymentResult with transaction details
        """
        # Step 1: Transform the request
        transform_result = self.ffi.transform_request(
            connector=connector,
            flow="authorize",
            auth=auth,
            payment={
                "amount": amount,
                "currency": currency,
                "reference_id": reference_id,
                "payment_method": payment_method,
            }
        )

        if not transform_result["success"]:
            return PaymentResult(
                success=False,
                status="failed",
                error_code=transform_result["error"]["code"],
                error_message=transform_result["error"]["message"],
            )

        http_request = transform_result["data"]

        # Step 2: Execute the HTTP request
        print(f"  -> {http_request['method']} {http_request['url']}")
        status_code, response_body = self.http_client.request(
            method=http_request["method"],
            url=http_request["url"],
            headers=http_request["headers"],
            body=http_request.get("body"),
        )
        print(f"  <- {status_code}")

        # Step 3: Transform the response
        response_result = self.ffi.transform_response(
            connector=connector,
            flow="authorize",
            status_code=status_code,
            body=response_body,
        )

        if not response_result["success"]:
            return PaymentResult(
                success=False,
                status="failed",
                error_code=response_result["error"]["code"],
                error_message=response_result["error"]["message"],
            )

        data = response_result["data"]
        return PaymentResult(
            success=data["status"] in ("succeeded", "authorized"),
            status=data["status"],
            transaction_id=data.get("transaction_id"),
            amount=data.get("amount"),
            currency=data.get("currency"),
            error_code=data.get("error_code"),
            error_message=data.get("error_message"),
            raw_response=data.get("raw_response"),
        )

    def refund(
        self,
        connector: str,
        auth: Dict[str, Any],
        transaction_id: str,
        amount: int,
        currency: str,
    ) -> PaymentResult:
        """
        Refund a payment.

        Args:
            connector: Connector name
            auth: Connector authentication credentials
            transaction_id: Original transaction ID
            amount: Amount to refund in minor units
            currency: 3-letter currency code

        Returns:
            PaymentResult with refund details
        """
        # Step 1: Transform the request
        transform_result = self.ffi.transform_request(
            connector=connector,
            flow="refund",
            auth=auth,
            payment={
                "amount": amount,
                "currency": currency,
                "transaction_id": transaction_id,
            }
        )

        if not transform_result["success"]:
            return PaymentResult(
                success=False,
                status="failed",
                error_code=transform_result["error"]["code"],
                error_message=transform_result["error"]["message"],
            )

        http_request = transform_result["data"]

        # Step 2: Execute the HTTP request
        print(f"  -> {http_request['method']} {http_request['url']}")
        status_code, response_body = self.http_client.request(
            method=http_request["method"],
            url=http_request["url"],
            headers=http_request["headers"],
            body=http_request.get("body"),
        )
        print(f"  <- {status_code}")

        # Step 3: Transform the response
        response_result = self.ffi.transform_response(
            connector=connector,
            flow="refund",
            status_code=status_code,
            body=response_body,
        )

        if not response_result["success"]:
            return PaymentResult(
                success=False,
                status="failed",
                error_code=response_result["error"]["code"],
                error_message=response_result["error"]["message"],
            )

        data = response_result["data"]
        return PaymentResult(
            success=data["status"] == "succeeded",
            status=data["status"],
            transaction_id=data.get("transaction_id"),
            amount=data.get("amount"),
            currency=data.get("currency"),
            error_code=data.get("error_code"),
            error_message=data.get("error_message"),
            raw_response=data.get("raw_response"),
        )


def main():
    """Demonstrate the full payment processing flow."""
    print("=" * 70)
    print("Full Payment Processing Example with Connector FFI")
    print("=" * 70)
    print()

    try:
        processor = PaymentProcessor()
    except FileNotFoundError as e:
        print(f"Error: {e}")
        print("\nTo build the library, run:")
        print("  cargo build --release -p connector-ffi")
        return 1

    # Test card details (test cards, not real)
    test_card = {
        "type": "card",
        "number": "4242424242424242",
        "exp_month": 12,
        "exp_year": 2025,
        "cvc": "123",
        "holder_name": "Test User",
    }

    # Example 1: Stripe Payment
    print("-" * 70)
    print("Example 1: Stripe Payment Authorization")
    print("-" * 70)

    stripe_result = processor.authorize(
        connector="stripe",
        auth={"api_key": "sk_test_YOUR_STRIPE_KEY_HERE"},
        amount=2000,  # $20.00
        currency="USD",
        payment_method=test_card,
        reference_id="order_001",
    )

    print(f"  Success: {stripe_result.success}")
    print(f"  Status: {stripe_result.status}")
    print(f"  Transaction ID: {stripe_result.transaction_id}")
    print(f"  Amount: {stripe_result.amount} {stripe_result.currency}")
    print()

    # Example 2: Stripe Refund
    if stripe_result.success and stripe_result.transaction_id:
        print("-" * 70)
        print("Example 2: Stripe Partial Refund")
        print("-" * 70)

        refund_result = processor.refund(
            connector="stripe",
            auth={"api_key": "sk_test_YOUR_STRIPE_KEY_HERE"},
            transaction_id=stripe_result.transaction_id,
            amount=500,  # $5.00 partial refund
            currency="USD",
        )

        print(f"  Success: {refund_result.success}")
        print(f"  Status: {refund_result.status}")
        print(f"  Refund ID: {refund_result.transaction_id}")
        print()

    # Example 3: Adyen Payment
    print("-" * 70)
    print("Example 3: Adyen Payment Authorization")
    print("-" * 70)

    adyen_result = processor.authorize(
        connector="adyen",
        auth={
            "api_key": "AQEyhmfuXNWTK0Qc+iSEmmGXuuP...",
            "merchant_id": "TestMerchant",
        },
        amount=1500,  # 15.00 EUR
        currency="EUR",
        payment_method=test_card,
        reference_id="order_002",
    )

    print(f"  Success: {adyen_result.success}")
    print(f"  Status: {adyen_result.status}")
    print(f"  Transaction ID: {adyen_result.transaction_id}")
    print(f"  Amount: {adyen_result.amount} {adyen_result.currency}")
    print()

    # Example 4: Forte Payment
    print("-" * 70)
    print("Example 4: Forte Payment Authorization")
    print("-" * 70)

    forte_result = processor.authorize(
        connector="forte",
        auth={
            "api_key": "api_access_id_xxx",
            "api_secret": "api_secret_key_xxx",
            "organization_id": "org_123",
            "location_id": "loc_456",
        },
        amount=2000,  # $20.00
        currency="USD",
        payment_method=test_card,
        reference_id="order_003",
    )

    print(f"  Success: {forte_result.success}")
    print(f"  Status: {forte_result.status}")
    print(f"  Transaction ID: {forte_result.transaction_id}")
    print(f"  Amount: {forte_result.amount} {forte_result.currency}")
    print()

    print("=" * 70)
    print("All examples completed!")
    print("=" * 70)
    print()
    print("Key Points:")
    print("  1. The FFI transforms requests to connector-specific formats")
    print("  2. Your application executes HTTP requests using native clients")
    print("  3. The FFI transforms responses back to a standard format")
    print("  4. No gRPC service needed - just a shared library!")
    print()

    return 0


if __name__ == "__main__":
    exit(main())
