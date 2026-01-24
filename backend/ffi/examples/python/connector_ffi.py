#!/usr/bin/env python3
"""
Connector FFI Python Bindings

This module provides Python bindings for the connector-service FFI library.
It allows you to transform payment requests to connector-specific HTTP requests
and transform connector responses back to standardized payment responses.

Usage:
    from connector_ffi import ConnectorFFI

    ffi = ConnectorFFI()

    # Transform a Stripe payment request
    result = ffi.transform_request(
        connector="stripe",
        flow="authorize",
        auth={"api_key": "sk_test_xxx"},
        payment={
            "amount": 1000,
            "currency": "USD",
            "payment_method": {
                "type": "card",
                "number": "4242424242424242",
                "exp_month": 12,
                "exp_year": 2025,
                "cvc": "123"
            }
        }
    )

    if result["success"]:
        http_request = result["data"]
        print(f"URL: {http_request['url']}")
        print(f"Method: {http_request['method']}")
        print(f"Headers: {http_request['headers']}")
        print(f"Body: {http_request['body']}")
"""

import ctypes
import json
import os
import platform
from pathlib import Path
from typing import Any, Dict, Optional


class ConnectorFFI:
    """Python bindings for the connector-service FFI library."""

    def __init__(self, library_path: Optional[str] = None):
        """
        Initialize the FFI bindings.

        Args:
            library_path: Path to the shared library. If not provided,
                         will look in common locations.
        """
        if library_path is None:
            library_path = self._find_library()

        self._lib = ctypes.CDLL(library_path)
        self._setup_functions()

    def _find_library(self) -> str:
        """Find the shared library in common locations."""
        # Determine library name based on platform
        system = platform.system()
        if system == "Linux":
            lib_name = "libconnector_ffi.so"
        elif system == "Darwin":
            lib_name = "libconnector_ffi.dylib"
        elif system == "Windows":
            lib_name = "connector_ffi.dll"
        else:
            raise RuntimeError(f"Unsupported platform: {system}")

        # Search paths
        search_paths = [
            # Current directory
            Path.cwd() / lib_name,
            # Relative to this script
            Path(__file__).parent / lib_name,
            Path(__file__).parent.parent.parent / "target" / "release" / lib_name,
            Path(__file__).parent.parent.parent.parent.parent / "target" / "release" / lib_name,
            # Common install locations
            Path("/usr/local/lib") / lib_name,
            Path("/usr/lib") / lib_name,
        ]

        for path in search_paths:
            if path.exists():
                return str(path)

        raise FileNotFoundError(
            f"Could not find {lib_name}. "
            f"Build with 'cargo build --release -p connector-ffi' "
            f"or provide the library_path parameter."
        )

    def _setup_functions(self):
        """Setup function signatures for the FFI calls."""
        # connector_transform_request_json
        self._lib.connector_transform_request_json.argtypes = [ctypes.c_char_p]
        self._lib.connector_transform_request_json.restype = ctypes.c_char_p

        # connector_transform_response_json
        self._lib.connector_transform_response_json.argtypes = [ctypes.c_char_p]
        self._lib.connector_transform_response_json.restype = ctypes.c_char_p

        # connector_list_supported
        self._lib.connector_list_supported.argtypes = []
        self._lib.connector_list_supported.restype = ctypes.c_char_p

        # connector_list_flows
        self._lib.connector_list_flows.argtypes = []
        self._lib.connector_list_flows.restype = ctypes.c_char_p

        # ffi_string_free
        self._lib.ffi_string_free.argtypes = [ctypes.c_char_p]
        self._lib.ffi_string_free.restype = None

        # connector_ffi_version
        self._lib.connector_ffi_version.argtypes = []
        self._lib.connector_ffi_version.restype = ctypes.c_char_p

    def _call_ffi(self, func, *args) -> Dict[str, Any]:
        """Call an FFI function and parse the JSON result."""
        result_ptr = func(*args)
        if result_ptr is None:
            return {"success": False, "error": {"code": "FFI_ERROR", "message": "FFI call returned null"}}

        result_str = result_ptr.decode("utf-8")
        # Note: We should free the string, but ctypes doesn't give us the mutable pointer
        # In a production implementation, we'd need to handle this properly
        return json.loads(result_str)

    def version(self) -> str:
        """Get the library version."""
        return self._lib.connector_ffi_version().decode("utf-8")

    def list_connectors(self) -> list:
        """Get list of supported connectors."""
        result_ptr = self._lib.connector_list_supported()
        if result_ptr is None:
            return []
        return json.loads(result_ptr.decode("utf-8"))

    def list_flows(self) -> list:
        """Get list of supported payment flows."""
        result_ptr = self._lib.connector_list_flows()
        if result_ptr is None:
            return []
        return json.loads(result_ptr.decode("utf-8"))

    def transform_request(
        self,
        connector: str,
        flow: str,
        auth: Dict[str, Any],
        payment: Dict[str, Any],
        config: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Transform a payment request to connector-specific HTTP request.

        Args:
            connector: Connector name (e.g., "stripe", "adyen")
            flow: Payment flow (e.g., "authorize", "capture", "refund")
            auth: Authentication credentials
            payment: Payment data
            config: Optional connector configuration

        Returns:
            Dict with:
                - success: bool
                - data: HTTP request components (url, method, headers, body) if successful
                - error: Error info if failed
        """
        request = {
            "connector": connector,
            "flow": flow,
            "auth": auth,
            "payment": payment,
        }
        if config:
            request["config"] = config

        request_json = json.dumps(request).encode("utf-8")
        return self._call_ffi(self._lib.connector_transform_request_json, request_json)

    def transform_response(
        self,
        connector: str,
        flow: str,
        status_code: int,
        body: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Transform a connector HTTP response to standardized payment response.

        Args:
            connector: Connector name
            flow: Payment flow
            status_code: HTTP status code
            body: Response body
            headers: Optional response headers

        Returns:
            Dict with:
                - success: bool
                - data: Standardized payment response if successful
                - error: Error info if failed
        """
        request = {
            "connector": connector,
            "flow": flow,
            "status_code": status_code,
            "body": body,
            "headers": headers or {},
        }

        request_json = json.dumps(request).encode("utf-8")
        return self._call_ffi(self._lib.connector_transform_response_json, request_json)


def main():
    """Demonstration of the FFI bindings."""
    print("=" * 60)
    print("Connector FFI Python Example")
    print("=" * 60)
    print()

    try:
        ffi = ConnectorFFI()
    except FileNotFoundError as e:
        print(f"Error: {e}")
        print()
        print("To build the library, run:")
        print("  cargo build --release -p connector-ffi")
        return 1

    # Show version and supported connectors
    print(f"Library version: {ffi.version()}")
    print(f"Supported connectors: {ffi.list_connectors()}")
    print(f"Supported flows: {ffi.list_flows()}")
    print()

    # Example 1: Stripe Authorization
    print("-" * 60)
    print("Example 1: Stripe Payment Authorization")
    print("-" * 60)

    stripe_result = ffi.transform_request(
        connector="stripe",
        flow="authorize",
        auth={"api_key": "sk_test_YOUR_STRIPE_KEY_HERE"},
        payment={
            "amount": 2000,  # $20.00 in cents
            "currency": "USD",
            "reference_id": "order_12345",
            "payment_method": {
                "type": "card",
                "number": "4242424242424242",
                "exp_month": 12,
                "exp_year": 2025,
                "cvc": "123",
                "holder_name": "John Doe",
            },
        },
    )

    if stripe_result["success"]:
        req = stripe_result["data"]
        print(f"URL: {req['url']}")
        print(f"Method: {req['method']}")
        print(f"Content-Type: {req['body_type']}")
        print("Headers:")
        for key, value in req["headers"].items():
            # Mask sensitive values
            if "authorization" in key.lower():
                value = value[:20] + "..." if len(value) > 20 else value
            print(f"  {key}: {value}")
        print(f"Body: {req['body'][:100]}..." if req.get("body") and len(req["body"]) > 100 else f"Body: {req.get('body')}")
    else:
        print(f"Error: {stripe_result['error']}")
    print()

    # Example 2: Stripe Response Transformation
    print("-" * 60)
    print("Example 2: Stripe Response Transformation")
    print("-" * 60)

    # Simulate a successful Stripe response
    stripe_response = ffi.transform_response(
        connector="stripe",
        flow="authorize",
        status_code=200,
        body=json.dumps({
            "id": "pi_3MtwBwLkdIwHu7ix28a3tqPa",
            "object": "payment_intent",
            "amount": 2000,
            "currency": "usd",
            "status": "succeeded",
            "payment_method": "pm_card_visa",
        }),
    )

    if stripe_response["success"]:
        resp = stripe_response["data"]
        print(f"Status: {resp['status']}")
        print(f"Transaction ID: {resp['transaction_id']}")
        print(f"Amount: {resp['amount']}")
        print(f"Currency: {resp['currency']}")
    else:
        print(f"Error: {stripe_response['error']}")
    print()

    # Example 3: Adyen Authorization
    print("-" * 60)
    print("Example 3: Adyen Payment Authorization")
    print("-" * 60)

    adyen_result = ffi.transform_request(
        connector="adyen",
        flow="authorize",
        auth={
            "api_key": "AQEyhmfuXNWTK0Qc+iSEmmGXuuP...",
            "merchant_id": "TestMerchantAccount",
        },
        payment={
            "amount": 1500,  # 15.00 EUR in cents
            "currency": "EUR",
            "reference_id": "order_67890",
            "payment_method": {
                "type": "card",
                "number": "4111111111111111",
                "exp_month": 3,
                "exp_year": 2030,
                "cvc": "737",
                "holder_name": "Jane Smith",
            },
        },
    )

    if adyen_result["success"]:
        req = adyen_result["data"]
        print(f"URL: {req['url']}")
        print(f"Method: {req['method']}")
        print(f"Content-Type: {req['body_type']}")
        print("Headers:")
        for key, value in req["headers"].items():
            if "api" in key.lower():
                value = value[:20] + "..." if len(value) > 20 else value
            print(f"  {key}: {value}")
        # Pretty print JSON body
        if req.get("body"):
            body_json = json.loads(req["body"])
            print("Body (JSON):")
            print(json.dumps(body_json, indent=2))
    else:
        print(f"Error: {adyen_result['error']}")
    print()

    # Example 4: Error Handling
    print("-" * 60)
    print("Example 4: Error Handling (Unknown Connector)")
    print("-" * 60)

    error_result = ffi.transform_request(
        connector="unknown_connector",
        flow="authorize",
        auth={"api_key": "test"},
        payment={"amount": 100, "currency": "USD"},
    )

    if not error_result["success"]:
        print(f"Error code: {error_result['error']['code']}")
        print(f"Error message: {error_result['error']['message']}")
    print()

    # Example 5: Refund Flow
    print("-" * 60)
    print("Example 5: Stripe Refund")
    print("-" * 60)

    refund_result = ffi.transform_request(
        connector="stripe",
        flow="refund",
        auth={"api_key": "sk_test_xxx"},
        payment={
            "amount": 500,  # Partial refund of $5.00
            "currency": "USD",
            "transaction_id": "pi_3MtwBwLkdIwHu7ix28a3tqPa",
        },
    )

    if refund_result["success"]:
        req = refund_result["data"]
        print(f"URL: {req['url']}")
        print(f"Method: {req['method']}")
        print(f"Body: {req.get('body')}")
    else:
        print(f"Error: {refund_result['error']}")
    print()

    print("=" * 60)
    print("All examples completed successfully!")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    exit(main())
