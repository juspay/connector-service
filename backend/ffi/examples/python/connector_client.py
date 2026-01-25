#!/usr/bin/env python3
"""
Connector Client - High-Level Payment Processing API

This module provides a high-level Python API for payment processing using
the connector-service FFI. It wraps the low-level FFI calls and HTTP execution
into simple flow methods like `authorize()`, `capture()`, `refund()`, etc.

Usage:
    from connector_client import ConnectorClient, PaymentMethod

    # Create a client for Stripe
    client = ConnectorClient(
        connector="stripe",
        auth={"api_key": "sk_test_xxx"}
    )

    # Authorize a payment
    result = client.authorize(
        amount=1000,
        currency="USD",
        payment_method=PaymentMethod.card(
            number="4242424242424242",
            exp_month=12,
            exp_year=2025,
            cvc="123"
        )
    )

    if result.success:
        print(f"Payment authorized: {result.transaction_id}")

        # Capture the payment
        capture_result = client.capture(
            transaction_id=result.transaction_id,
            amount=1000
        )
"""

import json
import ctypes
import platform
import urllib.request
import urllib.error
import ssl
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from enum import Enum


class PaymentStatus(Enum):
    """Standardized payment status."""
    SUCCEEDED = "succeeded"
    AUTHORIZED = "authorized"
    PENDING = "pending"
    FAILED = "failed"
    CANCELLED = "cancelled"
    REQUIRES_ACTION = "requires_action"
    UNKNOWN = "unknown"


@dataclass
class PaymentMethod:
    """Payment method data."""
    type: str
    data: Dict[str, Any]

    @classmethod
    def card(
        cls,
        number: str,
        exp_month: int,
        exp_year: int,
        cvc: str,
        holder_name: Optional[str] = None
    ) -> "PaymentMethod":
        """Create a card payment method."""
        data = {
            "type": "card",
            "number": number,
            "exp_month": exp_month,
            "exp_year": exp_year,
            "cvc": cvc,
        }
        if holder_name:
            data["holder_name"] = holder_name
        return cls(type="card", data=data)

    @classmethod
    def wallet(cls, wallet_type: str, token: str) -> "PaymentMethod":
        """Create a wallet payment method."""
        return cls(type="wallet", data={
            "type": "wallet",
            "wallet_type": wallet_type,
            "token": token
        })

    @classmethod
    def bank_transfer(
        cls,
        bank_code: Optional[str] = None,
        account_number: Optional[str] = None
    ) -> "PaymentMethod":
        """Create a bank transfer payment method."""
        return cls(type="bank_transfer", data={
            "type": "banktransfer",
            "bank_code": bank_code,
            "account_number": account_number
        })


@dataclass
class PaymentResult:
    """Result of a payment operation."""
    success: bool
    status: PaymentStatus
    transaction_id: Optional[str] = None
    amount: Optional[int] = None
    currency: Optional[str] = None
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    redirect_url: Optional[str] = None
    raw_response: Optional[Dict] = None
    http_status_code: Optional[int] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any], http_status: Optional[int] = None) -> "PaymentResult":
        """Create PaymentResult from dictionary."""
        status_str = data.get("status", "unknown")
        try:
            status = PaymentStatus(status_str)
        except ValueError:
            status = PaymentStatus.UNKNOWN

        return cls(
            success=status in (PaymentStatus.SUCCEEDED, PaymentStatus.AUTHORIZED),
            status=status,
            transaction_id=data.get("transaction_id"),
            amount=data.get("amount"),
            currency=data.get("currency"),
            error_code=data.get("error_code"),
            error_message=data.get("error_message"),
            redirect_url=data.get("redirect_url"),
            raw_response=data.get("raw_response"),
            http_status_code=http_status,
        )

    @classmethod
    def error(cls, code: str, message: str) -> "PaymentResult":
        """Create an error result."""
        return cls(
            success=False,
            status=PaymentStatus.FAILED,
            error_code=code,
            error_message=message,
        )


@dataclass
class ConnectorInfo:
    """Information about a connector."""
    name: str
    display_name: str
    base_url: str
    auth_type: str
    auth_fields: List[str]
    supported_flows: List[str]
    supported_currencies: List[str]
    body_format: str


class HttpClient:
    """
    HTTP client for making requests to payment connectors.

    Uses urllib for simplicity. In production, consider using
    requests, httpx, or aiohttp for better features.
    """

    def __init__(self, timeout: int = 30, verify_ssl: bool = True):
        """
        Initialize the HTTP client.

        Args:
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
        """
        self.timeout = timeout
        self.verify_ssl = verify_ssl

        if not verify_ssl:
            self._ssl_context = ssl.create_default_context()
            self._ssl_context.check_hostname = False
            self._ssl_context.verify_mode = ssl.CERT_NONE
        else:
            self._ssl_context = None

    def request(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        body: Optional[str] = None,
        body_type: str = "json"
    ) -> tuple:
        """
        Make an HTTP request.

        Args:
            method: HTTP method (GET, POST, etc.)
            url: Request URL
            headers: Request headers
            body: Request body
            body_type: Body type (json, form)

        Returns:
            Tuple of (status_code, response_body, response_headers)
        """
        # Encode body
        data = body.encode("utf-8") if body else None

        # Create request
        req = urllib.request.Request(
            url,
            data=data,
            headers=headers,
            method=method.upper()
        )

        try:
            if self._ssl_context:
                response = urllib.request.urlopen(
                    req, timeout=self.timeout, context=self._ssl_context
                )
            else:
                response = urllib.request.urlopen(req, timeout=self.timeout)

            status_code = response.getcode()
            response_body = response.read().decode("utf-8")
            response_headers = dict(response.headers)

            return status_code, response_body, response_headers

        except urllib.error.HTTPError as e:
            status_code = e.code
            response_body = e.read().decode("utf-8") if e.fp else ""
            response_headers = dict(e.headers) if e.headers else {}

            return status_code, response_body, response_headers

        except urllib.error.URLError as e:
            raise ConnectionError(f"Failed to connect: {e.reason}")
        except Exception as e:
            raise ConnectionError(f"Request failed: {str(e)}")


class ConnectorFFILib:
    """Low-level FFI bindings."""

    _instance = None

    def __new__(cls, library_path: Optional[str] = None):
        """Singleton pattern for FFI library."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, library_path: Optional[str] = None):
        """Initialize FFI bindings."""
        if self._initialized:
            return

        if library_path is None:
            library_path = self._find_library()

        self._lib = ctypes.CDLL(library_path)
        self._setup_functions()
        self._initialized = True

    def _find_library(self) -> str:
        """Find the shared library."""
        system = platform.system()
        if system == "Linux":
            lib_name = "libconnector_ffi.so"
        elif system == "Darwin":
            lib_name = "libconnector_ffi.dylib"
        elif system == "Windows":
            lib_name = "connector_ffi.dll"
        else:
            raise RuntimeError(f"Unsupported platform: {system}")

        search_paths = [
            Path.cwd() / lib_name,
            Path(__file__).parent / lib_name,
            Path(__file__).parent.parent.parent / "target" / "release" / lib_name,
            Path(__file__).parent.parent.parent.parent.parent / "target" / "release" / lib_name,
        ]

        for path in search_paths:
            if path.exists():
                return str(path)

        raise FileNotFoundError(
            f"Could not find {lib_name}. "
            f"Build with 'cargo build --release -p connector-ffi'"
        )

    def _setup_functions(self):
        """Setup FFI function signatures."""
        self._lib.connector_transform_request_json.argtypes = [ctypes.c_char_p]
        self._lib.connector_transform_request_json.restype = ctypes.c_char_p

        self._lib.connector_transform_response_json.argtypes = [ctypes.c_char_p]
        self._lib.connector_transform_response_json.restype = ctypes.c_char_p

        self._lib.connector_list_supported.argtypes = []
        self._lib.connector_list_supported.restype = ctypes.c_char_p

        self._lib.connector_list_flows.argtypes = []
        self._lib.connector_list_flows.restype = ctypes.c_char_p

        self._lib.connector_get_info.argtypes = [ctypes.c_char_p]
        self._lib.connector_get_info.restype = ctypes.c_char_p

        self._lib.connector_ffi_version.argtypes = []
        self._lib.connector_ffi_version.restype = ctypes.c_char_p

    def transform_request(self, request: Dict) -> Dict:
        """Transform a payment request."""
        request_json = json.dumps(request).encode("utf-8")
        result_ptr = self._lib.connector_transform_request_json(request_json)
        if result_ptr:
            return json.loads(result_ptr.decode("utf-8"))
        return {"success": False, "error": {"code": "FFI_ERROR", "message": "FFI returned null"}}

    def transform_response(self, response: Dict) -> Dict:
        """Transform a connector response."""
        response_json = json.dumps(response).encode("utf-8")
        result_ptr = self._lib.connector_transform_response_json(response_json)
        if result_ptr:
            return json.loads(result_ptr.decode("utf-8"))
        return {"success": False, "error": {"code": "FFI_ERROR", "message": "FFI returned null"}}

    def get_connector_info(self, connector: str) -> Dict:
        """Get connector information."""
        result_ptr = self._lib.connector_get_info(connector.encode("utf-8"))
        if result_ptr:
            return json.loads(result_ptr.decode("utf-8"))
        return {"success": False, "error": {"code": "FFI_ERROR", "message": "FFI returned null"}}

    def list_connectors(self) -> List[str]:
        """List supported connectors."""
        result_ptr = self._lib.connector_list_supported()
        if result_ptr:
            return json.loads(result_ptr.decode("utf-8"))
        return []

    def list_flows(self) -> List[str]:
        """List supported flows."""
        result_ptr = self._lib.connector_list_flows()
        if result_ptr:
            return json.loads(result_ptr.decode("utf-8"))
        return []

    def version(self) -> str:
        """Get library version."""
        return self._lib.connector_ffi_version().decode("utf-8")


class ConnectorClient:
    """
    High-level payment connector client.

    Provides simple methods for common payment operations that handle
    the full flow: request transformation -> HTTP execution -> response transformation.
    """

    def __init__(
        self,
        connector: str,
        auth: Dict[str, str],
        config: Optional[Dict[str, Any]] = None,
        http_client: Optional[HttpClient] = None,
        library_path: Optional[str] = None,
    ):
        """
        Initialize the connector client.

        Args:
            connector: Connector name (e.g., "stripe", "adyen")
            auth: Authentication credentials
            config: Optional connector configuration (e.g., custom base_url)
            http_client: Optional custom HTTP client
            library_path: Optional path to FFI library
        """
        self.connector = connector
        self.auth = auth
        self.config = config
        self.http = http_client or HttpClient()
        self._ffi = ConnectorFFILib(library_path)

        # Validate connector
        info_result = self._ffi.get_connector_info(connector)
        if not info_result.get("success"):
            raise ValueError(f"Unknown connector: {connector}")

        self._info = ConnectorInfo(**info_result["data"])

    @property
    def info(self) -> ConnectorInfo:
        """Get connector information."""
        return self._info

    def _execute_flow(
        self,
        flow: str,
        payment: Dict[str, Any],
    ) -> PaymentResult:
        """
        Execute a payment flow.

        Args:
            flow: Flow name (authorize, capture, etc.)
            payment: Payment data

        Returns:
            PaymentResult with operation outcome
        """
        # Step 1: Transform request
        transform_input = {
            "connector": self.connector,
            "flow": flow,
            "auth": self.auth,
            "payment": payment,
        }
        if self.config:
            transform_input["config"] = self.config

        request_result = self._ffi.transform_request(transform_input)

        if not request_result.get("success"):
            error = request_result.get("error", {})
            return PaymentResult.error(
                error.get("code", "TRANSFORM_ERROR"),
                error.get("message", "Request transformation failed")
            )

        http_request = request_result["data"]

        # Step 2: Execute HTTP request
        try:
            status_code, response_body, _ = self.http.request(
                method=http_request["method"],
                url=http_request["url"],
                headers=http_request["headers"],
                body=http_request.get("body"),
                body_type=http_request.get("body_type", "json"),
            )
        except ConnectionError as e:
            return PaymentResult.error("CONNECTION_ERROR", str(e))
        except Exception as e:
            return PaymentResult.error("HTTP_ERROR", str(e))

        # Step 3: Transform response
        response_input = {
            "connector": self.connector,
            "flow": flow,
            "status_code": status_code,
            "body": response_body,
        }

        response_result = self._ffi.transform_response(response_input)

        if not response_result.get("success"):
            error = response_result.get("error", {})
            return PaymentResult.error(
                error.get("code", "TRANSFORM_ERROR"),
                error.get("message", "Response transformation failed")
            )

        return PaymentResult.from_dict(response_result["data"], status_code)

    def authorize(
        self,
        amount: int,
        currency: str,
        payment_method: Optional[PaymentMethod] = None,
        reference_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> PaymentResult:
        """
        Authorize a payment.

        Args:
            amount: Amount in minor units (e.g., cents)
            currency: 3-letter currency code
            payment_method: Payment method details
            reference_id: Optional reference ID
            metadata: Optional metadata

        Returns:
            PaymentResult with authorization outcome
        """
        payment = {
            "amount": amount,
            "currency": currency,
        }
        if payment_method:
            payment["payment_method"] = payment_method.data
        if reference_id:
            payment["reference_id"] = reference_id
        if metadata:
            payment["metadata"] = metadata

        return self._execute_flow("authorize", payment)

    def capture(
        self,
        transaction_id: str,
        amount: Optional[int] = None,
        currency: str = "USD",
    ) -> PaymentResult:
        """
        Capture a previously authorized payment.

        Args:
            transaction_id: Original transaction ID
            amount: Amount to capture (optional, captures full amount if not specified)
            currency: Currency code

        Returns:
            PaymentResult with capture outcome
        """
        payment = {
            "transaction_id": transaction_id,
            "currency": currency,
        }
        if amount is not None:
            payment["amount"] = amount
        else:
            payment["amount"] = 0  # Will use original amount

        return self._execute_flow("capture", payment)

    def void(
        self,
        transaction_id: str,
        currency: str = "USD",
    ) -> PaymentResult:
        """
        Void/cancel a payment.

        Args:
            transaction_id: Transaction ID to void
            currency: Currency code

        Returns:
            PaymentResult with void outcome
        """
        payment = {
            "transaction_id": transaction_id,
            "amount": 0,
            "currency": currency,
        }

        return self._execute_flow("void", payment)

    def refund(
        self,
        transaction_id: str,
        amount: int,
        currency: str = "USD",
        reason: Optional[str] = None,
    ) -> PaymentResult:
        """
        Refund a payment.

        Args:
            transaction_id: Original transaction ID
            amount: Amount to refund in minor units
            currency: Currency code
            reason: Optional refund reason

        Returns:
            PaymentResult with refund outcome
        """
        payment = {
            "transaction_id": transaction_id,
            "amount": amount,
            "currency": currency,
        }
        if reason:
            payment["metadata"] = {"refund_reason": reason}

        return self._execute_flow("refund", payment)

    def sync(
        self,
        transaction_id: str,
        currency: str = "USD",
    ) -> PaymentResult:
        """
        Get the current status of a payment.

        Args:
            transaction_id: Transaction ID to check
            currency: Currency code

        Returns:
            PaymentResult with current status
        """
        payment = {
            "transaction_id": transaction_id,
            "amount": 0,
            "currency": currency,
        }

        return self._execute_flow("sync", payment)


# Convenience functions for quick access
def list_connectors() -> List[str]:
    """List all supported connectors."""
    return ConnectorFFILib().list_connectors()


def list_flows() -> List[str]:
    """List all supported payment flows."""
    return ConnectorFFILib().list_flows()


def get_connector_info(connector: str) -> Optional[ConnectorInfo]:
    """Get information about a specific connector."""
    result = ConnectorFFILib().get_connector_info(connector)
    if result.get("success"):
        return ConnectorInfo(**result["data"])
    return None


def version() -> str:
    """Get the FFI library version."""
    return ConnectorFFILib().version()


# Example usage and testing
if __name__ == "__main__":
    print("=" * 70)
    print("Connector Client Demo")
    print("=" * 70)
    print()

    # Show library info
    print(f"Library version: {version()}")
    print(f"Supported connectors: {list_connectors()}")
    print(f"Supported flows: {list_flows()}")
    print()

    # Show connector info
    print("-" * 70)
    print("Connector Information")
    print("-" * 70)
    for connector in ["stripe", "adyen", "forte"]:
        info = get_connector_info(connector)
        if info:
            print(f"\n{info.display_name}:")
            print(f"  Auth fields: {info.auth_fields}")
            print(f"  Flows: {info.supported_flows}")
            print(f"  Currencies: {info.supported_currencies}")
    print()

    # Demo payment flow (will fail without real credentials)
    print("-" * 70)
    print("Payment Flow Demo (Mock)")
    print("-" * 70)
    print()

    try:
        # This will fail at HTTP level without real credentials,
        # but demonstrates the API
        client = ConnectorClient(
            connector="stripe",
            auth={"api_key": "sk_test_YOUR_KEY_HERE"}
        )

        print(f"Created client for: {client.info.display_name}")
        print(f"Base URL: {client.info.base_url}")
        print()

        # Authorize payment
        print("Attempting payment authorization...")
        result = client.authorize(
            amount=2000,
            currency="USD",
            payment_method=PaymentMethod.card(
                number="4242424242424242",
                exp_month=12,
                exp_year=2025,
                cvc="123",
                holder_name="Test User"
            ),
            reference_id="test_order_001"
        )

        print(f"Result: {result.status.value}")
        if result.success:
            print(f"Transaction ID: {result.transaction_id}")
        else:
            print(f"Error: {result.error_code} - {result.error_message}")

    except FileNotFoundError as e:
        print(f"Library not found: {e}")
        print("Build with: cargo build --release -p connector-ffi")
    except Exception as e:
        print(f"Demo error (expected without real credentials): {e}")

    print()
    print("=" * 70)
    print("Demo complete!")
    print("=" * 70)
