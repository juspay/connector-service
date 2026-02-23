#!/usr/bin/env python3
"""
UniFFI FFI example: authorize_req + full round-trip (Python)

Demonstrates two usage patterns:
  1. Low-level: call authorize_req_transformer directly to get the connector HTTP request JSON
  2. High-level: use ConnectorClient for a full round-trip (build → HTTP → parse)

All types come from proto codegen — Connector, ConnectorAuth, ConnectorConfig
follow the same pattern as Currency, CaptureMethod, etc.

Prerequisites (run `make setup` first):
  - generated/connector_service_ffi.py  (UniFFI bindings)
  - generated/payment_pb2.py            (protobuf stubs)
"""

import json
import os
import sys
from pathlib import Path

# Ensure generated modules and the SDK root are importable
SCRIPT_DIR = Path(__file__).resolve().parent
SDK_ROOT = SCRIPT_DIR.parent
sys.path.insert(0, str(SDK_ROOT / "generated"))
sys.path.insert(0, str(SDK_ROOT))

# UniFFI-generated Python module
from connector_service_ffi import authorize_req_transformer, UniffiError

# Protobuf-generated stubs
from payment_pb2 import (
    Connector,
    ConnectorAuth,
    ConnectorConfig,
    HeaderKeyAuth,
    PaymentServiceAuthorizeRequest,
    PaymentAddress,
)

# High-level client
from connector_client import ConnectorClient


def build_authorize_request_msg() -> PaymentServiceAuthorizeRequest:
    """Build a sample PaymentServiceAuthorizeRequest for Stripe card payment."""
    req = PaymentServiceAuthorizeRequest()

    # Identification
    req.request_ref_id.id = "test_payment_123456"

    # Payment details
    req.amount = 1000
    req.minor_amount = 1000
    req.currency = 1  # USD
    req.capture_method = 1  # AUTOMATIC

    # Card payment method
    card = req.payment_method.card
    card.card_number.value = "4111111111111111"
    card.card_exp_month.value = "12"
    card.card_exp_year.value = "2050"
    card.card_cvc.value = "123"
    card.card_holder_name.value = "Test User"

    # Customer info
    req.email.value = "customer@example.com"
    req.customer_name = "Test Customer"

    # Auth / 3DS
    req.auth_type = 1  # NO_THREE_DS
    req.enrolled_for_3ds = False

    # URLs
    req.return_url = "https://example.com/return"
    req.webhook_url = "https://example.com/webhook"

    # Address (required, but empty)
    req.address.CopyFrom(PaymentAddress())

    # Misc
    req.description = "Test payment"
    req.test_mode = True

    return req


def build_connector_config() -> ConnectorConfig:
    """Build ConnectorConfig for Stripe using proto types."""
    api_key = os.getenv("STRIPE_API_KEY", "sk_test_placeholder")
    return ConnectorConfig(
        connector=Connector.STRIPE,
        auth=ConnectorAuth(header_key=HeaderKeyAuth(api_key=api_key)),
    )


def demo_low_level_ffi():
    """Demo 1: Low-level FFI — build the connector HTTP request only."""
    print("=== Demo 1: Low-level FFI (authorize_req_transformer) ===\n")

    request_msg = build_authorize_request_msg()
    request_bytes = request_msg.SerializeToString()

    config = build_connector_config()
    config_bytes = config.SerializeToString()

    print(f"Request proto bytes: {len(request_bytes)} bytes")
    print(f"Config proto bytes:  {len(config_bytes)} bytes")
    print(f"Connector: STRIPE\n")

    try:
        connector_request_json = authorize_req_transformer(request_bytes, config_bytes, None)
        connector_request = json.loads(connector_request_json)

        print("Connector HTTP request generated successfully:")
        print(f"  URL:    {connector_request['url']}")
        print(f"  Method: {connector_request['method']}")
        print(
            f"  Headers: {list((connector_request.get('headers') or {}).keys())}"
        )
        print("\nFull request JSON:")
        print(json.dumps(connector_request, indent=2))

    except UniffiError.HandlerError as e:
        print("Handler returned an error (FFI boundary is working):")
        print(f"  {e}")
        print("\nThis is expected with placeholder data. To get a full request,")
        print("provide valid STRIPE_API_KEY and complete payment fields.")

    except UniffiError as e:
        print(f"FFI error: {e}", file=sys.stderr)
        sys.exit(1)


def demo_full_round_trip():
    """Demo 2: Full round-trip using ConnectorClient."""
    print("\n=== Demo 2: Full round-trip (ConnectorClient) ===\n")

    api_key = os.getenv("STRIPE_API_KEY", "")
    if not api_key or api_key == "sk_test_placeholder":
        print("Skipping full round-trip: STRIPE_API_KEY not set.")
        print("Run with: STRIPE_API_KEY=sk_test_xxx python3 example.py")
        return

    config = ConnectorConfig(
        connector=Connector.STRIPE,
        auth=ConnectorAuth(header_key=HeaderKeyAuth(api_key=api_key)),
    )
    client = ConnectorClient(config)
    request_msg = build_authorize_request_msg()

    print("Connector: STRIPE")
    print("Sending authorize request...\n")

    try:
        response = client.authorize(request_msg)
        print("Authorize response received:")
        print(f"  Status: {response.status}")
        print(f"  Response: {response}")

    except UniffiError as e:
        print(f"FFI error: {e}", file=sys.stderr)

    except Exception as e:
        print(f"Error during round-trip: {e}", file=sys.stderr)


if __name__ == "__main__":
    demo_low_level_ffi()
    demo_full_round_trip()
