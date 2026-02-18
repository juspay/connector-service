"""
UniFFI FFI example: authorize_req

Demonstrates calling the connector FFI directly from Python using
protobuf-encoded bytes at the boundary, without going through gRPC.

Flow:
  1. Build PaymentServiceAuthorizeRequest as a Python protobuf object
  2. Serialize it to bytes
  3. Pass bytes + metadata to authorize_req via UniFFI
  4. Receive back the connector HTTP request JSON

Prerequisites (run `make setup` first):
  - generated/connector_service_ffi.py  (UniFFI bindings)
  - generated/payment_pb2.py            (protobuf stubs)
"""

import json
import os
import sys

sys.path.insert(0, "./generated")

# UniFFI-generated Python module
from connector_service_ffi import authorize_req, UniffiError

# Protobuf-generated stubs (same protos as the gRPC example)
from payment_pb2 import PaymentServiceAuthorizeRequest


def build_authorize_request() -> bytes:
    """Build a PaymentServiceAuthorizeRequest and serialize to protobuf bytes."""
    req = PaymentServiceAuthorizeRequest()
    req.amount = 1000
    req.minor_amount = 1000
    req.currency = 3  # USD - see Currency enum in payment.proto

    # Minimal card payment method
    card = req.payment_method.card
    card.card_exp_month = "03"
    card.card_exp_year = "2030"
    card.card_cvc = "737"

    req.auth_type = 1  # THREE_DS

    return req.SerializeToString()


def build_metadata() -> dict:
    """
    Build the metadata map that the FFI layer uses for connector routing and auth.

    Keys:
      connector           - connector name (matches ConnectorEnum variant, snake_case)
      connector_auth_type - JSON-encoded ConnectorAuthType variant
    """
    return {
        "connector": "stripe",
        "connector_auth_type": json.dumps({
            "HeaderKey": {
                "api_key": os.getenv("STRIPE_API_KEY", "sk_test_placeholder")
            }
        }),
    }


def main():
    print("=== UniFFI FFI authorize_req example ===\n")

    request_bytes = build_authorize_request()
    metadata = build_metadata()

    print(f"Request proto bytes: {len(request_bytes)} bytes")
    print(f"Connector: {metadata['connector']}\n")

    try:
        connector_request_json = authorize_req(request_bytes, metadata)
        connector_request = json.loads(connector_request_json)

        print("Connector HTTP request generated successfully:")
        print(f"  URL:    {connector_request.get('url', 'N/A')}")
        print(f"  Method: {connector_request.get('method', 'N/A')}")
        print(f"  Headers: {list(connector_request.get('headers', {}).keys())}")
        print(f"\nFull request JSON:\n{json.dumps(connector_request, indent=2)}")

    except UniffiError as e:
        print(f"FFI error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
