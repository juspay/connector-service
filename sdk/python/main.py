"""
UniFFI FFI example: authorize_req + full round-trip

Demonstrates two usage patterns:
  1. Low-level: call authorize_req directly to get the connector HTTP request JSON
  2. High-level: use ConnectorClient for a full round-trip (build -> HTTP -> parse)

Prerequisites (run `make setup` first):
  - generated/connector_service_ffi.py  (UniFFI bindings)
  - generated/payment_pb2.py            (protobuf stubs)
"""

import json
import os
import sys

sys.path.insert(0, "./generated")

# UniFFI-generated Python module
from connector_service_ffi import authorize_req_transformer, UniffiError

# Protobuf-generated stubs
from payment_pb2 import PaymentServiceAuthorizeRequest, PaymentAddress

# High-level client
from connector_client import ConnectorClient


def build_authorize_request_msg() -> PaymentServiceAuthorizeRequest:
    """Build a PaymentServiceAuthorizeRequest protobuf message.

    Field structure mirrors sdk/node-ffi-client/tests/test_node.js PAYLOAD.
    Proto message fields that are themselves messages (SecretString, CardNumberType)
    require setting the inner .value field.
    """
    req = PaymentServiceAuthorizeRequest()

    # Identification
    req.request_ref_id.id = "test_payment_123456"

    # Payment details
    req.amount = 1000
    req.minor_amount = 1000
    req.currency = 146           # USD (payment.proto enum)
    req.capture_method = 1       # AUTOMATIC

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
    req.auth_type = 2            # NO_THREE_DS
    req.enrolled_for_3ds = False

    # URLs
    req.return_url = "https://example.com/return"
    req.webhook_url = "https://example.com/webhook"

    # Address (required)
    req.address.CopyFrom(PaymentAddress())

    # Misc
    req.description = "Test payment"
    req.test_mode = True

    return req


def build_metadata() -> dict:
    """
    Build the metadata map that the FFI layer uses for connector routing and auth.

    Two purposes:
      1. parse_metadata() extracts "connector" and "connector_auth_type"
         to build FFIMetadataPayload
      2. ffi_headers_to_masked_metadata() reads x-* headers to build
         MaskedMetadata for the handler
    """
    api_key = os.getenv("STRIPE_API_KEY", "sk_test_placeholder")
    return {
        # Connector routing (used by parse_metadata to build FFIMetadataPayload)
        "connector": "Stripe",
        # ConnectorAuthType uses serde internally-tagged enum: #[serde(tag = "auth_type")]
        "connector_auth_type": json.dumps({
            "auth_type": "HeaderKey",
            "api_key": api_key,
        }),
        # Required metadata headers (used by ffi_headers_to_masked_metadata)
        "x-connector": "Stripe",
        "x-merchant-id": "test_merchant_123",
        "x-request-id": "test-request-001",
        "x-tenant-id": "public",
        "x-auth": "body-key",
        # Optional headers
        "x-api-key": api_key,
    }


def demo_low_level_ffi():
    """Demo 1: Low-level FFI — build the connector HTTP request only."""
    print("=== Demo 1: Low-level FFI (authorize_req_transformer) ===\n")

    request_msg = build_authorize_request_msg()
    request_bytes = request_msg.SerializeToString()
    metadata = build_metadata()

    print(f"Request proto bytes: {len(request_bytes)} bytes")
    print(f"Connector: {metadata['connector']}\n")

    try:
        connector_request_json = authorize_req_transformer(request_bytes, metadata)
        connector_request = json.loads(connector_request_json)

        print("Connector HTTP request generated successfully:")
        print(f"  URL:    {connector_request.get('url', 'N/A')}")
        print(f"  Method: {connector_request.get('method', 'N/A')}")
        print(f"  Headers: {list(connector_request.get('headers', {}).keys())}")
        print(f"\nFull request JSON:\n{json.dumps(connector_request, indent=2)}")

    except UniffiError.HandlerError as e:
        print(f"Handler returned an error (FFI boundary is working):")
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
        print("Run with: STRIPE_API_KEY=sk_test_xxx python3 main.py")
        return

    client = ConnectorClient()
    request_msg = build_authorize_request_msg()
    metadata = build_metadata()

    print(f"Connector: {metadata['connector']}")
    print(f"Sending authorize request...\n")

    try:
        response = client.authorize(request_msg, metadata)
        print("Authorize response received:")
        print(f"  Status: {response.status}")
        print(f"  Response: {response}")

    except UniffiError as e:
        print(f"FFI error: {e}", file=sys.stderr)

    except Exception as e:
        print(f"Error during round-trip: {e}", file=sys.stderr)


def main():
    demo_low_level_ffi()
    demo_full_round_trip()


if __name__ == "__main__":
    main()
