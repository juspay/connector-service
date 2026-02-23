"""
ConnectorClient — high-level wrapper around UniFFI FFI bindings.

Handles the full round-trip:
  1. Build connector HTTP request via authorize_req_transformer (FFI)
  2. Execute the HTTP request via requests library
  3. Parse the connector response via authorize_res_transformer (FFI)

All types (Connector, ConnectorAuth, ConnectorConfig) come from proto
codegen — same pattern as Currency, CaptureMethod, etc.
"""

import json

import requests as http_requests

from connector_service_ffi import authorize_req_transformer, authorize_res_transformer
from payment_pb2 import (
    Connector,
    ConnectorAuth,
    ConnectorConfig,
    HeaderKeyAuth,
    BodyKeyAuth,
    SignatureKeyAuth,
    MultiAuthKeyAuth,
    CertificateAuth,
    NoKeyAuth,
    TemporaryAuth,
    PaymentServiceAuthorizeResponse,
)


# ── ConnectorClient ────────────────────────────────────────────────────────────


class ConnectorClient:
    """High-level client for connector payment operations via UniFFI FFI.

    All types come from proto codegen (payment.proto, package ucs.v2).
    Same pattern as Currency, CaptureMethod, etc.

    Example:
        config = ConnectorConfig(
            connector=Connector.STRIPE,
            auth=ConnectorAuth(header_key=HeaderKeyAuth(api_key="sk_test_...")),
        )
        client = ConnectorClient(config)
    """

    def __init__(self, config: ConnectorConfig, default_options=None):
        """Create a ConnectorClient configured for a single connector.

        Args:
            config: An ConnectorConfig proto message bundling connector + auth.
            default_options: Reserved for future use.
        """
        # Pre-serialize config to proto bytes (same pattern as request)
        self._config_bytes = config.SerializeToString()
        self.default_options = default_options or {}

    def authorize(
        self, request, call_options=None
    ) -> PaymentServiceAuthorizeResponse:
        """Execute a full authorize round-trip: FFI request build -> HTTP -> FFI response parse.

        Args:
            request: A PaymentServiceAuthorizeRequest protobuf message.
            call_options: Per-call overrides (reserved for future use).

        Returns:
            PaymentServiceAuthorizeResponse protobuf message.
        """
        # Step 1: Serialize the protobuf request to bytes
        request_bytes = request.SerializeToString()

        # Step 2: Build the connector HTTP request via FFI
        connector_request_json = authorize_req_transformer(
            request_bytes, self._config_bytes, None
        )
        connector_request = json.loads(connector_request_json)

        url = connector_request["url"]
        method = connector_request["method"]
        headers = connector_request.get("headers", {})
        body = connector_request.get("body")

        # Body may be a dict/object — serialize to string for the HTTP call
        if body is not None and not isinstance(body, (str, bytes)):
            body = json.dumps(body)

        # Step 3: Execute the HTTP request
        response = http_requests.request(method, url, headers=headers, data=body)

        # Step 4: Parse the connector response via FFI
        response_body = response.text.encode("utf-8")
        response_headers = dict(response.headers)
        result_bytes = authorize_res_transformer(
            response_body,
            response.status_code,
            response_headers,
            request_bytes,
            self._config_bytes,
            None,
        )

        # Step 5: Deserialize the protobuf response
        result = PaymentServiceAuthorizeResponse()
        result.ParseFromString(result_bytes)
        return result
