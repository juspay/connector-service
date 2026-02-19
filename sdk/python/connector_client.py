"""
ConnectorClient — high-level wrapper around UniFFI FFI bindings.

Handles the full round-trip:
  1. Build connector HTTP request via authorize_req (FFI)
  2. Execute the HTTP request via requests library
  3. Parse the connector response via authorize_res (FFI)

Mirrors the Node.js client at sdk/node-ffi-client/src/client.js.
"""

import json

import requests as http_requests

from connector_service_ffi import authorize_req, authorize_res
from payment_pb2 import PaymentServiceAuthorizeResponse


class ConnectorClient:
    """High-level client for connector payment operations via UniFFI FFI."""

    def authorize(self, request, metadata: dict) -> PaymentServiceAuthorizeResponse:
        """Execute a full authorize round-trip: FFI request build -> HTTP -> FFI response parse.

        Args:
            request: A PaymentServiceAuthorizeRequest protobuf message.
            metadata: Dict with connector routing and auth info. Must include:
                - "connector": connector name (e.g. "Stripe")
                - "connector_auth_type": JSON string of auth config
                - x-* headers for masked metadata

        Returns:
            PaymentServiceAuthorizeResponse protobuf message.
        """
        # Step 1: Serialize the protobuf request to bytes
        request_bytes = request.SerializeToString()

        # Step 2: Build the connector HTTP request via FFI
        connector_request_json = authorize_req(request_bytes, metadata)
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
        result_bytes = authorize_res(
            response_body,
            response.status_code,
            response_headers,
            request_bytes,
            metadata,
        )

        # Step 5: Deserialize the protobuf response
        result = PaymentServiceAuthorizeResponse()
        result.ParseFromString(result_bytes)
        return result
