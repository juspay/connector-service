"""
ConnectorClient — high-level wrapper around UniFFI FFI bindings.

Handles the full round-trip:
  1. Serialize protobuf request to bytes
  2. Build connector HTTP request via authorize_req_transformer (UniFFI FFI)
  3. Execute the HTTP request via HttpClient
  4. Parse the connector response via authorize_res_transformer (UniFFI FFI)
  5. Deserialize protobuf response from bytes

Mirrors the Node.js client at sdk/javascript/src/payments/connector_client.ts.
"""

from .http_client import execute, HttpRequest, create_session, resolve_proxy_config, Defaults
from .generated.payment_pb2 import PaymentServiceAuthorizeResponse, PaymentServiceAuthorizeRequest
from .generated.sdk_options_pb2 import Options, FfiOptions, FfiConnectorHttpRequest, FfiConnectorHttpResponse
from .generated.connector_service_ffi import authorize_req_transformer, authorize_res_transformer
from typing import Dict, Optional

class ConnectorClient:
    """High-level client for connector payment operations via UniFFI FFI."""

    def __init__(self, lib_path: Optional[str] = None, options: Optional[Options] = None):
        """
        Initialize the client.
        
        Args:
            lib_path: Optional path to the shared library.
            options: Unified SDK configuration (http, ffi).
        """
        self.options = options or Options()
        # Instance-level cache: create the primary connection pool at startup
        self.session = create_session(self.options.http)

    def authorize(self, request: PaymentServiceAuthorizeRequest, metadata: dict, ffi_options: FfiOptions = None) -> PaymentServiceAuthorizeResponse:
        """Execute a full authorize round-trip: FFI request build -> HTTP -> FFI response parse.

        Args:
            request: A PaymentServiceAuthorizeRequest protobuf message.
            metadata: Dict with connector routing and auth info. Must include:
                - "connector": connector name (e.g. "Stripe")
                - "connector_auth_type": JSON string of auth config
                - x-* headers for masked metadata
            ffi_options: Optional FfiOptions protobuf message override.

        Returns:
            PaymentServiceAuthorizeResponse protobuf message.
        """
        # Step 1: Serialize the protobuf request to bytes
        request_bytes = request.SerializeToString()

        # Resolve FFI options (prefer call-specific override)
        ffi = ffi_options or self.options.ffi
        options_bytes = ffi.SerializeToString() if ffi else b""

        # Step 2: Build the connector HTTP request via FFI (returns Protobuf bytes)
        # The FFI transformer handles the mapping from domain types to raw HTTP details.
        result_bytes = authorize_req_transformer(request_bytes, metadata, options_bytes)
        connector_req = FfiConnectorHttpRequest.FromString(result_bytes)
        
        connector_request = HttpRequest(
            url=connector_req.url,
            method=connector_req.method,
            headers=dict(connector_req.headers),
            body=connector_req.body
        )

        # Step 3: Execute the HTTP request using the instance-owned pool
        # We resolve the proxy configuration specifically for this target URL.
        proxy_config = resolve_proxy_config(connector_req.url, self.options.http.proxy)
        
        # Map Protobuf timeouts to primitive floats for the engine
        http = self.options.http
        response = execute(
            connector_request, 
            self.session,
            connect_timeout_ms=float(http.connect_timeout_ms or Defaults.CONNECT_TIMEOUT_MS),
            response_timeout_ms=float(http.response_timeout_ms or Defaults.RESPONSE_TIMEOUT_MS),
            total_timeout_ms=float(http.total_timeout_ms or Defaults.TOTAL_TIMEOUT_MS),
            proxy_config=proxy_config
        )

        # Step 4: Parse the connector response via FFI
        # We wrap the native response in an internal FFI Protobuf record for safe binary transport.
        res_proto = FfiConnectorHttpResponse(
            status_code=response.status_code,
            headers=response.headers,
            body=response.body
        )
        res_bytes = res_proto.SerializeToString()

        result_bytes_res = authorize_res_transformer(
            res_bytes,
            request_bytes,
            metadata,
            options_bytes
        )

        # Step 5: Deserialize the final domain protobuf response
        response_msg = PaymentServiceAuthorizeResponse()
        response_msg.ParseFromString(result_bytes_res)
        return response_msg
