"""
ConnectorClient — high-level wrapper around UniFFI FFI bindings.

Handles the full round-trip:
  1. Serialize protobuf request to bytes
  2. Build connector HTTP request via authorize_req_transformer (UniFFI FFI)
  3. Execute the HTTP request via our standardized HttpClient
  4. Parse the connector response via authorize_res_transformer (UniFFI FFI)
  5. Deserialize protobuf response from bytes
"""

from . import http_client
from .generated import connector_service_ffi
from .generated import payment_pb2
from .generated import sdk_options_pb2


class ConnectorClient:
    """High-level client for connector payment operations via UniFFI FFI."""

    def __init__(self, options: sdk_options_pb2.Options = None):
        """Initialize with unified Options struct."""
        self.options = options or sdk_options_pb2.Options()

    def _get_options_bytes(self, ffi_options=None) -> bytes:
        # Resolve FFI options (prefer call-specific, fallback to client-global)
        ffi = ffi_options or self.options.ffi
        if not ffi:
            return b''
        return ffi.SerializeToString()

    def authorize(self, request, metadata: dict, ffi_options=None) -> payment_pb2.PaymentServiceAuthorizeResponse:
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
        # 1. Serialize request to bytes
        request_bytes = request.SerializeToString()
        options_bytes = self._get_options_bytes(ffi_options)

        # 2. Build the connector HTTP request via FFI bridge
        connector_request = connector_service_ffi.authorize_req_transformer(request_bytes, metadata, options_bytes)

        # 3. Execute the HTTP request (uses Global HttpOptions)
        http_req = http_client.HttpRequest(
            url=connector_request.url,
            method=connector_request.method,
            headers=connector_request.headers,
            body=connector_request.body
        )
        http_response = http_client.execute(http_req, self.options.http)

        # 4. Parse the connector response via FFI bridge
        ffi_res = connector_service_ffi.FfiConnectorHttpResponse(
            status_code=http_response.status_code,
            headers=http_response.headers,
            body=http_response.body
        )
        
        result_bytes = connector_service_ffi.authorize_res_transformer(
            ffi_res,
            request_bytes,
            metadata,
            options_bytes,
        )

        # 5. Decode the protobuf response from bytes
        result = payment_pb2.PaymentServiceAuthorizeResponse()
        result.ParseFromString(result_bytes)
        return result
