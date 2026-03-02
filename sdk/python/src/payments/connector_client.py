"""
ConnectorClient — high-level wrapper around UniFFI FFI bindings.

Handles the full round-trip:
  1. Build connector HTTP request via authorize_req_transformer (FFI)
  2. Execute the HTTP request via HttpClient
  3. Parse the connector response via authorize_res_transformer (FFI)
"""

from . import http_client
from .generated import connector_service_ffi
from .generated import payment_pb2
from .generated import sdk_options_pb2


class ConnectorClient:
    """High-level client for connector payment operations via UniFFI FFI."""

    def __init__(self, options=None):
        self.options = options or {}

    def _get_options_bytes(self, ffi_options=None) -> bytes:
        opts = sdk_options_pb2.FfiOptions()
        opts.env.test_mode = self.options.get("test_mode", True)
        if ffi_options:
            opts.MergeFrom(ffi_options)
        return opts.SerializeToString()

    def authorize(self, request, metadata: dict, ffi_options=None) -> payment_pb2.PaymentServiceAuthorizeResponse:
        """Execute a full authorize round-trip: FFI request build -> HTTP -> FFI response parse.

        Args:
            request: A PaymentServiceAuthorizeRequest protobuf message.
            metadata: Dict with connector routing and auth info. Must include:
                - "connector": connector name (e.g. "Stripe")
                - "connector_auth_type": JSON string of auth config
                - x-* headers for masked metadata
            options: Optional FfiOptions protobuf message with ffi configuration.

        Returns:
            PaymentServiceAuthorizeResponse protobuf message.
        """
        request_bytes = request.SerializeToString()
        options_bytes = self._get_options_bytes(ffi_options)

        # 1. Build Request via FFI
        connector_request = connector_service_ffi.authorize_req_transformer(request_bytes, metadata, options_bytes)

        # 2. Execute HTTP
        http_req = http_client.HttpRequest(
            url=connector_request.url,
            method=connector_request.method,
            headers=connector_request.headers,
            body=connector_request.body
        )
        http_response = http_client.execute(http_req, self.options)

        # 3. Parse Response via FFI
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

        # 4. Decode Result
        result = payment_pb2.PaymentServiceAuthorizeResponse()
        result.ParseFromString(result_bytes)
        return result
