from .uniffi_client import UniffiClient
from .http_client import execute, HttpRequest
from .generated import payments_pb2, sdk_options_pb2
from typing import Dict, Optional

class ConnectorClient:
    def __init__(self, lib_path: Optional[str] = None, options: Optional[sdk_options_pb2.Options] = None):
        self._uniffi = UniffiClient(lib_path)
        self._options = options or sdk_options_pb2.Options()

    def _get_native_http_options(self) -> sdk_options_pb2.HttpOptions:
        """
        Internal helper to map client-global options. 
        In Python, our execute() currently takes the proto HttpOptions directly,
        but we maintain the same 'Adapter' pattern for architectural consistency.
        """
        return self._options.http

    def authorize(
        self, 
        request_msg: payments_pb2.PaymentServiceAuthorizeRequest, 
        metadata: Dict[str, str],
        ffi_options: Optional[sdk_options_pb2.FfiOptions] = None
    ) -> payments_pb2.PaymentServiceAuthorizeResponse:
        
        # 1. Serialize request to bytes
        request_bytes = request_msg.SerializeToString()

        # 2. Resolve FFI options (prefer call-specific override)
        ffi = ffi_options or self._options.ffi
        options_bytes = ffi.SerializeToString() if ffi else b""

        # 3. Build the connector HTTP request via FFI bridge (returns Protobuf bytes)
        result_bytes = self._uniffi.authorize_req(request_bytes, metadata, options_bytes)
        connector_req = sdk_options_pb2.FfiConnectorHttpRequest.FromString(result_bytes)
        
        connector_request = HttpRequest(
            url=connector_req.url,
            method=connector_req.method,
            headers=connector_req.headers,
            body=connector_req.body
        )

        # 4. Execute the HTTP request (uses Global HttpOptions)
        response = execute(connector_request, self._get_native_http_options())

        # 5. Parse the connector response via FFI bridge
        # New Step: Serialize native response to FFI-internal Protobuf record
        res_proto = sdk_options_pb2.FfiConnectorHttpResponse(
            status_code=response.status_code,
            headers=response.headers,
            body=response.body
        )
        res_bytes = res_proto.SerializeToString()

        result_bytes = self._uniffi.authorize_res(
            res_bytes,
            request_bytes,
            metadata,
            options_bytes
        )

        # 6. Decode and return the protobuf response
        response_msg = payments_pb2.PaymentServiceAuthorizeResponse()
        response_msg.ParseFromString(result_bytes)
        return response_msg
