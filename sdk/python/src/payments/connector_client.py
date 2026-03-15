
"""
_ConnectorClientBase — high-level asynchronous wrapper around UniFFI FFI bindings.

Handles the full round-trip for any payment flow:
  1. Build connector HTTP request via {flow}_req_transformer (FFI)
  2. Execute the HTTP request via httpx AsyncClient
  3. Parse the connector response via {flow}_res_transformer (FFI)

Per-service client classes (PaymentClient, MerchantAuthenticationClient, …) are
generated in _generated_service_clients.py — no flow names are hardcoded in this file.
To add a new flow: implement a req_transformer in services/payments.rs and run `make generate`.

Error Handling:
  FFI transformers return raw bytes that may represent either a success proto or an
  error proto (RequestError for req_transformer, ResponseError for res_transformer).
  On error, the decoded proto (RequestError or ResponseError) is raised directly.
  Callers can catch the specific error type:

      try:
          response = await client.authorize(request)
      except RequestError as e:
          print(e.error_code, e.error_message)
      except ResponseError as e:
          print(e.error_code, e.error_message)
"""

from typing import Optional, Any

from .generated import connector_service_ffi as _ffi
from ._generated_flows import SERVICE_FLOWS
from .http_client import execute, HttpRequest, create_client
from .generated.sdk_config_pb2 import (
    ConnectorConfig,
    RequestConfig,
    FfiOptions,
    FfiConnectorHttpRequest,
    FfiConnectorHttpResponse,
    HttpConfig,
    RequestError as RequestErrorProto,
    ResponseError as ResponseErrorProto,
)


class RequestError(Exception):
    """Exception raised when req_transformer fails.

    Wraps RequestErrorProto and provides transparent access to proto fields.
    """

    def __init__(self, proto: RequestErrorProto):
        super().__init__(proto.error_message)
        self._proto = proto

    def __getattr__(self, name: str):
        # Delegate attribute access to proto
        return getattr(self._proto, name)


class ResponseError(Exception):
    """Exception raised when res_transformer fails.

    Wraps ResponseErrorProto and provides transparent access to proto fields.
    """

    def __init__(self, proto: ResponseErrorProto):
        super().__init__(proto.error_message)
        self._proto = proto

    def __getattr__(self, name: str):
        # Delegate attribute access to proto
        return getattr(self._proto, name)



def _check_req_error(result_bytes: bytes, success_cls: Any) -> Any:
    """
    Parse FFI req_transformer bytes as either a success proto or a RequestError.

    FfiConnectorHttpRequest.method (field 2, string) has the same field number and
    wire type as RequestError.error_message (field 2, optional string).  Parsing an
    HTTP-request response as RequestError would therefore put the HTTP method ("POST")
    into error_message and trigger a false positive.

    Discriminate using field 1 instead:
      - FfiConnectorHttpRequest.url  (field 1, string) — always non-empty on success
      - RequestError.status          (field 1, enum)   — non-zero on error

    Strategy: parse as FfiConnectorHttpRequest first.  If url is non-empty, this IS a
    valid HTTP request — return it immediately.  Otherwise fall through and parse as
    RequestError.

    Args:
        result_bytes: Raw bytes returned by the req_transformer FFI call.
        success_cls: Protobuf message class for the expected success type
                     (always FfiConnectorHttpRequest for req_transformer calls).

    Returns:
        Decoded success proto on success.

    Raises:
        RequestError: If the bytes represent a transformer error.
    """
    # Fast path: if the bytes decode to a valid FfiConnectorHttpRequest (non-empty url),
    # return immediately without any error check.
    try:
        success = success_cls()
        success.ParseFromString(result_bytes)
        if success.url:
            return success
    except Exception:
        pass

    # url was empty (or parsing failed) — treat as a RequestError.
    error_proto = RequestErrorProto()
    error_proto.ParseFromString(result_bytes)
    raise RequestError(error_proto)


def _check_res_error(result_bytes: bytes, success_cls: Any) -> Any:
    """
    Parse FFI res_transformer bytes as either a success proto or a ResponseError.

    Parse as ResponseError first; if parsing succeeds AND status is non-default,
    treat it as an actual error and raise it. Otherwise, parse as success message.

    Args:
        result_bytes: Raw bytes returned by the res_transformer FFI call.
        success_cls: Protobuf message class for the expected success type.

    Returns:
        Decoded success proto on success.

    Raises:
        ResponseError: If the bytes represent a transformer error.
    """
    # Discriminate error bytes from success bytes using status_code (field 4).
    #
    # Why not status or error_message?
    #
    # Most success response protos (e.g. PaymentServiceAuthorizeResponse) share field
    # numbers with ResponseError in an incompatible way:
    #   - Success field 1 (string)  → ResponseError.status (enum varint) → wire mismatch → status=0
    #   - Success field 2 (string)  → ResponseError.error_message (string) → wire MATCH!
    #     So a real connector_transaction_id like "pi_xxx" lands in error_message, causing
    #     HasField("error_message") to return True for every successful response (false positive).
    #
    # status_code (field 4) is safe: in success protos field 4 is always a message type
    # (e.g. ErrorInfo, wire-type 2), which mismatches status_code's uint32 (wire-type 0) →
    # silently ignored → status_code=0 for all success bytes.
    # For real errors, the Rust transformer sets status_code to the HTTP status code (4xx/5xx).
    #
    # Fallback: status != 0 catches connector-level errors (e.g. PAYMENT_FAILED enum) where
    # field 1 happens to be a varint-compatible field in the success proto.
    try:
        error_proto = ResponseErrorProto()
        error_proto.ParseFromString(result_bytes)

        if error_proto.status_code >= 400 or error_proto.status != 0:
            raise ResponseError(error_proto)
    except ResponseError:
        raise
    except Exception:
        pass

    # Parse as success message
    success = success_cls()
    success.ParseFromString(result_bytes)

    # Secondary check: the Rust res_transformer embeds connector errors inside the
    # success proto (PaymentServiceAuthorize/Charge/etc. Response) rather than returning
    # a ResponseError when a payment fails (e.g. SEPA+USD not supported, card declined).
    # The HTTP status code from the connector is stored in the success proto's
    # `status_code` field.  An HTTP 4xx/5xx here means the connector rejected the
    # payment — surface it as ResponseError so callers can handle it uniformly.
    #
    # We also try to forward the embedded error message and code from the
    # `error.connector_details` message field so the caller sees meaningful details.
    try:
        sc = getattr(success, "status_code", 0)
        if sc >= 400:
            synth = ResponseErrorProto()
            synth.status_code = sc
            try:
                error_info = success.error  # ErrorInfo field (name is consistent across protos)
                if error_info.HasField("connector_details"):
                    cd = error_info.connector_details
                    if cd.message:
                        synth.error_message = cd.message
                    if cd.code:
                        synth.error_code = cd.code
            except Exception:
                pass
            raise ResponseError(synth)
    except ResponseError:
        raise
    except Exception:
        pass

    return success


class _ConnectorClientBase:
    """Base class for per-service connector clients. Do not instantiate directly."""

    def __init__(
        self,
        config: ConnectorConfig,
        defaults: Optional[RequestConfig] = None,
        lib_path: Optional[str] = None,
    ):
        """
        Initialize the client.

        Args:
            config: Immutable connector identity and environment (connector, auth, environment).
            defaults: Optional per-request defaults (http, vault).
            lib_path: Optional path to the shared library.
        """
        self.config = config
        self.defaults = defaults or RequestConfig()
        # Instance-level cache: create the primary asynchronous connection pool at startup
        self.client = create_client(
            self.defaults.http if self.defaults.HasField("http") else None
        )

    def _resolve_config(
        self, options: Optional[RequestConfig] = None
    ) -> tuple[FfiOptions, Optional[HttpConfig]]:
        """
        Merges request-level options with client defaults.
        Environment comes from ConnectorConfig (immutable). HTTP/vault from defaults + request override.
        """
        environment = self.config.environment

        # HTTP: request override > client defaults
        http_config = (
            options.http
            if (options and options.HasField("http"))
            else (self.defaults.http if self.defaults.HasField("http") else None)
        )

        # Resolve FFI Context
        ffi = FfiOptions(
            environment=environment,
            connector=self.config.connector,
            auth=self.config.auth,
        )

        return ffi, http_config


    async def _execute_flow(
        self,
        flow: str,
        request: Any,
        response_cls: Any,
        options: Optional[RequestConfig] = None,
    ) -> Any:
        """
        Execute a full payment flow round-trip asynchronously.

        Errors from the FFI layer are raised as RequestError or ResponseError directly.

        Args:
            flow: Flow name matching the FFI transformer prefix (e.g. "authorize").
            request: A domain protobuf request message.
            response_cls: Protobuf message class to deserialize the response into.
            options: Optional per-request configuration overrides.

        Returns:
            Decoded domain response proto.

        Raises:
            RequestError: On req_transformer failures.
            ResponseError: On res_transformer failures.
        """
        req_transformer = getattr(_ffi, f"{flow}_req_transformer")
        res_transformer = getattr(_ffi, f"{flow}_res_transformer")

        # 1. Resolve final configuration (Identity is fixed, others merged)
        ffi_options, http_config = self._resolve_config(options)

        request_bytes = request.SerializeToString()
        options_bytes = ffi_options.SerializeToString()

        # 2. Build connector HTTP request via FFI
        #    Parse result bytes as FfiConnectorHttpRequest; if that fails, parse as RequestError.
        result_bytes = req_transformer(request_bytes, options_bytes)
        connector_req = _check_req_error(result_bytes, FfiConnectorHttpRequest)

        connector_request = HttpRequest(
            url=connector_req.url,
            method=connector_req.method,
            headers=dict(connector_req.headers),
            body=connector_req.body if connector_req.HasField("body") else None,
        )

        # 3. Execute the HTTP request using the instance-owned AsyncClient
        response = await execute(
            connector_request, self.client, http_config=http_config
        )

        # 4. Encode HTTP response for FFI
        res_proto = FfiConnectorHttpResponse(
            status_code=response.status_code,
            headers=response.headers,
            body=response.body,
        )
        res_bytes = res_proto.SerializeToString()

        # 5. Parse connector response via FFI
        #    Parse result bytes as response_cls; if that fails, parse as ResponseError.
        result_bytes_res = res_transformer(res_bytes, request_bytes, options_bytes)
        return _check_res_error(result_bytes_res, response_cls)


    def _execute_direct(
        self,
        flow: str,
        request: Any,
        response_cls: Any,
        options: Optional[RequestConfig] = None,
    ) -> Any:
        """
        Execute a single-step flow: FFI transformer called directly, no HTTP round-trip.

        Used for inbound flows like webhook processing where the connector sends
        data to us. Errors are raised as ResponseError directly.

        Args:
            flow: Flow name matching the FFI transformer (e.g. "handle_event").
            request: A domain protobuf request message.
            response_cls: Protobuf message class to deserialize the response into.
            options: Optional per-request configuration overrides.

        Returns:
            Decoded domain response proto.

        Raises:
            ResponseError: On FFI transformer failures.
        """
        transformer = getattr(_ffi, f"{flow}_transformer")

        request_bytes = request.SerializeToString()

        # Resolve final configuration
        ffi_options, _ = self._resolve_config(options)
        options_bytes = ffi_options.SerializeToString()

        result_bytes = transformer(request_bytes, options_bytes)

        # Parse result bytes as response_cls; if that fails, parse as ResponseError.
        return _check_res_error(result_bytes, response_cls)

    async def close(self):
        """Close the underlying asynchronous connection pool."""
        await self.client.aclose()


class ConnectorClient(_ConnectorClientBase):
    """Legacy flat client for backward compatibility. Flow methods attached dynamically."""

    pass


# Note: In the final generated state, ConnectorClient will have methods attached by the codegen
# or per-service clients (PaymentClient, etc.) will be used as the primary interface.