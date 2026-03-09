"""
_ConnectorClientBase — high-level asynchronous wrapper around UniFFI FFI bindings.

Handles the full round-trip for any payment flow:
  1. Build connector HTTP request via {flow}_req_transformer (FFI)
  2. Execute the HTTP request via httpx AsyncClient
  3. Parse the connector response via {flow}_res_transformer (FFI)

Per-service client classes (PaymentClient, MerchantAuthenticationClient, …) are
generated in _generated_service_clients.py — no flow names are hardcoded in this file.
To add a new flow: implement a req_transformer in services/payments.rs and run `make generate`.
"""

import json
from typing import Dict, Optional, Any

from .generated import connector_service_ffi as _ffi
from .generated import payment_pb2 as _pb2
from ._generated_flows import SERVICE_FLOWS
from .http_client import execute, HttpRequest, create_client
from .generated.sdk_config_pb2 import (
    ConnectorConfig,
    RequestConfig,
    FfiOptions,
    FfiConnectorHttpRequest,
    FfiConnectorHttpResponse,
    HttpConfig,
    Environment,
    FfiRequestError,
    FfiResponseError,
)


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

        # 2. HTTP: request override > client defaults
        http_config = (
            options.http
            if (options and options.HasField("http"))
            else (self.defaults.http if self.defaults.HasField("http") else None)
        )

        # 3. Resolve FFI Context
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
        response_cls,
        options: Optional[RequestConfig] = None,
    ):
        """
        Execute a full payment flow round-trip asynchronously.

        Args:
            flow: Flow name matching the FFI transformer prefix (e.g. "authorize").
            request: A domain protobuf request message.
            response_cls: Protobuf message class to deserialize the response into.
            options: Optional per-request configuration overrides.
        """
        req_transformer = getattr(_ffi, f"{flow}_req_transformer")
        res_transformer = getattr(_ffi, f"{flow}_res_transformer")

        # 1. Resolve final configuration (Identity is fixed, others merged)
        ffi_options, http_config = self._resolve_config(options)

        request_bytes = request.SerializeToString()
        options_bytes = ffi_options.SerializeToString()

        # 2. Build connector HTTP request via FFI
        result_bytes = req_transformer(request_bytes, options_bytes)
        # Inline FFI error check
        try:
            req_err = FfiRequestError()
            req_err.ParseFromString(result_bytes)
            if req_err.is_error:
                e = RuntimeError(req_err.message)
                e.ffi_error = req_err
                raise e
        except RuntimeError:
            raise
        except Exception:
            pass  # Not an error proto — continue
        connector_req = FfiConnectorHttpRequest.FromString(result_bytes)

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
        result_bytes_res = res_transformer(res_bytes, request_bytes, options_bytes)
        # Inline FFI error check
        try:
            res_err = FfiResponseError()
            res_err.ParseFromString(result_bytes_res)
            if res_err.is_error:
                e = RuntimeError(res_err.message)
                e.ffi_error = res_err
                raise e
        except RuntimeError:
            raise
        except Exception:
            pass  # Not an error proto — continue

        # 6. Deserialize final domain response
        return response_cls.FromString(result_bytes_res)

    def _execute_direct(
        self, flow: str, request, response_cls, options: Optional[RequestConfig] = None
    ):
        """
        Execute a single-step flow: FFI transformer called directly, no HTTP round-trip.
        """
        transformer = getattr(_ffi, f"{flow}_transformer")

        request_bytes = request.SerializeToString()

        # Resolve final configuration
        ffi_options, _ = self._resolve_config(options)
        options_bytes = ffi_options.SerializeToString()

        result_bytes = transformer(request_bytes, options_bytes)

        return response_cls.FromString(result_bytes)

    async def close(self):
        """Close the underlying asynchronous connection pool."""
        await self.client.aclose()


class ConnectorClient(_ConnectorClientBase):
    """Legacy flat client for backward compatibility. Flow methods attached dynamically."""

    pass


# Note: In the final generated state, ConnectorClient will have methods attached by the codegen
# or per-service clients (PaymentClient, etc.) will be used as the primary interface.
