"""
ConnectorClient — high-level wrapper around UniFFI FFI bindings.

Handles the full round-trip for any payment flow:
  1. Build connector HTTP request via {flow}_req_transformer (FFI)
  2. Execute the HTTP request via requests library
  3. Parse the connector response via {flow}_res_transformer (FFI)

Flow methods (authorize, capture, void, refund, …) are attached dynamically
from _generated_flows.py — no flow names are hardcoded in this file.
To add a new flow: edit sdk/flows.yaml and run `make codegen`.
"""

import json

import payments.generated.connector_service_ffi as _ffi
import payments.generated.payment_pb2 as _pb2
import requests as http_requests

from payments._generated_flows import FLOW_RESPONSES
from payments.generated.sdk_options_pb2 import FfiOptions
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
    
    def _execute_flow(self, flow: str, request, metadata: dict, ffi_options: FfiOptions = None):
        """Execute a full payment flow round-trip: FFI request build -> HTTP -> FFI response parse.

        Args:
            flow: Flow name matching the FFI transformer prefix (e.g. "authorize", "capture").
            request: A protobuf request message.
            metadata: Dict with connector routing and auth info. Must include:
                - "connector": connector name (e.g. "Stripe")
                - "connector_auth_type": JSON string of auth config
                - x-* headers for masked metadata
            ffi_options: Optional FfiOptions protobuf message override.

        Returns:
            A deserialized protobuf response message.
        """
        cls_name = FLOW_RESPONSES.get(flow)
        if cls_name is None:
            raise ValueError(
                f"Unknown flow '{flow}'. Add it to sdk/flows.yaml and run `make codegen`."
            )
        response_cls = getattr(_pb2, cls_name)

        req_transformer = getattr(_ffi, f"{flow}_req_transformer")
        res_transformer = getattr(_ffi, f"{flow}_res_transformer")

        request_bytes = request.SerializeToString()

        # Resolve FFI options (prefer call-specific override)
        ffi = ffi_options or self.options.ffi
        options_bytes = ffi.SerializeToString() if ffi else b""

        # Step 2: Build the connector HTTP request via FFI (returns Protobuf bytes)
        # The FFI transformer handles the mapping from domain types to raw HTTP details.
        result_bytes = req_transformer(request_bytes, metadata, options_bytes)
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

        # We wrap the native response in an internal FFI Protobuf record for safe binary transport.
        res_proto = FfiConnectorHttpResponse(
            status_code=response.status_code,
            headers=response.headers,
            body=response.body
        )
        res_bytes = res_proto.SerializeToString()

        result_bytes_res = res_transformer(
            res_bytes,
            request_bytes,
            metadata,
            options_bytes
        )

        # Step 5: Deserialize the final domain protobuf response
        response_msg = response_cls()
        response_msg.ParseFromString(result_bytes_res)
        return response_msg


def _make_flow_method(flow: str):
    def method(self, request, metadata: dict, options: FfiOptions = None):
        return self._execute_flow(flow, request, metadata, options)

    method.__name__ = flow
    method.__qualname__ = f"ConnectorClient.{flow}"
    return method


# Attach a method for every flow registered in _generated_flows.py.
# No flow names are hardcoded above — only _generated_flows.py is machine-written.
for _flow in FLOW_RESPONSES:
    setattr(ConnectorClient, _flow, _make_flow_method(_flow))
