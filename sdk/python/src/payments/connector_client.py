"""
ConnectorClient — high-level wrapper around UniFFI FFI bindings.

Handles the full round-trip for any payment flow:
  1. Build connector HTTP request via {flow}_req_transformer (FFI)
  2. Execute the HTTP request via httpx library
  3. Parse the connector response via {flow}_res_transformer (FFI)

Flow methods (authorize, capture, void, refund, …) are attached dynamically
from _generated_flows.py — no flow names are hardcoded in this file.
To add a new flow: edit sdk/flows.yaml and run `make codegen`.
"""

import json
from typing import Dict, Optional

import payments.generated.connector_service_ffi as _ffi
import payments.generated.payment_pb2 as _pb2
from payments._generated_flows import FLOW_RESPONSES
from payments.generated.sdk_config_pb2 import (
    FfiOptions, 
    ClientConfig, 
    RequestOptions, 
    FfiConnectorHttpRequest, 
    FfiConnectorHttpResponse,
    HttpTimeoutConfig
)
from .http_client import execute, HttpRequest, create_client, Defaults


class ConnectorClient:
    """High-level client for connector payment operations via UniFFI FFI."""

    def __init__(self, config: ClientConfig, lib_path: Optional[str] = None):
        """
        Initialize the client.
        
        Args:
            config: Initialization configuration (connector, environment, auth, http).
            lib_path: Optional path to the shared library.
        """
        self.config = config
        # Instance-level cache: create the primary connection pool at startup
        # Infrastructure (Certs, Proxy) and default timeouts are fixed here.
        self.client = create_client(self.config.http if self.config.HasField('http') else None)

    def _resolve_ffi_options(self, request_options: Optional[RequestOptions] = None) -> FfiOptions:
        """
        Merges request-level overrides with client defaults to build the 
        final context for the Rust transformation engine.
        """
        # Resolve Auth: Prefer request-level override, fallback to client default
        auth = request_options.auth if (request_options and request_options.HasField('auth')) else self.config.auth
        
        return FfiOptions(
            environment=self.config.environment,
            connector=self.config.connector,
            auth=auth
        )

    def _resolve_timeout_config(self, request_options: Optional[RequestOptions] = None) -> Optional[HttpTimeoutConfig]:
        """
        Resolves the final timeout configuration for a request.
        Identity Rule: Only timeouts can be overridden per request.
        """
        client_timeouts = self.config.http.timeouts if (self.config.HasField('http') and self.config.http.HasField('timeouts')) else None
        override_timeouts = request_options.timeouts if (request_options and request_options.HasField('timeouts')) else None

        if not override_timeouts:
            return client_timeouts

        # Merge timeouts: override > client default
        merged = HttpTimeoutConfig()
        if client_timeouts:
            merged.CopyFrom(client_timeouts)
        
        if override_timeouts.HasField('total_timeout_ms'): merged.total_timeout_ms = override_timeouts.total_timeout_ms
        if override_timeouts.HasField('connect_timeout_ms'): merged.connect_timeout_ms = override_timeouts.connect_timeout_ms
        if override_timeouts.HasField('response_timeout_ms'): merged.response_timeout_ms = override_timeouts.response_timeout_ms
        if override_timeouts.HasField('keep_alive_timeout_ms'): merged.keep_alive_timeout_ms = override_timeouts.keep_alive_timeout_ms
        
        return merged

    def _execute_flow(self, flow: str, request, metadata: dict, request_options: Optional[RequestOptions] = None):
        """Execute a full payment flow round-trip."""
        cls_name = FLOW_RESPONSES.get(flow)
        if cls_name is None:
            raise ValueError(
                f"Unknown flow '{flow}'. Add it to sdk/flows.yaml and run `make codegen`."
            )
        response_cls = getattr(_pb2, cls_name)

        req_transformer = getattr(_ffi, f"{flow}_req_transformer")
        res_transformer = getattr(_ffi, f"{flow}_res_transformer")

        request_bytes = request.SerializeToString()

        # 1. Resolve final configuration (Pattern-based merging)
        ffi_options = self._resolve_ffi_options(request_options)
        options_bytes = ffi_options.SerializeToString()

        # 2. Build the connector HTTP request via FFI
        result_bytes = req_transformer(request_bytes, metadata, options_bytes)
        connector_req = FfiConnectorHttpRequest.FromString(result_bytes)
        
        connector_request = HttpRequest(
            url=connector_req.url,
            method=connector_req.method,
            headers=dict(connector_req.headers),
            body=connector_req.body
        )

        # 3. Resolve Timeout Config (precedence logic)
        timeout_config = self._resolve_timeout_config(request_options)

        # 4. Execute HTTP using the instance-owned client
        response = execute(
            connector_request, 
            self.client,
            timeout_config=timeout_config
        )

        # 5. Encode HTTP response as FfiConnectorHttpResponse protobuf bytes
        res_proto = FfiConnectorHttpResponse(
            status_code=response.status_code,
            headers=response.headers,
            body=response.body
        )
        res_bytes = res_proto.SerializeToString()

        # 6. Parse connector response via FFI
        result_bytes_res = res_transformer(
            res_bytes,
            request_bytes,
            metadata,
            options_bytes
        )

        # 7. Deserialize the final domain protobuf response
        response_msg = response_cls()
        response_msg.ParseFromString(result_bytes_res)
        return response_msg


def _make_flow_method(flow: str):
    def method(self, request, metadata: dict, options: Optional[RequestOptions] = None):
        return self._execute_flow(flow, request, metadata, options)

    method.__name__ = flow
    method.__qualname__ = f"ConnectorClient.{flow}"
    return method


# Attach a method for every flow registered in _generated_flows.py.
for _flow in FLOW_RESPONSES:
    setattr(ConnectorClient, _flow, _make_flow_method(_flow))
