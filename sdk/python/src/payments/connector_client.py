"""
ConnectorClient — high-level asynchronous wrapper around UniFFI FFI bindings.

Handles the full round-trip for any payment flow:
  1. Build connector HTTP request via {flow}_req_transformer (FFI)
  2. Execute the HTTP request via httpx AsyncClient
  3. Parse the connector response via {flow}_res_transformer (FFI)

Flow methods (authorize, capture, void, refund, …) are attached dynamically
from _generated_flows.py.
"""

import json
from typing import Dict, Optional, Any

import payments.generated.connector_service_ffi as _ffi
import payments.generated.payment_pb2 as _pb2
from payments._generated_flows import FLOW_RESPONSES
from .http_client import execute, HttpRequest, create_client
from payments.generated.sdk_config_pb2 import ClientIdentity, ConfigOptions, FfiOptions, FfiConnectorHttpRequest, FfiConnectorHttpResponse


class ConnectorClient:
    """High-level asynchronous client for connector payment operations via UniFFI FFI."""

    def __init__(self, identity: ClientIdentity, defaults: Optional[ConfigOptions] = None):
        """
        Initialize the client with a fixed identity and overridable defaults.
        """
        self.identity = identity
        self.defaults = defaults or ConfigOptions()
        # Instance-level cache: create the primary asynchronous connection pool at startup
        self.client = create_client(self.defaults.http if self.defaults.HasField('http') else None)

    def _resolve_config(self, options: Optional[ConfigOptions] = None) -> tuple[FfiOptions, Optional[Any]]:
        """Merges request-level options with client defaults."""
        # 1. Environment: Request Override > Client Default
        environment = options.environment if options is not None else self.defaults.environment

        # 2. HTTP Overrides: Request Override > Client Default
        http_config = options.http if (options and options.HasField('http')) else (self.defaults.http if self.defaults.HasField('http') else None)

        # 3. Resolve FFI Context (Identity is strictly immutable)
        ffi = FfiOptions(
            environment=environment,
            connector=self.identity.connector,
            auth=self.identity.auth
        )

        return ffi, http_config

    async def _execute_flow(self, flow: str, request: Any, metadata: dict, options: Optional[ConfigOptions] = None):
        """Execute a full payment flow round-trip asynchronously."""
        cls_name = FLOW_RESPONSES.get(flow)
        if cls_name is None:
            raise ValueError(f"Unknown flow '{flow}'")
        
        response_cls = getattr(_pb2, cls_name)
        req_transformer = getattr(_ffi, f"{flow}_req_transformer")
        res_transformer = getattr(_ffi, f"{flow}_res_transformer")

        # 1. Resolve final configuration (Identity is fixed, others merged)
        ffi_options, http_config = self._resolve_config(options)
        
        request_bytes = request.SerializeToString()
        options_bytes = ffi_options.SerializeToString()

        # 2. Build connector HTTP request via FFI
        result_bytes = req_transformer(request_bytes, metadata, options_bytes)
        connector_req = FfiConnectorHttpRequest.FromString(result_bytes)
        
        connector_request = HttpRequest(
            url=connector_req.url,
            method=connector_req.method,
            headers=dict(connector_req.headers),
            body=connector_req.body if connector_req.HasField('body') else None
        )

        # 3. Execute the HTTP request using the instance-owned AsyncClient
        response = await execute(
            connector_request, 
            self.client,
            http_config=http_config
        )

        # 4. Encode HTTP response for FFI
        res_proto = FfiConnectorHttpResponse(
            status_code=response.status_code,
            headers=response.headers,
            body=response.body
        )
        res_bytes = res_proto.SerializeToString()

        # 5. Parse connector response via FFI
        result_bytes_res = res_transformer(
            res_bytes,
            request_bytes,
            metadata,
            options_bytes
        )

        # 6. Deserialize final domain response
        return response_cls.FromString(result_bytes_res)

    async def close(self):
        """Close the underlying asynchronous connection pool."""
        await self.client.aclose()


def _make_flow_method(flow: str):
    async def method(self, request, metadata: dict, options: ConfigOptions = None):
        return await self._execute_flow(flow, request, metadata, options)

    method.__name__ = flow
    method.__qualname__ = f"ConnectorClient.{flow}"
    return method


# Attach a method for every flow registered in _generated_flows.py.
for _flow in FLOW_RESPONSES:
    setattr(ConnectorClient, _flow, _make_flow_method(_flow))
