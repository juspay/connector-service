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


class ConnectorClient:
    """High-level client for connector payment operations via UniFFI FFI."""

    def _execute_flow(self, flow: str, request, metadata: dict, options: FfiOptions = None):
        """Execute a full payment flow round-trip: FFI request build -> HTTP -> FFI response parse.

        Args:
            flow: Flow name matching the FFI transformer prefix (e.g. "authorize", "capture").
            request: A protobuf request message.
            metadata: Dict with connector routing and auth info. Must include:
                - "connector": connector name (e.g. "Stripe")
                - "connector_auth_type": JSON string of auth config
                - x-* headers for masked metadata
            options: Optional FfiOptions protobuf message with ffi configuration.

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

        # Serialize FfiOptions to bytes if provided, otherwise use empty bytes
        options_bytes = b'' if options is None else options.SerializeToString()

        # Step 2: Build the connector HTTP request via FFI
        connector_request_json = req_transformer(request_bytes, metadata, options_bytes)
        connector_request = json.loads(connector_request_json)

        url = connector_request["url"]
        method = connector_request["method"]
        headers = connector_request.get("headers", {})
        body = connector_request.get("body")

        # Body may be a dict/object — serialize to string for the HTTP call
        if body is not None and not isinstance(body, (str, bytes)):
            body = json.dumps(body)

        response = http_requests.request(method, url, headers=headers, data=body)

        response_body = response.text.encode("utf-8")
        response_headers = dict(response.headers)
        result_bytes = res_transformer(
            response_body,
            response.status_code,
            response_headers,
            request_bytes,
            metadata,
            options_bytes,
        )

        result = response_cls()
        result.ParseFromString(result_bytes)
        return result


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
