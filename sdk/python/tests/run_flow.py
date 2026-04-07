#!/usr/bin/env python3
"""
Flow runner for the Python SDK — invoked by the Rust integration test harness.

The Rust python_executor sends a JSON payload via stdin and reads the result
from stdout.  This script:

  1. Reads a JSON request from stdin containing:
     - client:       SDK client class name (e.g. "PaymentClient")
     - flow:         Flow method name (e.g. "authorize")
     - request:      Protobuf request as JSON (same shape as grpc scenario payloads)
     - connector:    Connector name (e.g. "stripe")
     - credentials:  Connector auth config JSON (from creds.json)
     - environment:  "sandbox" or "production" (default: sandbox)

  2. Builds a ConnectorConfig from credentials
  3. Instantiates the appropriate client
  4. Calls the flow method with the protobuf request
  5. Writes JSON result to stdout:
     - On success: {"status": "ok", "response": <proto-json>}
     - On expected error: {"status": "connector_error", "error": <detail>}
     - On SDK error: {"status": "sdk_error", "error": <detail>}

Usage (standalone testing):
    echo '{"client":"PaymentClient","flow":"authorize","request":{...},...}' | python3 run_flow.py

Usage (from Rust harness):
    The python_executor.rs spawns this script as a subprocess.
"""

import json
import os
import sys
import traceback

# Ensure SDK source is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

try:
    from payments import (
        ConnectorConfig,
        ConnectorSpecificConfig,
        SdkOptions,
        Environment,
        IntegrationError,
        ConnectorResponseTransformationError,
    )
    from payments.generated.connector_service_ffi import InternalError
    import payments._generated_service_clients as service_clients
    import payments.generated.payment_pb2 as payment_pb2
    import payments.generated.payment_methods_pb2 as payment_methods_pb2
except ImportError as e:
    result = {"status": "sdk_error", "error": f"Import failed: {e}"}
    print(json.dumps(result))
    sys.exit(0)


def build_connector_config(connector: str, credentials: dict, environment: str) -> ConnectorConfig:
    """Build a ConnectorConfig from connector name and credential dict.

    Mirrors the logic in test_smoke.py _build_connector_config but works
    with the raw auth dict from creds.json.
    """
    env = Environment.PRODUCTION if environment == "production" else Environment.SANDBOX

    # Find the connector-specific config class (e.g., StripeConfig for "stripe")
    config_class = None
    target = connector.lower() + "config"
    for name in dir(payment_pb2):
        if name.lower() == target:
            config_class = getattr(payment_pb2, name)
            break

    if config_class is None:
        connector_specific = ConnectorSpecificConfig()
    else:
        valid_fields = {f.name for f in config_class.DESCRIPTOR.fields}
        kwargs = {}
        for key, value in credentials.items():
            if key in ("_comment", "metadata") or key not in valid_fields:
                continue
            if isinstance(value, dict) and "value" in value:
                kwargs[key] = payment_methods_pb2.SecretString(value=str(value["value"]))
            elif isinstance(value, str):
                kwargs[key] = value
        connector_specific = ConnectorSpecificConfig(**{connector.lower(): config_class(**kwargs)})

    return ConnectorConfig(
        connector_config=connector_specific,
        options=SdkOptions(environment=env),
    )


def serialize_response(response) -> dict:
    """Serialize a protobuf response to a JSON-compatible dict."""
    from google.protobuf.json_format import MessageToDict

    if hasattr(response, "DESCRIPTOR"):
        return MessageToDict(response, preserving_proto_field_name=True)
    if isinstance(response, dict):
        return response
    return {"raw": str(response)}


def run_flow(payload: dict) -> dict:
    """Execute a single SDK flow and return the result."""
    client_name = payload["client"]
    flow_name = payload["flow"]
    request_json = payload["request"]
    connector = payload["connector"]
    credentials = payload.get("credentials", {})
    environment = payload.get("environment", "sandbox")

    # Build connector config
    config = build_connector_config(connector, credentials, environment)

    # Instantiate the client
    client_class = getattr(service_clients, client_name, None)
    if client_class is None:
        return {"status": "sdk_error", "error": f"Unknown client class: {client_name}"}

    client = client_class(config)

    # Get the flow method
    method = getattr(client, flow_name, None)
    if method is None:
        return {
            "status": "sdk_error",
            "error": f"{client_name} has no method '{flow_name}'",
        }

    # Build the protobuf request from JSON
    # The request_json should be a dict that maps to the proto message fields
    try:
        from google.protobuf.json_format import ParseDict

        # Determine the request proto type from the flow method signature
        # We pass the raw JSON dict — the SDK _execute_flow method handles
        # protobuf serialization internally via the FFI layer
        response = method(request_json)
    except (IntegrationError, ConnectorResponseTransformationError) as e:
        msg = getattr(e, "error_message", None) or str(e)
        code = getattr(e, "error_code", None)
        detail = f"{code}: {msg}" if code else msg
        return {
            "status": "connector_error",
            "error": f"{type(e).__name__}: {detail}",
        }
    except InternalError as e:
        msg = str(e)
        return {
            "status": "connector_error",
            "error": f"InternalError: {msg}",
        }
    except Exception as e:
        tb = traceback.format_exc()
        return {
            "status": "sdk_error",
            "error": f"{type(e).__name__}: {e}",
            "traceback": tb[:2000],
        }

    # Serialize response
    try:
        response_dict = serialize_response(response)
        return {"status": "ok", "response": response_dict}
    except Exception as e:
        return {
            "status": "ok",
            "response": {"raw": str(response)},
            "serialization_warning": str(e),
        }


def main():
    """Read JSON from stdin, run the flow, write JSON to stdout."""
    try:
        input_data = json.loads(sys.stdin.read())
    except json.JSONDecodeError as e:
        result = {"status": "sdk_error", "error": f"Invalid JSON input: {e}"}
        print(json.dumps(result))
        sys.exit(0)

    result = run_flow(input_data)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
