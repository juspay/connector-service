"""
sdk_snippets.py — SDK integration example generator for connector docs.

Generates per-SDK code snippets (Python, JavaScript, Kotlin, Rust) for each
flow sample, with proto field comments inline. Called by generate-connector-docs.py;
all functions are pure (no I/O, no global state).

Proto field comments and nested message types are sourced from the manifest dict
(manifest["message_schemas"]) which is populated by the field-probe binary parsing
the .proto files in flow_metadata.rs.

Public API
----------
  render_config_section(connector_name, service_names, is_direct) -> list[str]
    Renders a 4-tab SDK config table (once per connector doc).

  render_payload_block(flow_key, service_name, grpc_request,
                       proto_request, message_schemas) -> list[str]
    Renders a single annotated Python dict payload block (per flow/PM).
"""

import json

# ── Constants ──────────────────────────────────────────────────────────────────

_SERVICE_TO_CLIENT: dict[str, str] = {
    "PaymentService":                     "PaymentClient",
    "CustomerService":                    "CustomerClient",
    "DisputeService":                     "DisputeClient",
    "EventService":                       "EventClient",
    "MerchantAuthenticationService":      "MerchantAuthenticationClient",
    "PaymentMethodAuthenticationService": "PaymentMethodAuthenticationClient",
    "PaymentMethodService":               "PaymentMethodClient",
    "RecurringPaymentService":            "RecurringPaymentClient",
    "RefundService":                      "RefundClient",
}


# ── Message schema proxy ────────────────────────────────────────────────────────

class _SchemaDB:
    """
    Thin proxy over the manifest's message_schemas dict.

    message_schemas layout (from Rust MessageSchema serialization):
      {
        "PaymentServiceAuthorizeRequest": {
          "comments":    {"field_name": "comment text", ...},
          "field_types": {"field_name": "MessageTypeName", ...}
        },
        ...
      }

    field_types only contains entries for fields whose declared type is a
    non-primitive message.  Scalar/wrapper fields are omitted so that
    recursive annotation falls through safely when a JSON value is not a dict.
    """

    def __init__(self, message_schemas: dict) -> None:
        self._schemas = message_schemas

    def get_comment(self, msg: str, field: str) -> str:
        return self._schemas.get(msg, {}).get("comments", {}).get(field, "")

    def get_type(self, msg: str, field: str) -> str:
        return self._schemas.get(msg, {}).get("field_types", {}).get(field, "")


# ── Annotated JSON rendering ───────────────────────────────────────────────────

def _json_scalar(val: object) -> str:
    """Render a scalar value as a JSON string."""
    return json.dumps(val)


def _annotate_inline_lines(
    obj: dict,
    msg_name: str,
    db: _SchemaDB,
    indent: int,
    cmt: str,   # "#" for Python, "//" for JS
) -> list[str]:
    """
    Return lines for the interior of a JSON object with inline comments.

    Layout:
      "field": scalar,  # comment
      "nested": {  # comment
          ...
      },
    """
    pad   = "    " * indent
    lines: list[str] = []

    items = list(obj.items())
    for idx, (key, val) in enumerate(items):
        trailing  = "," if idx < len(items) - 1 else ""
        comment   = db.get_comment(msg_name, key)
        child_msg = db.get_type(msg_name, key)
        cmt_part  = f"  {cmt} {comment}" if comment else ""

        if isinstance(val, dict):
            lines.append(f'{pad}"{key}": {{{cmt_part}')
            lines.extend(_annotate_inline_lines(val, child_msg, db, indent + 1, cmt))
            lines.append(f"{pad}}}{trailing}")

        elif isinstance(val, list) and val and isinstance(val[0], dict):
            lines.append(f'{pad}"{key}": [{cmt_part}')
            for j, item in enumerate(val):
                item_trailing = "," if j < len(val) - 1 else ""
                lines.append(f"{pad}    {{")
                lines.extend(_annotate_inline_lines(item, child_msg, db, indent + 2, cmt))
                lines.append(f"{pad}    }}{item_trailing}")
            lines.append(f"{pad}]{trailing}")

        else:
            lines.append(f'{pad}"{key}": {_json_scalar(val)}{trailing}{cmt_part}')

    return lines


def _annotate_before_lines(
    obj: dict,
    msg_name: str,
    db: _SchemaDB,
    indent: int,
) -> list[str]:
    """
    Return lines for the interior of a JSON object with JSONC-style
    comment lines *before* each field (used for Kotlin, which uses
    JsonFormat.parser() which can't handle inline comments).

    Layout:
      // comment
      "field": scalar,
      // comment
      "nested": {
          ...
      },
    """
    pad   = "    " * indent
    lines: list[str] = []

    items = list(obj.items())
    for idx, (key, val) in enumerate(items):
        trailing  = "," if idx < len(items) - 1 else ""
        comment   = db.get_comment(msg_name, key)
        child_msg = db.get_type(msg_name, key)

        if comment:
            lines.append(f"{pad}// {comment}")

        if isinstance(val, dict):
            lines.append(f'{pad}"{key}": {{')
            lines.extend(_annotate_before_lines(val, child_msg, db, indent + 1))
            lines.append(f"{pad}}}{trailing}")

        elif isinstance(val, list) and val and isinstance(val[0], dict):
            lines.append(f'{pad}"{key}": [')
            for j, item in enumerate(val):
                item_trailing = "," if j < len(val) - 1 else ""
                lines.append(f"{pad}    {{")
                lines.extend(_annotate_before_lines(item, child_msg, db, indent + 2))
                lines.append(f"{pad}    }}{item_trailing}")
            lines.append(f"{pad}]{trailing}")

        else:
            lines.append(f'{pad}"{key}": {_json_scalar(val)}{trailing}')

    return lines


def _build_annotated(
    obj: dict,
    msg_name: str,
    db: _SchemaDB,
    style: str,         # "python" | "js" | "kotlin"
    indent: int = 0,
) -> str:
    """Return the full annotated JSON object as a single string."""
    pad = "    " * indent
    if style == "kotlin":
        inner = _annotate_before_lines(obj, msg_name, db, indent + 1)
    else:
        cmt = "#" if style == "python" else "//"
        inner = _annotate_inline_lines(obj, msg_name, db, indent + 1, cmt)
    return "\n".join(["{"] + inner + [f"{pad}}}"])


# ── Helpers ────────────────────────────────────────────────────────────────────

def _client_class(service_name: str) -> str:
    return _SERVICE_TO_CLIENT.get(
        service_name,
        service_name.replace("Service", "") + "Client",
    )


def _to_camel(snake: str) -> str:
    """authorize_payment → authorizePayment"""
    parts = snake.split("_")
    return parts[0] + "".join(p.title() for p in parts[1:])


def _conn_enum(connector_name: str) -> str:
    return connector_name.upper()


def _conn_display(connector_name: str) -> str:
    return connector_name.replace("_", " ").title().replace(" ", "")


# ── Per-SDK config-only snippet builders ──────────────────────────────────────

def _config_python(connector_name: str) -> str:
    conn_enum = _conn_enum(connector_name)
    return f"""\
from payments.generated import sdk_config_pb2

config = sdk_config_pb2.ConnectorConfig(
    connector=sdk_config_pb2.Connector.{conn_enum},
    environment=sdk_config_pb2.Environment.SANDBOX,
    auth=sdk_config_pb2.ConnectorAuthType(
        header_key=sdk_config_pb2.HeaderKey(api_key="YOUR_API_KEY"),
    ),
)"""


def _config_javascript(connector_name: str) -> str:
    conn_display = _conn_display(connector_name)
    return f"""\
const {{ ConnectorClient }} = require('connector-service-node-ffi');

// Reuse this client for all flows
const client = new ConnectorClient({{
    connector: '{conn_display}',
    environment: 'sandbox',
    connector_auth_type: {{
        header_key: {{ api_key: 'YOUR_API_KEY' }},
    }},
}});"""


def _config_kotlin(connector_name: str) -> str:
    conn_display = _conn_display(connector_name)
    return f"""\
val config = ConnectorConfig.newBuilder()
    .setConnector("{conn_display}")
    .setEnvironment(Environment.SANDBOX)
    .setAuth(
        ConnectorAuthType.newBuilder()
            .setHeaderKey(HeaderKey.newBuilder().setApiKey("YOUR_API_KEY"))
    )
    .build()"""


def _config_rust(connector_name: str) -> str:
    conn_display = _conn_display(connector_name)
    return f"""\
use connector_service_sdk::{{ConnectorClient, ConnectorConfig}};

let config = ConnectorConfig {{
    connector: "{conn_display}".to_string(),
    environment: Environment::Sandbox,
    auth: ConnectorAuth::HeaderKey {{ api_key: "YOUR_API_KEY".into() }},
    ..Default::default()
}};"""


# ── HTML table cell builder ────────────────────────────────────────────────────

def _td(label: str, fence_lang: str, code: str) -> str:
    """
    One <td> containing a <details> block wrapping a fenced code snippet.

    The blank lines around the fenced block cause GitHub's CommonMark parser
    to re-enter markdown mode inside the HTML element, enabling syntax
    highlighting on the code fence.
    """
    return (
        f'<td valign="top">\n\n'
        f"<details><summary>{label}</summary>\n\n"
        f"```{fence_lang}\n"
        f"{code}\n"
        f"```\n\n"
        f"</details>\n\n"
        f"</td>"
    )


# ── Public API ─────────────────────────────────────────────────────────────────

def render_config_section(connector_name: str) -> list[str]:
    """
    Return markdown lines for the SDK Configuration section (emitted once per
    connector doc, after credentials).

    Produces an HTML <table> with four columns (Python, JavaScript, Kotlin, Rust),
    each containing a collapsible <details> block with the connector-specific
    config/client initialisation — no request payload.
    """
    cells = [
        _td("Python",     "python",     _config_python(connector_name)),
        _td("JavaScript", "javascript", _config_javascript(connector_name)),
        _td("Kotlin",     "kotlin",     _config_kotlin(connector_name)),
        _td("Rust",       "rust",       _config_rust(connector_name)),
    ]

    header_row = "<tr>" + "".join(
        f"<td><b>{label}</b></td>"
        for label in ("Python", "JavaScript", "Kotlin", "Rust")
    ) + "</tr>"

    body_cells = "\n".join(cells)

    return [
        "## SDK Configuration",
        "",
        "Use this config for all flows in this connector. "
        "Replace `YOUR_API_KEY` with your actual credentials.",
        "",
        "<table>",
        header_row,
        "<tr>",
        body_cells,
        "</tr>",
        "</table>",
        "",
    ]


def render_payload_block(
    flow_key: str,
    service_name: str,
    grpc_request: str,
    proto_request: dict,
    message_schemas: dict,
) -> list[str]:
    """
    Return markdown lines for a single annotated request payload block.

    Renders the proto request as a Python dict literal with inline ``# comments``
    sourced from the proto field descriptions. One block per flow/PM sample;
    the config section at the top of the connector doc provides the SDK setup.

    Args:
        flow_key:         e.g. "authorize", "capture"
        service_name:     e.g. "PaymentService"
        grpc_request:     e.g. "PaymentServiceAuthorizeRequest"
        proto_request:    probe-verified request payload dict
        message_schemas:  manifest["message_schemas"] dict from field-probe binary

    Returns:
        List of markdown lines (caller should append them as-is).
    """
    if not proto_request or not grpc_request:
        return []

    db          = _SchemaDB(message_schemas)
    client_cls  = _client_class(service_name)
    camel_method = _to_camel(flow_key)
    payload     = _build_annotated(proto_request, grpc_request, db, style="python", indent=0)

    return [
        "",
        f"> **Client call:** `{client_cls}.{camel_method}(request)`",
        "",
        "```python",
        payload,
        "```",
        "",
    ]
