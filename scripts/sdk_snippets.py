"""
sdk_snippets.py — SDK integration example generator for connector docs.

All functions are pure (no I/O, no global state). Called by generate-connector-docs.py.

Proto field comments come from manifest["message_schemas"] (populated by field-probe).

Public API
----------
  detect_scenarios(probe_connector) -> list[ScenarioSpec]
    Infer applicable integration scenarios from probe data.

  render_config_section(connector_name) -> list[str]
    4-tab SDK config table — emitted once per connector doc.

  render_scenario_section(scenario, connector_name, flow_payloads,
                           flow_metadata, message_schemas, ann_scenario) -> list[str]
    Full 4-tab runnable scenario example + status-handling table.

  render_pm_reference_section(probe_connector, flow_metadata,
                               message_schemas) -> list[str]
    Per-PM payment_method payload reference block.

  render_payload_block(flow_key, service_name, grpc_request,
                       proto_request, message_schemas) -> list[str]
    Single annotated payload block (used in Flow Reference section).

  render_llms_txt_entry(connector_name, display_name, probe_connector,
                         scenarios) -> str
    One connector block for docs/llms.txt.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path


# ── Proto type map (built once from .proto files) ──────────────────────────────

# {message_name: {field_name: proto_type_name}}  — all messages across all protos
_PROTO_FIELD_TYPES: dict[str, dict[str, str]] = {}

# Set of message type names that are "scalar wrappers" (single `value` field).
# These are stored as plain scalars in probe data but must be sent as
# {"value": ...} dicts in ParseDict calls.
_PROTO_WRAPPER_TYPES: frozenset[str] = frozenset()


def load_proto_type_map(proto_dir: Path) -> None:
    """Parse all *.proto files in proto_dir to build _PROTO_FIELD_TYPES and _PROTO_WRAPPER_TYPES."""
    global _PROTO_FIELD_TYPES, _PROTO_WRAPPER_TYPES

    type_map: dict[str, dict[str, str]] = {}
    _FIELD_RE = re.compile(
        r"^\s*(?:optional\s+|repeated\s+)?(\w+)\s+(\w+)\s*=\s*\d+"
    )
    _SKIP_KEYWORDS = frozenset(
        ["message", "enum", "oneof", "reserved", "option", "extensions",
         "syntax", "import", "package", "service", "rpc", "returns"]
    )

    for proto_file in sorted(proto_dir.glob("*.proto")):
        text = proto_file.read_text(encoding="utf-8")
        # Strip // comments and /* */ blocks
        text = re.sub(r"//[^\n]*", "", text)
        text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)

        pos = 0
        while pos < len(text):
            m = re.search(r"\bmessage\s+(\w+)\s*\{", text[pos:])
            if not m:
                break
            msg_name = m.group(1)
            body_start = pos + m.end()

            # Find matching closing brace using depth counting
            depth = 1
            i = body_start
            while i < len(text) and depth > 0:
                if text[i] == "{":
                    depth += 1
                elif text[i] == "}":
                    depth -= 1
                i += 1
            body = text[body_start : i - 1]

            # Extract only top-level lines (not inside nested { })
            fields: dict[str, str] = {}
            inner_depth = 0
            for line in body.splitlines():
                inner_depth += line.count("{") - line.count("}")
                if inner_depth > 0:
                    continue
                fm = _FIELD_RE.match(line)
                if fm:
                    ftype, fname = fm.group(1), fm.group(2)
                    if ftype not in _SKIP_KEYWORDS and fname not in _SKIP_KEYWORDS:
                        fields[fname] = ftype

            type_map[msg_name] = fields
            pos = pos + m.start() + 1  # advance past this message keyword

    _PROTO_FIELD_TYPES = type_map
    # Wrapper types: messages whose only field is named "value"
    _PROTO_WRAPPER_TYPES = frozenset(
        name for name, fields in type_map.items()
        if set(fields.keys()) == {"value"}
    )


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

# PM keys that represent wallets (first supported one is used for checkout_wallet)
_WALLET_PM_KEYS = ["GooglePay", "ApplePay", "SamsungPay"]

# PM keys that represent bank transfers (first supported one is used for checkout_bank)
_BANK_PM_KEYS = ["Sepa", "Ach", "Bacs", "Becs"]

# Default status handling for flows that return payment status
_AUTHORIZE_STATUS_HANDLING: dict[str, str] = {
    "AUTHORIZED": "Funds reserved — proceed to Capture to settle",
    "PENDING":    "Awaiting async confirmation — wait for webhook before capturing",
    "FAILED":     "Payment declined — surface error to customer, do not retry without new details",
}

_SETUP_RECURRING_STATUS_HANDLING: dict[str, str] = {
    "PENDING": "Mandate stored — save connector_transaction_id for future RecurringPaymentService.Charge calls",
    "FAILED":  "Setup failed — customer must re-enter payment details",
}

# Human-readable step descriptions per flow key
_STEP_DESCRIPTIONS: dict[str, str] = {
    "authorize":        "Authorize — reserve funds on the payment method",
    "capture":          "Capture — settle the reserved funds",
    "refund":           "Refund — return funds to the customer",
    "void":             "Void — release reserved funds (cancel authorization)",
    "get":              "Get — retrieve current payment status from the connector",
    "tokenize":         "Tokenize — store card details and return a reusable token",
    "create_customer":  "Create Customer — register customer record in the connector",
    "pre_authenticate": "Pre-Authenticate — initiate 3DS flow (collect device/browser data)",
    "authenticate":     "Authenticate — execute 3DS challenge or frictionless verification",
    "post_authenticate": "Post-Authenticate — validate authentication result with the issuing bank",
    "setup_recurring":  "Setup Recurring — store the payment mandate",
    "recurring_charge": "Recurring Charge — charge against the stored mandate",
}

# Flow keys whose SDK method name differs from the flow key itself.
# All other flows use the flow key directly as the method name (snake_case).
_FLOW_KEY_TO_METHOD: dict[str, str] = {
    "recurring_charge": "charge",    # RecurringPaymentService.charge(), not .recurring_charge()
    "create_customer":  "create",    # CustomerClient.create(), not .create_customer()
}

# Variable name used for the response of each flow step.
# Defaults to "{first_word_of_flow_key}_response" for most flows.
_FLOW_VAR_NAME: dict[str, str] = {
    "pre_authenticate":  "pre_authenticate_response",
    "authenticate":      "authenticate_response",
    "post_authenticate": "post_authenticate_response",
    "create_customer":   "create_response",
    "setup_recurring":   "setup_response",
    "recurring_charge":  "recurring_response",
}

# Fields that must reference the response of a previous flow step
# Maps (scenario_key, flow_key, field_name) -> Python expression string
_DYNAMIC_FIELDS: dict[tuple[str, str, str], str] = {
    ("checkout_card",      "capture",          "connector_transaction_id"): "authorize_response.connector_transaction_id",
    ("refund",             "refund",            "connector_transaction_id"): "authorize_response.connector_transaction_id",
    ("void_payment",       "void",             "connector_transaction_id"): "authorize_response.connector_transaction_id",
    ("get_payment",        "get",              "connector_transaction_id"): "authorize_response.connector_transaction_id",
    ("recurring",          "recurring_charge",  "connector_recurring_payment_id"): '{"connector_mandate_id": {"connector_mandate_id": setup_response.connector_recurring_payment_id}}',
}


# ── Scenario dataclass ─────────────────────────────────────────────────────────

@dataclass
class ScenarioSpec:
    key:             str               # e.g. "checkout_card"
    title:           str               # e.g. "Card Payment (Authorize + Capture)"
    flows:           list[str]         # ordered flow_keys e.g. ["authorize", "capture"]
    pm_key:          str | None        # primary PM for authorize, e.g. "Card"; None for refund/recurring
    description:     str               # one-liner shown in docs
    status_handling: dict[str, str]    # STATUS -> action description (for status table)


# ── Scenario detection ─────────────────────────────────────────────────────────

def detect_scenarios(probe_connector: dict) -> list[ScenarioSpec]:
    """
    Inspect probe data and return the applicable integration scenarios in display order.

    Rules:
      checkout_card        — authorize(Card) + capture both supported
      checkout_autocapture — authorize(Card) supported (no separate capture call)
      checkout_wallet      — authorize(GooglePay|ApplePay|SamsungPay) supported
      checkout_bank        — authorize(Sepa|Ach|Bacs|Becs) supported
      refund               — refund supported AND Card authorize supported
      recurring            — setup_recurring + recurring_charge both supported
    """
    flows = probe_connector.get("flows", {})

    def ok(flow_key: str, pm_key: str = "default") -> bool:
        return flows.get(flow_key, {}).get(pm_key, {}).get("status") == "supported"

    def has_payload(flow_key: str, pm_key: str = "default") -> bool:
        return bool(flows.get(flow_key, {}).get(pm_key, {}).get("proto_request"))

    card_ok           = ok("authorize", "Card") and has_payload("authorize", "Card")
    capture_ok        = ok("capture")
    refund_ok         = ok("refund")
    void_ok           = ok("void") and has_payload("void")
    get_ok            = ok("get") and has_payload("get")
    tokenize_ok       = ok("tokenize") and has_payload("tokenize")
    create_customer_ok = ok("create_customer") and has_payload("create_customer")
    setup_ok          = ok("setup_recurring")
    charge_ok         = ok("recurring_charge")
    pre_auth_ok       = ok("pre_authenticate") and has_payload("pre_authenticate")
    auth_ok           = ok("authenticate") and has_payload("authenticate")
    post_auth_ok      = ok("post_authenticate") and has_payload("post_authenticate")

    scenarios: list[ScenarioSpec] = []

    if card_ok and capture_ok:
        scenarios.append(ScenarioSpec(
            key="checkout_card",
            title="Card Payment (Authorize + Capture)",
            flows=["authorize", "capture"],
            pm_key="Card",
            description=(
                "Reserve funds with Authorize, then settle with a separate Capture call. "
                "Use for physical goods or delayed fulfillment where capture happens later."
            ),
            status_handling=_AUTHORIZE_STATUS_HANDLING,
        ))

    if card_ok:
        scenarios.append(ScenarioSpec(
            key="checkout_autocapture",
            title="Card Payment (Automatic Capture)",
            flows=["authorize"],
            pm_key="Card",
            description=(
                "Authorize and capture in one call using `capture_method=AUTOMATIC`. "
                "Use for digital goods or immediate fulfillment."
            ),
            status_handling=_AUTHORIZE_STATUS_HANDLING,
        ))

    for wallet_pm in _WALLET_PM_KEYS:
        if ok("authorize", wallet_pm) and has_payload("authorize", wallet_pm):
            scenarios.append(ScenarioSpec(
                key="checkout_wallet",
                title="Wallet Payment (Google Pay / Apple Pay)",
                flows=["authorize"],
                pm_key=wallet_pm,
                description=(
                    "Wallet payments pass an encrypted token from the browser/device SDK. "
                    "Pass the token blob directly — do not decrypt client-side."
                ),
                status_handling=_AUTHORIZE_STATUS_HANDLING,
            ))
            break

    for bank_pm in _BANK_PM_KEYS:
        if ok("authorize", bank_pm) and has_payload("authorize", bank_pm):
            scenarios.append(ScenarioSpec(
                key="checkout_bank",
                title="Bank Transfer (SEPA / ACH / BACS)",
                flows=["authorize"],
                pm_key=bank_pm,
                description=(
                    f"Direct bank debit ({bank_pm}). "
                    "Bank transfers typically use `capture_method=AUTOMATIC`."
                ),
                status_handling=_AUTHORIZE_STATUS_HANDLING,
            ))
            break

    if refund_ok and card_ok:
        scenarios.append(ScenarioSpec(
            key="refund",
            title="Refund a Payment",
            flows=["authorize", "refund"],
            pm_key="Card",
            description=(
                "Authorize with automatic capture, then refund the captured amount. "
                "`connector_transaction_id` from the Authorize response is reused for the Refund call."
            ),
            status_handling={},
        ))

    if setup_ok and charge_ok:
        scenarios.append(ScenarioSpec(
            key="recurring",
            title="Recurring / Mandate Payments",
            flows=["setup_recurring", "recurring_charge"],
            pm_key=None,
            description=(
                "Store a payment mandate with SetupRecurring, then charge it repeatedly "
                "with RecurringPaymentService.Charge without requiring customer action."
            ),
            status_handling=_SETUP_RECURRING_STATUS_HANDLING,
        ))

    if card_ok and void_ok:
        scenarios.append(ScenarioSpec(
            key="void_payment",
            title="Void a Payment",
            flows=["authorize", "void"],
            pm_key="Card",
            description=(
                "Authorize funds with a manual capture flag, then cancel the authorization "
                "with Void before any capture occurs. Releases the hold on the customer's funds."
            ),
            status_handling={},
        ))

    if card_ok and get_ok:
        scenarios.append(ScenarioSpec(
            key="get_payment",
            title="Get Payment Status",
            flows=["authorize", "get"],
            pm_key="Card",
            description=(
                "Authorize a payment, then poll the connector for its current status using Get. "
                "Use this to sync payment state when webhooks are unavailable or delayed."
            ),
            status_handling={},
        ))

    if create_customer_ok:
        scenarios.append(ScenarioSpec(
            key="create_customer",
            title="Create Customer",
            flows=["create_customer"],
            pm_key=None,
            description=(
                "Register a customer record in the connector system. "
                "Returns a connector_customer_id that can be reused for recurring payments "
                "and tokenized card storage."
            ),
            status_handling={},
        ))

    if tokenize_ok:
        scenarios.append(ScenarioSpec(
            key="tokenize",
            title="Tokenize Payment Method",
            flows=["tokenize"],
            pm_key=None,
            description=(
                "Store card details in the connector's vault and receive a reusable payment token. "
                "Use the returned token for one-click payments and recurring billing "
                "without re-collecting card data."
            ),
            status_handling={},
        ))

    if pre_auth_ok and auth_ok and post_auth_ok:
        scenarios.append(ScenarioSpec(
            key="authentication",
            title="3DS Authentication",
            flows=["pre_authenticate", "authenticate", "post_authenticate"],
            pm_key=None,
            description=(
                "Full 3D Secure authentication flow: PreAuthenticate collects device/browser data, "
                "Authenticate executes the challenge or frictionless verification, "
                "PostAuthenticate validates the result with the issuing bank."
            ),
            status_handling={},
        ))

    return scenarios


# ── Message schema proxy ───────────────────────────────────────────────────────

class _SchemaDB:
    """Proxy over manifest["message_schemas"] + parsed proto field types."""

    def __init__(self, message_schemas: dict) -> None:
        self._schemas = message_schemas

    def get_comment(self, msg: str, field: str) -> str:
        return self._schemas.get(msg, {}).get("comments", {}).get(field, "")

    def get_type(self, msg: str, field: str) -> str:
        # Try manifest schemas first, fall back to parsed proto type map
        t = self._schemas.get(msg, {}).get("field_types", {}).get(field, "")
        if not t:
            t = _PROTO_FIELD_TYPES.get(msg, {}).get(field, "")
        return t

    def is_wrapper(self, type_name: str) -> bool:
        """Return True if type_name is a single-value wrapper message (e.g. SecretString)."""
        return type_name in _PROTO_WRAPPER_TYPES

    def single_field_wrapper_key(self, type_name: str) -> str | None:
        """If type_name has exactly one field and that field's type is a wrapper, return the field name.
        Used for messages like TokenPaymentMethodType whose single field is a SecretString."""
        fields = _PROTO_FIELD_TYPES.get(type_name, {})
        if len(fields) == 1:
            field_name, field_type = next(iter(fields.items()))
            if self.is_wrapper(field_type):
                return field_name
        return None


# ── Annotated JSON rendering ───────────────────────────────────────────────────

def _json_scalar(val: object) -> str:
    """Convert a scalar value to its Python literal representation."""
    if isinstance(val, bool):
        return "True" if val else "False"
    if val is None:
        return "None"
    return json.dumps(val)


def _annotate_inline_lines(
    obj: dict,
    msg_name: str,
    db: _SchemaDB,
    indent: int,
    cmt: str,
) -> list[str]:
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
        elif child_msg and db.is_wrapper(child_msg):
            # Scalar stored in probe data, but proto field is a wrapper message — needs {"value": ...}
            lines.append(f'{pad}"{key}": {{"value": {_json_scalar(val)}}}{trailing}{cmt_part}')
        elif child_msg and not isinstance(val, (dict, list)):
            # Scalar for a non-wrapper message — check if msg has one field that is itself a wrapper
            inner_key = db.single_field_wrapper_key(child_msg)
            if inner_key:
                lines.append(f'{pad}"{key}": {{"{inner_key}": {{"value": {_json_scalar(val)}}}}}{trailing}{cmt_part}')
            else:
                lines.append(f'{pad}"{key}": {_json_scalar(val)}{trailing}{cmt_part}')
        else:
            lines.append(f'{pad}"{key}": {_json_scalar(val)}{trailing}{cmt_part}')

    return lines


def _annotate_before_lines(
    obj: dict,
    msg_name: str,
    db: _SchemaDB,
    indent: int,
) -> list[str]:
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
    style: str,
    indent: int = 0,
) -> str:
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
from payments.generated import sdk_config_pb2, payment_pb2

config = sdk_config_pb2.ConnectorConfig(
    connector=payment_pb2.Connector.{conn_enum},
    environment=sdk_config_pb2.Environment.SANDBOX,
)
# Set credentials before running (field names depend on connector auth type):
# config.auth.{connector_name}.api_key.value = "YOUR_API_KEY"
"""


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
    return (
        f'<td valign="top">\n\n'
        f"<details><summary>{label}</summary>\n\n"
        f"```{fence_lang}\n"
        f"{code}\n"
        f"```\n\n"
        f"</details>\n\n"
        f"</td>"
    )


# ── Scenario snippet builders ──────────────────────────────────────────────────

def _scenario_step_python(
    scenario_key: str,
    flow_key: str,
    step_num: int,
    payload: dict,
    grpc_req: str,
    client_var: str,
    db: _SchemaDB,
) -> list[str]:
    """
    Return lines for one step inside a scenario function body.
    Indentation: function body = 4 spaces, ParseDict args = 8 spaces, payload fields = 12 spaces.
    """
    method   = _FLOW_KEY_TO_METHOD.get(flow_key, flow_key)  # Python SDK uses snake_case method names
    var_name = _FLOW_VAR_NAME.get(flow_key, f"{flow_key.split('_')[0]}_response")
    desc     = _STEP_DESCRIPTIONS.get(flow_key, flow_key)
    lines: list[str] = []

    lines.append(f"    # Step {step_num}: {desc}")
    lines.append(f"    {var_name} = await {client_var}.{method}(ParseDict(")
    lines.append("        {")

    if payload:
        items = list(payload.items())
        for idx, (key, val) in enumerate(items):
            trailing  = "," if idx < len(items) - 1 else ""
            comment   = db.get_comment(grpc_req, key)
            child_msg = db.get_type(grpc_req, key)
            cmt_part  = f"  # {comment}" if comment else ""

            # Check if this field should reference a previous response
            dyn = _DYNAMIC_FIELDS.get((scenario_key, flow_key, key))
            if dyn:
                extra = f"  # from Authorize response" if "connector_transaction_id" in key else f"  # from SetupRecurring response"
                lines.append(f'            "{key}": {dyn},{extra}')
            elif isinstance(val, dict):
                lines.append(f'            "{key}": {{{cmt_part}')
                lines.extend(_annotate_inline_lines(val, child_msg, db, indent=4, cmt="#"))
                lines.append(f'            }}{trailing}')
            elif child_msg and db.is_wrapper(child_msg):
                # Scalar stored in probe data, but proto type is a wrapper message
                lines.append(f'            "{key}": {{"value": {_json_scalar(val)}}}{trailing}{cmt_part}')
            elif child_msg and not isinstance(val, (dict, list)):
                # Scalar for a non-wrapper message — check if msg has one field that is itself a wrapper
                inner_key = db.single_field_wrapper_key(child_msg)
                if inner_key:
                    lines.append(f'            "{key}": {{"{inner_key}": {{"value": {_json_scalar(val)}}}}}{trailing}{cmt_part}')
                else:
                    lines.append(f'            "{key}": {_json_scalar(val)}{trailing}{cmt_part}')
            else:
                lines.append(f'            "{key}": {_json_scalar(val)}{trailing}{cmt_part}')
    else:
        lines.append('            # No required fields')

    lines.append("        },")
    if grpc_req:
        lines.append(f"        payment_pb2.{grpc_req}(),")
    lines.append("    ))")
    lines.append("")

    # Status branching for flows that drive the payment state machine
    if flow_key == "authorize":
        lines.append(f'    if {var_name}.status == "FAILED":')
        lines.append(f'        raise RuntimeError(f"Payment failed: {{{var_name}.error}}")')
        lines.append(f'    if {var_name}.status == "PENDING":')
        lines.append(f'        # Awaiting async confirmation — handle via webhook')
        lines.append(f'        return {{"status": "pending", "transaction_id": {var_name}.connector_transaction_id}}')
        lines.append("")
    elif flow_key == "setup_recurring":
        lines.append(f'    if {var_name}.status == "FAILED":')
        lines.append(f'        raise RuntimeError(f"Recurring setup failed: {{{var_name}.error}}")')
        lines.append(f'    if {var_name}.status == "PENDING":')
        lines.append(f'        # Mandate stored asynchronously — save connector_recurring_payment_id')
        lines.append(f'        return {{"status": "pending", "mandate_id": {var_name}.connector_recurring_payment_id}}')
        lines.append("")
    elif flow_key in ("capture", "refund", "recurring_charge"):
        lines.append(f'    if {var_name}.status == "FAILED":')
        lines.append(f'        raise RuntimeError(f"{flow_key.title()} failed: {{{var_name}.error}}")')
        lines.append("")

    return lines


def _scenario_return_python(scenario: ScenarioSpec) -> str:
    """Return the final return statement for a scenario function."""
    if scenario.key in ("checkout_card",):
        return '    return {"status": capture_response.status, "transaction_id": authorize_response.connector_transaction_id}'
    elif scenario.key in ("checkout_autocapture", "checkout_wallet", "checkout_bank"):
        return '    return {"status": authorize_response.status, "transaction_id": authorize_response.connector_transaction_id}'
    elif scenario.key == "refund":
        return '    return {"status": refund_response.status}'
    elif scenario.key == "recurring":
        return '    return {"status": recurring_response.status, "transaction_id": getattr(recurring_response, "connector_transaction_id", "")}'
    elif scenario.key == "void_payment":
        return '    return {"status": void_response.status, "transaction_id": authorize_response.connector_transaction_id}'
    elif scenario.key == "get_payment":
        return '    return {"status": get_response.status, "transaction_id": get_response.connector_transaction_id}'
    elif scenario.key == "create_customer":
        return '    return {"customer_id": create_response.connector_customer_id}'
    elif scenario.key == "tokenize":
        return '    return {"token": tokenize_response.payment_method_token}'
    elif scenario.key == "authentication":
        return '    return {"status": post_authenticate_response.status}'
    return '    return {}'


def render_scenario_python(
    scenario: ScenarioSpec,
    connector_name: str,
    flow_payloads: dict[str, dict],
    flow_metadata: dict[str, dict],
    message_schemas: dict,
) -> str:
    """Return the full content of a runnable Python scenario file."""
    db         = _SchemaDB(message_schemas)
    conn_enum  = _conn_enum(connector_name)
    func_name  = f"process_{scenario.key}"

    # Collect unique service names and their client classes
    service_names: list[str] = []
    for fk in scenario.flows:
        svc = flow_metadata.get(fk, {}).get("service_name", "PaymentService")
        if svc not in service_names:
            service_names.append(svc)

    client_imports = "\n".join(
        f"from payments import {_client_class(svc)}" for svc in service_names
    )

    # Build function body
    body_lines: list[str] = []

    # Instantiate clients
    for svc in service_names:
        cls     = _client_class(svc)
        var     = cls.lower().replace("client", "_client")
        body_lines.append(f"    {var} = {cls}(config)")
    body_lines.append("")

    # One step per flow
    for step_num, flow_key in enumerate(scenario.flows, 1):
        meta       = flow_metadata.get(flow_key, {})
        svc        = meta.get("service_name", "PaymentService")
        grpc_req   = meta.get("grpc_request", "")
        client_var = _client_class(svc).lower().replace("client", "_client")

        payload = dict(flow_payloads.get(flow_key, {}))
        if flow_key == "authorize":
            if scenario.key in ("checkout_card", "void_payment", "get_payment"):
                # reserve funds only — capture/void/get happens in the next step
                payload["capture_method"] = "MANUAL"
            elif scenario.key == "refund":
                # refund scenario needs the payment already captured
                payload["capture_method"] = "AUTOMATIC"

        body_lines.extend(_scenario_step_python(
            scenario.key, flow_key, step_num, payload, grpc_req, client_var, db
        ))

    body_lines.append(_scenario_return_python(scenario))
    body = "\n".join(body_lines)

    return f"""\
# This file is auto-generated. Do not edit manually.
# Replace YOUR_API_KEY and placeholder values with real data.
# Regenerate: python3 scripts/generate-connector-docs.py {connector_name}
#
# Scenario: {scenario.title}
# {scenario.description}

import asyncio
from google.protobuf.json_format import ParseDict
{client_imports}
from payments.generated import sdk_config_pb2, payment_pb2

_default_config = sdk_config_pb2.ConnectorConfig(
    connector=payment_pb2.Connector.{conn_enum},
    environment=sdk_config_pb2.Environment.SANDBOX,
)
# Standalone credentials (field names depend on connector auth type):
# _default_config.auth.{connector_name}.api_key.value = "YOUR_API_KEY"


async def {func_name}(merchant_transaction_id: str, config: sdk_config_pb2.ConnectorConfig = _default_config):
    \"\"\"{scenario.title}

    {scenario.description}
    \"\"\"
{body}


if __name__ == "__main__":
    asyncio.run({func_name}("order_001"))
"""


def _scenario_step_javascript(
    scenario_key: str,
    flow_key: str,
    step_num: int,
    payload: dict,
    grpc_req: str,
    db: _SchemaDB,
) -> list[str]:
    """Return lines for one step inside a JavaScript scenario function body."""
    method   = _to_camel(flow_key)
    _js_var_defaults = {k: _to_camel(v.replace("_response", "Response")) for k, v in _FLOW_VAR_NAME.items()}
    var_name = _js_var_defaults.get(flow_key, f"{flow_key.split('_')[0]}Response")
    desc     = _STEP_DESCRIPTIONS.get(flow_key, flow_key)
    lines: list[str] = []

    lines.append(f"    // Step {step_num}: {desc}")
    lines.append(f"    const {var_name} = await client.{method}({{")

    if payload:
        items = list(payload.items())
        for idx, (key, val) in enumerate(items):
            trailing  = "," if idx < len(items) - 1 else ""
            comment   = db.get_comment(grpc_req, key)
            child_msg = db.get_type(grpc_req, key)
            cmt_part  = f"  // {comment}" if comment else ""

            dyn = _DYNAMIC_FIELDS.get((scenario_key, flow_key, key))
            if dyn:
                extra = "  // from authorize response"
                lines.append(f'        "{key}": {dyn},{extra}')
            elif isinstance(val, dict):
                lines.append(f'        "{key}": {{{cmt_part}')
                lines.extend(_annotate_inline_lines(val, child_msg, db, indent=3, cmt="//"))
                lines.append(f'        }}{trailing}')
            else:
                lines.append(f'        "{key}": {_json_scalar(val)}{trailing}{cmt_part}')
    else:
        lines.append('        // No required fields')

    lines.append("    });")
    lines.append("")

    if flow_key == "authorize":
        lines.append(f"    if ({var_name}.status === 'FAILED') {{")
        lines.append(f"        throw new Error(`Payment failed: ${{{var_name}.error?.message}}`);")
        lines.append("    }")
        lines.append(f"    if ({var_name}.status === 'PENDING') {{")
        lines.append(f"        // Awaiting async confirmation — handle via webhook")
        lines.append(f"        return {{ status: 'pending', transactionId: {var_name}.connector_transaction_id }};")
        lines.append("    }")
        lines.append("")
    elif flow_key == "setup_recurring":
        lines.append(f"    if ({var_name}.status === 'FAILED') {{")
        lines.append(f"        throw new Error(`Recurring setup failed: ${{{var_name}.error?.message}}`);")
        lines.append("    }")
        lines.append("")
    elif flow_key in ("capture", "refund", "recurring_charge"):
        lines.append(f"    if ({var_name}.status === 'FAILED') {{")
        lines.append(f"        throw new Error(`{flow_key.title()} failed: ${{{var_name}.error?.message}}`);")
        lines.append("    }")
        lines.append("")

    return lines


def _scenario_return_javascript(scenario: ScenarioSpec) -> str:
    if scenario.key == "checkout_card":
        return "    return { status: captureResponse.status, transactionId: authorizeResponse.connector_transaction_id };"
    elif scenario.key in ("checkout_autocapture", "checkout_wallet", "checkout_bank"):
        return "    return { status: authorizeResponse.status, transactionId: authorizeResponse.connector_transaction_id };"
    elif scenario.key == "refund":
        return "    return { status: refundResponse.status };"
    elif scenario.key == "recurring":
        return "    return { status: recurringResponse.status, transactionId: recurringResponse.connector_transaction_id ?? '' };"
    elif scenario.key == "void_payment":
        return "    return { status: voidResponse.status, transactionId: authorizeResponse.connector_transaction_id };"
    elif scenario.key == "get_payment":
        return "    return { status: getResponse.status, transactionId: getResponse.connector_transaction_id };"
    elif scenario.key == "create_customer":
        return "    return { customerId: createResponse.connector_customer_id };"
    elif scenario.key == "tokenize":
        return "    return { token: tokenizeResponse.payment_method_token };"
    elif scenario.key == "authentication":
        return "    return { status: postAuthenticateResponse.status };"
    return "    return {};"


def render_scenario_javascript(
    scenario: ScenarioSpec,
    connector_name: str,
    flow_payloads: dict[str, dict],
    flow_metadata: dict[str, dict],
    message_schemas: dict,
) -> str:
    """Return the full content of a runnable JavaScript scenario file."""
    db           = _SchemaDB(message_schemas)
    conn_display = _conn_display(connector_name)
    func_name    = _to_camel(f"process_{scenario.key}")

    body_lines: list[str] = []
    for step_num, flow_key in enumerate(scenario.flows, 1):
        meta     = flow_metadata.get(flow_key, {})
        grpc_req = meta.get("grpc_request", "")

        payload = dict(flow_payloads.get(flow_key, {}))
        if flow_key == "authorize":
            if scenario.key in ("checkout_card", "void_payment", "get_payment"):
                payload["capture_method"] = "MANUAL"
            elif scenario.key == "refund":
                payload["capture_method"] = "AUTOMATIC"

        body_lines.extend(_scenario_step_javascript(
            scenario.key, flow_key, step_num, payload, grpc_req, db
        ))

    body_lines.append(_scenario_return_javascript(scenario))
    body = "\n".join(body_lines)

    return f"""\
// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py {connector_name}
//
// Scenario: {scenario.title}
// {scenario.description}

const {{ ConnectorClient }} = require('connector-service-node-ffi');

const client = new ConnectorClient({{
    connector: '{conn_display}',
    environment: 'sandbox',
    connector_auth_type: {{
        header_key: {{ api_key: 'YOUR_API_KEY' }},
    }},
}});

async function {func_name}(merchantTransactionId) {{
    // {scenario.title}
    // {scenario.description}

{body}
}}
"""


# ── Public API: Config section ─────────────────────────────────────────────────

def render_config_section(connector_name: str) -> list[str]:
    """
    Return markdown lines for the SDK Configuration section (once per connector doc).
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

    return [
        "## SDK Configuration",
        "",
        "Use this config for all flows in this connector. "
        "Replace `YOUR_API_KEY` with your actual credentials.",
        "",
        "<table>",
        header_row,
        "<tr>",
        "\n".join(cells),
        "</tr>",
        "</table>",
        "",
    ]


# ── Public API: Scenario section ───────────────────────────────────────────────

def render_scenario_section(
    scenario: ScenarioSpec,
    connector_name: str,
    flow_payloads: dict[str, dict],
    flow_metadata: dict[str, dict],
    message_schemas: dict,
    ann_scenario: dict,
) -> list[str]:
    """
    Return markdown lines for one scenario subsection inside ## Integration Scenarios.
    Emits links to the pre-generated example files instead of embedding code.
    """
    title      = ann_scenario.get("title", scenario.title)
    description = ann_scenario.get("description", scenario.description)
    status_hdl  = ann_scenario.get("status_handling", scenario.status_handling)

    out: list[str] = []
    a = out.append

    a(f"### {title}")
    a("")
    a(description)
    a("")

    if status_hdl:
        a("**Response status handling:**")
        a("")
        a("| Status | Recommended action |")
        a("|--------|-------------------|")
        for status, action in status_hdl.items():
            a(f"| `{status}` | {action} |")
        a("")

    py_path = f"../../examples/{connector_name}/python/{scenario.key}.py"
    js_path = f"../../examples/{connector_name}/javascript/{scenario.key}.js"
    a(f"**Examples:** [Python]({py_path}) · [JavaScript]({js_path})")
    a("")
    a("> **Kotlin / Rust:** See `examples/{connector_name}/kotlin/` and `examples/{connector_name}/rust/`"
      " for per-flow examples covering each individual API call in this scenario.")
    a("")

    return out


# ── Public API: Per-flow example file renderers ────────────────────────────────

def render_flow_python(
    flow_key: str,
    connector_name: str,
    proto_req: dict,
    flow_metadata: dict[str, dict],
    message_schemas: dict,
    pm_label: str = "",
) -> str:
    """Return the full content of a runnable Python file for a single flow."""
    db         = _SchemaDB(message_schemas)
    meta       = flow_metadata.get(flow_key, {})
    svc        = meta.get("service_name", "PaymentService")
    grpc_req   = meta.get("grpc_request", "")
    rpc_name   = meta.get("rpc_name", flow_key)
    conn_enum  = _conn_enum(connector_name)
    client_cls = _client_class(svc)
    client_var = client_cls.lower().replace("client", "_client")

    body_lines: list[str] = [f"    {client_var} = {client_cls}(config)", ""]
    body_lines.extend(_scenario_step_python("_standalone_", flow_key, 1, proto_req, grpc_req, client_var, db))

    resp_var = f"{flow_key.split('_')[0]}_response"
    if flow_key == "authorize":
        body_lines.append(f'    return {{"status": {resp_var}.status, "transaction_id": {resp_var}.connector_transaction_id}}')
    elif flow_key == "setup_recurring":
        body_lines.append(f'    return {{"status": {resp_var}.status, "mandate_id": {resp_var}.connector_transaction_id}}')
    else:
        body_lines.append(f'    return {{"status": {resp_var}.status}}')

    body      = "\n".join(body_lines)
    svc_label = f"{svc}.{rpc_name}"
    pm_part   = f" ({pm_label})" if pm_label else ""

    return f"""\
# This file is auto-generated. Do not edit manually.
# Replace YOUR_API_KEY and placeholder values with real data.
# Regenerate: python3 scripts/generate-connector-docs.py {connector_name}
#
# Flow: {svc_label}{pm_part}

import asyncio
from google.protobuf.json_format import ParseDict
from payments import {client_cls}
from payments.generated import sdk_config_pb2, payment_pb2

_default_config = sdk_config_pb2.ConnectorConfig(
    connector=payment_pb2.Connector.{conn_enum},
    environment=sdk_config_pb2.Environment.SANDBOX,
)
# Standalone credentials (field names depend on connector auth type):
# _default_config.auth.{connector_name}.api_key.value = "YOUR_API_KEY"


async def {flow_key}(merchant_transaction_id: str, config: sdk_config_pb2.ConnectorConfig = _default_config):
{body}


if __name__ == "__main__":
    asyncio.run({flow_key}("order_001"))
"""


def render_flow_javascript(
    flow_key: str,
    connector_name: str,
    proto_req: dict,
    flow_metadata: dict[str, dict],
    message_schemas: dict,
    pm_label: str = "",
) -> str:
    """Return the full content of a runnable JavaScript file for a single flow."""
    db           = _SchemaDB(message_schemas)
    meta         = flow_metadata.get(flow_key, {})
    svc          = meta.get("service_name", "PaymentService")
    grpc_req     = meta.get("grpc_request", "")
    rpc_name     = meta.get("rpc_name", flow_key)
    conn_display = _conn_display(connector_name)
    _JS_RESERVED = frozenset({"void", "delete", "return", "new", "in", "do", "for", "if"})
    func_name    = (_to_camel(flow_key) if flow_key not in _JS_RESERVED else f"{flow_key}Payment")
    var_name     = f"{flow_key.split('_')[0]}Response"

    body_lines: list[str] = list(_scenario_step_javascript("_standalone_", flow_key, 1, proto_req, grpc_req, db))

    if flow_key == "authorize":
        body_lines.append(f"    return {{ status: {var_name}.status, transactionId: {var_name}.connector_transaction_id }};")
    elif flow_key == "setup_recurring":
        body_lines.append(f"    return {{ status: {var_name}.status, mandateId: {var_name}.connector_transaction_id }};")
    else:
        body_lines.append(f"    return {{ status: {var_name}.status }};")

    body      = "\n".join(body_lines)
    svc_label = f"{svc}.{rpc_name}"
    pm_part   = f" ({pm_label})" if pm_label else ""

    return f"""\
// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py {connector_name}
//
// Flow: {svc_label}{pm_part}

const {{ ConnectorClient }} = require('connector-service-node-ffi');

const client = new ConnectorClient({{
    connector: '{conn_display}',
    environment: 'sandbox',
    connector_auth_type: {{
        header_key: {{ api_key: 'YOUR_API_KEY' }},
    }},
}});

async function {func_name}(merchantTransactionId) {{
{body}
}}

{func_name}("order_001").catch(console.error);
"""


def render_flow_kotlin(
    flow_key: str,
    connector_name: str,
    proto_req: dict,
    flow_metadata: dict[str, dict],
    message_schemas: dict,
    pm_label: str = "",
) -> str:
    """Return the full content of a runnable Kotlin file for a single flow."""
    meta       = flow_metadata.get(flow_key, {})
    svc        = meta.get("service_name", "PaymentService")
    grpc_req   = meta.get("grpc_request", "")
    rpc_name   = meta.get("rpc_name", flow_key)
    conn_enum  = _conn_enum(connector_name)
    client_cls = _client_class(svc)
    method     = _to_camel(flow_key)

    body_lines = _kotlin_payload_lines(proto_req, grpc_req, message_schemas, indent=2)
    body       = "\n".join(body_lines)

    svc_label  = f"{svc}.{rpc_name}"
    pm_part    = f" ({pm_label})" if pm_label else ""

    # Status handling for flows that return payment status
    if flow_key == "authorize":
        status_block = (
            '    when (response.status.name) {\n'
            '        "FAILED"  -> throw RuntimeException("Authorize failed: ${response.error.message}")\n'
            '        "PENDING" -> println("Pending — await webhook before proceeding")\n'
            '        else      -> println("Authorized: ${response.connectorTransactionId}")\n'
            '    }'
        )
    elif flow_key == "setup_recurring":
        status_block = (
            '    when (response.status.name) {\n'
            '        "FAILED" -> throw RuntimeException("Setup failed: ${response.error.message}")\n'
            '        else     -> println("Mandate stored: ${response.connectorTransactionId}")\n'
            '    }'
        )
    elif flow_key in ("capture", "refund", "recurring_charge", "void"):
        status_block = (
            f'    if (response.status.name == "FAILED")\n'
            f'        throw RuntimeException("{flow_key.title()} failed: ${{response.error.message}}")\n'
            f'    println("Done: ${{response.status.name}}")'
        )
    else:
        status_block = '    println("Status: ${response.status.name}")'

    return f"""\
// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py {connector_name}
//
// Flow: {svc_label}{pm_part}
//
// SDK: sdk/java (Kotlin/JVM — uses UniFFI protobuf builder pattern)
// Build: ./gradlew compileKotlin  (from sdk/java/)

import payments.{client_cls}
import payments.ConnectorConfig
import payments.Connector
import payments.Environment

fun main() {{
    val config = ConnectorConfig.newBuilder()
        .setConnector(Connector.{conn_enum})
        .setEnvironment(Environment.SANDBOX)
        // .setAuth(...) — set your connector auth here
        .build()

    val client = {client_cls}(config)

    val request = {grpc_req}.newBuilder().apply {{
{body}
    }}.build()

    val response = client.{method}(request)
{status_block}
}}
"""


def _kotlin_payload_lines(
    obj: dict,
    msg_name: str,
    message_schemas: dict,
    indent: int,
) -> list[str]:
    """Recursively build Kotlin builder apply-block lines for a proto payload dict."""
    pad    = "    " * indent
    db     = _SchemaDB(message_schemas)
    lines: list[str] = []

    for key, val in obj.items():
        camel = _to_camel(key)
        comment = db.get_comment(msg_name, key)
        child_msg = db.get_type(msg_name, key)
        cmt_part = f"  // {comment}" if comment else ""

        if isinstance(val, dict):
            lines.append(f"{pad}{camel}Builder.apply {{{cmt_part}")
            lines.extend(_kotlin_payload_lines(val, child_msg, message_schemas, indent + 1))
            lines.append(f"{pad}}}")
        elif isinstance(val, bool):
            lines.append(f"{pad}{camel} = {str(val).lower()}{cmt_part}")
        elif isinstance(val, int):
            lines.append(f"{pad}{camel} = {val}L{cmt_part}")
        elif isinstance(val, float):
            lines.append(f"{pad}{camel} = {val}{cmt_part}")
        elif isinstance(val, str):
            # String wrapper proto fields (e.g. card_number, card_cvc) use Builder.value
            # Heuristic: if child_msg is empty (scalar string), use Builder.value for sensitive-looking fields
            # For simplicity emit both options as a comment
            lines.append(f'{pad}{camel}Builder.value = {json.dumps(val)}{cmt_part}')
        else:
            lines.append(f"{pad}// {camel}: {json.dumps(val)}{cmt_part}")

    return lines


def render_flow_rust(
    flow_key: str,
    connector_name: str,
    proto_req: dict,
    flow_metadata: dict[str, dict],
    message_schemas: dict,
    pm_label: str = "",
) -> str:
    """Return the full content of a runnable Rust file for a single flow."""
    meta      = flow_metadata.get(flow_key, {})
    svc       = meta.get("service_name", "PaymentService")
    grpc_req  = meta.get("grpc_request", "")
    rpc_name  = meta.get("rpc_name", flow_key)
    conn_enum = connector_name.replace("_", "").title()  # "adyen" -> "Adyen"
    method    = flow_key  # Rust uses snake_case

    body_lines = _rust_payload_lines(proto_req, grpc_req, message_schemas, indent=1)
    body       = "\n".join(body_lines)

    svc_label = f"{svc}.{rpc_name}"
    pm_part   = f" ({pm_label})" if pm_label else ""

    if flow_key == "authorize":
        status_block = (
            '    match response.status() {\n'
            '        PaymentStatus::Failed  => panic!("Authorize failed: {:?}", response.error),\n'
            '        PaymentStatus::Pending => println!("Pending — await webhook"),\n'
            '        _                      => println!("Authorized: {}", response.connector_transaction_id),\n'
            '    }'
        )
    elif flow_key == "setup_recurring":
        status_block = (
            '    if response.status() == PaymentStatus::Failed {\n'
            '        panic!("Setup failed: {:?}", response.error);\n'
            '    }\n'
            '    println!("Mandate: {}", response.connector_transaction_id);'
        )
    else:
        status_block = '    println!("Status: {:?}", response.status());'

    return f"""\
// This file is auto-generated. Do not edit manually.
// Replace YOUR_API_KEY and placeholder values with real data.
// Regenerate: python3 scripts/generate-connector-docs.py {connector_name}
//
// Flow: {svc_label}{pm_part}
//
// SDK: sdk/rust (native Rust — uses hyperswitch_payments_client)
// Build: cargo check -p hyperswitch-payments-client  (from repo root)

use grpc_api_types::payments::{{Connector, ConnectorConfig, Environment, {grpc_req}}};
use hyperswitch_payments_client::ConnectorClient;

#[tokio::main]
async fn main() {{
    let config = ConnectorConfig {{
        connector: Connector::{conn_enum}.into(),
        environment: Environment::Sandbox.into(),
        // auth: Some(ConnectorAuth {{ ... }})  — set your connector auth here
        ..Default::default()
    }};

    let client = ConnectorClient::new(config);

    // Build request with probe-verified field values.
    // Note: sensitive fields use Secret::new("value") and card_number uses .try_into().
    // See sdk/rust/examples/basic.rs for the full type-safe construction pattern.
    let request = {grpc_req} {{
{body}
        ..Default::default()
    }};

    let response = client.{method}(request).await.unwrap();
{status_block}
}}
"""


def _rust_payload_lines(
    obj: dict,
    msg_name: str,
    message_schemas: dict,
    indent: int,
) -> list[str]:
    """Recursively build Rust struct literal lines for a proto payload dict."""
    pad    = "    " * indent
    db     = _SchemaDB(message_schemas)
    lines: list[str] = []

    for key, val in obj.items():
        comment   = db.get_comment(msg_name, key)
        child_msg = db.get_type(msg_name, key)
        cmt_part  = f"  // {comment}" if comment else ""

        if isinstance(val, dict):
            inner = _rust_payload_lines(val, child_msg, message_schemas, indent + 1)
            inner_str = "\n".join(inner)
            lines.append(f"{pad}{key}: Some({child_msg or 'Message'} {{{cmt_part}")
            lines.append(inner_str)
            lines.append(f"{pad}    ..Default::default()")
            lines.append(f"{pad}}}),")
        elif isinstance(val, bool):
            lines.append(f"{pad}{key}: Some({str(val).lower()}),{cmt_part}")
        elif isinstance(val, (int, float)):
            lines.append(f"{pad}{key}: Some({val}),{cmt_part}")
        elif isinstance(val, str):
            lines.append(f'{pad}{key}: Some("{val}".to_string()),{cmt_part}')
        else:
            lines.append(f"{pad}// {key}: {json.dumps(val)}{cmt_part}")

    return lines


# Human-readable label per PM key (order defines display order in PM Reference section)
_PROBE_PM_LABELS: dict[str, str] = {
    "Card":           "Card (Raw PAN)",
    "GooglePay":      "Google Pay",
    "ApplePay":       "Apple Pay",
    "Sepa":           "SEPA Direct Debit",
    "Bacs":           "BACS Direct Debit",
    "Ach":            "ACH Direct Debit",
    "Becs":           "BECS Direct Debit",
    "Ideal":          "iDEAL",
    "PaypalRedirect": "PayPal Redirect",
    "Blik":           "BLIK",
    "Klarna":         "Klarna",
    "Afterpay":       "Afterpay / Clearpay",
    "UpiCollect":     "UPI Collect",
    "Affirm":         "Affirm",
    "SamsungPay":     "Samsung Pay",
}


# ── Public API: PM reference section ──────────────────────────────────────────

def render_pm_reference_section(
    probe_connector: dict,
    flow_metadata: dict[str, dict],
    message_schemas: dict,
) -> list[str]:
    """
    Return markdown lines for ## Payment Method Reference.

    For each PM supported in authorize, shows only the payment_method object
    with annotated fields — not the full request payload.
    """
    flows    = probe_connector.get("flows", {})
    auth_pms = flows.get("authorize", {})
    grpc_req = flow_metadata.get("authorize", {}).get("grpc_request", "PaymentServiceAuthorizeRequest")
    db       = _SchemaDB(message_schemas)

    out: list[str] = []
    a = out.append

    rendered_any = False
    for pm_key, label in _PROBE_PM_LABELS.items():
        entry = auth_pms.get(pm_key, {})
        if entry.get("status") != "supported":
            continue
        proto_req = entry.get("proto_request", {})
        pm_payload = proto_req.get("payment_method", {})
        if not pm_payload:
            continue

        if not rendered_any:
            a("## Payment Method Reference")
            a("")
            a("Use these `payment_method` objects in your Authorize request. "
              "All other fields (amount, customer, address) remain the same across payment methods.")
            a("")
            rendered_any = True

        a(f"### {label}")
        a("")
        # Render just the payment_method sub-object
        pm_msg = db.get_type(grpc_req, "payment_method")
        annotated = _build_annotated(pm_payload, pm_msg, db, style="python", indent=0)
        a("```python")
        a(f'"payment_method": {annotated}')
        a("```")
        a("")

    return out


# ── Public API: Payload block (Flow Reference) ─────────────────────────────────

def render_payload_block(
    flow_key: str,
    service_name: str,
    grpc_request: str,
    proto_request: dict,
    message_schemas: dict,
) -> list[str]:
    """
    Return markdown lines for a single annotated request payload block.
    Used in the Flow Reference section.
    """
    if not proto_request or not grpc_request:
        return []

    db           = _SchemaDB(message_schemas)
    client_cls   = _client_class(service_name)
    camel_method = _to_camel(flow_key)
    payload      = _build_annotated(proto_request, grpc_request, db, style="python", indent=0)

    return [
        "",
        f"> **Client call:** `{client_cls}.{camel_method}(request)`",
        "",
        "```python",
        payload,
        "```",
        "",
    ]


# ── Public API: llms.txt entry ────────────────────────────────────────────────

def render_llms_txt_entry(
    connector_name: str,
    display_name: str,
    probe_connector: dict,
    scenarios: list[ScenarioSpec],
) -> str:
    """
    Return one connector's block for docs/llms.txt.
    """
    flows    = probe_connector.get("flows", {})
    auth_pms = flows.get("authorize", {})

    supported_pms = [
        pm for pm in auth_pms
        if pm != "default" and auth_pms[pm].get("status") == "supported"
    ]
    supported_flows = [
        fk for fk, fdata in flows.items()
        if any(v.get("status") == "supported" for v in fdata.values())
    ]
    scenario_keys = [s.key for s in scenarios]
    example_paths = [
        f"examples/{connector_name}/python/{s.key}.py" for s in scenarios
    ]

    lines = [
        f"## {display_name}",
        f"connector_id: {connector_name}",
        f"doc: docs/connectors/{connector_name}.md",
        f"scenarios: {', '.join(scenario_keys) if scenario_keys else 'none'}",
        f"payment_methods: {', '.join(supported_pms) if supported_pms else 'none'}",
        f"flows: {', '.join(supported_flows)}",
        f"examples_python: {', '.join(example_paths) if example_paths else 'none'}",
        "",
    ]
    return "\n".join(lines)
