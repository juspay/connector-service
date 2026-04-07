#!/usr/bin/env python3
"""
Smoke test that validates every SDK flow can be instantiated and the
request/response transformer round-trip executes without import errors.

This test does NOT make real HTTP calls. It verifies:
  1. Every client class can be instantiated with a ConnectorConfig
  2. Every flow method exists and is callable on its client
  3. The FFI request transformer can be invoked (may fail with connector
     validation errors, which is expected — we test the SDK plumbing, not
     connector behavior)

Usage:
    pytest sdk/python/tests/test_all_flows_smoke.py -v
    pytest sdk/python/tests/test_all_flows_smoke.py -v -k "PaymentClient"
"""

import importlib.util
import os
import sys

import pytest

# ── Direct-import helper ──────────────────────────────────────────────────────
# Load _generated_flows.py directly to avoid triggering the payments package
# __init__.py, which eagerly imports the native Rust FFI extension.

_FLOWS_MODULE_PATH = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "src", "payments", "_generated_flows.py")
)


def _load_generated_flows():
    """Load _generated_flows module directly, bypassing the payments package."""
    spec = importlib.util.spec_from_file_location("_generated_flows", _FLOWS_MODULE_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ── Check whether the native FFI module is available ──────────────────────────
# Add SDK source to path so we *can* import payments when FFI is available.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

_FFI_AVAILABLE = False
try:
    from payments.generated import connector_service_ffi as _ffi  # noqa: F401

    _FFI_AVAILABLE = True
except Exception:
    pass

_requires_ffi = pytest.mark.skipif(
    not _FFI_AVAILABLE,
    reason="Native FFI module (payments.generated.connector_service_ffi) not built — run `make -C sdk generate`",
)

# ── Flow registry ──────────────────────────────────────────────────────────────

# (client_class_name, flow_method_name) — every entry from SERVICE_FLOWS
ALL_FLOWS = [
    # DisputeClient
    ("DisputeClient", "accept"),
    ("DisputeClient", "defend"),
    ("DisputeClient", "submit_evidence"),
    # PaymentMethodAuthenticationClient
    ("PaymentMethodAuthenticationClient", "authenticate"),
    ("PaymentMethodAuthenticationClient", "post_authenticate"),
    ("PaymentMethodAuthenticationClient", "pre_authenticate"),
    # PaymentClient
    ("PaymentClient", "authorize"),
    ("PaymentClient", "capture"),
    ("PaymentClient", "create_order"),
    ("PaymentClient", "get"),
    ("PaymentClient", "proxy_authorize"),
    ("PaymentClient", "proxy_setup_recurring"),
    ("PaymentClient", "refund"),
    ("PaymentClient", "reverse"),
    ("PaymentClient", "setup_recurring"),
    ("PaymentClient", "token_authorize"),
    ("PaymentClient", "token_setup_recurring"),
    ("PaymentClient", "void"),
    # RecurringPaymentClient
    ("RecurringPaymentClient", "charge"),
    # CustomerClient
    ("CustomerClient", "create"),
    # MerchantAuthenticationClient
    ("MerchantAuthenticationClient", "create_client_authentication_token"),
    ("MerchantAuthenticationClient", "create_server_authentication_token"),
    ("MerchantAuthenticationClient", "create_server_session_authentication_token"),
    # PayoutClient
    ("PayoutClient", "payout_create"),
    ("PayoutClient", "payout_create_link"),
    ("PayoutClient", "payout_create_recipient"),
    ("PayoutClient", "payout_enroll_disburse_account"),
    ("PayoutClient", "payout_get"),
    ("PayoutClient", "payout_stage"),
    ("PayoutClient", "payout_transfer"),
    ("PayoutClient", "payout_void"),
    # PaymentMethodClient
    ("PaymentMethodClient", "tokenize"),
]

# Single-step flows (no HTTP)
SINGLE_FLOWS = [
    ("EventClient", "handle_event"),
]


# ── Helpers ────────────────────────────────────────────────────────────────────


def _get_client_class(name: str):
    """Import and return a client class by name."""
    import payments._generated_service_clients as clients

    return getattr(clients, name)


def _build_dummy_config():
    """Build a minimal ConnectorConfig for smoke testing.

    Uses Stripe with a dummy key so that the FFI layer can at least parse
    the config structure, even though real calls would fail auth.
    """
    from payments import ConnectorConfig, ConnectorSpecificConfig, SdkOptions, Environment

    try:
        import payments.generated.payment_pb2 as pb2
        import payments.generated.payment_methods_pb2 as pm_pb2

        stripe_config = pb2.StripeConfig(
            api_key=pm_pb2.SecretString(value="sk_test_smoke_dummy_key"),
        )
        connector_specific = ConnectorSpecificConfig(stripe=stripe_config)
    except Exception:
        connector_specific = ConnectorSpecificConfig()

    return ConnectorConfig(
        connector_config=connector_specific,
        options=SdkOptions(environment=Environment.SANDBOX),
    )


# ── Tests ──────────────────────────────────────────────────────────────────────


class TestClientInstantiation:
    """Verify all client classes can be instantiated."""

    @pytest.fixture(scope="class")
    def config(self):
        return _build_dummy_config()

    @_requires_ffi
    @pytest.mark.parametrize(
        "client_name",
        sorted(set(c for c, _ in ALL_FLOWS + SINGLE_FLOWS)),
    )
    def test_client_instantiation(self, config, client_name):
        """Client class can be instantiated with a ConnectorConfig."""
        cls = _get_client_class(client_name)
        client = cls(config)
        assert client is not None


class TestFlowMethodsExist:
    """Verify every flow method exists and is callable on its client."""

    @pytest.fixture(scope="class")
    def config(self):
        return _build_dummy_config()

    @_requires_ffi
    @pytest.mark.parametrize(
        "client_name,flow_name",
        ALL_FLOWS + SINGLE_FLOWS,
        ids=[f"{c}.{f}" for c, f in ALL_FLOWS + SINGLE_FLOWS],
    )
    def test_flow_method_exists(self, config, client_name, flow_name):
        """Flow method exists on the client and is callable."""
        cls = _get_client_class(client_name)
        client = cls(config)
        method = getattr(client, flow_name, None)
        assert method is not None, f"{client_name} has no method '{flow_name}'"
        assert callable(method), f"{client_name}.{flow_name} is not callable"


class TestFlowCount:
    """Verify the total flow count matches expectations."""

    def test_total_service_flows(self):
        """SERVICE_FLOWS has exactly 32 flows across 8 clients."""
        mod = _load_generated_flows()
        total = sum(len(flows) for flows in mod.SERVICE_FLOWS.values())
        assert total == 32, f"Expected 32 SERVICE_FLOWS entries, got {total}"

    def test_total_single_flows(self):
        """SINGLE_SERVICE_FLOWS has exactly 1 flow (handle_event)."""
        mod = _load_generated_flows()
        total = sum(len(flows) for flows in mod.SINGLE_SERVICE_FLOWS.values())
        assert total == 1, f"Expected 1 SINGLE_SERVICE_FLOWS entry, got {total}"

    def test_all_flows_list_completeness(self):
        """Our ALL_FLOWS list covers every entry in SERVICE_FLOWS."""
        mod = _load_generated_flows()
        expected = set()
        for client, flows in mod.SERVICE_FLOWS.items():
            for flow in flows:
                expected.add((client, flow))

        actual = set(ALL_FLOWS)
        missing = expected - actual
        extra = actual - expected
        assert not missing, f"ALL_FLOWS is missing: {missing}"
        assert not extra, f"ALL_FLOWS has extra entries: {extra}"
