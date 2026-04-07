#!/usr/bin/env python3
"""
Structural tests for the Python SDK flow registry.

Validates that:
  1. SERVICE_FLOWS and SINGLE_SERVICE_FLOWS are importable and well-formed
  2. Every expected FFI flow has a corresponding entry in SERVICE_FLOWS
  3. Client class names follow expected naming conventions
  4. Response type names are non-empty strings
  5. No duplicate flow names exist across different clients

Run with pytest:
    pytest sdk/python/tests/test_flow_structure.py -v
"""

import importlib.util
import os
import sys

import pytest

# ── Direct-import helper ──────────────────────────────────────────────────────
# We load _generated_flows.py directly from its file path using importlib so
# that we do NOT trigger ``payments/__init__.py``, which eagerly imports the
# native Rust FFI extension module (``payments.generated.connector_service_ffi``).
# That module only exists after ``make -C sdk generate`` has been run, which is
# not required for these pure-Python structural tests.

_FLOWS_MODULE_PATH = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "src", "payments", "_generated_flows.py")
)


def _load_generated_flows():
    """Load _generated_flows module directly, bypassing the payments package."""
    spec = importlib.util.spec_from_file_location("_generated_flows", _FLOWS_MODULE_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ── Expected data ──────────────────────────────────────────────────────────────

# All 32 FFI flow names (from _generated_ffi_flows.rs)
EXPECTED_FFI_FLOWS = {
    "accept",
    "authenticate",
    "authorize",
    "capture",
    "charge",
    "create",
    "create_client_authentication_token",
    "create_order",
    "create_server_authentication_token",
    "create_server_session_authentication_token",
    "defend",
    "get",
    "payout_create",
    "payout_create_link",
    "payout_create_recipient",
    "payout_enroll_disburse_account",
    "payout_get",
    "payout_stage",
    "payout_transfer",
    "payout_void",
    "post_authenticate",
    "pre_authenticate",
    "proxy_authorize",
    "proxy_setup_recurring",
    "refund",
    "reverse",
    "setup_recurring",
    "submit_evidence",
    "token_authorize",
    "token_setup_recurring",
    "tokenize",
    "void",
}

# Expected client classes
EXPECTED_CLIENTS = {
    "DisputeClient",
    "PaymentMethodAuthenticationClient",
    "PaymentClient",
    "RecurringPaymentClient",
    "CustomerClient",
    "MerchantAuthenticationClient",
    "PayoutClient",
    "PaymentMethodClient",
}

# Client → expected flows mapping
EXPECTED_CLIENT_FLOWS = {
    "DisputeClient": {"accept", "defend", "submit_evidence"},
    "PaymentMethodAuthenticationClient": {"authenticate", "post_authenticate", "pre_authenticate"},
    "PaymentClient": {
        "authorize",
        "capture",
        "create_order",
        "get",
        "proxy_authorize",
        "proxy_setup_recurring",
        "refund",
        "reverse",
        "setup_recurring",
        "token_authorize",
        "token_setup_recurring",
        "void",
    },
    "RecurringPaymentClient": {"charge"},
    "CustomerClient": {"create"},
    "MerchantAuthenticationClient": {
        "create_client_authentication_token",
        "create_server_authentication_token",
        "create_server_session_authentication_token",
    },
    "PayoutClient": {
        "payout_create",
        "payout_create_link",
        "payout_create_recipient",
        "payout_enroll_disburse_account",
        "payout_get",
        "payout_stage",
        "payout_transfer",
        "payout_void",
    },
    "PaymentMethodClient": {"tokenize"},
}


# ── Fixtures ───────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def service_flows():
    mod = _load_generated_flows()
    return mod.SERVICE_FLOWS


@pytest.fixture(scope="module")
def single_service_flows():
    mod = _load_generated_flows()
    return mod.SINGLE_SERVICE_FLOWS


# ── Import tests ───────────────────────────────────────────────────────────────


def test_service_flows_importable(service_flows):
    """SERVICE_FLOWS is importable and is a dict."""
    assert isinstance(service_flows, dict)
    assert len(service_flows) > 0


def test_single_service_flows_importable(single_service_flows):
    """SINGLE_SERVICE_FLOWS is importable and is a dict."""
    assert isinstance(single_service_flows, dict)


# ── Client structure tests ─────────────────────────────────────────────────────


def test_expected_clients_present(service_flows):
    """All expected client classes are present in SERVICE_FLOWS."""
    actual_clients = set(service_flows.keys())
    missing = EXPECTED_CLIENTS - actual_clients
    assert not missing, f"Missing clients: {missing}"


def test_no_unexpected_clients(service_flows):
    """No unexpected client classes in SERVICE_FLOWS."""
    actual_clients = set(service_flows.keys())
    unexpected = actual_clients - EXPECTED_CLIENTS
    assert not unexpected, f"Unexpected clients: {unexpected}"


def test_client_names_end_with_client(service_flows):
    """All client names end with 'Client'."""
    for client_name in service_flows:
        assert client_name.endswith("Client"), f"Bad client name: {client_name}"


# ── Flow coverage tests ───────────────────────────────────────────────────────


def test_all_ffi_flows_present_in_sdk(service_flows):
    """Every expected FFI flow has a corresponding SDK entry."""
    all_sdk_flows = set()
    for flows in service_flows.values():
        all_sdk_flows.update(flows.keys())

    missing = EXPECTED_FFI_FLOWS - all_sdk_flows
    assert not missing, f"FFI flows missing from Python SDK: {missing}"


def test_no_duplicate_flow_names_across_clients(service_flows):
    """No flow name appears in more than one client."""
    seen = {}
    duplicates = []
    for client, flows in service_flows.items():
        for flow in flows:
            if flow in seen:
                duplicates.append(f"{flow} in both {seen[flow]} and {client}")
            else:
                seen[flow] = client

    assert not duplicates, f"Duplicate flows across clients: {duplicates}"


@pytest.mark.parametrize("client,expected_flows", EXPECTED_CLIENT_FLOWS.items())
def test_client_has_expected_flows(service_flows, client, expected_flows):
    """Each client has exactly the expected set of flows."""
    actual = set(service_flows.get(client, {}).keys())
    missing = expected_flows - actual
    extra = actual - expected_flows
    assert not missing, f"{client} missing flows: {missing}"
    assert not extra, f"{client} has unexpected flows: {extra}"


# ── Response type validation ───────────────────────────────────────────────────


def test_all_response_types_are_strings(service_flows):
    """Every response type is a non-empty string ending with 'Response'."""
    for client, flows in service_flows.items():
        for flow, response_type in flows.items():
            assert isinstance(response_type, str), (
                f"{client}.{flow} response type is not a string: {response_type}"
            )
            assert len(response_type) > 0, (
                f"{client}.{flow} has empty response type"
            )
            assert response_type.endswith("Response"), (
                f"{client}.{flow} response type doesn't end with 'Response': {response_type}"
            )


# ── Single service flows ──────────────────────────────────────────────────────


def test_event_client_in_single_service_flows(single_service_flows):
    """EventClient with handle_event should be in SINGLE_SERVICE_FLOWS."""
    assert "EventClient" in single_service_flows
    assert "handle_event" in single_service_flows["EventClient"]


def test_single_service_flows_not_in_service_flows(service_flows, single_service_flows):
    """SINGLE_SERVICE_FLOWS clients should not overlap with SERVICE_FLOWS."""
    overlap = set(service_flows.keys()) & set(single_service_flows.keys())
    assert not overlap, f"Overlapping clients: {overlap}"


# ── Count sanity ───────────────────────────────────────────────────────────────


def test_total_sdk_flow_count(service_flows):
    """Total number of flows across all clients matches expected count."""
    total = sum(len(flows) for flows in service_flows.values())
    # 32 FFI flows mapped into SERVICE_FLOWS
    assert total == 32, f"Expected 32 total SDK flows, got {total}"


def test_total_client_count(service_flows):
    """Number of client classes matches expected count."""
    assert len(service_flows) == 8, f"Expected 8 clients, got {len(service_flows)}"
