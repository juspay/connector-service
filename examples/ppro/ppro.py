# This file is auto-generated. Do not edit manually.
# Replace YOUR_API_KEY and placeholder values with real data.
# Regenerate: python3 scripts/generate-connector-docs.py ppro
#
# Ppro — all integration scenarios and flows in one file.
# Run a scenario:  python3 ppro.py checkout_card

import asyncio
import sys
from google.protobuf.json_format import ParseDict
from payments import PaymentClient
from payments.generated import sdk_config_pb2, payment_pb2

_default_config = sdk_config_pb2.ConnectorConfig(
    options=sdk_config_pb2.SdkOptions(environment=sdk_config_pb2.Environment.SANDBOX),
)
# Standalone credentials (field names depend on connector auth type):
# _default_config.connector_config.CopyFrom(payment_pb2.ConnectorSpecificConfig(
#     ppro=payment_pb2.PproConfig(api_key=...),
# ))


async def authorize(merchant_transaction_id: str, config: sdk_config_pb2.ConnectorConfig = _default_config):
    """Flow: PaymentService.authorize (Ideal)"""
    payment_client = PaymentClient(config)

    # Step 1: Authorize — reserve funds on the payment method
    authorize_response = await payment_client.authorize(ParseDict(
        {
            "merchant_transaction_id": "probe_txn_001",
            "amount": {
                "minor_amount": 1000,
                "currency": "USD"
            },
            "payment_method": {
            },
            "capture_method": "AUTOMATIC",
            "address": {
            },
            "auth_type": "NO_THREE_DS",
            "return_url": "https://example.com/return"
        },
    ))

    if authorize_response.status == "FAILED":
        raise RuntimeError(f"Payment failed: {authorize_response.error}")
    if authorize_response.status == "PENDING":
        # Awaiting async confirmation — handle via webhook
        return {"status": "pending", "transaction_id": authorize_response.connector_transaction_id}

    return {"status": authorize_response.status, "transaction_id": authorize_response.connector_transaction_id}


async def capture(merchant_transaction_id: str, config: sdk_config_pb2.ConnectorConfig = _default_config):
    """Flow: PaymentService.capture"""
    payment_client = PaymentClient(config)

    # Step 1: Capture — settle the reserved funds
    capture_response = await payment_client.capture(ParseDict(
        {
            "merchant_capture_id": "probe_capture_001",
            "connector_transaction_id": "probe_connector_txn_001",
            "amount_to_capture": {
                "minor_amount": 1000,
                "currency": "USD"
            }
        },
    ))

    if capture_response.status == "FAILED":
        raise RuntimeError(f"Capture failed: {capture_response.error}")

    return {"status": capture_response.status}


async def get(merchant_transaction_id: str, config: sdk_config_pb2.ConnectorConfig = _default_config):
    """Flow: PaymentService.get"""
    payment_client = PaymentClient(config)

    # Step 1: Get — retrieve current payment status from the connector
    get_response = await payment_client.get(ParseDict(
        {
            "merchant_transaction_id": "probe_merchant_txn_001",
            "connector_transaction_id": "probe_connector_txn_001",
            "amount": {
                "minor_amount": 1000,
                "currency": "USD"
            }
        },
    ))

    return {"status": get_response.status}


async def handle_event(merchant_transaction_id: str, config: sdk_config_pb2.ConnectorConfig = _default_config):
    """Flow: PaymentService.handle_event"""
    payment_client = PaymentClient(config)

    # Step 1: handle_event
    handle_response = await payment_client.handle_event(ParseDict(
        {
            # No required fields
        },
    ))

    return {"status": handle_response.status}


async def recurring_charge(merchant_transaction_id: str, config: sdk_config_pb2.ConnectorConfig = _default_config):
    """Flow: PaymentService.recurring_charge"""
    payment_client = PaymentClient(config)

    # Step 1: Recurring Charge — charge against the stored mandate
    recurring_response = await payment_client.charge(ParseDict(
        {
            "connector_recurring_payment_id": {
                "connector_mandate_id": "probe-mandate-123"
            },
            "amount": {
                "minor_amount": 1000,
                "currency": "USD"
            },
            "payment_method": {
                "token": "probe_pm_token"
            },
            "return_url": "https://example.com/recurring-return",
            "connector_customer_id": "cust_probe_123",
            "payment_method_type": "PAY_PAL",
            "off_session": True
        },
    ))

    if recurring_response.status == "FAILED":
        raise RuntimeError(f"Recurring_Charge failed: {recurring_response.error}")

    return {"status": recurring_response.status}


async def refund(merchant_transaction_id: str, config: sdk_config_pb2.ConnectorConfig = _default_config):
    """Flow: PaymentService.refund"""
    payment_client = PaymentClient(config)

    # Step 1: Refund — return funds to the customer
    refund_response = await payment_client.refund(ParseDict(
        {
            "merchant_refund_id": "probe_refund_001",
            "connector_transaction_id": "probe_connector_txn_001",
            "payment_amount": 1000,
            "refund_amount": {
                "minor_amount": 1000,
                "currency": "USD"
            },
            "reason": "customer_request"
        },
    ))

    if refund_response.status == "FAILED":
        raise RuntimeError(f"Refund failed: {refund_response.error}")

    return {"status": refund_response.status}


async def refund_get(merchant_transaction_id: str, config: sdk_config_pb2.ConnectorConfig = _default_config):
    """Flow: PaymentService.refund_get"""
    payment_client = PaymentClient(config)

    # Step 1: refund_get
    refund_response = await payment_client.refund_get(ParseDict(
        {
            "merchant_refund_id": "probe_refund_001",
            "connector_transaction_id": "probe_connector_txn_001",
            "refund_id": "probe_refund_id_001"
        },
    ))

    return {"status": refund_response.status}


async def void(merchant_transaction_id: str, config: sdk_config_pb2.ConnectorConfig = _default_config):
    """Flow: PaymentService.void"""
    payment_client = PaymentClient(config)

    # Step 1: Void — release reserved funds (cancel authorization)
    void_response = await payment_client.void(ParseDict(
        {
            "merchant_void_id": "probe_void_001",
            "connector_transaction_id": "probe_connector_txn_001",
            "amount": {
                "minor_amount": 1000,
                "currency": "USD"
            }
        },
    ))

    return {"status": void_response.status}

if __name__ == "__main__":
    scenario = sys.argv[1] if len(sys.argv) > 1 else "authorize"
    fn = globals().get(f"process_{scenario}")
    if not fn:
        available = [k[8:] for k in globals() if k.startswith("process_")]
        print(f"Unknown scenario: {scenario}. Available: {available}", file=sys.stderr)
        sys.exit(1)
    asyncio.run(fn("order_001"))
