# This file is auto-generated. Do not edit manually.
# Replace YOUR_API_KEY and placeholder values with real data.
# Regenerate: python3 scripts/generate-connector-docs.py braintree
#
# Braintree — all integration scenarios and flows in one file.
# Run a scenario:  python3 braintree.py checkout_card

import asyncio
import sys
from google.protobuf.json_format import ParseDict
from payments import PaymentClient
from payments.generated import sdk_config_pb2, payment_pb2, payment_methods_pb2

_default_config = sdk_config_pb2.ConnectorConfig(
    options=sdk_config_pb2.SdkOptions(environment=sdk_config_pb2.Environment.SANDBOX),
)
# Standalone credentials (field names depend on connector auth type):
# _default_config.connector_config.CopyFrom(payment_pb2.ConnectorSpecificConfig(
#     braintree=payment_pb2.BraintreeConfig(api_key=...),
# ))


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


async def create_client_authentication_token(merchant_transaction_id: str, config: sdk_config_pb2.ConnectorConfig = _default_config):
    """Flow: PaymentService.create_client_authentication_token"""
    payment_client = PaymentClient(config)

    # Step 1: create_client_authentication_token
    create_response = await payment_client.create_client_authentication_token(ParseDict(
        {
            "merchant_client_session_id": "probe_sdk_session_001",
            "domain_context": {
                "minor_amount": 1000,
                "currency": "USD"
            }
        },
    ))

    return {"status": create_response.status}


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
            "refund_id": "probe_refund_id_001",
            "refund_metadata": "{\"currency\":\"USD\"}"
        },
    ))

    return {"status": refund_response.status}


async def tokenize(merchant_transaction_id: str, config: sdk_config_pb2.ConnectorConfig = _default_config):
    """Flow: PaymentService.tokenize"""
    payment_client = PaymentClient(config)

    # Step 1: Tokenize — store card details and return a reusable token
    tokenize_response = await payment_client.tokenize(ParseDict(
        {
            "amount": {
                "minor_amount": 1000,
                "currency": "USD"
            },
            "payment_method": {
                "card_number": "4111111111111111",
                "card_exp_month": "03",
                "card_exp_year": "2030",
                "card_cvc": "737",
                "card_holder_name": "John Doe"
            },
            "address": {
            }
        },
    ))

    return {"status": tokenize_response.status}


async def void(merchant_transaction_id: str, config: sdk_config_pb2.ConnectorConfig = _default_config):
    """Flow: PaymentService.void"""
    payment_client = PaymentClient(config)

    # Step 1: Void — release reserved funds (cancel authorization)
    void_response = await payment_client.void(ParseDict(
        {
            "merchant_void_id": "probe_void_001",
            "connector_transaction_id": "probe_connector_txn_001"
        },
    ))

    return {"status": void_response.status}

if __name__ == "__main__":
    scenario = sys.argv[1] if len(sys.argv) > 1 else "capture"
    fn = globals().get(f"process_{scenario}")
    if not fn:
        available = [k[8:] for k in globals() if k.startswith("process_")]
        print(f"Unknown scenario: {scenario}. Available: {available}", file=sys.stderr)
        sys.exit(1)
    asyncio.run(fn("order_001"))
