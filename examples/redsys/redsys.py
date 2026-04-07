# This file is auto-generated. Do not edit manually.
# Replace YOUR_API_KEY and placeholder values with real data.
# Regenerate: python3 scripts/generate-connector-docs.py redsys
#
# Redsys — all integration scenarios and flows in one file.
# Run a scenario:  python3 redsys.py checkout_card

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
#     redsys=payment_pb2.RedsysConfig(api_key=...),
# ))


async def authenticate(merchant_transaction_id: str, config: sdk_config_pb2.ConnectorConfig = _default_config):
    """Flow: PaymentService.authenticate"""
    payment_client = PaymentClient(config)

    # Step 1: Authenticate — execute 3DS challenge or frictionless verification
    authenticate_response = await payment_client.authenticate(ParseDict(
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
            },
            "authentication_data": {
                "eci": "05",
                "cavv": "AAAAAAAAAA==",
                "threeds_server_transaction_id": "probe-3ds-txn-001",
                "message_version": "2.1.0",
                "ds_transaction_id": "probe-ds-txn-001"
            },
            "return_url": "https://example.com/3ds-return",
            "continue_redirection_url": "https://example.com/3ds-continue",
            "browser_info": {
                "color_depth": 24,
                "screen_height": 900,
                "screen_width": 1440,
                "java_enabled": False,
                "java_script_enabled": True,
                "language": "en-US",
                "time_zone_offset_minutes": -480,
                "accept_header": "application/json",
                "user_agent": "Mozilla/5.0 (probe-bot)",
                "accept_language": "en-US,en;q=0.9",
                "ip_address": "1.2.3.4"
            }
        },
    ))

    return {"status": authenticate_response.status}


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


async def pre_authenticate(merchant_transaction_id: str, config: sdk_config_pb2.ConnectorConfig = _default_config):
    """Flow: PaymentService.pre_authenticate"""
    payment_client = PaymentClient(config)

    # Step 1: Pre-Authenticate — initiate 3DS flow (collect device/browser data)
    pre_authenticate_response = await payment_client.pre_authenticate(ParseDict(
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
            },
            "enrolled_for_3ds": False,
            "return_url": "https://example.com/3ds-return"
        },
    ))

    return {"status": pre_response.status}


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
    scenario = sys.argv[1] if len(sys.argv) > 1 else "authenticate"
    fn = globals().get(f"process_{scenario}")
    if not fn:
        available = [k[8:] for k in globals() if k.startswith("process_")]
        print(f"Unknown scenario: {scenario}. Available: {available}", file=sys.stderr)
        sys.exit(1)
    asyncio.run(fn("order_001"))
