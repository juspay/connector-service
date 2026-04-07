# This file is auto-generated. Do not edit manually.
# Replace YOUR_API_KEY and placeholder values with real data.
# Regenerate: python3 scripts/generate-connector-docs.py cryptopay
#
# Cryptopay — all integration scenarios and flows in one file.
# Run a scenario:  python3 cryptopay.py checkout_card

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
#     cryptopay=payment_pb2.CryptopayConfig(api_key=...),
# ))


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

if __name__ == "__main__":
    scenario = sys.argv[1] if len(sys.argv) > 1 else "get"
    fn = globals().get(f"process_{scenario}")
    if not fn:
        available = [k[8:] for k in globals() if k.startswith("process_")]
        print(f"Unknown scenario: {scenario}. Available: {available}", file=sys.stderr)
        sys.exit(1)
    asyncio.run(fn("order_001"))
