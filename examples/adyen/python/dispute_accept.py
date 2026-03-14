# This file is auto-generated. Do not edit manually.
# Replace YOUR_API_KEY and placeholder values with real data.
# Regenerate: python3 scripts/generate-connector-docs.py adyen
#
# Flow: DisputeService.Accept

import asyncio
from google.protobuf.json_format import ParseDict
from payments import DisputeClient
from payments.generated import sdk_config_pb2, payment_pb2

_default_config = sdk_config_pb2.ConnectorConfig(
    connector=payment_pb2.Connector.ADYEN,
    environment=sdk_config_pb2.Environment.SANDBOX,
)
# Standalone credentials (field names depend on connector auth type):
# _default_config.auth.adyen.api_key.value = "YOUR_API_KEY"


async def dispute_accept(merchant_transaction_id: str, config: sdk_config_pb2.ConnectorConfig = _default_config):
    dispute_client = DisputeClient(config)

    # Step 1: dispute_accept
    dispute_response = await dispute_client.dispute_accept(ParseDict(
        {
            "merchant_dispute_id": "probe_dispute_001",  # Identification
            "connector_transaction_id": "probe_txn_001",
            "dispute_id": "probe_dispute_id_001"
        },
        payment_pb2.DisputeServiceAcceptRequest(),
    ))

    return {"status": dispute_response.status}


if __name__ == "__main__":
    asyncio.run(dispute_accept("order_001"))
