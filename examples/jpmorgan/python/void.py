# This file is auto-generated. Do not edit manually.
# Replace YOUR_API_KEY and placeholder values with real data.
# Regenerate: python3 scripts/generate-connector-docs.py jpmorgan
#
# Flow: PaymentService.Void

import asyncio
from google.protobuf.json_format import ParseDict
from payments import PaymentClient
from payments.generated import sdk_config_pb2, payment_pb2

_default_config = sdk_config_pb2.ConnectorConfig(
    connector=payment_pb2.Connector.JPMORGAN,
    environment=sdk_config_pb2.Environment.SANDBOX,
)
# Standalone credentials (field names depend on connector auth type):
# _default_config.auth.jpmorgan.api_key.value = "YOUR_API_KEY"


async def void(merchant_transaction_id: str, config: sdk_config_pb2.ConnectorConfig = _default_config):
    payment_client = PaymentClient(config)

    # Step 1: Void — release reserved funds (cancel authorization)
    void_response = await payment_client.void(ParseDict(
        {
            "merchant_void_id": "probe_void_001",  # Identification
            "connector_transaction_id": "probe_connector_txn_001",
            "state": {  # State Information
                "access_token": {  # Access token obtained from connector
                    "token": {"value": "probe_access_token"},  # The token string.
                    "expires_in_seconds": 3600,  # Expiration timestamp (seconds since epoch)
                    "token_type": "Bearer"  # Token type (e.g., "Bearer", "Basic").
                }
            }
        },
        payment_pb2.PaymentServiceVoidRequest(),
    ))

    return {"status": void_response.status}


if __name__ == "__main__":
    asyncio.run(void("order_001"))
