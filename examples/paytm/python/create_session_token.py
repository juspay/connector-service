# This file is auto-generated. Do not edit manually.
# Replace YOUR_API_KEY and placeholder values with real data.
# Regenerate: python3 scripts/generate-connector-docs.py paytm
#
# Flow: MerchantAuthenticationService.CreateSessionToken

import asyncio
from google.protobuf.json_format import ParseDict
from payments import MerchantAuthenticationClient
from payments.generated import sdk_config_pb2, payment_pb2

_default_config = sdk_config_pb2.ConnectorConfig(
    connector=payment_pb2.Connector.PAYTM,
    environment=sdk_config_pb2.Environment.SANDBOX,
)
# Standalone credentials (field names depend on connector auth type):
# _default_config.auth.paytm.api_key.value = "YOUR_API_KEY"


async def create_session_token(merchant_transaction_id: str, config: sdk_config_pb2.ConnectorConfig = _default_config):
    merchantauthentication_client = MerchantAuthenticationClient(config)

    # Step 1: create_session_token
    create_response = await merchantauthentication_client.create_session_token(ParseDict(
        {
            "amount": {  # Amount Information
                "minor_amount": 1000,  # Amount in minor units (e.g., 1000 = $10.00)
                "currency": "USD"  # ISO 4217 currency code (e.g., "USD", "EUR")
            }
        },
        payment_pb2.MerchantAuthenticationServiceCreateSessionTokenRequest(),
    ))

    return {"status": create_response.status}


if __name__ == "__main__":
    asyncio.run(create_session_token("order_001"))
