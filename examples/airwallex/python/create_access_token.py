# This file is auto-generated. Do not edit manually.
# Replace YOUR_API_KEY and placeholder values with real data.
# Regenerate: python3 scripts/generate-connector-docs.py airwallex
#
# Flow: MerchantAuthenticationService.CreateAccessToken

import asyncio
from google.protobuf.json_format import ParseDict
from payments import MerchantAuthenticationClient
from payments.generated import sdk_config_pb2, payment_pb2

_default_config = sdk_config_pb2.ConnectorConfig(
    connector=payment_pb2.Connector.AIRWALLEX,
    environment=sdk_config_pb2.Environment.SANDBOX,
)
# Standalone credentials (field names depend on connector auth type):
# _default_config.auth.airwallex.api_key.value = "YOUR_API_KEY"


async def create_access_token(merchant_transaction_id: str, config: sdk_config_pb2.ConnectorConfig = _default_config):
    merchantauthentication_client = MerchantAuthenticationClient(config)

    # Step 1: create_access_token
    create_response = await merchantauthentication_client.create_access_token(ParseDict(
        {
            # No required fields
        },
        payment_pb2.MerchantAuthenticationServiceCreateAccessTokenRequest(),
    ))

    return {"status": create_response.status}


if __name__ == "__main__":
    asyncio.run(create_access_token("order_001"))
