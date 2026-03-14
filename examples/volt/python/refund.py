# This file is auto-generated. Do not edit manually.
# Replace YOUR_API_KEY and placeholder values with real data.
# Regenerate: python3 scripts/generate-connector-docs.py volt
#
# Flow: PaymentService.Refund

import asyncio
from google.protobuf.json_format import ParseDict
from payments import PaymentClient
from payments.generated import sdk_config_pb2, payment_pb2

_default_config = sdk_config_pb2.ConnectorConfig(
    connector=payment_pb2.Connector.VOLT,
    environment=sdk_config_pb2.Environment.SANDBOX,
)
# Standalone credentials (field names depend on connector auth type):
# _default_config.auth.volt.api_key.value = "YOUR_API_KEY"


async def refund(merchant_transaction_id: str, config: sdk_config_pb2.ConnectorConfig = _default_config):
    payment_client = PaymentClient(config)

    # Step 1: Refund — return funds to the customer
    refund_response = await payment_client.refund(ParseDict(
        {
            "merchant_refund_id": "probe_refund_001",  # Identification
            "connector_transaction_id": "probe_connector_txn_001",
            "payment_amount": 1000,  # Amount Information
            "refund_amount": {
                "minor_amount": 1000,  # Amount in minor units (e.g., 1000 = $10.00)
                "currency": "USD"  # ISO 4217 currency code (e.g., "USD", "EUR")
            },
            "reason": "customer_request",  # Reason for the refund
            "state": {  # State data for access token storage and other connector-specific state
                "access_token": {  # Access token obtained from connector
                    "token": {"value": "probe_access_token"},  # The token string.
                    "expires_in_seconds": 3600,  # Expiration timestamp (seconds since epoch)
                    "token_type": "Bearer"  # Token type (e.g., "Bearer", "Basic").
                }
            }
        },
        payment_pb2.PaymentServiceRefundRequest(),
    ))

    if refund_response.status == "FAILED":
        raise RuntimeError(f"Refund failed: {refund_response.error}")

    return {"status": refund_response.status}


if __name__ == "__main__":
    asyncio.run(refund("order_001"))
