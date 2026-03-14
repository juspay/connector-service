# This file is auto-generated. Do not edit manually.
# Replace YOUR_API_KEY and placeholder values with real data.
# Regenerate: python3 scripts/generate-connector-docs.py authorizedotnet
#
# Scenario: Create Customer
# Register a customer record in the connector system. Returns a connector_customer_id that can be reused for recurring payments and tokenized card storage.

import asyncio
from google.protobuf.json_format import ParseDict
from payments import CustomerClient
from payments.generated import sdk_config_pb2, payment_pb2

_default_config = sdk_config_pb2.ConnectorConfig(
    connector=payment_pb2.Connector.AUTHORIZEDOTNET,
    environment=sdk_config_pb2.Environment.SANDBOX,
)
# Standalone credentials (field names depend on connector auth type):
# _default_config.auth.authorizedotnet.api_key.value = "YOUR_API_KEY"


async def process_create_customer(merchant_transaction_id: str, config: sdk_config_pb2.ConnectorConfig = _default_config):
    """Create Customer

    Register a customer record in the connector system. Returns a connector_customer_id that can be reused for recurring payments and tokenized card storage.
    """
    customer_client = CustomerClient(config)

    # Step 1: Create Customer — register customer record in the connector
    create_response = await customer_client.create(ParseDict(
        {
            "customer_name": "John Doe",  # Name of the customer
            "email": {"value": "test@example.com"},  # Email address of the customer
            "phone_number": "4155552671",  # Phone number of the customer
            "address": {  # Address Information
                "billing_address": {
                    "first_name": {"value": "John"},  # Personal Information
                    "last_name": {"value": "Doe"},
                    "line1": {"value": "123 Main St"},  # Address Details
                    "city": {"value": "Seattle"},
                    "state": {"value": "WA"},
                    "zip_code": {"value": "98101"},
                    "country_alpha2_code": "US",
                    "email": {"value": "test@example.com"},  # Contact Information
                    "phone_number": {"value": "4155552671"},
                    "phone_country_code": "+1"
                }
            }
        },
        payment_pb2.CustomerServiceCreateRequest(),
    ))

    return {"customer_id": create_response.connector_customer_id}


if __name__ == "__main__":
    asyncio.run(process_create_customer("order_001"))
