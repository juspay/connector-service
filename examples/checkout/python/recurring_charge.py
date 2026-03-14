# This file is auto-generated. Do not edit manually.
# Replace YOUR_API_KEY and placeholder values with real data.
# Regenerate: python3 scripts/generate-connector-docs.py checkout
#
# Flow: RecurringPaymentService.Charge

import asyncio
from google.protobuf.json_format import ParseDict
from payments import RecurringPaymentClient
from payments.generated import sdk_config_pb2, payment_pb2

_default_config = sdk_config_pb2.ConnectorConfig(
    connector=payment_pb2.Connector.CHECKOUT,
    environment=sdk_config_pb2.Environment.SANDBOX,
)
# Standalone credentials (field names depend on connector auth type):
# _default_config.auth.checkout.api_key.value = "YOUR_API_KEY"


async def recurring_charge(merchant_transaction_id: str, config: sdk_config_pb2.ConnectorConfig = _default_config):
    recurringpayment_client = RecurringPaymentClient(config)

    # Step 1: Recurring Charge — charge against the stored mandate
    recurring_response = await recurringpayment_client.charge(ParseDict(
        {
            "connector_recurring_payment_id": {  # Reference to existing mandate
                "mandate_id_type": {
                    "connector_mandate_id": "probe_mandate_123"
                }
            },
            "amount": {  # Amount Information
                "minor_amount": 1000,  # Amount in minor units (e.g., 1000 = $10.00)
                "currency": "USD"  # ISO 4217 currency code (e.g., "USD", "EUR")
            },
            "payment_method": {  # Optional payment Method Information (for network transaction flows)
                "token": {"token": {"value": "probe_pm_token"}}  # Payment tokens
            },
            "return_url": "https://example.com/recurring-return",
            "connector_customer_id": "probe_cust_connector_001",
            "payment_method_type": "PAY_PAL",
            "off_session": True  # Behavioral Flags and Preferences
        },
        payment_pb2.RecurringPaymentServiceChargeRequest(),
    ))

    if recurring_response.status == "FAILED":
        raise RuntimeError(f"Recurring_Charge failed: {recurring_response.error}")

    return {"status": recurring_response.status}


if __name__ == "__main__":
    asyncio.run(recurring_charge("order_001"))
