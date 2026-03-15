# This file is auto-generated. Do not edit manually.
# Replace YOUR_API_KEY and placeholder values with real data.
# Regenerate: python3 scripts/generate-connector-docs.py razorpay
#
# Razorpay — all integration scenarios and flows in one file.
# Run a scenario:  python3 razorpay.py checkout_card

import asyncio
import sys
from google.protobuf.json_format import ParseDict
from payments import PaymentClient
from payments.generated import sdk_config_pb2, payment_pb2

_default_config = sdk_config_pb2.ConnectorConfig(
    connector=payment_pb2.Connector.RAZORPAY,
    environment=sdk_config_pb2.Environment.SANDBOX,
)
# Standalone credentials (field names depend on connector auth type):
# _default_config.auth.razorpay.api_key.value = "YOUR_API_KEY"


async def process_checkout_card(merchant_transaction_id: str, config: sdk_config_pb2.ConnectorConfig = _default_config):
    """Card Payment (Authorize + Capture)

    Reserve funds with Authorize, then settle with a separate Capture call. Use for physical goods or delayed fulfillment where capture happens later.
    """
    payment_client = PaymentClient(config)

    # Step 1: Authorize — reserve funds on the payment method
    authorize_response = await payment_client.authorize(ParseDict(
        {
            "merchant_transaction_id": "probe_txn_001",  # Identification
            "amount": {  # The amount for the payment
                "minor_amount": 1000,  # Amount in minor units (e.g., 1000 = $10.00)
                "currency": "USD"  # ISO 4217 currency code (e.g., "USD", "EUR")
            },
            "payment_method": {  # Payment method to be used
                "card": {  # Generic card payment
                    "card_number": {"value": "4111111111111111"},  # Card Identification
                    "card_exp_month": {"value": "03"},
                    "card_exp_year": {"value": "2030"},
                    "card_cvc": {"value": "737"},
                    "card_holder_name": {"value": "John Doe"}  # Cardholder Information
                }
            },
            "capture_method": "MANUAL",  # Method for capturing the payment
            "customer": {  # Customer Information
                "name": "John Doe",  # Customer's full name
                "email": {"value": "test@example.com"},  # Customer's email address
                "id": "cust_probe_123",  # Internal customer ID
                "phone_number": "4155552671",  # Customer's phone number
                "phone_country_code": "+1"  # Customer's phone country code
            },
            "address": {  # Address Information
                "shipping_address": {
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
                },
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
            },
            "auth_type": "NO_THREE_DS",  # Authentication Details
            "return_url": "https://example.com/return",  # URLs for Redirection and Webhooks
            "webhook_url": "https://example.com/webhook",
            "complete_authorize_url": "https://example.com/complete",
            "merchant_order_id": "probe_order_001",
            "browser_info": {
                "color_depth": 24,  # Display Information
                "screen_height": 900,
                "screen_width": 1440,
                "java_enabled": False,  # Browser Settings
                "java_script_enabled": True,
                "language": "en-US",
                "time_zone_offset_minutes": -480,
                "accept_header": "application/json",  # Browser Headers
                "user_agent": "Mozilla/5.0 (probe-bot)",
                "accept_language": "en-US,en;q=0.9",
                "ip_address": "1.2.3.4"  # Device Information
            }
        },
        payment_pb2.PaymentServiceAuthorizeRequest(),
    ))

    if authorize_response.status == "FAILED":
        raise RuntimeError(f"Payment failed: {authorize_response.error}")
    if authorize_response.status == "PENDING":
        # Awaiting async confirmation — handle via webhook
        return {"status": "pending", "transaction_id": authorize_response.connector_transaction_id}

    # Step 2: Capture — settle the reserved funds
    capture_response = await payment_client.capture(ParseDict(
        {
            "merchant_capture_id": "probe_capture_001",  # Identification
            "connector_transaction_id": authorize_response.connector_transaction_id,  # from Authorize response
            "amount_to_capture": {  # Capture Details
                "minor_amount": 1000,  # Amount in minor units (e.g., 1000 = $10.00)
                "currency": "USD"  # ISO 4217 currency code (e.g., "USD", "EUR")
            }
        },
        payment_pb2.PaymentServiceCaptureRequest(),
    ))

    if capture_response.status == "FAILED":
        raise RuntimeError(f"Capture failed: {capture_response.error}")

    return {"status": capture_response.status, "transaction_id": authorize_response.connector_transaction_id}


async def process_checkout_autocapture(merchant_transaction_id: str, config: sdk_config_pb2.ConnectorConfig = _default_config):
    """Card Payment (Automatic Capture)

    Authorize and capture in one call using `capture_method=AUTOMATIC`. Use for digital goods or immediate fulfillment.
    """
    payment_client = PaymentClient(config)

    # Step 1: Authorize — reserve funds on the payment method
    authorize_response = await payment_client.authorize(ParseDict(
        {
            "merchant_transaction_id": "probe_txn_001",  # Identification
            "amount": {  # The amount for the payment
                "minor_amount": 1000,  # Amount in minor units (e.g., 1000 = $10.00)
                "currency": "USD"  # ISO 4217 currency code (e.g., "USD", "EUR")
            },
            "payment_method": {  # Payment method to be used
                "card": {  # Generic card payment
                    "card_number": {"value": "4111111111111111"},  # Card Identification
                    "card_exp_month": {"value": "03"},
                    "card_exp_year": {"value": "2030"},
                    "card_cvc": {"value": "737"},
                    "card_holder_name": {"value": "John Doe"}  # Cardholder Information
                }
            },
            "capture_method": "AUTOMATIC",  # Method for capturing the payment
            "customer": {  # Customer Information
                "name": "John Doe",  # Customer's full name
                "email": {"value": "test@example.com"},  # Customer's email address
                "id": "cust_probe_123",  # Internal customer ID
                "phone_number": "4155552671",  # Customer's phone number
                "phone_country_code": "+1"  # Customer's phone country code
            },
            "address": {  # Address Information
                "shipping_address": {
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
                },
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
            },
            "auth_type": "NO_THREE_DS",  # Authentication Details
            "return_url": "https://example.com/return",  # URLs for Redirection and Webhooks
            "webhook_url": "https://example.com/webhook",
            "complete_authorize_url": "https://example.com/complete",
            "merchant_order_id": "probe_order_001",
            "browser_info": {
                "color_depth": 24,  # Display Information
                "screen_height": 900,
                "screen_width": 1440,
                "java_enabled": False,  # Browser Settings
                "java_script_enabled": True,
                "language": "en-US",
                "time_zone_offset_minutes": -480,
                "accept_header": "application/json",  # Browser Headers
                "user_agent": "Mozilla/5.0 (probe-bot)",
                "accept_language": "en-US,en;q=0.9",
                "ip_address": "1.2.3.4"  # Device Information
            }
        },
        payment_pb2.PaymentServiceAuthorizeRequest(),
    ))

    if authorize_response.status == "FAILED":
        raise RuntimeError(f"Payment failed: {authorize_response.error}")
    if authorize_response.status == "PENDING":
        # Awaiting async confirmation — handle via webhook
        return {"status": "pending", "transaction_id": authorize_response.connector_transaction_id}

    return {"status": authorize_response.status, "transaction_id": authorize_response.connector_transaction_id}


async def process_refund(merchant_transaction_id: str, config: sdk_config_pb2.ConnectorConfig = _default_config):
    """Refund a Payment

    Authorize with automatic capture, then refund the captured amount. `connector_transaction_id` from the Authorize response is reused for the Refund call.
    """
    payment_client = PaymentClient(config)

    # Step 1: Authorize — reserve funds on the payment method
    authorize_response = await payment_client.authorize(ParseDict(
        {
            "merchant_transaction_id": "probe_txn_001",  # Identification
            "amount": {  # The amount for the payment
                "minor_amount": 1000,  # Amount in minor units (e.g., 1000 = $10.00)
                "currency": "USD"  # ISO 4217 currency code (e.g., "USD", "EUR")
            },
            "payment_method": {  # Payment method to be used
                "card": {  # Generic card payment
                    "card_number": {"value": "4111111111111111"},  # Card Identification
                    "card_exp_month": {"value": "03"},
                    "card_exp_year": {"value": "2030"},
                    "card_cvc": {"value": "737"},
                    "card_holder_name": {"value": "John Doe"}  # Cardholder Information
                }
            },
            "capture_method": "AUTOMATIC",  # Method for capturing the payment
            "customer": {  # Customer Information
                "name": "John Doe",  # Customer's full name
                "email": {"value": "test@example.com"},  # Customer's email address
                "id": "cust_probe_123",  # Internal customer ID
                "phone_number": "4155552671",  # Customer's phone number
                "phone_country_code": "+1"  # Customer's phone country code
            },
            "address": {  # Address Information
                "shipping_address": {
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
                },
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
            },
            "auth_type": "NO_THREE_DS",  # Authentication Details
            "return_url": "https://example.com/return",  # URLs for Redirection and Webhooks
            "webhook_url": "https://example.com/webhook",
            "complete_authorize_url": "https://example.com/complete",
            "merchant_order_id": "probe_order_001",
            "browser_info": {
                "color_depth": 24,  # Display Information
                "screen_height": 900,
                "screen_width": 1440,
                "java_enabled": False,  # Browser Settings
                "java_script_enabled": True,
                "language": "en-US",
                "time_zone_offset_minutes": -480,
                "accept_header": "application/json",  # Browser Headers
                "user_agent": "Mozilla/5.0 (probe-bot)",
                "accept_language": "en-US,en;q=0.9",
                "ip_address": "1.2.3.4"  # Device Information
            }
        },
        payment_pb2.PaymentServiceAuthorizeRequest(),
    ))

    if authorize_response.status == "FAILED":
        raise RuntimeError(f"Payment failed: {authorize_response.error}")
    if authorize_response.status == "PENDING":
        # Awaiting async confirmation — handle via webhook
        return {"status": "pending", "transaction_id": authorize_response.connector_transaction_id}

    # Step 2: Refund — return funds to the customer
    refund_response = await payment_client.refund(ParseDict(
        {
            "merchant_refund_id": "probe_refund_001",  # Identification
            "connector_transaction_id": authorize_response.connector_transaction_id,  # from Authorize response
            "payment_amount": 1000,  # Amount Information
            "refund_amount": {
                "minor_amount": 1000,  # Amount in minor units (e.g., 1000 = $10.00)
                "currency": "USD"  # ISO 4217 currency code (e.g., "USD", "EUR")
            },
            "reason": "customer_request"  # Reason for the refund
        },
        payment_pb2.PaymentServiceRefundRequest(),
    ))

    if refund_response.status == "FAILED":
        raise RuntimeError(f"Refund failed: {refund_response.error}")

    return {"status": refund_response.status}


async def process_get_payment(merchant_transaction_id: str, config: sdk_config_pb2.ConnectorConfig = _default_config):
    """Get Payment Status

    Authorize a payment, then poll the connector for its current status using Get. Use this to sync payment state when webhooks are unavailable or delayed.
    """
    payment_client = PaymentClient(config)

    # Step 1: Authorize — reserve funds on the payment method
    authorize_response = await payment_client.authorize(ParseDict(
        {
            "merchant_transaction_id": "probe_txn_001",  # Identification
            "amount": {  # The amount for the payment
                "minor_amount": 1000,  # Amount in minor units (e.g., 1000 = $10.00)
                "currency": "USD"  # ISO 4217 currency code (e.g., "USD", "EUR")
            },
            "payment_method": {  # Payment method to be used
                "card": {  # Generic card payment
                    "card_number": {"value": "4111111111111111"},  # Card Identification
                    "card_exp_month": {"value": "03"},
                    "card_exp_year": {"value": "2030"},
                    "card_cvc": {"value": "737"},
                    "card_holder_name": {"value": "John Doe"}  # Cardholder Information
                }
            },
            "capture_method": "MANUAL",  # Method for capturing the payment
            "customer": {  # Customer Information
                "name": "John Doe",  # Customer's full name
                "email": {"value": "test@example.com"},  # Customer's email address
                "id": "cust_probe_123",  # Internal customer ID
                "phone_number": "4155552671",  # Customer's phone number
                "phone_country_code": "+1"  # Customer's phone country code
            },
            "address": {  # Address Information
                "shipping_address": {
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
                },
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
            },
            "auth_type": "NO_THREE_DS",  # Authentication Details
            "return_url": "https://example.com/return",  # URLs for Redirection and Webhooks
            "webhook_url": "https://example.com/webhook",
            "complete_authorize_url": "https://example.com/complete",
            "merchant_order_id": "probe_order_001",
            "browser_info": {
                "color_depth": 24,  # Display Information
                "screen_height": 900,
                "screen_width": 1440,
                "java_enabled": False,  # Browser Settings
                "java_script_enabled": True,
                "language": "en-US",
                "time_zone_offset_minutes": -480,
                "accept_header": "application/json",  # Browser Headers
                "user_agent": "Mozilla/5.0 (probe-bot)",
                "accept_language": "en-US,en;q=0.9",
                "ip_address": "1.2.3.4"  # Device Information
            }
        },
        payment_pb2.PaymentServiceAuthorizeRequest(),
    ))

    if authorize_response.status == "FAILED":
        raise RuntimeError(f"Payment failed: {authorize_response.error}")
    if authorize_response.status == "PENDING":
        # Awaiting async confirmation — handle via webhook
        return {"status": "pending", "transaction_id": authorize_response.connector_transaction_id}

    # Step 2: Get — retrieve current payment status from the connector
    get_response = await payment_client.get(ParseDict(
        {
            "connector_transaction_id": authorize_response.connector_transaction_id,  # from Authorize response
            "amount": {  # Amount Information
                "minor_amount": 1000,  # Amount in minor units (e.g., 1000 = $10.00)
                "currency": "USD"  # ISO 4217 currency code (e.g., "USD", "EUR")
            }
        },
        payment_pb2.PaymentServiceGetRequest(),
    ))

    return {"status": get_response.status, "transaction_id": get_response.connector_transaction_id}


async def authorize(merchant_transaction_id: str, config: sdk_config_pb2.ConnectorConfig = _default_config):
    """Flow: PaymentService.Authorize (Card)"""
    payment_client = PaymentClient(config)

    # Step 1: Authorize — reserve funds on the payment method
    authorize_response = await payment_client.authorize(ParseDict(
        {
            "merchant_transaction_id": "probe_txn_001",  # Identification
            "amount": {  # The amount for the payment
                "minor_amount": 1000,  # Amount in minor units (e.g., 1000 = $10.00)
                "currency": "USD"  # ISO 4217 currency code (e.g., "USD", "EUR")
            },
            "payment_method": {  # Payment method to be used
                "card": {  # Generic card payment
                    "card_number": {"value": "4111111111111111"},  # Card Identification
                    "card_exp_month": {"value": "03"},
                    "card_exp_year": {"value": "2030"},
                    "card_cvc": {"value": "737"},
                    "card_holder_name": {"value": "John Doe"}  # Cardholder Information
                }
            },
            "capture_method": "AUTOMATIC",  # Method for capturing the payment
            "customer": {  # Customer Information
                "name": "John Doe",  # Customer's full name
                "email": {"value": "test@example.com"},  # Customer's email address
                "id": "cust_probe_123",  # Internal customer ID
                "phone_number": "4155552671",  # Customer's phone number
                "phone_country_code": "+1"  # Customer's phone country code
            },
            "address": {  # Address Information
                "shipping_address": {
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
                },
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
            },
            "auth_type": "NO_THREE_DS",  # Authentication Details
            "return_url": "https://example.com/return",  # URLs for Redirection and Webhooks
            "webhook_url": "https://example.com/webhook",
            "complete_authorize_url": "https://example.com/complete",
            "merchant_order_id": "probe_order_001",
            "browser_info": {
                "color_depth": 24,  # Display Information
                "screen_height": 900,
                "screen_width": 1440,
                "java_enabled": False,  # Browser Settings
                "java_script_enabled": True,
                "language": "en-US",
                "time_zone_offset_minutes": -480,
                "accept_header": "application/json",  # Browser Headers
                "user_agent": "Mozilla/5.0 (probe-bot)",
                "accept_language": "en-US,en;q=0.9",
                "ip_address": "1.2.3.4"  # Device Information
            }
        },
        payment_pb2.PaymentServiceAuthorizeRequest(),
    ))

    if authorize_response.status == "FAILED":
        raise RuntimeError(f"Payment failed: {authorize_response.error}")
    if authorize_response.status == "PENDING":
        # Awaiting async confirmation — handle via webhook
        return {"status": "pending", "transaction_id": authorize_response.connector_transaction_id}

    return {"status": authorize_response.status, "transaction_id": authorize_response.connector_transaction_id}


async def capture(merchant_transaction_id: str, config: sdk_config_pb2.ConnectorConfig = _default_config):
    """Flow: PaymentService.Capture"""
    payment_client = PaymentClient(config)

    # Step 1: Capture — settle the reserved funds
    capture_response = await payment_client.capture(ParseDict(
        {
            "merchant_capture_id": "probe_capture_001",  # Identification
            "connector_transaction_id": "probe_connector_txn_001",
            "amount_to_capture": {  # Capture Details
                "minor_amount": 1000,  # Amount in minor units (e.g., 1000 = $10.00)
                "currency": "USD"  # ISO 4217 currency code (e.g., "USD", "EUR")
            }
        },
        payment_pb2.PaymentServiceCaptureRequest(),
    ))

    if capture_response.status == "FAILED":
        raise RuntimeError(f"Capture failed: {capture_response.error}")

    return {"status": capture_response.status}


async def create_order(merchant_transaction_id: str, config: sdk_config_pb2.ConnectorConfig = _default_config):
    """Flow: PaymentService.CreateOrder"""
    payment_client = PaymentClient(config)

    # Step 1: create_order
    create_response = await payment_client.create_order(ParseDict(
        {
            "merchant_order_id": "probe_order_001",  # Identification
            "amount": {  # Amount Information
                "minor_amount": 1000,  # Amount in minor units (e.g., 1000 = $10.00)
                "currency": "USD"  # ISO 4217 currency code (e.g., "USD", "EUR")
            }
        },
        payment_pb2.PaymentServiceCreateOrderRequest(),
    ))

    return {"status": create_response.status}


async def get(merchant_transaction_id: str, config: sdk_config_pb2.ConnectorConfig = _default_config):
    """Flow: PaymentService.Get"""
    payment_client = PaymentClient(config)

    # Step 1: Get — retrieve current payment status from the connector
    get_response = await payment_client.get(ParseDict(
        {
            "connector_transaction_id": "probe_connector_txn_001",
            "amount": {  # Amount Information
                "minor_amount": 1000,  # Amount in minor units (e.g., 1000 = $10.00)
                "currency": "USD"  # ISO 4217 currency code (e.g., "USD", "EUR")
            }
        },
        payment_pb2.PaymentServiceGetRequest(),
    ))

    return {"status": get_response.status}

if __name__ == "__main__":
    scenario = sys.argv[1] if len(sys.argv) > 1 else "checkout_card"
    fn = globals().get(f"process_{scenario}")
    if not fn:
        available = [k[8:] for k in globals() if k.startswith("process_")]
        print(f"Unknown scenario: {scenario}. Available: {available}", file=sys.stderr)
        sys.exit(1)
    asyncio.run(fn("order_001"))
