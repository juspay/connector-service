# This file is auto-generated. Do not edit manually.
# Replace YOUR_API_KEY and placeholder values with real data.
# Regenerate: python3 scripts/generate-connector-docs.py aci
#
# Aci — all integration scenarios and flows in one file.
# Run a scenario:  python3 aci.py checkout_card

import asyncio
import sys
from google.protobuf.json_format import ParseDict
from payments import PaymentClient
from payments import RecurringPaymentClient
from payments.generated import sdk_config_pb2, payment_pb2

_default_config = sdk_config_pb2.ConnectorConfig(
    connector=payment_pb2.Connector.ACI,
    environment=sdk_config_pb2.Environment.SANDBOX,
)
# Standalone credentials (field names depend on connector auth type):
# _default_config.auth.aci.api_key.value = "YOUR_API_KEY"


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


async def process_recurring(merchant_transaction_id: str, config: sdk_config_pb2.ConnectorConfig = _default_config):
    """Recurring / Mandate Payments

    Store a payment mandate with SetupRecurring, then charge it repeatedly with RecurringPaymentService.Charge without requiring customer action.
    """
    payment_client = PaymentClient(config)
    recurringpayment_client = RecurringPaymentClient(config)

    # Step 1: Setup Recurring — store the payment mandate
    setup_response = await payment_client.setup_recurring(ParseDict(
        {
            "merchant_recurring_payment_id": "probe_mandate_001",  # Identification
            "amount": {  # Mandate Details
                "minor_amount": 0,  # Amount in minor units (e.g., 1000 = $10.00)
                "currency": "USD"  # ISO 4217 currency code (e.g., "USD", "EUR")
            },
            "payment_method": {
                "card": {  # Generic card payment
                    "card_number": {"value": "4111111111111111"},  # Card Identification
                    "card_exp_month": {"value": "03"},
                    "card_exp_year": {"value": "2030"},
                    "card_cvc": {"value": "737"},
                    "card_holder_name": {"value": "John Doe"}  # Cardholder Information
                }
            },
            "customer": {
                "name": "John Doe",  # Customer's full name
                "email": {"value": "test@example.com"},  # Customer's email address
                "id": "cust_probe_123",  # Internal customer ID
                "phone_number": "4155552671",  # Customer's phone number
                "phone_country_code": "+1"  # Customer's phone country code
            },
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
            },
            "auth_type": "NO_THREE_DS",  # Type of authentication to be used
            "enrolled_for_3ds": False,  # Indicates if the customer is enrolled for 3D Secure
            "return_url": "https://example.com/mandate-return",  # URL to redirect after setup
            "setup_future_usage": "OFF_SESSION",  # Indicates future usage intention
            "request_incremental_authorization": False,  # Indicates if incremental authorization is requested
            "customer_acceptance": {  # Details of customer acceptance
                "acceptance_type": "OFFLINE",  # Type of acceptance (e.g., online, offline).
                "accepted_at": 0  # Timestamp when the acceptance was made (Unix timestamp, seconds since epoch).
            },
            "browser_info": {  # Information about the customer's browser
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
        payment_pb2.PaymentServiceSetupRecurringRequest(),
    ))

    if setup_response.status == "FAILED":
        raise RuntimeError(f"Recurring setup failed: {setup_response.error}")
    if setup_response.status == "PENDING":
        # Mandate stored asynchronously — save connector_recurring_payment_id
        return {"status": "pending", "mandate_id": setup_response.connector_recurring_payment_id}

    # Step 2: Recurring Charge — charge against the stored mandate
    recurring_response = await recurringpayment_client.charge(ParseDict(
        {
            "connector_recurring_payment_id": {"connector_mandate_id": {"connector_mandate_id": setup_response.mandate_reference.connector_mandate_id.connector_mandate_id}},  # from SetupRecurring response
            "amount": {  # Amount Information
                "minor_amount": 1000,  # Amount in minor units (e.g., 1000 = $10.00)
                "currency": "USD"  # ISO 4217 currency code (e.g., "USD", "EUR")
            },
            "return_url": "https://example.com/recurring-return",
            "off_session": True  # Behavioral Flags and Preferences
        },
        payment_pb2.RecurringPaymentServiceChargeRequest(),
    ))

    if recurring_response.status == "FAILED":
        raise RuntimeError(f"Recurring_Charge failed: {recurring_response.error}")

    return {"status": recurring_response.status, "transaction_id": getattr(recurring_response, "connector_transaction_id", "")}


async def process_void_payment(merchant_transaction_id: str, config: sdk_config_pb2.ConnectorConfig = _default_config):
    """Void a Payment

    Authorize funds with a manual capture flag, then cancel the authorization with Void before any capture occurs. Releases the hold on the customer's funds.
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

    # Step 2: Void — release reserved funds (cancel authorization)
    void_response = await payment_client.void(ParseDict(
        {
            "merchant_void_id": "probe_void_001",  # Identification
            "connector_transaction_id": authorize_response.connector_transaction_id,  # from Authorize response
        },
        payment_pb2.PaymentServiceVoidRequest(),
    ))

    return {"status": void_response.status, "transaction_id": authorize_response.connector_transaction_id}


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


async def recurring_charge(merchant_transaction_id: str, config: sdk_config_pb2.ConnectorConfig = _default_config):
    """Flow: RecurringPaymentService.Charge"""
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


async def setup_recurring(merchant_transaction_id: str, config: sdk_config_pb2.ConnectorConfig = _default_config):
    """Flow: PaymentService.SetupRecurring"""
    payment_client = PaymentClient(config)

    # Step 1: Setup Recurring — store the payment mandate
    setup_response = await payment_client.setup_recurring(ParseDict(
        {
            "merchant_recurring_payment_id": "probe_mandate_001",  # Identification
            "amount": {  # Mandate Details
                "minor_amount": 0,  # Amount in minor units (e.g., 1000 = $10.00)
                "currency": "USD"  # ISO 4217 currency code (e.g., "USD", "EUR")
            },
            "payment_method": {
                "card": {  # Generic card payment
                    "card_number": {"value": "4111111111111111"},  # Card Identification
                    "card_exp_month": {"value": "03"},
                    "card_exp_year": {"value": "2030"},
                    "card_cvc": {"value": "737"},
                    "card_holder_name": {"value": "John Doe"}  # Cardholder Information
                }
            },
            "customer": {
                "name": "John Doe",  # Customer's full name
                "email": {"value": "test@example.com"},  # Customer's email address
                "id": "cust_probe_123",  # Internal customer ID
                "phone_number": "4155552671",  # Customer's phone number
                "phone_country_code": "+1"  # Customer's phone country code
            },
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
            },
            "auth_type": "NO_THREE_DS",  # Type of authentication to be used
            "enrolled_for_3ds": False,  # Indicates if the customer is enrolled for 3D Secure
            "return_url": "https://example.com/mandate-return",  # URL to redirect after setup
            "setup_future_usage": "OFF_SESSION",  # Indicates future usage intention
            "request_incremental_authorization": False,  # Indicates if incremental authorization is requested
            "customer_acceptance": {  # Details of customer acceptance
                "acceptance_type": "OFFLINE",  # Type of acceptance (e.g., online, offline).
                "accepted_at": 0  # Timestamp when the acceptance was made (Unix timestamp, seconds since epoch).
            },
            "browser_info": {  # Information about the customer's browser
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
        payment_pb2.PaymentServiceSetupRecurringRequest(),
    ))

    if setup_response.status == "FAILED":
        raise RuntimeError(f"Recurring setup failed: {setup_response.error}")
    if setup_response.status == "PENDING":
        # Mandate stored asynchronously — save connector_recurring_payment_id
        return {"status": "pending", "mandate_id": setup_response.connector_recurring_payment_id}

    return {"status": setup_response.status, "mandate_id": setup_response.connector_transaction_id}


async def void(merchant_transaction_id: str, config: sdk_config_pb2.ConnectorConfig = _default_config):
    """Flow: PaymentService.Void"""
    payment_client = PaymentClient(config)

    # Step 1: Void — release reserved funds (cancel authorization)
    void_response = await payment_client.void(ParseDict(
        {
            "merchant_void_id": "probe_void_001",  # Identification
            "connector_transaction_id": "probe_connector_txn_001"
        },
        payment_pb2.PaymentServiceVoidRequest(),
    ))

    return {"status": void_response.status}

if __name__ == "__main__":
    scenario = sys.argv[1] if len(sys.argv) > 1 else "checkout_card"
    fn = globals().get(f"process_{scenario}")
    if not fn:
        available = [k[8:] for k in globals() if k.startswith("process_")]
        print(f"Unknown scenario: {scenario}. Available: {available}", file=sys.stderr)
        sys.exit(1)
    asyncio.run(fn("order_001"))
