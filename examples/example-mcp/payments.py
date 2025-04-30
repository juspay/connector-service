from mcp.server.fastmcp import FastMCP
import os
import grpc
import sys
from typing import Dict, Any, Optional
from enum import Enum

# Razorpay test credentials
RAZORPAY_API_KEY = "<YOUR_RAZORPAY_API_KEY>"  # Replace with your Razorpay API key
RAZORPAY_KEY1 = "<YOUR_RAZORPAY_KEY1>"  # Replace with your Razorpay Key1

# Add path for generated protobuf files
import os.path
PROTO_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "example-py", "generated")
sys.path.append(PROTO_PATH)

# Import protobuf generated classes
try:
    from payment_pb2 import (
        PaymentsAuthorizeRequest,
        PaymentsSyncRequest,
        Card,
        PaymentMethodData,
        PaymentAddress,
        AuthType,
        BodyKey,
        AuthenticationType,
        Currency as PBCurrency,
        Connector as PBConnector,
        PaymentMethod as PBPaymentMethod,
        BrowserInformation,
    )
    from payment_pb2_grpc import PaymentServiceStub
    
    # Verify enum values exist to catch potential issues early
    try:
        # Test accessing some enum values
        _ = PBPaymentMethod.CARD
        _ = PBConnector.STRIPE
        _ = PBCurrency.USD
        
        GRPC_AVAILABLE = True
        print("gRPC dependencies successfully loaded and verified")
    except (ValueError, AttributeError) as enum_error:
        print(f"Warning: gRPC modules loaded but enum values not properly defined: {enum_error}")
        GRPC_AVAILABLE = False
except ImportError as e:
    GRPC_AVAILABLE = False
    print(f"Warning: gRPC dependencies not found. Using mock implementation. Error: {str(e)}")

mcp = FastMCP('cursor-mcp')

class Currency(str, Enum):
    USD = "USD"
    EUR = "EUR"
    GBP = "GBP"
    INR = "INR"

class PaymentMethod(str, Enum):
    CARD = "card"

class Connector(str, Enum):
    STRIPE = "STRIPE"
    RAZORPAY = "RAZORPAY"
    ADYEN = "ADYEN"

def map_currency(currency_str: str):
    """Map string currency to protobuf enum value"""
    currency_map = {
        "USD": PBCurrency.USD,
        "EUR": PBCurrency.EUR,
        "GBP": PBCurrency.GBP,
        "INR": PBCurrency.INR
    }
    # Print for debugging
    mapped_currency = currency_map.get(currency_str.upper())
    print(f"Mapping currency: {currency_str} -> {mapped_currency}")
    return mapped_currency

def map_connector(connector_str: str):
    """Map string connector to protobuf enum value"""
    connector_map = {
        "RAZORPAY": PBConnector.RAZORPAY,
        "STRIPE": PBConnector.STRIPE,
        "ADYEN": PBConnector.ADYEN
    }
    # Print for debugging
    print(f"Mapping connector: {connector_str} -> {connector_map.get(connector_str)}")
    return connector_map.get(connector_str)

def map_payment_method(method_str: str):
    """Map string payment method to protobuf enum value"""
    method_map = {
        "card": PBPaymentMethod.CARD
    }
    
    # Get the enum value if it exists, otherwise use CARD as default
    try:
        return method_map.get(method_str.lower(), PBPaymentMethod.CARD)
    except ValueError:
        # If there's an issue with the enum values, fall back to CARD
        return PBPaymentMethod.CARD

@mcp.tool()
def authorize_payment(
    amount: float,
    currency: str,
    connector: str,
    api_key: str = "",
    payment_method: str = "card",
    card_details: Dict[str, str] = None,
    email: str = "test@example.com",
    reference_id: Optional[str] = None,
    grpc_server_url: str = "localhost:8000"
) -> Dict[str, Any]:
    """
    Authorize a payment with the specified details.
    
    Args:
        amount: Amount to charge
        currency: Currency code (e.g., USD, EUR)
        connector: Payment processor (e.g., stripe, razorpay)
        api_key: API key for the payment processor (optional, defaults to test keys)
        payment_method: Method of payment (e.g., CARD)
        card_details: Dictionary containing card information
        email: Customer email
        reference_id: Optional reference ID for the transaction
        grpc_server_url: URL of the gRPC server (default: localhost:8000)
    """
    try:
        # Set default card details if not provided
        if card_details is None:
            card_details = {
                "card_number": "4242424242424242",
                "card_exp_month": "12",
                "card_exp_year": "2025",
                "card_cvc": "123"
            }
            
        # Validate inputs
        if not isinstance(amount, (int, float)) or amount <= 0:
            return {"error": "Invalid amount"}
        
        if currency not in [c.value for c in Currency]:
            return {"error": "Unsupported currency"}
            
        if connector not in [c.value for c in Connector]:
            return {"error": "Unsupported payment connector"}
            
        if payment_method not in [pm.value for pm in PaymentMethod]:
            return {"error": "Unsupported payment method"}
            
        required_card_fields = ["card_number", "card_exp_month", "card_exp_year", "card_cvc"]
        if not all(field in card_details for field in required_card_fields):
            return {"error": "Missing required card details"}

        # Use Razorpay test credentials if connector is razorpay and no API key provided
        key1 = ""
        if connector.lower() == "razorpay":
            # Try to get credentials from environment or use constants
            if not api_key:
                api_key = os.environ.get("API_KEY", RAZORPAY_API_KEY)
            key1 = os.environ.get("KEY1", RAZORPAY_KEY1)

        # If gRPC dependencies are available, use actual client
        if GRPC_AVAILABLE:
            try:
                # Create gRPC channel and client
                channel = grpc.insecure_channel(grpc_server_url)
                client = PaymentServiceStub(channel)
                
                # Build request with all required fields
                request = PaymentsAuthorizeRequest(
                    amount=int(amount * 100),  # Convert to minor units
                    currency=map_currency(currency),
                    connector=map_connector(connector),
                    auth_creds=AuthType(
                        body_key=BodyKey(api_key=api_key, key1=key1)
                    ),
                    payment_method=map_payment_method(payment_method),
                    payment_method_data=PaymentMethodData(
                        card=Card(
                            card_number=card_details["card_number"],
                            card_exp_month=card_details["card_exp_month"],
                            card_exp_year=card_details["card_exp_year"],
                            card_cvc=card_details["card_cvc"]
                        )
                    ),
                    address=PaymentAddress(),
                    auth_type=AuthenticationType.THREE_DS,
                    connector_request_reference_id=reference_id or f"ref_{os.urandom(4).hex()}",
                    enrolled_for_3ds=True,
                    request_incremental_authorization=False,
                    minor_amount=int(amount * 100),
                    email=email,
                    browser_info=BrowserInformation(
                        user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X)",
                        accept_header="text/html,application/xhtml+xml",
                        language="en-US",
                        color_depth=24,
                        screen_height=1080,
                        screen_width=1920,
                        java_enabled=False
                    )
                )
                
                # Make the RPC call
                response = client.PaymentAuthorize(request)
                
                # Return parsed response based on what we observed in the actual response
                payment_id = ""
                if hasattr(response, "resource_id") and hasattr(response.resource_id, "connector_transaction_id"):
                    payment_id = response.resource_id.connector_transaction_id
                
                # Map status codes to string representation
                status_map = {
                    "3": "pending_authentication",  # AUTHENTICATION_PENDING
                    "7": "charged",                # CHARGED
                    "2": "pending",                # PENDING
                }
                
                status = "unknown"
                if hasattr(response, "status"):
                    status_str = str(response.status)
                    if status_str in status_map:
                        status = status_map[status_str]
                    else:
                        status = status_str.lower() if isinstance(status_str, str) else "unknown"
                
                # Check for redirection data
                redirect_url = ""
                if hasattr(response, "redirection_data") and hasattr(response.redirection_data, "form"):
                    if hasattr(response.redirection_data.form, "endpoint"):
                        redirect_url = response.redirection_data.form.endpoint
                
                return {
                    "status": status,
                    "payment_id": payment_id,
                    "amount": amount,
                    "currency": currency,
                    "connector": connector,
                    "reference_id": reference_id,
                    "redirect_url": redirect_url,
                    "response_type": str(type(response))
                }
            except grpc.RpcError as e:
                return {"error": f"RPC error: {e.code()}: {e.details()}"}
            except Exception as e:
                return {"error": f"gRPC client error: {str(e)}"}
            finally:
                if 'channel' in locals():
                    channel.close()
        
        # Fall back to mock implementation if gRPC is not available
        return {
            "status": "authorized",
            "payment_id": "pay_" + os.urandom(8).hex(),
            "amount": amount,
            "currency": currency,
            "connector": connector,
            "reference_id": reference_id or "ref_" + os.urandom(8).hex(),
            "created_at": "2024-03-21T10:00:00Z",
            "note": "Mock implementation (gRPC not available)"
        }
    except Exception as e:
        return {"error": str(e)}

@mcp.tool()
def sync_payment(
    payment_id: str,
    connector: str,
    api_key: str = "",
    reference_id: Optional[str] = None,
    grpc_server_url: str = "localhost:8000"
) -> Dict[str, Any]:
    """
    Sync the status of a payment with the payment processor.
    
    Args:
        payment_id: ID of the payment to sync
        connector: Payment processor (e.g., STRIPE, RAZORPAY)
        api_key: API key for the payment processor (optional, defaults to test keys)
        reference_id: Optional reference ID for the transaction
        grpc_server_url: URL of the gRPC server (default: localhost:8000)
    """
    try:
        if not payment_id:
            return {"error": "Payment ID is required"}
            
        if connector not in [c.value for c in Connector]:
            return {"error": "Unsupported payment connector"}

        # Use Razorpay test credentials if connector is razorpay and no API key provided
        key1 = ""
        if connector.lower() == "razorpay":
            # Try to get credentials from environment or use constants
            if not api_key:
                api_key = os.environ.get("API_KEY", RAZORPAY_API_KEY)
            key1 = os.environ.get("KEY1", RAZORPAY_KEY1)

        # If gRPC dependencies are available, use actual client
        if GRPC_AVAILABLE:
            try:
                # Create gRPC channel and client
                channel = grpc.insecure_channel(grpc_server_url)
                client = PaymentServiceStub(channel)
                
                # Create sync request
                request = PaymentsSyncRequest(
                    connector=map_connector(connector),
                    auth_creds=AuthType(
                        body_key=BodyKey(api_key=api_key, key1=key1)
                    ),
                    resource_id=payment_id,
                    connector_request_reference_id=reference_id or f"conn_req_{os.urandom(4).hex()}"
                )
                
                # Make the RPC call
                response = client.PaymentSync(request)
                
                # Return parsed response based on what we observed in the actual response
                payment_id_from_response = ""
                if hasattr(response, "resource_id") and hasattr(response.resource_id, "connector_transaction_id"):
                    payment_id_from_response = response.resource_id.connector_transaction_id
                
                # Map status codes to string representation
                status_map = {
                    "3": "pending_authentication",  # AUTHENTICATION_PENDING
                    "7": "charged",                # CHARGED
                    "2": "pending",                # PENDING
                }
                
                status = "unknown"
                if hasattr(response, "status"):
                    status_str = str(response.status)
                    if status_str in status_map:
                        status = status_map[status_str]
                    else:
                        status = status_str.lower() if isinstance(status_str, str) else "unknown"
                
                return {
                    "status": status,
                    "payment_id": payment_id_from_response or payment_id,
                    "connector": connector,
                    "reference_id": reference_id,
                    "response_type": str(type(response))
                }
            except grpc.RpcError as e:
                return {"error": f"RPC error: {e.code()}: {e.details()}"}
            except Exception as e:
                return {"error": f"gRPC client error: {str(e)}"}
            finally:
                if 'channel' in locals():
                    channel.close()
        
        # Fall back to mock implementation
        return {
            "status": "succeeded",
            "payment_id": payment_id,
            "connector": connector,
            "reference_id": reference_id,
            "last_synced_at": "2024-03-21T10:05:00Z",
            "note": "Mock implementation (gRPC not available)"
        }
    except Exception as e:
        return {"error": str(e)}

@mcp.tool()
def get_payment_details(payment_id: str) -> Dict[str, Any]:
    """
    Get details of a specific payment.
    
    Args:
        payment_id: ID of the payment to retrieve details for
    """
    try:
        if not payment_id:
            return {"error": "Payment ID is required"}

        # In a real implementation, this would fetch payment details from a database
        # For demonstration, we'll return mock data
        return {
            "payment_id": payment_id,
            "status": "succeeded",
            "amount": 1000,
            "currency": "USD",
            "payment_method": "card",
            "created_at": "2024-03-21T10:00:00Z",
            "updated_at": "2024-03-21T10:05:00Z"
        }
    except Exception as e:
        return {"error": str(e)}

if __name__ == "__main__":
    mcp.run(transport="stdio")