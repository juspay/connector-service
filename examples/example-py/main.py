import grpc
import os
import sys

sys.path.append("./generated")

from payment_pb2 import (
    PaymentsAuthorizeRequest,
    PaymentsSyncRequest,
    Card,
    PaymentMethodData,
    PaymentAddress,
    AuthenticationType,
    PaymentsAuthorizeResponse,
    PaymentsSyncResponse,
    Currency,
    PaymentMethod,
    BrowserInformation,
)
from payment_pb2_grpc import PaymentServiceStub
from typing import Union

def get_env_variable(var_name: str, default: str) -> str:
    """Fetch an environment variable or return a default value."""
    return os.getenv(var_name, default)

# Retrieve credentials from environment variables
api_key = get_env_variable("API_KEY", "default_api_key")
key1 = get_env_variable("KEY1", "default_key1")

metadata = [
    ('x-auth','body-key'),
    ('x-connector', 'razorpay'),
    ('x-api-key', api_key),
    ('x-key1',key1)
]

def make_payment_authorization_request(url: str) -> Union[PaymentsAuthorizeResponse, None]:
    """Send a payment authorization request."""
    try:
        channel = grpc.insecure_channel(url)
        client = PaymentServiceStub(channel)

        # Create request with updated values
        request = PaymentsAuthorizeRequest(
            amount=1000,
            currency=Currency.USD,
            # connector=Connector.RAZORPAY,
            # auth_creds=AuthType(
            #     body_key=BodyKey(api_key=api_key, key1=key1)
            # ),
            payment_method=PaymentMethod.CARD,
            payment_method_data=PaymentMethodData(
                card=Card(
                    card_number="5123456789012346",
                    card_exp_month="03",
                    card_exp_year="2030",
                    card_cvc="100",
                )
            ),
            address=PaymentAddress(),
            auth_type=AuthenticationType.THREE_DS,
            connector_request_reference_id="ref_12345",
            enrolled_for_3ds=True,
            request_incremental_authorization=False,
            minor_amount=1000,
            email="example@example.com",
            browser_info=BrowserInformation(
                user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
                accept_header="text/html,application/xhtml+xml",
                language="en-US",
                color_depth=24,
                screen_height=1080,
                screen_width=1920,
                java_enabled=False,
            ),
            connector_customer="cus_131",
            return_url="www.google.com"
        )

        # TODO set connector and auth in headers
        return client.PaymentAuthorize(request,metadata=metadata)
    except grpc.RpcError as e:
        print(f"RPC error: {e.code()}: {e.details()}", file=sys.stderr)
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
    finally:
        if 'channel' in locals():
            channel.close()


def make_payment_sync_request(url: str) -> Union[PaymentsSyncResponse, None]:
    """Send a payment sync request."""
    try:
        channel = grpc.insecure_channel(url)
        client = PaymentServiceStub(channel)
        resource_id = get_env_variable("RESOURCE_ID", "pay_QHj9Thiy5mCC4Y")

        # Create the request
        request = PaymentsSyncRequest(
            # connector=Connector.RAZORPAY,
            # auth_creds=AuthType(
            #     body_key=BodyKey(api_key=api_key, key1=key1)
            # ),
            resource_id=resource_id,
            connector_request_reference_id="conn_req_abc",
        )

        # TODO set connector and auth in headers
        return client.PaymentSync(request,metadata=metadata)
    except grpc.RpcError as e:
        print(f"RPC error: {e.code()}: {e.details()}", file=sys.stderr)
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
    finally:
        if 'channel' in locals():
            channel.close()


def main():
    """Main function to parse arguments and execute operations."""
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <url> [operation]", file=sys.stderr)
        print("Operations: authorize, sync", file=sys.stderr)
        sys.exit(1)

    url = sys.argv[1]
    operation = sys.argv[2] if len(sys.argv) > 2 else "authorize"

    if operation == "authorize":
        response = make_payment_authorization_request(url)
        print(f"Authorization Response: {response}")
    elif operation == "sync":
        response = make_payment_sync_request(url)
        print(f"Sync Response: {response}")
    else:
        print(f"Unknown operation: {operation}. Use 'authorize' or 'sync'.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
