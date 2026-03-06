# AUTO-GENERATED — do not edit by hand.
# Source: services.proto ∩ bindings/uniffi.rs  |  Regenerate: make generate
#
# This stub exposes dynamically-attached flow methods to static analysers
# (Pylance, pyright, mypy) so IDEs offer completions and type checking.
from payments.generated.sdk_config_pb2 import RequestOptions
from payments.generated.payment_pb2 import (
    MerchantAuthenticationServiceCreateAccessTokenRequest,
    MerchantAuthenticationServiceCreateAccessTokenResponse,
    PaymentServiceAuthorizeRequest,
    PaymentServiceAuthorizeResponse,
    PaymentServiceCaptureRequest,
    PaymentServiceCaptureResponse,
    PaymentServiceGetRequest,
    PaymentServiceGetResponse,
    PaymentServiceRefundRequest,
    PaymentServiceVoidRequest,
    PaymentServiceVoidResponse,
    RefundResponse,
)

class ConnectorClient:
    def __init__(self, lib_path: str | None = ...) -> None: ...

    def authorize(self, request: PaymentServiceAuthorizeRequest, metadata: dict, options: RequestOptions | None = ...) -> PaymentServiceAuthorizeResponse:
        """PaymentService.Authorize — Authorize a payment amount on a payment method. This reserves funds without capturing them, essential for verifying availability before finalizing."""
        ...

    def capture(self, request: PaymentServiceCaptureRequest, metadata: dict, options: RequestOptions | None = ...) -> PaymentServiceCaptureResponse:
        """PaymentService.Capture — Finalize an authorized payment transaction. Transfers reserved funds from customer to merchant account, completing the payment lifecycle."""
        ...

    def create_access_token(self, request: MerchantAuthenticationServiceCreateAccessTokenRequest, metadata: dict, options: RequestOptions | None = ...) -> MerchantAuthenticationServiceCreateAccessTokenResponse:
        """MerchantAuthenticationService.CreateAccessToken — Generate short-lived connector authentication token. Provides secure credentials for connector API access without storing secrets client-side."""
        ...

    def get(self, request: PaymentServiceGetRequest, metadata: dict, options: RequestOptions | None = ...) -> PaymentServiceGetResponse:
        """PaymentService.Get — Retrieve current payment status from the payment processor. Enables synchronization between your system and payment processors for accurate state tracking."""
        ...

    def refund(self, request: PaymentServiceRefundRequest, metadata: dict, options: RequestOptions | None = ...) -> RefundResponse:
        """PaymentService.Refund — Initiate a refund to customer's payment method. Returns funds for returns, cancellations, or service adjustments after original payment."""
        ...

    def void(self, request: PaymentServiceVoidRequest, metadata: dict, options: RequestOptions | None = ...) -> PaymentServiceVoidResponse:
        """PaymentService.Void — Cancel an authorized payment before capture. Releases held funds back to customer, typically used when orders are cancelled or abandoned."""
        ...

