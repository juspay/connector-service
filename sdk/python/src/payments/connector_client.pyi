# AUTO-GENERATED — do not edit by hand.
# Source: services.proto ∩ bindings/uniffi.rs  |  Regenerate: make generate
#
# This stub exposes per-service client classes to static analysers
# (Pylance, pyright, mypy) so IDEs offer completions and type checking.
from payments.generated.sdk_options_pb2 import FfiOptions
from payments.generated.payment_pb2 import (
    CustomerServiceCreateRequest,
    CustomerServiceCreateResponse,
    MerchantAuthenticationServiceCreateAccessTokenRequest,
    MerchantAuthenticationServiceCreateAccessTokenResponse,
    PaymentServiceAuthorizeRequest,
    PaymentServiceAuthorizeResponse,
    PaymentServiceCaptureRequest,
    PaymentServiceCaptureResponse,
    PaymentServiceGetRequest,
    PaymentServiceGetResponse,
    PaymentServiceRefundRequest,
    PaymentServiceReverseRequest,
    PaymentServiceReverseResponse,
    PaymentServiceVoidRequest,
    PaymentServiceVoidResponse,
    RecurringPaymentServiceChargeRequest,
    RecurringPaymentServiceChargeResponse,
    RefundResponse,
)

class _ConnectorClientBase:
    def __init__(self, lib_path: str | None = ..., options=...) -> None: ...

class PaymentClient(_ConnectorClientBase):
    def authorize(self, request: PaymentServiceAuthorizeRequest, metadata: dict, options: FfiOptions | None = ...) -> PaymentServiceAuthorizeResponse:
        """PaymentService.Authorize — Authorize a payment amount on a payment method. This reserves funds without capturing them, essential for verifying availability before finalizing."""
        ...

    def capture(self, request: PaymentServiceCaptureRequest, metadata: dict, options: FfiOptions | None = ...) -> PaymentServiceCaptureResponse:
        """PaymentService.Capture — Finalize an authorized payment transaction. Transfers reserved funds from customer to merchant account, completing the payment lifecycle."""
        ...

    def get(self, request: PaymentServiceGetRequest, metadata: dict, options: FfiOptions | None = ...) -> PaymentServiceGetResponse:
        """PaymentService.Get — Retrieve current payment status from the payment processor. Enables synchronization between your system and payment processors for accurate state tracking."""
        ...

    def refund(self, request: PaymentServiceRefundRequest, metadata: dict, options: FfiOptions | None = ...) -> RefundResponse:
        """PaymentService.Refund — Initiate a refund to customer's payment method. Returns funds for returns, cancellations, or service adjustments after original payment."""
        ...

    def reverse(self, request: PaymentServiceReverseRequest, metadata: dict, options: FfiOptions | None = ...) -> PaymentServiceReverseResponse:
        """PaymentService.Reverse — Reverse a captured payment before settlement. Recovers funds after capture but before bank settlement, used for corrections or cancellations."""
        ...

    def void(self, request: PaymentServiceVoidRequest, metadata: dict, options: FfiOptions | None = ...) -> PaymentServiceVoidResponse:
        """PaymentService.Void — Cancel an authorized payment before capture. Releases held funds back to customer, typically used when orders are cancelled or abandoned."""
        ...


class RecurringPaymentClient(_ConnectorClientBase):
    def charge(self, request: RecurringPaymentServiceChargeRequest, metadata: dict, options: FfiOptions | None = ...) -> RecurringPaymentServiceChargeResponse:
        """RecurringPaymentService.Charge — Charge using an existing stored recurring payment instruction. Processes repeat payments for subscriptions or recurring billing without collecting payment details."""
        ...


class CustomerClient(_ConnectorClientBase):
    def create(self, request: CustomerServiceCreateRequest, metadata: dict, options: FfiOptions | None = ...) -> CustomerServiceCreateResponse:
        """CustomerService.Create — Create customer record in the payment processor system. Stores customer details for future payment operations without re-sending personal information."""
        ...


class MerchantAuthenticationClient(_ConnectorClientBase):
    def create_access_token(self, request: MerchantAuthenticationServiceCreateAccessTokenRequest, metadata: dict, options: FfiOptions | None = ...) -> MerchantAuthenticationServiceCreateAccessTokenResponse:
        """MerchantAuthenticationService.CreateAccessToken — Generate short-lived connector authentication token. Provides secure credentials for connector API access without storing secrets client-side."""
        ...


