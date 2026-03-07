# AUTO-GENERATED — do not edit by hand.
# Source: services.proto ∩ bindings/uniffi.rs  |  Regenerate: make generate
#
# This stub exposes per-service client classes to static analysers
# (Pylance, pyright, mypy) so IDEs offer completions and type checking.
from payments.generated.sdk_config_pb2 import ClientIdentity, ConfigOptions
from payments.generated.payment_pb2 import (
    CustomerServiceCreateRequest,
    CustomerServiceCreateResponse,
    EventServiceHandleRequest,
    EventServiceHandleResponse,
    MerchantAuthenticationServiceCreateAccessTokenRequest,
    MerchantAuthenticationServiceCreateAccessTokenResponse,
    MerchantAuthenticationServiceCreateSessionTokenRequest,
    MerchantAuthenticationServiceCreateSessionTokenResponse,
    PaymentMethodAuthenticationServiceAuthenticateRequest,
    PaymentMethodAuthenticationServiceAuthenticateResponse,
    PaymentMethodAuthenticationServicePostAuthenticateRequest,
    PaymentMethodAuthenticationServicePostAuthenticateResponse,
    PaymentMethodAuthenticationServicePreAuthenticateRequest,
    PaymentMethodAuthenticationServicePreAuthenticateResponse,
    PaymentMethodServiceTokenizeRequest,
    PaymentMethodServiceTokenizeResponse,
    PaymentServiceAuthorizeRequest,
    PaymentServiceAuthorizeResponse,
    PaymentServiceCaptureRequest,
    PaymentServiceCaptureResponse,
    PaymentServiceCreateOrderRequest,
    PaymentServiceCreateOrderResponse,
    PaymentServiceGetRequest,
    PaymentServiceGetResponse,
    PaymentServiceRefundRequest,
    PaymentServiceReverseRequest,
    PaymentServiceReverseResponse,
    PaymentServiceSetupRecurringRequest,
    PaymentServiceSetupRecurringResponse,
    PaymentServiceVoidRequest,
    PaymentServiceVoidResponse,
    RecurringPaymentServiceChargeRequest,
    RecurringPaymentServiceChargeResponse,
    RefundResponse,
)

class _ConnectorClientBase:
    def __init__(self, identity: ClientIdentity, defaults: ConfigOptions | None = ..., lib_path: str | None = ...) -> None: ...

class CustomerClient(_ConnectorClientBase):
    def create(self, request: CustomerServiceCreateRequest, metadata: dict, options: ConfigOptions | None = ...) -> CustomerServiceCreateResponse:
        """CustomerService.Create — Create customer record in the payment processor system. Stores customer details for future payment operations without re-sending personal information."""
        ...


class EventClient(_ConnectorClientBase):
    def handle_event(self, request: EventServiceHandleRequest, metadata: dict, options: ConfigOptions | None = ...) -> EventServiceHandleResponse:
        """EventService.HandleEvent — Process webhook notifications from connectors. Translates connector events into standardized responses for asynchronous payment state updates."""
        ...


class MerchantAuthenticationClient(_ConnectorClientBase):
    def create_access_token(self, request: MerchantAuthenticationServiceCreateAccessTokenRequest, metadata: dict, options: ConfigOptions | None = ...) -> MerchantAuthenticationServiceCreateAccessTokenResponse:
        """MerchantAuthenticationService.CreateAccessToken — Generate short-lived connector authentication token. Provides secure credentials for connector API access without storing secrets client-side."""
        ...

    def create_session_token(self, request: MerchantAuthenticationServiceCreateSessionTokenRequest, metadata: dict, options: ConfigOptions | None = ...) -> MerchantAuthenticationServiceCreateSessionTokenResponse:
        """MerchantAuthenticationService.CreateSessionToken — Create session token for payment processing. Maintains session state across multiple payment operations for improved security and tracking."""
        ...


class PaymentMethodAuthenticationClient(_ConnectorClientBase):
    def authenticate(self, request: PaymentMethodAuthenticationServiceAuthenticateRequest, metadata: dict, options: ConfigOptions | None = ...) -> PaymentMethodAuthenticationServiceAuthenticateResponse:
        """PaymentMethodAuthenticationService.Authenticate — Execute 3DS challenge or frictionless verification. Authenticates customer via bank challenge or behind-the-scenes verification for fraud prevention."""
        ...

    def post_authenticate(self, request: PaymentMethodAuthenticationServicePostAuthenticateRequest, metadata: dict, options: ConfigOptions | None = ...) -> PaymentMethodAuthenticationServicePostAuthenticateResponse:
        """PaymentMethodAuthenticationService.PostAuthenticate — Validate authentication results with the issuing bank. Processes bank's authentication decision to determine if payment can proceed."""
        ...

    def pre_authenticate(self, request: PaymentMethodAuthenticationServicePreAuthenticateRequest, metadata: dict, options: ConfigOptions | None = ...) -> PaymentMethodAuthenticationServicePreAuthenticateResponse:
        """PaymentMethodAuthenticationService.PreAuthenticate — Initiate 3DS flow before payment authorization. Collects device data and prepares authentication context for frictionless or challenge-based verification."""
        ...


class PaymentMethodClient(_ConnectorClientBase):
    def tokenize(self, request: PaymentMethodServiceTokenizeRequest, metadata: dict, options: ConfigOptions | None = ...) -> PaymentMethodServiceTokenizeResponse:
        """PaymentMethodService.Tokenize — Tokenize payment method for secure storage. Replaces raw card details with secure token for one-click payments and recurring billing."""
        ...


class PaymentClient(_ConnectorClientBase):
    def authorize(self, request: PaymentServiceAuthorizeRequest, metadata: dict, options: ConfigOptions | None = ...) -> PaymentServiceAuthorizeResponse:
        """PaymentService.Authorize — Authorize a payment amount on a payment method. This reserves funds without capturing them, essential for verifying availability before finalizing."""
        ...

    def capture(self, request: PaymentServiceCaptureRequest, metadata: dict, options: ConfigOptions | None = ...) -> PaymentServiceCaptureResponse:
        """PaymentService.Capture — Finalize an authorized payment transaction. Transfers reserved funds from customer to merchant account, completing the payment lifecycle."""
        ...

    def create_order(self, request: PaymentServiceCreateOrderRequest, metadata: dict, options: ConfigOptions | None = ...) -> PaymentServiceCreateOrderResponse:
        """PaymentService.CreateOrder — Initialize an order in the payment processor system. Sets up payment context before customer enters card details for improved authorization rates."""
        ...

    def get(self, request: PaymentServiceGetRequest, metadata: dict, options: ConfigOptions | None = ...) -> PaymentServiceGetResponse:
        """PaymentService.Get — Retrieve current payment status from the payment processor. Enables synchronization between your system and payment processors for accurate state tracking."""
        ...

    def refund(self, request: PaymentServiceRefundRequest, metadata: dict, options: ConfigOptions | None = ...) -> RefundResponse:
        """PaymentService.Refund — Initiate a refund to customer's payment method. Returns funds for returns, cancellations, or service adjustments after original payment."""
        ...

    def reverse(self, request: PaymentServiceReverseRequest, metadata: dict, options: ConfigOptions | None = ...) -> PaymentServiceReverseResponse:
        """PaymentService.Reverse — Reverse a captured payment before settlement. Recovers funds after capture but before bank settlement, used for corrections or cancellations."""
        ...

    def setup_recurring(self, request: PaymentServiceSetupRecurringRequest, metadata: dict, options: ConfigOptions | None = ...) -> PaymentServiceSetupRecurringResponse:
        """PaymentService.SetupRecurring — Setup a recurring payment instruction for future payments/ debits. This could be for SaaS subscriptions, monthly bill payments, insurance payments and similar use cases."""
        ...

    def void(self, request: PaymentServiceVoidRequest, metadata: dict, options: ConfigOptions | None = ...) -> PaymentServiceVoidResponse:
        """PaymentService.Void — Cancel an authorized payment before capture. Releases held funds back to customer, typically used when orders are cancelled or abandoned."""
        ...


class RecurringPaymentClient(_ConnectorClientBase):
    def charge(self, request: RecurringPaymentServiceChargeRequest, metadata: dict, options: ConfigOptions | None = ...) -> RecurringPaymentServiceChargeResponse:
        """RecurringPaymentService.Charge — Charge using an existing stored recurring payment instruction. Processes repeat payments for subscriptions or recurring billing without collecting payment details."""
        ...


