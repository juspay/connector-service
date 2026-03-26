# AUTO-GENERATED — do not edit by hand.
# Source: services.proto ∩ bindings/uniffi.rs  |  Regenerate: make generate
#
# This stub exposes per-service client classes to static analysers
# (Pylance, pyright, mypy) so IDEs offer completions and type checking.
from payments.generated.sdk_config_pb2 import ConnectorConfig, RequestConfig
from payments.generated.payment_pb2 import (
    CustomerServiceCreateRequest,
    CustomerServiceCreateResponse,
    DisputeServiceAcceptRequest,
    DisputeServiceAcceptResponse,
    DisputeServiceDefendRequest,
    DisputeServiceDefendResponse,
    DisputeServiceSubmitEvidenceRequest,
    DisputeServiceSubmitEvidenceResponse,
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
    PayoutServiceCreateRequest,
    PayoutServiceCreateResponse,
    ProxyPaymentMethodAuthenticationServiceAuthenticateRequest,
    ProxyPaymentMethodAuthenticationServicePostAuthenticateRequest,
    ProxyPaymentMethodAuthenticationServicePreAuthenticateRequest,
    ProxyPaymentServiceAuthorizeRequest,
    ProxyPaymentServiceSetupRecurringRequest,
    RecurringPaymentServiceChargeRequest,
    RecurringPaymentServiceChargeResponse,
    RefundResponse,
    TokenizedPaymentServiceAuthorizeRequest,
    TokenizedPaymentServiceSetupRecurringRequest,
)

class _ConnectorClientBase:
    def __init__(self, config: ConnectorConfig, defaults: RequestConfig | None = ..., lib_path: str | None = ...) -> None: ...

class CustomerClient(_ConnectorClientBase):
    def create(self, request: CustomerServiceCreateRequest, options: RequestConfig | None = ...) -> CustomerServiceCreateResponse:
        """CustomerService.Create — Create customer record in the payment processor system. Stores customer details for future payment operations without re-sending personal information."""
        ...


class DirectPaymentClient(_ConnectorClientBase):
    def authorize(self, request: PaymentServiceAuthorizeRequest, options: RequestConfig | None = ...) -> PaymentServiceAuthorizeResponse:
        """DirectPaymentService.Authorize — Authorize a payment amount on a payment method. This reserves funds without capturing them, essential for verifying availability before finalizing."""
        ...

    def capture(self, request: PaymentServiceCaptureRequest, options: RequestConfig | None = ...) -> PaymentServiceCaptureResponse:
        """DirectPaymentService.Capture — Finalize an authorized payment by transferring funds. Captures the authorized amount to complete the transaction and move funds to your merchant account."""
        ...

    def create_order(self, request: PaymentServiceCreateOrderRequest, options: RequestConfig | None = ...) -> PaymentServiceCreateOrderResponse:
        """DirectPaymentService.CreateOrder — Create a payment order for later processing. Establishes a transaction context that can be authorized or captured in subsequent API calls."""
        ...

    def get(self, request: PaymentServiceGetRequest, options: RequestConfig | None = ...) -> PaymentServiceGetResponse:
        """DirectPaymentService.Get — Retrieve current payment status from the payment processor. Enables synchronization between your system and payment processors for accurate state tracking."""
        ...

    def refund(self, request: PaymentServiceRefundRequest, options: RequestConfig | None = ...) -> RefundResponse:
        """DirectPaymentService.Refund — Process a partial or full refund for a captured payment. Returns funds to the customer when goods are returned or services are cancelled."""
        ...

    def reverse(self, request: PaymentServiceReverseRequest, options: RequestConfig | None = ...) -> PaymentServiceReverseResponse:
        """DirectPaymentService.Reverse — Reverse a captured payment in full. Initiates a complete refund when you need to cancel a settled transaction rather than just an authorization."""
        ...

    def setup_recurring(self, request: PaymentServiceSetupRecurringRequest, options: RequestConfig | None = ...) -> PaymentServiceSetupRecurringResponse:
        """DirectPaymentService.SetupRecurring — Configure a payment method for recurring billing. Sets up the mandate and payment details needed for future automated charges."""
        ...

    def void(self, request: PaymentServiceVoidRequest, options: RequestConfig | None = ...) -> PaymentServiceVoidResponse:
        """DirectPaymentService.Void — Cancel an authorized payment that has not been captured. Releases held funds back to the customer's payment method when a transaction cannot be completed."""
        ...


class DisputeClient(_ConnectorClientBase):
    def accept(self, request: DisputeServiceAcceptRequest, options: RequestConfig | None = ...) -> DisputeServiceAcceptResponse:
        """DisputeService.Accept — Concede dispute and accepts chargeback loss. Acknowledges liability and stops dispute defense process when evidence is insufficient."""
        ...

    def defend(self, request: DisputeServiceDefendRequest, options: RequestConfig | None = ...) -> DisputeServiceDefendResponse:
        """DisputeService.Defend — Submit defense with reason code for dispute. Presents formal argument against customer's chargeback claim with supporting documentation."""
        ...

    def submit_evidence(self, request: DisputeServiceSubmitEvidenceRequest, options: RequestConfig | None = ...) -> DisputeServiceSubmitEvidenceResponse:
        """DisputeService.SubmitEvidence — Upload evidence to dispute customer chargeback. Provides documentation like receipts and delivery proof to contest fraudulent transaction claims."""
        ...


class EventClient(_ConnectorClientBase):
    def handle_event(self, request: EventServiceHandleRequest, options: RequestConfig | None = ...) -> EventServiceHandleResponse:
        """EventService.HandleEvent — Process webhook notifications from connectors. Translates connector events into standardized responses for asynchronous payment state updates."""
        ...


class MerchantAuthenticationClient(_ConnectorClientBase):
    def create_access_token(self, request: MerchantAuthenticationServiceCreateAccessTokenRequest, options: RequestConfig | None = ...) -> MerchantAuthenticationServiceCreateAccessTokenResponse:
        """MerchantAuthenticationService.CreateAccessToken — Generate short-lived connector authentication token. Provides secure credentials for connector API access without storing secrets client-side."""
        ...

    def create_session_token(self, request: MerchantAuthenticationServiceCreateSessionTokenRequest, options: RequestConfig | None = ...) -> MerchantAuthenticationServiceCreateSessionTokenResponse:
        """MerchantAuthenticationService.CreateSessionToken — Create session token for payment processing. Maintains session state across multiple payment operations for improved security and tracking."""
        ...


class PaymentMethodAuthenticationClient(_ConnectorClientBase):
    def authenticate(self, request: PaymentMethodAuthenticationServiceAuthenticateRequest, options: RequestConfig | None = ...) -> PaymentMethodAuthenticationServiceAuthenticateResponse:
        """PaymentMethodAuthenticationService.Authenticate — Execute 3DS challenge or frictionless verification. Authenticates customer via bank challenge or behind-the-scenes verification for fraud prevention."""
        ...

    def post_authenticate(self, request: PaymentMethodAuthenticationServicePostAuthenticateRequest, options: RequestConfig | None = ...) -> PaymentMethodAuthenticationServicePostAuthenticateResponse:
        """PaymentMethodAuthenticationService.PostAuthenticate — Validate authentication results with the issuing bank. Processes bank's authentication decision to determine if payment can proceed."""
        ...

    def pre_authenticate(self, request: PaymentMethodAuthenticationServicePreAuthenticateRequest, options: RequestConfig | None = ...) -> PaymentMethodAuthenticationServicePreAuthenticateResponse:
        """PaymentMethodAuthenticationService.PreAuthenticate — Initiate 3DS flow before payment authorization. Collects device data and prepares authentication context for frictionless or challenge-based verification."""
        ...


class PaymentMethodClient(_ConnectorClientBase):
    def tokenize(self, request: PaymentMethodServiceTokenizeRequest, options: RequestConfig | None = ...) -> PaymentMethodServiceTokenizeResponse:
        """PaymentMethodService.Tokenize — Tokenize payment method for secure storage. Replaces raw card details with secure token for one-click payments and recurring billing."""
        ...


class PayoutClient(_ConnectorClientBase):
    def payout_create(self, request: PayoutServiceCreateRequest, options: RequestConfig | None = ...) -> PayoutServiceCreateResponse:
        """PayoutService.Create — Creates a payout."""
        ...


class ProxiedPaymentClient(_ConnectorClientBase):
    def proxied_authenticate(self, request: ProxyPaymentMethodAuthenticationServiceAuthenticateRequest, options: RequestConfig | None = ...) -> PaymentMethodAuthenticationServiceAuthenticateResponse:
        """ProxiedPaymentService.Authenticate — Execute 3DS challenge/frictionless step via vault proxy."""
        ...

    def proxied_authorize(self, request: ProxyPaymentServiceAuthorizeRequest, options: RequestConfig | None = ...) -> PaymentServiceAuthorizeResponse:
        """ProxiedPaymentService.Authorize — Authorize using vault-aliased card data. Proxy substitutes before connector."""
        ...

    def proxied_post_authenticate(self, request: ProxyPaymentMethodAuthenticationServicePostAuthenticateRequest, options: RequestConfig | None = ...) -> PaymentMethodAuthenticationServicePostAuthenticateResponse:
        """ProxiedPaymentService.PostAuthenticate — Post-authenticate via vault proxy."""
        ...

    def proxied_pre_authenticate(self, request: ProxyPaymentMethodAuthenticationServicePreAuthenticateRequest, options: RequestConfig | None = ...) -> PaymentMethodAuthenticationServicePreAuthenticateResponse:
        """ProxiedPaymentService.PreAuthenticate — Start 3DS pre-auth. Proxy substitutes aliases before forwarding to 3DS server."""
        ...

    def proxied_setup_recurring(self, request: ProxyPaymentServiceSetupRecurringRequest, options: RequestConfig | None = ...) -> PaymentServiceSetupRecurringResponse:
        """ProxiedPaymentService.SetupRecurring — Setup recurring mandate using vault-aliased card data."""
        ...


class RecurringPaymentClient(_ConnectorClientBase):
    def charge(self, request: RecurringPaymentServiceChargeRequest, options: RequestConfig | None = ...) -> RecurringPaymentServiceChargeResponse:
        """RecurringPaymentService.Charge — Charge using an existing stored recurring payment instruction. Processes repeat payments for subscriptions or recurring billing without collecting payment details."""
        ...


class TokenizedPaymentClient(_ConnectorClientBase):
    def tokenized_authorize(self, request: TokenizedPaymentServiceAuthorizeRequest, options: RequestConfig | None = ...) -> PaymentServiceAuthorizeResponse:
        """TokenizedPaymentService.Authorize — Authorize using a connector-issued payment method token."""
        ...

    def tokenized_setup_recurring(self, request: TokenizedPaymentServiceSetupRecurringRequest, options: RequestConfig | None = ...) -> PaymentServiceSetupRecurringResponse:
        """TokenizedPaymentService.SetupRecurring — Setup a recurring mandate using a connector token."""
        ...
