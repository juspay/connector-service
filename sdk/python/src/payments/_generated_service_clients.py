# AUTO-GENERATED — do not edit by hand.
# Source: services.proto ∩ bindings/uniffi.rs  |  Regenerate: make generate

from payments.connector_client import _ConnectorClientBase
import payments.generated.payment_pb2 as _pb2

class CustomerClient(_ConnectorClientBase):
    """CustomerService flows"""

    def create(self, request, metadata: dict, options=None):
        """CustomerService.Create — Create customer record in the payment processor system. Stores customer details for future payment operations without re-sending personal information."""
        return self._execute_flow("create", request, metadata, _pb2.CustomerServiceCreateResponse, options)

class EventClient(_ConnectorClientBase):
    """EventService flows"""

    def handle_event(self, request, metadata: dict, options=None):
        """EventService.HandleEvent — Process webhook notifications from connectors. Translates connector events into standardized responses for asynchronous payment state updates."""
        return self._execute_direct("handle_event", request, metadata, _pb2.EventServiceHandleResponse, options)

class MerchantAuthenticationClient(_ConnectorClientBase):
    """MerchantAuthenticationService flows"""

    def create_access_token(self, request, metadata: dict, options=None):
        """MerchantAuthenticationService.CreateAccessToken — Generate short-lived connector authentication token. Provides secure credentials for connector API access without storing secrets client-side."""
        return self._execute_flow("create_access_token", request, metadata, _pb2.MerchantAuthenticationServiceCreateAccessTokenResponse, options)

    def create_session_token(self, request, metadata: dict, options=None):
        """MerchantAuthenticationService.CreateSessionToken — Create session token for payment processing. Maintains session state across multiple payment operations for improved security and tracking."""
        return self._execute_flow("create_session_token", request, metadata, _pb2.MerchantAuthenticationServiceCreateSessionTokenResponse, options)

class PaymentMethodAuthenticationClient(_ConnectorClientBase):
    """PaymentMethodAuthenticationService flows"""

    def authenticate(self, request, metadata: dict, options=None):
        """PaymentMethodAuthenticationService.Authenticate — Execute 3DS challenge or frictionless verification. Authenticates customer via bank challenge or behind-the-scenes verification for fraud prevention."""
        return self._execute_flow("authenticate", request, metadata, _pb2.PaymentMethodAuthenticationServiceAuthenticateResponse, options)

    def post_authenticate(self, request, metadata: dict, options=None):
        """PaymentMethodAuthenticationService.PostAuthenticate — Validate authentication results with the issuing bank. Processes bank's authentication decision to determine if payment can proceed."""
        return self._execute_flow("post_authenticate", request, metadata, _pb2.PaymentMethodAuthenticationServicePostAuthenticateResponse, options)

    def pre_authenticate(self, request, metadata: dict, options=None):
        """PaymentMethodAuthenticationService.PreAuthenticate — Initiate 3DS flow before payment authorization. Collects device data and prepares authentication context for frictionless or challenge-based verification."""
        return self._execute_flow("pre_authenticate", request, metadata, _pb2.PaymentMethodAuthenticationServicePreAuthenticateResponse, options)

class PaymentMethodClient(_ConnectorClientBase):
    """PaymentMethodService flows"""

    def tokenize(self, request, metadata: dict, options=None):
        """PaymentMethodService.Tokenize — Tokenize payment method for secure storage. Replaces raw card details with secure token for one-click payments and recurring billing."""
        return self._execute_flow("tokenize", request, metadata, _pb2.PaymentMethodServiceTokenizeResponse, options)

class PaymentClient(_ConnectorClientBase):
    """PaymentService flows"""

    def authorize(self, request, metadata: dict, options=None):
        """PaymentService.Authorize — Authorize a payment amount on a payment method. This reserves funds without capturing them, essential for verifying availability before finalizing."""
        return self._execute_flow("authorize", request, metadata, _pb2.PaymentServiceAuthorizeResponse, options)

    def capture(self, request, metadata: dict, options=None):
        """PaymentService.Capture — Finalize an authorized payment transaction. Transfers reserved funds from customer to merchant account, completing the payment lifecycle."""
        return self._execute_flow("capture", request, metadata, _pb2.PaymentServiceCaptureResponse, options)

    def create_order(self, request, metadata: dict, options=None):
        """PaymentService.CreateOrder — Initialize an order in the payment processor system. Sets up payment context before customer enters card details for improved authorization rates."""
        return self._execute_flow("create_order", request, metadata, _pb2.PaymentServiceCreateOrderResponse, options)

    def get(self, request, metadata: dict, options=None):
        """PaymentService.Get — Retrieve current payment status from the payment processor. Enables synchronization between your system and payment processors for accurate state tracking."""
        return self._execute_flow("get", request, metadata, _pb2.PaymentServiceGetResponse, options)

    def refund(self, request, metadata: dict, options=None):
        """PaymentService.Refund — Initiate a refund to customer's payment method. Returns funds for returns, cancellations, or service adjustments after original payment."""
        return self._execute_flow("refund", request, metadata, _pb2.RefundResponse, options)

    def reverse(self, request, metadata: dict, options=None):
        """PaymentService.Reverse — Reverse a captured payment before settlement. Recovers funds after capture but before bank settlement, used for corrections or cancellations."""
        return self._execute_flow("reverse", request, metadata, _pb2.PaymentServiceReverseResponse, options)

    def setup_recurring(self, request, metadata: dict, options=None):
        """PaymentService.SetupRecurring — Setup a recurring payment instruction for future payments/ debits. This could be for SaaS subscriptions, monthly bill payments, insurance payments and similar use cases."""
        return self._execute_flow("setup_recurring", request, metadata, _pb2.PaymentServiceSetupRecurringResponse, options)

    def void(self, request, metadata: dict, options=None):
        """PaymentService.Void — Cancel an authorized payment before capture. Releases held funds back to customer, typically used when orders are cancelled or abandoned."""
        return self._execute_flow("void", request, metadata, _pb2.PaymentServiceVoidResponse, options)

class RecurringPaymentClient(_ConnectorClientBase):
    """RecurringPaymentService flows"""

    def charge(self, request, metadata: dict, options=None):
        """RecurringPaymentService.Charge — Charge using an existing stored recurring payment instruction. Processes repeat payments for subscriptions or recurring billing without collecting payment details."""
        return self._execute_flow("charge", request, metadata, _pb2.RecurringPaymentServiceChargeResponse, options)

