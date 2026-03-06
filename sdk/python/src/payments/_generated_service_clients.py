# AUTO-GENERATED — do not edit by hand.
# Source: services.proto ∩ bindings/uniffi.rs  |  Regenerate: make generate

from payments.connector_client import _ConnectorClientBase
import payments.generated.payment_pb2 as _pb2

class PaymentClient(_ConnectorClientBase):
    """PaymentService flows"""

    def authorize(self, request, metadata: dict, options=None):
        """PaymentService.Authorize — Authorize a payment amount on a payment method. This reserves funds without capturing them, essential for verifying availability before finalizing."""
        return self._execute_flow("authorize", request, metadata, _pb2.PaymentServiceAuthorizeResponse, options)

    def capture(self, request, metadata: dict, options=None):
        """PaymentService.Capture — Finalize an authorized payment transaction. Transfers reserved funds from customer to merchant account, completing the payment lifecycle."""
        return self._execute_flow("capture", request, metadata, _pb2.PaymentServiceCaptureResponse, options)

    def get(self, request, metadata: dict, options=None):
        """PaymentService.Get — Retrieve current payment status from the payment processor. Enables synchronization between your system and payment processors for accurate state tracking."""
        return self._execute_flow("get", request, metadata, _pb2.PaymentServiceGetResponse, options)

    def refund(self, request, metadata: dict, options=None):
        """PaymentService.Refund — Initiate a refund to customer's payment method. Returns funds for returns, cancellations, or service adjustments after original payment."""
        return self._execute_flow("refund", request, metadata, _pb2.RefundResponse, options)

    def reverse(self, request, metadata: dict, options=None):
        """PaymentService.Reverse — Reverse a captured payment before settlement. Recovers funds after capture but before bank settlement, used for corrections or cancellations."""
        return self._execute_flow("reverse", request, metadata, _pb2.PaymentServiceReverseResponse, options)

    def void(self, request, metadata: dict, options=None):
        """PaymentService.Void — Cancel an authorized payment before capture. Releases held funds back to customer, typically used when orders are cancelled or abandoned."""
        return self._execute_flow("void", request, metadata, _pb2.PaymentServiceVoidResponse, options)

class RecurringPaymentClient(_ConnectorClientBase):
    """RecurringPaymentService flows"""

    def charge(self, request, metadata: dict, options=None):
        """RecurringPaymentService.Charge — Charge using an existing stored recurring payment instruction. Processes repeat payments for subscriptions or recurring billing without collecting payment details."""
        return self._execute_flow("charge", request, metadata, _pb2.RecurringPaymentServiceChargeResponse, options)

class CustomerClient(_ConnectorClientBase):
    """CustomerService flows"""

    def create(self, request, metadata: dict, options=None):
        """CustomerService.Create — Create customer record in the payment processor system. Stores customer details for future payment operations without re-sending personal information."""
        return self._execute_flow("create", request, metadata, _pb2.CustomerServiceCreateResponse, options)

class MerchantAuthenticationClient(_ConnectorClientBase):
    """MerchantAuthenticationService flows"""

    def create_access_token(self, request, metadata: dict, options=None):
        """MerchantAuthenticationService.CreateAccessToken — Generate short-lived connector authentication token. Provides secure credentials for connector API access without storing secrets client-side."""
        return self._execute_flow("create_access_token", request, metadata, _pb2.MerchantAuthenticationServiceCreateAccessTokenResponse, options)

