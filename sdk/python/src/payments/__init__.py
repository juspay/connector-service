# Hyperswitch Payments SDK
#
# Export structure:
#   - ConnectorClient (flat - high-level API)
#   - payments (namespace - request/response types, enums)
#   - payment_methods (namespace - payment method types)
#   - configs (namespace - configuration types)

from .connector_client import ConnectorClient

# Import from generated proto files
from .generated.payment_pb2 import (
    # Request types
    PaymentServiceAuthorizeRequest,
    PaymentServiceAuthorizeResponse,
    PaymentServiceCaptureRequest,
    PaymentServiceCaptureResponse,
    PaymentServiceVoidRequest,
    PaymentServiceVoidResponse,
    PaymentServiceRefundRequest,
    PaymentServiceReverseRequest,
    PaymentServiceGetRequest,
    PaymentServiceGetResponse,
    PaymentServiceCreateOrderRequest,
    PaymentServiceCreateOrderResponse,
    PaymentServiceSetupRecurringRequest,
    PaymentServiceSetupRecurringResponse,
    PaymentServiceIncrementalAuthorizationRequest,
    PaymentServiceIncrementalAuthorizationResponse,
    PaymentServiceVerifyRedirectResponseRequest,
    PaymentServiceVerifyRedirectResponseResponse,
    PaymentServiceDisputeRequest,
    # Authentication types
    PaymentMethodAuthenticationServicePreAuthenticateRequest,
    PaymentMethodAuthenticationServicePreAuthenticateResponse,
    PaymentMethodAuthenticationServiceAuthenticateRequest,
    PaymentMethodAuthenticationServiceAuthenticateResponse,
    # Tokenization
    PaymentMethodServiceTokenizeRequest,
    PaymentMethodServiceTokenizeResponse,
    # Access token types
    MerchantAuthenticationServiceCreateAccessTokenRequest,
    MerchantAuthenticationServiceCreateAccessTokenResponse,
    # Data types
    AccessToken,
    ConnectorState,
    Customer,
    PaymentAddress,
    Money,
    BrowserInformation,
    CustomerAcceptance,
    SessionToken,
    # Response types
    ConnectorResponseData,
    ErrorInfo,
    # Enums
    Currency,
    CaptureMethod,
    AuthenticationType,
    PaymentMethodType,
    PaymentStatus,
    RefundStatus,
    DisputeStatus,
    MandateStatus,
    AuthorizationStatus,
    OperationStatus,
    HttpMethod,
    FutureUsage,
    PaymentExperience,
    PaymentChannel,
    Connector,
    ProductType,
    DisputeStage,
    Tokenization,
    WebhookEventType,
    ThreeDsCompletionIndicator,
    TransactionStatus,
    ExemptionIndicator,
    MitCategory,
    SyncRequestType,
    AcceptanceType,
    CavvAlgorithm,
)

from .generated.payment_methods_pb2 import (
    PaymentMethod,
    CardNumberType,
    CardDetails,
)

from .generated.sdk_config_pb2 import (
    ClientConfig,
    RequestOptions,
    HttpConfig,
    HttpTimeoutConfig,
    CaCert,
    ProxyOptions,
    HttpDefault,
    Environment,
    FfiOptions,
    FfiConnectorHttpRequest,
    FfiConnectorHttpResponse,
)

from .http_client import HttpRequest, HttpResponse, ConnectorError, execute, create_client

class PaymentsNamespace:
    """Namespace for payment request/response types and enums."""
    PaymentServiceAuthorizeRequest = PaymentServiceAuthorizeRequest
    PaymentServiceAuthorizeResponse = PaymentServiceAuthorizeResponse
    PaymentServiceCaptureRequest = PaymentServiceCaptureRequest
    PaymentServiceCaptureResponse = PaymentServiceCaptureResponse
    PaymentServiceVoidRequest = PaymentServiceVoidRequest
    PaymentServiceVoidResponse = PaymentServiceVoidResponse
    PaymentServiceRefundRequest = PaymentServiceRefundRequest
    PaymentServiceReverseRequest = PaymentServiceReverseRequest
    PaymentServiceGetRequest = PaymentServiceGetRequest
    PaymentServiceGetResponse = PaymentServiceGetResponse
    PaymentServiceCreateOrderRequest = PaymentServiceCreateOrderRequest
    PaymentServiceCreateOrderResponse = PaymentServiceCreateOrderResponse
    PaymentServiceSetupRecurringRequest = PaymentServiceSetupRecurringRequest
    PaymentServiceSetupRecurringResponse = PaymentServiceSetupRecurringResponse
    PaymentServiceIncrementalAuthorizationRequest = PaymentServiceIncrementalAuthorizationRequest
    PaymentServiceIncrementalAuthorizationResponse = PaymentServiceIncrementalAuthorizationResponse
    PaymentServiceVerifyRedirectResponseRequest = PaymentServiceVerifyRedirectResponseRequest
    PaymentServiceVerifyRedirectResponseResponse = PaymentServiceVerifyRedirectResponseResponse
    PaymentServiceDisputeRequest = PaymentServiceDisputeRequest
    PaymentMethodAuthenticationServicePreAuthenticateRequest = PaymentMethodAuthenticationServicePreAuthenticateRequest
    PaymentMethodAuthenticationServicePreAuthenticateResponse = PaymentMethodAuthenticationServicePreAuthenticateResponse
    PaymentMethodAuthenticationServiceAuthenticateRequest = PaymentMethodAuthenticationServiceAuthenticateRequest
    PaymentMethodAuthenticationServiceAuthenticateResponse = PaymentMethodAuthenticationServiceAuthenticateResponse
    PaymentMethodServiceTokenizeRequest = PaymentMethodServiceTokenizeRequest
    PaymentMethodServiceTokenizeResponse = PaymentMethodServiceTokenizeResponse
    MerchantAuthenticationServiceCreateAccessTokenRequest = MerchantAuthenticationServiceCreateAccessTokenRequest
    MerchantAuthenticationServiceCreateAccessTokenResponse = MerchantAuthenticationServiceCreateAccessTokenResponse
    AccessToken = AccessToken
    ConnectorState = ConnectorState
    Customer = Customer
    PaymentAddress = PaymentAddress
    Money = Money
    BrowserInformation = BrowserInformation
    CustomerAcceptance = CustomerAcceptance
    SessionToken = SessionToken
    ConnectorResponseData = ConnectorResponseData
    ErrorInfo = ErrorInfo
    Currency = Currency
    CaptureMethod = CaptureMethod
    AuthenticationType = AuthenticationType
    PaymentMethodType = PaymentMethodType
    PaymentStatus = PaymentStatus
    RefundStatus = RefundStatus
    DisputeStatus = DisputeStatus
    MandateStatus = MandateStatus
    AuthorizationStatus = AuthorizationStatus
    OperationStatus = OperationStatus
    HttpMethod = HttpMethod
    FutureUsage = FutureUsage
    PaymentExperience = PaymentExperience
    PaymentChannel = PaymentChannel
    Connector = Connector
    ProductType = ProductType
    DisputeStage = DisputeStage
    Tokenization = Tokenization
    WebhookEventType = WebhookEventType
    ThreeDsCompletionIndicator = ThreeDsCompletionIndicator
    TransactionStatus = TransactionStatus
    ExemptionIndicator = ExemptionIndicator
    MitCategory = MitCategory
    SyncRequestType = SyncRequestType
    AcceptanceType = AcceptanceType
    CavvAlgorithm = CavvAlgorithm

class PaymentMethodsNamespace:
    """Namespace for payment method types."""
    PaymentMethod = PaymentMethod
    CardNumberType = CardNumberType
    CardDetails = CardDetails

class ConfigsNamespace:
    """Namespace for configuration types."""
    ClientConfig = ClientConfig
    RequestOptions = RequestOptions
    HttpConfig = HttpConfig
    HttpTimeoutConfig = HttpTimeoutConfig
    CaCert = CaCert
    ProxyOptions = ProxyOptions
    HttpDefault = HttpDefault
    Environment = Environment
    FfiOptions = FfiOptions
    FfiConnectorHttpRequest = FfiConnectorHttpRequest
    FfiConnectorHttpResponse = FfiConnectorHttpResponse

# Create namespace instances
payments = PaymentsNamespace()
payment_methods = PaymentMethodsNamespace()
configs = ConfigsNamespace()

# Re-export all from payment_pb2 for backward compatibility (e.g. USD, AUTOMATIC)
from .generated.payment_pb2 import *

# Explicitly define public API
__all__ = [
    "ConnectorClient",
    "HttpRequest",
    "HttpResponse",
    "ConnectorError",
    "execute",
    "create_client",
    "payments",
    "payment_methods",
    "configs",
]
