# Hyperswitch Payments SDK
#
# Export structure:
#   - PaymentClient, MerchantAuthenticationClient (per-service high-level API)
#   - payments (namespace - request/response types, enums)
#   - payment_methods (namespace - payment method types)
#   - configs (namespace - configuration types)

from payments._generated_service_clients import PaymentClient, MerchantAuthenticationClient

# Import from generated proto files
from payments.generated.payment_pb2 import (
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
    # Data types
    Customer,
    PaymentAddress,
    Money,
    BrowserInformation,
    CustomerAcceptance,
    SessionToken,
    # Response types
    ConnectorResponseData,
    CardConnectorResponse,
    ErrorInfo,
)

from payments.generated.payment_methods_pb2 import (
    PaymentMethod,
    CardNumberType,
    CardDetails,
)

from payments.generated.sdk_config_pb2 import (
    ConnectorConfig,
    RequestConfig,
    Environment,
    FfiOptions,
    FfiConnectorHttpRequest,
    FfiConnectorHttpResponse,
    RequestError,
    ResponseError,
)

# Import enums from payment_pb2
from payments.generated.payment_pb2 import (
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

# Import FFI functions
from payments.generated.connector_service_ffi import (
    authorize_req_transformer,
    authorize_res_transformer,
)

# Create namespace objects (matching JavaScript SDK structure)
# These provide organized access to types

class PaymentsNamespace:
    """Namespace for payment request/response types and enums."""

    # Request types
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

    # Data types
    Customer = Customer
    PaymentAddress = PaymentAddress
    Money = Money
    BrowserInformation = BrowserInformation
    CustomerAcceptance = CustomerAcceptance
    SessionToken = SessionToken

    # Response types
    ConnectorResponseData = ConnectorResponseData
    CardConnectorResponse = CardConnectorResponse
    ErrorInfo = ErrorInfo

    # Enums
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

    ConnectorConfig = ConnectorConfig
    RequestConfig = RequestConfig
    Environment = Environment
    FfiOptions = FfiOptions
    FfiConnectorHttpRequest = FfiConnectorHttpRequest
    FfiConnectorHttpResponse = FfiConnectorHttpResponse
    # Error types returned via RuntimeError.ffi_error on FFI failures
    RequestError = RequestError
    ResponseError = ResponseError


# Create namespace instances
payments = PaymentsNamespace()
payment_methods = PaymentMethodsNamespace()
configs = ConfigsNamespace()

# Legacy exports (to be deprecated)
from payments.generated.payment_pb2 import *
from payments.generated.sdk_config_pb2 import *
from payments.generated.connector_service_ffi import *
