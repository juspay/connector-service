/**
 * Re-exports for payment request/response types and enums.
 *
 * Usage:
 *   import payments.PaymentServiceAuthorizeRequest
 *   import payments.Currency
 *
 * Mirrors the JavaScript `payments` namespace and Python `PaymentsNamespace`.
 */
@file:Suppress("unused")

package payments

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------
typealias PaymentServiceAuthorizeRequest = ucs.v2.Payment.PaymentServiceAuthorizeRequest
typealias PaymentServiceAuthorizeResponse = ucs.v2.Payment.PaymentServiceAuthorizeResponse
typealias PaymentServiceCaptureRequest = ucs.v2.Payment.PaymentServiceCaptureRequest
typealias PaymentServiceCaptureResponse = ucs.v2.Payment.PaymentServiceCaptureResponse
typealias PaymentServiceVoidRequest = ucs.v2.Payment.PaymentServiceVoidRequest
typealias PaymentServiceVoidResponse = ucs.v2.Payment.PaymentServiceVoidResponse
typealias PaymentServiceRefundRequest = ucs.v2.Payment.PaymentServiceRefundRequest
typealias RefundResponse = ucs.v2.Payment.RefundResponse
typealias PaymentServiceReverseRequest = ucs.v2.Payment.PaymentServiceReverseRequest
typealias PaymentServiceReverseResponse = ucs.v2.Payment.PaymentServiceReverseResponse
typealias PaymentServiceGetRequest = ucs.v2.Payment.PaymentServiceGetRequest
typealias PaymentServiceGetResponse = ucs.v2.Payment.PaymentServiceGetResponse
typealias PaymentServiceCreateOrderRequest = ucs.v2.Payment.PaymentServiceCreateOrderRequest
typealias PaymentServiceCreateOrderResponse = ucs.v2.Payment.PaymentServiceCreateOrderResponse
typealias PaymentServiceSetupRecurringRequest = ucs.v2.Payment.PaymentServiceSetupRecurringRequest
typealias PaymentServiceSetupRecurringResponse = ucs.v2.Payment.PaymentServiceSetupRecurringResponse
typealias PaymentServiceIncrementalAuthorizationRequest = ucs.v2.Payment.PaymentServiceIncrementalAuthorizationRequest
typealias PaymentServiceIncrementalAuthorizationResponse = ucs.v2.Payment.PaymentServiceIncrementalAuthorizationResponse
typealias PaymentServiceVerifyRedirectResponseRequest = ucs.v2.Payment.PaymentServiceVerifyRedirectResponseRequest
typealias PaymentServiceVerifyRedirectResponseResponse = ucs.v2.Payment.PaymentServiceVerifyRedirectResponseResponse
typealias PaymentServiceDisputeRequest = ucs.v2.Payment.PaymentServiceDisputeRequest
typealias DisputeResponse = ucs.v2.Payment.DisputeResponse

// Authentication service
typealias MerchantAuthenticationServiceCreateAccessTokenRequest = ucs.v2.Payment.MerchantAuthenticationServiceCreateAccessTokenRequest
typealias MerchantAuthenticationServiceCreateAccessTokenResponse = ucs.v2.Payment.MerchantAuthenticationServiceCreateAccessTokenResponse
typealias MerchantAuthenticationServiceCreateSessionTokenRequest = ucs.v2.Payment.MerchantAuthenticationServiceCreateSessionTokenRequest
typealias MerchantAuthenticationServiceCreateSessionTokenResponse = ucs.v2.Payment.MerchantAuthenticationServiceCreateSessionTokenResponse
typealias MerchantAuthenticationServiceCreateSdkSessionTokenRequest = ucs.v2.Payment.MerchantAuthenticationServiceCreateSdkSessionTokenRequest
typealias MerchantAuthenticationServiceCreateSdkSessionTokenResponse = ucs.v2.Payment.MerchantAuthenticationServiceCreateSdkSessionTokenResponse

// Payment method authentication
typealias PaymentMethodAuthenticationServicePreAuthenticateRequest = ucs.v2.Payment.PaymentMethodAuthenticationServicePreAuthenticateRequest
typealias PaymentMethodAuthenticationServicePreAuthenticateResponse = ucs.v2.Payment.PaymentMethodAuthenticationServicePreAuthenticateResponse
typealias PaymentMethodAuthenticationServiceAuthenticateRequest = ucs.v2.Payment.PaymentMethodAuthenticationServiceAuthenticateRequest
typealias PaymentMethodAuthenticationServiceAuthenticateResponse = ucs.v2.Payment.PaymentMethodAuthenticationServiceAuthenticateResponse

// Tokenization
typealias PaymentMethodServiceTokenizeRequest = ucs.v2.Payment.PaymentMethodServiceTokenizeRequest
typealias PaymentMethodServiceTokenizeResponse = ucs.v2.Payment.PaymentMethodServiceTokenizeResponse

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------
typealias Money = ucs.v2.Payment.Money
typealias ErrorInfo = ucs.v2.Payment.ErrorInfo
typealias Customer = ucs.v2.Payment.Customer
typealias PaymentAddress = ucs.v2.Payment.PaymentAddress
typealias Address = ucs.v2.Payment.Address
typealias Identifier = ucs.v2.Payment.Identifier
typealias ConnectorState = ucs.v2.Payment.ConnectorState
typealias AccessToken = ucs.v2.Payment.AccessToken
typealias SecretString = ucs.v2.PaymentMethods.SecretString
typealias BrowserInformation = ucs.v2.Payment.BrowserInformation
typealias CustomerAcceptance = ucs.v2.Payment.CustomerAcceptance
typealias SessionToken = ucs.v2.Payment.SessionToken
typealias ConnectorResponseData = ucs.v2.Payment.ConnectorResponseData
typealias CardConnectorResponse = ucs.v2.Payment.CardConnectorResponse
typealias AuthenticationData = ucs.v2.Payment.AuthenticationData
typealias Metadata = ucs.v2.Payment.Metadata
typealias ConnectorAuth = ucs.v2.Payment.ConnectorAuth

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------
typealias Currency = ucs.v2.Payment.Currency
typealias CaptureMethod = ucs.v2.Payment.CaptureMethod
typealias AuthenticationType = ucs.v2.Payment.AuthenticationType
typealias PaymentMethodType = ucs.v2.Payment.PaymentMethodType
typealias PaymentStatus = ucs.v2.Payment.PaymentStatus
typealias RefundStatus = ucs.v2.Payment.RefundStatus
typealias DisputeStatus = ucs.v2.Payment.DisputeStatus
typealias MandateStatus = ucs.v2.Payment.MandateStatus
typealias AuthorizationStatus = ucs.v2.Payment.AuthorizationStatus
typealias OperationStatus = ucs.v2.Payment.OperationStatus
typealias HttpMethod = ucs.v2.Payment.HttpMethod
typealias FutureUsage = ucs.v2.Payment.FutureUsage
typealias PaymentExperience = ucs.v2.Payment.PaymentExperience
typealias PaymentChannel = ucs.v2.Payment.PaymentChannel
typealias Connector = ucs.v2.Payment.Connector
typealias ProductType = ucs.v2.Payment.ProductType
typealias DisputeStage = ucs.v2.Payment.DisputeStage
typealias Tokenization = ucs.v2.Payment.Tokenization
typealias WebhookEventType = ucs.v2.Payment.WebhookEventType
typealias ThreeDsCompletionIndicator = ucs.v2.Payment.ThreeDsCompletionIndicator
typealias TransactionStatus = ucs.v2.Payment.TransactionStatus
typealias ExemptionIndicator = ucs.v2.Payment.ExemptionIndicator
typealias MitCategory = ucs.v2.Payment.MitCategory
typealias SyncRequestType = ucs.v2.Payment.SyncRequestType
typealias AcceptanceType = ucs.v2.Payment.AcceptanceType
typealias CavvAlgorithm = ucs.v2.Payment.CavvAlgorithm
