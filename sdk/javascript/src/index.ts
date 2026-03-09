// Re-export client classes flat (high-level API)
export * from "./payments/_generated_connector_client_flows";
export { UniffiClient } from "./payments/_generated_uniffi_client_flows";
export type { RustBuffer, RustCallStatus } from "./payments/uniffi_client";
export * from "./http_client";
export * from './payments/generated/proto';

// ---------------------------------------------------------------------------
// Domain namespaces — runtime values
// Usage: import { payments, payment_methods, configs } from '@juspay/connector-service-sdk';
//        const config: configs.IConnectorConfig = { ... };
//        const client = new ConnectorClient(identity);
// ---------------------------------------------------------------------------
<<<<<<< HEAD
=======

export const payments = {
  // Request / Response types
  PaymentServiceAuthorizeRequest: ucs.v2.PaymentServiceAuthorizeRequest,
  PaymentServiceAuthorizeResponse: ucs.v2.PaymentServiceAuthorizeResponse,
  PaymentServiceCaptureRequest: ucs.v2.PaymentServiceCaptureRequest,
  PaymentServiceCaptureResponse: ucs.v2.PaymentServiceCaptureResponse,
  PaymentServiceVoidRequest: ucs.v2.PaymentServiceVoidRequest,
  PaymentServiceVoidResponse: ucs.v2.PaymentServiceVoidResponse,
  PaymentServiceRefundRequest: ucs.v2.PaymentServiceRefundRequest,
  PaymentServiceReverseRequest: ucs.v2.PaymentServiceReverseRequest,
  PaymentServiceGetRequest: ucs.v2.PaymentServiceGetRequest,
  PaymentServiceGetResponse: ucs.v2.PaymentServiceGetResponse,
  PaymentServiceCreateOrderRequest: ucs.v2.PaymentServiceCreateOrderRequest,
  PaymentServiceCreateOrderResponse: ucs.v2.PaymentServiceCreateOrderResponse,
  PaymentServiceSetupRecurringRequest: ucs.v2.PaymentServiceSetupRecurringRequest,
  PaymentServiceSetupRecurringResponse: ucs.v2.PaymentServiceSetupRecurringResponse,
  PaymentServiceIncrementalAuthorizationRequest: ucs.v2.PaymentServiceIncrementalAuthorizationRequest,
  PaymentServiceIncrementalAuthorizationResponse: ucs.v2.PaymentServiceIncrementalAuthorizationResponse,
  PaymentServiceVerifyRedirectResponseRequest: ucs.v2.PaymentServiceVerifyRedirectResponseRequest,
  PaymentServiceVerifyRedirectResponseResponse: ucs.v2.PaymentServiceVerifyRedirectResponseResponse,
  PaymentServiceDisputeRequest: ucs.v2.PaymentServiceDisputeRequest,
  // Authentication types
  PaymentMethodAuthenticationServicePreAuthenticateRequest: ucs.v2.PaymentMethodAuthenticationServicePreAuthenticateRequest,
  PaymentMethodAuthenticationServicePreAuthenticateResponse: ucs.v2.PaymentMethodAuthenticationServicePreAuthenticateResponse,
  PaymentMethodAuthenticationServiceAuthenticateRequest: ucs.v2.PaymentMethodAuthenticationServiceAuthenticateRequest,
  PaymentMethodAuthenticationServiceAuthenticateResponse: ucs.v2.PaymentMethodAuthenticationServiceAuthenticateResponse,
  // Tokenization
  PaymentMethodServiceTokenizeRequest: ucs.v2.PaymentMethodServiceTokenizeRequest,
  PaymentMethodServiceTokenizeResponse: ucs.v2.PaymentMethodServiceTokenizeResponse,
  // Access token types
  MerchantAuthenticationServiceCreateAccessTokenRequest: ucs.v2.MerchantAuthenticationServiceCreateAccessTokenRequest,
  MerchantAuthenticationServiceCreateAccessTokenResponse: ucs.v2.MerchantAuthenticationServiceCreateAccessTokenResponse,
  // Data types
  SecretString: ucs.v2.SecretString,
  AccessToken: ucs.v2.AccessToken,
  ConnectorState: ucs.v2.ConnectorState,
  Customer: ucs.v2.Customer,
  PaymentAddress: ucs.v2.PaymentAddress,
  Money: ucs.v2.Money,
  BrowserInformation: ucs.v2.BrowserInformation,
  CustomerAcceptance: ucs.v2.CustomerAcceptance,
  SessionToken: ucs.v2.SessionToken,
  // Response data types
  ConnectorResponseData: ucs.v2.ConnectorResponseData,
  CardConnectorResponse: ucs.v2.CardConnectorResponse,
  ErrorInfo: ucs.v2.ErrorInfo,
  // Enums
  Currency: ucs.v2.Currency,
  Connector: ucs.v2.Connector,
  CaptureMethod: ucs.v2.CaptureMethod,
  AuthenticationType: ucs.v2.AuthenticationType,
  PaymentMethodType: ucs.v2.PaymentMethodType,
  PaymentStatus: ucs.v2.PaymentStatus,
  RefundStatus: ucs.v2.RefundStatus,
  DisputeStatus: ucs.v2.DisputeStatus,
  MandateStatus: ucs.v2.MandateStatus,
  AuthorizationStatus: ucs.v2.AuthorizationStatus,
  OperationStatus: ucs.v2.OperationStatus,
  HttpMethod: ucs.v2.HttpMethod,
  FutureUsage: ucs.v2.FutureUsage,
  PaymentExperience: ucs.v2.PaymentExperience,
  PaymentChannel: ucs.v2.PaymentChannel,
  ProductType: ucs.v2.ProductType,
  DisputeStage: ucs.v2.DisputeStage,
  Tokenization: ucs.v2.Tokenization,
  WebhookEventType: ucs.v2.WebhookEventType,
  ThreeDsCompletionIndicator: ucs.v2.ThreeDsCompletionIndicator,
  TransactionStatus: ucs.v2.TransactionStatus,
  ExemptionIndicator: ucs.v2.ExemptionIndicator,
  MitCategory: ucs.v2.MitCategory,
  SyncRequestType: ucs.v2.SyncRequestType,
  AcceptanceType: ucs.v2.AcceptanceType,
  CavvAlgorithm: ucs.v2.CavvAlgorithm,
};

export const payment_methods = {
  PaymentMethod: ucs.v2.PaymentMethod,
  CardNumberType: ucs.v2.CardNumberType,
  CardDetails: ucs.v2.CardDetails,
  CardRedirect: ucs.v2.CardRedirect,
};

export const configs = {
  // Configuration types
  ConnectorConfig: ucs.v2.ConnectorConfig,
  RequestConfig: ucs.v2.RequestConfig,
  HttpConfig: ucs.v2.HttpConfig,
  CaCert: ucs.v2.CaCert,
  HttpDefault: ucs.v2.HttpDefault,
  Environment: ucs.v2.Environment,
  // FFI Internal
  FfiOptions: ucs.v2.FfiOptions,
  FfiConnectorHttpRequest: ucs.v2.FfiConnectorHttpRequest,
  FfiConnectorHttpResponse: ucs.v2.FfiConnectorHttpResponse,
};

// ---------------------------------------------------------------------------
// Domain namespaces — type declarations (declaration merging)
// Enables: const req: payments.IPaymentServiceAuthorizeRequest = ...
//          let res: payments.PaymentServiceAuthorizeResponse = ...
// ---------------------------------------------------------------------------

export namespace payments {
  // Input interfaces (I-prefixed — used for .create() parameters)
  export type IPaymentServiceAuthorizeRequest = ucs.v2.IPaymentServiceAuthorizeRequest;
  export type IPaymentServiceAuthorizeResponse = ucs.v2.IPaymentServiceAuthorizeResponse;
  export type IPaymentServiceCaptureRequest = ucs.v2.IPaymentServiceCaptureRequest;
  export type IPaymentServiceCaptureResponse = ucs.v2.IPaymentServiceCaptureResponse;
  export type IPaymentServiceVoidRequest = ucs.v2.IPaymentServiceVoidRequest;
  export type IPaymentServiceVoidResponse = ucs.v2.IPaymentServiceVoidResponse;
  export type IPaymentServiceRefundRequest = ucs.v2.IPaymentServiceRefundRequest;
  export type IPaymentServiceReverseRequest = ucs.v2.IPaymentServiceReverseRequest;
  export type IPaymentServiceGetRequest = ucs.v2.IPaymentServiceGetRequest;
  export type IPaymentServiceGetResponse = ucs.v2.IPaymentServiceGetResponse;
  export type IPaymentServiceCreateOrderRequest = ucs.v2.IPaymentServiceCreateOrderRequest;
  export type IPaymentServiceCreateOrderResponse = ucs.v2.IPaymentServiceCreateOrderResponse;
  export type IPaymentServiceSetupRecurringRequest = ucs.v2.IPaymentServiceSetupRecurringRequest;
  export type IPaymentServiceSetupRecurringResponse = ucs.v2.IPaymentServiceSetupRecurringResponse;
  export type IPaymentServiceIncrementalAuthorizationRequest = ucs.v2.IPaymentServiceIncrementalAuthorizationRequest;
  export type IPaymentServiceIncrementalAuthorizationResponse = ucs.v2.IPaymentServiceIncrementalAuthorizationResponse;
  export type IPaymentServiceVerifyRedirectResponseRequest = ucs.v2.IPaymentServiceVerifyRedirectResponseRequest;
  export type IPaymentServiceVerifyRedirectResponseResponse = ucs.v2.IPaymentServiceVerifyRedirectResponseResponse;
  export type IPaymentServiceDisputeRequest = ucs.v2.IPaymentServiceDisputeRequest;
  export type IPaymentMethodAuthenticationServicePreAuthenticateRequest = ucs.v2.IPaymentMethodAuthenticationServicePreAuthenticateRequest;
  export type IPaymentMethodAuthenticationServicePreAuthenticateResponse = ucs.v2.IPaymentMethodAuthenticationServicePreAuthenticateResponse;
  export type IPaymentMethodAuthenticationServiceAuthenticateRequest = ucs.v2.IPaymentMethodAuthenticationServiceAuthenticateRequest;
  export type IPaymentMethodAuthenticationServiceAuthenticateResponse = ucs.v2.IPaymentMethodAuthenticationServiceAuthenticateResponse;
  export type IPaymentMethodServiceTokenizeRequest = ucs.v2.IPaymentMethodServiceTokenizeRequest;
  export type IPaymentMethodServiceTokenizeResponse = ucs.v2.IPaymentMethodServiceTokenizeResponse;
  export type IMerchantAuthenticationServiceCreateAccessTokenRequest = ucs.v2.IMerchantAuthenticationServiceCreateAccessTokenRequest;
  export type IMerchantAuthenticationServiceCreateAccessTokenResponse = ucs.v2.IMerchantAuthenticationServiceCreateAccessTokenResponse;
  // Data type interfaces
  export type ISecretString = ucs.v2.ISecretString;
  export type IAccessToken = ucs.v2.IAccessToken;
  export type IConnectorState = ucs.v2.IConnectorState;
  export type ICustomer = ucs.v2.ICustomer;
  export type IPaymentAddress = ucs.v2.IPaymentAddress;
  export type IMoney = ucs.v2.IMoney;
  export type IBrowserInformation = ucs.v2.IBrowserInformation;
  export type ICustomerAcceptance = ucs.v2.ICustomerAcceptance;
  export type ISessionToken = ucs.v2.ISessionToken;
  export type IConnectorResponseData = ucs.v2.IConnectorResponseData;
  export type ICardConnectorResponse = ucs.v2.ICardConnectorResponse;
  export type IErrorInfo = ucs.v2.IErrorInfo;

  // Class types (used for variable annotations on decoded/response values)
  export type PaymentServiceAuthorizeRequest = ucs.v2.PaymentServiceAuthorizeRequest;
  export type PaymentServiceAuthorizeResponse = ucs.v2.PaymentServiceAuthorizeResponse;
  export type PaymentServiceCaptureRequest = ucs.v2.PaymentServiceCaptureRequest;
  export type PaymentServiceCaptureResponse = ucs.v2.PaymentServiceCaptureResponse;
  export type PaymentServiceVoidRequest = ucs.v2.PaymentServiceVoidRequest;
  export type PaymentServiceVoidResponse = ucs.v2.PaymentServiceVoidResponse;
  export type PaymentServiceRefundRequest = ucs.v2.PaymentServiceRefundRequest;
  export type PaymentServiceReverseRequest = ucs.v2.PaymentServiceReverseRequest;
  export type PaymentServiceGetRequest = ucs.v2.PaymentServiceGetRequest;
  export type PaymentServiceGetResponse = ucs.v2.PaymentServiceGetResponse;
  export type PaymentServiceCreateOrderRequest = ucs.v2.PaymentServiceCreateOrderRequest;
  export type PaymentServiceCreateOrderResponse = ucs.v2.PaymentServiceCreateOrderResponse;
  export type PaymentServiceSetupRecurringRequest = ucs.v2.PaymentServiceSetupRecurringRequest;
  export type PaymentServiceSetupRecurringResponse = ucs.v2.PaymentServiceSetupRecurringResponse;
  export type PaymentServiceIncrementalAuthorizationRequest = ucs.v2.PaymentServiceIncrementalAuthorizationRequest;
  export type PaymentServiceIncrementalAuthorizationResponse = ucs.v2.PaymentServiceIncrementalAuthorizationResponse;
  export type PaymentServiceVerifyRedirectResponseRequest = ucs.v2.PaymentServiceVerifyRedirectResponseRequest;
  export type PaymentServiceVerifyRedirectResponseResponse = ucs.v2.PaymentServiceVerifyRedirectResponseResponse;
  export type PaymentServiceDisputeRequest = ucs.v2.PaymentServiceDisputeRequest;
  export type PaymentMethodAuthenticationServicePreAuthenticateRequest = ucs.v2.PaymentMethodAuthenticationServicePreAuthenticateRequest;
  export type PaymentMethodAuthenticationServicePreAuthenticateResponse = ucs.v2.PaymentMethodAuthenticationServicePreAuthenticateResponse;
  export type PaymentMethodAuthenticationServiceAuthenticateRequest = ucs.v2.PaymentMethodAuthenticationServiceAuthenticateRequest;
  export type PaymentMethodAuthenticationServiceAuthenticateResponse = ucs.v2.PaymentMethodAuthenticationServiceAuthenticateResponse;
  export type PaymentMethodServiceTokenizeRequest = ucs.v2.PaymentMethodServiceTokenizeRequest;
  export type PaymentMethodServiceTokenizeResponse = ucs.v2.PaymentMethodServiceTokenizeResponse;
  export type MerchantAuthenticationServiceCreateAccessTokenRequest = ucs.v2.MerchantAuthenticationServiceCreateAccessTokenRequest;
  export type MerchantAuthenticationServiceCreateAccessTokenResponse = ucs.v2.MerchantAuthenticationServiceCreateAccessTokenResponse;
  export type SecretString = ucs.v2.SecretString;
  export type AccessToken = ucs.v2.AccessToken;
  export type ConnectorState = ucs.v2.ConnectorState;
  export type Customer = ucs.v2.Customer;
  export type PaymentAddress = ucs.v2.PaymentAddress;
  export type Money = ucs.v2.Money;
  export type BrowserInformation = ucs.v2.BrowserInformation;
  export type CustomerAcceptance = ucs.v2.CustomerAcceptance;
  export type SessionToken = ucs.v2.SessionToken;
  export type ConnectorResponseData = ucs.v2.ConnectorResponseData;
  export type ErrorInfo = ucs.v2.ErrorInfo;
}

export namespace payment_methods {
  export type IPaymentMethod = ucs.v2.IPaymentMethod;
  export type ICardDetails = ucs.v2.ICardDetails;
  export type ICardRedirect = ucs.v2.ICardRedirect;

  export type PaymentMethod = ucs.v2.PaymentMethod;
  export type CardNumberType = ucs.v2.CardNumberType;
  export type CardDetails = ucs.v2.CardDetails;
  export type CardRedirect = ucs.v2.CardRedirect;
}

export namespace configs {
  export type IConnectorConfig = ucs.v2.IConnectorConfig;
  export type IRequestConfig = ucs.v2.IRequestConfig;
  export type IHttpConfig = ucs.v2.IHttpConfig;
  export type ICaCert = ucs.v2.ICaCert;
  export type IFfiOptions = ucs.v2.IFfiOptions;
  export type IFfiConnectorHttpRequest = ucs.v2.IFfiConnectorHttpRequest;
  export type IFfiConnectorHttpResponse = ucs.v2.IFfiConnectorHttpResponse;

  export type ConnectorConfig = ucs.v2.ConnectorConfig;
  export type RequestConfig = ucs.v2.RequestConfig;
  export type HttpConfig = ucs.v2.HttpConfig;
  export type CaCert = ucs.v2.CaCert;
  export type FfiOptions = ucs.v2.FfiOptions;
  export type FfiConnectorHttpRequest = ucs.v2.FfiConnectorHttpRequest;
  export type FfiConnectorHttpResponse = ucs.v2.FfiConnectorHttpResponse;
  export type Environment = ucs.v2.Environment;
}
>>>>>>> 3a4909a0eac8a664572a48ab4ba374b64e8e3432
