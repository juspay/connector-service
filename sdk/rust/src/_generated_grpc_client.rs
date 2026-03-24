// AUTO-GENERATED — do not edit by hand.
// Source: services.proto  |  Regenerate: make generate  (or: python3 scripts/generators/code/generate.py --lang grpc)

use std::{collections::HashMap, sync::Arc};

use grpc_api_types::payments::{
    // tonic-generated client stubs (one module per service)
    customer_service_client::CustomerServiceClient,
    dispute_service_client::DisputeServiceClient,
    event_service_client::EventServiceClient,
    merchant_authentication_service_client::MerchantAuthenticationServiceClient,
    payment_method_authentication_service_client::PaymentMethodAuthenticationServiceClient,
    payment_method_service_client::PaymentMethodServiceClient,
    payment_service_client::PaymentServiceClient,
    payout_service_client::PayoutServiceClient,
    proxy_payment_service_client::ProxyPaymentServiceClient,
    recurring_payment_service_client::RecurringPaymentServiceClient,
    tokenized_payment_service_client::TokenizedPaymentServiceClient,
    // request / response types (all unique types across all services)
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
    MerchantAuthenticationServiceCreateSdkSessionTokenRequest,
    MerchantAuthenticationServiceCreateSdkSessionTokenResponse,
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
    PaymentServiceIncrementalAuthorizationRequest,
    PaymentServiceIncrementalAuthorizationResponse,
    PaymentServiceRefundRequest,
    PaymentServiceReverseRequest,
    PaymentServiceReverseResponse,
    PaymentServiceSetupRecurringRequest,
    PaymentServiceSetupRecurringResponse,
    PaymentServiceVerifyRedirectResponseRequest,
    PaymentServiceVerifyRedirectResponseResponse,
    PaymentServiceVoidRequest,
    PaymentServiceVoidResponse,
    PayoutMethodEligibilityRequest,
    PayoutMethodEligibilityResponse,
    PayoutServiceCreateLinkRequest,
    PayoutServiceCreateLinkResponse,
    PayoutServiceCreateRecipientRequest,
    PayoutServiceCreateRecipientResponse,
    PayoutServiceEnrollDisburseAccountRequest,
    PayoutServiceEnrollDisburseAccountResponse,
    PayoutServiceStageRequest,
    PayoutServiceStageResponse,
    PayoutServiceTransferRequest,
    PayoutServiceTransferResponse,
    ProxyPaymentMethodAuthenticationServiceAuthenticateRequest,
    ProxyPaymentMethodAuthenticationServicePostAuthenticateRequest,
    ProxyPaymentMethodAuthenticationServicePreAuthenticateRequest,
    ProxyPaymentServiceAuthorizeRequest,
    ProxyPaymentServiceSetupRecurringRequest,
    RecurringPaymentServiceChargeRequest,
    RecurringPaymentServiceChargeResponse,
    RecurringPaymentServiceRevokeRequest,
    RecurringPaymentServiceRevokeResponse,
    RefundResponse,
    TokenizedPaymentServiceAuthorizeRequest,
    TokenizedPaymentServiceSetupRecurringRequest,
};
use tonic::{
    metadata::{MetadataKey, MetadataValue},
    transport::Channel,
    Request, Status,
};

use crate::grpc_config::GrpcConfig;

// ── Internal macro ────────────────────────────────────────────────────────────
//
// Generates a typed sub-client struct for one gRPC service.
// Each method:
//   - creates a fresh tonic stub (Channel is Arc-backed so clone is O(1))
//   - injects all auth headers from the shared header map
//   - returns the unwrapped inner response on success
macro_rules! impl_grpc_client {
    ($name:ident, $stub:ident, $( ($method:ident, $stub_method:ident, $req:ty, $res:ty) ),+ $(,)?) => {
        pub struct $name {
            channel: Channel,
            headers: Arc<HashMap<String, String>>,
        }

        impl $name {
            fn new(channel: Channel, headers: Arc<HashMap<String, String>>) -> Self {
                Self { channel, headers }
            }

            fn inject_headers<T>(&self, payload: T) -> Request<T> {
                let mut req = Request::new(payload);
                for (k, v) in self.headers.as_ref() {
                    if let (Ok(key), Ok(val)) = (
                        MetadataKey::from_bytes(k.as_bytes()),
                        MetadataValue::try_from(v.as_str()),
                    ) {
                        req.metadata_mut().insert(key, val);
                    }
                }
                req
            }

            $(
                pub async fn $method(&self, request: $req) -> Result<$res, Status> {
                    $stub::new(self.channel.clone())
                        .$stub_method(self.inject_headers(request))
                        .await
                        .map(|r| r.into_inner())
                }
            )+
        }
    };
}

// ── Sub-clients (one per proto service) ──────────────────────────────────────

// CustomerService
impl_grpc_client!(
    GrpcCustomerClient,
    CustomerServiceClient,
    (
        create,
        create,
        CustomerServiceCreateRequest,
        CustomerServiceCreateResponse
    ),
);

// DisputeService
impl_grpc_client!(
    GrpcDisputeClient,
    DisputeServiceClient,
    (
        submit_evidence,
        submit_evidence,
        DisputeServiceSubmitEvidenceRequest,
        DisputeServiceSubmitEvidenceResponse
    ),
    (
        defend,
        defend,
        DisputeServiceDefendRequest,
        DisputeServiceDefendResponse
    ),
    (
        accept,
        accept,
        DisputeServiceAcceptRequest,
        DisputeServiceAcceptResponse
    ),
);

// EventService
impl_grpc_client!(
    GrpcEventClient,
    EventServiceClient,
    (
        handle_event,
        handle_event,
        EventServiceHandleRequest,
        EventServiceHandleResponse
    ),
);

// MerchantAuthenticationService
impl_grpc_client!(
    GrpcMerchantAuthenticationClient,
    MerchantAuthenticationServiceClient,
    (
        create_access_token,
        create_access_token,
        MerchantAuthenticationServiceCreateAccessTokenRequest,
        MerchantAuthenticationServiceCreateAccessTokenResponse
    ),
    (
        create_session_token,
        create_session_token,
        MerchantAuthenticationServiceCreateSessionTokenRequest,
        MerchantAuthenticationServiceCreateSessionTokenResponse
    ),
    (
        create_sdk_session_token,
        create_sdk_session_token,
        MerchantAuthenticationServiceCreateSdkSessionTokenRequest,
        MerchantAuthenticationServiceCreateSdkSessionTokenResponse
    ),
);

// PaymentMethodAuthenticationService
impl_grpc_client!(
    GrpcPaymentMethodAuthenticationClient,
    PaymentMethodAuthenticationServiceClient,
    (
        pre_authenticate,
        pre_authenticate,
        PaymentMethodAuthenticationServicePreAuthenticateRequest,
        PaymentMethodAuthenticationServicePreAuthenticateResponse
    ),
    (
        authenticate,
        authenticate,
        PaymentMethodAuthenticationServiceAuthenticateRequest,
        PaymentMethodAuthenticationServiceAuthenticateResponse
    ),
    (
        post_authenticate,
        post_authenticate,
        PaymentMethodAuthenticationServicePostAuthenticateRequest,
        PaymentMethodAuthenticationServicePostAuthenticateResponse
    ),
);

// PaymentMethodService
impl_grpc_client!(
    GrpcPaymentMethodClient,
    PaymentMethodServiceClient,
    (
        tokenize,
        tokenize,
        PaymentMethodServiceTokenizeRequest,
        PaymentMethodServiceTokenizeResponse
    ),
    (
        eligibility,
        eligibility,
        PayoutMethodEligibilityRequest,
        PayoutMethodEligibilityResponse
    ),
);

// PaymentService
impl_grpc_client!(
    GrpcPaymentClient,
    PaymentServiceClient,
    (
        authorize,
        authorize,
        PaymentServiceAuthorizeRequest,
        PaymentServiceAuthorizeResponse
    ),
    (
        get,
        get,
        PaymentServiceGetRequest,
        PaymentServiceGetResponse
    ),
    (
        void,
        void,
        PaymentServiceVoidRequest,
        PaymentServiceVoidResponse
    ),
    (
        reverse,
        reverse,
        PaymentServiceReverseRequest,
        PaymentServiceReverseResponse
    ),
    (
        capture,
        capture,
        PaymentServiceCaptureRequest,
        PaymentServiceCaptureResponse
    ),
    (
        create_order,
        create_order,
        PaymentServiceCreateOrderRequest,
        PaymentServiceCreateOrderResponse
    ),
    (refund, refund, PaymentServiceRefundRequest, RefundResponse),
    (
        incremental_authorization,
        incremental_authorization,
        PaymentServiceIncrementalAuthorizationRequest,
        PaymentServiceIncrementalAuthorizationResponse
    ),
    (
        verify_redirect_response,
        verify_redirect_response,
        PaymentServiceVerifyRedirectResponseRequest,
        PaymentServiceVerifyRedirectResponseResponse
    ),
    (
        setup_recurring,
        setup_recurring,
        PaymentServiceSetupRecurringRequest,
        PaymentServiceSetupRecurringResponse
    ),
);

// PayoutService
impl_grpc_client!(
    GrpcPayoutClient,
    PayoutServiceClient,
    (
        transfer,
        transfer,
        PayoutServiceTransferRequest,
        PayoutServiceTransferResponse
    ),
    (
        stage,
        stage,
        PayoutServiceStageRequest,
        PayoutServiceStageResponse
    ),
    (
        create_link,
        create_link,
        PayoutServiceCreateLinkRequest,
        PayoutServiceCreateLinkResponse
    ),
    (
        create_recipient,
        create_recipient,
        PayoutServiceCreateRecipientRequest,
        PayoutServiceCreateRecipientResponse
    ),
    (
        enroll_disburse_account,
        enroll_disburse_account,
        PayoutServiceEnrollDisburseAccountRequest,
        PayoutServiceEnrollDisburseAccountResponse
    ),
);

// ProxyPaymentService
impl_grpc_client!(
    GrpcProxyPaymentClient,
    ProxyPaymentServiceClient,
    (
        proxy_authorize,
        authorize,
        ProxyPaymentServiceAuthorizeRequest,
        PaymentServiceAuthorizeResponse
    ),
    (
        proxy_setup_recurring,
        setup_recurring,
        ProxyPaymentServiceSetupRecurringRequest,
        PaymentServiceSetupRecurringResponse
    ),
    (
        proxy_pre_authenticate,
        pre_authenticate,
        ProxyPaymentMethodAuthenticationServicePreAuthenticateRequest,
        PaymentMethodAuthenticationServicePreAuthenticateResponse
    ),
    (
        proxy_authenticate,
        authenticate,
        ProxyPaymentMethodAuthenticationServiceAuthenticateRequest,
        PaymentMethodAuthenticationServiceAuthenticateResponse
    ),
    (
        proxy_post_authenticate,
        post_authenticate,
        ProxyPaymentMethodAuthenticationServicePostAuthenticateRequest,
        PaymentMethodAuthenticationServicePostAuthenticateResponse
    ),
);

// RecurringPaymentService
impl_grpc_client!(
    GrpcRecurringPaymentClient,
    RecurringPaymentServiceClient,
    (
        charge,
        charge,
        RecurringPaymentServiceChargeRequest,
        RecurringPaymentServiceChargeResponse
    ),
    (
        revoke,
        revoke,
        RecurringPaymentServiceRevokeRequest,
        RecurringPaymentServiceRevokeResponse
    ),
);

// TokenizedPaymentService
impl_grpc_client!(
    GrpcTokenizedPaymentClient,
    TokenizedPaymentServiceClient,
    (
        tokenized_authorize,
        authorize,
        TokenizedPaymentServiceAuthorizeRequest,
        PaymentServiceAuthorizeResponse
    ),
    (
        tokenized_setup_recurring,
        setup_recurring,
        TokenizedPaymentServiceSetupRecurringRequest,
        PaymentServiceSetupRecurringResponse
    ),
);

// ── GrpcClient ────────────────────────────────────────────────────────────────

/// Top-level gRPC client for the connector-service.
///
/// All sub-clients share a single underlying connection pool ([`Channel`]).
/// Auth headers from [`GrpcConfig`] are injected automatically on every call.
///
/// # Example
/// ```rust,no_run
/// # use hyperswitch_payments_client::{GrpcClient, GrpcConfig};
/// # #[tokio::main] async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let client = GrpcClient::new(GrpcConfig {
///     endpoint:    "http://localhost:8000".into(),
///     connector:   "stripe".into(),
///     auth_type:   "header-key".into(),
///     api_key:     "sk_test_...".into(),
///     api_secret:  None,
///     key1:        None,
///     merchant_id: None,
///     tenant_id:   None,
/// }).await?;
///
/// let _ = client.customer.create(Default::default()).await;
/// let _ = client.dispute.submit_evidence(Default::default()).await;
/// let _ = client.event.handle_event(Default::default()).await;
/// let _ = client.merchant_authentication.create_access_token(Default::default()).await;
/// # Ok(()) }
/// ```
pub struct GrpcClient {
    pub customer: GrpcCustomerClient,
    pub dispute: GrpcDisputeClient,
    pub event: GrpcEventClient,
    pub merchant_authentication: GrpcMerchantAuthenticationClient,
    pub payment_method_authentication: GrpcPaymentMethodAuthenticationClient,
    pub payment_method: GrpcPaymentMethodClient,
    pub payment: GrpcPaymentClient,
    pub payout: GrpcPayoutClient,
    pub proxy_payment: GrpcProxyPaymentClient,
    pub recurring_payment: GrpcRecurringPaymentClient,
    pub tokenized_payment: GrpcTokenizedPaymentClient,
}

impl GrpcClient {
    /// Connect to the server eagerly — fails fast if the endpoint is unreachable.
    ///
    /// # Errors
    /// Returns [`tonic::transport::Error`] if the URI is invalid or the TCP
    /// connection cannot be established.
    pub async fn new(config: GrpcConfig) -> Result<Self, tonic::transport::Error> {
        let endpoint = config.endpoint.clone();
        let headers = Arc::new(config.into_headers());

        let channel = Channel::from_shared(endpoint)
            .expect("invalid endpoint URI")
            .connect()
            .await?;

        Ok(Self {
            customer: GrpcCustomerClient::new(channel.clone(), Arc::clone(&headers)),
            dispute: GrpcDisputeClient::new(channel.clone(), Arc::clone(&headers)),
            event: GrpcEventClient::new(channel.clone(), Arc::clone(&headers)),
            merchant_authentication: GrpcMerchantAuthenticationClient::new(
                channel.clone(),
                Arc::clone(&headers),
            ),
            payment_method_authentication: GrpcPaymentMethodAuthenticationClient::new(
                channel.clone(),
                Arc::clone(&headers),
            ),
            payment_method: GrpcPaymentMethodClient::new(channel.clone(), Arc::clone(&headers)),
            payment: GrpcPaymentClient::new(channel.clone(), Arc::clone(&headers)),
            payout: GrpcPayoutClient::new(channel.clone(), Arc::clone(&headers)),
            proxy_payment: GrpcProxyPaymentClient::new(channel.clone(), Arc::clone(&headers)),
            recurring_payment: GrpcRecurringPaymentClient::new(
                channel.clone(),
                Arc::clone(&headers),
            ),
            tokenized_payment: GrpcTokenizedPaymentClient::new(
                channel.clone(),
                Arc::clone(&headers),
            ),
        })
    }
}
