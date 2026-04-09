use crate::macros::{
    req_transformer, res_transformer,
};
use external_services;
use grpc_api_types::payments::ConnectorResponseTransformationError;
use grpc_api_types::payments::{
    CustomerServiceCreateRequest, CustomerServiceCreateResponse, DisputeServiceAcceptRequest,
    DisputeServiceAcceptResponse, DisputeServiceDefendRequest, DisputeServiceDefendResponse,
    DisputeServiceSubmitEvidenceRequest, DisputeServiceSubmitEvidenceResponse,
    EventServiceHandleRequest, EventServiceHandleResponse,
    MerchantAuthenticationServiceCreateAccessTokenRequest,
    MerchantAuthenticationServiceCreateAccessTokenResponse,
    MerchantAuthenticationServiceCreateSessionTokenRequest,
    MerchantAuthenticationServiceCreateSessionTokenResponse,
    PaymentMethodAuthenticationServiceAuthenticateRequest,
    PaymentMethodAuthenticationServiceAuthenticateResponse,
    PaymentMethodAuthenticationServicePostAuthenticateRequest,
    PaymentMethodAuthenticationServicePostAuthenticateResponse,
    PaymentMethodAuthenticationServicePreAuthenticateRequest,
    PaymentMethodAuthenticationServicePreAuthenticateResponse, PaymentMethodServiceTokenizeRequest,
    PaymentMethodServiceTokenizeResponse, PaymentServiceAuthorizeRequest,
    PaymentServiceAuthorizeResponse, PaymentServiceCaptureRequest, PaymentServiceCaptureResponse,
    PaymentServiceCreateOrderRequest, PaymentServiceCreateOrderResponse, PaymentServiceGetRequest,
    PaymentServiceGetResponse, PaymentServiceProxyAuthorizeRequest,
    PaymentServiceProxySetupRecurringRequest, PaymentServiceRefundRequest,
    PaymentServiceReverseRequest, PaymentServiceReverseResponse,
    PaymentServiceSetupRecurringRequest, PaymentServiceSetupRecurringResponse,
    PaymentServiceTokenAuthorizeRequest, PaymentServiceTokenSetupRecurringRequest,
    PaymentServiceVoidRequest, PaymentServiceVoidResponse, RecurringPaymentServiceChargeRequest,
    RecurringPaymentServiceChargeResponse, RefundResponse,
};

use domain_types::{
    connector_flow::{
        Accept, Authenticate, Authorize, Capture, CreateAccessToken, CreateConnectorCustomer,
        CreateOrder, CreateSessionToken, DefendDispute, PSync, PaymentMethodToken,
        PostAuthenticate, PreAuthenticate, Refund, RepeatPayment, SetupMandate, SubmitEvidence,
        Void, VoidPC,
    },
    connector_types::{
        AcceptDisputeData, AccessTokenRequestData, AccessTokenResponseData, ConnectorCustomerData,
        ConnectorCustomerResponse, ConnectorWebhookSecrets, DisputeDefendData, DisputeFlowData,
        DisputeResponseData, PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData,
        PaymentMethodTokenResponse, PaymentMethodTokenizationData, PaymentVoidData,
        PaymentsAuthenticateData, PaymentsAuthorizeData, PaymentsCancelPostCaptureData,
        PaymentsCaptureData, PaymentsPostAuthenticateData, PaymentsPreAuthenticateData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundsData, RefundsResponseData,
        RepeatPaymentData, RequestDetails, SessionTokenRequestData, SessionTokenResponseData,
        SetupMandateRequestData, SubmitEvidenceData,
    },
};

// authorize request transformer
req_transformer!(
    fn_name: authorize_req_transformer,
    request_type: PaymentServiceAuthorizeRequest,
    flow_marker: Authorize,
    resource_common_data_type: PaymentFlowData,
    request_data_type: PaymentsAuthorizeData<domain_types::payment_method_data::DefaultPCIHolder>,
    response_data_type: PaymentsResponseData,
    connector_data_type: domain_types::payment_method_data::DefaultPCIHolder,
    request_data_fn: |p: &PaymentServiceAuthorizeRequest| {
        let auth_req: domain_types::types::AuthorizationRequest = p.clone().into();
        domain_types::types::build_request_data_with_required_pmd(p.payment_method.clone(), auth_req)
    },
);

// authorize response transformer
res_transformer!(
    fn_name: authorize_res_transformer,
    request_type: PaymentServiceAuthorizeRequest,
    response_type: PaymentServiceAuthorizeResponse,
    flow_marker: Authorize,
    resource_common_data_type: PaymentFlowData,
    request_data_type: PaymentsAuthorizeData<domain_types::payment_method_data::DefaultPCIHolder>,
    response_data_type: PaymentsResponseData,
    generate_response_fn: generate_payment_authorize_response,
    connector_data_type: domain_types::payment_method_data::DefaultPCIHolder,
    request_data_fn: |p: &PaymentServiceAuthorizeRequest| {
        let auth_req: domain_types::types::AuthorizationRequest = p.clone().into();
        domain_types::types::build_request_data_with_required_pmd(p.payment_method.clone(), auth_req)
    },
);

// capture request transformer
req_transformer!(
    fn_name: capture_req_transformer,
    request_type: PaymentServiceCaptureRequest,
    flow_marker: Capture,
    resource_common_data_type: PaymentFlowData,
    request_data_type: PaymentsCaptureData,
    response_data_type: PaymentsResponseData,
    connector_data_type: T,
    request_data_fn: |p: &PaymentServiceCaptureRequest| {
        domain_types::utils::ForeignTryFrom::foreign_try_from(p.clone())
    },
);

// capture response transformer
res_transformer!(
    fn_name: capture_res_transformer,
    request_type: PaymentServiceCaptureRequest,
    response_type: PaymentServiceCaptureResponse,
    flow_marker: Capture,
    resource_common_data_type: PaymentFlowData,
    request_data_type: PaymentsCaptureData,
    response_data_type: PaymentsResponseData,
    generate_response_fn: generate_payment_capture_response,
    connector_data_type: T,
    request_data_fn: |p: &PaymentServiceCaptureRequest| {
        domain_types::utils::ForeignTryFrom::foreign_try_from(p.clone())
    },
);

// void request transformer
req_transformer!(
    fn_name: void_req_transformer,
    request_type: PaymentServiceVoidRequest,
    flow_marker: Void,
    resource_common_data_type: PaymentFlowData,
    request_data_type: PaymentVoidData,
    response_data_type: PaymentsResponseData,
    connector_data_type: T,
    request_data_fn: |p: &PaymentServiceVoidRequest| {
        domain_types::utils::ForeignTryFrom::foreign_try_from(p.clone())
    },
);

// void response transformer
res_transformer!(
    fn_name: void_res_transformer,
    request_type: PaymentServiceVoidRequest,
    response_type: PaymentServiceVoidResponse,
    flow_marker: Void,
    resource_common_data_type: PaymentFlowData,
    request_data_type: PaymentVoidData,
    response_data_type: PaymentsResponseData,
    generate_response_fn: generate_payment_void_response,
    connector_data_type: T,
    request_data_fn: |p: &PaymentServiceVoidRequest| {
        domain_types::utils::ForeignTryFrom::foreign_try_from(p.clone())
    },
);

// psync request transformer
req_transformer!(
    fn_name: get_req_transformer,
    request_type: PaymentServiceGetRequest,
    flow_marker: PSync,
    resource_common_data_type: PaymentFlowData,
    request_data_type: PaymentsSyncData,
    response_data_type: PaymentsResponseData,
    connector_data_type: T,
    request_data_fn: |p: &PaymentServiceGetRequest| {
        domain_types::utils::ForeignTryFrom::foreign_try_from(p.clone())
    },
);

// psync response transformer
res_transformer!(
    fn_name: get_res_transformer,
    request_type: PaymentServiceGetRequest,
    response_type: PaymentServiceGetResponse,
    flow_marker: PSync,
    resource_common_data_type: PaymentFlowData,
    request_data_type: PaymentsSyncData,
    response_data_type: PaymentsResponseData,
    generate_response_fn: generate_payment_sync_response,
    connector_data_type: T,
    request_data_fn: |p: &PaymentServiceGetRequest| {
        domain_types::utils::ForeignTryFrom::foreign_try_from(p.clone())
    },
);

// create order request transformer
req_transformer!(
    fn_name: create_order_req_transformer,
    request_type: PaymentServiceCreateOrderRequest,
    flow_marker: CreateOrder,
    resource_common_data_type: PaymentFlowData,
    request_data_type: PaymentCreateOrderData,
    response_data_type: PaymentCreateOrderResponse,
    connector_data_type: T,
    request_data_fn: |p: &PaymentServiceCreateOrderRequest| {
        domain_types::utils::ForeignTryFrom::foreign_try_from(p.clone())
    },
);

// create order response transformer
res_transformer!(
    fn_name: create_order_res_transformer,
    request_type: PaymentServiceCreateOrderRequest,
    response_type: PaymentServiceCreateOrderResponse,
    flow_marker: CreateOrder,
    resource_common_data_type: PaymentFlowData,
    request_data_type: PaymentCreateOrderData,
    response_data_type: PaymentCreateOrderResponse,
    generate_response_fn: generate_create_order_response,
    connector_data_type: T,
    request_data_fn: |p: &PaymentServiceCreateOrderRequest| {
        domain_types::utils::ForeignTryFrom::foreign_try_from(p.clone())
    },
);

// create access token request transformer
req_transformer!(
    fn_name: create_access_token_req_transformer,
    request_type: MerchantAuthenticationServiceCreateAccessTokenRequest,
    flow_marker: CreateAccessToken,
    resource_common_data_type: PaymentFlowData,
    request_data_type: AccessTokenRequestData,
    response_data_type: AccessTokenResponseData,
    connector_data_type: T,
    request_data_fn: |p: &MerchantAuthenticationServiceCreateAccessTokenRequest| {
        domain_types::utils::ForeignTryFrom::foreign_try_from(p.clone())
    },
);

// create access token response transformer
res_transformer!(
    fn_name: create_access_token_res_transformer,
    request_type: MerchantAuthenticationServiceCreateAccessTokenRequest,
    response_type: MerchantAuthenticationServiceCreateAccessTokenResponse,
    flow_marker: CreateAccessToken,
    resource_common_data_type: PaymentFlowData,
    request_data_type: AccessTokenRequestData,
    response_data_type: AccessTokenResponseData,
    generate_response_fn: generate_access_token_response,
    connector_data_type: T,
    request_data_fn: |p: &MerchantAuthenticationServiceCreateAccessTokenRequest| {
        domain_types::utils::ForeignTryFrom::foreign_try_from(p.clone())
    },
);

// refund request transformer
req_transformer!(
    fn_name: refund_req_transformer,
    request_type: PaymentServiceRefundRequest,
    flow_marker: Refund,
    resource_common_data_type: RefundFlowData,
    request_data_type: RefundsData,
    response_data_type: RefundsResponseData,
    connector_data_type: T,
    request_data_fn: |p: &PaymentServiceRefundRequest| {
        domain_types::utils::ForeignTryFrom::foreign_try_from(p.clone())
    },
);

// refund response transformer
res_transformer!(
    fn_name: refund_res_transformer,
    request_type: PaymentServiceRefundRequest,
    response_type: RefundResponse,
    flow_marker: Refund,
    resource_common_data_type: RefundFlowData,
    request_data_type: RefundsData,
    response_data_type: RefundsResponseData,
    generate_response_fn: generate_refund_response,
    connector_data_type: T,
    request_data_fn: |p: &PaymentServiceRefundRequest| {
        domain_types::utils::ForeignTryFrom::foreign_try_from(p.clone())
    },
);

// reverse (void post-capture) request transformer
req_transformer!(
    fn_name: reverse_req_transformer,
    request_type: PaymentServiceReverseRequest,
    flow_marker: VoidPC,
    resource_common_data_type: PaymentFlowData,
    request_data_type: PaymentsCancelPostCaptureData,
    response_data_type: PaymentsResponseData,
    connector_data_type: T,
    request_data_fn: |p: &PaymentServiceReverseRequest| {
        domain_types::utils::ForeignTryFrom::foreign_try_from(p.clone())
    },
);

// reverse (void post-capture) response transformer
res_transformer!(
    fn_name: reverse_res_transformer,
    request_type: PaymentServiceReverseRequest,
    response_type: PaymentServiceReverseResponse,
    flow_marker: VoidPC,
    resource_common_data_type: PaymentFlowData,
    request_data_type: PaymentsCancelPostCaptureData,
    response_data_type: PaymentsResponseData,
    generate_response_fn: generate_payment_void_post_capture_response,
    connector_data_type: T,
    request_data_fn: |p: &PaymentServiceReverseRequest| {
        domain_types::utils::ForeignTryFrom::foreign_try_from(p.clone())
    },
);

// create connector customer request transformer
req_transformer!(
    fn_name: create_req_transformer,
    request_type: CustomerServiceCreateRequest,
    flow_marker: CreateConnectorCustomer,
    resource_common_data_type: PaymentFlowData,
    request_data_type: ConnectorCustomerData,
    response_data_type: ConnectorCustomerResponse,
    connector_data_type: T,
    request_data_fn: |p: &CustomerServiceCreateRequest| {
        domain_types::utils::ForeignTryFrom::foreign_try_from(p.clone())
    },
);

// create connector customer response transformer
res_transformer!(
    fn_name: create_res_transformer,
    request_type: CustomerServiceCreateRequest,
    response_type: CustomerServiceCreateResponse,
    flow_marker: CreateConnectorCustomer,
    resource_common_data_type: PaymentFlowData,
    request_data_type: ConnectorCustomerData,
    response_data_type: ConnectorCustomerResponse,
    generate_response_fn: generate_create_connector_customer_response,
    connector_data_type: T,
    request_data_fn: |p: &CustomerServiceCreateRequest| {
        domain_types::utils::ForeignTryFrom::foreign_try_from(p.clone())
    },
);

// repeat payment (charge) request transformer
req_transformer!(
    fn_name: charge_req_transformer,
    request_type: RecurringPaymentServiceChargeRequest,
    flow_marker: RepeatPayment,
    resource_common_data_type: PaymentFlowData,
    request_data_type: RepeatPaymentData<domain_types::payment_method_data::DefaultPCIHolder>,
    response_data_type: PaymentsResponseData,
    connector_data_type: domain_types::payment_method_data::DefaultPCIHolder,
    request_data_fn: |p: &RecurringPaymentServiceChargeRequest| {
        domain_types::types::build_request_data_with_required_pmd(p.payment_method.clone(), p.clone())
    },
);

// repeat payment (charge) response transformer
res_transformer!(
    fn_name: charge_res_transformer,
    request_type: RecurringPaymentServiceChargeRequest,
    response_type: RecurringPaymentServiceChargeResponse,
    flow_marker: RepeatPayment,
    resource_common_data_type: PaymentFlowData,
    request_data_type: RepeatPaymentData<domain_types::payment_method_data::DefaultPCIHolder>,
    response_data_type: PaymentsResponseData,
    generate_response_fn: generate_repeat_payment_response,
    connector_data_type: domain_types::payment_method_data::DefaultPCIHolder,
    request_data_fn: |p: &RecurringPaymentServiceChargeRequest| {
        domain_types::types::build_request_data_with_required_pmd(p.payment_method.clone(), p.clone())
    },
);

// create session token request transformer
req_transformer!(
    fn_name: create_session_token_req_transformer,
    request_type: MerchantAuthenticationServiceCreateSessionTokenRequest,
    flow_marker: CreateSessionToken,
    resource_common_data_type: PaymentFlowData,
    request_data_type: SessionTokenRequestData,
    response_data_type: SessionTokenResponseData,
    connector_data_type: T,
    request_data_fn: |p: &MerchantAuthenticationServiceCreateSessionTokenRequest| {
        domain_types::utils::ForeignTryFrom::foreign_try_from(p.clone())
    },
);

// create session token response transformer
res_transformer!(
    fn_name: create_session_token_res_transformer,
    request_type: MerchantAuthenticationServiceCreateSessionTokenRequest,
    response_type: MerchantAuthenticationServiceCreateSessionTokenResponse,
    flow_marker: CreateSessionToken,
    resource_common_data_type: PaymentFlowData,
    request_data_type: SessionTokenRequestData,
    response_data_type: SessionTokenResponseData,
    generate_response_fn: generate_session_token_response,
    connector_data_type: T,
    request_data_fn: |p: &MerchantAuthenticationServiceCreateSessionTokenRequest| {
        domain_types::utils::ForeignTryFrom::foreign_try_from(p.clone())
    },
);

// setup recurring (setup mandate) request transformer
req_transformer!(
    fn_name: setup_recurring_req_transformer,
    request_type: PaymentServiceSetupRecurringRequest,
    flow_marker: SetupMandate,
    resource_common_data_type: PaymentFlowData,
    request_data_type: SetupMandateRequestData<domain_types::payment_method_data::DefaultPCIHolder>,
    response_data_type: PaymentsResponseData,
    connector_data_type: domain_types::payment_method_data::DefaultPCIHolder,
    request_data_fn: |p: &PaymentServiceSetupRecurringRequest| {
        domain_types::types::build_request_data_with_required_pmd(p.payment_method.clone(), p.clone())
    },
);

// setup recurring (setup mandate) response transformer
res_transformer!(
    fn_name: setup_recurring_res_transformer,
    request_type: PaymentServiceSetupRecurringRequest,
    response_type: PaymentServiceSetupRecurringResponse,
    flow_marker: SetupMandate,
    resource_common_data_type: PaymentFlowData,
    request_data_type: SetupMandateRequestData<domain_types::payment_method_data::DefaultPCIHolder>,
    response_data_type: PaymentsResponseData,
    generate_response_fn: generate_setup_mandate_response,
    connector_data_type: domain_types::payment_method_data::DefaultPCIHolder,
    request_data_fn: |p: &PaymentServiceSetupRecurringRequest| {
        domain_types::types::build_request_data_with_required_pmd(p.payment_method.clone(), p.clone())
    },
);

// tokenize (payment method token) request transformer
req_transformer!(
    fn_name: tokenize_req_transformer,
    request_type: PaymentMethodServiceTokenizeRequest,
    flow_marker: PaymentMethodToken,
    resource_common_data_type: PaymentFlowData,
    request_data_type: PaymentMethodTokenizationData<domain_types::payment_method_data::DefaultPCIHolder>,
    response_data_type: PaymentMethodTokenResponse,
    connector_data_type: domain_types::payment_method_data::DefaultPCIHolder,
    request_data_fn: |p: &PaymentMethodServiceTokenizeRequest| {
        domain_types::types::build_request_data_with_required_pmd(p.payment_method.clone(), p.clone())
    },
);

// tokenize (payment method token) response transformer
res_transformer!(
    fn_name: tokenize_res_transformer,
    request_type: PaymentMethodServiceTokenizeRequest,
    response_type: PaymentMethodServiceTokenizeResponse,
    flow_marker: PaymentMethodToken,
    resource_common_data_type: PaymentFlowData,
    request_data_type: PaymentMethodTokenizationData<domain_types::payment_method_data::DefaultPCIHolder>,
    response_data_type: PaymentMethodTokenResponse,
    generate_response_fn: generate_create_payment_method_token_response,
    connector_data_type: domain_types::payment_method_data::DefaultPCIHolder,
    request_data_fn: |p: &PaymentMethodServiceTokenizeRequest| {
        domain_types::types::build_request_data_with_required_pmd(p.payment_method.clone(), p.clone())
    },
);

// pre_authenticate request transformer
req_transformer!(
    fn_name: pre_authenticate_req_transformer,
    request_type: PaymentMethodAuthenticationServicePreAuthenticateRequest,
    flow_marker: PreAuthenticate,
    resource_common_data_type: PaymentFlowData,
    request_data_type: PaymentsPreAuthenticateData<domain_types::payment_method_data::DefaultPCIHolder>,
    response_data_type: PaymentsResponseData,
    connector_data_type: domain_types::payment_method_data::DefaultPCIHolder,
    request_data_fn: |p: &PaymentMethodAuthenticationServicePreAuthenticateRequest| {
        domain_types::utils::ForeignTryFrom::foreign_try_from((p.clone(), None::<domain_types::payment_method_data::PaymentMethodData<domain_types::payment_method_data::DefaultPCIHolder>>))
    },
);

// pre_authenticate response transformer
res_transformer!(
    fn_name: pre_authenticate_res_transformer,
    request_type: PaymentMethodAuthenticationServicePreAuthenticateRequest,
    response_type: PaymentMethodAuthenticationServicePreAuthenticateResponse,
    flow_marker: PreAuthenticate,
    resource_common_data_type: PaymentFlowData,
    request_data_type: PaymentsPreAuthenticateData<domain_types::payment_method_data::DefaultPCIHolder>,
    response_data_type: PaymentsResponseData,
    generate_response_fn: generate_payment_pre_authenticate_response,
    connector_data_type: domain_types::payment_method_data::DefaultPCIHolder,
    request_data_fn: |p: &PaymentMethodAuthenticationServicePreAuthenticateRequest| {
        domain_types::utils::ForeignTryFrom::foreign_try_from((p.clone(), None::<domain_types::payment_method_data::PaymentMethodData<domain_types::payment_method_data::DefaultPCIHolder>>))
    },
);

// authenticate request transformer
req_transformer!(
    fn_name: authenticate_req_transformer,
    request_type: PaymentMethodAuthenticationServiceAuthenticateRequest,
    flow_marker: Authenticate,
    resource_common_data_type: PaymentFlowData,
    request_data_type: PaymentsAuthenticateData<domain_types::payment_method_data::DefaultPCIHolder>,
    response_data_type: PaymentsResponseData,
    connector_data_type: domain_types::payment_method_data::DefaultPCIHolder,
    request_data_fn: |p: &PaymentMethodAuthenticationServiceAuthenticateRequest| {
        domain_types::utils::ForeignTryFrom::foreign_try_from((p.clone(), None::<domain_types::payment_method_data::PaymentMethodData<domain_types::payment_method_data::DefaultPCIHolder>>))
    },
);

// authenticate response transformer
res_transformer!(
    fn_name: authenticate_res_transformer,
    request_type: PaymentMethodAuthenticationServiceAuthenticateRequest,
    response_type: PaymentMethodAuthenticationServiceAuthenticateResponse,
    flow_marker: Authenticate,
    resource_common_data_type: PaymentFlowData,
    request_data_type: PaymentsAuthenticateData<domain_types::payment_method_data::DefaultPCIHolder>,
    response_data_type: PaymentsResponseData,
    generate_response_fn: generate_payment_authenticate_response,
    connector_data_type: domain_types::payment_method_data::DefaultPCIHolder,
    request_data_fn: |p: &PaymentMethodAuthenticationServiceAuthenticateRequest| {
        domain_types::utils::ForeignTryFrom::foreign_try_from((p.clone(), None::<domain_types::payment_method_data::PaymentMethodData<domain_types::payment_method_data::DefaultPCIHolder>>))
    },
);

// post_authenticate request transformer
req_transformer!(
    fn_name: post_authenticate_req_transformer,
    request_type: PaymentMethodAuthenticationServicePostAuthenticateRequest,
    flow_marker: PostAuthenticate,
    resource_common_data_type: PaymentFlowData,
    request_data_type: PaymentsPostAuthenticateData<domain_types::payment_method_data::DefaultPCIHolder>,
    response_data_type: PaymentsResponseData,
    connector_data_type: domain_types::payment_method_data::DefaultPCIHolder,
    request_data_fn: |p: &PaymentMethodAuthenticationServicePostAuthenticateRequest| {
        domain_types::utils::ForeignTryFrom::foreign_try_from((p.clone(), None::<domain_types::payment_method_data::PaymentMethodData<domain_types::payment_method_data::DefaultPCIHolder>>))
    },
);

// post_authenticate response transformer
res_transformer!(
    fn_name: post_authenticate_res_transformer,
    request_type: PaymentMethodAuthenticationServicePostAuthenticateRequest,
    response_type: PaymentMethodAuthenticationServicePostAuthenticateResponse,
    flow_marker: PostAuthenticate,
    resource_common_data_type: PaymentFlowData,
    request_data_type: PaymentsPostAuthenticateData<domain_types::payment_method_data::DefaultPCIHolder>,
    response_data_type: PaymentsResponseData,
    generate_response_fn: generate_payment_post_authenticate_response,
    connector_data_type: domain_types::payment_method_data::DefaultPCIHolder,
    request_data_fn: |p: &PaymentMethodAuthenticationServicePostAuthenticateRequest| {
        domain_types::utils::ForeignTryFrom::foreign_try_from((p.clone(), None::<domain_types::payment_method_data::PaymentMethodData<domain_types::payment_method_data::DefaultPCIHolder>>))
    },
);

// accept request transformer
req_transformer!(
    fn_name: accept_req_transformer,
    request_type: DisputeServiceAcceptRequest,
    flow_marker: Accept,
    resource_common_data_type: DisputeFlowData,
    request_data_type: AcceptDisputeData,
    response_data_type: DisputeResponseData,
    connector_data_type: T,
    request_data_fn: |p: &DisputeServiceAcceptRequest| {
        domain_types::utils::ForeignTryFrom::foreign_try_from(p.clone())
    },
);

// submit_evidence request transformer
req_transformer!(
    fn_name: submit_evidence_req_transformer,
    request_type: DisputeServiceSubmitEvidenceRequest,
    flow_marker: SubmitEvidence,
    resource_common_data_type: DisputeFlowData,
    request_data_type: SubmitEvidenceData,
    response_data_type: DisputeResponseData,
    connector_data_type: T,
    request_data_fn: |p: &DisputeServiceSubmitEvidenceRequest| {
        domain_types::utils::ForeignTryFrom::foreign_try_from(p.clone())
    },
);

// defend request transformer
req_transformer!(
    fn_name: defend_req_transformer,
    request_type: DisputeServiceDefendRequest,
    flow_marker: DefendDispute,
    resource_common_data_type: DisputeFlowData,
    request_data_type: DisputeDefendData,
    response_data_type: DisputeResponseData,
    connector_data_type: T,
    request_data_fn: |p: &DisputeServiceDefendRequest| {
        domain_types::utils::ForeignTryFrom::foreign_try_from(p.clone())
    },
);

// accept response transformer
res_transformer!(
    fn_name: accept_res_transformer,
    request_type: DisputeServiceAcceptRequest,
    response_type: DisputeServiceAcceptResponse,
    flow_marker: Accept,
    resource_common_data_type: DisputeFlowData,
    request_data_type: AcceptDisputeData,
    response_data_type: DisputeResponseData,
    generate_response_fn: generate_accept_dispute_response,
    connector_data_type: T,
    request_data_fn: |p: &DisputeServiceAcceptRequest| {
        domain_types::utils::ForeignTryFrom::foreign_try_from(p.clone())
    },
);

// submit_evidence response transformer
res_transformer!(
    fn_name: submit_evidence_res_transformer,
    request_type: DisputeServiceSubmitEvidenceRequest,
    response_type: DisputeServiceSubmitEvidenceResponse,
    flow_marker: SubmitEvidence,
    resource_common_data_type: DisputeFlowData,
    request_data_type: SubmitEvidenceData,
    response_data_type: DisputeResponseData,
    generate_response_fn: generate_submit_evidence_response,
    connector_data_type: T,
    request_data_fn: |p: &DisputeServiceSubmitEvidenceRequest| {
        domain_types::utils::ForeignTryFrom::foreign_try_from(p.clone())
    },
);

// defend response transformer
res_transformer!(
    fn_name: defend_res_transformer,
    request_type: DisputeServiceDefendRequest,
    response_type: DisputeServiceDefendResponse,
    flow_marker: DefendDispute,
    resource_common_data_type: DisputeFlowData,
    request_data_type: DisputeDefendData,
    response_data_type: DisputeResponseData,
    generate_response_fn: generate_defend_dispute_response,
    connector_data_type: T,
    request_data_fn: |p: &DisputeServiceDefendRequest| {
        domain_types::utils::ForeignTryFrom::foreign_try_from(p.clone())
    },
);

/// handle_event — synchronous webhook processing (single-step, no outgoing HTTP).
///
/// The caller supplies the raw webhook body + headers received from the connector
/// and gets back a fully-structured `EventServiceHandleResponse`.
///
/// External source verification (async HTTP used by PayPal / Stripe) is **not**
/// performed here; only local synchronous signature verification is done.
/// The gRPC server performs external verification before calling its equivalent path.
pub fn handle_event_transformer(
    payload: EventServiceHandleRequest,
    _config: &std::sync::Arc<ucs_env::configs::Config>,
    connector: domain_types::connector_types::ConnectorEnum,
    connector_config: domain_types::router_data::ConnectorSpecificConfig,
    _metadata: &common_utils::metadata::MaskedMetadata,
) -> Result<EventServiceHandleResponse, ConnectorResponseTransformationError> {
    use domain_types::utils::ForeignTryFrom as _;

    let request_details =
        payload
            .request_details
            .ok_or_else(|| ConnectorResponseTransformationError {
                error_message: "Missing required field: request_details".to_string(),
                error_code: "MISSING_REQUIRED_FIELD".to_string(),
                http_status_code: None,
            })?;
    let request_details = RequestDetails::foreign_try_from(request_details).map_err(|e| {
        ConnectorResponseTransformationError {
            error_message: format!("ForeignTryFrom failed: {e}"),
            error_code: "CONVERSION_FAILED".to_string(),
            http_status_code: None,
        }
    })?;

    let webhook_secrets = payload
        .webhook_secrets
        .map(|ws| {
            ConnectorWebhookSecrets::foreign_try_from(ws).map_err(|e| {
                ConnectorResponseTransformationError {
                    error_message: format!("ForeignTryFrom failed: {e}"),
                    error_code: "CONVERSION_FAILED".to_string(),
                    http_status_code: None,
                }
            })
        })
        .transpose()?;

    let connector_data: connector_integration::types::ConnectorData<
        domain_types::payment_method_data::DefaultPCIHolder,
    > = connector_integration::types::ConnectorData::get_connector_by_name(&connector);

    // Local synchronous source verification only (no external HTTP call in FFI).
    let source_verified = connector_data
        .connector
        .verify_webhook_source(
            request_details.clone(),
            webhook_secrets.clone(),
            Some(connector_config.clone()),
        )
        .unwrap_or(false);

    connector_integration::webhook_utils::process_webhook_event(
        connector_data,
        request_details,
        webhook_secrets,
        Some(connector_config),
        source_verified,
    )
    .map_err(
        |e: error_stack::Report<domain_types::errors::ApplicationErrorResponse>| {
            ConnectorResponseTransformationError {
                error_message: format!("Error in Processing webhook events: {e}"),
                error_code: "WEBHOOK_PROCESSING_ERROR".to_string(),
                http_status_code: None,
            }
        },
    )
}

// token_authorize — converts token request to base authorize, then processes like regular authorize
req_transformer!(
    fn_name: token_authorize_req_transformer,
    request_type: PaymentServiceTokenAuthorizeRequest,
    flow_marker: Authorize,
    resource_common_data_type: PaymentFlowData,
    request_data_type: PaymentsAuthorizeData<domain_types::payment_method_data::DefaultPCIHolder>,
    response_data_type: PaymentsResponseData,
    connector_data_type: domain_types::payment_method_data::DefaultPCIHolder,
    request_data_fn: |p: &PaymentServiceTokenAuthorizeRequest| {
        let base: PaymentServiceAuthorizeRequest = domain_types::types::tokenized_authorize_to_base(p.clone());
        let auth_req: domain_types::types::AuthorizationRequest = base.clone().into();
        domain_types::types::build_request_data_with_required_pmd(base.payment_method.clone(), auth_req)
    },
);

res_transformer!(
    fn_name: token_authorize_res_transformer,
    request_type: PaymentServiceTokenAuthorizeRequest,
    response_type: PaymentServiceAuthorizeResponse,
    flow_marker: Authorize,
    resource_common_data_type: PaymentFlowData,
    request_data_type: PaymentsAuthorizeData<domain_types::payment_method_data::DefaultPCIHolder>,
    response_data_type: PaymentsResponseData,
    generate_response_fn: generate_payment_authorize_response,
    connector_data_type: domain_types::payment_method_data::DefaultPCIHolder,
    request_data_fn: |p: &PaymentServiceTokenAuthorizeRequest| {
        let base: PaymentServiceAuthorizeRequest = domain_types::types::tokenized_authorize_to_base(p.clone());
        let auth_req: domain_types::types::AuthorizationRequest = base.clone().into();
        domain_types::types::build_request_data_with_required_pmd(base.payment_method.clone(), auth_req)
    },
);

// token_setup_recurring — converts token request to base setup_recurring, then processes like regular setup_recurring
req_transformer!(
    fn_name: token_setup_recurring_req_transformer,
    request_type: PaymentServiceTokenSetupRecurringRequest,
    flow_marker: SetupMandate,
    resource_common_data_type: PaymentFlowData,
    request_data_type: SetupMandateRequestData<domain_types::payment_method_data::DefaultPCIHolder>,
    response_data_type: PaymentsResponseData,
    connector_data_type: domain_types::payment_method_data::DefaultPCIHolder,
    request_data_fn: |p: &PaymentServiceTokenSetupRecurringRequest| {
        let base: PaymentServiceSetupRecurringRequest = domain_types::types::tokenized_setup_recurring_to_base(p.clone());
        domain_types::types::build_request_data_with_required_pmd(base.payment_method.clone(), base)
    },
);

res_transformer!(
    fn_name: token_setup_recurring_res_transformer,
    request_type: PaymentServiceTokenSetupRecurringRequest,
    response_type: PaymentServiceSetupRecurringResponse,
    flow_marker: SetupMandate,
    resource_common_data_type: PaymentFlowData,
    request_data_type: SetupMandateRequestData<domain_types::payment_method_data::DefaultPCIHolder>,
    response_data_type: PaymentsResponseData,
    generate_response_fn: generate_setup_mandate_response,
    connector_data_type: domain_types::payment_method_data::DefaultPCIHolder,
    request_data_fn: |p: &PaymentServiceTokenSetupRecurringRequest| {
        let base: PaymentServiceSetupRecurringRequest = domain_types::types::tokenized_setup_recurring_to_base(p.clone());
        domain_types::types::build_request_data_with_required_pmd(base.payment_method.clone(), base)
    },
);

// proxy_authorize — VaultTokenHolder: the request type carries a vault token, not raw card data
req_transformer!(
    fn_name: proxy_authorize_req_transformer,
    request_type: PaymentServiceProxyAuthorizeRequest,
    flow_marker: Authorize,
    resource_common_data_type: PaymentFlowData,
    request_data_type: PaymentsAuthorizeData<domain_types::payment_method_data::VaultTokenHolder>,
    response_data_type: PaymentsResponseData,
    connector_data_type: domain_types::payment_method_data::VaultTokenHolder,
    request_data_fn: |p: &PaymentServiceProxyAuthorizeRequest| {
        domain_types::utils::ForeignTryFrom::foreign_try_from(p.clone())
    },
);

res_transformer!(
    fn_name: proxy_authorize_res_transformer,
    request_type: PaymentServiceProxyAuthorizeRequest,
    response_type: PaymentServiceAuthorizeResponse,
    flow_marker: Authorize,
    resource_common_data_type: PaymentFlowData,
    request_data_type: PaymentsAuthorizeData<domain_types::payment_method_data::VaultTokenHolder>,
    response_data_type: PaymentsResponseData,
    generate_response_fn: generate_payment_authorize_response,
    connector_data_type: domain_types::payment_method_data::VaultTokenHolder,
    request_data_fn: |p: &PaymentServiceProxyAuthorizeRequest| {
        domain_types::utils::ForeignTryFrom::foreign_try_from(p.clone())
    },
);

// proxy_setup_recurring — VaultTokenHolder: the request type carries a vault token, not raw card data
req_transformer!(
    fn_name: proxy_setup_recurring_req_transformer,
    request_type: PaymentServiceProxySetupRecurringRequest,
    flow_marker: SetupMandate,
    resource_common_data_type: PaymentFlowData,
    request_data_type: SetupMandateRequestData<domain_types::payment_method_data::VaultTokenHolder>,
    response_data_type: PaymentsResponseData,
    connector_data_type: domain_types::payment_method_data::VaultTokenHolder,
    request_data_fn: |p: &PaymentServiceProxySetupRecurringRequest| {
        domain_types::utils::ForeignTryFrom::foreign_try_from(p.clone())
    },
);

res_transformer!(
    fn_name: proxy_setup_recurring_res_transformer,
    request_type: PaymentServiceProxySetupRecurringRequest,
    response_type: PaymentServiceSetupRecurringResponse,
    flow_marker: SetupMandate,
    resource_common_data_type: PaymentFlowData,
    request_data_type: SetupMandateRequestData<domain_types::payment_method_data::VaultTokenHolder>,
    response_data_type: PaymentsResponseData,
    generate_response_fn: generate_setup_mandate_response,
    connector_data_type: domain_types::payment_method_data::VaultTokenHolder,
    request_data_fn: |p: &PaymentServiceProxySetupRecurringRequest| {
        domain_types::utils::ForeignTryFrom::foreign_try_from(p.clone())
    },
);
