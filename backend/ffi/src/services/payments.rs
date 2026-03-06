use external_services;
use grpc_api_types::payments::{
    CustomerServiceCreateRequest, CustomerServiceCreateResponse,
    MerchantAuthenticationServiceCreateAccessTokenRequest,
    MerchantAuthenticationServiceCreateAccessTokenResponse, PaymentServiceAuthorizeRequest,
    PaymentServiceAuthorizeResponse, PaymentServiceCaptureRequest, PaymentServiceCaptureResponse,
    PaymentServiceGetRequest, PaymentServiceGetResponse, PaymentServiceRefundRequest,
    PaymentServiceReverseRequest, PaymentServiceReverseResponse, PaymentServiceVoidRequest,
    PaymentServiceVoidResponse, RecurringPaymentServiceChargeRequest,
    RecurringPaymentServiceChargeResponse, RefundResponse,
};

use crate::errors::{FfiError, FfiPaymentError};
use crate::macros::{req_transformer, res_transformer};

use domain_types::{
    connector_flow::{
        Authorize, Capture, CreateAccessToken, CreateConnectorCustomer, PSync, Refund,
        RepeatPayment, Void, VoidPC,
    },
    connector_types::{
        AccessTokenRequestData, AccessTokenResponseData, ConnectorCustomerData,
        ConnectorCustomerResponse, PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData,
        PaymentsCancelPostCaptureData, PaymentsCaptureData, PaymentsResponseData, PaymentsSyncData,
        RefundFlowData, RefundsData, RefundsResponseData, RepeatPaymentData,
    },
};

// authorize request transformer
req_transformer!(
    fn_name: authorize_req_transformer,
    request_type: PaymentServiceAuthorizeRequest,
    flow_marker: Authorize,
    resource_common_data_type: PaymentFlowData,
    request_data_type: PaymentsAuthorizeData<T>,
    response_data_type: PaymentsResponseData,
);

// authorize response transformer
res_transformer!(
    fn_name: authorize_res_transformer,
    request_type: PaymentServiceAuthorizeRequest,
    response_type: PaymentServiceAuthorizeResponse,
    flow_marker: Authorize,
    resource_common_data_type: PaymentFlowData,
    request_data_type: PaymentsAuthorizeData<T>,
    response_data_type: PaymentsResponseData,
    generate_response_fn: generate_payment_authorize_response,
);

// capture request transformer
req_transformer!(
    fn_name: capture_req_transformer,
    request_type: PaymentServiceCaptureRequest,
    flow_marker: Capture,
    resource_common_data_type: PaymentFlowData,
    request_data_type: PaymentsCaptureData,
    response_data_type: PaymentsResponseData,
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
);

// void request transformer
req_transformer!(
    fn_name: void_req_transformer,
    request_type: PaymentServiceVoidRequest,
    flow_marker: Void,
    resource_common_data_type: PaymentFlowData,
    request_data_type: PaymentVoidData,
    response_data_type: PaymentsResponseData,
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
);

// psync request transformer
req_transformer!(
    fn_name: get_req_transformer,
    request_type: PaymentServiceGetRequest,
    flow_marker: PSync,
    resource_common_data_type: PaymentFlowData,
    request_data_type: PaymentsSyncData,
    response_data_type: PaymentsResponseData,
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
);

// create access token request transformer
req_transformer!(
    fn_name: create_access_token_req_transformer,
    request_type: MerchantAuthenticationServiceCreateAccessTokenRequest,
    flow_marker: CreateAccessToken,
    resource_common_data_type: PaymentFlowData,
    request_data_type: AccessTokenRequestData,
    response_data_type: AccessTokenResponseData,
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
);

// refund request transformer
req_transformer!(
    fn_name: refund_req_transformer,
    request_type: PaymentServiceRefundRequest,
    flow_marker: Refund,
    resource_common_data_type: RefundFlowData,
    request_data_type: RefundsData,
    response_data_type: RefundsResponseData,
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
);

// reverse (void post-capture) request transformer
req_transformer!(
    fn_name: reverse_req_transformer,
    request_type: PaymentServiceReverseRequest,
    flow_marker: VoidPC,
    resource_common_data_type: PaymentFlowData,
    request_data_type: PaymentsCancelPostCaptureData,
    response_data_type: PaymentsResponseData,
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
);

// create connector customer request transformer
req_transformer!(
    fn_name: create_req_transformer,
    request_type: CustomerServiceCreateRequest,
    flow_marker: CreateConnectorCustomer,
    resource_common_data_type: PaymentFlowData,
    request_data_type: ConnectorCustomerData,
    response_data_type: ConnectorCustomerResponse,
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
);

// repeat payment (charge) request transformer
req_transformer!(
    fn_name: charge_req_transformer,
    request_type: RecurringPaymentServiceChargeRequest,
    flow_marker: RepeatPayment,
    resource_common_data_type: PaymentFlowData,
    request_data_type: RepeatPaymentData<T>,
    response_data_type: PaymentsResponseData,
);

// repeat payment (charge) response transformer
res_transformer!(
    fn_name: charge_res_transformer,
    request_type: RecurringPaymentServiceChargeRequest,
    response_type: RecurringPaymentServiceChargeResponse,
    flow_marker: RepeatPayment,
    resource_common_data_type: PaymentFlowData,
    request_data_type: RepeatPaymentData<T>,
    response_data_type: PaymentsResponseData,
    generate_response_fn: generate_repeat_payment_response,
);
