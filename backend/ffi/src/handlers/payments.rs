pub const EMBEDDED_DEVELOPMENT_CONFIG: &str = include_str!("../../../../config/development.toml");
pub const EMBEDDED_PROD_CONFIG: &str = include_str!("../../../../config/production.toml");

use grpc_api_types::payments::{
    PaymentServiceAuthorizeRequest, PaymentServiceAuthorizeResponse, PaymentServiceCaptureRequest,
    PaymentServiceCaptureResponse, PaymentServiceCreateAccessTokenRequest,
    PaymentServiceCreateAccessTokenResponse, PaymentServiceGetRequest, PaymentServiceGetResponse,
    PaymentServiceRefundRequest, PaymentServiceVoidRequest, PaymentServiceVoidResponse,
    RefundResponse,
};

use crate::services::payments::{
    access_token_req_transformer, access_token_res_transformer, authorize_req_transformer,
    authorize_res_transformer, capture_req_transformer, capture_res_transformer,
    get_req_transformer, get_res_transformer, refund_req_transformer, refund_res_transformer,
    void_req_transformer, void_res_transformer,
};

use crate::errors::FfiPaymentError;
use crate::types::FfiRequestData;
use domain_types::payment_method_data::DefaultPCIHolder;
// authorize_req handler
pub fn authorize_req_handler(
    test_mode: Option<bool>,
    request: FfiRequestData<PaymentServiceAuthorizeRequest>,
) -> Result<Option<common_utils::request::Request>, FfiPaymentError> {
    let config_str = if test_mode == Some(false) {
        EMBEDDED_PROD_CONFIG
    } else {
        EMBEDDED_DEVELOPMENT_CONFIG
    };
    let config = crate::utils::load_config(config_str)?;
    // PCI and NON PCI clients need to be determined
    authorize_req_transformer::<DefaultPCIHolder>(
        request.payload,
        &config,
        request.extracted_metadata.connector,
        request.extracted_metadata.connector_auth_type,
        &request.masked_metadata.unwrap_or_default(),
    )
}

// authorize_res handler
pub fn authorize_res_handler(
    test_mode: Option<bool>,
    request: FfiRequestData<PaymentServiceAuthorizeRequest>,
    response: domain_types::router_response_types::Response,
) -> Result<PaymentServiceAuthorizeResponse, FfiPaymentError> {
    let config_str = if test_mode == Some(false) {
        EMBEDDED_PROD_CONFIG
    } else {
        EMBEDDED_DEVELOPMENT_CONFIG
    };
    let config = crate::utils::load_config(config_str)?;
    // PCI and NON PCI clients need to be determined
    authorize_res_transformer::<DefaultPCIHolder>(
        request.payload,
        &config,
        request.extracted_metadata.connector,
        request.extracted_metadata.connector_auth_type,
        &request.masked_metadata.unwrap_or_default(),
        response,
    )
}

// capture_req handler
pub fn capture_req_handler(
    test_mode: Option<bool>,
    request: FfiRequestData<PaymentServiceCaptureRequest>,
) -> Result<Option<common_utils::request::Request>, FfiPaymentError> {
    let config_str = if test_mode == Some(false) {
        EMBEDDED_PROD_CONFIG
    } else {
        EMBEDDED_DEVELOPMENT_CONFIG
    };
    let config = crate::utils::load_config(config_str)?;
    // PCI and NON PCI clients need to be determined
    capture_req_transformer::<DefaultPCIHolder>(
        request.payload,
        &config,
        request.extracted_metadata.connector,
        request.extracted_metadata.connector_auth_type,
        &request.masked_metadata.unwrap_or_default(),
    )
}

// capture_res handler
pub fn capture_res_handler(
    test_mode: Option<bool>,
    request: FfiRequestData<PaymentServiceCaptureRequest>,
    response: domain_types::router_response_types::Response,
) -> Result<PaymentServiceCaptureResponse, FfiPaymentError> {
    let config_str = if test_mode == Some(false) {
        EMBEDDED_PROD_CONFIG
    } else {
        EMBEDDED_DEVELOPMENT_CONFIG
    };
    let config = crate::utils::load_config(config_str)?;
    // PCI and NON PCI clients need to be determined
    capture_res_transformer::<DefaultPCIHolder>(
        request.payload,
        &config,
        request.extracted_metadata.connector,
        request.extracted_metadata.connector_auth_type,
        &request.masked_metadata.unwrap_or_default(),
        response,
    )
}

// void_req handler
pub fn void_req_handler(
    test_mode: Option<bool>,
    request: FfiRequestData<PaymentServiceVoidRequest>,
) -> Result<Option<common_utils::request::Request>, FfiPaymentError> {
    let config_str = if test_mode == Some(false) {
        EMBEDDED_PROD_CONFIG
    } else {
        EMBEDDED_DEVELOPMENT_CONFIG
    };
    let config = crate::utils::load_config(config_str)?;
    void_req_transformer::<DefaultPCIHolder>(
        request.payload,
        &config,
        request.extracted_metadata.connector,
        request.extracted_metadata.connector_auth_type,
        &request.masked_metadata.unwrap_or_default(),
    )
}

// void_res handler
pub fn void_res_handler(
    test_mode: Option<bool>,
    request: FfiRequestData<PaymentServiceVoidRequest>,
    response: domain_types::router_response_types::Response,
) -> Result<PaymentServiceVoidResponse, FfiPaymentError> {
    let config_str = if test_mode == Some(false) {
        EMBEDDED_PROD_CONFIG
    } else {
        EMBEDDED_DEVELOPMENT_CONFIG
    };
    let config = crate::utils::load_config(config_str)?;
    void_res_transformer::<DefaultPCIHolder>(
        request.payload,
        &config,
        request.extracted_metadata.connector,
        request.extracted_metadata.connector_auth_type,
        &request.masked_metadata.unwrap_or_default(),
        response,
    )
}

// get_req handler
pub fn get_req_handler(
    test_mode: Option<bool>,
    request: FfiRequestData<PaymentServiceGetRequest>,
) -> Result<Option<common_utils::request::Request>, FfiPaymentError> {
    let config_str = if test_mode == Some(false) {
        EMBEDDED_PROD_CONFIG
    } else {
        EMBEDDED_DEVELOPMENT_CONFIG
    };
    let config = crate::utils::load_config(config_str)?;
    get_req_transformer::<DefaultPCIHolder>(
        request.payload,
        &config,
        request.extracted_metadata.connector,
        request.extracted_metadata.connector_auth_type,
        &request.masked_metadata.unwrap_or_default(),
    )
}

// get_res handler
pub fn get_res_handler(
    test_mode: Option<bool>,
    request: FfiRequestData<PaymentServiceGetRequest>,
    response: domain_types::router_response_types::Response,
) -> Result<PaymentServiceGetResponse, FfiPaymentError> {
    let config_str = if test_mode == Some(false) {
        EMBEDDED_PROD_CONFIG
    } else {
        EMBEDDED_DEVELOPMENT_CONFIG
    };
    let config = crate::utils::load_config(config_str)?;
    get_res_transformer::<DefaultPCIHolder>(
        request.payload,
        &config,
        request.extracted_metadata.connector,
        request.extracted_metadata.connector_auth_type,
        &request.masked_metadata.unwrap_or_default(),
        response,
    )
}

// create_access_token_req handler
pub fn create_access_token_req_handler(
    test_mode: Option<bool>,
    request: FfiRequestData<PaymentServiceCreateAccessTokenRequest>,
) -> Result<Option<common_utils::request::Request>, FfiPaymentError> {
    let config_str = if test_mode == Some(false) {
        EMBEDDED_PROD_CONFIG
    } else {
        EMBEDDED_DEVELOPMENT_CONFIG
    };
    let config = crate::utils::load_config(config_str)?;
    access_token_req_transformer::<DefaultPCIHolder>(
        request.payload,
        &config,
        request.extracted_metadata.connector,
        request.extracted_metadata.connector_auth_type,
        &request.masked_metadata.unwrap_or_default(),
    )
}

// create_access_token_res handler
pub fn create_access_token_res_handler(
    test_mode: Option<bool>,
    request: FfiRequestData<PaymentServiceCreateAccessTokenRequest>,
    response: domain_types::router_response_types::Response,
) -> Result<PaymentServiceCreateAccessTokenResponse, FfiPaymentError> {
    let config_str = if test_mode == Some(false) {
        EMBEDDED_PROD_CONFIG
    } else {
        EMBEDDED_DEVELOPMENT_CONFIG
    };
    let config = crate::utils::load_config(config_str)?;
    access_token_res_transformer::<DefaultPCIHolder>(
        request.payload,
        &config,
        request.extracted_metadata.connector,
        request.extracted_metadata.connector_auth_type,
        &request.masked_metadata.unwrap_or_default(),
        response,
    )
}

// refund_req handler
pub fn refund_req_handler(
    test_mode: Option<bool>,
    request: FfiRequestData<PaymentServiceRefundRequest>,
) -> Result<Option<common_utils::request::Request>, FfiPaymentError> {
    let config_str = if test_mode == Some(false) {
        EMBEDDED_PROD_CONFIG
    } else {
        EMBEDDED_DEVELOPMENT_CONFIG
    };
    let config = crate::utils::load_config(config_str)?;
    refund_req_transformer::<DefaultPCIHolder>(
        request.payload,
        &config,
        request.extracted_metadata.connector,
        request.extracted_metadata.connector_auth_type,
        &request.masked_metadata.unwrap_or_default(),
    )
}

// refund_res handler
pub fn refund_res_handler(
    test_mode: Option<bool>,
    request: FfiRequestData<PaymentServiceRefundRequest>,
    response: domain_types::router_response_types::Response,
) -> Result<RefundResponse, FfiPaymentError> {
    let config_str = if test_mode == Some(false) {
        EMBEDDED_PROD_CONFIG
    } else {
        EMBEDDED_DEVELOPMENT_CONFIG
    };
    let config = crate::utils::load_config(config_str)?;
    refund_res_transformer::<DefaultPCIHolder>(
        request.payload,
        &config,
        request.extracted_metadata.connector,
        request.extracted_metadata.connector_auth_type,
        &request.masked_metadata.unwrap_or_default(),
        response,
    )
}
