// Embedded development config - read at build time via include_str!
// Path goes: flows/ -> src/ -> ffi/ -> backend/ -> project_root -> config/
const EMBEDDED_DEVELOPMENT_CONFIG: &str = include_str!("../../../../config/development.toml");

use crate::macros::{payment_flow, payment_flow_wrapper};

use grpc_api_types::payments::{PaymentServiceAuthorizeRequest, PaymentServiceCaptureRequest};

use crate::types::RequestData;
use domain_types::{
    connector_flow::{Authorize, Capture},
    connector_types::{PaymentsAuthorizeData, PaymentsCaptureData},
    payment_method_data::DefaultPCIHolder,
};
// Generate authorize function using the payment_flow_generic! macro
payment_flow!(
    authorize,
    Authorize,
    PaymentServiceAuthorizeRequest,
    PaymentsAuthorizeData<T>,
    "PAYMENT_AUTHORIZE_ERROR"
);

// Generate capture function using the payment_flow! macro
payment_flow!(
    capture,
    Capture,
    PaymentServiceCaptureRequest,
    PaymentsCaptureData,
    "PAYMENT_CAPTURE_ERROR"
);

// Generate authorize_flow wrapper using payment_flow_wrapper! macro
payment_flow_wrapper!(
    authorize_flow,
    authorize,
    PaymentServiceAuthorizeRequest,
    DefaultPCIHolder
);

// Generate capture_flow wrapper using payment_flow_wrapper! macro
payment_flow_wrapper!(
    capture_flow,
    capture,
    PaymentServiceCaptureRequest,
    DefaultPCIHolder
);
