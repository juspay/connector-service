use crate::flows::payments::{authorize_flow, capture_flow};
use crate::macros::napi_handler;

use external_services;
use grpc_api_types::payments::{PaymentServiceAuthorizeRequest, PaymentServiceCaptureRequest};

#[cfg(feature = "napi")]
mod napi_bindings {
    use super::*;

    napi_handler!(
        authorize,
        PaymentServiceAuthorizeRequest,
        JsRequest,
        authorize_flow
    );

    napi_handler!(
        capture,
        PaymentServiceCaptureRequest,
        JsRequest,
        capture_flow
    );
}

#[cfg(feature = "napi")]
pub use napi_bindings::*;
