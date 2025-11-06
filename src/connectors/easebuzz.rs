mod transformers;

use std::fmt::Debug;

use common_enums::{AttemptStatus, CaptureMethod, PaymentMethod, PaymentMethodType};
use common_utils::{errors::CustomResult, ext_traits::ByteSliceExt, request::RequestContent};
use domain_types::{
    connector_flow::{
        Accept, Authorize, Capture, CreateOrder, CreateSessionToken, DefendDispute, PSync, RSync,
        Refund, RepeatPayment, SetupMandate, SubmitEvidence, Void,
    },
    connector_types::{
        AcceptDisputeData, ConnectorSpecifications, ConnectorWebhookSecrets, DisputeDefendData,
        DisputeFlowData, DisputeResponseData, EventType, PaymentCreateOrderData,
        PaymentCreateOrderResponse, PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData,
        PaymentsCaptureData, PaymentsResponseData, PaymentsSyncData, RefundFlowData,
        RefundSyncData, RefundWebhookDetailsResponse, RefundsData, RefundsResponseData,
        RepeatPaymentData, RequestDetails, ResponseId, SessionTokenRequestData,
        SessionTokenResponseData, SetupMandateRequestData, SubmitEvidenceData,
    },
    payment_method_data::PaymentMethodDataTypes,
    router_data_v2::RouterDataV2,
    types::{
        PaymentSyncData, PaymentsAuthorizeType, PaymentsCaptureType, PaymentsCompleteAuthorizeType,
        RefundsType, SetupMandateType,
    },
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, Secret};
use serde::{Deserialize, Serialize};

use crate::{
    constants::headers,
    core::errors::{self, CustomResult as CoreCustomResult},
    types::{self, api, ConnectorCommon, Response},
    utils,
};

pub mod constants;

pub use self::transformers::*;

// Stub types for unsupported flows - MANDATORY to avoid compilation errors
#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzVoidRequest;
#[derive(Debug, Clone, Deserialize)]
pub struct EaseBuzzVoidResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzCaptureRequest;
#[derive(Debug, Clone, Deserialize)]
pub struct EaseBuzzCaptureResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzRefundRequest;
#[derive(Debug, Clone, Deserialize)]
pub struct EaseBuzzRefundResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzRefundSyncRequest;
#[derive(Debug, Clone, Deserialize)]
pub struct EaseBuzzRefundSyncResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzCreateOrderRequest;
#[derive(Debug, Clone, Deserialize)]
pub struct EaseBuzzCreateOrderResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzSessionTokenRequest;
#[derive(Debug, Clone, Deserialize)]
pub struct EaseBuzzSessionTokenResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzSetupMandateRequest;
#[derive(Debug, Clone, Deserialize)]
pub struct EaseBuzzSetupMandateResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzRepeatPaymentRequest;
#[derive(Debug, Clone, Deserialize)]
pub struct EaseBuzzRepeatPaymentResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzAcceptDisputeRequest;
#[derive(Debug, Clone, Deserialize)]
pub struct EaseBuzzAcceptDisputeResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzDefendDisputeRequest;
#[derive(Debug, Clone, Deserialize)]
pub struct EaseBuzzDefendDisputeResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzSubmitEvidenceRequest;
#[derive(Debug, Clone, Deserialize)]
pub struct EaseBuzzSubmitEvidenceResponse;

// CRITICAL: Use UCS v2 macro framework - NO manual implementations
crate::macros::create_all_prerequisites!(
    connector_name: EaseBuzz,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: EaseBuzzPaymentsRequest,
            response_body: EaseBuzzPaymentsResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: PSync,
            request_body: EaseBuzzPaymentsSyncRequest,
            response_body: EaseBuzzPaymentsSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ),
        (
            flow: Void,
            request_body: EaseBuzzVoidRequest,
            response_body: EaseBuzzVoidResponse,
            router_data: RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        ),
        (
            flow: Capture,
            request_body: EaseBuzzCaptureRequest,
            response_body: EaseBuzzCaptureResponse,
            router_data: RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        ),
        (
            flow: Refund,
            request_body: EaseBuzzRefundRequest,
            response_body: EaseBuzzRefundResponse,
            router_data: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ),
        (
            flow: RSync,
            request_body: EaseBuzzRefundSyncRequest,
            response_body: EaseBuzzRefundSyncResponse,
            router_data: RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ),
        (
            flow: CreateOrder,
            request_body: EaseBuzzCreateOrderRequest,
            response_body: EaseBuzzCreateOrderResponse,
            router_data: RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>,
        ),
        (
            flow: CreateSessionToken,
            request_body: EaseBuzzSessionTokenRequest,
            response_body: EaseBuzzSessionTokenResponse,
            router_data: RouterDataV2<CreateSessionToken, PaymentFlowData, SessionTokenRequestData, SessionTokenResponseData>,
        ),
        (
            flow: SetupMandate,
            request_body: EaseBuzzSetupMandateRequest,
            response_body: EaseBuzzSetupMandateResponse,
            router_data: RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>,
        ),
        (
            flow: RepeatPayment,
            request_body: EaseBuzzRepeatPaymentRequest,
            response_body: EaseBuzzRepeatPaymentResponse,
            router_data: RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>,
        ),
        (
            flow: Accept,
            request_body: EaseBuzzAcceptDisputeRequest,
            response_body: EaseBuzzAcceptDisputeResponse,
            router_data: RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>,
        ),
        (
            flow: DefendDispute,
            request_body: EaseBuzzDefendDisputeRequest,
            response_body: EaseBuzzDefendDisputeResponse,
            router_data: RouterDataV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>,
        ),
        (
            flow: SubmitEvidence,
            request_body: EaseBuzzSubmitEvidenceRequest,
            response_body: EaseBuzzSubmitEvidenceResponse,
            router_data: RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>,
        )
    ],
    amount_converters: [
        amount_converter: StringMajorUnit  // EaseBuzz expects amount in major units as string
    ],
    member_functions: {
        get_currency_unit: |_currency: domain_types::router_data::Currency| -> Result<crate::types::api::CurrencyUnit, crate::core::errors::ConnectorError> {
            Ok(crate::types::api::CurrencyUnit::Major)
        },

        connector_webhook_details: || -> Option<ConnectorWebhookSecrets> {
            None
        },

        connector_specifications: || -> ConnectorSpecifications {
            ConnectorSpecifications {
                supports_network_tokenization: false,
                supported_countries: vec![
                    common_enums::CountryAlpha2::IN,
                ],
                supported_payment_methods: vec![
                    PaymentMethod::Upi,
                ],
                supported_payment_method_types: std::collections::HashMap::from([
                    (PaymentMethod::Upi, vec![PaymentMethodType::UpiIntent, PaymentMethodType::UpiCollect]),
                ]),
                supported_flows: &[
                    common_enums::PaymentFlow::Upi,
                ],
                supported_features: vec![
                    common_enums::ConnectorFeatures::UpiIntent,
                    common_enums::ConnectorFeatures::UpiCollect,
                ],
            }
        },

        get_api_tag: |flow: &str| -> &'static str {
            match flow {
                "Authorize" => "payments_initiate",
                "PSync" => "payments_sync",
                "RSync" => "refunds_sync",
                "Refund" => "refunds",
                _ => flow
            }
        }
    }
);

// MANDATORY: Use macro for each implemented flow
crate::macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: EaseBuzz,
    curl_request: Json(EaseBuzzPaymentsRequest),
    curl_response: EaseBuzzPaymentsResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
    other_functions: {
        get_request_body: |req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, _connector: &EaseBuzz<T>| -> CustomResult<RequestContent, errors::ConnectorError> {
            let connector_req = req.try_into()?;
            Ok(RequestContent::Json(Box::new(connector_req)))
        },

        build_request_v2: |req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, connector: &EaseBuzz<T>| -> CustomResult<Option<common_utils::request::Request>, errors::ConnectorError> {
            let request = common_utils::request::RequestBuilder::new()
                .method(common_utils::request::Method::Post)
                .url(&types::PaymentsAuthorizeType::get_url(connector, req)?)
                .attach_default_headers()
                .headers(types::PaymentsAuthorizeType::get_headers(connector, req)?)
                .set_body(types::PaymentsAuthorizeType::get_request_body(connector, req, req)?)
                .build();
            Ok(Some(request))
        },

        handle_response_v2: |data: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, _connector: &EaseBuzz<T>, res: Response| -> CustomResult<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, errors::ConnectorError> {
            let response: EaseBuzzPaymentsResponse = res
                .response
                .parse_struct("EaseBuzzPaymentsResponse")
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
            
            let response_data: PaymentsResponseData = response.try_into()?;
            
            Ok(RouterDataV2 {
                router_data: data.router_data.clone(),
                amount: data.amount,
                connector: data.connector.clone(),
                resource_common_data: data.resource_common_data.clone(),
                response: Ok(response_data),
            })
        },

        get_url: |req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, connector: &EaseBuzz<T>| -> CustomResult<String, errors::ConnectorError> {
            let is_test = req.resource_common_data.test_mode.unwrap_or(false);
            Ok(format!("{}/payment/initiateLink", if is_test { constants::SANDBOX_BASE_URL } else { constants::BASE_URL }))
        },

        get_headers: |_req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, _connector: &EaseBuzz<T>| -> CustomResult<Vec<(String, common_utils::request::Maskable<String>)>, errors::ConnectorError> {
            let header = vec![
                (headers::CONTENT_TYPE.to_string(), "application/json".to_string().into()),
                (headers::ACCEPT.to_string(), "application/json".to_string().into()),
            ];
            Ok(header)
        }
    }
);

crate::macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type, get_error_response_v2],
    connector: EaseBuzz,
    curl_request: Json(EaseBuzzPaymentsSyncRequest),
    curl_response: EaseBuzzPaymentsSyncResponse,
    flow_name: PSync,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsSyncData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize],
    other_functions: {
        get_request_body: |req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, _connector: &EaseBuzz<T>| -> CustomResult<RequestContent, errors::ConnectorError> {
            let connector_req = req.try_into()?;
            Ok(RequestContent::Json(Box::new(connector_req)))
        },

        build_request_v2: |req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, connector: &EaseBuzz<T>| -> CustomResult<Option<common_utils::request::Request>, errors::ConnectorError> {
            let request = common_utils::request::RequestBuilder::new()
                .method(common_utils::request::Method::Post)
                .url(&types::PaymentsSyncType::get_url(connector, req)?)
                .attach_default_headers()
                .headers(types::PaymentsSyncType::get_headers(connector, req)?)
                .set_body(types::PaymentsSyncType::get_request_body(connector, req, req)?)
                .build();
            Ok(Some(request))
        },

        handle_response_v2: |data: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, _connector: &EaseBuzz<T>, res: Response| -> CustomResult<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, errors::ConnectorError> {
            let response: EaseBuzzPaymentsSyncResponse = res
                .response
                .parse_struct("EaseBuzzPaymentsSyncResponse")
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
            
            let response_data: PaymentsResponseData = response.try_into()?;
            
            Ok(RouterDataV2 {
                router_data: data.router_data.clone(),
                amount: data.amount,
                connector: data.connector.clone(),
                resource_common_data: data.resource_common_data.clone(),
                response: Ok(response_data),
            })
        },

        get_url: |req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, connector: &EaseBuzz<T>| -> CustomResult<String, errors::ConnectorError> {
            let is_test = req.resource_common_data.test_mode.unwrap_or(false);
            Ok(format!("{}/transaction/v1/retrieve", if is_test { constants::SANDBOX_BASE_URL } else { constants::BASE_URL }))
        },

        get_headers: |_req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, _connector: &EaseBuzz<T>| -> CustomResult<Vec<(String, common_utils::request::Maskable<String>)>, errors::ConnectorError> {
            let header = vec![
                (headers::CONTENT_TYPE.to_string(), "application/json".to_string().into()),
                (headers::ACCEPT.to_string(), "application/json".to_string().into()),
            ];
            Ok(header)
        }
    }
);

// MANDATORY: Implement all connector_types traits even for unused flows
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::PaymentOrderCreate for EaseBuzz<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::PaymentSessionToken for EaseBuzz<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::PaymentVoidV2 for EaseBuzz<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::PaymentCaptureV2 for EaseBuzz<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::RefundV2 for EaseBuzz<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::RefundSyncV2 for EaseBuzz<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::PaymentSetupMandate for EaseBuzz<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::PaymentRepeat for EaseBuzz<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    connector_types::DisputeConnector for EaseBuzz<T> {}

// MANDATORY: Add manual implementations that return NotImplemented errors for unimplemented flows
macro_rules! impl_not_implemented_flow {
    ($flow:ty, $common_data:ty, $req:ty, $resp:ty) => {
        impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
            crate::types::ConnectorIntegrationV2<$flow, $common_data, $req, $resp> for EaseBuzz<T>
        {
            fn build_request_v2(
                &self,
                _req: &RouterDataV2<$flow, $common_data, $req, $resp>,
            ) -> CustomResult<Option<common_utils::request::Request>, errors::ConnectorError> {
                let flow_name = stringify!($flow);
                Err(errors::ConnectorError::NotImplemented(format!("{} flow not implemented", flow_name)).into())
            }
        }
    };
}

// Use macro for all unimplemented flows
impl_not_implemented_flow!(Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData);
impl_not_implemented_flow!(Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData);
impl_not_implemented_flow!(Refund, RefundFlowData, RefundsData, RefundsResponseData);
impl_not_implemented_flow!(RSync, RefundFlowData, RefundSyncData, RefundsResponseData);
impl_not_implemented_flow!(CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse);
impl_not_implemented_flow!(CreateSessionToken, PaymentFlowData, SessionTokenRequestData, SessionTokenResponseData);
impl_not_implemented_flow!(SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData);
impl_not_implemented_flow!(RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData);
impl_not_implemented_flow!(Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData);
impl_not_implemented_flow!(DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData);
impl_not_implemented_flow!(SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData);

// CRITICAL: Add impl_source_verification_stub! for ALL flows
crate::macros::impl_source_verification_stub!(Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData);
crate::macros::impl_source_verification_stub!(PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData);
crate::macros::impl_source_verification_stub!(Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData);
crate::macros::impl_source_verification_stub!(Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData);
crate::macros::impl_source_verification_stub!(Refund, RefundFlowData, RefundsData, RefundsResponseData);
crate::macros::impl_source_verification_stub!(RSync, RefundFlowData, RefundSyncData, RefundsResponseData);
crate::macros::impl_source_verification_stub!(CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse);
crate::macros::impl_source_verification_stub!(CreateSessionToken, PaymentFlowData, SessionTokenRequestData, SessionTokenResponseData);
crate::macros::impl_source_verification_stub!(SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData);
crate::macros::impl_source_verification_stub!(RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData);
crate::macros::impl_source_verification_stub!(Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData);
crate::macros::impl_source_verification_stub!(DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData);
crate::macros::impl_source_verification_stub!(SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData);

// Custom ConnectorCommon implementation for EaseBuzz-specific logic
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    ConnectorCommon for EaseBuzz<T>
{
    fn id(&self) -> &'static str {
        "easebuzz"
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn base_url<'a>(&self, _connectors: &'a crate::types::api::ConnectorsConfig) -> &'a str {
        // This will be overridden by get_url in each flow
        constants::BASE_URL
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut crate::types::api::ConnectorEvent>,
    ) -> CustomResult<crate::types::ErrorResponse, errors::ConnectorError> {
        let response: Result<EaseBuzzErrorResponse, error_stack::Report<common_utils::errors::ParsingError>> =
            res.response.parse_struct("EaseBuzzErrorResponse");

        match response {
            Ok(error_res) => {
                event_builder.map(|e| e.set_error_response_body(&error_res));
                Ok(crate::types::ErrorResponse {
                    status_code: res.status_code,
                    code: error_res.error_code.unwrap_or_else(|| "UNKNOWN_ERROR".to_string()),
                    message: error_res.error_desc.unwrap_or_else(|| "Unknown error occurred".to_string()),
                    reason: error_res.reason,
                    attempt_status: Some(AttemptStatus::Failure),
                    connector_transaction_id: None,
                })
            }
            Err(_) => {
                let error_response = serde_json::Value::String(res.response.clone());
                event_builder.map(|event| event.set_error_response_body(&error_response));
                Ok(crate::types::ErrorResponse {
                    status_code: res.status_code,
                    code: "UNKNOWN_ERROR".to_string(),
                    message: "Unknown error occurred".to_string(),
                    reason: Some(res.response),
                    attempt_status: Some(AttemptStatus::Failure),
                    connector_transaction_id: None,
                })
            }
        }
    }
}