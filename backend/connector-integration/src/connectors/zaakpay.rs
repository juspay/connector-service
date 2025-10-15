pub mod transformers;

use common_enums::{AttemptStatus, PaymentMethodType};
use common_utils::{
    errors::CustomResult,
    ext_traits::ByteSliceExt,
    request::RequestContent,
    types::{self, StringMinorUnit},
};
use domain_types::{
    connector_flow::{Authorize, PSync, RSync},
    connector_types::{
        ConnectorWebhookSecrets, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData,
        PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsResponseData,
    },
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
};
use error_stack::ResultExt;
use hyperswitch_masking::Secret;

use serde::{Deserialize, Serialize};

use crate::{with_error_response_body};

use super::macros;

#[derive(Debug, Clone)]
pub struct ZaakPay<T> {
    amount_converter: &'static (dyn types::AmountConvertor<Output = String> + Sync),
    connector_name: &'static str,
    payment_method_data: std::marker::PhantomData<T>,
}

impl<T> interfaces::api::ConnectorCommon for ZaakPay<T>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize,
{
    fn id(&self) -> &'static str {
        self.connector_name
    }

    fn get_currency_unit(&self) -> common_enums::CurrencyUnit {
        common_enums::CurrencyUnit::Minor
    }

    fn get_auth_header(
        &self,
        _auth_type: &domain_types::router_data::ConnectorAuthType,
    ) -> CustomResult<Vec<(String, String)>, errors::ConnectorError> {
        Ok(vec![])
    }

    fn base_url<'a>(&self, _req: &'a domain_types::router_data::ConnectorData) -> &'a str {
        "https://api.zaakpay.com"
    }
}





impl<T> interfaces::connector_integration_v2::ConnectorIntegrationV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
    for ZaakPay<T>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize,
{
    fn build_request_v2(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    ) -> CustomResult<Option<services::Request>, errors::ConnectorError> {
        let request = transformers::ZaakPayPaymentsRequest::try_from(req)?;
        let url = self.base_url(&domain_types::router_data::ConnectorCommonData {
            connector_name: self.connector_name,
            resource_common_data: &req.router_data.resource_common_data,
            connector_auth_type: &req.router_data.connector_auth_type,
            test_mode: req.router_data.resource_common_data.test_mode,
        }) + "/transaction/.do";
        Ok(Some(services::RequestBuilder::new()
            .method(services::Method::Post)
            .url(&url)
            .attach_default_headers()
            .set_body(RequestContent::Json(request))
            .build()))
    }

    fn handle_response_v2(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        res: Response,
        _event_builder: Option<&mut interfaces::events::connector_api_logs::ConnectorEvent>,
    ) -> CustomResult<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, errors::ConnectorError> {
        let response: transformers::ZaakPayPaymentsResponse = res
            .response
            .parse_struct("ZaakPayPaymentsResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        
        let router_response = domain_types::connector_types::PaymentsResponseData::try_from(response)?;
        Ok(req.clone().with_response(router_response))
    }

    fn get_error_response_v2(
        &self,
        res: &[u8],
        _event_builder: Option<&mut interfaces::events::connector_api_logs::ConnectorEvent>,
    ) -> CustomResult<errors::ConnectorError, errors::ConnectorError> {
        self.get_error_response_v2(res)
    }
}

impl<T> interfaces::connector_integration_v2::ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    for ZaakPay<T>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize,
{
    fn build_request_v2(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<Option<services::Request>, errors::ConnectorError> {
        let request = transformers::ZaakPayPaymentsSyncRequest::try_from(req)?;
        let url = self.base_url(&utils::ConnectorCommonData {
            connector_name: self.connector_name,
            resource_common_data: &req.router_data.resource_common_data,
            connector_auth_type: &req.router_data.connector_auth_type,
            test_mode: req.router_data.resource_common_data.test_mode,
        }) + "/status.do";
        Ok(Some(services::RequestBuilder::new()
            .method(services::Method::Post)
            .url(&url)
            .attach_default_headers()
            .set_body(RequestContent::Json(request))
            .build()))
    }

    fn handle_response_v2(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        res: Response,
        _event_builder: Option<&mut interfaces::events::connector_api_logs::ConnectorEvent>,
    ) -> CustomResult<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, errors::ConnectorError> {
        let response: transformers::ZaakPayPaymentsSyncResponse = res
            .response
            .parse_struct("ZaakPayPaymentsSyncResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        
        let router_response = domain_types::connector_types::PaymentsResponseData::try_from(response)?;
        Ok(req.clone().with_response(router_response))
    }

    fn get_error_response_v2(
        &self,
        res: &[u8],
        _event_builder: Option<&mut interfaces::events::connector_api_logs::ConnectorEvent>,
    ) -> CustomResult<errors::ConnectorError, errors::ConnectorError> {
        self.get_error_response_v2(res)
    }
}

impl<T> interfaces::connector_integration_v2::ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
    for ZaakPay<T>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize,
{
    fn build_request_v2(
        &self,
        req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
    ) -> CustomResult<Option<services::Request>, errors::ConnectorError> {
        let request = transformers::ZaakPayRefundSyncRequest::try_from(req)?;
        let url = self.base_url(&utils::ConnectorCommonData {
            connector_name: self.connector_name,
            resource_common_data: &req.router_data.resource_common_data,
            connector_auth_type: &req.router_data.connector_auth_type,
            test_mode: req.router_data.resource_common_data.test_mode,
        }) + "/status.do";
        Ok(Some(services::RequestBuilder::new()
            .method(services::Method::Post)
            .url(&url)
            .attach_default_headers()
            .set_body(RequestContent::Json(request))
            .build()))
    }

    fn handle_response_v2(
        &self,
        req: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        res: Response,
        _event_builder: Option<&mut interfaces::events::connector_api_logs::ConnectorEvent>,
    ) -> CustomResult<RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>, errors::ConnectorError> {
        let response: transformers::ZaakPayRefundSyncResponse = res
            .response
            .parse_struct("ZaakPayRefundSyncResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        
        let router_response = RefundsResponseData::try_from(response)?;
        Ok(req.clone().with_response(router_response))
    }

    fn get_error_response_v2(
        &self,
        res: &[u8],
        _event_builder: Option<&mut interfaces::events::connector_api_logs::ConnectorEvent>,
    ) -> CustomResult<errors::ConnectorError, errors::ConnectorError> {
        self.get_error_response_v2(res)
    }
}

// Stub implementations for unsupported flows
macro_rules! impl_not_implemented_flow {
    ($flow:ty, $common_data:ty, $req:ty, $resp:ty) => {
        impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
            interfaces::connector_integration_v2::ConnectorIntegrationV2<$flow, $common_data, $req, $resp> for ZaakPay<T>
        {
            fn build_request_v2(
                &self,
                _req: &RouterDataV2<$flow, $common_data, $req, $resp>,
            ) -> CustomResult<Option<services::Request>, errors::ConnectorError> {
                let flow_name = stringify!($flow);
                Err(errors::ConnectorError::NotImplemented(flow_name.to_string()).into())
            }

            fn handle_response_v2(
                &self,
                _req: &RouterDataV2<$flow, $common_data, $req, $resp>,
                _res: Response,
                _event_builder: Option<&mut interfaces::events::connector_api_logs::ConnectorEvent>,
            ) -> CustomResult<RouterDataV2<$flow, $common_data, $req, $resp>, errors::ConnectorError> {
                let flow_name = stringify!($flow);
                Err(errors::ConnectorError::NotImplemented(flow_name.to_string()).into())
            }

            fn get_error_response_v2(
                &self,
                _res: &[u8],
                _event_builder: Option<&mut interfaces::events::connector_api_logs::ConnectorEvent>,
            ) -> CustomResult<errors::ConnectorError, errors::ConnectorError> {
                Ok(errors::ConnectorError::NotImplemented("Error handling not implemented".to_string()))
            }
        }
    };
}

impl_not_implemented_flow!(interfaces::connector_types::Void, PaymentFlowData, interfaces::connector_types::PaymentVoidData, PaymentsResponseData);
impl_not_implemented_flow!(interfaces::connector_types::Capture, PaymentFlowData, interfaces::connector_types::PaymentsCaptureData, PaymentsResponseData);
impl_not_implemented_flow!(interfaces::connector_types::Refund, RefundFlowData, interfaces::connector_types::RefundsData, RefundsResponseData);
impl_not_implemented_flow!(interfaces::connector_types::CreateOrder, PaymentFlowData, interfaces::connector_types::PaymentCreateOrderData, interfaces::connector_types::PaymentCreateOrderResponse);
impl_not_implemented_flow!(interfaces::connector_types::CreateSessionToken, PaymentFlowData, interfaces::connector_types::SessionTokenRequestData, interfaces::connector_types::SessionTokenResponseData);
impl_not_implemented_flow!(interfaces::connector_types::SetupMandate, PaymentFlowData, interfaces::connector_types::SetupMandateRequestData, PaymentsResponseData);
impl_not_implemented_flow!(interfaces::connector_types::RepeatPayment, PaymentFlowData, interfaces::connector_types::RepeatPaymentData, PaymentsResponseData);
impl_not_implemented_flow!(interfaces::connector_types::Accept, interfaces::connector_types::DisputeFlowData, interfaces::connector_types::AcceptDisputeData, interfaces::connector_types::DisputeResponseData);
impl_not_implemented_flow!(interfaces::connector_types::DefendDispute, interfaces::connector_types::DisputeFlowData, interfaces::connector_types::DisputeDefendData, interfaces::connector_types::DisputeResponseData);
impl_not_implemented_flow!(interfaces::connector_types::SubmitEvidence, interfaces::connector_types::DisputeFlowData, interfaces::connector_types::SubmitEvidenceData, interfaces::connector_types::DisputeResponseData);

// Implement all required connector type traits
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    interfaces::connector_types::PaymentVoidV2 for ZaakPay<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    interfaces::connector_types::PaymentCaptureV2 for ZaakPay<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    interfaces::connector_types::PaymentRefundV2 for ZaakPay<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    interfaces::connector_types::PaymentOrderCreate for ZaakPay<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    interfaces::connector_types::PaymentSessionToken for ZaakPay<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    interfaces::connector_types::PaymentSetupMandate for ZaakPay<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    interfaces::connector_types::PaymentRepeatPayment for ZaakPay<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    interfaces::connector_types::DisputeAccept for ZaakPay<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    interfaces::connector_types::DisputeDefend for ZaakPay<T> {}
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    interfaces::connector_types::DisputeSubmitEvidence for ZaakPay<T> {}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    interfaces::connector_types::ConnectorServiceTrait<T> for ZaakPay<T> {}

// Error response types
#[derive(Debug, Deserialize)]
pub struct ZaakPayErrorResponse {
    pub response_code: String,
    pub response_description: String,
}

impl From<ZaakPayErrorResponse> for errors::ConnectorError {
    fn from(error: ZaakPayErrorResponse) -> Self {
        match error.response_code.as_str() {
            "100" => errors::ConnectorError::AuthenticationFailed,
            "101" => errors::ConnectorError::InvalidRequestData {
                message: error.response_description,
            },
            "102" => errors::ConnectorError::InvalidRequestData {
                message: error.response_description,
            },
            "103" => errors::ConnectorError::InvalidRequestData {
                message: error.response_description,
            },
            _ => errors::ConnectorError::UnexpectedResponse {
                status_code: 400,
                response_body: error.response_description,
            },
        }
    }
}