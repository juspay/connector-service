pub mod constants;
pub mod test;
pub mod transformers;

use std::marker::PhantomData;

use common_enums::{AttemptStatus, PaymentMethodType};
use common_utils::{
    errors::CustomResult,
    ext_traits::BytesExt,
    request::RequestContent,
    types::{StringMinorUnit},
};
use domain_types::{
    connector_flow::{Authorize, PSync, RSync},
    connector_types::{
        ConnectorSpecifications, ConnectorWebhookSecrets, PaymentFlowData, PaymentsAuthorizeData,
        PaymentsResponseData, PaymentsSyncData, RefundSyncData, RefundsResponseData,
    },
    payment_method_data::PaymentMethodDataTypes,
    router_data_v2::RouterDataV2,
    types::{AmountConverterTrait, MinorUnit},
};
use error_stack::ResultExt;
use hyperswitch_domain_models::{
    router_data_v2::{self},
    router_request_types::ResponseId,
};
use hyperswitch_interfaces::errors;

use self::transformers as easebuzz;
use crate::{
    configs::settings,
    services::{self, ConnectorCommon, ConnectorCommonExt},
    types::{self, api::ConnectorCommonExtTrait},
    utils,
};

#[derive(Debug, Clone)]
pub struct EaseBuzz<T> {
    amount_converter: &'static (dyn AmountConverterTrait<Output = String> + Sync),
    connector_name: &'static str,
    payment_method_data: PhantomData<T>,
}

impl<T> ConnectorCommon for EaseBuzz<T>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize,
{
    fn get_id(&self) -> &'static str {
        self.connector_name
    }

    fn get_base_url(&self) -> &'static str {
        constants::get_base_url()
    }

    fn get_auth_header(&self, _auth_type: &types::ConnectorAuthType) -> CustomResult<Vec<(String, String)>, errors::ConnectorError> {
        Ok(vec![])
    }

    fn build_error_response(
        &self,
        res: utils::Response,
        code: &str,
        message: &str,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        utils::build_error_response(res, code, message, self.get_id())
    }
}

impl<T> services::ConnectorIntegrationV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
    for EaseBuzz<T>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize,
{
    fn get_headers(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        _connectors: &settings::Connectors,
    ) -> CustomResult<Vec<(String, String)>, errors::ConnectorError> {
        let auth = easebuzz::get_auth_header(&req.connector_auth_type)?;
        Ok(auth)
    }

    fn get_content_type(&self) -> &'static str {
        "application/x-www-form-urlencoded"
    }

    fn get_url(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        connectors: &settings::Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        let endpoint = if req.request.payment_method_type == PaymentMethodType::Upi {
            constants::EaseBuzzEndpoints::EasebuzSeamlessTransaction
        } else {
            constants::EaseBuzzEndpoints::EaseBuzInitiatePayment
        };
        let base_url = self.get_base_url();
        let endpoint_url = constants::get_endpoint(endpoint, req.resource_common_data.test_mode.unwrap_or(false));
        Ok(format!("{}{}", base_url, endpoint_url))
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        _connectors: &settings::Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        let easebuzz_req = easebuzz::EaseBuzzPaymentsRequest::try_from(req)?;
        Ok(RequestContent::FormUrlEncoded(easebuzz_req))
    }

    fn build_request(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        connectors: &settings::Connectors,
    ) -> CustomResult<services::Request, errors::ConnectorError> {
        Ok(utils::build_request(
            req,
            self.get_url(req, connectors)?,
            self.get_headers(req, connectors)?,
            self.get_request_body(req, connectors)?,
            self.get_content_type(),
        ))
    }

    fn handle_response(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        res: utils::Response,
        _connectors: &settings::Connectors,
    ) -> CustomResult<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, errors::ConnectorError> {
        let response: easebuzz::EaseBuzzPaymentsResponse = res
            .response
            .parse_struct("EaseBuzzPaymentsResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        
        let status = self.get_status(response.status, response.error_desc.as_deref());
        
        Ok(RouterDataV2 {
            response: Ok(PaymentsResponseData {
                status,
                response_id: ResponseId::ConnectorTransactionId(response._data.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                charge_id: None,
                amount_captured: None,
                fraud_check: None,
                error_message: response.error_desc,
                access_token: None,
                surf_payment_response: None,
            }),
            ..req.clone()
        })
    }

    fn get_error_response(
        &self,
        res: utils::Response,
        _connectors: &settings::Connectors,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, "401", "Unauthorized")
    }
}

impl<T> services::ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    for EaseBuzz<T>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize,
{
    fn get_headers(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        _connectors: &settings::Connectors,
    ) -> CustomResult<Vec<(String, String)>, errors::ConnectorError> {
        let auth = easebuzz::get_auth_header(&req.connector_auth_type)?;
        Ok(auth)
    }

    fn get_content_type(&self) -> &'static str {
        "application/x-www-form-urlencoded"
    }

    fn get_url(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        connectors: &settings::Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        let base_url = self.get_base_url();
        let endpoint_url = constants::get_endpoint(
            constants::EaseBuzzEndpoints::EasebuzTxnSync,
            req.resource_common_data.test_mode.unwrap_or(false),
        );
        Ok(format!("{}{}", base_url, endpoint_url))
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        _connectors: &settings::Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        let easebuzz_req = easebuzz::EaseBuzzPaymentsSyncRequest::try_from(req)?;
        Ok(RequestContent::FormUrlEncoded(easebuzz_req))
    }

    fn build_request(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        connectors: &settings::Connectors,
    ) -> CustomResult<services::Request, errors::ConnectorError> {
        Ok(utils::build_request(
            req,
            self.get_url(req, connectors)?,
            self.get_headers(req, connectors)?,
            self.get_request_body(req, connectors)?,
            self.get_content_type(),
        ))
    }

    fn handle_response(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        res: utils::Response,
        _connectors: &settings::Connectors,
    ) -> CustomResult<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, errors::ConnectorError> {
        let response: easebuzz::EaseBuzzPaymentsSyncResponse = res
            .response
            .parse_struct("EaseBuzzPaymentsSyncResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        
        let status = if response.status {
            AttemptStatus::Charged
        } else {
            AttemptStatus::Failure
        };
        
        Ok(RouterDataV2 {
            response: Ok(PaymentsResponseData {
                status,
                response_id: ResponseId::ConnectorTransactionId(
                    req.request.connector_transaction_id.get_connector_transaction_id()?,
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                charge_id: None,
                amount_captured: None,
                fraud_check: None,
                error_message: None,
                access_token: None,
                surf_payment_response: None,
            }),
            ..req.clone()
        })
    }

    fn get_error_response(
        &self,
        res: utils::Response,
        _connectors: &settings::Connectors,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, "401", "Unauthorized")
    }
}

impl<T> services::ConnectorIntegrationV2<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>
    for EaseBuzz<T>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize,
{
    fn get_headers(
        &self,
        req: &RouterDataV2<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>,
        _connectors: &settings::Connectors,
    ) -> CustomResult<Vec<(String, String)>, errors::ConnectorError> {
        let auth = easebuzz::get_auth_header(&req.connector_auth_type)?;
        Ok(auth)
    }

    fn get_content_type(&self) -> &'static str {
        "application/x-www-form-urlencoded"
    }

    fn get_url(
        &self,
        req: &RouterDataV2<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>,
        connectors: &settings::Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        let base_url = self.get_base_url();
        let endpoint_url = constants::get_endpoint(
            constants::EaseBuzzEndpoints::EaseBuzRefundSync,
            req.resource_common_data.test_mode.unwrap_or(false),
        );
        Ok(format!("{}{}", base_url, endpoint_url))
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>,
        _connectors: &settings::Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        let easebuzz_req = easebuzz::EaseBuzzRefundSyncRequest::try_from(req)?;
        Ok(RequestContent::FormUrlEncoded(easebuzz_req))
    }

    fn build_request(
        &self,
        req: &RouterDataV2<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>,
        connectors: &settings::Connectors,
    ) -> CustomResult<services::Request, errors::ConnectorError> {
        Ok(utils::build_request(
            req,
            self.get_url(req, connectors)?,
            self.get_headers(req, connectors)?,
            self.get_request_body(req, connectors)?,
            self.get_content_type(),
        ))
    }

    fn handle_response(
        &self,
        req: &RouterDataV2<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>,
        res: utils::Response,
        _connectors: &settings::Connectors,
    ) -> CustomResult<RouterDataV2<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>, errors::ConnectorError> {
        let response: easebuzz::EaseBuzzRefundSyncResponseWrapper = res
            .response
            .parse_struct("EaseBuzzRefundSyncResponseWrapper")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        
        let (status, refund_status) = match response.response {
            easebuzz::EaseBuzzRefundSyncResponse::Success(resp) => {
                (AttemptStatus::Succeeded, Some(resp.refund_status))
            }
            easebuzz::EaseBuzzRefundSyncResponse::Failure(_) => {
                (AttemptStatus::Failure, None)
            }
            easebuzz::EaseBuzzRefundSyncResponse::ValidationError(_) => {
                (AttemptStatus::Failure, None)
            }
        };
        
        Ok(RouterDataV2 {
            response: Ok(RefundsResponseData {
                refund_id: response.response.get_refund_id(),
                status,
                amount_captured: None,
                connector_refund_id: response.response.get_connector_refund_id(),
                refund_status,
                error_message: None,
                connector_metadata: None,
            }),
            ..req.clone()
        })
    }

    fn get_error_response(
        &self,
        res: utils::Response,
        _connectors: &settings::Connectors,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, "401", "Unauthorized")
    }
}

impl<T> services::ConnectorRedirectResponse for EaseBuzz<T>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize,
{
    fn get_flow_type(
        &self,
        _req: &utils::RouterData<utils::AccessToken, types::PaymentsAuthorizeData, types::PaymentsResponseData>,
    ) -> String {
        "redirect".to_string()
    }
}

impl<T> services::ConnectorSpecifications for EaseBuzz<T>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize,
{
    fn get_connector_about(&self) -> Option<types::ConnectorAbout> {
        Some(types::ConnectorAbout {
            connector_name: self.get_id().to_string(),
            connector_type: types::ConnectorType::PaymentGateway,
            description: Some("EaseBuzz payment gateway connector".to_string()),
            supported_payment_methods: vec![PaymentMethodType::Upi],
            supported_currencies: constants::SUPPORTED_CURRENCIES.to_vec(),
            supported_countries: constants::SUPPORTED_COUNTRIES.to_vec(),
        })
    }

    fn get_supported_payment_methods(&self) -> Vec<PaymentMethodType> {
        vec![PaymentMethodType::Upi]
    }

    fn get_supported_currencies(&self) -> Vec<common_enums::Currency> {
        constants::SUPPORTED_CURRENCIES.to_vec()
    }

    fn get_supported_countries(&self) -> Vec<common_enums::CountryAlpha2> {
        constants::SUPPORTED_COUNTRIES.to_vec()
    }
}

impl<T> services::ConnectorWebhook for EaseBuzz<T>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize,
{
    fn get_webhook_event_type(
        &self,
        _request: &utils::RouterData<utils::AccessToken, types::PaymentsAuthorizeData, types::PaymentsResponseData>,
    ) -> CustomResult<types::WebhookEvent, errors::ConnectorError> {
        Ok(types::WebhookEvent::PaymentIntentSuccess)
    }

    fn get_webhook_object_reference_id(
        &self,
        request: &utils::RouterData<utils::AccessToken, types::PaymentsAuthorizeData, types::PaymentsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(request.request.connector_transaction_id.get_string_repr().to_string())
    }

    fn get_webhook_api_version(
        &self,
        _request: &utils::RouterData<utils::AccessToken, types::PaymentsAuthorizeData, types::PaymentsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok("1.0".to_string())
    }

    fn get_webhook_source(
        &self,
        _request: &utils::RouterData<utils::AccessToken, types::PaymentsAuthorizeData, types::PaymentsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok("easebuzz".to_string())
    }

    fn verify_webhook_signature(
        &self,
        _request: &utils::RouterData<utils::AccessToken, types::PaymentsAuthorizeData, types::PaymentsResponseData>,
        _webhook_secrets: &api_models::webhooks::ConnectorWebhookSecrets,
    ) -> CustomResult<bool, errors::ConnectorError> {
        Ok(true)
    }
}

impl<T> EaseBuzz<T>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize,
{
    pub fn new() -> Self {
        Self {
            amount_converter: &StringMinorUnit,
            connector_name: "easebuzz",
            payment_method_data: PhantomData,
        }
    }

    fn get_status(&self, status: i32, error_desc: Option<&str>) -> AttemptStatus {
        match status {
            1 => AttemptStatus::AuthenticationPending,
            0 => match error_desc {
                Some("pending") => AttemptStatus::Pending,
                Some(_) => AttemptStatus::Failure,
                None => AttemptStatus::Failure,
            },
            _ => AttemptStatus::Failure,
        }
    }
}

impl<T> Default for EaseBuzz<T>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize,
{
    fn default() -> Self {
        Self::new()
    }
}