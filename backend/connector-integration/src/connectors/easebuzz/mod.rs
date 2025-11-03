pub mod constants;
pub mod test;
pub mod transformers;

use std::marker::PhantomData;

use common_enums::{AttemptStatus, PaymentMethodType};
use common_utils::{
    errors::CustomResult,
    ext_traits::BytesExt,
    types::StringMinorUnit,
};
use domain_types::{
    connector_flow::{Authorize, PSync, RSync},
    connector_types::{
        PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, RefundSyncData, RefundsResponseData,
    },
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
};
use error_stack::ResultExt;
use hyperswitch_masking::Secret;
use interfaces::{
    api::ConnectorCommon,
    connector_integration_v2::ConnectorIntegrationV2,
    connector_types,
    events::connector_api_logs::ConnectorEvent,
};
use masking::SecretSerdeValue;
use serde::Serialize;

use self::transformers as easebuzz;
use super::macros;
use crate::{types::ResponseRouterData, with_error_response_body};

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

    fn get_auth_header(&self, _auth_type: &ConnectorAuthType) -> CustomResult<Vec<(String, String)>, errors::ConnectorError> {
        Ok(vec![])
    }

    fn build_error_response(
        &self,
        res: Response,
        code: &str,
        message: &str,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        with_error_response_body(res, code, message, self.get_id())
    }
}

impl<T> ConnectorIntegrationV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
    for EaseBuzz<T>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize,
{
    fn get_headers(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        _connectors: &Connectors,
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
        connectors: &Connectors,
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
        _connectors: &Connectors,
    ) -> CustomResult<interfaces::services::Request, errors::ConnectorError> {
        let easebuzz_req = easebuzz::EaseBuzzPaymentsRequest::try_from(req)?;
        Ok(interfaces::services::RequestBuilder::new()
            .method(interfaces::services::Method::Post)
            .url(&self.get_url(req, &Connectors::default())?)
            .headers(self.get_headers(req, &Connectors::default())?)
            .body(interfaces::services::RequestBody::Form(easebuzz_req))
            .build())
    }

    fn handle_response(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        res: Response,
        _connectors: &Connectors,
    ) -> CustomResult<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, errors::ConnectorError> {
        let response: easebuzz::EaseBuzzPaymentsResponse = res
            .response
            .parse_struct("EaseBuzzPaymentsResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        
        let status = self.get_status(response.status, response.error_desc.as_deref());
        
        Ok(RouterDataV2 {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: domain_types::router_data::ResponseId::ConnectorTransactionId(response.data),
                redirection_data: None,
                connector_metadata: None,
                mandate_reference: None,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                status_code: res.status_code,
            }),
            ..req.clone()
        })
    }

    fn get_error_response(
        &self,
        res: Response,
        _connectors: &Connectors,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, "401", "Unauthorized")
    }
}

impl<T> ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    for EaseBuzz<T>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize,
{
    fn get_headers(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        _connectors: &Connectors,
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
        connectors: &Connectors,
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
        _connectors: &Connectors,
    ) -> CustomResult<interfaces::services::Request, errors::ConnectorError> {
        let easebuzz_req = easebuzz::EaseBuzzPaymentsSyncRequest::try_from(req)?;
        Ok(interfaces::services::RequestBuilder::new()
            .method(interfaces::services::Method::Post)
            .url(&self.get_url(req, &Connectors::default())?)
            .headers(self.get_headers(req, &Connectors::default())?)
            .body(interfaces::services::RequestBody::Form(easebuzz_req))
            .build())
    }

    fn handle_response(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        res: Response,
        _connectors: &Connectors,
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
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: req.request.connector_transaction_id.clone(),
                redirection_data: None,
                connector_metadata: None,
                mandate_reference: None,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                status_code: res.status_code,
            }),
            ..req.clone()
        })
    }

    fn get_error_response(
        &self,
        res: Response,
        _connectors: &Connectors,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, "401", "Unauthorized")
    }
}

impl<T> ConnectorIntegrationV2<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>
    for EaseBuzz<T>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize,
{
    fn get_headers(
        &self,
        req: &RouterDataV2<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>,
        _connectors: &Connectors,
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
        connectors: &Connectors,
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
        _connectors: &Connectors,
    ) -> CustomResult<interfaces::services::Request, errors::ConnectorError> {
        let easebuzz_req = easebuzz::EaseBuzzRefundSyncRequest::try_from(req)?;
        Ok(interfaces::services::RequestBuilder::new()
            .method(interfaces::services::Method::Post)
            .url(&self.get_url(req, &Connectors::default())?)
            .headers(self.get_headers(req, &Connectors::default())?)
            .body(interfaces::services::RequestBody::Form(easebuzz_req))
            .build())
    }

    fn handle_response(
        &self,
        req: &RouterDataV2<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>,
        res: Response,
        _connectors: &Connectors,
    ) -> CustomResult<RouterDataV2<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>, errors::ConnectorError> {
        let response: easebuzz::EaseBuzzRefundSyncResponseWrapper = res
            .response
            .parse_struct("EaseBuzzRefundSyncResponseWrapper")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        
        let (status, refund_status) = match response.response {
            easebuzz::EaseBuzzRefundSyncResponse::Success(resp) => {
                (common_enums::RefundStatus::Success, Some(resp.refunds.as_ref().and_then(|r| r.first().map(|ref_| ref_.refund_status.clone())).unwrap_or_default()))
            }
            easebuzz::EaseBuzzRefundSyncResponse::Failure(_) => {
                (common_enums::RefundStatus::Failure, None)
            }
            easebuzz::EaseBuzzRefundSyncResponse::ValidationError(_) => {
                (common_enums::RefundStatus::Failure, None)
            }
        };
        
        Ok(RouterDataV2 {
            response: Ok(RefundsResponseData {
                connector_refund_id: response.response.get_connector_refund_id().unwrap_or_default(),
                refund_status: status,
                status_code: res.status_code,
            }),
            ..req.clone()
        })
    }

    fn get_error_response(
        &self,
        res: Response,
        _connectors: &Connectors,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, "401", "Unauthorized")
    }
}

impl<T> connector_types::ConnectorRedirectResponse for EaseBuzz<T>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize,
{
    fn get_flow_type(
        &self,
        _req: &domain_types::router_data::RouterData<domain_types::router_request_types::AccessToken, domain_types::connector_types::PaymentsAuthorizeData, domain_types::connector_types::PaymentsResponseData>,
    ) -> String {
        "redirect".to_string()
    }
}

impl<T> connector_types::ConnectorSpecifications for EaseBuzz<T>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize,
{
    fn get_connector_about(&self) -> Option<connector_types::ConnectorAbout> {
        Some(connector_types::ConnectorAbout {
            connector_name: self.get_id().to_string(),
            connector_type: connector_types::ConnectorType::PaymentGateway,
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

impl<T> connector_types::ConnectorWebhook for EaseBuzz<T>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize,
{
    fn get_webhook_event_type(
        &self,
        _request: &domain_types::router_data::RouterData<domain_types::router_request_types::AccessToken, domain_types::connector_types::PaymentsAuthorizeData, domain_types::connector_types::PaymentsResponseData>,
    ) -> CustomResult<domain_types::connector_types::EventType, errors::ConnectorError> {
        Ok(domain_types::connector_types::EventType::PaymentIntentSuccess)
    }

    fn get_webhook_object_reference_id(
        &self,
        request: &domain_types::router_data::RouterData<domain_types::router_request_types::AccessToken, domain_types::connector_types::PaymentsAuthorizeData, domain_types::connector_types::PaymentsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(request.request.connector_transaction_id.get_string_repr().to_string())
    }

    fn get_webhook_api_version(
        &self,
        _request: &domain_types::router_data::RouterData<domain_types::router_request_types::AccessToken, domain_types::connector_types::PaymentsAuthorizeData, domain_types::connector_types::PaymentsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok("1.0".to_string())
    }

    fn get_webhook_source(
        &self,
        _request: &domain_types::router_data::RouterData<domain_types::router_request_types::AccessToken, domain_types::connector_types::PaymentsAuthorizeData, domain_types::connector_types::PaymentsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok("easebuzz".to_string())
    }

    fn verify_webhook_signature(
        &self,
        _request: &domain_types::router_data::RouterData<domain_types::router_request_types::AccessToken, domain_types::connector_types::PaymentsAuthorizeData, domain_types::connector_types::PaymentsResponseData>,
        _webhook_secrets: &domain_types::connector_types::ConnectorWebhookSecrets,
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

// Mock trait for compilation
pub trait AmountConverterTrait<Output> {
    fn convert(&self, amount: i64, currency: common_enums::Currency) -> CustomResult<Output, errors::ConnectorError>;
}

impl AmountConverterTrait<String> for StringMinorUnit {
    fn convert(&self, amount: i64, _currency: common_enums::Currency) -> CustomResult<String, errors::ConnectorError> {
        Ok(amount.to_string())
    }
}