pub mod constants;
pub mod test;
pub mod transformers;

use std::marker::PhantomData;

use common_enums::{AttemptStatus, PaymentMethodType};
use common_utils::{
    errors::CustomResult,
    ext_traits::BytesExt,
    request::RequestContent,
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
use hyperswitch_masking::{Maskable, Secret};
use interfaces::{
    api::ConnectorCommon,
    connector_integration_v2::ConnectorIntegrationV2,
    verification::{ConnectorSourceVerificationSecrets, SourceVerification},
};
use serde::Serialize;

use self::transformers as easebuzz;

#[derive(Debug, Clone)]
pub struct EaseBuzz<T> {
    connector_name: &'static str,
    payment_method_data: PhantomData<T>,
}

impl<T> ConnectorCommon for EaseBuzz<T>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize,
{
    fn id(&self) -> &'static str {
        self.connector_name
    }

    fn base_url<'a>(&self, _connectors: &'a Connectors) -> &'a str {
        constants::get_base_url()
    }

    fn build_error_response(
        &self,
        res: Response,
        _event_builder: Option<&mut interfaces::events::connector_api_logs::ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        Ok(ErrorResponse {
            error_code: "401".to_string(),
            error_message: "Unauthorized".to_string(),
            status_code: res.status_code,
            reason: None,
            retry: None,
        })
    }
}

impl<T> SourceVerification<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData> for EaseBuzz<T>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize,
{
}

impl<T> SourceVerification<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData> for EaseBuzz<T>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize,
{
}

impl<T> SourceVerification<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData> for EaseBuzz<T>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize,
{
}

impl<T> ConnectorIntegrationV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
    for EaseBuzz<T>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize,
{
    fn get_headers(
        &self,
        _req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        Ok(vec![])
    }

    fn get_content_type(&self) -> &'static str {
        "application/x-www-form-urlencoded"
    }

    fn get_url(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        let endpoint = if req.request.payment_method_type == PaymentMethodType::Upi {
            constants::EaseBuzzEndpoints::EasebuzSeamlessTransaction
        } else {
            constants::EaseBuzzEndpoints::EaseBuzInitiatePayment
        };
        let base_url = self.base_url(&Connectors::default());
        let endpoint_url = constants::get_endpoint(endpoint, req.resource_common_data.test_mode.unwrap_or(false));
        Ok(format!("{}{}", base_url, endpoint_url))
    }

    fn get_request_body(
        &self,
        _req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        Ok(None)
    }

    fn handle_response_v2(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        res: Response,
        _event_builder: Option<&mut interfaces::events::connector_api_logs::ConnectorEvent>,
    ) -> CustomResult<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, errors::ConnectorError> {
        Ok(RouterDataV2 {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: domain_types::connector_types::ResponseId::ConnectorTransactionId("test".to_string()),
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

    fn get_error_response_v2(
        &self,
        res: Response,
        _event_builder: Option<&mut interfaces::events::connector_api_logs::ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, None)
    }
}

impl<T> ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    for EaseBuzz<T>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize,
{
    fn get_headers(
        &self,
        _req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        Ok(vec![])
    }

    fn get_content_type(&self) -> &'static str {
        "application/x-www-form-urlencoded"
    }

    fn get_url(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        let base_url = self.base_url(&Connectors::default());
        let endpoint_url = constants::get_endpoint(
            constants::EaseBuzzEndpoints::EasebuzTxnSync,
            req.resource_common_data.test_mode.unwrap_or(false),
        );
        Ok(format!("{}{}", base_url, endpoint_url))
    }

    fn get_request_body(
        &self,
        _req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        Ok(None)
    }

    fn handle_response_v2(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        res: Response,
        _event_builder: Option<&mut interfaces::events::connector_api_logs::ConnectorEvent>,
    ) -> CustomResult<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, errors::ConnectorError> {
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

    fn get_error_response_v2(
        &self,
        res: Response,
        _event_builder: Option<&mut interfaces::events::connector_api_logs::ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, None)
    }
}

impl<T> ConnectorIntegrationV2<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>
    for EaseBuzz<T>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize,
{
    fn get_headers(
        &self,
        _req: &RouterDataV2<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        Ok(vec![])
    }

    fn get_content_type(&self) -> &'static str {
        "application/x-www-form-urlencoded"
    }

    fn get_url(
        &self,
        req: &RouterDataV2<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        let base_url = self.base_url(&Connectors::default());
        let endpoint_url = constants::get_endpoint(
            constants::EaseBuzzEndpoints::EaseBuzRefundSync,
            req.resource_common_data.test_mode.unwrap_or(false),
        );
        Ok(format!("{}{}", base_url, endpoint_url))
    }

    fn get_request_body(
        &self,
        _req: &RouterDataV2<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        Ok(None)
    }

    fn handle_response_v2(
        &self,
        req: &RouterDataV2<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>,
        res: Response,
        _event_builder: Option<&mut interfaces::events::connector_api_logs::ConnectorEvent>,
    ) -> CustomResult<RouterDataV2<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>, errors::ConnectorError> {
        Ok(RouterDataV2 {
            response: Ok(RefundsResponseData {
                connector_refund_id: "test".to_string(),
                refund_status: common_enums::RefundStatus::Success,
                status_code: res.status_code,
            }),
            ..req.clone()
        })
    }

    fn get_error_response_v2(
        &self,
        res: Response,
        _event_builder: Option<&mut interfaces::events::connector_api_logs::ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, None)
    }
}

impl<T> EaseBuzz<T>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize,
{
    pub fn new() -> Self {
        Self {
            connector_name: "easebuzz",
            payment_method_data: PhantomData,
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

// Implement the required trait for the connector factory
impl<T> interfaces::ConnectorServiceTrait<T> for EaseBuzz<T>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize,
{
}