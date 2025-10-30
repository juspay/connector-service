pub mod constants;
pub mod test;
pub mod transformers;

use std::marker::PhantomData;

use common_utils::errors::CustomResult;
use domain_types::{
    connector_flow::{Authorize, PSync},
    connector_types::{ConnectorSpecifications, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData},
    payment_method_data::PaymentMethodDataTypes,
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    errors::ConnectorError,
};
use interfaces::{
    api::ConnectorCommon,
    connector_integration_v2::ConnectorIntegrationV2,
    connector_types::{ConnectorServiceTrait, PaymentAuthorizeV2, PaymentSyncV2, ValidationTrait},
};

#[derive(Debug, Clone)]
pub struct Tpsl<T> {
    connector_name: &'static str,
    payment_method_data: PhantomData<T>,
}

impl<T> Tpsl<T> {
    pub fn new() -> Self {
        Self {
            connector_name: "tpsl",
            payment_method_data: PhantomData,
        }
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    ConnectorCommon for Tpsl<T>
{
    fn id(&self) -> &'static str {
        self.connector_name
    }

    fn base_url<'a>(&self, _connectors: &'a domain_types::types::Connectors) -> &'a str {
        constants::get_base_url()
    }
}

// Implement ConnectorIntegrationV2 for Authorize flow
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    ConnectorIntegrationV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData> for Tpsl<T>
{
    fn build_request_v2(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    ) -> CustomResult<Option<common_utils::request::Request>, ConnectorError> {
        // Use the transformer to build the request
        let tpsl_request = crate::connectors::tpsl::transformers::TpslPaymentsRequest::try_from(req)
            .map_err(|_| ConnectorError::RequestEncodingFailed)?;
        
        // For now, return None as we need to implement the actual request building
        Ok(None)
    }

    fn handle_response_v2(
        &self,
        _req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        _event: Option<&mut interfaces::events::connector_api_logs::ConnectorEvent>,
        _response: Response,
    ) -> CustomResult<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, ConnectorError> {
        Err(ConnectorError::NotImplemented("Response handling not implemented".to_string()).into())
    }

    fn get_error_response_v2(
        &self,
        _response: Response,
        _event: Option<&mut interfaces::events::connector_api_logs::ConnectorEvent>,
    ) -> CustomResult<domain_types::router_data::ErrorResponse, ConnectorError> {
        Err(ConnectorError::NotImplemented("Error handling not implemented".to_string()).into())
    }
}

// Implement ConnectorIntegrationV2 for PSync flow
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData> for Tpsl<T>
{
    fn build_request_v2(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<Option<common_utils::request::Request>, ConnectorError> {
        // Use the transformer to build the request
        let tpsl_request = crate::connectors::tpsl::transformers::TpslPaymentsSyncRequest::try_from(req)
            .map_err(|_| ConnectorError::RequestEncodingFailed)?;
        
        // For now, return None as we need to implement the actual request building
        Ok(None)
    }

    fn handle_response_v2(
        &self,
        _req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        _event: Option<&mut interfaces::events::connector_api_logs::ConnectorEvent>,
        _response: Response,
    ) -> CustomResult<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, ConnectorError> {
        Err(ConnectorError::NotImplemented("Response handling not implemented".to_string()).into())
    }

    fn get_error_response_v2(
        &self,
        _response: Response,
        _event: Option<&mut interfaces::events::connector_api_logs::ConnectorEvent>,
    ) -> CustomResult<domain_types::router_data::ErrorResponse, ConnectorError> {
        Err(ConnectorError::NotImplemented("Error handling not implemented".to_string()).into())
    }
}

// Validation implementation
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    ValidationTrait for Tpsl<T>
{
}

// Implement required traits for ConnectorServiceTrait
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    ConnectorServiceTrait<T> for Tpsl<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    PaymentAuthorizeV2<T> for Tpsl<T>
{
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    PaymentSyncV2 for Tpsl<T>
{
}

// ConnectorSpecifications implementation
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    ConnectorSpecifications for Tpsl<T>
{
}

// Default implementation
impl<T> Default for Tpsl<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Default)]
pub struct ErrorResponse {
    pub status_code: u16,
    pub code: String,
    pub message: String,
    pub reason: Option<String>,
    pub status_message: Option<String>,
}