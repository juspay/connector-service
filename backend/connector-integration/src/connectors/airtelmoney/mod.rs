// AirtelMoney Connector Implementation
pub mod constants;
pub mod transformers;

use common_utils::{
    errors::CustomResult,
    request::RequestContent,
    types::{self, StringMinorUnit},
};
use domain_types::{
    connector_flow::{Authorize, PSync, RSync, Refund},
    connector_types::{
        PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData,
        RefundFlowData, RefundsData, RefundsResponseData,
    },
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
};
use error_stack::ResultExt;
use hyperswitch_masking::Secret;
use interfaces::{
    api::ConnectorCommon,
    connector_integration_v2::ConnectorIntegrationV2,
};
use serde::Serialize;
use transformers::{AirtelMoneyPaymentsRequest, AirtelMoneyPaymentsResponse};

use super::macros;
use crate::types::ResponseRouterData;

// Simple connector struct without macro framework for now
pub struct AirtelMoney<T> {
    amount_converter: &'static (dyn common_utils::types::AmountConverterTrait<Output = String> + Sync),
    connector_name: &'static str,
    payment_method_data: std::marker::PhantomData<T>,
}

impl<T> AirtelMoney<T> {
    pub fn new() -> Self {
        Self {
            amount_converter: &common_utils::types::StringMinorUnit,
            connector_name: "airtelmoney",
            payment_method_data: std::marker::PhantomData,
        }
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize> 
    ConnectorCommon for AirtelMoney<T> {
    fn get_id(&self) -> &'static str {
        "airtelmoney"
    }

    fn get_base_url(&self) -> &'static str {
        constants::get_base_url()
    }

    fn get_auth_header(&self, _auth_type: &ConnectorAuthType) -> CustomResult<Vec<(String, String)>, errors::ConnectorError> {
        Ok(vec![])
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize> 
    ConnectorIntegrationV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData> for AirtelMoney<T> {
    fn build_request_v2(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    ) -> CustomResult<Option<common_utils::request::Request>, errors::ConnectorError> {
        let request = AirtelMoneyPaymentsRequest::try_from(req)?;
        Ok(Some(common_utils::request::RequestBuilder::new()
            .method(common_utils::request::HttpMethod::Post)
            .url(&format!("{}/apbnative/partners/:merchantId/customers/:customerId/authRequest", self.get_base_url()))
            .body(common_utils::request::RequestContent::Json(request))
            .build()))
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize> 
    ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData> for AirtelMoney<T> {
    fn build_request_v2(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<Option<common_utils::request::Request>, errors::ConnectorError> {
        let request = AirtelMoneyPaymentsRequest::try_from(req)?;
        Ok(Some(common_utils::request::RequestBuilder::new()
            .method(common_utils::request::HttpMethod::Post)
            .url(&format!("{}/ecom/v2/inquiry", self.get_base_url()))
            .body(common_utils::request::RequestContent::Json(request))
            .build()))
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize> 
    ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData> for AirtelMoney<T> {
    fn build_request_v2(
        &self,
        req: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> CustomResult<Option<common_utils::request::Request>, errors::ConnectorError> {
        let request = AirtelMoneyPaymentsRequest::try_from(req)?;
        Ok(Some(common_utils::request::RequestBuilder::new()
            .method(common_utils::request::HttpMethod::Post)
            .url(&format!("{}/ecom/v2/reversal", self.get_base_url()))
            .body(common_utils::request::RequestContent::Json(request))
            .build()))
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize> 
    ConnectorIntegrationV2<RSync, RefundSyncData, RefundSyncData, RefundsResponseData> for AirtelMoney<T> {
    fn build_request_v2(
        &self,
        req: &RouterDataV2<RSync, RefundSyncData, RefundSyncData, RefundsResponseData>,
    ) -> CustomResult<Option<common_utils::request::Request>, errors::ConnectorError> {
        let request = AirtelMoneyPaymentsRequest::try_from(req)?;
        Ok(Some(common_utils::request::RequestBuilder::new()
            .method(common_utils::request::HttpMethod::Post)
            .url(&format!("{}/ecom/v2/inquiry", self.get_base_url()))
            .body(common_utils::request::RequestContent::Json(request))
            .build()))
    }
}