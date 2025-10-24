// Simplified EaseBuzz Connector Implementation

use std::fmt::Debug;

use common_enums::{AttemptStatus, PaymentMethodType};
use common_utils::{
    errors::CustomResult,
    types::StringMinorUnit,
};
use domain_types::{
    connector_flow::{Authorize, PSync, RSync, Refund},
    connector_types::{
        ConnectorCommon, ConnectorWebhookSecrets, PaymentFlowData, PaymentsAuthorizeData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundsData, RefundsResponseData,
        RefundSyncData,
    },
    payment_method_data::PaymentMethodDataTypes,
    router_data_v2::RouterDataV2,
    router_response_types::Response,
};
use error_stack::ResultExt;
use hyperswitch_masking::{Mask, Maskable, Secret};
use serde::{Deserialize, Serialize};

// Main connector struct
#[derive(Debug, Clone)]
pub struct EaseBuzz<T> {
    pub connector_data: T,
    pub auth_type: domain_types::router_data::ConnectorAuthType,
}

impl<T> EaseBuzz<T> {
    pub fn new(connector_data: T, auth_type: domain_types::router_data::ConnectorAuthType) -> Self {
        Self {
            connector_data,
            auth_type,
        }
    }
}

// Basic request/response types
#[derive(Debug, Serialize)]
pub struct EaseBuzzPaymentsRequest {
    pub key: Secret<String>,
    pub txnid: String,
    pub amount: String,
    pub hash: Secret<String>,
}

#[derive(Debug, Deserialize)]
pub struct EaseBuzzPaymentsResponse {
    pub status: i32,
    pub error_desc: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct EaseBuzzPaymentsSyncRequest {
    pub key: Secret<String>,
    pub txnid: String,
    pub hash: Secret<String>,
}

#[derive(Debug, Deserialize)]
pub struct EaseBuzzPaymentsSyncResponse {
    pub status: bool,
    pub msg: String,
}

#[derive(Debug, Serialize)]
pub struct EaseBuzzRefundRequest {
    pub key: Secret<String>,
    pub txnid: String,
    pub refund_amount: String,
    pub hash: Secret<String>,
}

#[derive(Debug, Deserialize)]
pub struct EaseBuzzRefundResponse {
    pub status: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct EaseBuzzRefundSyncRequest {
    pub key: Secret<String>,
    pub easebuzz_id: String,
    pub hash: Secret<String>,
}

#[derive(Debug, Deserialize)]
pub struct EaseBuzzRefundSyncResponse {
    pub status: String,
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct EaseBuzzErrorResponse {
    pub status: i32,
    pub error_code: Option<String>,
    pub error_desc: Option<String>,
}

// Implement connector common traits
impl<T: PaymentMethodDataTypes + Debug + Send + Sync + 'static> ConnectorCommon for EaseBuzz<T> {
    fn get_id(&self) -> &'static str {
        "easebuzz"
    }

    fn get_name(&self) -> &'static str {
        "EaseBuzz"
    }

    fn get_connector_type(&self) -> domain_types::types::ConnectorType {
        domain_types::types::ConnectorType::PaymentGateway
    }

    fn get_connector_metadata(&self) -> Option<domain_types::types::ConnectorMetadata> {
        Some(domain_types::types::ConnectorMetadata {
            description: Some("EaseBuzz payment gateway supporting UPI transactions".to_string()),
            website: Some("https://easebuzz.in".to_string()),
            supported_payment_methods: vec![PaymentMethodType::Upi],
            supported_currencies: vec!["INR".parse().unwrap()],
            supported_countries: vec!["IN".parse().unwrap()],
            ..Default::default()
        })
    }

    fn get_webhook_secret(&self) -> Option<&Secret<String>> {
        None
    }

    fn get_webhook_url(&self) -> Option<&str> {
        None
    }

    fn get_webhook_details(&self) -> Option<ConnectorWebhookSecrets> {
        None
    }

    fn get_connector_specifications(&self) -> domain_types::connector_types::ConnectorSpecifications {
        domain_types::connector_types::ConnectorSpecifications {
            connector_name: "easebuzz".to_string(),
            connector_type: domain_types::types::ConnectorType::PaymentGateway,
            supported_payment_methods: vec![PaymentMethodType::Upi],
            supported_currencies: vec!["INR".parse().unwrap()],
            supported_countries: vec!["IN".parse().unwrap()],
            ..Default::default()
        }
    }
}

// Trait implementations for the connector
impl<T: PaymentMethodDataTypes + Debug + Send + Sync + 'static> 
    domain_types::connector_types::ConnectorServiceTrait<T> for EaseBuzz<T> {}

impl<T: PaymentMethodDataTypes + Debug + Send + Sync + 'static> 
    domain_types::connector_types::PaymentAuthorizeV2<T> for EaseBuzz<T> {}

impl<T: PaymentMethodDataTypes + Debug + Send + Sync + 'static> 
    domain_types::connector_types::PaymentSyncV2 for EaseBuzz<T> {}

impl<T: PaymentMethodDataTypes + Debug + Send + Sync + 'static> 
    domain_types::connector_types::RefundV2 for EaseBuzz<T> {}

impl<T: PaymentMethodDataTypes + Debug + Send + Sync + 'static> 
    domain_types::connector_types::RefundSyncV2 for EaseBuzz<T> {}

// Basic implementation functions
impl<T: PaymentMethodDataTypes + Debug + Send + Sync + 'static> EaseBuzz<T> {
    pub fn build_headers<F, FCD, Req, Res>(
        &self,
        _req: &RouterDataV2<F, FCD, Req, Res>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, domain_types::errors::ConnectorError>
    where
        Self: domain_types::connector_types::ConnectorIntegrationV2,
    {
        let header = vec![(
            "Content-Type".to_string(),
            self.get_content_type().to_string().into(),
        )];
        Ok(header)
    }

    pub fn get_content_type(&self) -> &'static str {
        "application/x-www-form-urlencoded"
    }

    pub fn get_error_response_v2(
        &self,
        res: Response,
        _event_builder: Option<&mut interfaces::events::connector_api_logs::ConnectorEvent>,
    ) -> CustomResult<domain_types::router_data::ErrorResponse, domain_types::errors::ConnectorError> {
        self.build_error_response(res)
    }

    pub fn build_error_response(
        &self,
        res: Response,
    ) -> CustomResult<domain_types::router_data::ErrorResponse, domain_types::errors::ConnectorError> {
        let error_response: EaseBuzzErrorResponse = res
            .response
            .parse_struct("EaseBuzzErrorResponse")
            .change_context(domain_types::errors::ConnectorError::ResponseDeserializationFailed)?;

        Ok(domain_types::router_data::ErrorResponse {
            status_code: res.status_code,
            code: error_response.error_code,
            message: error_response.error_desc,
            reason: None,
        })
    }
}

// Add a simple parse_struct extension for serde_json::Value
trait ParseStructExt {
    fn parse_struct<T>(&self, _type_name: &str) -> CustomResult<T, domain_types::errors::ConnectorError>
    where
        T: for<'de> Deserialize<'de>;
}

impl ParseStructExt for serde_json::Value {
    fn parse_struct<T>(&self, _type_name: &str) -> CustomResult<T, domain_types::errors::ConnectorError>
    where
        T: for<'de> Deserialize<'de>,
    {
        serde_json::from_value(self.clone())
            .change_context(domain_types::errors::ConnectorError::ResponseDeserializationFailed)
    }
}