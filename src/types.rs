// Type definitions for the connector service

use std::marker::PhantomData;

use common_utils::CustomResult;
use domain_types::{
    payment_method_data::PaymentMethodDataTypes,
    router_data_v2::RouterDataV2,
};
use serde::{Deserialize, Serialize};

// Connector enum for type system integration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConnectorEnum {
    EaseBuzz,
    // Add other connectors here as needed
}

impl ConnectorEnum {
    pub fn as_str(&self) -> &'static str {
        match self {
            ConnectorEnum::EaseBuzz => "easebuzz",
        }
    }
}

// URL trait implementations for different flow types
pub trait GetUrl {
    type Request;
    type Response;
    
    fn get_url<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>(
        connector: &crate::connectors::easebuzz::EaseBuzz<T>,
        req: &RouterDataV2<Self, domain_types::connector_types::PaymentFlowData, Self::Request, Self::Response>,
        base_url: &str,
    ) -> CustomResult<String, domain_types::errors::ConnectorError>
    where
        Self: Sized;
}

// Associated type definitions for URL traits
impl GetUrl for domain_types::connector_types::PaymentsAuthorizeType {
    type Request = domain_types::connector_types::PaymentsAuthorizeData<PhantomData<String>>;
    type Response = domain_types::connector_types::PaymentsResponseData;

    fn get_url<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>(
        _connector: &crate::connectors::easebuzz::EaseBuzz<T>,
        req: &RouterDataV2<Self, domain_types::connector_types::PaymentFlowData, Self::Request, Self::Response>,
        _base_url: &str,
    ) -> CustomResult<String, domain_types::errors::ConnectorError> {
        let test_mode = req.resource_common_data.test_mode.unwrap_or(false);
        Ok(crate::connectors::easebuzz::constants::get_initiate_payment_url(test_mode))
    }
}

impl GetUrl for domain_types::connector_types::PaymentsSyncType {
    type Request = domain_types::connector_types::PaymentsSyncData;
    type Response = domain_types::connector_types::PaymentsResponseData;

    fn get_url<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>(
        _connector: &crate::connectors::easebuzz::EaseBuzz<T>,
        req: &RouterDataV2<Self, domain_types::connector_types::PaymentFlowData, Self::Request, Self::Response>,
        _base_url: &str,
    ) -> CustomResult<String, domain_types::errors::ConnectorError> {
        let test_mode = req.resource_common_data.test_mode.unwrap_or(false);
        Ok(crate::connectors::easebuzz::constants::get_txn_sync_url(test_mode))
    }
}

impl GetUrl for domain_types::connector_types::RefundType {
    type Request = domain_types::connector_types::RefundFlowData;
    type Response = domain_types::connector_types::RefundsResponseData;

    fn get_url<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>(
        _connector: &crate::connectors::easebuzz::EaseBuzz<T>,
        req: &RouterDataV2<Self, domain_types::connector_types::PaymentFlowData, Self::Request, Self::Response>,
        _base_url: &str,
    ) -> CustomResult<String, domain_types::errors::ConnectorError> {
        let test_mode = req.resource_common_data.test_mode.unwrap_or(false);
        Ok(crate::connectors::easebuzz::constants::get_refund_url(test_mode))
    }
}

impl GetUrl for domain_types::connector_types::RefundSyncType {
    type Request = domain_types::connector_types::RefundSyncData;
    type Response = domain_types::connector_types::RefundsResponseData;

    fn get_url<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>(
        _connector: &crate::connectors::easebuzz::EaseBuzz<T>,
        req: &RouterDataV2<Self, domain_types::connector_types::PaymentFlowData, Self::Request, Self::Response>,
        _base_url: &str,
    ) -> CustomResult<String, domain_types::errors::ConnectorError> {
        let test_mode = req.resource_common_data.test_mode.unwrap_or(false);
        Ok(crate::connectors::easebuzz::constants::get_refund_sync_url(test_mode))
    }
}

// Response router data type
#[derive(Debug)]
pub struct ResponseRouterData<F, T, R> {
    pub flow: PhantomData<F>,
    pub data: PhantomData<T>,
    pub response: PhantomData<R>,
}

// Helper macro for error responses
#[macro_export]
macro_rules! with_error_response_body {
    () => {
        // Stub implementation
    };
}

// Re-export domain types for convenience
pub use domain_types::*;