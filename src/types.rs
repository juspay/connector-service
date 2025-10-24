// Type definitions for the connector service

use std::marker::PhantomData;

use common_enums::{AttemptStatus, Currency, PaymentMethodType};
use common_utils::{
    errors::CustomResult,
    types::{self, StringMinorUnit},
};
use domain_types::{
    connector_flow::{Authorize, PSync, RSync, Refund},
    connector_types::{
        ConnectorCommon, ConnectorCommonV2, ConnectorIntegrationV2, ConnectorSpecifications,
        ConnectorWebhookSecrets, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData,
        PaymentsSyncData, RefundFlowData, RefundsData, RefundsResponseData, RefundSyncData,
    },
    payment_method_data::PaymentMethodDataTypes,
    router_data_v2::RouterDataV2,
    types as domain_types,
};
use hyperswitch_masking::Secret;
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
    fn get_url<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>(
        connector: &crate::connectors::easebuzz::EaseBuzz<T>,
        req: &RouterDataV2<Self, domain_types::connector_types::PaymentFlowData, Self::Request, Self::Response>,
        base_url: &str,
    ) -> CustomResult<String, errors::ConnectorError>
    where
        Self: Sized;
}

impl GetUrl for domain_types::connector_types::PaymentsAuthorizeType {
    type Request = domain_types::connector_types::PaymentsAuthorizeData<T>;
    type Response = domain_types::connector_types::PaymentsResponseData;

    fn get_url<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>(
        _connector: &crate::connectors::easebuzz::EaseBuzz<T>,
        req: &RouterDataV2<Self, domain_types::connector_types::PaymentFlowData, Self::Request, Self::Response>,
        base_url: &str,
    ) -> CustomResult<String, errors::ConnectorError> {
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
        base_url: &str,
    ) -> CustomResult<String, errors::ConnectorError> {
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
        base_url: &str,
    ) -> CustomResult<String, errors::ConnectorError> {
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
        base_url: &str,
    ) -> CustomResult<String, errors::ConnectorError> {
        let test_mode = req.resource_common_data.test_mode.unwrap_or(false);
        Ok(crate::connectors::easebuzz::constants::get_refund_sync_url(test_mode))
    }
}

// Re-export domain types for convenience
pub use domain_types::*;