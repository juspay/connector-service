// Placeholder transformers for EaseBuzz connector
// This file contains the request/response transformation logic

use domain_types::{
    connector_flow::{Authorize, PSync, RSync},
    connector_types::{PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, RefundSyncData, RefundsResponseData},
    payment_method_data::PaymentMethodDataTypes,
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
};
use hyperswitch_masking::Secret;

#[derive(Debug, serde::Serialize)]
pub struct EaseBuzzPaymentsRequest {
    // Placeholder fields
}

#[derive(Debug, serde::Deserialize)]
pub struct EaseBuzzPaymentsResponse {
    // Placeholder fields
}

#[derive(Debug, serde::Serialize)]
pub struct EaseBuzzPaymentsSyncRequest {
    // Placeholder fields
}

#[derive(Debug, serde::Deserialize)]
pub struct EaseBuzzPaymentsSyncResponse {
    // Placeholder fields
}

#[derive(Debug, serde::Serialize)]
pub struct EaseBuzzRefundSyncRequest {
    // Placeholder fields
}

#[derive(Debug, serde::Deserialize)]
pub struct EaseBuzzRefundSyncResponseWrapper {
    // Placeholder fields
}

pub fn get_auth_header(_auth_type: &ConnectorAuthType) -> Result<Vec<(String, String)>, domain_types::errors::ConnectorError> {
    Ok(vec![])
}