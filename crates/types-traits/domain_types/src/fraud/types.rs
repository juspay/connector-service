//! Fraud type conversions - Following the payouts pattern

use crate::{
    errors::{IntegrationError, IntegrationErrorContext},
    fraud,
    types::Connectors,
    utils::{extract_merchant_id_from_metadata, ForeignTryFrom},
};
use common_utils::metadata::MaskedMetadata;

// Example implementation structure (actual conversions to be added as needed):
//
// impl ForeignTryFrom<(grpc_api_types::fraud::FraudServiceEvaluatePreAuthorizationRequest, Connectors, &MaskedMetadata)>
//     for fraud::fraud_types::FraudFlowData
// {
//     type Error = IntegrationError;
//
//     fn foreign_try_from(
//         (value, connectors, metadata): (
//             grpc_api_types::fraud::FraudServiceEvaluatePreAuthorizationRequest,
//             Connectors,
//             &MaskedMetadata,
//         ),
//     ) -> Result<Self, error_stack::Report<Self::Error>> {
//         let merchant_id = extract_merchant_id_from_metadata(metadata)?;
//
//         Ok(Self {
//             merchant_fraud_id: value.merchant_fraud_id.clone(),
//             order_id: value.order_id.clone(),
//             connector_fraud_id: value.connector_fraud_id.clone(),
//             connectors,
//             connector_state: value.connector_state.map(|s| s.into()),
//             raw_connector_response: None,
//             raw_connector_request: None,
//             connector_response_headers: None,
//         })
//     }
// }
