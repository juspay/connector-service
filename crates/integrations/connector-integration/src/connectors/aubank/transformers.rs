//! AU Bank Transformer — Delegates to shared Juspay UPI Stack utilities

use crate::connectors::{
    aubank::AubankRouterData,
    juspay_upi_stack::{
        transformers::{
            build_authorize_request, build_psync_request, build_refund_request,
            build_rsync_request, handle_authorize_response, handle_psync_response,
            handle_refund_response, handle_rsync_response,
        },
        types::{
            JuspayUpiAuthConfig as SharedAuthConfig, JwsObject, Refund360Response,
            RegisterIntentResponse, Status360Response,
        },
    },
};
use crate::types::ResponseRouterData;
use domain_types::{
    connector_flow::{Authorize, PSync, RSync, Refund},
    connector_types::{
        PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData,
        RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData,
    },
    errors::{ConnectorError, IntegrationError, IntegrationErrorContext},
    payment_method_data::PaymentMethodDataTypes,
    router_data::ConnectorSpecificConfig,
    router_data_v2::RouterDataV2,
};
use error_stack::ResultExt;
use hyperswitch_masking::{PeekInterface, Secret};
use serde::Serialize;

// Re-export shared utilities for use in aubank.rs
pub use crate::connectors::juspay_upi_stack::crypto::get_current_timestamp_ms;
pub use crate::connectors::juspay_upi_stack::transformers::build_error_response;
pub use crate::connectors::juspay_upi_stack::transformers::extract_merchant_identifiers_from_metadata;

/// Auth configuration for AU Bank.
/// This struct extracts AU-specific fields from ConnectorSpecificConfig.
#[derive(Debug, Clone)]
pub struct AubankAuthConfig {
    pub merchant_kid: String,
    pub juspay_kid: String,
    pub merchant_private_key: Secret<String>,
    pub juspay_public_key: Secret<String>,
    pub base_url: String,
}

impl TryFrom<&ConnectorSpecificConfig> for AubankAuthConfig {
    type Error = error_stack::Report<IntegrationError>;

    fn try_from(config: &ConnectorSpecificConfig) -> Result<Self, Self::Error> {
        match config {
            ConnectorSpecificConfig::Aubank {
                merchant_kid,
                juspay_kid,
                merchant_private_key,
                juspay_public_key,
                base_url,
            } => Ok(Self {
                merchant_kid: merchant_kid.peek().clone(),
                juspay_kid: juspay_kid.peek().clone(),
                merchant_private_key: merchant_private_key.clone(),
                juspay_public_key: juspay_public_key.clone(),
                base_url: base_url.clone().unwrap_or_default(),
            }),
            _ => Err(IntegrationError::FailedToObtainAuthType {
                context: IntegrationErrorContext {
                    suggested_action: Some("Check connector_specific_config in merchant connector account configuration".to_string()),
                    doc_url: Some(crate::connectors::juspay_upi_stack::constants::DOC_URL_REGISTER_INTENT.to_string()),
                    additional_context: Some("Expected Aubank variant with fields: merchant_kid, juspay_kid, merchant_private_key, juspay_public_key".to_string()),
                },
            }
            .into()),
        }
    }
}

impl From<AubankAuthConfig> for SharedAuthConfig {
    fn from(config: AubankAuthConfig) -> Self {
        let jwe_kid = config.merchant_kid.clone();
        let merchant_private_key = config.merchant_private_key.clone();
        Self {
            merchant_kid: config.merchant_kid,
            juspay_kid: config.juspay_kid,
            merchant_private_key: config.merchant_private_key,
            juspay_public_key: config.juspay_public_key,
            use_jwe: true, // AU Bank uses JWE encryption for responses
            jwe_kid: Some(jwe_kid),
            juspay_jwe_public_key: None,
            merchant_jwe_private_key: Some(merchant_private_key),
        }
    }
}

/// Error response structure from AU Bank API.
#[derive(Debug, serde::Deserialize)]
pub struct AubankErrorResponse {
    pub status: String,
    #[serde(rename = "responseCode")]
    pub response_code: String,
    #[serde(rename = "responseMessage")]
    pub response_message: String,
}

// ============================================================
// NEWTYPE WRAPPERS to avoid conflicting impls with Axisbank
// ============================================================

/// Authorize request body (Register Intent) — JWS object.
pub type AubankPaymentsRequest = JwsObject;

/// Authorize response wrapper (newtype to avoid conflict with Axisbank).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AubankPaymentsResponse(pub RegisterIntentResponse);

impl std::ops::Deref for AubankPaymentsResponse {
    type Target = RegisterIntentResponse;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// PSync request body (Status 360) — JWS object.
pub type AubankSyncRequest = JwsObject;

/// PSync response wrapper (newtype to avoid conflict with Axisbank).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AubankSyncResponse(pub Status360Response);

impl std::ops::Deref for AubankSyncResponse {
    type Target = Status360Response;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Refund request body (Refund 360) — JWS object.
pub type AubankRefundRequest = JwsObject;

/// Refund response wrapper (newtype to avoid conflict with Axisbank).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AubankRefundResponse(pub Refund360Response);

impl std::ops::Deref for AubankRefundResponse {
    type Target = Refund360Response;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// RSync request body (Refund Status 360) — JWS object.
pub type AubankRefundSyncRequest = JwsObject;

/// RSync response wrapper (newtype to avoid conflict with Axisbank).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AubankRefundSyncResponse(pub Refund360Response);

impl std::ops::Deref for AubankRefundSyncResponse {
    type Target = Refund360Response;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// ============================================================
// REQUEST BUILDERS
// ============================================================

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        AubankRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for AubankPaymentsRequest
{
    type Error = error_stack::Report<IntegrationError>;

    fn try_from(
        wrapper: AubankRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &wrapper.router_data;
        let auth = AubankAuthConfig::try_from(&router_data.connector_config)?;
        let shared_auth: SharedAuthConfig = auth.into();

        // Convert amount from minor to major units
        let amount = wrapper
            .connector
            .amount_converter
            .convert(router_data.request.minor_amount, router_data.request.currency)
            .change_context(IntegrationError::RequestEncodingFailed {
                context: IntegrationErrorContext {
                    suggested_action: Some("Verify amount and currency values are valid".to_string()),
                    doc_url: Some(crate::connectors::juspay_upi_stack::constants::DOC_URL_REGISTER_INTENT.to_string()),
                    additional_context: Some("Amount must be a positive integer in minor units (paise). Currency should be INR for UPI transactions.".to_string()),
                },
            })?;

        build_authorize_request(router_data, &shared_auth, amount.get_amount_as_string())
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static>
    TryFrom<ResponseRouterData<AubankPaymentsResponse, Self>>
    for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        resp: ResponseRouterData<AubankPaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        handle_authorize_response(resp.response.0, resp.http_code, resp.router_data)
    }
}

// ============================================================
// PSYNC FLOW (Status 360)
// ============================================================

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        AubankRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    > for AubankSyncRequest
{
    type Error = error_stack::Report<IntegrationError>;

    fn try_from(
        wrapper: AubankRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &wrapper.router_data;
        let auth = AubankAuthConfig::try_from(&router_data.connector_config)?;
        let shared_auth: SharedAuthConfig = auth.into();

        let merchant_transaction_id = router_data
            .resource_common_data
            .connector_request_reference_id
            .clone();

        build_psync_request(merchant_transaction_id, &shared_auth)
    }
}

impl TryFrom<ResponseRouterData<AubankSyncResponse, Self>>
    for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(resp: ResponseRouterData<AubankSyncResponse, Self>) -> Result<Self, Self::Error> {
        handle_psync_response(resp.response.0, resp.http_code, resp.router_data)
    }
}

// ============================================================
// REFUND FLOW (Refund 360)
// ============================================================

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        AubankRouterData<RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>, T>,
    > for AubankRefundRequest
{
    type Error = error_stack::Report<IntegrationError>;

    fn try_from(
        wrapper: AubankRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &wrapper.router_data;
        let auth = AubankAuthConfig::try_from(&router_data.connector_config)?;
        let shared_auth: SharedAuthConfig = auth.into();

        build_refund_request(&router_data.request, &shared_auth)
    }
}

impl TryFrom<ResponseRouterData<AubankRefundResponse, Self>>
    for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(resp: ResponseRouterData<AubankRefundResponse, Self>) -> Result<Self, Self::Error> {
        handle_refund_response(resp.response.0, resp.http_code, resp.router_data)
    }
}

// ============================================================
// RSYNC FLOW (Refund Status 360)
// ============================================================

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        AubankRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    > for AubankRefundSyncRequest
{
    type Error = error_stack::Report<IntegrationError>;

    fn try_from(
        wrapper: AubankRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &wrapper.router_data;
        let auth = AubankAuthConfig::try_from(&router_data.connector_config)?;
        let shared_auth: SharedAuthConfig = auth.into();

        build_rsync_request(&router_data.request, &shared_auth)
    }
}

impl TryFrom<ResponseRouterData<AubankRefundSyncResponse, Self>>
    for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        resp: ResponseRouterData<AubankRefundSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        handle_rsync_response(resp.response.0, resp.http_code, resp.router_data)
    }
}
