use common_enums::enums;
use common_utils::{
    consts::{NO_ERROR_CODE, NO_ERROR_MESSAGE},
    pii,
    types::{AmountConvertor, FloatMajorUnit, FloatMajorUnitForConnector},
};
use domain_types::{
    connector_flow::{Authorize, Capture, PSync, RSync, Refund, Void},
    connector_types::{
        PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData,
        RefundsResponseData, ResponseId,
    },
    errors::ConnectorError,
    payment_method_data::PaymentMethodData,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
};
use error_stack::{report, ResultExt};
use hyperswitch_masking::{PeekInterface, Secret};
use serde::{Deserialize, Serialize};

use crate::{connectors::fiserv::FiservRouterData, types::ResponseRouterData};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservPaymentsRequest {
    pub amount: Amount,
    pub source: Source,
    pub transaction_details: TransactionDetails,
    pub merchant_details: MerchantDetails,
    pub transaction_interaction: TransactionInteraction,
}

#[derive(Debug, Serialize)]
#[serde(tag = "sourceType")]
pub enum Source {
    PaymentCard {
        card: CardData,
    },
    #[allow(dead_code)]
    GooglePay {
        data: Secret<String>,
        signature: Secret<String>,
        version: String,
    },
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CardData {
    pub card_data: cards::CardNumber,
    pub expiration_month: Secret<String>,
    pub expiration_year: Secret<String>,
    pub security_code: Secret<String>,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GooglePayToken {
    pub signature: Secret<String>,
    pub signed_message: Secret<String>,
    pub protocol_version: String,
}

#[derive(Default, Debug, Serialize)]
pub struct Amount {
    pub total: FloatMajorUnit,
    pub currency: String,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionDetails {
    pub capture_flag: Option<bool>,
    pub reversal_reason_code: Option<String>,
    pub merchant_transaction_id: String,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MerchantDetails {
    pub merchant_id: Secret<String>,
    pub terminal_id: Option<Secret<String>>,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionInteraction {
    pub origin: TransactionInteractionOrigin,
    pub eci_indicator: TransactionInteractionEciIndicator,
    pub pos_condition_code: TransactionInteractionPosConditionCode,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum TransactionInteractionOrigin {
    #[default]
    Ecom,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TransactionInteractionEciIndicator {
    #[default]
    ChannelEncrypted,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TransactionInteractionPosConditionCode {
    #[default]
    CardNotPresentEcom,
}

fn get_card_expiry_year_4_digit_placeholder(
    year_yy: &Secret<String>,
) -> Result<Secret<String>, error_stack::Report<ConnectorError>> {
    let year_str = year_yy.peek();
    if year_str.len() == 2 && year_str.chars().all(char::is_numeric) {
        Ok(Secret::new(format!("20{year_str}")))
    } else if year_str.len() == 4 && year_str.chars().all(char::is_numeric) {
        Ok(year_yy.clone())
    } else {
        Err(report!(ConnectorError::RequestEncodingFailed))
            .attach_printable("Invalid card expiry year format: expected YY or YYYY")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FiservAuthType {
    pub api_key: Secret<String>,
    pub merchant_account: Secret<String>,
    pub api_secret: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for FiservAuthType {
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey {
                api_key,
                key1,
                api_secret,
            } => Ok(Self {
                api_key: api_key.to_owned(),
                merchant_account: key1.to_owned(),
                api_secret: api_secret.to_owned(),
            }),
            _ => Err(report!(ConnectorError::FailedToObtainAuthType)),
        }
    }
}

#[derive(Default, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservErrorResponse {
    pub details: Option<Vec<FiservErrorDetails>>,
    pub error: Option<Vec<FiservErrorDetails>>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservErrorDetails {
    #[serde(rename = "type")]
    pub error_type: String,
    pub code: Option<String>,
    pub message: String,
    pub field: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum FiservPaymentStatus {
    Succeeded,
    Failed,
    Captured,
    Declined,
    Voided,
    Authorized,
    #[default]
    Processing,
}

impl From<FiservPaymentStatus> for enums::AttemptStatus {
    fn from(item: FiservPaymentStatus) -> Self {
        match item {
            FiservPaymentStatus::Captured | FiservPaymentStatus::Succeeded => Self::Charged,
            FiservPaymentStatus::Declined | FiservPaymentStatus::Failed => Self::Failure,
            FiservPaymentStatus::Processing => Self::Authorizing,
            FiservPaymentStatus::Voided => Self::Voided,
            FiservPaymentStatus::Authorized => Self::Authorized,
        }
    }
}

impl From<FiservPaymentStatus> for enums::RefundStatus {
    fn from(item: FiservPaymentStatus) -> Self {
        match item {
            FiservPaymentStatus::Captured
            | FiservPaymentStatus::Succeeded
            | FiservPaymentStatus::Authorized => Self::Success,
            FiservPaymentStatus::Declined | FiservPaymentStatus::Failed => Self::Failure,
            FiservPaymentStatus::Voided | FiservPaymentStatus::Processing => Self::Pending,
        }
    }
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FiservPaymentsResponse {
    pub gateway_response: GatewayResponse,
}

// Create a new response type for Capture that's a clone of the payments response
// This resolves the naming conflict in the macro framework
#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FiservCaptureResponse {
    pub gateway_response: GatewayResponse,
}

// Create a response type for Void
#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FiservVoidResponse {
    pub gateway_response: GatewayResponse,
}

// Create Refund response type
#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FiservRefundResponse {
    pub gateway_response: GatewayResponse,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
#[serde(transparent)]
pub struct FiservSyncResponse {
    pub sync_responses: Vec<FiservPaymentsResponse>,
}

// Create a distinct type for RefundSync to avoid templating conflicts
#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
#[serde(transparent)]
pub struct FiservRefundSyncResponse {
    pub sync_responses: Vec<FiservPaymentsResponse>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GatewayResponse {
    pub gateway_transaction_id: Option<String>,
    pub transaction_state: FiservPaymentStatus,
    pub transaction_processing_details: TransactionProcessingDetails,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TransactionProcessingDetails {
    pub order_id: String,
    pub transaction_id: String,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservCaptureRequest {
    pub amount: Amount,
    pub transaction_details: TransactionDetails,
    pub merchant_details: MerchantDetails,
    pub reference_transaction_details: ReferenceTransactionDetails,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReferenceTransactionDetails {
    pub reference_transaction_id: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct FiservSessionObject {
    pub terminal_id: Secret<String>,
}

// The TryFrom<&Option<pii::SecretSerdeValue>> for FiservSessionObject might not be needed
// if FiservSessionObject is always parsed from the string within connector_meta_data directly
// in the TryFrom implementations for FiservPaymentsRequest, FiservCaptureRequest, etc.
impl TryFrom<&Option<pii::SecretSerdeValue>> for FiservSessionObject {
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(meta_data: &Option<pii::SecretSerdeValue>) -> Result<Self, Self::Error> {
        let secret_value_str = meta_data
            .as_ref()
            .ok_or_else(|| {
                report!(ConnectorError::MissingRequiredField {
                    field_name: "connector_meta_data (FiservSessionObject)"
                })
            })
            .and_then(|secret_value| match secret_value.peek() {
                serde_json::Value::String(s) => Ok(s.clone()),
                _ => Err(report!(ConnectorError::InvalidConnectorConfig {
                    config: "FiservSessionObject in connector_meta_data was not a JSON string",
                })),
            })?;

        serde_json::from_str(&secret_value_str).change_context(
            ConnectorError::InvalidConnectorConfig {
                config: "Deserializing FiservSessionObject from connector_meta_data string",
            },
        )
    }
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservVoidRequest {
    pub transaction_details: TransactionDetails,
    pub merchant_details: MerchantDetails,
    pub reference_transaction_details: ReferenceTransactionDetails,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservRefundRequest {
    pub amount: Amount,
    pub merchant_details: MerchantDetails,
    pub reference_transaction_details: ReferenceTransactionDetails,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservSyncRequest {
    pub merchant_details: MerchantDetails,
    pub reference_transaction_details: ReferenceTransactionDetails,
}

// Create a distinct type for RefundSync to avoid templating conflicts
#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservRefundSyncRequest {
    pub merchant_details: MerchantDetails,
    pub reference_transaction_details: ReferenceTransactionDetails,
}

// Implementations for FiservRouterData - needed for the macro framework
impl
    TryFrom<
        FiservRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        >,
    > for FiservPaymentsRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: FiservRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let auth: FiservAuthType = FiservAuthType::try_from(&router_data.connector_auth_type)?;

        // Use FloatMajorUnitForConnector to properly convert minor to major unit
        let converter = FloatMajorUnitForConnector;
        let amount_major = converter
            .convert(
                router_data.request.minor_amount,
                router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        let amount = Amount {
            total: amount_major,
            currency: router_data.request.currency.to_string(),
        };
        let transaction_details = TransactionDetails {
            capture_flag: Some(matches!(
                router_data.request.capture_method,
                Some(enums::CaptureMethod::Automatic) | None
            )),
            reversal_reason_code: None,
            merchant_transaction_id: router_data
                .resource_common_data
                .connector_request_reference_id
                .clone(),
        };

        let session_meta_value = router_data
            .resource_common_data
            .connector_meta_data
            .as_ref()
            .ok_or_else(|| {
                report!(ConnectorError::MissingRequiredField {
                    field_name: "connector_meta_data for FiservSessionObject"
                })
            })?
            .peek();

        let session_str = match session_meta_value {
            serde_json::Value::String(s) => s,
            _ => {
                return Err(report!(ConnectorError::InvalidConnectorConfig {
                    config: "connector_meta_data was not a JSON string for FiservSessionObject",
                }))
            }
        };

        let session: FiservSessionObject = serde_json::from_str(session_str).change_context(
            ConnectorError::InvalidConnectorConfig {
                config: "Deserializing FiservSessionObject from connector_meta_data string",
            },
        )?;

        let merchant_details = MerchantDetails {
            merchant_id: auth.merchant_account.clone(),
            terminal_id: Some(session.terminal_id.clone()),
        };
        let transaction_interaction = TransactionInteraction::default();

        let source = match router_data.request.payment_method_data.clone() {
            PaymentMethodData::Card(ref ccard) => {
                let card = CardData {
                    card_data: ccard.card_number.clone(),
                    expiration_month: ccard.card_exp_month.clone(),
                    expiration_year: get_card_expiry_year_4_digit_placeholder(
                        &ccard.card_exp_year,
                    )?,
                    security_code: ccard.card_cvc.clone(),
                };
                Source::PaymentCard { card }
            }
            _ => Err(report!(ConnectorError::NotImplemented(
                "Payment method not implemented for Fiserv".to_string(),
            )))?,
        };
        Ok(Self {
            amount,
            source,
            transaction_details,
            merchant_details,
            transaction_interaction,
        })
    }
}

impl
    TryFrom<
        FiservRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    > for FiservCaptureRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: FiservRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = item.router_data;
        let auth: FiservAuthType = FiservAuthType::try_from(&router_data.connector_auth_type)?;

        // Prioritize connector_metadata from PaymentsCaptureData if available,
        // otherwise fall back to resource_common_data.connector_meta_data.

        // Try to get session string from different sources - converting both paths to String for type consistency
        let session_str = if let Some(meta) = router_data
            .resource_common_data
            .connector_meta_data
            .as_ref()
        {
            // Use connector_meta_data from resource_common_data (which is Secret<Value>)
            match meta.peek() {
                serde_json::Value::String(s) => s.to_string(), // Convert &str to String
                _ => return Err(report!(ConnectorError::InvalidConnectorConfig {
                    config: "connector_meta_data was not a JSON string for FiservSessionObject in Capture",
                })),
            }
        } else if let Some(connector_meta) = router_data.request.connector_metadata.as_ref() {
            // Use connector_metadata from request (which is Value)
            match connector_meta {
                serde_json::Value::String(s) => s.clone(), // String
                _ => return Err(report!(ConnectorError::InvalidConnectorConfig {
                    config: "connector_metadata was not a JSON string for FiservSessionObject in Capture",
                })),
            }
        } else {
            // No metadata available
            return Err(report!(ConnectorError::MissingRequiredField {
                field_name:
                    "connector_metadata or connector_meta_data for FiservSessionObject in Capture"
            }));
        };

        let session: FiservSessionObject =
            serde_json::from_str(&session_str)
                .change_context(ConnectorError::InvalidConnectorConfig {
                config:
                    "Deserializing FiservSessionObject from connector_metadata string in Capture",
            })?;

        let merchant_details = MerchantDetails {
            merchant_id: auth.merchant_account.clone(),
            terminal_id: Some(session.terminal_id.clone()),
        };

        // Use FloatMajorUnitForConnector to properly convert minor to major unit
        let converter = FloatMajorUnitForConnector;

        let amount_major = converter
            .convert(
                router_data.request.minor_amount_to_capture,
                router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        Ok(Self {
            amount: Amount {
                total: amount_major,
                currency: router_data.request.currency.to_string(),
            },
            transaction_details: TransactionDetails {
                capture_flag: Some(true),
                reversal_reason_code: None,
                merchant_transaction_id: router_data
                    .resource_common_data
                    .connector_request_reference_id
                    .clone(),
            },
            merchant_details,
            reference_transaction_details: ReferenceTransactionDetails {
                reference_transaction_id: router_data
                    .request
                    .connector_transaction_id
                    .get_connector_transaction_id()
                    .change_context(ConnectorError::MissingConnectorTransactionID)?,
            },
        })
    }
}

impl
    TryFrom<
        FiservRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    > for FiservSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: FiservRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let auth: FiservAuthType = FiservAuthType::try_from(&router_data.connector_auth_type)?;
        Ok(Self {
            merchant_details: MerchantDetails {
                merchant_id: auth.merchant_account.clone(),
                terminal_id: None,
            },
            reference_transaction_details: ReferenceTransactionDetails {
                reference_transaction_id: router_data
                    .request
                    .connector_transaction_id
                    .get_connector_transaction_id()
                    .change_context(ConnectorError::MissingConnectorTransactionID)?,
            },
        })
    }
}

// Implementation for the Void request
impl
    TryFrom<
        FiservRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        >,
    > for FiservVoidRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: FiservRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let auth: FiservAuthType = FiservAuthType::try_from(&router_data.connector_auth_type)?;

        // Get session information
        let session_meta_value = router_data
            .resource_common_data
            .connector_meta_data
            .as_ref()
            .ok_or_else(|| {
                report!(ConnectorError::MissingRequiredField {
                    field_name: "connector_meta_data for FiservSessionObject in Void"
                })
            })?
            .peek();

        let session_str = match session_meta_value {
            serde_json::Value::String(s) => s,
            _ => {
                return Err(report!(ConnectorError::InvalidConnectorConfig {
                    config:
                        "connector_meta_data was not a JSON string for FiservSessionObject in Void",
                }))
            }
        };

        let session: FiservSessionObject = serde_json::from_str(session_str).change_context(
            ConnectorError::InvalidConnectorConfig {
                config: "Deserializing FiservSessionObject from connector_meta_data string in Void",
            },
        )?;

        Ok(Self {
            merchant_details: MerchantDetails {
                merchant_id: auth.merchant_account.clone(),
                terminal_id: Some(session.terminal_id.clone()),
            },
            reference_transaction_details: ReferenceTransactionDetails {
                reference_transaction_id: router_data.request.connector_transaction_id.clone(),
            },
            transaction_details: TransactionDetails {
                capture_flag: None,
                reversal_reason_code: router_data.request.cancellation_reason.clone(),
                merchant_transaction_id: router_data
                    .resource_common_data
                    .connector_request_reference_id
                    .clone(),
            },
        })
    }
}

// Implementation for the Refund request
impl
    TryFrom<
        FiservRouterData<RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>>,
    > for FiservRefundRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: FiservRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let auth: FiservAuthType = FiservAuthType::try_from(&router_data.connector_auth_type)?;

        // Try to get session information - use only connector_metadata from request since
        // RefundFlowData doesn't have connector_meta_data field in resource_common_data
        let session_str = if let Some(connector_meta) =
            router_data.request.connector_metadata.as_ref()
        {
            // Use connector_metadata from request
            match connector_meta {
                serde_json::Value::String(s) => s.clone(),
                _ => return Err(report!(ConnectorError::InvalidConnectorConfig {
                    config:
                        "connector_metadata was not a JSON string for FiservSessionObject in Refund",
                })),
            }
        } else {
            // No metadata available
            return Err(report!(ConnectorError::MissingRequiredField {
                field_name:
                    "connector_metadata or connector_meta_data for FiservSessionObject in Refund"
            }));
        };

        let session: FiservSessionObject = serde_json::from_str(&session_str).change_context(
            ConnectorError::InvalidConnectorConfig {
                config: "Deserializing FiservSessionObject from metadata string in Refund",
            },
        )?;

        // Convert minor amount to float major unit
        let converter = FloatMajorUnitForConnector;
        let amount_major = converter
            .convert(
                router_data.request.minor_refund_amount,
                router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        Ok(Self {
            amount: Amount {
                total: amount_major,
                currency: router_data.request.currency.to_string(),
            },
            merchant_details: MerchantDetails {
                merchant_id: auth.merchant_account.clone(),
                terminal_id: Some(session.terminal_id.clone()),
            },
            reference_transaction_details: ReferenceTransactionDetails {
                reference_transaction_id: router_data.request.connector_transaction_id.to_string(),
            },
        })
    }
}

// Implementation for the RefundSync request
impl
    TryFrom<
        FiservRouterData<RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>>,
    > for FiservRefundSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: FiservRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let auth: FiservAuthType = FiservAuthType::try_from(&router_data.connector_auth_type)?;
        Ok(Self {
            merchant_details: MerchantDetails {
                merchant_id: auth.merchant_account.clone(),
                terminal_id: None,
            },
            reference_transaction_details: ReferenceTransactionDetails {
                reference_transaction_id: router_data.request.connector_transaction_id.clone(),
            },
        })
    }
}

// Response handling TryFrom implementations for macro framework

// Standard payment response handling for Authorize flow
impl<F> TryFrom<ResponseRouterData<FiservPaymentsResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<FiservPaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let gateway_resp = &response.gateway_response;
        let status = enums::AttemptStatus::from(gateway_resp.transaction_state.clone());

        // Update the status in router_data
        let mut router_data_out = router_data;
        router_data_out.resource_common_data.status = status;

        let response_payload = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(
                gateway_resp
                    .gateway_transaction_id
                    .clone()
                    .unwrap_or_else(|| {
                        gateway_resp
                            .transaction_processing_details
                            .transaction_id
                            .clone()
                    }),
            ),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: Some(
                gateway_resp.transaction_processing_details.order_id.clone(),
            ),
            incremental_authorization_allowed: None,
            raw_connector_response: None,
            status_code: Some(item.http_code),
        };

        if status == enums::AttemptStatus::Failure || status == enums::AttemptStatus::Voided {
            router_data_out.response = Err(ErrorResponse {
                code: gateway_resp
                    .transaction_processing_details
                    .transaction_id
                    .clone(),
                message: format!("Payment status: {:?}", gateway_resp.transaction_state),
                reason: None,
                status_code: http_code,
                attempt_status: Some(status),
                connector_transaction_id: gateway_resp.gateway_transaction_id.clone(),
                network_decline_code: None,
                network_advice_code: None,
                network_error_message: None,
                raw_connector_response: None,
            });
        } else {
            router_data_out.response = Ok(response_payload);
        }

        Ok(router_data_out)
    }
}

// Implementation for the Capture flow response
impl<F> TryFrom<ResponseRouterData<FiservCaptureResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<FiservCaptureResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let gateway_resp = &response.gateway_response;
        let status = enums::AttemptStatus::from(gateway_resp.transaction_state.clone());

        // Update the status in router_data
        let mut router_data_out = router_data;
        router_data_out.resource_common_data.status = status;

        let response_payload = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(
                gateway_resp
                    .gateway_transaction_id
                    .clone()
                    .unwrap_or_else(|| {
                        gateway_resp
                            .transaction_processing_details
                            .transaction_id
                            .clone()
                    }),
            ),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: Some(
                gateway_resp.transaction_processing_details.order_id.clone(),
            ),
            incremental_authorization_allowed: None,
            raw_connector_response: None,
            status_code: Some(item.http_code),
        };

        if status == enums::AttemptStatus::Failure || status == enums::AttemptStatus::Voided {
            router_data_out.response = Err(ErrorResponse {
                code: gateway_resp
                    .transaction_processing_details
                    .transaction_id
                    .clone(),
                message: format!("Payment status: {:?}", gateway_resp.transaction_state),
                reason: None,
                status_code: http_code,
                attempt_status: Some(status),
                connector_transaction_id: gateway_resp.gateway_transaction_id.clone(),
                network_decline_code: None,
                network_advice_code: None,
                network_error_message: None,
                raw_connector_response: None,
            });
        } else {
            router_data_out.response = Ok(response_payload);
        }

        Ok(router_data_out)
    }
}

// Implementation for the Void flow response
impl<F> TryFrom<ResponseRouterData<FiservVoidResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(item: ResponseRouterData<FiservVoidResponse, Self>) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let gateway_resp = &response.gateway_response;
        let status = enums::AttemptStatus::from(gateway_resp.transaction_state.clone());

        // Update the status in router_data
        let mut router_data_out = router_data;
        router_data_out.resource_common_data.status = status;

        let response_payload = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(
                gateway_resp
                    .gateway_transaction_id
                    .clone()
                    .unwrap_or_else(|| {
                        gateway_resp
                            .transaction_processing_details
                            .transaction_id
                            .clone()
                    }),
            ),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: Some(
                gateway_resp.transaction_processing_details.order_id.clone(),
            ),
            incremental_authorization_allowed: None,
            raw_connector_response: None,
            status_code: Some(item.http_code),
        };

        if status == enums::AttemptStatus::Failure {
            router_data_out.response = Err(ErrorResponse {
                code: gateway_resp
                    .transaction_processing_details
                    .transaction_id
                    .clone(),
                message: format!("Void status: {:?}", gateway_resp.transaction_state),
                reason: None,
                status_code: http_code,
                attempt_status: Some(status),
                connector_transaction_id: gateway_resp.gateway_transaction_id.clone(),
                network_decline_code: None,
                network_advice_code: None,
                network_error_message: None,
                raw_connector_response: None,
            });
        } else {
            router_data_out.response = Ok(response_payload);
        }

        Ok(router_data_out)
    }
}

// Payment Sync response handling
impl<F> TryFrom<ResponseRouterData<FiservSyncResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(item: ResponseRouterData<FiservSyncResponse, Self>) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        // Get first transaction from array
        let fiserv_payment_response = response
            .sync_responses
            .first()
            .ok_or(ConnectorError::ResponseHandlingFailed)
            .attach_printable("Fiserv Sync response array was empty")?;

        let gateway_resp = &fiserv_payment_response.gateway_response;
        let status = enums::AttemptStatus::from(gateway_resp.transaction_state.clone());

        // Update the status in router_data
        let mut router_data_out = router_data;
        router_data_out.resource_common_data.status = status;

        let response_payload = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(
                gateway_resp
                    .gateway_transaction_id
                    .clone()
                    .unwrap_or_else(|| {
                        gateway_resp
                            .transaction_processing_details
                            .transaction_id
                            .clone()
                    }),
            ),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: Some(
                gateway_resp.transaction_processing_details.order_id.clone(),
            ),
            incremental_authorization_allowed: None,
            raw_connector_response: None,
            status_code: Some(item.http_code),
        };

        if status == enums::AttemptStatus::Failure || status == enums::AttemptStatus::Voided {
            router_data_out.response = Err(ErrorResponse {
                code: gateway_resp
                    .transaction_processing_details
                    .transaction_id
                    .clone(),
                message: format!("Payment status: {:?}", gateway_resp.transaction_state),
                reason: None,
                status_code: http_code,
                attempt_status: Some(status),
                connector_transaction_id: gateway_resp.gateway_transaction_id.clone(),
                network_decline_code: None,
                network_advice_code: None,
                network_error_message: None,
                raw_connector_response: None,
            });
        } else {
            router_data_out.response = Ok(response_payload);
        }

        Ok(router_data_out)
    }
}

// Refund flow response handling
impl<F> TryFrom<ResponseRouterData<FiservRefundResponse, Self>>
    for RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(item: ResponseRouterData<FiservRefundResponse, Self>) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let gateway_resp = &response.gateway_response;
        let refund_status = enums::RefundStatus::from(gateway_resp.transaction_state.clone());

        // Update the status in router_data
        let mut router_data_out = router_data;

        let response_payload = RefundsResponseData {
            connector_refund_id: gateway_resp
                .gateway_transaction_id
                .clone()
                .unwrap_or_else(|| {
                    gateway_resp
                        .transaction_processing_details
                        .transaction_id
                        .clone()
                }),
            refund_status,
            raw_connector_response: None,
            status_code: Some(http_code),
        };

        if refund_status == enums::RefundStatus::Failure {
            router_data_out.response = Err(ErrorResponse {
                code: gateway_resp
                    .transaction_processing_details
                    .transaction_id
                    .clone(),
                message: format!("Refund status: {:?}", gateway_resp.transaction_state),
                reason: None,
                status_code: http_code,
                attempt_status: None,
                connector_transaction_id: gateway_resp.gateway_transaction_id.clone(),
                network_decline_code: None,
                network_advice_code: None,
                network_error_message: None,
                raw_connector_response: None,
            });
        } else {
            router_data_out.response = Ok(response_payload);
        }

        Ok(router_data_out)
    }
}

// Refund Sync response handling
impl<F> TryFrom<ResponseRouterData<FiservRefundSyncResponse, Self>>
    for RouterDataV2<F, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<FiservRefundSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        // Get first transaction from array
        let fiserv_payment_response = response
            .sync_responses
            .first()
            .ok_or(ConnectorError::ResponseHandlingFailed)
            .attach_printable("Fiserv Sync response array was empty")?;

        let gateway_resp = &fiserv_payment_response.gateway_response;
        let refund_status = enums::RefundStatus::from(gateway_resp.transaction_state.clone());

        // Update the router data
        let mut router_data_out = router_data;

        let response_payload = RefundsResponseData {
            connector_refund_id: gateway_resp
                .gateway_transaction_id
                .clone()
                .unwrap_or_else(|| {
                    gateway_resp
                        .transaction_processing_details
                        .transaction_id
                        .clone()
                }),
            refund_status,
            raw_connector_response: None,
            status_code: Some(http_code),
        };

        if refund_status == enums::RefundStatus::Failure {
            router_data_out.response = Err(ErrorResponse {
                code: gateway_resp
                    .transaction_processing_details
                    .transaction_id
                    .clone(),
                message: format!("Refund status: {:?}", gateway_resp.transaction_state),
                reason: None,
                status_code: http_code,
                attempt_status: None,
                connector_transaction_id: gateway_resp.gateway_transaction_id.clone(),
                network_decline_code: None,
                network_advice_code: None,
                network_error_message: None,
                raw_connector_response: None,
            });
        } else {
            router_data_out.response = Ok(response_payload);
        }

        Ok(router_data_out)
    }
}

// Error response handling
impl<F, Req, Res> TryFrom<ResponseRouterData<FiservErrorResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, Req, Res>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(item: ResponseRouterData<FiservErrorResponse, Self>) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let error_details = response
            .error
            .as_ref()
            .or(response.details.as_ref())
            .and_then(|e| e.first());

        let message = error_details.map_or(NO_ERROR_MESSAGE.to_string(), |e| e.message.clone());
        let code = error_details
            .and_then(|e| e.code.clone())
            .unwrap_or_else(|| NO_ERROR_CODE.to_string());
        let reason = error_details.and_then(|e| e.field.clone());

        let mut router_data_out = router_data;
        router_data_out.response = Err(ErrorResponse {
            code,
            message,
            reason,
            status_code: http_code,
            attempt_status: None,
            connector_transaction_id: None,
            network_decline_code: None,
            network_advice_code: None,
            network_error_message: None,
            raw_connector_response: None,
        });

        Ok(router_data_out)
    }
}
