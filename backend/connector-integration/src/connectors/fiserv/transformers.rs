use hyperswitch_common_enums::enums;
use hyperswitch_common_utils::{
    pii, 
    types::FloatMajorUnit,
};
use error_stack::{ResultExt, report};
use hyperswitch_domain_models::{
    payment_method_data::PaymentMethodData,
    router_data::ConnectorAuthType, // Removed ErrorResponse as DomainModelsErrorResponse
    // router_flow_types::refunds::{RSync}, // Removed Execute // This RSync is unused due to full qualification
    // router_request_types::ResponseId as DomainModelsResponseId, // Unused
    // router_response_types::{ // Unused
    //     PaymentsResponseData as HsPaymentsResponseData, 
    //     RefundsResponseData as HsRefundsResponseData
    // },
    // types as hs_types, // Unused
};
use hyperswitch_interfaces::errors;
use hyperswitch_masking::{Secret, PeekInterface}; 
use serde::{Deserialize, Serialize};

use domain_types::{
    connector_flow::{Authorize as AuthorizeFlow, Capture as CaptureFlow, Void as VoidFlow, PSync as PSyncFlow, Refund as RefundFlowMarker}, // Added RefundFlowMarker
    connector_types::{
        PaymentFlowData, PaymentsAuthorizeData, PaymentsCaptureData, 
        PaymentsResponseData as ConnectorPaymentsResponseData, 
        PaymentsSyncData as ConnectorPaymentsSyncData, 
        RefundFlowData, RefundsData, 
        RefundsResponseData as ConnectorRefundsResponseData, 
        PaymentVoidData,
        // ResponseId as ConnectorResponseId, // Unused
    },
    // utils::ForeignTryFrom, // Unused
};
use hyperswitch_domain_models::router_data_v2::RouterDataV2;


#[derive(Debug)] // Removed Serialize from FiservRouterData
pub struct FiservRouterData<'a, F, ReqBody, Resp> {
    pub amount: FloatMajorUnit, 
    pub router_data: &'a RouterDataV2<F, ReqBody, PaymentsAuthorizeData, Resp>, 
}

// This TryFrom is specifically for Authorize flow where PaymentsAuthorizeData is in RouterDataV2
impl<'a, F, ReqBody, Resp> TryFrom<(FloatMajorUnit, &'a RouterDataV2<F, ReqBody, PaymentsAuthorizeData, Resp>)> for FiservRouterData<'a, F, ReqBody, Resp> {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from((amount, router_data): (FloatMajorUnit, &'a RouterDataV2<F, ReqBody, PaymentsAuthorizeData, Resp>)) -> Result<Self, Self::Error> {
        Ok(Self {
            amount,
            router_data,
        })
    }
}

// Specific FiservRouterData for Refund flow
#[derive(Debug)]
pub struct FiservRefundRouterData<'a> {
    pub amount: FloatMajorUnit,
    // This must be RefundFlowData to match the RefundV2 trait constraint
    pub router_data: &'a RouterDataV2<RefundFlowMarker, RefundFlowData, RefundsData, ConnectorRefundsResponseData>,
}

impl<'a> TryFrom<(FloatMajorUnit, &'a RouterDataV2<RefundFlowMarker, RefundFlowData, RefundsData, ConnectorRefundsResponseData>)> for FiservRefundRouterData<'a> {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from((amount, router_data): (FloatMajorUnit, &'a RouterDataV2<RefundFlowMarker, RefundFlowData, RefundsData, ConnectorRefundsResponseData>)) -> Result<Self, Self::Error> {
        Ok(Self {
            amount,
            router_data,
        })
    }
}

// Specific FiservRouterData for Capture flow
#[derive(Debug)]
pub struct FiservCaptureRouterData<'a> {
    pub amount: FloatMajorUnit,
    pub router_data: &'a RouterDataV2<CaptureFlow, PaymentFlowData, PaymentsCaptureData, ConnectorPaymentsResponseData>,
}

impl<'a> TryFrom<(FloatMajorUnit, &'a RouterDataV2<CaptureFlow, PaymentFlowData, PaymentsCaptureData, ConnectorPaymentsResponseData>)> for FiservCaptureRouterData<'a> {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from((amount, router_data): (FloatMajorUnit, &'a RouterDataV2<CaptureFlow, PaymentFlowData, PaymentsCaptureData, ConnectorPaymentsResponseData>)) -> Result<Self, Self::Error> {
        Ok(Self {
            amount,
            router_data,
        })
    }
}


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
    PaymentCard { card: CardData },
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
    pub card_data: hyperswitch_cards::CardNumber, 
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

fn get_card_expiry_year_4_digit_placeholder(year_yy: &Secret<String>) -> Result<Secret<String>, error_stack::Report<errors::ConnectorError>> {
    let year_str = year_yy.peek();
    if year_str.len() == 2 && year_str.chars().all(char::is_numeric) {
        Ok(Secret::new(format!("20{}", year_str)))
    } else if year_str.len() == 4 && year_str.chars().all(char::is_numeric) {
        Ok(year_yy.clone()) 
    } else {
        Err(report!(errors::ConnectorError::RequestEncodingFailed))
            .attach_printable("Invalid card expiry year format: expected YY or YYYY")
    }
}

impl<'a> TryFrom<&FiservRouterData<'a, AuthorizeFlow, PaymentFlowData, ConnectorPaymentsResponseData>> for FiservPaymentsRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: &FiservRouterData<'a, AuthorizeFlow, PaymentFlowData, ConnectorPaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let router_data = item.router_data; 
        let auth: FiservAuthType =
            FiservAuthType::try_from(&router_data.connector_auth_type)?;

        let amount = Amount {
            total: item.amount.clone(), 
            currency: router_data.request.currency.to_string(),
        };
        let transaction_details = TransactionDetails {
            capture_flag: Some(matches!(
                router_data.request.capture_method,
                Some(enums::CaptureMethod::Automatic) | None 
            )),
            reversal_reason_code: None,
            merchant_transaction_id: router_data.resource_common_data.connector_request_reference_id.clone(),
        };

        let session_meta_value = router_data.resource_common_data.connector_meta_data
            .as_ref()
            .ok_or_else(|| report!(errors::ConnectorError::MissingRequiredField { field_name: "connector_meta_data for FiservSessionObject" }))?
            .peek();

        let session_str = match session_meta_value {
            serde_json::Value::String(s) => s,
            _ => return Err(report!(errors::ConnectorError::InvalidConnectorConfig {
                config: "connector_meta_data was not a JSON string for FiservSessionObject",
            })),
        };
            
        let session: FiservSessionObject = serde_json::from_str(session_str)
            .change_context(errors::ConnectorError::InvalidConnectorConfig {
                config: "Deserializing FiservSessionObject from connector_meta_data string",
            })?;

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
                    expiration_year: get_card_expiry_year_4_digit_placeholder(&ccard.card_exp_year)?,
                    security_code: ccard.card_cvc.clone(),
                };
                Source::PaymentCard { card }
            }
            _ => Err(report!(errors::ConnectorError::NotImplemented(
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


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FiservAuthType {
    pub api_key: Secret<String>,
    pub merchant_account: Secret<String>, 
    pub api_secret: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for FiservAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey { api_key, key1, api_secret } => Ok(Self {
                api_key: api_key.to_owned(),
                merchant_account: key1.to_owned(),
                api_secret: api_secret.to_owned(),
            }),
            _ => Err(report!(errors::ConnectorError::FailedToObtainAuthType)),
        }
    }
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservCancelRequest {
    pub transaction_details: TransactionDetails,
    pub merchant_details: MerchantDetails,
    pub reference_transaction_details: ReferenceTransactionDetails,
}

impl TryFrom<&RouterDataV2<VoidFlow, PaymentFlowData, PaymentVoidData, ConnectorPaymentsResponseData>> for FiservCancelRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &RouterDataV2<VoidFlow, PaymentFlowData, PaymentVoidData, ConnectorPaymentsResponseData>) -> Result<Self, Self::Error> {
        let auth: FiservAuthType =
            FiservAuthType::try_from(&item.connector_auth_type)?;

        let session_meta_value = item.resource_common_data.connector_meta_data
            .as_ref()
            .ok_or_else(|| report!(errors::ConnectorError::MissingRequiredField { field_name: "connector_meta_data for FiservSessionObject in Void" }))?
            .peek();

        let session_str = match session_meta_value {
            serde_json::Value::String(s) => s,
            _ => return Err(report!(errors::ConnectorError::InvalidConnectorConfig {
                config: "connector_meta_data was not a JSON string for FiservSessionObject in Void",
            })),
        };
            
        let session: FiservSessionObject = serde_json::from_str(session_str)
            .change_context(errors::ConnectorError::InvalidConnectorConfig {
                config: "Deserializing FiservSessionObject from connector_meta_data string in Void",
            })?;

        Ok(Self {
            merchant_details: MerchantDetails {
                merchant_id: auth.merchant_account.clone(),
                terminal_id: Some(session.terminal_id.clone()),
            },
            reference_transaction_details: ReferenceTransactionDetails {
                reference_transaction_id: item.request.connector_transaction_id.clone(), // Corrected: PaymentVoidData has connector_transaction_id
            },
            transaction_details: TransactionDetails {
                capture_flag: None,
                reversal_reason_code: item.request.cancellation_reason.clone(),
                merchant_transaction_id: item.resource_common_data.connector_request_reference_id.clone(),
            },
        })
    }
}


#[derive(Default, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorResponse { 
    pub details: Option<Vec<ErrorDetails>>,
    pub error: Option<Vec<ErrorDetails>>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorDetails {
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
            FiservPaymentStatus::Succeeded
            | FiservPaymentStatus::Authorized
            | FiservPaymentStatus::Captured => Self::Success, 
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

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
#[serde(transparent)]
pub struct FiservSyncResponse {
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
// I'll keep it for now in case it's used elsewhere or intended for a different purpose.

impl TryFrom<&Option<pii::SecretSerdeValue>> for FiservSessionObject {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(meta_data: &Option<pii::SecretSerdeValue>) -> Result<Self, Self::Error> {
        let secret_value_str = meta_data
            .as_ref()
            .ok_or_else(|| report!(errors::ConnectorError::MissingRequiredField {field_name: "connector_meta_data (FiservSessionObject)"}))
            .and_then(|secret_value| {
                match secret_value.peek() {
                    serde_json::Value::String(s) => Ok(s.clone()),
                    _ => Err(report!(errors::ConnectorError::InvalidConnectorConfig {
                        config: "FiservSessionObject in connector_meta_data was not a JSON string",
                    })),
                }
            })?;
        
        serde_json::from_str(&secret_value_str)
            .change_context(errors::ConnectorError::InvalidConnectorConfig {
                config: "Deserializing FiservSessionObject from connector_meta_data string",
            })
    }
}

impl<'a> TryFrom<&FiservCaptureRouterData<'a>> for FiservCaptureRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &FiservCaptureRouterData<'a>) -> Result<Self, Self::Error> {
        let router_data = item.router_data;
        let auth: FiservAuthType = FiservAuthType::try_from(&router_data.connector_auth_type)?;

        // Prioritize connector_metadata from PaymentsCaptureData if available,
        // otherwise fall back to resource_common_data.connector_meta_data.
        let connector_metadata_source = router_data.request.connector_metadata // From PaymentsCaptureData
            .as_ref()
            .map(|json_val| json_val.to_string()) // Convert serde_json::Value to String
            .or_else(|| {
                router_data.resource_common_data.connector_meta_data
                    .as_ref()
                    .and_then(|secret_val| match secret_val.peek() {
                        serde_json::Value::String(s) => Some(s.clone()),
                        _ => None,
                    })
            })
            .ok_or_else(|| report!(errors::ConnectorError::MissingRequiredField {
                field_name: "connector_metadata (for terminal_id) in either request or common data for Capture"
            }))?;
            
        let session: FiservSessionObject = serde_json::from_str(&connector_metadata_source)
            .change_context(errors::ConnectorError::InvalidConnectorConfig {
                config: "Deserializing FiservSessionObject from connector_metadata string in Capture",
            })?;
        
        Ok(Self {
            amount: Amount {
                total: item.amount.clone(), 
                currency: router_data.request.currency.to_string(),
            },
            transaction_details: TransactionDetails {
                capture_flag: Some(true), 
                reversal_reason_code: None,
                merchant_transaction_id: router_data.resource_common_data.connector_request_reference_id.clone(),
            },
            merchant_details: MerchantDetails {
                merchant_id: auth.merchant_account.clone(),
                terminal_id: Some(session.terminal_id.clone()),
            },
            reference_transaction_details: ReferenceTransactionDetails {
                reference_transaction_id: router_data // This is RouterDataV2<CaptureFlow, PaymentFlowData, PaymentsCaptureData, ConnectorPaymentsResponseData>
                    .request // This is PaymentsCaptureData
                    .connector_transaction_id // This is ConnectorResponseId
                    .get_connector_transaction_id() // Method on ConnectorResponseId
                    .change_context(errors::ConnectorError::MissingConnectorTransactionID)?, 
            },
        })
    }
}


#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservSyncRequest {
    pub merchant_details: MerchantDetails,
    pub reference_transaction_details: ReferenceTransactionDetails,
}

impl TryFrom<&RouterDataV2<PSyncFlow, PaymentFlowData, ConnectorPaymentsSyncData, ConnectorPaymentsResponseData>> for FiservSyncRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &RouterDataV2<PSyncFlow, PaymentFlowData, ConnectorPaymentsSyncData, ConnectorPaymentsResponseData>) -> Result<Self, Self::Error> {
        let auth: FiservAuthType = FiservAuthType::try_from(&item.connector_auth_type)?;
        Ok(Self {
            merchant_details: MerchantDetails {
                merchant_id: auth.merchant_account.clone(),
                terminal_id: None, 
            },
            reference_transaction_details: ReferenceTransactionDetails {
                reference_transaction_id: item
                    .request // This is ConnectorPaymentsSyncData
                    .connector_transaction_id // This is ConnectorResponseId
                    .get_connector_transaction_id()
                    .change_context(errors::ConnectorError::MissingConnectorTransactionID)?, 
            },
        })
    }
}

// Changed hyperswitch_domain_models::router_flow_types::RSync to domain_types::connector_flow::RSync
// and fully qualified RSync here as well
impl TryFrom<&RouterDataV2<domain_types::connector_flow::RSync, RefundFlowData, domain_types::connector_types::RefundSyncData, ConnectorRefundsResponseData>> for FiservSyncRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &RouterDataV2<domain_types::connector_flow::RSync, RefundFlowData, domain_types::connector_types::RefundSyncData, ConnectorRefundsResponseData>) -> Result<Self, Self::Error> {
        let auth: FiservAuthType = FiservAuthType::try_from(&item.connector_auth_type)?;
        Ok(Self {
            merchant_details: MerchantDetails {
                merchant_id: auth.merchant_account.clone(),
                terminal_id: None,
            },
            reference_transaction_details: ReferenceTransactionDetails {
                reference_transaction_id: item
                    .request // This is domain_types::connector_types::RefundSyncData
                    .connector_refund_id // This is String
                    .clone(),
            },
        })
    }
}


#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservRefundRequest {
    pub amount: Amount,
    pub merchant_details: MerchantDetails,
    pub reference_transaction_details: ReferenceTransactionDetails,
}

impl<'a> TryFrom<&FiservRefundRouterData<'a>> for FiservRefundRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &FiservRefundRouterData<'a>) -> Result<Self, Self::Error> {
        let router_data = item.router_data; // This is &RouterDataV2<RefundFlowMarker, RefundFlowData, RefundsData, ConnectorRefundsResponseData>
        let auth: FiservAuthType = FiservAuthType::try_from(&router_data.connector_auth_type)?;
        
        // Use refund_connector_metadata from RefundsData (router_data.request)
        let session_meta_value = router_data.request.refund_connector_metadata
            .as_ref()
            .ok_or_else(|| report!(errors::ConnectorError::MissingRequiredField { field_name: "refund_connector_metadata for FiservSessionObject in Refund" }))?
            .peek();

        let session_str = match session_meta_value {
            serde_json::Value::String(s) => s,
            _ => return Err(report!(errors::ConnectorError::InvalidConnectorConfig {
                config: "connector_meta_data was not a JSON string for FiservSessionObject in Refund",
            })),
        };
            
        let session: FiservSessionObject = serde_json::from_str(&session_str) // Added borrow here
            .change_context(errors::ConnectorError::InvalidConnectorConfig {
                config: "Deserializing FiservSessionObject from connector_meta_data string in Refund",
            })?;

        Ok(Self {
            amount: Amount {
                total: item.amount.clone(), 
                currency: router_data.request.currency.to_string(),
            },
            merchant_details: MerchantDetails {
                merchant_id: auth.merchant_account.clone(),
                terminal_id: Some(session.terminal_id.clone()), 
            },
            reference_transaction_details: ReferenceTransactionDetails {
                reference_transaction_id: router_data // This is RouterDataV2<RefundFlowMarker, RefundFlowData, RefundsData, ConnectorRefundsResponseData>
                    .request // This is RefundsData
                    .connector_transaction_id // This is String
                    .to_string(),
            },
        })
    }
}


#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RefundResponse { 
    pub gateway_response: GatewayResponse,
}
