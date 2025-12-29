use crate::types::ResponseRouterData;
use common_enums::AttemptStatus;
use domain_types::{
    connector_flow::{Authorize, PSync},
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, ResponseId},
    errors,
    payment_method_data::{BankRedirectData, PaymentMethodData, PaymentMethodDataTypes},
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
};
use hyperswitch_masking::{ExposeInterface, Secret};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

// ============================================================================
// AUTHENTICATION TYPE
// ============================================================================

#[derive(Debug, Clone)]
pub struct LoonioAuthType {
    pub merchant_id: Secret<String>,
    pub merchant_token: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for LoonioAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::BodyKey { api_key, key1: _ } => {
                // api_key format: "merchant_id:merchant_token"
                let api_key_value = api_key.clone().expose();
                let parts: Vec<&str> = api_key_value.split(':').collect();
                if parts.len() != 2 {
                    return Err(error_stack::report!(
                        errors::ConnectorError::FailedToObtainAuthType
                    ));
                }
                Ok(Self {
                    merchant_id: Secret::new(parts[0].to_string()),
                    merchant_token: Secret::new(parts[1].to_string()),
                })
            }
            _ => Err(error_stack::report!(errors::ConnectorError::FailedToObtainAuthType)),
        }
    }
}

// ============================================================================
// ERROR RESPONSE
// ============================================================================

#[derive(Debug, Deserialize, Serialize)]
pub struct LoonioErrorResponse {
    pub status: Option<u16>,
    pub error_code: Option<String>,
    pub message: String,
}

// ============================================================================
// AUTHORIZE FLOW
// ============================================================================

#[derive(Debug, Serialize)]
pub struct LoonioAuthorizeRequest {
    pub currency_code: String,
    pub customer_profile: LoonioCustomerProfile,
    pub amount: f64,
    pub customer_id: String,
    pub transaction_id: String,
    pub payment_method_type: String,
    pub redirect_url: LoonioRedirectUrl,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook_url: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct LoonioCustomerProfile {
    pub first_name: String,
    pub last_name: String,
    pub email: String,
}

#[derive(Debug, Serialize)]
pub struct LoonioRedirectUrl {
    pub success_url: String,
    pub failed_url: String,
}

#[derive(Debug, Deserialize)]
pub struct LoonioAuthorizeResponse {
    pub payment_form: String,
}

impl<T: PaymentMethodDataTypes + Debug> TryFrom<&RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>
    for LoonioAuthorizeRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let payment_method_data = &item.request.payment_method_data;

        // Extract customer information
        let first_name = item
            .resource_common_data
            .get_billing_first_name()
            .ok()
            .map(|s| s.expose().clone())
            .unwrap_or_default();
        let last_name = item
            .resource_common_data
            .get_billing_last_name()
            .ok()
            .map(|s| s.expose().clone())
            .unwrap_or_default();
        let email = item.request.email.clone().map(|e| e.expose().expose().clone()).unwrap_or_default();

        // Get return URL for redirect
        let return_url = item
            .request
            .router_return_url
            .clone()
            .ok_or(errors::ConnectorError::MissingRequiredField {
                field_name: "router_return_url",
            })?;

        // Convert amount from minor units to base units (f64)
        let amount = item.request.minor_amount.get_amount_as_i64() as f64 / 100.0;

        // Handle BankRedirect payment method (Interac e-Transfer)
        match payment_method_data {
            PaymentMethodData::BankRedirect(bank_redirect_data) => {
                match bank_redirect_data {
                    BankRedirectData::Interac { .. } => {
                        // Interac e-Transfer is supported
                        Ok(Self {
                            currency_code: item.request.currency.to_string(),
                            customer_profile: LoonioCustomerProfile {
                                first_name,
                                last_name,
                                email,
                            },
                            amount,
                            customer_id: item
                                .resource_common_data
                                .connector_customer
                                .clone()
                                .unwrap_or_default(),
                            transaction_id: item
                                .resource_common_data
                                .connector_request_reference_id
                                .clone(),
                            payment_method_type: "INTERAC_ETRANSFER".to_string(),
                            redirect_url: LoonioRedirectUrl {
                                success_url: return_url.clone(),
                                failed_url: return_url,
                            },
                            webhook_url: item.request.webhook_url.clone(),
                        })
                    }
                    _ => Err(error_stack::report!(errors::ConnectorError::NotSupported {
                        message: format!(
                            "BankRedirect type is not supported by Loonio",
                        ),
                        connector: "loonio",
                    })),
                }
            }
            _ => Err(error_stack::report!(errors::ConnectorError::NotSupported {
                message: format!(
                    "Payment method is not supported by Loonio",
                ),
                connector: "loonio",
            })),
        }
    }
}

impl<T: PaymentMethodDataTypes>
    TryFrom<ResponseRouterData<LoonioAuthorizeResponse, RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>>
    for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            LoonioAuthorizeResponse,
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let redirection_data = Some(Box::new(RedirectForm::Uri {
            uri: item.response.payment_form,
        }));

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::NoResponseId,
                redirection_data,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            resource_common_data: PaymentFlowData {
                status: AttemptStatus::AuthenticationPending,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

// ============================================================================
// PSYNC FLOW
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct LoonioPSyncResponse {
    pub transaction_id: String,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub customer_bank_info: Option<LoonioCustomerBankInfo>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct LoonioCustomerBankInfo {
    pub account_number: String,
    pub institution_number: String,
    pub transit_number: String,
}

// Status mapping function
fn map_loonio_status_to_attempt_status(state: &str) -> AttemptStatus {
    match state {
        "CREATED" => AttemptStatus::AuthenticationPending,
        "PREPARED" => AttemptStatus::Pending,
        "PENDING" => AttemptStatus::Pending,
        "SETTLED" => AttemptStatus::Charged,
        "AVAILABLE" => AttemptStatus::Charged,
        "ABANDONED" => AttemptStatus::Failure,
        "REJECTED" => AttemptStatus::Failure,
        "FAILED" => AttemptStatus::Failure,
        "RETURNED" => AttemptStatus::Failure,
        "NSF" => AttemptStatus::Failure,
        "ROLLBACK" => AttemptStatus::Voided,
        _ => AttemptStatus::Pending,
    }
}

impl TryFrom<ResponseRouterData<LoonioPSyncResponse, RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>>
    for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            LoonioPSyncResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let status = map_loonio_status_to_attempt_status(&item.response.state);

        // Include customer bank info in connector response if present (masked)
        let connector_metadata = item.response.customer_bank_info.map(|bank_info| {
            serde_json::json!({
                "customer_bank_info": {
                    "account_number": bank_info.account_number,
                    "institution_number": bank_info.institution_number,
                    "transit_number": bank_info.transit_number,
                }
            })
        });

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.transaction_id),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}