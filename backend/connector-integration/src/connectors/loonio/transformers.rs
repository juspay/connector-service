use crate::types::ResponseRouterData;
use common_enums::AttemptStatus;
use common_utils::{pii::Email, types::FloatMajorUnit, Method};
use domain_types::{
    connector_flow::{Authorize, PSync},
    connector_types::{
        PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, ResponseId,
    },
    errors,
    payment_method_data::{BankRedirectData, PaymentMethodData, PaymentMethodDataTypes},
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, PeekInterface, Secret};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

// ===== AUTH TYPE =====

#[derive(Debug, Clone)]
pub struct LoonioAuthType {
    pub merchant_id: Secret<String>,
    pub merchant_token: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for LoonioAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self {
                merchant_id: api_key.to_owned(),
                merchant_token: key1.to_owned(),
            }),
            _ => Err(error_stack::report!(
                errors::ConnectorError::FailedToObtainAuthType
            )),
        }
    }
}

// ===== ERROR RESPONSE =====

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoonioErrorResponse {
    pub status: Option<u16>,
    pub error_code: Option<String>,
    pub message: String,
}

// ===== AUTHORIZE FLOW =====

#[derive(Debug, Serialize)]
pub struct LoonioCustomerProfile {
    pub first_name: Secret<String>,
    pub last_name: Secret<String>,
    pub email: Email,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address_a: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub province: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub postal_code: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct LoonioRedirectUrls {
    pub success_url: String,
    pub failed_url: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InteracPaymentMethodType {
    InteracEtransfer,
}

#[derive(Debug, Serialize)]
pub struct LoonioAuthorizeRequest {
    pub currency_code: common_enums::Currency,
    pub customer_profile: LoonioCustomerProfile,
    pub amount: FloatMajorUnit,
    pub customer_id: String,
    pub transaction_id: String,
    pub payment_method_type: InteracPaymentMethodType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
    pub redirect_url: LoonioRedirectUrls,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook_url: Option<String>,
}

impl<T: PaymentMethodDataTypes>
    TryFrom<
        &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    > for LoonioAuthorizeRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData<T>,
            PaymentsResponseData,
        >,
    ) -> Result<Self, Self::Error> {
        // Validate payment method is BankRedirect
        match &item.request.payment_method_data {
            PaymentMethodData::BankRedirect(BankRedirectData::Interac { .. }) => {
                // Interac is supported
            }
            _ => {
                return Err(errors::ConnectorError::NotImplemented(
                    "Payment method not supported by Loonio".to_string(),
                ))?;
            }
        }

        // Get billing details
        let billing = item
            .resource_common_data
            .get_billing()
            .change_context(errors::ConnectorError::MissingRequiredField {
                field_name: "billing",
            })
            .attach_printable("Failed to get billing details")?;

        let billing_address =
            billing
                .address
                .as_ref()
                .ok_or(errors::ConnectorError::MissingRequiredField {
                    field_name: "billing.address",
                })?;

        let first_name = billing_address.get_first_name()?.to_owned();
        let last_name = billing_address.get_last_name()?.to_owned();

        // Get email from billing address (not from request.email)
        let email = item
            .resource_common_data
            .get_billing_email()
            .change_context(errors::ConnectorError::MissingRequiredField {
                field_name: "billing.email",
            })
            .attach_printable("Failed to get billing email")?;

        let return_url = item.request.router_return_url.clone().ok_or(
            errors::ConnectorError::MissingRequiredField {
                field_name: "return_url",
            },
        )?;

        // Convert amount using utility
        let amount = domain_types::utils::convert_amount(
            &common_utils::types::FloatMajorUnitForConnector,
            item.request.minor_amount,
            item.request.currency,
        )
        .attach_printable("Failed to convert amount to FloatMajorUnit")?;

        // Extract optional address fields with proper Secret wrapping
        let phone = billing
            .phone
            .as_ref()
            .and_then(|p| p.number.as_ref())
            .map(|n| Secret::new(n.peek().clone()));
        let address_a = billing_address
            .line1
            .as_ref()
            .map(|l| Secret::new(l.peek().clone()));
        let city = billing_address.city.as_ref().map(|c| c.peek().clone());
        let province = billing_address
            .state
            .as_ref()
            .map(|s| Secret::new(s.peek().clone()));
        let postal_code = billing_address
            .zip
            .as_ref()
            .map(|z| Secret::new(z.peek().clone()));
        let country = billing_address.country.as_ref().map(|c| c.to_string());

        Ok(Self {
            currency_code: item.request.currency,
            customer_profile: LoonioCustomerProfile {
                first_name,
                last_name,
                email,
                phone,
                address_a,
                city,
                province,
                postal_code,
                country,
            },
            amount,
            customer_id: item
                .resource_common_data
                .get_customer_id()
                .change_context(errors::ConnectorError::MissingRequiredField {
                    field_name: "customer_id",
                })
                .attach_printable("Failed to get customer_id")?
                .get_string_repr()
                .to_string(),
            transaction_id: item
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            payment_method_type: InteracPaymentMethodType::InteracEtransfer,
            locale: Some("EN".to_string()),
            redirect_url: LoonioRedirectUrls {
                success_url: return_url.clone(),
                failed_url: return_url,
            },
            webhook_url: item.request.webhook_url.clone(),
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct LoonioAuthorizeResponse {
    pub payment_form: String,
}

impl<T: PaymentMethodDataTypes> TryFrom<ResponseRouterData<LoonioAuthorizeResponse, Self>>
    for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<LoonioAuthorizeResponse, Self>,
    ) -> Result<Self, Self::Error> {
        // For redirect-based flows, status should be AuthenticationPending
        let status = AttemptStatus::AuthenticationPending;

        // Build redirect form - use Form variant like Hyperswitch does
        let redirection_data = Some(Box::new(RedirectForm::Form {
            endpoint: item.response.payment_form.clone(),
            method: Method::Get,
            form_fields: HashMap::new(),
        }));

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    item.router_data
                        .resource_common_data
                        .connector_request_reference_id
                        .clone(),
                ),
                redirection_data,
                mandate_reference: None,
                connector_metadata: None,
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

// ===== PSYNC FLOW =====

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LoonioTransactionStatus {
    Created,
    Prepared,
    Pending,
    Settled,
    Available,
    Abandoned,
    Rejected,
    Failed,
    Returned,
    #[serde(rename = "NSF")]
    Nsf,
    Rollback,
}

fn map_loonio_status_to_attempt_status(status: &LoonioTransactionStatus) -> AttemptStatus {
    match status {
        LoonioTransactionStatus::Created => AttemptStatus::AuthenticationPending,
        LoonioTransactionStatus::Prepared | LoonioTransactionStatus::Pending => {
            AttemptStatus::Pending
        }
        LoonioTransactionStatus::Settled | LoonioTransactionStatus::Available => {
            AttemptStatus::Charged
        }
        LoonioTransactionStatus::Abandoned
        | LoonioTransactionStatus::Rejected
        | LoonioTransactionStatus::Failed
        | LoonioTransactionStatus::Returned
        | LoonioTransactionStatus::Nsf => AttemptStatus::Failure,
        LoonioTransactionStatus::Rollback => AttemptStatus::Voided,
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct LoonioPSyncResponse {
    pub transaction_id: String,
    pub state: LoonioTransactionStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub customer_bank_info: Option<Secret<Value>>,
}

impl TryFrom<ResponseRouterData<LoonioPSyncResponse, Self>>
    for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: ResponseRouterData<LoonioPSyncResponse, Self>) -> Result<Self, Self::Error> {
        let status = map_loonio_status_to_attempt_status(&item.response.state);

        // Include customer_bank_info in connector_metadata if present
        let connector_metadata = item
            .response
            .customer_bank_info
            .as_ref()
            .map(|info| serde_json::json!({ "customer_bank_info": info.clone().expose() }));

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
