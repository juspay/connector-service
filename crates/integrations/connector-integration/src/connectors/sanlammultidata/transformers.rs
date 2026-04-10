use crate::{connectors::sanlammultidata::SanlammultidataRouterData, types::ResponseRouterData};
use common_enums::{AttemptStatus, BankNames, BankType, Currency};
use common_utils::{
    consts::{NO_ERROR_CODE, NO_ERROR_MESSAGE},
    ext_traits::ValueExt,
    pii::SecretSerdeValue,
    types::MinorUnit,
};
use domain_types::{
    connector_flow::Authorize,
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, ResponseId},
    errors::{ConnectorError, IntegrationError},
    payment_method_data::{BankDebitData, PaymentMethodData, PaymentMethodDataTypes},
    router_data::{ConnectorSpecificConfig, ErrorResponse},
    router_data_v2::RouterDataV2,
    utils::{get_unimplemented_payment_method_error_message, is_payment_failure},
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, Secret};
use serde::{Deserialize, Serialize};

pub struct SanlammultidataAuthType {
    pub(super) api_key: Secret<String>,
}

impl TryFrom<&ConnectorSpecificConfig> for SanlammultidataAuthType {
    type Error = error_stack::Report<IntegrationError>;
    fn try_from(item: &ConnectorSpecificConfig) -> Result<Self, Self::Error> {
        match item {
            ConnectorSpecificConfig::Sanlammultidata { api_key, .. } => Ok(Self {
                api_key: api_key.to_owned(),
            }),
            _ => Err(IntegrationError::FailedToObtainAuthType {
                context: Default::default(),
            }
            .into()),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct SanlammultidataMetaData {
    pub batch_user_reference: Option<String>,
}

impl TryFrom<SecretSerdeValue> for SanlammultidataMetaData {
    type Error = error_stack::Report<IntegrationError>;
    fn try_from(metadata: SecretSerdeValue) -> Result<Self, Self::Error> {
        let metadata = metadata
            .expose()
            .parse_value::<Self>("SanlammultidataMetaData")
            .change_context(IntegrationError::InvalidDataFormat {
                field_name: "metadata",
                context: Default::default(),
            })?;
        Ok(metadata)
    }
}

#[derive(Debug, Serialize)]
pub struct SanlammultidataPaymentsRequest {
    pub user_reference: String,
    pub amount: MinorUnit,
    pub currency: Currency,
    #[serde(rename = "payment_method")]
    pub payment_method: SanlammultidataPaymentMethod,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub statement_descriptor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub batch_user_reference: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SanlammultidataPaymentMethod {
    EftDebitOrder(EftDebitOrder),
}

#[derive(Debug, Serialize)]
pub struct EftDebitOrder {
    pub homing_account: Secret<String>,
    pub homing_branch: Secret<String>,
    pub homing_account_name: Secret<String>,
    pub bank_name: SanlammultidataBankNames,
    pub bank_type: SanlammultidataBankType,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SanlammultidataBankNames {
    Absa,
    Capitec,
    Fnb,
    Nedbank,
    StandardBank,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SanlammultidataBankType {
    Savings,
    Cheque,
    Transmission,
    Bond,
    Current,
    SubscriptionShare,
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        SanlammultidataRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for SanlammultidataPaymentsRequest
{
    type Error = error_stack::Report<IntegrationError>;
    fn try_from(
        item: SanlammultidataRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let payment_method = match item.router_data.request.payment_method_data {
            PaymentMethodData::BankDebit(ref bank_debit_data) => match bank_debit_data {
                BankDebitData::EftBankDebit {
                    account_number,
                    branch_code,
                    bank_account_holder_name,
                    bank_name,
                    bank_type,
                } => {
                    let homing_account_name = bank_account_holder_name.as_ref().ok_or(
                        IntegrationError::MissingRequiredField {
                            field_name: "bank_account_holder_name",
                            context: Default::default(),
                        },
                    )?;

                    let bank_name = bank_name
                        .map(SanlammultidataBankNames::try_from)
                        .transpose()?
                        .ok_or(IntegrationError::MissingRequiredField {
                            field_name: "bank_name",
                            context: Default::default(),
                        })?;

                    let bank_type = bank_type.map(SanlammultidataBankType::from).ok_or(
                        IntegrationError::MissingRequiredField {
                            field_name: "bank_type",
                            context: Default::default(),
                        },
                    )?;

                    Ok(SanlammultidataPaymentMethod::EftDebitOrder(EftDebitOrder {
                        homing_account: account_number.clone(),
                        homing_branch: branch_code.clone(),
                        homing_account_name: homing_account_name.clone(),
                        bank_name,
                        bank_type,
                    }))
                }
                _ => Err(IntegrationError::not_implemented(
                    get_unimplemented_payment_method_error_message("Sanlammultidata"),
                ))?,
            },
            PaymentMethodData::Card(_)
            | PaymentMethodData::CardRedirect(_)
            | PaymentMethodData::Crypto(_)
            | PaymentMethodData::Wallet(_)
            | PaymentMethodData::PayLater(_)
            | PaymentMethodData::BankRedirect(_)
            | PaymentMethodData::BankTransfer(_)
            | PaymentMethodData::MandatePayment
            | PaymentMethodData::Reward
            | PaymentMethodData::RealTimePayment(_)
            | PaymentMethodData::Upi(_)
            | PaymentMethodData::MobilePayment(_)
            | PaymentMethodData::Voucher(_)
            | PaymentMethodData::GiftCard(_)
            | PaymentMethodData::OpenBanking(_)
            | PaymentMethodData::PaymentMethodToken(_)
            | PaymentMethodData::NetworkToken(_)
            | PaymentMethodData::DecryptedWalletTokenDetailsForNetworkTransactionId(_)
            | PaymentMethodData::CardDetailsForNetworkTransactionId(_) => {
                Err(IntegrationError::not_implemented(
                    get_unimplemented_payment_method_error_message("Sanlammultidata"),
                ))
            }
        }?;

        let batch_user_reference = item
            .router_data
            .request
            .metadata
            .map(SanlammultidataMetaData::try_from)
            .transpose()?
            .and_then(|m| m.batch_user_reference);

        Ok(Self {
            amount: item.router_data.request.minor_amount,
            currency: item.router_data.request.currency,
            payment_method,
            user_reference: item
                .router_data
                .resource_common_data
                .connector_request_reference_id,
            batch_user_reference,
            statement_descriptor: item
                .router_data
                .request
                .billing_descriptor
                .as_ref()
                .and_then(|descriptor| descriptor.statement_descriptor.clone()),
        })
    }
}

impl TryFrom<BankNames> for SanlammultidataBankNames {
    type Error = error_stack::Report<IntegrationError>;
    fn try_from(bank: BankNames) -> Result<Self, Self::Error> {
        match bank {
            BankNames::Absa => Ok(Self::Absa),
            bank => Err(IntegrationError::NotSupported {
                message: format!("Invalid BankName for EFT Debit order payment: {bank:?}"),
                connector: "Sanlammultidata",
                context: Default::default(),
            })?,
        }
    }
}

impl From<BankType> for SanlammultidataBankType {
    fn from(value: BankType) -> Self {
        match value {
            BankType::Checking => Self::Cheque,
            BankType::Savings => Self::Savings,
            BankType::Current => Self::Current,
            BankType::Bond => Self::Bond,
            BankType::Transmission => Self::Transmission,
            BankType::SubscriptionShare => Self::SubscriptionShare,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SanlammultidataPaymentsResponse {
    pub status: SanlammultidataPaymentStatus,
    pub topic: String,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SanlammultidataPaymentStatus {
    Queued,
    Rejected,
    Unknown,
}

impl<F, T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<ResponseRouterData<SanlammultidataPaymentsResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<SanlammultidataPaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let status = AttemptStatus::from(item.response.status);
        let response = if is_payment_failure(status) {
            Err(ErrorResponse {
                code: item
                    .response
                    .error_code
                    .clone()
                    .unwrap_or(NO_ERROR_CODE.to_string()),
                message: item
                    .response
                    .error_message
                    .clone()
                    .unwrap_or(NO_ERROR_MESSAGE.to_string()),
                reason: None,
                status_code: item.http_code,
                attempt_status: None,
                connector_transaction_id: None,
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
            })
        } else {
            Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::NoResponseId,
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            })
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            response,
            ..item.router_data
        })
    }
}

impl From<SanlammultidataPaymentStatus> for AttemptStatus {
    fn from(status: SanlammultidataPaymentStatus) -> Self {
        match status {
            SanlammultidataPaymentStatus::Queued | SanlammultidataPaymentStatus::Unknown => {
                Self::Pending
            }
            SanlammultidataPaymentStatus::Rejected => Self::Failure,
        }
    }
}
