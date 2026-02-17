use crate::types::ResponseRouterData;
use common_enums::AttemptStatus;
use domain_types::{
    connector_flow::Authorize,
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, ResponseId},
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
};
use hyperswitch_masking::{Secret, Maskable};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct FiservemeaAuthType {
    pub api_key: Secret<String>,
    pub api_secret: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for FiservemeaAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::HeaderKey { api_key } => Ok(Self {
                api_key: api_key.to_owned(),
                api_secret: Secret::new("".to_string()),
            }),
            ConnectorAuthType::BodyKey { api_key, key1, .. } => Ok(Self {
                api_key: api_key.to_owned(),
                api_secret: key1.to_owned(),
            }),
            _ => Err(error_stack::report!(
                errors::ConnectorError::FailedToObtainAuthType
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FiservemeaErrorResponse {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FiservemeaProcessorResponse {
    pub transactionState: String,
    pub transactionResult: String,
    pub approvalCode: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FiservemeaAuthorizeResponse {
    pub ipgTransactionId: String,
    pub transactionState: String,
    pub transactionResult: String,
    pub clientRequestId: String,
    pub approvalCode: Option<String>,
    pub processor: Option<FiservemeaProcessorResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FiservemeaPaymentMethod<T: PaymentMethodDataTypes> {
    pub paymentCard: FiservemeaPaymentCard<T>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FiservemeaPaymentCard<T: PaymentMethodDataTypes> {
    pub number: String,
    pub expiryDate: String,
    pub securityCode: Option<String>,
    pub holder: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FiservemeaTransactionAmount {
    pub total: i64,
    pub currency: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FiservemeaOrderDetails {
    pub orderId: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FiservemeaAuthorizeRequest<T: PaymentMethodDataTypes> {
    pub requestType: String,
    pub merchantTransactionId: String,
    pub transactionAmount: FiservemeaTransactionAmount,
    pub order: FiservemeaOrderDetails,
    pub paymentMethod: FiservemeaPaymentMethod<T>,
}

impl<T: PaymentMethodDataTypes>
    TryFrom<
        &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    > for FiservemeaAuthorizeRequest<T>
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
        let amount = item.request.minor_amount.get_amount_as_i64();
        let currency = item.request.currency.to_string();
        
        let payment_method = match &item.request.payment_method {
            Some(pm) => {
                let card_number = pm
                    .payment_method_data
                    .as_any()
                    .downcast_ref::<domain_types::payment_method_data::PaymentMethod>()
                    .ok_or_else(|| {
                        error_stack::report!(errors::ConnectorError::InvalidPaymentMethod)
                    })?;
                
                let card = card_number
                    .payment_method_data
                    .as_any()
                    .downcast_ref::<domain_types::payment_method_data::PaymentCard>()
                    .ok_or_else(|| {
                        error_stack::report!(errors::ConnectorError::InvalidPaymentMethod)
                    })?;
                
                FiservemeaPaymentCard {
                    number: card.card_number.clone().expose(),
                    expiryDate: format!("{:02}{:02}", card.expiry_month, card.expiry_year),
                    securityCode: card.cvv.as_ref().map(|c| c.expose().to_string()),
                    holder: card.holder.as_ref().map(|h| h.expose().to_string()),
                }
            }
            None => return Err(error_stack::report!(errors::ConnectorError::InvalidPaymentMethod)),
        };

        let request_type = if item.request.capture_method == CaptureMethod::Sale {
            "PaymentCardSaleTransaction".to_string()
        } else {
            "PaymentCardPreAuthTransaction".to_string()
        };

        Ok(Self {
            requestType: request_type,
            merchantTransactionId: item
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            transactionAmount: FiservemeaTransactionAmount {
                total: amount,
                currency,
            },
            order: FiservemeaOrderDetails {
                orderId: item
                    .resource_common_data
                    .connector_request_reference_id
                    .clone(),
            },
            paymentMethod: FiservemeaPaymentMethod { paymentCard: payment_method },
        })
    }
}

impl<T: PaymentMethodDataTypes>
    TryFrom<
        ResponseRouterData<
            FiservemeaAuthorizeResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    > for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            FiservemeaAuthorizeResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        let status = map_fiservemea_status_to_attempt_status(&item.response.transactionState);

        let connector_transaction_id = item.response.ipgTransactionId.clone();
        let network_txn_id = item
            .response
            .processor
            .as_ref()
            .and_then(|p| p.approvalCode.clone());

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(connector_transaction_id),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id,
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

fn map_fiservemea_status_to_attempt_status(status: &str) -> AttemptStatus {
    match status.to_lowercase().as_str() {
        "authorized" => AttemptStatus::Authorized,
        "captured" => AttemptStatus::Charged,
        "settled" => AttemptStatus::Charged,
        "voided" => AttemptStatus::Voided,
        "declined" => AttemptStatus::Failure,
        "failed" => AttemptStatus::Failure,
        "waiting" => AttemptStatus::Pending,
        _ => AttemptStatus::Pending,
    }
}
