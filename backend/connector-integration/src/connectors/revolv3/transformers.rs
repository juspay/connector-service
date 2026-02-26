use crate::{types::ResponseRouterData, utils::is_refund_failure};
use common_enums::{AttemptStatus, RefundStatus};
use common_utils::types::FloatMajorUnit;
use domain_types::{
    connector_flow::{Authorize, Capture, PSync, RSync, Refund, Void},
    connector_types::{
        PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData,
        RefundsResponseData, ResponseId,
    },
    errors,
    payment_method_data::{Card, PaymentMethodData, PaymentMethodDataTypes, RawCardNumber},
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
};
use error_stack::ResultExt;
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};
use time::{format_description::well_known::Iso8601, PrimitiveDateTime};

#[derive(Debug, Clone)]
pub struct Revolv3AuthType {
    pub api_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for Revolv3AuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::HeaderKey { api_key } => Ok(Self {
                api_key: api_key.to_owned(),
            }),
            _ => Err(error_stack::report!(
                errors::ConnectorError::FailedToObtainAuthType
            )),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum Revolv3PaymentsRequest<T: PaymentMethodDataTypes> {
    Sale(Revolv3SaleRequest<T>),
    Authorize(Revolv3AuthorizeRequest<T>),
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Revolv3AuthorizeRequest<T: PaymentMethodDataTypes> {
    pub payment_method: Revolv3PaymentMethodData<T>,
    pub amount: Revolv3AmountData,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Revolv3SaleRequest<T: PaymentMethodDataTypes> {
    pub payment_method: Revolv3PaymentMethodData<T>,
    pub invoice: Revolv3InvoiceData,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Revolv3InvoiceData {
    pub merchant_invoice_ref_id: Option<String>,
    pub amount: Revolv3AmountData,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Revolv3AmountData {
    pub value: FloatMajorUnit,
    pub currency: common_enums::Currency,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum Revolv3PaymentMethodData<T: PaymentMethodDataTypes> {
    CreditCard(CreditCardDataPaymentMethodData<T>),
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreditCardDataPaymentMethodData<T: PaymentMethodDataTypes> {
    billing_full_name: Secret<String>,
    credit_card: Revolv3CreditCardData<T>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Revolv3CreditCardData<T: PaymentMethodDataTypes> {
    payment_account_number: RawCardNumber<T>,
    expiration_date: Secret<String>,
    security_code: Secret<String>,
}

impl<T: PaymentMethodDataTypes> Revolv3PaymentMethodData<T> {
    pub fn set_credit_card_data(
        item: &RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData<T>,
            PaymentsResponseData,
        >,
        card: Card<T>,
    ) -> Result<Self, error_stack::Report<errors::ConnectorError>> {
        let credit_card_data = CreditCardDataPaymentMethodData {
            billing_full_name: item.resource_common_data.get_billing_full_name()?,
            credit_card: Revolv3CreditCardData {
                payment_account_number: card.card_number.clone(),
                expiration_date: card.get_expiry_date_as_mmyy()?,
                security_code: card.card_cvc.clone(),
            },
        };

        Ok(Self::CreditCard(credit_card_data))
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        super::Revolv3RouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for Revolv3PaymentsRequest<T>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: super::Revolv3RouterData<
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
            PaymentMethodData::Card(ref card_data) => {
                if item.router_data.resource_common_data.is_three_ds() {
                    Err(errors::ConnectorError::NotSupported {
                        message: "Cards No3DS".to_string(),
                        connector: "revolv3",
                    })?
                };
                Revolv3PaymentMethodData::set_credit_card_data(
                    &item.router_data,
                    card_data.clone(),
                )?
            }
            _ => Err(errors::ConnectorError::NotImplemented(
                domain_types::utils::get_unimplemented_payment_method_error_message("revolv3"),
            ))?,
        };

        let amount = Revolv3AmountData {
            value: item
                .connector
                .amount_converter
                .convert(
                    item.router_data.request.minor_amount,
                    item.router_data.request.currency,
                )
                .change_context(errors::ConnectorError::AmountConversionFailed)?,
            currency: item.router_data.request.currency,
        };

        if item.router_data.request.is_auto_capture()? {
            let invoice = Revolv3InvoiceData {
                merchant_invoice_ref_id: item
                    .router_data
                    .request
                    .merchant_order_reference_id
                    .clone(),
                amount,
            };

            Ok(Self::Sale(Revolv3SaleRequest {
                payment_method,
                invoice,
            }))
        } else {
            Ok(Self::Authorize(Revolv3AuthorizeRequest {
                payment_method,
                amount,
            }))
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Revolv3PaymentsResponse {
    Sale(Revolv3SaleResponse),
    Authorize(Revolv3AuthorizeResponse),
}

// Note: An authorization request does not create an invoice
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Revolv3AuthorizeResponse {
    pub network_transaction_id: Option<String>,
    pub payment_method_authorization_id: Option<i64>,
    pub payment_method: Option<Revolv3PaymentMethodResponse>,
    pub payment_processor: Option<String>,
    pub response_message: Option<String>,
    pub response_code: Option<String>,
    pub processor_transaction_id: Option<String>,
    pub auth_code: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Revolv3SaleResponse {
    pub invoice_id: i64,
    pub merchant_invoice_ref_id: Option<String>,
    pub network_transaction_id: Option<String>,
    pub invoice_status: InvoiceStatus,
    pub payment_method_id: Option<i64>,
    pub payment_processor: Option<String>,
    pub response_message: Option<String>,
    pub response_code: Option<String>,
    pub processor_transaction_id: Option<String>,
    pub auth_code: Option<String>,
}

pub struct DerivedPaymentResponse {
    pub status: AttemptStatus,
    pub response: Result<PaymentsResponseData, domain_types::router_data::ErrorResponse>,
}

impl Revolv3SaleResponse {
    pub fn get_transaction_response(
        &self,
        status_code: u16,
    ) -> Result<DerivedPaymentResponse, error_stack::Report<errors::ConnectorError>> {
        let status = AttemptStatus::from(&self.invoice_status);
        let response = if domain_types::utils::is_payment_failure(status) {
            Err(domain_types::router_data::ErrorResponse {
                code: self
                    .response_code
                    .clone()
                    .unwrap_or(common_utils::consts::NO_ERROR_CODE.to_string()),
                message: self
                    .response_message
                    .clone()
                    .unwrap_or(common_utils::consts::NO_ERROR_MESSAGE.to_string()),
                reason: self.response_message.clone(),
                status_code,
                attempt_status: None,
                connector_transaction_id: Some(self.invoice_id.to_string()),
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
            })
        } else {
            Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(self.invoice_id.to_string()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: self.network_transaction_id.clone(),
                connector_response_reference_id: self.merchant_invoice_ref_id.clone(),
                incremental_authorization_allowed: None,
                status_code,
            })
        };

        Ok(DerivedPaymentResponse { status, response })
    }
}

impl Revolv3AuthorizeResponse {
    pub fn get_transaction_response(
        &self,
        status_code: u16,
    ) -> Result<DerivedPaymentResponse, error_stack::Report<errors::ConnectorError>> {
        // Synchronous flow — PSync is not applicable
        match self.payment_method_authorization_id {
            Some(ref payment_method_authorization_id) => Ok(DerivedPaymentResponse {
                status: AttemptStatus::Authorized,
                response: Ok(PaymentsResponseData::TransactionResponse {
                    resource_id: ResponseId::ConnectorTransactionId(
                        payment_method_authorization_id.to_string(),
                    ),
                    redirection_data: None,
                    mandate_reference: None,
                    connector_metadata: None,
                    network_txn_id: self.network_transaction_id.clone(),
                    connector_response_reference_id: None,
                    incremental_authorization_allowed: None,
                    status_code,
                }),
            }),
            _ => Ok(DerivedPaymentResponse {
                status: AttemptStatus::Failure,
                response: Err(domain_types::router_data::ErrorResponse {
                    code: self
                        .response_code
                        .clone()
                        .unwrap_or(common_utils::consts::NO_ERROR_CODE.to_string()),
                    message: self
                        .response_message
                        .clone()
                        .unwrap_or(common_utils::consts::NO_ERROR_MESSAGE.to_string()),
                    reason: self.response_message.clone(),
                    status_code,
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }),
            }),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum InvoiceStatus {
    Paid,
    Pending,
    Noncollectable,
    Failed,
    OneTimePaymentPending,
    RetryPending,
}

impl From<&InvoiceStatus> for AttemptStatus {
    fn from(status: &InvoiceStatus) -> Self {
        match status {
            InvoiceStatus::Paid => Self::Charged,
            InvoiceStatus::Pending
            | InvoiceStatus::OneTimePaymentPending
            | InvoiceStatus::RetryPending => Self::Pending,
            InvoiceStatus::Noncollectable | InvoiceStatus::Failed => Self::Failure,
        }
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<ResponseRouterData<Revolv3PaymentsResponse, Self>>
    for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<Revolv3PaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let derived_response = match item.response {
            Revolv3PaymentsResponse::Authorize(ref auth_response) => {
                auth_response.get_transaction_response(item.http_code)
            }
            Revolv3PaymentsResponse::Sale(ref sale_response) => {
                sale_response.get_transaction_response(item.http_code)
            }
        }?;

        Ok(Self {
            response: derived_response.response,
            resource_common_data: PaymentFlowData {
                status: derived_response.status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Revolv3PaymentSyncResponse {
    pub invoice_id: i64,
    pub merchant_invoice_ref_id: Option<String>,
    pub network_transaction_id: Option<String>,
    pub invoice_status: InvoiceStatus,
    pub payment_method: Option<Revolv3PaymentMethodResponse>,
    pub invoice_attempts: Option<Vec<Revolv3InvoiceAttempt>>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Revolv3PaymentMethodResponse {
    pub payment_method_id: Option<i64>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Revolv3InvoiceAttempt {
    pub invoice_attempt_date: String,
    pub response_code: Option<String>,
    pub response_message: Option<String>,
}

fn get_latest_attempt(
    attempts: &Option<Vec<Revolv3InvoiceAttempt>>,
) -> Option<&Revolv3InvoiceAttempt> {
    attempts
        .as_ref()?
        .iter()
        .filter_map(|attempt| {
            PrimitiveDateTime::parse(&attempt.invoice_attempt_date, &Iso8601::DEFAULT)
                .ok()
                .map(|dt| (dt, attempt))
        })
        .max_by_key(|(dt, _)| *dt)
        .map(|(_, attempt)| attempt)
}

impl TryFrom<ResponseRouterData<Revolv3PaymentSyncResponse, Self>>
    for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<Revolv3PaymentSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let status = AttemptStatus::from(&item.response.invoice_status);
        let response = if domain_types::utils::is_payment_failure(status) {
            let latest_attempt = get_latest_attempt(&item.response.invoice_attempts);
            let error_message = latest_attempt.and_then(|attempt| attempt.response_message.clone());

            Err(domain_types::router_data::ErrorResponse {
                code: latest_attempt
                    .and_then(|attempt| attempt.response_code.clone())
                    .unwrap_or(common_utils::consts::NO_ERROR_CODE.to_string()),
                message: error_message
                    .clone()
                    .unwrap_or(common_utils::consts::NO_ERROR_MESSAGE.to_string()),
                reason: error_message.clone(),
                status_code: item.http_code,
                attempt_status: None,
                connector_transaction_id: Some(item.response.invoice_id.to_string()),
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
            })
        } else {
            Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    item.response.invoice_id.to_string(),
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: item.response.network_transaction_id.clone(),
                connector_response_reference_id: item.response.merchant_invoice_ref_id.clone(),
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            })
        };

        Ok(Self {
            response,
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Revolv3RefundRequest {
    pub amount: FloatMajorUnit,
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        super::Revolv3RouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    > for Revolv3RefundRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: super::Revolv3RouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            amount: item
                .connector
                .amount_converter
                .convert(
                    item.router_data.request.minor_refund_amount,
                    item.router_data.request.currency,
                )
                .change_context(errors::ConnectorError::AmountConversionFailed)?,
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Revolv3RefundResponse {
    pub invoice: RefundInvoice,
    pub refunds: Option<Vec<Revolv3InvoiceAttempt>>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RefundInvoice {
    pub invoice_id: i64,
    pub parent_invoice_id: i64,
    pub invoice_status: RefundInvoiceStatus,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum RefundInvoiceStatus {
    Refund,
    PartialRefund,
    RefundPending,
    RefundDeclined,
    RefundFailed,
}

impl From<&RefundInvoiceStatus> for RefundStatus {
    fn from(status: &RefundInvoiceStatus) -> Self {
        match status {
            RefundInvoiceStatus::Refund | RefundInvoiceStatus::PartialRefund => Self::Success,
            RefundInvoiceStatus::RefundPending => Self::Pending,
            RefundInvoiceStatus::RefundDeclined | RefundInvoiceStatus::RefundFailed => {
                Self::Failure
            }
        }
    }
}

impl TryFrom<ResponseRouterData<Revolv3RefundResponse, Self>>
    for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<Revolv3RefundResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let refund_status = RefundStatus::Pending; //from(&item.response.invoice.invoice_status);
        let response = if is_refund_failure(refund_status) {
            let latest_attempt = get_latest_attempt(&item.response.refunds);
            let error_message = latest_attempt
                .as_ref()
                .and_then(|attempt| attempt.response_message.clone());
            Err(domain_types::router_data::ErrorResponse {
                code: latest_attempt
                    .as_ref()
                    .and_then(|attempt| attempt.response_code.clone())
                    .unwrap_or(common_utils::consts::NO_ERROR_CODE.to_string()),
                message: error_message
                    .clone()
                    .unwrap_or(common_utils::consts::NO_ERROR_MESSAGE.to_string()),
                reason: error_message.clone(),
                status_code: item.http_code,
                attempt_status: None,
                connector_transaction_id: Some(item.response.invoice.invoice_id.to_string()),
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
            })
        } else {
            Ok(RefundsResponseData {
                connector_refund_id: item.response.invoice.invoice_id.to_string(),
                refund_status,
                status_code: item.http_code,
            })
        };

        Ok(Self {
            response,
            ..item.router_data
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Revolv3RefundSyncResponse {
    pub invoice_id: i64,
    pub merchant_invoice_ref_id: Option<String>,
    pub network_transaction_id: Option<String>,
    pub invoice_status: RefundInvoiceStatus,
    pub payment_method: Option<Revolv3PaymentMethodResponse>,
    pub invoice_attempts: Option<Vec<Revolv3InvoiceAttempt>>,
}

impl TryFrom<ResponseRouterData<Revolv3RefundSyncResponse, Self>>
    for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<Revolv3RefundSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let refund_status = RefundStatus::from(&item.response.invoice_status);
        let response = if is_refund_failure(refund_status) {
            let latest_attempt = get_latest_attempt(&item.response.invoice_attempts);
            let error_message = latest_attempt
                .as_ref()
                .and_then(|attempt| attempt.response_message.clone());
            Err(domain_types::router_data::ErrorResponse {
                code: latest_attempt
                    .as_ref()
                    .and_then(|attempt| attempt.response_code.clone())
                    .unwrap_or(common_utils::consts::NO_ERROR_CODE.to_string()),
                message: error_message
                    .clone()
                    .unwrap_or(common_utils::consts::NO_ERROR_MESSAGE.to_string()),
                reason: error_message.clone(),
                status_code: item.http_code,
                attempt_status: None,
                connector_transaction_id: Some(item.response.invoice_id.to_string()),
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
            })
        } else {
            Ok(RefundsResponseData {
                connector_refund_id: item.response.invoice_id.to_string(),
                refund_status,
                status_code: item.http_code,
            })
        };

        Ok(Self {
            response,
            ..item.router_data
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Revolv3CaptureRequest {
    pub invoice: Revolv3InvoiceData,
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        super::Revolv3RouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    > for Revolv3CaptureRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: super::Revolv3RouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let invoice = Revolv3InvoiceData {
            merchant_invoice_ref_id: item.router_data.request.merchant_order_reference_id.clone(),
            amount: Revolv3AmountData {
                value: item
                    .connector
                    .amount_converter
                    .convert(
                        item.router_data.request.minor_amount_to_capture,
                        item.router_data.request.currency,
                    )
                    .change_context(errors::ConnectorError::AmountConversionFailed)?,
                currency: item.router_data.request.currency,
            },
        };

        Ok(Self { invoice })
    }
}

impl<F> TryFrom<ResponseRouterData<Revolv3SaleResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(value: ResponseRouterData<Revolv3SaleResponse, Self>) -> Result<Self, Self::Error> {
        let derived_response = value.response.get_transaction_response(value.http_code)?;
        Ok(Self {
            response: derived_response.response,
            resource_common_data: PaymentFlowData {
                status: derived_response.status,
                ..value.router_data.resource_common_data
            },
            ..value.router_data
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Revolv3AuthReversalRequest {
    pub payment_method_authorization_id: String,
    pub reason: Option<String>,
    pub amount: Option<FloatMajorUnit>,
}

impl<T>
    TryFrom<
        super::Revolv3RouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    > for Revolv3AuthReversalRequest
where
    T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize,
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: super::Revolv3RouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let payment_method_authorization_id =
            item.router_data.request.connector_transaction_id.clone();
        let reason = item.router_data.request.cancellation_reason.clone();
        let amount = item
            .router_data
            .request
            .amount
            .zip(item.router_data.request.currency)
            .map(|(minor_amount, currency)| {
                item.connector
                    .amount_converter
                    .convert(minor_amount, currency)
            })
            .transpose()
            .change_context(errors::ConnectorError::AmountConversionFailed)?;

        Ok(Self {
            payment_method_authorization_id,
            reason,
            amount,
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Revolv3AuthReversalResponse {
    pub payment_processor: i32,
    pub reference_number: Option<String>,
    pub message: Option<String>,
}

impl TryFrom<ResponseRouterData<Revolv3AuthReversalResponse, Self>>
    for RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<Revolv3AuthReversalResponse, Self>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::NoResponseId,
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            resource_common_data: PaymentFlowData {
                status: AttemptStatus::Voided,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Revolv3ErrorResponse {
    pub message: String,
    pub errors: Option<Vec<String>>,
}
