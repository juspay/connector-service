use common_utils::{
    types::StringMinorUnit,
};
use domain_types::{
    connector_flow::{Authorize, Capture, Void, PSync, RSync},
    connector_types::{
        PaymentFlowData, PaymentVoidData,
        PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData, PaymentsSyncData,
        RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData,
        ResponseId,
    },
    errors::{self, ConnectorError},
    payment_method_data::{
        PaymentMethodData, PaymentMethodDataTypes, RawCardNumber,
    },
    router_data::{ConnectorAuthType},
    router_data_v2::RouterDataV2,
};
use error_stack::ResultExt;
use hyperswitch_masking::{Secret, PeekInterface};
use serde::{Deserialize, Serialize};

use crate::{connectors::helcim::HelcimRouterData, types::ResponseRouterData};

pub fn check_currency(
    currency: common_enums::Currency,
) -> Result<common_enums::Currency, errors::ConnectorError> {
    if currency == common_enums::Currency::USD {
        Ok(currency)
    } else {
        Err(errors::ConnectorError::NotSupported {
            message: format!("currency {currency} is not supported for this merchant account"),
            connector: "Helcim",
        })?
    }
}

// Auth Struct
pub struct HelcimAuthType {
    pub(super) api_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for HelcimAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::HeaderKey { api_key } => Ok(Self {
                api_key: api_key.to_owned(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HelcimBillingAddress {
    name: Secret<String>,
    street1: Secret<String>,
    postal_code: Secret<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    street2: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    city: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<common_utils::pii::Email>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HelcimInvoice {
    invoice_number: String,
    line_items: Vec<HelcimLineItems>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HelcimLineItems {
    description: String,
    quantity: u8,
    price: StringMinorUnit,
    total: StringMinorUnit,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HelcimCard<T: PaymentMethodDataTypes + Serialize> {
    card_number: RawCardNumber<T>,
    card_expiry: Secret<String>,
    card_c_v_v: Secret<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HelcimPaymentsRequest<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    amount: StringMinorUnit,
    currency: common_enums::Currency,
    ip_address: Secret<String, common_utils::pii::IpAddress>,
    card_data: HelcimCard<T>,
    invoice: HelcimInvoice,
    billing_address: HelcimBillingAddress,
    #[serde(skip_serializing_if = "Option::is_none")]
    ecommerce: Option<bool>,
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        HelcimRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for HelcimPaymentsRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: HelcimRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        match &item.router_data.request.payment_method_data {
            PaymentMethodData::Card(req_card) => {
                let card_data = HelcimCard {
                    card_expiry: Secret::new(format!("{}{}", req_card.card_exp_month.peek(), req_card.card_exp_year.peek())),
                    card_number: req_card.card_number.clone(),
                    card_c_v_v: req_card.card_cvc.clone(),
                };

                let req_address = item
                    .router_data
                    .resource_common_data
                    .get_billing_address()?
                    .to_owned();

                let billing_address = HelcimBillingAddress {
                    name: req_address.get_full_name()?,
                    street1: req_address.get_line1()?.to_owned(),
                    postal_code: req_address.get_zip()?.to_owned(),
                    street2: req_address.line2,
                    city: req_address.city,
                    email: item.router_data.request.email.clone(),
                };

                let ip_address = item
                    .router_data
                    .request
                    .get_browser_info()?
                    .get_ip_address()?;

                let line_items = vec![HelcimLineItems {
                    description: item
                        .router_data
                        .resource_common_data
                        .description
                        .clone()
                        .unwrap_or("No Description".to_string()),
                    quantity: 1,
                    price: item.connector.amount_converter.convert(
                        item.router_data.request.minor_amount,
                        item.router_data.request.currency,
                    ).change_context(errors::ConnectorError::RequestEncodingFailed)?,
                    total: item.connector.amount_converter.convert(
                        item.router_data.request.minor_amount,
                        item.router_data.request.currency,
                    ).change_context(errors::ConnectorError::RequestEncodingFailed)?,
                }];

                let invoice = HelcimInvoice {
                    invoice_number: item.router_data.resource_common_data.connector_request_reference_id.clone(),
                    line_items,
                };

                let currency = check_currency(item.router_data.request.currency)?;

                Ok(Self {
                    amount: item.connector.amount_converter.convert(
                        item.router_data.request.minor_amount,
                        item.router_data.request.currency,
                    ).change_context(errors::ConnectorError::RequestEncodingFailed)?,
                    currency,
                    ip_address,
                    card_data,
                    invoice,
                    billing_address,
                    ecommerce: None,
                })
            }
            _ => Err(errors::ConnectorError::NotImplemented(
                "Payment method not supported".to_string(),
            ))?,
        }
    }
}

// PaymentsResponse
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "UPPERCASE")]
pub enum HelcimPaymentStatus {
    Approved,
    Declined,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum HelcimTransactionType {
    Purchase,
    PreAuth,
    Capture,
    Verify,
    Reverse,
}

impl From<HelcimPaymentsResponse> for common_enums::AttemptStatus {
    fn from(item: HelcimPaymentsResponse) -> Self {
        match item.transaction_type {
            HelcimTransactionType::Purchase | HelcimTransactionType::Verify => match item.status {
                HelcimPaymentStatus::Approved => Self::Charged,
                HelcimPaymentStatus::Declined => Self::Failure,
            },
            HelcimTransactionType::PreAuth => match item.status {
                HelcimPaymentStatus::Approved => Self::Authorized,
                HelcimPaymentStatus::Declined => Self::AuthorizationFailed,
            },
            HelcimTransactionType::Capture => match item.status {
                HelcimPaymentStatus::Approved => Self::Charged,
                HelcimPaymentStatus::Declined => Self::CaptureFailed,
            },
            HelcimTransactionType::Reverse => match item.status {
                HelcimPaymentStatus::Approved => Self::Voided,
                HelcimPaymentStatus::Declined => Self::VoidFailed,
            },
        }
    }
}

impl From<HelcimSyncResponse> for common_enums::AttemptStatus {
    fn from(item: HelcimSyncResponse) -> Self {
        match item.transaction_type {
            HelcimTransactionType::Purchase | HelcimTransactionType::Verify => match item.status {
                HelcimPaymentStatus::Approved => Self::Charged,
                HelcimPaymentStatus::Declined => Self::Failure,
            },
            HelcimTransactionType::PreAuth => match item.status {
                HelcimPaymentStatus::Approved => Self::Authorized,
                HelcimPaymentStatus::Declined => Self::AuthorizationFailed,
            },
            HelcimTransactionType::Capture => match item.status {
                HelcimPaymentStatus::Approved => Self::Charged,
                HelcimPaymentStatus::Declined => Self::CaptureFailed,
            },
            HelcimTransactionType::Reverse => match item.status {
                HelcimPaymentStatus::Approved => Self::Voided,
                HelcimPaymentStatus::Declined => Self::VoidFailed,
            },
        }
    }
}

impl From<HelcimCaptureResponse> for common_enums::AttemptStatus {
    fn from(item: HelcimCaptureResponse) -> Self {
        match item.transaction_type {
            HelcimTransactionType::Purchase | HelcimTransactionType::Verify => match item.status {
                HelcimPaymentStatus::Approved => Self::Charged,
                HelcimPaymentStatus::Declined => Self::Failure,
            },
            HelcimTransactionType::PreAuth => match item.status {
                HelcimPaymentStatus::Approved => Self::Authorized,
                HelcimPaymentStatus::Declined => Self::AuthorizationFailed,
            },
            HelcimTransactionType::Capture => match item.status {
                HelcimPaymentStatus::Approved => Self::Charged,
                HelcimPaymentStatus::Declined => Self::CaptureFailed,
            },
            HelcimTransactionType::Reverse => match item.status {
                HelcimPaymentStatus::Approved => Self::Voided,
                HelcimPaymentStatus::Declined => Self::VoidFailed,
            },
        }
    }
}

impl From<HelcimVoidResponse> for common_enums::AttemptStatus {
    fn from(item: HelcimVoidResponse) -> Self {
        match item.transaction_type {
            HelcimTransactionType::Purchase | HelcimTransactionType::Verify => match item.status {
                HelcimPaymentStatus::Approved => Self::Charged,
                HelcimPaymentStatus::Declined => Self::Failure,
            },
            HelcimTransactionType::PreAuth => match item.status {
                HelcimPaymentStatus::Approved => Self::Authorized,
                HelcimPaymentStatus::Declined => Self::AuthorizationFailed,
            },
            HelcimTransactionType::Capture => match item.status {
                HelcimPaymentStatus::Approved => Self::Charged,
                HelcimPaymentStatus::Declined => Self::CaptureFailed,
            },
            HelcimTransactionType::Reverse => match item.status {
                HelcimPaymentStatus::Approved => Self::Voided,
                HelcimPaymentStatus::Declined => Self::VoidFailed,
            },
        }
    }
}

impl From<HelcimRSyncResponse> for common_enums::RefundStatus {
    fn from(item: HelcimRSyncResponse) -> Self {
        match item.transaction_type {
            HelcimRefundTransactionType::Refund => match item.status {
                HelcimPaymentStatus::Approved => Self::Success,
                HelcimPaymentStatus::Declined => Self::Failure,
            },
        }
    }
}

// TryFrom implementations for void response
impl<F, T> TryFrom<ResponseRouterData<HelcimVoidResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, T, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<HelcimVoidResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData { response, router_data, http_code } = item;
        
        let status = common_enums::AttemptStatus::from(response.clone());

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    response.transaction_id.to_string(),
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: response.invoice_number.clone(),
                incremental_authorization_allowed: None,
                status_code: http_code,
            }),
            ..router_data
        })
    }
}

// TryFrom implementations for RSync response
impl<F, T> TryFrom<ResponseRouterData<HelcimRSyncResponse, Self>>
    for RouterDataV2<F, RefundFlowData, T, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<HelcimRSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData { response, router_data, http_code } = item;
        
        let refund_status = common_enums::RefundStatus::from(response.clone());

        Ok(Self {
            resource_common_data: RefundFlowData {
                status: refund_status,
                ..router_data.resource_common_data
            },
            response: Ok(RefundsResponseData {
                connector_refund_id: response.transaction_id.to_string(),
                refund_status,
                status_code: http_code,
            }),
            ..router_data
        })
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct HelcimPaymentsResponse {
    status: HelcimPaymentStatus,
    transaction_type: HelcimTransactionType,
    transaction_id: u64,
    amount: f64,
    currency: String,
    date_created: String,
    card_token: Option<String>,
    card_f4l4: Option<String>,
    card_type: Option<String>,
    avs_response: Option<String>,
    cvv_response: Option<String>,
    approval_code: Option<String>,
    order_number: Option<String>,
    customer_code: Option<String>,
    invoice_number: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct HelcimSyncResponse {
    status: HelcimPaymentStatus,
    transaction_type: HelcimTransactionType,
    transaction_id: u64,
    amount: f64,
    currency: String,
    date_created: String,
    card_token: Option<String>,
    card_f4l4: Option<String>,
    card_type: Option<String>,
    avs_response: Option<String>,
    cvv_response: Option<String>,
    approval_code: Option<String>,
    order_number: Option<String>,
    customer_code: Option<String>,
    invoice_number: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct HelcimCaptureResponse {
    status: HelcimPaymentStatus,
    transaction_type: HelcimTransactionType,
    transaction_id: u64,
    amount: f64,
    currency: String,
    date_created: String,
    card_token: Option<String>,
    card_f4l4: Option<String>,
    card_type: Option<String>,
    avs_response: Option<String>,
    cvv_response: Option<String>,
    approval_code: Option<String>,
    order_number: Option<String>,
    customer_code: Option<String>,
    invoice_number: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct HelcimVoidResponse {
    status: HelcimPaymentStatus,
    transaction_id: u64,
    invoice_number: Option<String>,
    #[serde(rename = "type")]
    transaction_type: HelcimTransactionType,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct HelcimMetaData {
    pub preauth_transaction_id: u64,
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        ResponseRouterData<
            HelcimPaymentsResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    > for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<
            HelcimPaymentsResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData { response, router_data, http_code } = item;
        
        let status = common_enums::AttemptStatus::from(response.clone());
        
        //PreAuth Transaction ID is stored in connector metadata
        //Initially resource_id is stored as NoResponseID for manual capture
        //After Capture Transaction is completed it is updated to store the Capture ID
        let resource_id = if router_data.request.is_auto_capture()? {
            ResponseId::ConnectorTransactionId(response.transaction_id.to_string())
        } else {
            ResponseId::NoResponseId
        };
        let connector_metadata = if !router_data.request.is_auto_capture()? {
            Some(serde_json::json!(HelcimMetaData {
                preauth_transaction_id: response.transaction_id,
            }))
        } else {
            None
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id,
                redirection_data: None,
                connector_metadata,
                network_txn_id: None,
                connector_response_reference_id: response.invoice_number.clone(),
                incremental_authorization_allowed: None,
                mandate_reference: None,
                status_code: http_code,
            }),
            ..router_data
        })
    }
}

// Sync request (empty for GET requests)
#[derive(Debug, Serialize)]
pub struct HelcimSyncRequest;

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        HelcimRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    > for HelcimSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        _item: HelcimRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self)
    }
}

impl<F> TryFrom<ResponseRouterData<HelcimSyncResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<HelcimSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData { response, router_data, http_code } = item;
        
        let status = common_enums::AttemptStatus::from(response.clone());

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    response.transaction_id.to_string(),
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: response.invoice_number.clone(),
                incremental_authorization_allowed: None,
                status_code: http_code,
            }),
            ..router_data
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HelcimCaptureRequest {
    pre_auth_transaction_id: u64,
    amount: StringMinorUnit,
    ip_address: Secret<String, common_utils::pii::IpAddress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ecommerce: Option<bool>,
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        HelcimRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    > for HelcimCaptureRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: HelcimRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let ip_address = item
            .router_data
            .request
            .browser_info
            .clone()
            .ok_or_else(|| errors::ConnectorError::MissingRequiredField {
                field_name: "browser_info",
            })?
            .get_ip_address()?;
        Ok(Self {
            pre_auth_transaction_id: item
                .router_data
                .request
                .get_connector_transaction_id()?
                .parse::<u64>()
                .change_context(errors::ConnectorError::RequestEncodingFailed)?,
            amount: item.connector.amount_converter.convert(
                item.router_data.request.minor_amount_to_capture,
                item.router_data.request.currency,
            ).change_context(errors::ConnectorError::RequestEncodingFailed)?,
            ip_address,
            ecommerce: None,
        })
    }
}

impl<F, T> TryFrom<ResponseRouterData<HelcimCaptureResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, T, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<HelcimCaptureResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData { response, router_data, http_code } = item;
        
        let status = common_enums::AttemptStatus::from(response.clone());

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    response.transaction_id.to_string(),
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: response.invoice_number.clone(),
                incremental_authorization_allowed: None,
                status_code: http_code,
            }),
            ..router_data
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HelcimVoidRequest {
    card_transaction_id: u64,
    ip_address: Secret<String, common_utils::pii::IpAddress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ecommerce: Option<bool>,
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        HelcimRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    > for HelcimVoidRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: HelcimRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let ip_address = item
            .router_data
            .request
            .browser_info
            .ok_or_else(|| errors::ConnectorError::MissingRequiredField {
                field_name: "browser_info",
            })?
            .get_ip_address()?;
        Ok(Self {
            card_transaction_id: item
                .router_data
                .request
                .connector_transaction_id
                .parse::<u64>()
                .change_context(errors::ConnectorError::RequestEncodingFailed)?,
            ip_address,
            ecommerce: None,
        })
    }
}

// REFUND:
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HelcimRefundRequest {
    amount: StringMinorUnit,
    original_transaction_id: u64,
    ip_address: Secret<String, common_utils::pii::IpAddress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ecommerce: Option<bool>,
}

impl<
        F,
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        HelcimRouterData<RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>, T>,
    > for HelcimRefundRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: HelcimRouterData<
            RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let original_transaction_id = item
            .router_data
            .request
            .connector_transaction_id
            .parse::<u64>()
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;

        let ip_address = item
            .router_data
            .request
            .browser_info
            .ok_or_else(|| errors::ConnectorError::MissingRequiredField {
                field_name: "browser_info",
            })?
            .get_ip_address()?;
        Ok(Self {
            amount: item.connector.amount_converter.convert(
                item.router_data.request.minor_refund_amount,
                item.router_data.request.currency,
            ).change_context(errors::ConnectorError::RequestEncodingFailed)?,
            original_transaction_id,
            ip_address,
            ecommerce: None,
        })
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum HelcimRefundTransactionType {
    Refund,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct HelcimRefundResponse {
    status: HelcimPaymentStatus,
    transaction_type: HelcimRefundTransactionType,
    transaction_id: u64,
    amount: f64,
    currency: String,
    date_created: String,
    invoice_number: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct HelcimRSyncResponse {
    status: HelcimPaymentStatus,
    transaction_id: u64,
    invoice_number: Option<String>,
    #[serde(rename = "type")]
    transaction_type: HelcimRefundTransactionType,
}

impl From<HelcimRefundResponse> for common_enums::RefundStatus {
    fn from(item: HelcimRefundResponse) -> Self {
        match item.transaction_type {
            HelcimRefundTransactionType::Refund => match item.status {
                HelcimPaymentStatus::Approved => Self::Success,
                HelcimPaymentStatus::Declined => Self::Failure,
            },
        }
    }
}

impl<F> TryFrom<ResponseRouterData<HelcimRefundResponse, Self>>
    for RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<HelcimRefundResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData { response, router_data, http_code } = item;
        
        let refund_status = common_enums::RefundStatus::from(response.clone());

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: response.transaction_id.to_string(),
                refund_status,
                status_code: http_code,
            }),
            ..router_data
        })
    }
}

// Refund Sync request (empty for GET requests)
#[derive(Debug, Serialize)]
pub struct HelcimRSyncRequest;

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        HelcimRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    > for HelcimRSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        _item: HelcimRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self)
    }
}

impl<F> TryFrom<ResponseRouterData<HelcimRefundResponse, Self>>
    for RouterDataV2<F, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<HelcimRefundResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData { response, router_data, http_code } = item;
        
        let refund_status = common_enums::RefundStatus::from(response.clone());

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: response.transaction_id.to_string(),
                refund_status,
                status_code: http_code,
            }),
            ..router_data
        })
    }
}

#[derive(Debug, strum::Display, Deserialize, Serialize)]
#[serde(untagged)]
pub enum HelcimErrorTypes {
    StringType(String),
    JsonType(serde_json::Value),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct HelcimPaymentsErrorResponse {
    pub errors: HelcimErrorTypes,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum HelcimErrorResponse {
    Payment(HelcimPaymentsErrorResponse),
    General(String),
}