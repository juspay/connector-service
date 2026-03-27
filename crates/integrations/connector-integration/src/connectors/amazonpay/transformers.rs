use crate::{connectors::amazonpay::AmazonpayRouterData, types::ResponseRouterData};
use common_enums::{AttemptStatus, RefundStatus};
use domain_types::{
    connector_flow::{Authorize, Capture, PSync, RSync, Refund, Void},
    connector_types::{
        PaymentFlowData, PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData,
        PaymentsSyncData, PaymentVoidData, RefundFlowData, RefundSyncData, RefundsData,
        RefundsResponseData, ResponseId,
    },
    errors,
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes, WalletData},
    router_data::ConnectorSpecificConfig,
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
};
use error_stack::ResultExt;
use hyperswitch_masking::{PeekInterface, Secret};
use serde::{Deserialize, Serialize};

type Error = error_stack::Report<errors::ConnectorError>;

// =============================================================================
// AUTH TYPE
// =============================================================================

#[derive(Debug, Clone)]
pub struct AmazonpayAuthType {
    pub api_key: Secret<String>,
    pub client_id: Option<Secret<String>>,
    pub merchant_id: Option<Secret<String>>,
    pub secret_key: Option<Secret<String>>,
}

impl TryFrom<&ConnectorSpecificConfig> for AmazonpayAuthType {
    type Error = Error;

    fn try_from(auth_type: &ConnectorSpecificConfig) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorSpecificConfig::Amazonpay { api_key, client_id, merchant_id, secret_key, .. } => Ok(Self {
                api_key: api_key.to_owned(),
                client_id: client_id.to_owned(),
                merchant_id: merchant_id.to_owned(),
                secret_key: secret_key.to_owned(),
            }),
            _ => Err(error_stack::report!(
                errors::ConnectorError::FailedToObtainAuthType
            )),
        }
    }
}

// =============================================================================
// ERROR RESPONSE
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmazonpayErrorResponse {
    pub code: String,
    pub message: String,
}

// =============================================================================
// AUTHORIZE REQUEST — V2 PreAuth Charge (`POST /v1/payments/charge`)
// Handles: REDIRECT_WALLET_DEBIT (AmazonPayRedirect)
//          DIRECT_WALLET_DEBIT   (AmazonPayRedirect with access_token)
// =============================================================================

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AmazonpayAuthorizeRequest<T: PaymentMethodDataTypes> {
    pub intent: String,
    pub amount: String,
    pub currency_code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callback_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
    pub charge_id: String,
    pub reference_id: String,
    pub merchant_id: String,
    pub attributable_program: String,
    pub selected_payment_instrument_type: String,
    #[serde(skip)]
    pub _phantom: std::marker::PhantomData<T>,
}

// TryFrom for macro-generated AmazonpayRouterData wrapper (owned)
impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + serde::Serialize>
    TryFrom<
        AmazonpayRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for AmazonpayAuthorizeRequest<T>
{
    type Error = Error;

    fn try_from(
        wrapper: AmazonpayRouterData<
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

        let auth = AmazonpayAuthType::try_from(&router_data.connector_config)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;

        let amount = router_data.request.minor_amount.get_amount_as_i64().to_string();
        let currency_code = router_data.request.currency.to_string();
        let charge_id = router_data
            .resource_common_data
            .connector_request_reference_id
            .clone();
        let reference_id = router_data
            .resource_common_data
            .connector_request_reference_id
            .clone();
        let callback_url = router_data.request.router_return_url.clone();

        let (access_token, selected_payment_instrument_type) =
            match &router_data.request.payment_method_data {
                PaymentMethodData::Wallet(wallet_data) => match wallet_data {
                    // REDIRECT_WALLET_DEBIT — AmazonPayRedirect: redirect-based wallet charge
                    WalletData::AmazonPayRedirect(_) => (None, "AMAZON_PAY_BALANCE".to_string()),
                    _ => {
                        return Err(error_stack::report!(
                            errors::ConnectorError::NotImplemented(
                                "Only AmazonPayRedirect wallet type is supported for AmazonPay"
                                    .to_string()
                            )
                        ))
                    }
                },
                _ => {
                    return Err(error_stack::report!(
                        errors::ConnectorError::NotImplemented(
                            "Only Wallet payment method is supported for AmazonPay Authorize"
                                .to_string()
                        )
                    ))
                }
            };

        let merchant_id = auth
            .merchant_id
            .as_ref()
            .map(|id| id.peek().to_string())
            .unwrap_or_default();

        Ok(Self {
            intent: "AuthorizeWithAutoCapture".to_string(),
            amount,
            currency_code,
            callback_url,
            access_token,
            charge_id,
            reference_id,
            merchant_id,
            attributable_program: "JUSPAY".to_string(),
            selected_payment_instrument_type,
            _phantom: std::marker::PhantomData,
        })
    }
}

// =============================================================================
// AUTHORIZE RESPONSE — V2 PreAuth Charge Response
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AmazonpayAuthorizeResponse {
    pub charge_id: Option<String>,
    pub amazon_charge_id: Option<String>,
    pub status: Option<String>,
    pub amazon_pay_url: Option<String>,
    pub merchant_id: Option<String>,
    pub currency_code: Option<String>,
    pub requested_amount: Option<String>,
    pub approved_amount: Option<String>,
    pub create_time: Option<String>,
    pub update_time: Option<String>,
    pub custom_data: Option<String>,
}

fn map_amazonpay_status(status_str: &str) -> AttemptStatus {
    match status_str {
        "AuthApproved" => AttemptStatus::Authorized,
        "CaptureApproved" => AttemptStatus::Charged,
        "CapturePending" | "Pending" => AttemptStatus::Pending,
        "AuthDeclined" | "Declined" => AttemptStatus::Failure,
        _ => AttemptStatus::Pending,
    }
}

impl<T: PaymentMethodDataTypes>
    TryFrom<
        ResponseRouterData<
            AmazonpayAuthorizeResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    > for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = Error;

    fn try_from(
        item: ResponseRouterData<
            AmazonpayAuthorizeResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        let status_str = item.response.status.as_deref().unwrap_or("Pending");
        let base_status = map_amazonpay_status(status_str);

        let connector_transaction_id = item
            .response
            .amazon_charge_id
            .clone()
            .or_else(|| item.response.charge_id.clone())
            .unwrap_or_default();

        // If there's a redirect URL, we need to redirect the customer
        let redirection_data = item.response.amazon_pay_url.as_ref().map(|url| {
            Box::new(RedirectForm::Form {
                endpoint: url.clone(),
                method: common_utils::request::Method::Get,
                form_fields: Default::default(),
            })
        });

        let final_status = if redirection_data.is_some() {
            AttemptStatus::AuthenticationPending
        } else {
            base_status
        };

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(connector_transaction_id),
                redirection_data,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: item.response.charge_id.clone(),
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            resource_common_data: PaymentFlowData {
                status: final_status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

// =============================================================================
// CAPTURE REQUEST — V2 PreAuth Capture (`POST /v1/payments/capture`)
// =============================================================================

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AmazonpayCaptureRequest {
    pub merchant_id: String,
    pub amount: String,
    pub currency_code: String,
    pub charge_id_type: String,
    pub charge_id: String,
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        AmazonpayRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    > for AmazonpayCaptureRequest
{
    type Error = Error;

    fn try_from(
        wrapper: AmazonpayRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &wrapper.router_data;

        let auth = AmazonpayAuthType::try_from(&router_data.connector_config)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;

        let amount = router_data
            .request
            .minor_amount_to_capture
            .get_amount_as_i64()
            .to_string();
        let currency_code = router_data.request.currency.to_string();
        let charge_id = router_data
            .request
            .get_connector_transaction_id()
            .change_context(errors::ConnectorError::MissingConnectorTransactionID)?;

        let merchant_id = auth
            .merchant_id
            .as_ref()
            .map(|id| id.peek().to_string())
            .unwrap_or_default();

        Ok(Self {
            merchant_id,
            amount,
            currency_code,
            charge_id_type: "AmazonTransactionId".to_string(),
            charge_id,
        })
    }
}

// =============================================================================
// CAPTURE RESPONSE — V2 PreAuth Capture Response
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AmazonpayCaptureResponse {
    pub merchant_id: Option<String>,
    pub charge_id: Option<String>,
    pub amazon_charge_id: Option<String>,
    pub requested_amount: Option<String>,
    pub approved_amount: Option<String>,
    pub currency_code: Option<String>,
    pub status: Option<String>,
    pub custom_data: Option<String>,
    pub create_time: Option<String>,
    pub update_time: Option<String>,
}

impl TryFrom<
    ResponseRouterData<
        AmazonpayCaptureResponse,
        RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
    >,
> for RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = Error;

    fn try_from(
        item: ResponseRouterData<
            AmazonpayCaptureResponse,
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let status_str = item.response.status.as_deref().unwrap_or("CapturePending");
        let status = map_amazonpay_status(status_str);

        let connector_transaction_id = item
            .response
            .amazon_charge_id
            .clone()
            .or_else(|| item.response.charge_id.clone())
            .unwrap_or_default();

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(connector_transaction_id),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: item.response.charge_id.clone(),
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

// =============================================================================
// PSYNC RESPONSE — V2 Get Status Response (GET /v1/payments/charge)
// Reuses the same response structure as the authorize response
// =============================================================================

pub type AmazonpaySyncResponse = AmazonpayAuthorizeResponse;

impl TryFrom<
    ResponseRouterData<
        AmazonpaySyncResponse,
        RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    >,
> for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = Error;

    fn try_from(
        item: ResponseRouterData<
            AmazonpaySyncResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let status_str = item.response.status.as_deref().unwrap_or("Pending");
        let status = map_amazonpay_status(status_str);

        let connector_transaction_id = item
            .response
            .amazon_charge_id
            .clone()
            .or_else(|| item.response.charge_id.clone())
            .unwrap_or_default();

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(connector_transaction_id),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: item.response.charge_id.clone(),
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

// =============================================================================
// VOID REQUEST — V2 PreAuth Void (`POST /v1/payments/release`)
// =============================================================================

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AmazonpayVoidRequest {
    pub merchant_id: String,
    pub charge_id_type: String,
    pub charge_id: String,
    pub note_to_customer: String,
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        AmazonpayRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    > for AmazonpayVoidRequest
{
    type Error = Error;

    fn try_from(
        wrapper: AmazonpayRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &wrapper.router_data;

        let auth = AmazonpayAuthType::try_from(&router_data.connector_config)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;

        let charge_id = router_data.request.connector_transaction_id.clone();

        let note_to_customer = router_data
            .request
            .cancellation_reason
            .clone()
            .unwrap_or_else(|| "Order cancelled".to_string());

        let merchant_id = auth
            .merchant_id
            .as_ref()
            .map(|id| id.peek().to_string())
            .unwrap_or_default();

        Ok(Self {
            merchant_id,
            charge_id_type: "AmazonTransactionId".to_string(),
            charge_id,
            note_to_customer,
        })
    }
}

// =============================================================================
// VOID RESPONSE — V2 PreAuth Void Response
// =============================================================================

fn map_amazonpay_void_status(status_str: &str) -> AttemptStatus {
    match status_str {
        "Approved" => AttemptStatus::Voided,
        "Pending" => AttemptStatus::VoidInitiated,
        "Declined" => AttemptStatus::VoidFailed,
        _ => AttemptStatus::VoidFailed,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AmazonpayVoidResponse {
    pub merchant_id: Option<String>,
    pub charge_id: Option<String>,
    pub amazon_charge_id: Option<String>,
    pub currency_code: Option<String>,
    pub status: Option<String>,
    pub create_time: Option<String>,
    pub update_time: Option<String>,
    pub amount: Option<String>,
}

impl
    TryFrom<
        ResponseRouterData<
            AmazonpayVoidResponse,
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        >,
    > for RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = Error;

    fn try_from(
        item: ResponseRouterData<
            AmazonpayVoidResponse,
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let status_str = item.response.status.as_deref().unwrap_or("Declined");
        let status = map_amazonpay_void_status(status_str);

        let connector_transaction_id = item
            .response
            .amazon_charge_id
            .clone()
            .or_else(|| item.response.charge_id.clone())
            .unwrap_or_default();

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(connector_transaction_id),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: item.response.charge_id.clone(),
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

// =============================================================================
// REFUND REQUEST — V2 Refund Init (`POST /v1/payments/refund`)
// =============================================================================

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AmazonpayRefundRequest {
    pub amount: String,
    pub charge_id: String,
    pub charge_id_type: String,
    pub currency_code: String,
    pub merchant_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note_to_customer: Option<String>,
    pub refund_id: String,
    pub soft_descriptor: String,
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        AmazonpayRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    > for AmazonpayRefundRequest
{
    type Error = Error;

    fn try_from(
        wrapper: AmazonpayRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &wrapper.router_data;

        let auth = AmazonpayAuthType::try_from(&router_data.connector_config)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;

        let amount = router_data
            .request
            .minor_refund_amount
            .get_amount_as_i64()
            .to_string();
        let currency_code = router_data.request.currency.to_string();
        let charge_id = router_data.request.connector_transaction_id.clone();
        let refund_id = router_data.request.refund_id.clone();

        let merchant_id = auth
            .merchant_id
            .as_ref()
            .map(|id| id.peek().to_string())
            .unwrap_or_default();

        Ok(Self {
            amount,
            charge_id,
            charge_id_type: "AmazonTransactionId".to_string(),
            currency_code,
            merchant_id,
            note_to_customer: router_data.request.reason.clone(),
            refund_id,
            soft_descriptor: "Refund".to_string(),
        })
    }
}

// =============================================================================
// REFUND RESPONSE — V2 Refund Init Response
// =============================================================================

fn map_amazonpay_refund_status(status_str: &str) -> RefundStatus {
    match status_str {
        "Completed" | "Success" => RefundStatus::Success,
        "Pending" | "Initiated" => RefundStatus::Pending,
        "Declined" | "Failed" => RefundStatus::Failure,
        _ => RefundStatus::Pending,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AmazonpayRefundResponse {
    pub amazon_refund_id: Option<String>,
    pub amount: Option<String>,
    pub create_time: Option<String>,
    pub currency_code: Option<String>,
    pub refunded_fee: Option<String>,
    pub refund_id: Option<String>,
    pub status: Option<String>,
    pub update_time: Option<String>,
}

impl
    TryFrom<
        ResponseRouterData<
            AmazonpayRefundResponse,
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    > for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = Error;

    fn try_from(
        item: ResponseRouterData<
            AmazonpayRefundResponse,
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let status_str = item.response.status.as_deref().unwrap_or("Pending");
        let refund_status = map_amazonpay_refund_status(status_str);

        let connector_refund_id = item
            .response
            .amazon_refund_id
            .clone()
            .or_else(|| item.response.refund_id.clone())
            .unwrap_or_default();

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id,
                refund_status,
                status_code: item.http_code,
            }),
            resource_common_data: RefundFlowData {
                status: refund_status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

// =============================================================================
// RSYNC RESPONSE — V2 Refund Status Response (GET /v1/payments/refund)
// Reuses the same response structure as the refund response
// =============================================================================

pub type AmazonpayRefundSyncResponse = AmazonpayRefundResponse;

impl
    TryFrom<
        ResponseRouterData<
            AmazonpayRefundSyncResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    > for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = Error;

    fn try_from(
        item: ResponseRouterData<
            AmazonpayRefundSyncResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let status_str = item.response.status.as_deref().unwrap_or("Pending");
        let refund_status = map_amazonpay_refund_status(status_str);

        let connector_refund_id = item
            .response
            .amazon_refund_id
            .clone()
            .or_else(|| item.response.refund_id.clone())
            .unwrap_or_default();

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id,
                refund_status,
                status_code: item.http_code,
            }),
            resource_common_data: RefundFlowData {
                status: refund_status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}
