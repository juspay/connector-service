use common_enums::AttemptStatus;
use common_utils::{
    request::Method,
    types::MinorUnit,
};
use url::Url;
use domain_types::{
    connector_flow::{Authorize, PSync, RSync, Refund},
    connector_types::{
        PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData,
        RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData, ResponseId,
    },
    errors,
    payment_method_data::{
        BillDeskRedirectData, NetbankingData, PaymentMethodData, PaymentMethodDataTypes, UpiData,
        WalletData,
    },
    router_data::ConnectorSpecificConfig,
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, Secret};
use serde::{Deserialize, Serialize};

use crate::types::ResponseRouterData;

// =============================================================================
// AUTH TYPE
// =============================================================================

#[derive(Debug, Clone)]
pub struct BilldeskAuthType {
    pub api_key: Secret<String>,
    pub key1: Option<Secret<String>>,
}

impl TryFrom<&ConnectorSpecificConfig> for BilldeskAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorSpecificConfig) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorSpecificConfig::Billdesk { api_key, key1, .. } => Ok(Self {
                api_key: api_key.to_owned(),
                key1: key1.to_owned(),
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
pub struct BilldeskErrorResponse {
    #[serde(rename = "error_code")]
    pub code: String,
    pub message: String,
}

// =============================================================================
// REQUEST STRUCTURES
// =============================================================================

/// Billdesk V2 Payment Method sub-object
#[derive(Debug, Serialize)]
pub struct BilldeskPaymentObject {
    /// Payment method type: "UPI", "NET_BANKING", "WALLET", "CARD"
    pub payment_method_type: String,
    /// Payment method (e.g. bank code for NB, VPA for UPI collect, wallet name)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_method: Option<String>,
    /// UPI flow type: "collect", "intent", "qr"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow: Option<String>,
    /// VPA for UPI collect
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vpa_id: Option<String>,
}

/// Billdesk V2 Device object
#[derive(Debug, Serialize)]
pub struct BilldeskDevice {
    pub init_channel: String,
    pub ip: String,
    pub user_agent: String,
}

/// Billdesk V2 CreateTxnReq
#[derive(Debug, Serialize)]
pub struct BilldeskPaymentsRequest<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    pub mercid: String,
    pub orderid: String,
    pub amount: String,
    pub currency: String,
    pub ru: String,
    pub itemcode: String,
    pub txnid: String,
    pub payment: BilldeskPaymentObject,
    pub device: BilldeskDevice,
    #[serde(skip)]
    pub _phantom: std::marker::PhantomData<T>,
}

// =============================================================================
// REQUEST TRANSFORMATION  (BilldeskRouterData → BilldeskPaymentsRequest)
// =============================================================================

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        super::BilldeskRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for BilldeskPaymentsRequest<T>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: super::BilldeskRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;

        // Merchant ID from auth
        let auth = BilldeskAuthType::try_from(&router_data.connector_config)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        let mercid = auth.api_key.expose();

        let orderid = router_data
            .resource_common_data
            .connector_request_reference_id
            .clone();
        let txnid = router_data
            .resource_common_data
            .payment_id
            .clone();

        // Amount as string with 2 decimal places
        let amount_minor: MinorUnit = router_data.request.minor_amount;
        let amount_str = format!("{:.2}", amount_minor.get_amount_as_i64() as f64 / 100.0);

        let currency = router_data.request.currency.to_string();

        let ru = router_data
            .request
            .get_router_return_url()
            .change_context(errors::ConnectorError::MissingRequiredField {
                field_name: "return_url",
            })?;

        let ip = router_data
            .request
            .get_ip_address_as_optional()
            .map(|ip| ip.expose())
            .unwrap_or_else(|| "127.0.0.1".to_string());

        let user_agent = router_data
            .request
            .browser_info
            .as_ref()
            .and_then(|info| info.get_user_agent().ok())
            .unwrap_or_else(|| "Mozilla/5.0".to_string());

        let device = BilldeskDevice {
            init_channel: "internet".to_string(),
            ip,
            user_agent,
        };

        // Build payment object based on payment method data
        let payment = match &router_data.request.payment_method_data {
            // UPI Intent (UPI_PAY)
            PaymentMethodData::Upi(UpiData::UpiIntent(_)) => BilldeskPaymentObject {
                payment_method_type: "UPI".to_string(),
                payment_method: None,
                flow: Some("intent".to_string()),
                vpa_id: None,
            },
            // UPI Collect (UPI_COLLECT) — VPA required
            PaymentMethodData::Upi(UpiData::UpiCollect(collect_data)) => {
                let vpa = collect_data
                    .vpa_id
                    .as_ref()
                    .map(|v| v.clone().expose());
                BilldeskPaymentObject {
                    payment_method_type: "UPI".to_string(),
                    payment_method: None,
                    flow: Some("collect".to_string()),
                    vpa_id: vpa,
                }
            }
            // UPI QR (UPI_QR)
            PaymentMethodData::Upi(UpiData::UpiQr(_)) => BilldeskPaymentObject {
                payment_method_type: "UPI".to_string(),
                payment_method: None,
                flow: Some("qr".to_string()),
                vpa_id: None,
            },
            // Wallet: BillDesk redirect (REDIRECT_WALLET_DEBIT)
            PaymentMethodData::Wallet(WalletData::BillDeskRedirect(BillDeskRedirectData {})) => {
                BilldeskPaymentObject {
                    payment_method_type: "WALLET".to_string(),
                    payment_method: Some("billdesk".to_string()),
                    flow: None,
                    vpa_id: None,
                }
            }
            // Net Banking (all banks via bank_code)
            PaymentMethodData::Netbanking(NetbankingData { bank_code, .. }) => {
                BilldeskPaymentObject {
                    payment_method_type: "NET_BANKING".to_string(),
                    payment_method: Some(bank_code.clone()),
                    flow: None,
                    vpa_id: None,
                }
            }
            _ => {
                return Err(errors::ConnectorError::NotImplemented(
                    "Payment method not supported by BillDesk".to_string(),
                )
                .into())
            }
        };

        Ok(Self {
            mercid,
            orderid,
            amount: amount_str,
            currency,
            ru,
            itemcode: "DIRECT".to_string(),
            txnid,
            payment,
            device,
            _phantom: std::marker::PhantomData,
        })
    }
}

// =============================================================================
// RESPONSE STRUCTURES
// =============================================================================

#[derive(Debug, Deserialize, Serialize)]
pub struct BilldeskLink {
    pub href: Option<String>,
    pub rel: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BilldeskPaymentsResponse {
    /// Billdesk transaction ID
    #[serde(rename = "transactionid")]
    pub transaction_id: Option<String>,
    /// Auth status: "0300"=charged, "0002"=pending/redirect, "0399"=failed
    pub auth_status: Option<String>,
    /// Next step hint: "redirect", "3ds2_challenge"
    pub next_step: Option<String>,
    /// Redirect links
    pub links: Option<Vec<BilldeskLink>>,
    /// Error info
    pub transaction_error_type: Option<String>,
    pub transaction_error_desc: Option<String>,
}

// =============================================================================
// RESPONSE TRANSFORMATION (BilldeskPaymentsResponse → RouterDataV2)
// =============================================================================

impl<T: PaymentMethodDataTypes>
    TryFrom<
        ResponseRouterData<
            BilldeskPaymentsResponse,
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
            BilldeskPaymentsResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;

        let auth_status = response
            .auth_status
            .as_deref()
            .unwrap_or("");

        // Find redirect URL from links if present
        let redirect_url = response.links.as_ref().and_then(|links| {
            links.iter().find_map(|link| link.href.clone())
        });

        let (status, redirection_data) = match auth_status {
            // Frictionless 3DS2 — payment charged directly
            "0300" => (AttemptStatus::Charged, None),
            // Pending redirect or 3DS challenge
            "0002" => {
                let next_step = response.next_step.as_deref().unwrap_or("");
                if matches!(next_step, "redirect" | "3ds2_challenge") {
                    if let Some(url_str) = redirect_url {
                        let parsed_url = Url::parse(&url_str).map_err(|_| {
                            error_stack::report!(errors::ConnectorError::ResponseHandlingFailed)
                        })?;
                        let redirect_form = RedirectForm::from((parsed_url, Method::Get));
                        (
                            AttemptStatus::AuthenticationPending,
                            Some(Box::new(redirect_form)),
                        )
                    } else {
                        (AttemptStatus::Pending, None)
                    }
                } else {
                    (AttemptStatus::Pending, None)
                }
            }
            // Auth failed
            "0399" => (AttemptStatus::AuthorizationFailed, None),
            // Unknown — treat as pending
            _ => (AttemptStatus::Pending, None),
        };

        let resource_id = response
            .transaction_id
            .clone()
            .map(ResponseId::ConnectorTransactionId)
            .unwrap_or(ResponseId::NoResponseId);

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id,
                redirection_data,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: response.transaction_id.clone(),
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
// PSYNC REQUEST STRUCTURE
// =============================================================================

/// Billdesk V2 Transaction Status Request
#[derive(Debug, Serialize)]
pub struct BilldeskSyncRequest {
    /// Merchant ID
    pub mercid: String,
    /// Billdesk transaction ID (connector_transaction_id)
    pub transactionid: String,
}

// =============================================================================
// PSYNC REQUEST TRANSFORMATION
// =============================================================================

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        super::BilldeskRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    > for BilldeskSyncRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: super::BilldeskRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;

        let auth = BilldeskAuthType::try_from(&router_data.connector_config)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        let mercid = auth.api_key.expose();

        let transactionid = router_data
            .request
            .get_connector_transaction_id()
            .change_context(errors::ConnectorError::MissingConnectorTransactionID)?;

        Ok(Self {
            mercid,
            transactionid,
        })
    }
}

// =============================================================================
// PSYNC RESPONSE STRUCTURE
// =============================================================================

/// Billdesk V2 Transaction Status Response (same schema as CreateTxnResp)
#[derive(Debug, Deserialize, Serialize)]
pub struct BilldeskSyncResponse {
    /// Billdesk transaction ID
    #[serde(rename = "transactionid")]
    pub transaction_id: Option<String>,
    /// Auth status: "0300"=charged, "0002"=pending, "0399"=failed
    pub auth_status: Option<String>,
    /// Next step hint
    pub next_step: Option<String>,
    /// Redirect links
    pub links: Option<Vec<BilldeskLink>>,
    /// Error info
    pub transaction_error_type: Option<String>,
    pub transaction_error_desc: Option<String>,
}

// =============================================================================
// PSYNC RESPONSE TRANSFORMATION
// =============================================================================

impl
    TryFrom<
        ResponseRouterData<
            BilldeskSyncResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    > for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            BilldeskSyncResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;

        let auth_status = response.auth_status.as_deref().unwrap_or("");

        let status = match auth_status {
            "0300" => AttemptStatus::Charged,
            "0002" => AttemptStatus::Pending,
            "0399" => AttemptStatus::AuthorizationFailed,
            _ => AttemptStatus::Pending,
        };

        let resource_id = response
            .transaction_id
            .clone()
            .map(ResponseId::ConnectorTransactionId)
            .unwrap_or(ResponseId::NoResponseId);

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id,
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: response.transaction_id.clone(),
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
// REFUND REQUEST STRUCTURE
// =============================================================================

/// Billdesk V2 Refund Request
#[derive(Debug, Serialize)]
pub struct BilldeskRefundRequest {
    /// Billdesk merchant ID
    pub mercid: String,
    /// Refund amount as string with 2 decimal places
    pub refund_amount: String,
    /// Refund description (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refund_desc: Option<String>,
    /// Juspay refund reference ID
    pub refund_ref_id: String,
}

// =============================================================================
// REFUND REQUEST TRANSFORMATION
// =============================================================================

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        super::BilldeskRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    > for BilldeskRefundRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: super::BilldeskRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;

        let auth = BilldeskAuthType::try_from(&router_data.connector_config)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        let mercid = auth.api_key.expose();

        let refund_amount_minor: MinorUnit = router_data.request.minor_refund_amount;
        let refund_amount = format!("{:.2}", refund_amount_minor.get_amount_as_i64() as f64 / 100.0);

        let refund_ref_id = router_data.request.refund_id.clone();

        Ok(Self {
            mercid,
            refund_amount,
            refund_desc: router_data.request.reason.clone(),
            refund_ref_id,
        })
    }
}

// =============================================================================
// REFUND RESPONSE STRUCTURE
// =============================================================================

/// Billdesk V2 Refund Response
#[derive(Debug, Deserialize, Serialize)]
pub struct BilldeskRefundResponse {
    /// Billdesk refund ID
    pub refundid: Option<String>,
    /// Refund status: "0700"=success, "0798"=pending, "0799"=failed
    pub refund_status: Option<String>,
    /// Error info
    pub transaction_error_type: Option<String>,
    pub transaction_error_desc: Option<String>,
}

// =============================================================================
// REFUND RESPONSE TRANSFORMATION
// =============================================================================

impl<F>
    TryFrom<
        ResponseRouterData<
            BilldeskRefundResponse,
            RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    > for RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            BilldeskRefundResponse,
            RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;

        let refund_status = match response.refund_status.as_deref().unwrap_or("") {
            "0700" => common_enums::RefundStatus::Success,
            "0799" => common_enums::RefundStatus::Failure,
            _ => common_enums::RefundStatus::Pending,
        };

        let connector_refund_id = response
            .refundid
            .clone()
            .unwrap_or_else(|| item.router_data.request.refund_id.clone());

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
// RSYNC REQUEST STRUCTURE
// =============================================================================

/// Billdesk V2 Refund Status Request
#[derive(Debug, Serialize)]
pub struct BilldeskRSyncRequest {
    /// Billdesk merchant ID
    pub mercid: String,
    /// Billdesk refund ID (connector_refund_id)
    pub refundid: String,
}

// =============================================================================
// RSYNC REQUEST TRANSFORMATION
// =============================================================================

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        super::BilldeskRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    > for BilldeskRSyncRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: super::BilldeskRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;

        let auth = BilldeskAuthType::try_from(&router_data.connector_config)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        let mercid = auth.api_key.expose();

        let refundid = router_data.request.connector_refund_id.clone();

        Ok(Self { mercid, refundid })
    }
}

// =============================================================================
// RSYNC RESPONSE STRUCTURE
// =============================================================================

/// Billdesk V2 Refund Status Response (same schema as RefundResponse)
#[derive(Debug, Deserialize, Serialize)]
pub struct BilldeskRSyncResponse {
    /// Billdesk refund ID
    pub refundid: Option<String>,
    /// Refund status: "0700"=success, "0798"=pending, "0799"=failed
    pub refund_status: Option<String>,
    /// Error info
    pub transaction_error_type: Option<String>,
    pub transaction_error_desc: Option<String>,
}

// =============================================================================
// RSYNC RESPONSE TRANSFORMATION
// =============================================================================

impl
    TryFrom<
        ResponseRouterData<
            BilldeskRSyncResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    > for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            BilldeskRSyncResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;

        let refund_status = match response.refund_status.as_deref().unwrap_or("") {
            "0700" => common_enums::RefundStatus::Success,
            "0799" => common_enums::RefundStatus::Failure,
            _ => common_enums::RefundStatus::Pending,
        };

        let connector_refund_id = response
            .refundid
            .clone()
            .unwrap_or_else(|| item.router_data.request.connector_refund_id.clone());

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
