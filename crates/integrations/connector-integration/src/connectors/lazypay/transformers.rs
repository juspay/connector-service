use crate::{
    connectors::lazypay::LazypayRouterData,
    types::ResponseRouterData,
};
use common_enums::AttemptStatus;
use common_utils::{consts::NO_ERROR_CODE, request::Method};
use url::Url;
use domain_types::{
    connector_flow::{Authorize, PSync, RSync, Refund, Void},
    connector_types::{
        PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData, PaymentsResponseData,
        PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData,
        ResponseId,
    },
    errors,
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes, WalletData},
    router_data::{ConnectorSpecificConfig, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, PeekInterface, Secret};
use serde::{Deserialize, Serialize};

// ============================================================================
// Auth Type
// ============================================================================

#[derive(Debug, Clone)]
pub struct LazypayAuthType {
    pub access_key: Secret<String>,
    pub secret_key: Secret<String>,
}

impl TryFrom<&ConnectorSpecificConfig> for LazypayAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorSpecificConfig) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorSpecificConfig::Lazypay {
                access_key,
                secret_key,
                ..
            } => Ok(Self {
                access_key: access_key.to_owned(),
                secret_key: secret_key.to_owned(),
            }),
            _ => Err(error_stack::report!(
                errors::ConnectorError::FailedToObtainAuthType
            )),
        }
    }
}

// ============================================================================
// Error Response
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LazypayErrorResponse {
    pub code: String,
    pub message: String,
}

// ============================================================================
// Request Types
// ============================================================================

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LazypayAmount {
    pub value: String,
    pub currency: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LazypayUserDetails {
    pub mobile: String,
    pub email: String,
    #[serde(rename = "firstName")]
    pub first_name: String,
    #[serde(rename = "lastName")]
    pub last_name: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LazypayAddress {
    pub address1: String,
    pub address2: String,
    pub city: String,
    pub state: String,
    pub country: String,
    pub pincode: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LazypayCustomParams {
    pub promo_code: String,
    pub coupon_code: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LazypayAuthorizeRequest {
    pub eligibility_response_id: String,
    pub merchant_txn_id: String,
    pub user_details: LazypayUserDetails,
    pub amount: LazypayAmount,
    pub address: LazypayAddress,
    pub source: String,
    pub custom_params: LazypayCustomParams,
    pub notify_url: String,
    pub return_url: String,
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        LazypayRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            T,
        >,
    > for LazypayAuthorizeRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        wrapper: LazypayRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let item = &wrapper.router_data;

        // Validate payment method — must be LazyPayRedirect wallet
        match &item.request.payment_method_data {
            PaymentMethodData::Wallet(WalletData::LazyPayRedirect(_)) => {}
            _ => {
                return Err(error_stack::report!(
                    errors::ConnectorError::NotImplemented(
                        "Only LazyPayRedirect wallet is supported for LazyPay".to_string(),
                    )
                ))
            }
        }

        let amount_str = item.request.minor_amount.get_amount_as_i64().to_string();

        let first_name = item
            .resource_common_data
            .get_optional_billing_first_name()
            .map(|s| s.expose())
            .unwrap_or_default();

        let last_name = item
            .resource_common_data
            .get_optional_billing_last_name()
            .map(|s| s.expose())
            .unwrap_or_default();

        let phone = item
            .resource_common_data
            .get_optional_billing_phone_number()
            .map(|s| s.expose())
            .unwrap_or_default();

        let email = item
            .resource_common_data
            .get_optional_billing_email()
            .map(|e| e.expose().expose())
            .unwrap_or_default();

        let address1 = item
            .resource_common_data
            .get_optional_billing_line1()
            .map(|s| s.expose())
            .unwrap_or_default();

        let address2 = item
            .resource_common_data
            .get_optional_billing_line2()
            .map(|s| s.expose())
            .unwrap_or_default();

        let city = item
            .resource_common_data
            .get_optional_billing_city()
            .map(|s| s.expose())
            .unwrap_or_default();

        let state = item
            .resource_common_data
            .get_optional_billing_state()
            .map(|s| s.expose())
            .unwrap_or_default();

        let country = item
            .resource_common_data
            .get_optional_billing_country()
            .map(|c| c.to_string())
            .unwrap_or_default();

        let pincode = item
            .resource_common_data
            .get_optional_billing_zip()
            .map(|s| s.expose())
            .unwrap_or_default();

        let merchant_txn_id = item
            .resource_common_data
            .connector_request_reference_id
            .clone();

        let return_url = item
            .request
            .router_return_url
            .clone()
            .unwrap_or_default();

        let notify_url = return_url.clone();

        let source = item
            .resource_common_data
            .merchant_id
            .get_string_repr()
            .to_string();

        Ok(Self {
            eligibility_response_id: String::new(),
            merchant_txn_id,
            user_details: LazypayUserDetails {
                mobile: phone,
                email,
                first_name,
                last_name,
            },
            amount: LazypayAmount {
                value: amount_str,
                currency: "INR".to_string(),
            },
            address: LazypayAddress {
                address1,
                address2,
                city,
                state,
                country,
                pincode,
            },
            source,
            custom_params: LazypayCustomParams {
                promo_code: String::new(),
                coupon_code: String::new(),
            },
            notify_url,
            return_url,
        })
    }
}

// ============================================================================
// Response Types
// ============================================================================

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LazypayAuthorizeResponse {
    pub txn_ref_no: String,
    pub checkout_page_url: String,
    pub lp_txn_id: Option<String>,
    pub payment_modes: Option<String>,
}

impl<T: PaymentMethodDataTypes>
    TryFrom<
        ResponseRouterData<
            LazypayAuthorizeResponse,
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
            LazypayAuthorizeResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        // Store txnRefNo in connector_metadata so Void can use it
        let connector_metadata = serde_json::json!({
            "txn_ref_no": item.response.txn_ref_no
        });

        // The connector_transaction_id is the merchantTxnId (sent in request)
        let merchant_txn_id = item
            .router_data
            .resource_common_data
            .connector_request_reference_id
            .clone();

        let checkout_url = Url::parse(&item.response.checkout_page_url)
            .change_context(errors::ConnectorError::FailedToObtainIntegrationUrl)
            .attach_printable("Failed to parse LazyPay checkoutPageUrl")?;

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(merchant_txn_id),
                redirection_data: Some(Box::new(RedirectForm::from((checkout_url, Method::Get)))),
                mandate_reference: None,
                connector_metadata: Some(connector_metadata),
                network_txn_id: None,
                connector_response_reference_id: item.response.lp_txn_id.clone(),
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
// PSync Types
// ============================================================================

/// EnquiryRefundStatus — connector status enum for enquiry/sync response
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LazypayEnquiryRefundStatus {
    Success,
    Fail,
    InProgress,
    DisputeResolved,
    RefundOnDispute,
    CheckoutPageRendered,
    Forwarded,
    Cancelled,
    SelfInviteOtp,
    #[serde(other)]
    Unknown,
}

impl From<LazypayEnquiryRefundStatus> for AttemptStatus {
    fn from(status: LazypayEnquiryRefundStatus) -> Self {
        match status {
            LazypayEnquiryRefundStatus::Success => Self::Charged,
            LazypayEnquiryRefundStatus::Fail => Self::Failure,
            LazypayEnquiryRefundStatus::InProgress => Self::Pending,
            LazypayEnquiryRefundStatus::DisputeResolved => Self::Charged,
            LazypayEnquiryRefundStatus::RefundOnDispute => Self::Pending,
            LazypayEnquiryRefundStatus::CheckoutPageRendered => Self::AuthenticationPending,
            LazypayEnquiryRefundStatus::Forwarded => Self::Pending,
            LazypayEnquiryRefundStatus::Cancelled => Self::Voided,
            LazypayEnquiryRefundStatus::SelfInviteOtp => Self::AuthenticationPending,
            LazypayEnquiryRefundStatus::Unknown => Self::Failure,
        }
    }
}

/// Transaction type in enquiry response
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LazypayEnquiryTransactionType {
    Sale,
    Refund,
}

/// Single enquiry response object
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LazypayEnquiryRefundResponseObject {
    pub status: LazypayEnquiryRefundStatus,
    pub resp_message: Option<String>,
    pub lp_txn_id: Option<String>,
    pub txn_type: Option<LazypayEnquiryTransactionType>,
    pub txn_date_time: Option<String>,
    pub amount: Option<String>,
}

/// Top-level enquiry response — list of objects
pub type LazypaySyncResponse = Vec<LazypayEnquiryRefundResponseObject>;

// ============================================================================
// Void (Cancel Payment) Types
// ============================================================================

/// Void request — POST /v0/payment/pay with cancelTxn=1
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LazypayVoidRequest {
    /// LazyPay txn reference from the Authorize response (stored in connector_metadata)
    pub txn_ref_no: String,
    /// Must always be 1 to signal cancellation
    pub cancel_txn: i32,
}

/// LazypayMetadata — deserialized from connector_metadata JSON
#[derive(Debug, Deserialize)]
pub struct LazypayConnectorMetadata {
    pub txn_ref_no: String,
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        LazypayRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    > for LazypayVoidRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        wrapper: LazypayRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let item = &wrapper.router_data;

        // txnRefNo is stored in connector_feature_data during Authorize (as connector_metadata)
        let connector_meta = item
            .resource_common_data
            .connector_feature_data
            .as_ref()
            .ok_or_else(|| {
                error_stack::report!(errors::ConnectorError::MissingRequiredField {
                    field_name: "connector_feature_data for txnRefNo in Void",
                })
            })?;

        let meta: LazypayConnectorMetadata =
            serde_json::from_value(connector_meta.peek().clone())
                .change_context(errors::ConnectorError::RequestEncodingFailed)
                .attach_printable("Failed to deserialize LazypayConnectorMetadata from connector_feature_data")?;

        Ok(Self {
            txn_ref_no: meta.txn_ref_no,
            cancel_txn: 1,
        })
    }
}

/// Void response — CancelPaymentResponse
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LazypayVoidResponse {
    pub transaction_id: Option<String>,
    pub merchant_order_id: Option<String>,
    pub amount: Option<String>,
    pub currency: Option<String>,
    pub signature: Option<String>,
    pub response_data: Option<String>,
}

impl<F>
    TryFrom<
        ResponseRouterData<
            LazypayVoidResponse,
            RouterDataV2<F, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        >,
    > for RouterDataV2<F, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            LazypayVoidResponse,
            RouterDataV2<F, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        // A successful HTTP 200 response means voided; anything else is VoidFailed
        let status = if http_code == 200 {
            AttemptStatus::Voided
        } else {
            AttemptStatus::VoidFailed
        };

        let connector_txn_id = response
            .transaction_id
            .clone()
            .or_else(|| response.merchant_order_id.clone())
            .unwrap_or_else(|| {
                router_data
                    .request
                    .connector_transaction_id
                    .clone()
            });

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(connector_txn_id),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: response.merchant_order_id.clone(),
                incremental_authorization_allowed: None,
                status_code: http_code,
            }),
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            ..router_data
        })
    }
}

// ============================================================================
// Refund Status Mapping
// ============================================================================

impl From<LazypayEnquiryRefundStatus> for common_enums::RefundStatus {
    fn from(status: LazypayEnquiryRefundStatus) -> Self {
        match status {
            LazypayEnquiryRefundStatus::Success => Self::Success,
            LazypayEnquiryRefundStatus::Fail => Self::Failure,
            LazypayEnquiryRefundStatus::InProgress => Self::Pending,
            LazypayEnquiryRefundStatus::DisputeResolved => Self::Pending,
            LazypayEnquiryRefundStatus::RefundOnDispute => Self::Pending,
            LazypayEnquiryRefundStatus::CheckoutPageRendered => Self::Pending,
            LazypayEnquiryRefundStatus::Forwarded => Self::Pending,
            LazypayEnquiryRefundStatus::Cancelled => Self::Failure,
            LazypayEnquiryRefundStatus::SelfInviteOtp => Self::Pending,
            LazypayEnquiryRefundStatus::Unknown => Self::Failure,
        }
    }
}

// ============================================================================
// Refund Request / Response Types
// ============================================================================

/// Refund request — POST /v0/refund
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LazypayRefundRequest {
    pub merchant_txn_id: String,
    pub amount: LazypayAmount,
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        LazypayRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    > for LazypayRefundRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        wrapper: LazypayRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let item = &wrapper.router_data;

        let merchant_txn_id = item.request.connector_transaction_id.clone();

        let amount_str = item
            .request
            .minor_refund_amount
            .get_amount_as_i64()
            .to_string();

        Ok(Self {
            merchant_txn_id,
            amount: LazypayAmount {
                value: amount_str,
                currency: "INR".to_string(),
            },
        })
    }
}

/// Refund response — wraps a single EnquiryRefundResponseObject
pub type LazypayRefundResponse = LazypayEnquiryRefundResponseObject;

impl
    TryFrom<
        ResponseRouterData<
            LazypayRefundResponse,
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    > for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            LazypayRefundResponse,
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let refund_status = common_enums::RefundStatus::from(response.status.clone());

        let connector_refund_id = response
            .lp_txn_id
            .clone()
            .unwrap_or_else(|| router_data.request.connector_transaction_id.clone());

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id,
                refund_status,
                status_code: http_code,
            }),
            resource_common_data: RefundFlowData {
                status: refund_status,
                ..router_data.resource_common_data
            },
            ..router_data
        })
    }
}

// ============================================================================
// RSync (Refund Sync) Types
// ============================================================================

/// RSync response — same enquiry endpoint with isSale=false; list of EnquiryRefundResponseObject
pub type LazypayRSyncResponse = Vec<LazypayEnquiryRefundResponseObject>;

impl TryFrom<ResponseRouterData<LazypayRSyncResponse, RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>>>
    for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<LazypayRSyncResponse, RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let connector_refund_id = router_data.request.connector_refund_id.clone();

        // Filter response list: find entry where lpTxnId == connector_refund_id AND txnType == REFUND
        let refund_entry = response
            .iter()
            .find(|obj| {
                obj.txn_type == Some(LazypayEnquiryTransactionType::Refund)
                    && obj.lp_txn_id.as_deref() == Some(connector_refund_id.as_str())
            })
            .or_else(|| {
                // Fall back: any REFUND type entry
                response
                    .iter()
                    .find(|obj| obj.txn_type == Some(LazypayEnquiryTransactionType::Refund))
            })
            .ok_or_else(|| {
                error_stack::report!(errors::ConnectorError::ResponseDeserializationFailed)
                    .attach_printable("LazyPay RSync enquiry response: no REFUND entry found")
            })?;

        let refund_status = common_enums::RefundStatus::from(refund_entry.status.clone());

        let returned_refund_id = refund_entry
            .lp_txn_id
            .clone()
            .unwrap_or_else(|| connector_refund_id.clone());

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: returned_refund_id,
                refund_status,
                status_code: http_code,
            }),
            resource_common_data: RefundFlowData {
                status: refund_status,
                ..router_data.resource_common_data
            },
            ..router_data
        })
    }
}

/// TryFrom for PSync response
impl TryFrom<ResponseRouterData<LazypaySyncResponse, RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>>
    for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<LazypaySyncResponse, RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        // Filter for SALE type transaction; fall back to first element if none match
        let sale_entry = response
            .iter()
            .find(|obj| obj.txn_type == Some(LazypayEnquiryTransactionType::Sale))
            .or_else(|| response.first())
            .ok_or_else(|| {
                error_stack::report!(errors::ConnectorError::ResponseDeserializationFailed)
                    .attach_printable("LazyPay enquiry response list is empty")
            })?;

        let status = AttemptStatus::from(sale_entry.status.clone());

        // connector_transaction_id from PSync request
        let connector_txn_id = router_data
            .request
            .connector_transaction_id
            .get_connector_transaction_id()
            .unwrap_or_default();

        let response_data = if status == AttemptStatus::Failure {
            Err(ErrorResponse {
                code: NO_ERROR_CODE.to_string(),
                message: sale_entry
                    .resp_message
                    .clone()
                    .unwrap_or_else(|| "Payment failed".to_string()),
                reason: sale_entry.resp_message.clone(),
                status_code: http_code,
                attempt_status: Some(status),
                connector_transaction_id: Some(connector_txn_id.clone()),
                network_decline_code: None,
                network_advice_code: None,
                network_error_message: None,
            })
        } else {
            Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(connector_txn_id),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: sale_entry.lp_txn_id.clone(),
                incremental_authorization_allowed: None,
                status_code: http_code,
            })
        };

        Ok(Self {
            response: response_data,
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            ..router_data
        })
    }
}
